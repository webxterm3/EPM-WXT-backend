package policy

import (
	"strings"
	"testing"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

func install(agentID, machineName, name, publisher string) *store.InstalledApp {
	return &store.InstalledApp{
		AgentID: agentID, MachineName: machineName, Name: name, Publisher: publisher,
	}
}

// streamOf feeds a fixed set of installs, the way the store streams them.
func streamOf(apps ...*store.InstalledApp) func(func(*store.InstalledApp) error) error {
	return func(fn func(*store.InstalledApp) error) error {
		for _, a := range apps {
			if err := fn(a); err != nil {
				return err
			}
		}
		return nil
	}
}

func simulatorFor(p *store.AppPolicy, machines ...*store.Machine) *Simulator {
	sim := &Simulator{Effective: map[string]Effective{}, Machines: map[string]*store.Machine{}}
	for _, m := range machines {
		sim.Effective[m.AgentID] = Resolve(m, []*store.AppPolicy{p}, false)
		sim.Machines[m.AgentID] = m
	}
	return sim
}

func TestSimulationCountsWhatAPolicyWouldDo(t *testing.T) {
	p := policy("block-games", store.PolicyScopeTenant, 0,
		rule("games", store.ActionBlock, store.MatchCriteria{AppName: equals("Steam")}))

	sim := simulatorFor(p,
		&store.Machine{AgentID: "a1", Name: "Laptop 1", TenantID: "t1"},
		&store.Machine{AgentID: "a2", Name: "Laptop 2", TenantID: "t1"},
		&store.Machine{AgentID: "a3", Name: "Laptop 3", TenantID: "t1"},
	)

	got, err := sim.Run(streamOf(
		install("a1", "Laptop 1", "Steam", "Valve"),
		install("a1", "Laptop 1", "Slack", "Slack"),
		install("a2", "Laptop 2", "Steam", "Valve"),
		install("a3", "Laptop 3", "Slack", "Slack"),
	))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got.Summary.MachinesEvaluated != 3 {
		t.Errorf("MachinesEvaluated = %d, want 3", got.Summary.MachinesEvaluated)
	}
	// Only the two with Steam. A machine that merely has Slack is untouched by
	// this policy and counting it would overstate the reach.
	if got.Summary.MachinesAffected != 2 {
		t.Errorf("MachinesAffected = %d, want 2", got.Summary.MachinesAffected)
	}
	if got.Summary.InstallsMatched != 2 {
		t.Errorf("InstallsMatched = %d, want 2", got.Summary.InstallsMatched)
	}

	blocked := got.ByAction[store.ActionBlock]
	if blocked.Apps != 1 || blocked.Machines != 2 || blocked.Installs != 2 {
		t.Errorf("block bucket = %+v, want 1 app on 2 machines", blocked)
	}

	if len(got.TopApps) != 1 || got.TopApps[0].Name != "Steam" {
		t.Errorf("TopApps = %+v", got.TopApps)
	}
	if got.TopApps[0].RuleName != "games" || got.TopApps[0].PolicyName != "block-games" {
		t.Errorf("the impact does not say which rule caused it: %+v", got.TopApps[0])
	}
}

// Nearly everything resolves to allow. If that counted as "affected", every
// machine would be affected by every policy and the headline number would
// convey nothing.
func TestAllowedSoftwareDoesNotCountAsAffected(t *testing.T) {
	p := policy("allow-all", store.PolicyScopeTenant, 0,
		rule("ours", store.ActionAllow, store.MatchCriteria{Publisher: equals("Acme")}))

	sim := simulatorFor(p, &store.Machine{AgentID: "a1", Name: "L1", TenantID: "t1"})
	got, err := sim.Run(streamOf(install("a1", "L1", "Acme Tool", "Acme")))
	if err != nil {
		t.Fatal(err)
	}

	if got.Summary.MachinesAffected != 0 {
		t.Errorf("MachinesAffected = %d, want 0", got.Summary.MachinesAffected)
	}
	if got.Summary.InstallsMatched != 0 {
		t.Errorf("InstallsMatched = %d, want 0", got.Summary.InstallsMatched)
	}
}

// A machine outside the policy's target set has inventory but no resolved
// policy; counting its software would overstate what the policy reaches.
func TestMachinesOutsideTheScopeAreNotCounted(t *testing.T) {
	p := policy("machine-scoped", store.PolicyScopeMachine, 0,
		rule("block", store.ActionBlock, store.MatchCriteria{AppName: equals("Steam")}))
	p.Scope.AgentIDs = []string{"a1"}

	// Only a1 is resolved; a2's installs stream past with no policy.
	sim := simulatorFor(p, &store.Machine{AgentID: "a1", Name: "L1", TenantID: "t1"})

	got, err := sim.Run(streamOf(
		install("a1", "L1", "Steam", "Valve"),
		install("a2", "L2", "Steam", "Valve"),
	))
	if err != nil {
		t.Fatal(err)
	}

	if got.ByAction[store.ActionBlock].Machines != 1 {
		t.Errorf("block reached %d machines, want 1", got.ByAction[store.ActionBlock].Machines)
	}
	if got.Summary.InstallsMatched != 1 {
		t.Errorf("InstallsMatched = %d, want 1", got.Summary.InstallsMatched)
	}
}

// An empty rule must reach nothing here too — simulation is where an operator
// would first see a mis-click, and it has to agree with what enforcement would
// do rather than reassure them differently.
func TestSimulatingAnEmptyRuleShowsNoImpact(t *testing.T) {
	p := policy("careless", store.PolicyScopeTenant, 0,
		rule("blank", store.ActionBlock, store.MatchCriteria{}))

	sim := simulatorFor(p, &store.Machine{AgentID: "a1", Name: "L1", TenantID: "t1"})
	got, err := sim.Run(streamOf(
		install("a1", "L1", "Steam", "Valve"),
		install("a1", "L1", "Slack", "Slack"),
	))
	if err != nil {
		t.Fatal(err)
	}

	if got.Summary.InstallsMatched != 0 {
		t.Errorf("an empty rule showed %d matches", got.Summary.InstallsMatched)
	}
}

// The limits are what keep the headline number from being read as a promise,
// so they travel in the payload rather than living only in the UI copy.
func TestSimulationAlwaysReportsItsLimits(t *testing.T) {
	sim := &Simulator{Effective: map[string]Effective{}, Machines: map[string]*store.Machine{}}
	got, err := sim.Run(streamOf())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Limits) == 0 {
		t.Fatal("no limits returned")
	}

	joined := strings.Join(got.Limits, " ")
	// The biggest gap: installed is not the same as executed.
	if !strings.Contains(joined, "not running software") {
		t.Error("the limits do not say that this is installed, not executed, software")
	}
}

// A hundred machines is tens of thousands of rows. The drill-down lists have
// to stay renderable while the headline counts stay exact.
func TestDrillDownListsAreCappedButCountsAreNot(t *testing.T) {
	p := policy("block-all-acme", store.PolicyScopeTenant, 0,
		rule("acme", store.ActionBlock, store.MatchCriteria{Publisher: equals("Acme")}))

	machines := make([]*store.Machine, 0, 120)
	installs := make([]*store.InstalledApp, 0, 120)
	for i := 0; i < 120; i++ {
		id := "agent-" + itoa(i)
		machines = append(machines, &store.Machine{AgentID: id, Name: "M" + itoa(i), TenantID: "t1"})
		installs = append(installs, install(id, "M"+itoa(i), "Tool "+itoa(i), "Acme"))
	}

	got, err := simulatorFor(p, machines...).Run(streamOf(installs...))
	if err != nil {
		t.Fatal(err)
	}

	if got.ByAction[store.ActionBlock].Installs != 120 {
		t.Errorf("counted %d installs, want all 120 — the counts must stay exact",
			got.ByAction[store.ActionBlock].Installs)
	}
	if len(got.TopApps) > maxReported || len(got.Machines) > maxReported {
		t.Errorf("drill-down lists were not capped: %d apps, %d machines",
			len(got.TopApps), len(got.Machines))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// "Would be elevated: 3" is a promise, and this product cannot keep it: no
// platform implements elevation, so those three installs keep exactly the
// rights they already have. The figure is still worth showing — it is the
// reach of the rule — but it must not be shown alone.
//
// This is the same failure the elevate action has already been shipped with
// once: something that looks configured, reports a number, and changes
// nothing on the endpoint.
func TestASimulationThatProjectsElevationSaysNothingIsElevated(t *testing.T) {
	const admission = "Nothing is elevated yet"

	t.Run("said when a rule would elevate something", func(t *testing.T) {
		p := policy("devs-get-docker", store.PolicyScopeTenant, 0,
			rule("docker", store.ActionElevate, store.MatchCriteria{AppName: equals("Docker Desktop")}))
		m := &store.Machine{AgentID: "a1", Name: "dev-01", TenantID: "t1"}

		got, err := simulatorFor(p, m).Run(streamOf(
			install("a1", "dev-01", "Docker Desktop", "Docker Inc"),
		))
		if err != nil {
			t.Fatal(err)
		}

		if got.ByAction[store.ActionElevate].Installs == 0 {
			t.Fatal("the rule matched nothing — this test is no longer exercising elevation")
		}
		if !strings.Contains(strings.Join(got.Limits, " "), admission) {
			t.Errorf("the projection reported %d installs as elevated without saying that "+
				"none of them will be", got.ByAction[store.ActionElevate].Installs)
		}
	})

	t.Run("not said when nothing would be elevated", func(t *testing.T) {
		p := policy("no-games", store.PolicyScopeTenant, 0,
			rule("games", store.ActionBlock, store.MatchCriteria{AppName: equals("Steam")}))
		m := &store.Machine{AgentID: "a1", Name: "dev-01", TenantID: "t1"}

		got, err := simulatorFor(p, m).Run(streamOf(
			install("a1", "dev-01", "Steam", "Valve"),
		))
		if err != nil {
			t.Fatal(err)
		}

		if strings.Contains(strings.Join(got.Limits, " "), admission) {
			t.Error("a caveat about elevation appeared for a policy that does not elevate — " +
				"noise here trains people to skip the one list that admits what this cannot do")
		}
	})
}
