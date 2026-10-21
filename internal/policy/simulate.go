package policy

import (
	"sort"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// Simulation reports what a policy would do, without doing any of it.
//
// It is evaluated against the reported INVENTORY — what is installed — not
// against what people actually run. That difference is the whole reason
// Limits below exists and is returned in the payload rather than left to the
// documentation: a number labelled "simulation" gets read as a guarantee, and
// this one is not.
type Simulation struct {
	Summary   Summary           `json:"summary"`
	ByAction  map[string]Bucket `json:"by_action"`
	TopApps   []AppImpact       `json:"top_apps"`
	Machines  []MachineImpact   `json:"machines"`
	Conflicts []Conflict        `json:"conflicts,omitempty"`
	Limits    []string          `json:"limits"`
}

type Summary struct {
	MachinesEvaluated int `json:"machines_evaluated"`
	MachinesAffected  int `json:"machines_affected"`
	AppsEvaluated     int `json:"apps_evaluated"`
	InstallsMatched   int `json:"installs_matched"`
}

// Bucket counts one action's reach.
type Bucket struct {
	Apps     int `json:"apps"`
	Machines int `json:"machines"`
	Installs int `json:"installs"`
}

// AppImpact is one application the policy would act on.
type AppImpact struct {
	Name         string `json:"name"`
	Publisher    string `json:"publisher"`
	Action       string `json:"action"`
	MachineCount int    `json:"machine_count"`
	RuleName     string `json:"rule_name"`
	PolicyName   string `json:"policy_name"`
}

// MachineImpact is one machine the policy would act on.
type MachineImpact struct {
	AgentID     string `json:"agent_id"`
	MachineName string `json:"machine_name"`
	Blocked     int    `json:"blocked"`
	Elevated    int    `json:"elevated"`
}

// maxReported caps the drill-down lists. The headline counts stay exact; the
// lists are a sample, because a policy matching ten thousand installs would
// otherwise produce a response nobody can render or read.
const maxReported = 50

// appKey identifies one product across the fleet. Name and publisher together,
// because "Chrome" from Google and "Chrome" from a repackager are not the same
// thing and a policy may well treat them differently.
type appKey struct{ name, publisher string }

// Simulator evaluates a draft policy across a fleet.
type Simulator struct {
	// Effective is the resolved policy for each machine, keyed by agent id.
	Effective map[string]Effective
	// Machines is every machine considered, keyed by agent id.
	Machines map[string]*store.Machine
}

// Run evaluates the given installs and returns the projected impact.
//
// The caller streams installs in rather than passing a slice: a hundred
// machines is tens of thousands of rows, and materialising all of them to
// count a few is how a backend falls over on a button click.
func (s *Simulator) Run(stream func(func(*store.InstalledApp) error) error) (Simulation, error) {
	sim := Simulation{
		ByAction: map[string]Bucket{},
		Limits:   simulationLimits(),
	}

	appsSeen := map[appKey]bool{}
	actionApps := map[string]map[appKey]bool{}
	actionMachines := map[string]map[string]bool{}
	affected := map[string]bool{}

	impacts := map[appKey]*AppImpact{}
	machineImpacts := map[string]*MachineImpact{}
	conflicts := map[string]Conflict{}

	err := stream(func(app *store.InstalledApp) error {
		eff, known := s.Effective[app.AgentID]
		if !known {
			// A machine with inventory but no resolved policy is one that was
			// not in the target set. Counting it would overstate the reach.
			return nil
		}

		key := appKey{app.Name, app.Publisher}
		appsSeen[key] = true

		for _, c := range eff.Conflicts {
			conflicts[c.PolicyA+"|"+c.PolicyB+"|"+c.RuleA+"|"+c.RuleB] = c
		}

		d := eff.Decide(app)
		// allow is the default outcome for almost everything, so it is counted
		// but does not make a machine "affected" — otherwise every machine in
		// the fleet is affected by every policy and the number means nothing.
		if !d.Matched || d.Action == store.ActionAllow {
			bucket := sim.ByAction[store.ActionAllow]
			bucket.Installs++
			sim.ByAction[store.ActionAllow] = bucket
			return nil
		}

		sim.Summary.InstallsMatched++
		affected[app.AgentID] = true

		bucket := sim.ByAction[d.Action]
		bucket.Installs++
		sim.ByAction[d.Action] = bucket

		if actionApps[d.Action] == nil {
			actionApps[d.Action] = map[appKey]bool{}
			actionMachines[d.Action] = map[string]bool{}
		}
		actionApps[d.Action][key] = true
		actionMachines[d.Action][app.AgentID] = true

		if impacts[key] == nil {
			impacts[key] = &AppImpact{
				Name: app.Name, Publisher: app.Publisher, Action: d.Action,
				RuleName: d.RuleName, PolicyName: d.PolicyName,
			}
		}
		impacts[key].MachineCount++

		if machineImpacts[app.AgentID] == nil {
			name := app.MachineName
			if m, ok := s.Machines[app.AgentID]; ok && m.Name != "" {
				name = m.Name
			}
			machineImpacts[app.AgentID] = &MachineImpact{AgentID: app.AgentID, MachineName: name}
		}
		switch d.Action {
		case store.ActionBlock:
			machineImpacts[app.AgentID].Blocked++
		case store.ActionElevate:
			machineImpacts[app.AgentID].Elevated++
		}
		return nil
	})
	if err != nil {
		return sim, err
	}

	for action, apps := range actionApps {
		bucket := sim.ByAction[action]
		bucket.Apps = len(apps)
		bucket.Machines = len(actionMachines[action])
		sim.ByAction[action] = bucket
	}

	sim.Summary.MachinesEvaluated = len(s.Effective)
	sim.Summary.MachinesAffected = len(affected)
	sim.Summary.AppsEvaluated = len(appsSeen)

	// "Would be elevated: 42" is a promise this product cannot keep yet, and a
	// number beside the word "would" reads as one. No platform implements
	// elevation — the agent's platformElevator reports unsupported on both
	// Windows and macOS — so the honest reading of that figure is "how many
	// installs a rule points at", not "how many will gain admin rights".
	//
	// Added only when the figure is non-zero: a caveat about something the
	// policy does not do is noise that trains people to skip the list, and
	// this list is the one place the projection admits what it is not.
	if sim.ByAction[store.ActionElevate].Installs > 0 {
		sim.Limits = append([]string{
			"Nothing is elevated yet: no platform implements it, so these installs keep the rights they have now. " +
				"Each endpoint reports the rule as one it cannot honour.",
		}, sim.Limits...)
	}

	sim.TopApps = topApps(impacts)
	sim.Machines = topMachines(machineImpacts)
	for _, c := range conflicts {
		sim.Conflicts = append(sim.Conflicts, c)
	}
	sort.Slice(sim.Conflicts, func(i, j int) bool {
		return sim.Conflicts[i].PolicyA < sim.Conflicts[j].PolicyA
	})
	return sim, nil
}

func topApps(in map[appKey]*AppImpact) []AppImpact {
	out := make([]AppImpact, 0, len(in))
	for _, v := range in {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].MachineCount != out[j].MachineCount {
			return out[i].MachineCount > out[j].MachineCount
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > maxReported {
		out = out[:maxReported]
	}
	return out
}

func topMachines(in map[string]*MachineImpact) []MachineImpact {
	out := make([]MachineImpact, 0, len(in))
	for _, v := range in {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		li, lj := out[i].Blocked+out[i].Elevated, out[j].Blocked+out[j].Elevated
		if li != lj {
			return li > lj
		}
		return out[i].MachineName < out[j].MachineName
	})
	if len(out) > maxReported {
		out = out[:maxReported]
	}
	return out
}

// simulationLimits are returned with every result so the UI cannot quietly
// omit them. Each one is a way this projection differs from what will actually
// happen on the endpoints.
func simulationLimits() []string {
	return []string{
		"This is installed software, not running software. A rule aimed at something nobody launches shows impact that never materialises.",
		"Anything not in the inventory is invisible here — a portable .exe from a USB stick, an installer in a temp folder, a script interpreter.",
		"Decisions are per machine, not per user. Elevation in particular is a per-user concept that this cannot express.",
		"Path rules are compared against the installed path, not the path a program is actually launched from.",
		"Hash-rule impact is a lower bound: only applications whose hash has been collected can match one.",
		"Machines that have not reported recently are evaluated against stale facts, and machines that never reported are not counted at all.",
	}
}
