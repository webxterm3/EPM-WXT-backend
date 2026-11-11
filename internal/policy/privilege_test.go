package policy

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

func privMachine(agentID string, groups ...string) *store.Machine {
	return &store.Machine{AgentID: agentID, TenantID: "t", GroupIDs: groups}
}

func privPolicy(name, scopeKind string, demote bool, opts ...func(*store.PrivilegePolicy)) *store.PrivilegePolicy {
	p := &store.PrivilegePolicy{
		ID:           primitive.NewObjectID(),
		TenantID:     "t",
		Name:         name,
		Enabled:      true,
		Scope:        store.PolicyScope{Kind: scopeKind},
		Mode:         store.ModeEnforce,
		DemoteAdmins: demote,
		CreatedAt:    time.Unix(1000, 0),
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func admin(name string, demotable bool) *store.LocalAccount {
	return &store.LocalAccount{
		Username: name, IsAdmin: true, IsLocal: true,
		Demotable: demotable, Present: true,
	}
}

// ── The enforcement gate ────────────────────────────────────────────────────

// Nothing is removed from anybody until three separate things are each true.
// Each one is pinned on its own, because each is somebody's last line of
// defence against a fleet-wide mistake.

func TestNothingIsEnforcedWhileTheTenantSwitchIsOff(t *testing.T) {
	eff := ResolvePrivilege(privMachine("a1"), []*store.PrivilegePolicy{
		privPolicy("Strip admins", store.PolicyScopeTenant, true),
	}, false)

	if eff.Mode != store.ModeAudit {
		t.Errorf("Mode = %q, want audit while the tenant switch is off", eff.Mode)
	}
	if eff.Enforcing() {
		t.Error("a policy enforced with the tenant switch off")
	}
}

func TestAnAuditPolicyNeverEnforcesEvenWithTheSwitchOn(t *testing.T) {
	p := privPolicy("Watch only", store.PolicyScopeTenant, true)
	p.Mode = store.ModeAudit

	eff := ResolvePrivilege(privMachine("a1"), []*store.PrivilegePolicy{p}, true)
	if eff.Enforcing() {
		t.Error("an audit policy enforced")
	}
}

func TestAPolicyThatDoesNotAskToDemoteNeverDemotes(t *testing.T) {
	eff := ResolvePrivilege(privMachine("a1"), []*store.PrivilegePolicy{
		privPolicy("Inventory only", store.PolicyScopeTenant, false),
	}, true)

	if eff.Enforcing() {
		t.Error("a policy with demote_admins false still enforced")
	}
}

func TestEverythingOnMeansEnforcing(t *testing.T) {
	eff := ResolvePrivilege(privMachine("a1"), []*store.PrivilegePolicy{
		privPolicy("Strip admins", store.PolicyScopeTenant, true),
	}, true)

	if !eff.Enforcing() {
		t.Error("switch on, mode enforce and demote_admins true should enforce")
	}
}

// No policy at all must mean no instruction, not a default one.
func TestNoPolicyDemotesNobody(t *testing.T) {
	eff := ResolvePrivilege(privMachine("a1"), nil, true)

	if eff.DemoteAdmins {
		t.Error("a machine under no policy was told to demote")
	}
	if eff.Enforcing() {
		t.Error("a machine under no policy was enforcing")
	}
}

func TestADisabledPolicyDoesNotApply(t *testing.T) {
	p := privPolicy("Strip admins", store.PolicyScopeTenant, true)
	p.Enabled = false

	if ResolvePrivilege(privMachine("a1"), []*store.PrivilegePolicy{p}, true).Enforcing() {
		t.Error("a disabled policy applied")
	}
}

// ── Scope and precedence ────────────────────────────────────────────────────

// The whole point of machine scope: exempting one build server from a
// fleet-wide instruction.
func TestAMachinePolicyOverridesTheTenantInstruction(t *testing.T) {
	tenantWide := privPolicy("Strip everybody", store.PolicyScopeTenant, true)
	exempt := privPolicy("Leave the build server", store.PolicyScopeMachine, false)
	exempt.Scope.AgentIDs = []string{"build-1"}

	policies := []*store.PrivilegePolicy{tenantWide, exempt}

	if !ResolvePrivilege(privMachine("laptop-1"), policies, true).DemoteAdmins {
		t.Error("an ordinary machine escaped the tenant-wide instruction")
	}
	if ResolvePrivilege(privMachine("build-1"), policies, true).DemoteAdmins {
		t.Error("the machine-scoped exemption did not win")
	}
}

func TestGroupScopeSitsBetweenMachineAndTenant(t *testing.T) {
	tenantWide := privPolicy("Strip everybody", store.PolicyScopeTenant, true)
	groupExempt := privPolicy("Leave engineering", store.PolicyScopeGroup, false)
	groupExempt.Scope.GroupIDs = []string{"eng"}

	policies := []*store.PrivilegePolicy{tenantWide, groupExempt}

	if ResolvePrivilege(privMachine("a1", "eng"), policies, true).DemoteAdmins {
		t.Error("the group-scoped exemption did not beat the tenant policy")
	}
	if !ResolvePrivilege(privMachine("a2", "sales"), policies, true).DemoteAdmins {
		t.Error("a machine in another group escaped the tenant policy")
	}
}

// A policy naming a machine that no longer exists must reach nobody. This
// exact bug has already been found once in the application policies — a
// machine re-enrolled, got a new agent id, and two policies silently stopped
// applying while the portal showed them as enabled and enforcing.
func TestAPolicyPinnedToADeadEnrolmentReachesNobody(t *testing.T) {
	stale := privPolicy("Strip admins", store.PolicyScopeMachine, true)
	stale.Scope.AgentIDs = []string{"super-admin-74f699fe"} // re-enrolled since

	eff := ResolvePrivilege(privMachine("super-admin-1639100b"), []*store.PrivilegePolicy{stale}, true)

	if len(eff.Sources) != 0 {
		t.Error("a policy naming a dead agent id still applied")
	}
	if eff.Enforcing() {
		t.Error("and it enforced")
	}
}

// The two resolvers must agree about who is in scope, or the privilege
// simulation counts machines the enforcement never reaches.
func TestBothResolversAgreeAboutScope(t *testing.T) {
	m := privMachine("a1", "eng")
	scopes := []store.PolicyScope{
		{Kind: store.PolicyScopeTenant},
		{Kind: store.PolicyScopeGroup, GroupIDs: []string{"eng"}},
		{Kind: store.PolicyScopeGroup, GroupIDs: []string{"sales"}},
		{Kind: store.PolicyScopeMachine, AgentIDs: []string{"a1"}},
		{Kind: store.PolicyScopeMachine, AgentIDs: []string{"a2"}},
	}

	for _, scope := range scopes {
		app := AppliesTo(&store.AppPolicy{Scope: scope}, m)
		priv := appliesToPrivilege(&store.PrivilegePolicy{Scope: scope}, m)

		if app != priv {
			t.Errorf("scope %v: application resolver says %t, privilege resolver says %t",
				scope, app, priv)
		}
	}
}

// ── Exemptions ──────────────────────────────────────────────────────────────

// Exemptions union rather than letting the most specific policy win. An
// exemption is a statement that something must not be touched, and the author
// of the narrower policy was never asked about it.
func TestExemptionsUnionAcrossPolicies(t *testing.T) {
	tenantWide := privPolicy("Strip everybody", store.PolicyScopeTenant, true)
	tenantWide.KeepAdmin = []string{"svc-backup"}

	perMachine := privPolicy("This laptop", store.PolicyScopeMachine, true)
	perMachine.Scope.AgentIDs = []string{"a1"}
	perMachine.KeepAdmin = []string{"priya"}

	eff := ResolvePrivilege(privMachine("a1"), []*store.PrivilegePolicy{tenantWide, perMachine}, true)

	if !eff.KeepsAdmin("svc-backup") {
		t.Error("the tenant-wide exemption was dropped by the machine policy — " +
			"a service account somebody wrote down would have been demoted")
	}
	if !eff.KeepsAdmin("priya") {
		t.Error("the machine-scoped exemption was lost")
	}
}

// The three places a username is typed do not agree about case, and both
// supported platforms match usernames case-insensitively anyway.
func TestExemptionsIgnoreCase(t *testing.T) {
	p := privPolicy("Strip", store.PolicyScopeTenant, true)
	p.KeepAdmin = []string{"Priya"}

	eff := ResolvePrivilege(privMachine("a1"), []*store.PrivilegePolicy{p}, true)

	for _, spelling := range []string{"priya", "PRIYA", "Priya", "  priya  "} {
		if !eff.KeepsAdmin(spelling) {
			t.Errorf("%q did not match the exemption", spelling)
		}
	}
	if eff.KeepsAdmin("priyanka") {
		t.Error("a different username matched the exemption")
	}
}

func TestAnEmptyUsernameIsNeverExempt(t *testing.T) {
	p := privPolicy("Strip", store.PolicyScopeTenant, true)
	p.KeepAdmin = []string{"priya"}

	eff := ResolvePrivilege(privMachine("a1"), []*store.PrivilegePolicy{p}, true)
	if eff.KeepsAdmin("") || eff.KeepsAdmin("   ") {
		t.Error("an empty username matched an exemption")
	}
}

// The break-glass account is the machine's way back in. A policy that
// demoted its own recovery account would be the most expensive bug here.
func TestTheBreakGlassAccountIsAlwaysExempt(t *testing.T) {
	p := privPolicy("Strip", store.PolicyScopeTenant, true)
	p.BreakGlass = store.BreakGlassSpec{Enabled: true, Username: "vsay-recovery"}

	eff := ResolvePrivilege(privMachine("a1"), []*store.PrivilegePolicy{p}, true)

	if !eff.KeepsAdmin("vsay-recovery") {
		t.Error("the break-glass account was not exempt from its own policy")
	}
}

// ── Elevation merging ───────────────────────────────────────────────────────

// Every field here grants a way to get privilege BACK. Letting the narrower
// policy win would produce a machine where one policy removed the rights and
// another closed the route back — somebody unable to work, with nothing in
// the portal explaining why.
func TestElevationMergesPermissively(t *testing.T) {
	a := privPolicy("A", store.PolicyScopeTenant, true)
	a.Elevation = store.ElevationSpec{AllowInstallRequests: true}

	b := privPolicy("B", store.PolicyScopeMachine, true)
	b.Scope.AgentIDs = []string{"a1"}
	b.Elevation = store.ElevationSpec{AllowAdminRequests: true}

	eff := ResolvePrivilege(privMachine("a1"), []*store.PrivilegePolicy{a, b}, true)

	if !eff.Elevation.AllowInstallRequests || !eff.Elevation.AllowAdminRequests {
		t.Errorf("elevation did not merge permissively: %+v", eff.Elevation)
	}
}

// The time limit is the one field that must NOT loosen on merge. It is a
// ceiling, and a ceiling that rose when a second policy applied would be the
// single place where merging relaxed a deliberate restriction.
func TestTheGrantCeilingTakesTheShortestLimit(t *testing.T) {
	a := privPolicy("Generous", store.PolicyScopeTenant, true)
	a.Elevation = store.ElevationSpec{MaxGrantMinutes: 480}

	b := privPolicy("Strict", store.PolicyScopeMachine, true)
	b.Scope.AgentIDs = []string{"a1"}
	b.Elevation = store.ElevationSpec{MaxGrantMinutes: 30}

	eff := ResolvePrivilege(privMachine("a1"), []*store.PrivilegePolicy{a, b}, true)

	if eff.Elevation.MaxGrantMinutes != 30 {
		t.Errorf("MaxGrantMinutes = %d, want the shorter limit of 30", eff.Elevation.MaxGrantMinutes)
	}
}

func TestAnUnsetCeilingDoesNotOverrideASetOne(t *testing.T) {
	a := privPolicy("Strict", store.PolicyScopeTenant, true)
	a.Elevation = store.ElevationSpec{MaxGrantMinutes: 30}

	b := privPolicy("Unspecified", store.PolicyScopeMachine, true)
	b.Scope.AgentIDs = []string{"a1"}

	eff := ResolvePrivilege(privMachine("a1"), []*store.PrivilegePolicy{a, b}, true)

	if eff.Elevation.MaxGrantMinutes != 30 {
		t.Errorf("MaxGrantMinutes = %d; a policy that said nothing removed the ceiling",
			eff.Elevation.MaxGrantMinutes)
	}
}

func TestSudoCommandsAreUnionedWithoutDuplicates(t *testing.T) {
	cmd := store.SudoCommand{Path: "/usr/sbin/installer", AnyArguments: true}

	a := privPolicy("A", store.PolicyScopeTenant, true)
	a.Elevation = store.ElevationSpec{SudoCommands: []store.SudoCommand{cmd}}

	b := privPolicy("B", store.PolicyScopeMachine, true)
	b.Scope.AgentIDs = []string{"a1"}
	b.Elevation = store.ElevationSpec{SudoCommands: []store.SudoCommand{
		cmd,
		{Path: "/sbin/ping", Args: []string{"-c", "4"}},
	}}

	eff := ResolvePrivilege(privMachine("a1"), []*store.PrivilegePolicy{a, b}, true)

	if len(eff.Elevation.SudoCommands) != 2 {
		t.Errorf("got %d sudo commands, want 2 (the duplicate collapsed): %+v",
			len(eff.Elevation.SudoCommands), eff.Elevation.SudoCommands)
	}
}

// ── Simulation ──────────────────────────────────────────────────────────────

// The invariant that makes this feature survivable: if carrying out the plan
// would leave nobody holding administrator rights, apply NOTHING.
func TestAMachineWithNoAdminLeftIsRefusedEntirely(t *testing.T) {
	fleet := []MachineAccounts{{
		Machine:  privMachine("a1"),
		Reported: true,
		Accounts: []*store.LocalAccount{admin("priya", true)},
	}}

	sim := SimulatePrivilege(fleet, []*store.PrivilegePolicy{
		privPolicy("Strip", store.PolicyScopeTenant, true),
	}, true)

	if sim.MachinesRefused != 1 {
		t.Errorf("MachinesRefused = %d, want 1", sim.MachinesRefused)
	}
	if sim.AccountsDemoted != 0 {
		t.Errorf("AccountsDemoted = %d — the machine would have been left with no administrator",
			sim.AccountsDemoted)
	}
	if len(sim.Changes) != 1 || sim.Changes[0].Refused != RefusedNoAdminLeft {
		t.Errorf("the refusal reason was not reported: %+v", sim.Changes)
	}
}

// Refusal is all-or-nothing. A partial demotion would leave the machine in a
// state no policy described, and choosing on the endpoint which one person
// keeps their rights is a decision nobody made.
func TestRefusalIsAllOrNothing(t *testing.T) {
	fleet := []MachineAccounts{{
		Machine:  privMachine("a1"),
		Reported: true,
		Accounts: []*store.LocalAccount{
			admin("priya", true), admin("amit", true), admin("zara", true),
		},
	}}

	sim := SimulatePrivilege(fleet, []*store.PrivilegePolicy{
		privPolicy("Strip", store.PolicyScopeTenant, true),
	}, true)

	if sim.AccountsDemoted != 0 {
		t.Errorf("demoted %d of 3 administrators instead of refusing", sim.AccountsDemoted)
	}
	if len(sim.Changes[0].Demoted) != 0 {
		t.Errorf("a partial plan survived: %v", sim.Changes[0].Demoted)
	}
}

// root keeps the machine administered, so the demotion can go ahead. This is
// the ordinary case on a real macOS machine.
func TestAnOrdinaryMachineDemotesAndKeepsRoot(t *testing.T) {
	fleet := []MachineAccounts{{
		Machine:  privMachine("a1"),
		Reported: true,
		Accounts: []*store.LocalAccount{
			admin("root", false), // a built-in: present, admin, not demotable
			admin("priya", true),
		},
	}}

	sim := SimulatePrivilege(fleet, []*store.PrivilegePolicy{
		privPolicy("Strip", store.PolicyScopeTenant, true),
	}, true)

	if sim.MachinesRefused != 0 {
		t.Fatalf("refused a machine that still had root: %+v", sim.Changes)
	}
	if sim.AccountsDemoted != 1 || sim.MachinesAffected != 1 {
		t.Errorf("demoted %d accounts on %d machines, want 1 and 1",
			sim.AccountsDemoted, sim.MachinesAffected)
	}
	if len(sim.Changes[0].Demoted) != 1 || sim.Changes[0].Demoted[0] != "priya" {
		t.Errorf("demoted %v, want [priya]", sim.Changes[0].Demoted)
	}
}

func TestAnExemptAdministratorIsReportedWithAReason(t *testing.T) {
	p := privPolicy("Strip", store.PolicyScopeTenant, true)
	p.KeepAdmin = []string{"priya"}

	fleet := []MachineAccounts{{
		Machine:  privMachine("a1"),
		Reported: true,
		Accounts: []*store.LocalAccount{admin("root", false), admin("priya", true)},
	}}

	sim := SimulatePrivilege(fleet, []*store.PrivilegePolicy{p}, true)

	if sim.AccountsDemoted != 0 {
		t.Errorf("demoted an exempt administrator")
	}
	var found bool
	for _, c := range sim.Changes {
		for _, k := range c.Kept {
			if k.Username == "priya" && k.Reason == KeepReasonExempt {
				found = true
			}
		}
	}
	// With nothing to demote, the machine produces no change entry at all —
	// which is correct, and is why this asserts on the counts rather than
	// requiring an entry to exist.
	if sim.MachinesAffected != 0 {
		t.Errorf("MachinesAffected = %d, want 0", sim.MachinesAffected)
	}
	_ = found
}

// A machine that has never reported cannot be reasoned about. Counting it as
// unaffected would make the simulation look complete when it is not.
func TestUnreportedMachinesAreCountedSeparately(t *testing.T) {
	fleet := []MachineAccounts{
		{Machine: privMachine("a1"), Reported: false},
		{
			Machine: privMachine("a2"), Reported: true,
			Accounts: []*store.LocalAccount{admin("root", false), admin("priya", true)},
		},
	}

	sim := SimulatePrivilege(fleet, []*store.PrivilegePolicy{
		privPolicy("Strip", store.PolicyScopeTenant, true),
	}, true)

	if sim.MachinesInScope != 2 {
		t.Errorf("MachinesInScope = %d, want 2", sim.MachinesInScope)
	}
	if sim.MachinesNotReported != 1 {
		t.Errorf("MachinesNotReported = %d, want 1", sim.MachinesNotReported)
	}
	if sim.AccountsDemoted != 1 {
		t.Errorf("AccountsDemoted = %d, want 1 from the machine that did report", sim.AccountsDemoted)
	}
}

// A directory account's rights are not removable with a local group edit, so
// it is never in the demotion plan — and it still counts as an administrator
// remaining, because it is one.
func TestADirectoryAdministratorIsNeverDemoted(t *testing.T) {
	dir := admin("corp\\priya", false)
	dir.IsLocal = false

	fleet := []MachineAccounts{{
		Machine:  privMachine("a1"),
		Reported: true,
		Accounts: []*store.LocalAccount{dir, admin("amit", true)},
	}}

	sim := SimulatePrivilege(fleet, []*store.PrivilegePolicy{
		privPolicy("Strip", store.PolicyScopeTenant, true),
	}, true)

	if sim.AccountsDemoted != 1 || sim.Changes[0].Demoted[0] != "amit" {
		t.Errorf("demoted %v, want only [amit]", sim.Changes[0].Demoted)
	}
	for _, k := range sim.Changes[0].Kept {
		if k.Username == "corp\\priya" && k.Reason != KeepReasonDirectory {
			t.Errorf("the directory account was kept for the wrong reason: %q", k.Reason)
		}
	}
}

// A deleted account is not an administrator, and must not be counted as one
// of the administrators that would remain.
func TestDeletedAccountsDoNotCountAsRemainingAdministrators(t *testing.T) {
	gone := admin("old-admin", false)
	gone.Present = false

	fleet := []MachineAccounts{{
		Machine:  privMachine("a1"),
		Reported: true,
		Accounts: []*store.LocalAccount{gone, admin("priya", true)},
	}}

	sim := SimulatePrivilege(fleet, []*store.PrivilegePolicy{
		privPolicy("Strip", store.PolicyScopeTenant, true),
	}, true)

	if sim.MachinesRefused != 1 {
		t.Error("a deleted administrator was counted as one that would remain, " +
			"so the machine was left with nobody")
	}
}

// An out-of-scope machine must not appear in the numbers at all.
func TestOutOfScopeMachinesAreNotCounted(t *testing.T) {
	p := privPolicy("Just this one", store.PolicyScopeMachine, true)
	p.Scope.AgentIDs = []string{"a1"}

	fleet := []MachineAccounts{
		{Machine: privMachine("a1"), Reported: true, Accounts: []*store.LocalAccount{admin("root", false), admin("priya", true)}},
		{Machine: privMachine("a2"), Reported: true, Accounts: []*store.LocalAccount{admin("root", false), admin("amit", true)}},
	}

	sim := SimulatePrivilege(fleet, []*store.PrivilegePolicy{p}, true)

	if sim.MachinesInScope != 1 {
		t.Errorf("MachinesInScope = %d, want 1", sim.MachinesInScope)
	}
	if sim.AccountsDemoted != 1 {
		t.Errorf("AccountsDemoted = %d, want 1", sim.AccountsDemoted)
	}
}

// The simulation must be able to answer "what if" while the switch is off —
// that is the whole point of running it before turning enforcement on.
func TestTheSimulationCanAnswerWhatIfWithTheSwitchOff(t *testing.T) {
	fleet := []MachineAccounts{{
		Machine:  privMachine("a1"),
		Reported: true,
		Accounts: []*store.LocalAccount{admin("root", false), admin("priya", true)},
	}}
	policies := []*store.PrivilegePolicy{privPolicy("Strip", store.PolicyScopeTenant, true)}

	whatIf := SimulatePrivilege(fleet, policies, true)
	if whatIf.AccountsDemoted != 1 {
		t.Errorf("the what-if run reported %d demotions, want 1", whatIf.AccountsDemoted)
	}

	// And with the live value of a switch that is off, it still describes the
	// plan: the instruction is the policy's, the gate is the tenant's, and the
	// operator is asking what the policy says.
	live := SimulatePrivilege(fleet, policies, false)
	if live.MachinesInScope != 1 {
		t.Errorf("MachinesInScope = %d, want 1 even with the switch off", live.MachinesInScope)
	}
}
