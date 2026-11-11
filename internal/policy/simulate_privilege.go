package policy

import (
	"sort"
	"strings"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// Least-privilege simulation.
//
// This answers the question that has to be answerable before anybody switches
// enforcement on: if I save this, whose administrator rights come off, on
// which machines, and where would it refuse?
//
// It runs entirely against the reported account inventory. No agent is
// contacted and nothing is delivered to any endpoint.
//
// Its honest limit, which the UI states: an inventory is what each machine
// last reported. A machine that has not reported is not in these numbers at
// all, and one whose report is a week old is counted as it was a week ago.

// PrivilegeSimulation is what a draft policy would do across the fleet.
type PrivilegeSimulation struct {
	// MachinesInScope is how many machines the policy reaches at all.
	MachinesInScope int `json:"machines_in_scope"`

	// MachinesAffected is how many would actually lose an administrator.
	//
	// Separate from the above because the gap is the useful part: a policy
	// reaching 200 machines and changing 3 is a very different proposition
	// from one reaching 200 and changing 200, and the scope count alone
	// cannot tell them apart.
	MachinesAffected int `json:"machines_affected"`

	// AccountsDemoted is the headline number: how many accounts lose rights.
	AccountsDemoted int `json:"accounts_demoted"`

	// AccountsExempt is how many administrators are deliberately left alone,
	// by an exemption or by being a built-in.
	AccountsExempt int `json:"accounts_exempt"`

	// MachinesRefused is where the endpoint would apply nothing because
	// demoting would leave no administrator at all.
	//
	// Surfaced as its own number rather than folded into "unaffected",
	// because it is not the policy declining to act — it is the safety
	// invariant stopping it, and it means those machines need a break-glass
	// account before this policy can do anything there.
	MachinesRefused int `json:"machines_refused"`

	// MachinesNotReported have no account inventory, so nothing can be said
	// about them. Counted and shown rather than quietly excluded, because
	// every number above is only as complete as this one is small.
	MachinesNotReported int `json:"machines_not_reported"`

	// Changes lists what would happen, for the drill-down.
	Changes []PrivilegeChange `json:"changes"`
}

// PrivilegeChange is one machine's outcome.
type PrivilegeChange struct {
	AgentID     string `json:"agent_id"`
	MachineName string `json:"machine_name"`

	// Demoted names the accounts that would lose administrator rights.
	Demoted []string `json:"demoted,omitempty"`

	// Kept names the administrators left alone, with why.
	Kept []KeptAccount `json:"kept,omitempty"`

	// Refused is set when the invariant stopped the whole machine, and says
	// which invariant.
	Refused string `json:"refused,omitempty"`
}

// KeptAccount is one administrator the policy would not touch, and why.
type KeptAccount struct {
	Username string `json:"username"`
	Reason   string `json:"reason"`
}

// Reasons an administrator keeps their rights.
const (
	KeepReasonExempt     = "named in the policy's exemptions"
	KeepReasonBreakGlass = "the break-glass account"
	KeepReasonBuiltIn    = "a built-in system account"
	KeepReasonDirectory  = "a directory account, not local to this machine"
)

// RefusedNoAdminLeft is the invariant that makes this feature survivable.
const RefusedNoAdminLeft = "no administrator would remain on this machine"

// MachineAccounts pairs a machine with what it reported.
//
// The simulation takes this rather than reading a store, so it stays pure and
// so the same function can be driven by a test with no database.
type MachineAccounts struct {
	Machine  *store.Machine
	Accounts []*store.LocalAccount

	// Reported distinguishes a machine with no accounts — which is never
	// true — from one that has never sent a snapshot.
	Reported bool
}

// SimulatePrivilege reports what a set of policies would do across the fleet.
//
// enforcementEnabled is passed through to the resolver and is deliberately
// NOT forced on. A simulation run with the tenant switch off must show what
// would happen if it were on, so the caller passes true to ask "what if";
// passing the live value answers "what is actually about to happen". Both
// questions are real and the function does not choose between them.
func SimulatePrivilege(fleet []MachineAccounts, policies []*store.PrivilegePolicy, enforcementEnabled bool) PrivilegeSimulation {
	sim := PrivilegeSimulation{}

	for _, entry := range fleet {
		if entry.Machine == nil {
			continue
		}

		eff := ResolvePrivilege(entry.Machine, policies, enforcementEnabled)
		if len(eff.Sources) == 0 {
			continue
		}
		sim.MachinesInScope++

		if !entry.Reported {
			sim.MachinesNotReported++
			continue
		}
		if !eff.DemoteAdmins {
			continue
		}

		change := planMachine(entry, eff)

		switch {
		case change.Refused != "":
			sim.MachinesRefused++
		case len(change.Demoted) > 0:
			sim.MachinesAffected++
			sim.AccountsDemoted += len(change.Demoted)
		}
		sim.AccountsExempt += len(change.Kept)

		if change.Refused != "" || len(change.Demoted) > 0 {
			sim.Changes = append(sim.Changes, change)
		}
	}

	// Most-affected first: an operator reviewing this wants the machines that
	// change most, not the alphabetical order the fleet happened to load in.
	sort.SliceStable(sim.Changes, func(i, j int) bool {
		return len(sim.Changes[i].Demoted) > len(sim.Changes[j].Demoted)
	})
	return sim
}

// planMachine works out one machine's outcome.
//
// This is the same decision the endpoint makes, written once here so the
// number an operator reviews is the number that will happen. The endpoint
// re-runs the invariants against the live account database at the moment of
// the change and wins any disagreement — a machine where somebody granted
// themselves admin since the last scan is exactly the case the endpoint can
// see and this cannot.
func planMachine(entry MachineAccounts, eff EffectivePrivilege) PrivilegeChange {
	change := PrivilegeChange{
		AgentID:     entry.Machine.AgentID,
		MachineName: entry.Machine.Name,
	}

	remaining := 0
	for _, acc := range entry.Accounts {
		if acc == nil || !acc.Present || !acc.IsAdmin {
			continue
		}

		if reason, kept := keepReason(acc, eff); kept {
			change.Kept = append(change.Kept, KeptAccount{Username: acc.Username, Reason: reason})
			remaining++
			continue
		}
		change.Demoted = append(change.Demoted, acc.Username)
	}

	// The invariant. If carrying out the plan would leave nobody holding
	// administrator rights, the endpoint applies NOTHING — not a partial
	// demotion, not all-but-one. A partial application would be a machine in
	// a state no policy described, and deciding on the endpoint which one
	// person keeps their rights is a decision nobody made.
	if len(change.Demoted) > 0 && remaining == 0 {
		change.Refused = RefusedNoAdminLeft
		change.Demoted = nil
	}
	return change
}

// keepReason reports whether an administrator keeps their rights, and why.
//
// The order is the order of certainty, not of importance: Demotable is the
// endpoint's own answer and already covers built-ins and directory accounts,
// so it is asked first and the reason is then narrowed for display.
func keepReason(acc *store.LocalAccount, eff EffectivePrivilege) (string, bool) {
	if eff.BreakGlass.Enabled && strings.EqualFold(acc.Username, eff.BreakGlass.Username) {
		return KeepReasonBreakGlass, true
	}
	if eff.KeepsAdmin(acc.Username) {
		return KeepReasonExempt, true
	}
	if !acc.IsLocal {
		return KeepReasonDirectory, true
	}
	if !acc.Demotable {
		return KeepReasonBuiltIn, true
	}
	return "", false
}
