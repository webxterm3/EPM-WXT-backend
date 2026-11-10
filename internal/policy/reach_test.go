package policy

import (
	"testing"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// A machine-scoped policy names AGENT IDs, and an agent ID belongs to one
// ENROLMENT rather than to a Mac. Re-enrol the machine and it gets a new
// one, while the policy goes on naming the old.
//
// Nothing fails when that happens, which is the problem. The resolver
// correctly finds no policy for the machine; the agent correctly reports
// "no rule covers this"; the approval route correctly offers to ask. The
// only visible symptom is software somebody believes they blocked asking to
// be approved — and every screen still shows the policy as enabled and
// enforcing, because every screen reads the policy rather than asking who
// it reaches.
func TestAPolicyPinnedToAnOldEnrolmentReachesNobody(t *testing.T) {
	// The exact shape this was found in: the policy names the id from
	// before the Mac was re-enrolled.
	p := &store.AppPolicy{
		Name: "Block Claude", Enabled: true,
		Scope: store.PolicyScope{
			Kind: store.PolicyScopeMachine, AgentIDs: []string{"super-admin-74f699fe"},
		},
	}
	live := &store.Machine{AgentID: "super-admin-1639100b"}

	if AppliesTo(p, live) {
		t.Fatal("a policy naming a dead agent id was reported as reaching the live machine")
	}

	// And it still reaches the machine it does name, so the count is a
	// measure of reach rather than a blanket "machine scopes are broken".
	old := &store.Machine{AgentID: "super-admin-74f699fe"}
	if !AppliesTo(p, old) {
		t.Error("the policy does not reach the machine it names")
	}
}

// The exported name and the one the resolver uses must be the same
// function. Two implementations would be two opinions about which machines
// a policy covers — and the count exists precisely to say when the
// resolver's opinion is "none".
func TestTheReachCountAgreesWithTheResolver(t *testing.T) {
	tenantWide := &store.AppPolicy{
		Name: "Everywhere", Enabled: true,
		Scope:   store.PolicyScope{Kind: store.PolicyScopeTenant},
		Rules:   []store.PolicyRule{{Name: "r", Enabled: true, Action: store.ActionBlock}},
		Mode:    store.ModeEnforce,
	}
	m := &store.Machine{AgentID: "a1", TenantID: "t"}

	reaches := AppliesTo(tenantWide, m)
	resolved := Resolve(m, []*store.AppPolicy{tenantWide}, true)

	if reaches != (len(resolved.Rules) > 0) {
		t.Fatalf("AppliesTo says %v but the resolver produced %d rules — the "+
			"count and the decision disagree", reaches, len(resolved.Rules))
	}
}

// A policy scoped to a machine that no longer exists resolves to nothing,
// which is what the agent reported: mode audit, default allow, rules 0.
func TestADeadScopeResolvesToNoRules(t *testing.T) {
	p := &store.AppPolicy{
		Name: "Block Claude", Enabled: true, Mode: store.ModeEnforce,
		Scope: store.PolicyScope{
			Kind: store.PolicyScopeMachine, AgentIDs: []string{"gone"},
		},
		Rules: []store.PolicyRule{{Name: "Block Claude", Enabled: true, Action: store.ActionBlock}},
	}
	eff := Resolve(&store.Machine{AgentID: "live"}, []*store.AppPolicy{p}, true)

	if len(eff.Rules) != 0 {
		t.Fatalf("a policy scoped to a machine that does not exist produced %d rules",
			len(eff.Rules))
	}
	if eff.DefaultAction != store.ActionAllow {
		t.Errorf("default action = %q, want allow", eff.DefaultAction)
	}
}
