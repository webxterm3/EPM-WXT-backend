package api

import (
	"strings"
	"testing"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

func draft(mutate func(*store.AppPolicy)) store.AppPolicy {
	p := store.AppPolicy{
		Name:  "Block games",
		Scope: store.PolicyScope{Kind: store.PolicyScopeTenant},
		Rules: []store.PolicyRule{{
			Name: "steam", Enabled: true, Action: store.ActionBlock,
			Match: store.MatchCriteria{AppName: store.StringMatch{
				Op: store.OpEquals, Values: []string{"Steam"},
			}},
		}},
	}
	if mutate != nil {
		mutate(&p)
	}
	return p
}

func TestPreparePolicyAcceptsAValidPolicy(t *testing.T) {
	p, err := preparePolicy(draft(nil), "t1", "admin")
	if err != nil {
		t.Fatalf("a valid policy was rejected: %v", err)
	}
	if p.TenantID != "t1" {
		t.Errorf("TenantID = %q", p.TenantID)
	}
	// A rule with no id cannot be cited by a simulation result or an audit
	// entry once the list is reordered.
	if p.Rules[0].ID == "" {
		t.Error("the rule was stored without a stable id")
	}
}

// Saving a rule with no criteria would leave an operator looking at something
// that silently does nothing. The matcher also fails closed, but that protects
// the fleet rather than informing the person.
func TestRuleWithNoCriteriaIsRejected(t *testing.T) {
	_, err := preparePolicy(draft(func(p *store.AppPolicy) {
		p.Rules[0].Match = store.MatchCriteria{}
	}), "t1", "admin")

	if err == nil {
		t.Fatal("a rule with no criteria was accepted")
	}
	if !strings.Contains(err.Error(), "match nothing") {
		t.Errorf("error %q does not explain that the rule would do nothing", err)
	}
}

// Phase A never enforces, and a policy that defaults to block would take a
// fleet out the moment enforcement was switched on.
func TestDefaultsAreSafe(t *testing.T) {
	p, err := preparePolicy(draft(func(d *store.AppPolicy) {
		d.Mode = ""
		d.DefaultAction = ""
	}), "t1", "admin")
	if err != nil {
		t.Fatal(err)
	}

	if p.Mode != store.ModeAudit {
		t.Errorf("Mode = %q, want audit", p.Mode)
	}
	if p.DefaultAction != store.ActionAllow {
		t.Errorf("DefaultAction = %q, want allow", p.DefaultAction)
	}
}

// Enforcement is what stands between a policy bug and somebody's laptop, so
// every way of failing to find out whether it is on has to answer "off".
//
// The dangerous direction is only one of them: reporting enforcement as on
// when it is off is a cosmetic bug in the portal, while reporting it as off —
// or resolving it as off — when it should be on is a policy nobody is
// enforcing. But a handler with nothing wired in must not reach for a default
// of true, and this pins that.
func TestEnforcementFailsClosed(t *testing.T) {
	// No pusher: the server is half-built, or this is a code path that was
	// never given one.
	h := &Handler{}
	if h.enforcementEnabled("t1") {
		t.Error("a handler with no policy pusher reported enforcement as on")
	}
	// No tenant on the request.
	if h.enforcementEnabled("") {
		t.Error("a request with no tenant reported enforcement as on")
	}
}

// A policy may ask to enforce; whether it does is the tenant's switch.
//
// preparePolicy must keep accepting enforce as a stored mode — the resolver is
// what gates it — or turning the tenant switch on would find every policy
// permanently pinned to audit.
func TestAPolicyMayAskToEnforce(t *testing.T) {
	p, err := preparePolicy(draft(func(p *store.AppPolicy) { p.Mode = store.ModeEnforce }), "t1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != store.ModeEnforce {
		t.Errorf("Mode = %q, want enforce to be preserved", p.Mode)
	}
}

func TestScopeMustNameItsTargets(t *testing.T) {
	cases := map[string]func(*store.AppPolicy){
		"group scope with no groups":   func(p *store.AppPolicy) { p.Scope = store.PolicyScope{Kind: store.PolicyScopeGroup} },
		"machine scope with no agents": func(p *store.AppPolicy) { p.Scope = store.PolicyScope{Kind: store.PolicyScopeMachine} },
		"unknown scope":                func(p *store.AppPolicy) { p.Scope = store.PolicyScope{Kind: "everything"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := preparePolicy(draft(mutate), "t1", "admin"); err == nil {
				t.Error("accepted a scope that names nothing")
			}
		})
	}
}

// A tenant-wide policy carrying stray group or machine ids would be confusing
// to read and could become wrong if the scope were later changed.
func TestTenantScopeClearsStrayTargets(t *testing.T) {
	p, err := preparePolicy(draft(func(d *store.AppPolicy) {
		d.Scope = store.PolicyScope{
			Kind: store.PolicyScopeTenant, GroupIDs: []string{"g1"}, AgentIDs: []string{"a1"},
		}
	}), "t1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Scope.GroupIDs) != 0 || len(p.Scope.AgentIDs) != 0 {
		t.Errorf("stray targets survived on a tenant-scoped policy: %+v", p.Scope)
	}
}

func TestUnknownActionIsRejected(t *testing.T) {
	_, err := preparePolicy(draft(func(p *store.AppPolicy) {
		p.Rules[0].Action = "quarantine"
	}), "t1", "admin")
	if err == nil {
		t.Fatal("an unknown action was accepted")
	}
}

func TestPolicyNeedsAName(t *testing.T) {
	for _, name := range []string{"", "   "} {
		if _, err := preparePolicy(draft(func(p *store.AppPolicy) { p.Name = name }), "t1", "admin"); err == nil {
			t.Errorf("accepted a policy named %q", name)
		}
	}
}

// The tenant comes from the authenticated session, never from the body —
// otherwise a crafted request writes into somebody else's tenant.
func TestTenantIsTakenFromTheSessionNotTheBody(t *testing.T) {
	p, err := preparePolicy(draft(func(d *store.AppPolicy) {
		d.TenantID = "someone-elses-tenant"
	}), "t1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if p.TenantID != "t1" {
		t.Errorf("TenantID = %q — a request body must not choose its own tenant", p.TenantID)
	}
}
