package policy

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

func app(name, publisher string) *store.InstalledApp {
	return &store.InstalledApp{Name: name, Publisher: publisher}
}

func equals(values ...string) store.StringMatch {
	return store.StringMatch{Op: store.OpEquals, Values: values}
}

func rule(name, action string, match store.MatchCriteria) store.PolicyRule {
	return store.PolicyRule{ID: name, Name: name, Enabled: true, Action: action, Match: match}
}

func policy(name, scope string, priority int, rules ...store.PolicyRule) *store.AppPolicy {
	return &store.AppPolicy{
		ID: primitive.NewObjectID(), Name: name, Enabled: true,
		Scope: store.PolicyScope{Kind: scope}, Mode: store.ModeAudit,
		Priority: priority, DefaultAction: store.ActionAllow, Rules: rules,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func machine() *store.Machine {
	return &store.Machine{AgentID: "agent-1", TenantID: "t1", GroupIDs: []string{"g1"}}
}

// The single most important rule in this package. A rule saved from a
// half-filled form must not match every application on every machine — if its
// action were block, that is a fleet-wide outage authored by a mis-click.
func TestEmptyCriteriaMatchNothing(t *testing.T) {
	eff := Resolve(machine(), []*store.AppPolicy{
		policy("careless", store.PolicyScopeTenant, 0,
			rule("blank", store.ActionBlock, store.MatchCriteria{})),
	}, false)

	for _, a := range []*store.InstalledApp{
		app("Google Chrome", "Google LLC"),
		app("", ""),
		app("Anything At All", "Anyone"),
	} {
		d := eff.Decide(a)
		if d.Matched {
			t.Errorf("%q matched an empty rule", a.Name)
		}
		if d.Action != store.ActionAllow {
			t.Errorf("%q resolved to %q, want the default", a.Name, d.Action)
		}
	}
}

// Populated fields are ANDed. A rule naming both a product and a publisher
// must not fire on a different product from the same publisher.
func TestFieldsAreAnded(t *testing.T) {
	eff := Resolve(machine(), []*store.AppPolicy{
		policy("p", store.PolicyScopeTenant, 0,
			rule("chrome-by-google", store.ActionBlock, store.MatchCriteria{
				AppName: equals("Google Chrome"), Publisher: equals("Google LLC"),
			})),
	}, false)

	if !eff.Decide(app("Google Chrome", "Google LLC")).Matched {
		t.Error("the rule did not match the application it names")
	}
	if eff.Decide(app("Google Earth", "Google LLC")).Matched {
		t.Error("the rule matched a different product from the same publisher")
	}
	if eff.Decide(app("Google Chrome", "Someone Else")).Matched {
		t.Error("the rule matched a repackaged build from another publisher")
	}
}

// Values within one field are ORed, so one rule can name several products.
func TestValuesWithinAFieldAreOred(t *testing.T) {
	eff := Resolve(machine(), []*store.AppPolicy{
		policy("p", store.PolicyScopeTenant, 0,
			rule("games", store.ActionBlock, store.MatchCriteria{
				AppName: equals("Steam", "Epic Games Launcher"),
			})),
	}, false)

	for _, name := range []string{"Steam", "Epic Games Launcher"} {
		if !eff.Decide(app(name, "")).Matched {
			t.Errorf("%q was not matched", name)
		}
	}
	if eff.Decide(app("Slack", "")).Matched {
		t.Error("an unlisted application was matched")
	}
}

// Registries and filesystems report inconsistent casing. A rule that misses
// because of it fails silently, which is the worst outcome here.
func TestMatchingIsCaseInsensitiveByDefault(t *testing.T) {
	eff := Resolve(machine(), []*store.AppPolicy{
		policy("p", store.PolicyScopeTenant, 0,
			rule("r", store.ActionBlock, store.MatchCriteria{AppName: equals("google chrome")})),
	}, false)

	if !eff.Decide(app("GOOGLE CHROME", "")).Matched {
		t.Error("a differently-cased name was not matched")
	}
}

// Precedence: machine beats group beats tenant.
func TestMoreSpecificScopeWins(t *testing.T) {
	m := machine()
	tenant := policy("tenant-blocks", store.PolicyScopeTenant, 0,
		rule("block", store.ActionBlock, store.MatchCriteria{AppName: equals("Zoom")}))
	group := policy("group-elevates", store.PolicyScopeGroup, 0,
		rule("elevate", store.ActionElevate, store.MatchCriteria{AppName: equals("Zoom")}))
	group.Scope.GroupIDs = []string{"g1"}
	machinePol := policy("machine-allows", store.PolicyScopeMachine, 0,
		rule("allow", store.ActionAllow, store.MatchCriteria{AppName: equals("Zoom")}))
	machinePol.Scope.AgentIDs = []string{"agent-1"}

	// Deliberately passed in the "wrong" order — resolution must not depend on
	// the order the database happened to return rows in.
	eff := Resolve(m, []*store.AppPolicy{tenant, group, machinePol}, false)

	d := eff.Decide(app("Zoom", ""))
	if d.Action != store.ActionAllow || d.PolicyName != "machine-allows" {
		t.Errorf("decided %q from %q, want allow from machine-allows", d.Action, d.PolicyName)
	}

	// Without the machine-scoped one, the group should win over the tenant.
	eff = Resolve(m, []*store.AppPolicy{tenant, group}, false)
	if d := eff.Decide(app("Zoom", "")); d.Action != store.ActionElevate {
		t.Errorf("decided %q, want the group policy to beat the tenant", d.Action)
	}
}

func TestPolicyScopedToAnotherMachineIsIgnored(t *testing.T) {
	other := policy("someone-else", store.PolicyScopeMachine, 0,
		rule("block", store.ActionBlock, store.MatchCriteria{AppName: equals("Zoom")}))
	other.Scope.AgentIDs = []string{"agent-999"}

	eff := Resolve(machine(), []*store.AppPolicy{other}, false)
	if d := eff.Decide(app("Zoom", "")); d.Matched {
		t.Error("a policy aimed at a different machine was applied")
	}
}

func TestPolicyForAGroupTheMachineIsNotInIsIgnored(t *testing.T) {
	other := policy("other-group", store.PolicyScopeGroup, 0,
		rule("block", store.ActionBlock, store.MatchCriteria{AppName: equals("Zoom")}))
	other.Scope.GroupIDs = []string{"g-other"}

	eff := Resolve(machine(), []*store.AppPolicy{other}, false)
	if d := eff.Decide(app("Zoom", "")); d.Matched {
		t.Error("a policy for a group this machine is not in was applied")
	}
}

func TestDisabledPoliciesAndRulesAreIgnored(t *testing.T) {
	off := policy("off", store.PolicyScopeTenant, 0,
		rule("block", store.ActionBlock, store.MatchCriteria{AppName: equals("Zoom")}))
	off.Enabled = false

	withDisabledRule := policy("on", store.PolicyScopeTenant, 0,
		store.PolicyRule{ID: "r", Name: "r", Enabled: false, Action: store.ActionBlock,
			Match: store.MatchCriteria{AppName: equals("Slack")}})

	eff := Resolve(machine(), []*store.AppPolicy{off, withDisabledRule}, false)
	if eff.Decide(app("Zoom", "")).Matched {
		t.Error("a disabled policy was applied")
	}
	if eff.Decide(app("Slack", "")).Matched {
		t.Error("a disabled rule was applied")
	}
}

// First match wins, top to bottom. An exception has to be placed above the
// broad rule it carves out of.
func TestFirstMatchWins(t *testing.T) {
	eff := Resolve(machine(), []*store.AppPolicy{
		policy("p", store.PolicyScopeTenant, 0,
			rule("allow-ours", store.ActionAllow, store.MatchCriteria{Publisher: equals("Acme")}),
			rule("block-everything-else", store.ActionBlock, store.MatchCriteria{AppName: store.StringMatch{Op: store.OpWildcard, Values: []string{"*"}}}),
		),
	}, false)

	if d := eff.Decide(app("Acme Tool", "Acme")); d.Action != store.ActionAllow {
		t.Errorf("decided %q for the carve-out, want allow", d.Action)
	}
	if d := eff.Decide(app("Random Thing", "Someone")); d.Action != store.ActionBlock {
		t.Errorf("decided %q for everything else, want block", d.Action)
	}
}

// Without an explicit fall-through there is no way to say "this one is an
// exception" other than reordering, which is not always possible.
func TestDefaultActionRuleFallsThrough(t *testing.T) {
	p := policy("p", store.PolicyScopeTenant, 0,
		rule("exempt", store.ActionDefault, store.MatchCriteria{AppName: equals("Slack")}),
		rule("block-rest", store.ActionBlock, store.MatchCriteria{AppName: store.StringMatch{Op: store.OpWildcard, Values: []string{"*"}}}),
	)
	p.DefaultAction = store.ActionAllow

	eff := Resolve(machine(), []*store.AppPolicy{p}, false)

	d := eff.Decide(app("Slack", ""))
	if d.Action != store.ActionAllow || d.Matched {
		t.Errorf("decided %q (matched=%v), want the default to apply", d.Action, d.Matched)
	}
	if d := eff.Decide(app("Other", "")); d.Action != store.ActionBlock {
		t.Errorf("decided %q for an unexempt app, want block", d.Action)
	}
}

// Phase A must never resolve to enforce, whatever the stored policies say.
// This is the one switch standing between a policy bug and somebody's laptop.
func TestEnforcementIsOffUntilExplicitlyEnabled(t *testing.T) {
	p := policy("p", store.PolicyScopeTenant, 0,
		rule("block", store.ActionBlock, store.MatchCriteria{AppName: equals("Zoom")}))
	p.Mode = store.ModeEnforce

	eff := Resolve(machine(), []*store.AppPolicy{p}, false)
	if eff.Mode != store.ModeAudit {
		t.Fatalf("Mode = %q with enforcement off, want audit", eff.Mode)
	}
	if d := eff.Decide(app("Zoom", "")); d.Mode != store.ModeAudit {
		t.Errorf("decision Mode = %q, want audit", d.Mode)
	}

	// And that it does flip when deliberately turned on.
	if on := Resolve(machine(), []*store.AppPolicy{p}, true); on.Mode != store.ModeEnforce {
		t.Errorf("Mode = %q with enforcement on, want enforce", on.Mode)
	}
}

// Enabling application control must not brick every machine.
func TestNoPolicyMeansAllow(t *testing.T) {
	eff := Resolve(machine(), nil, false)
	if d := eff.Decide(app("Anything", "")); d.Action != store.ActionAllow {
		t.Errorf("decided %q with no policy at all, want allow", d.Action)
	}
}

// A machine in two groups whose policies disagree gets a deterministic answer
// AND is told that it was arbitrary, rather than discovering it mid-incident.
func TestConflictingGroupPoliciesAreReported(t *testing.T) {
	m := machine()
	m.GroupIDs = []string{"finance", "engineering"}

	a := policy("finance-blocks", store.PolicyScopeGroup, 10,
		rule("block-zoom", store.ActionBlock, store.MatchCriteria{AppName: equals("Zoom")}))
	a.Scope.GroupIDs = []string{"finance"}
	b := policy("engineering-allows", store.PolicyScopeGroup, 5,
		rule("allow-zoom", store.ActionAllow, store.MatchCriteria{AppName: equals("Zoom")}))
	b.Scope.GroupIDs = []string{"engineering"}

	eff := Resolve(m, []*store.AppPolicy{b, a}, false)

	if d := eff.Decide(app("Zoom", "")); d.Action != store.ActionBlock {
		t.Errorf("decided %q, want the higher-priority group to win", d.Action)
	}
	if len(eff.Conflicts) == 0 {
		t.Fatal("the disagreement between two groups was not reported")
	}
	if eff.Conflicts[0].PolicyA != "finance-blocks" {
		t.Errorf("conflict names %q as the winner", eff.Conflicts[0].PolicyA)
	}
}

// Two policies identical in scope, priority and creation time must still
// resolve the same way every time — never depending on database row order.
func TestResolutionIsDeterministic(t *testing.T) {
	a := policy("a", store.PolicyScopeTenant, 0,
		rule("r", store.ActionBlock, store.MatchCriteria{AppName: equals("Zoom")}))
	b := policy("b", store.PolicyScopeTenant, 0,
		rule("r", store.ActionAllow, store.MatchCriteria{AppName: equals("Zoom")}))

	first := Resolve(machine(), []*store.AppPolicy{a, b}, false).Decide(app("Zoom", ""))
	second := Resolve(machine(), []*store.AppPolicy{b, a}, false).Decide(app("Zoom", ""))

	if first.Action != second.Action || first.PolicyID != second.PolicyID {
		t.Errorf("the same inputs in a different order decided differently: %+v vs %+v", first, second)
	}
}

// An operator has to be able to see why a machine has the policy it has.
func TestEffectiveRulesCarryTheirOrigin(t *testing.T) {
	p := policy("named-policy", store.PolicyScopeTenant, 0,
		rule("named-rule", store.ActionBlock, store.MatchCriteria{AppName: equals("Zoom")}))

	d := Resolve(machine(), []*store.AppPolicy{p}, false).Decide(app("Zoom", ""))
	if d.PolicyName != "named-policy" || d.RuleName != "named-rule" || d.Scope != store.PolicyScopeTenant {
		t.Errorf("decision does not say where it came from: %+v", d)
	}
}
