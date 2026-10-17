package policy

import (
	"sort"
	"strings"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// scopeRank orders policies from least to most specific. A policy aimed at one
// machine beats one aimed at its group, which beats one aimed at the tenant.
func scopeRank(kind string) int {
	switch kind {
	case store.PolicyScopeMachine:
		return 300
	case store.PolicyScopeGroup:
		return 200
	default:
		return 100
	}
}

// EffectiveRule is one rule flattened into a machine's evaluation order,
// carrying where it came from so an operator can be told WHY a decision was
// made rather than only what it was.
type EffectiveRule struct {
	Rule       store.PolicyRule `json:"rule"`
	PolicyID   string           `json:"policy_id"`
	PolicyName string           `json:"policy_name"`
	Scope      string           `json:"scope"`
	Mode       string           `json:"mode"`

	// RemoveBlocked carries the owning policy's choice about how hard a block
	// should bite. It travels on the RULE because rules from several policies
	// are flattened into one ordered list, and by the time the endpoint makes
	// a decision there is no policy left to ask.
	RemoveBlocked bool `json:"remove_blocked,omitempty"`
}

// Effective is everything that applies to one machine, in evaluation order.
type Effective struct {
	AgentID  string `json:"agent_id"`
	TenantID string `json:"tenant_id"`

	// Mode is the strongest mode any contributing policy asked for, or audit
	// whenever the tenant's enforcement switch is off.
	Mode string `json:"mode"`

	DefaultAction string          `json:"default_action"`
	Rules         []EffectiveRule `json:"rules"`
	Sources       []Source        `json:"sources"`
	Conflicts     []Conflict      `json:"conflicts,omitempty"`
}

// Source is one policy that contributed, in the order it contributed.
type Source struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Scope      string `json:"scope"`
	Priority   int    `json:"priority"`
}

// Conflict records two same-tier policies disagreeing.
//
// It is reported rather than resolved silently, and rather than rejected at
// save time: a machine's group membership changes without anyone touching the
// policy, so a conflict can appear hours after a save. A save-time check would
// be a guarantee that does not hold.
type Conflict struct {
	Scope       string `json:"scope"`
	PolicyA     string `json:"policy_a"`
	PolicyB     string `json:"policy_b"`
	RuleA       string `json:"rule_a"`
	RuleB       string `json:"rule_b"`
	Explanation string `json:"explanation"`
}

// Decision is what a policy says about one application.
type Decision struct {
	Action     string `json:"action"`
	RuleID     string `json:"rule_id,omitempty"`
	RuleName   string `json:"rule_name,omitempty"`
	PolicyID   string `json:"policy_id,omitempty"`
	PolicyName string `json:"policy_name,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Mode       string `json:"mode"`
	// Matched is false when no rule applied and DefaultAction was used.
	Matched bool `json:"matched"`
}

// appliesTo reports whether a policy covers a machine.
func appliesTo(p *store.AppPolicy, machine *store.Machine) bool {
	switch p.Scope.Kind {
	case store.PolicyScopeMachine:
		for _, id := range p.Scope.AgentIDs {
			if id == machine.AgentID {
				return true
			}
		}
		return false

	case store.PolicyScopeGroup:
		for _, want := range p.Scope.GroupIDs {
			for _, has := range machine.GroupIDs {
				if want == has {
					return true
				}
			}
		}
		return false

	default:
		return true
	}
}

// Resolve produces the policy in force for one machine.
//
// Pure: no I/O, no clock. Every caller — the admin-save push, the on-connect
// push, and simulation — goes through this one function, so they cannot
// disagree about what a machine's policy is.
//
// Ordering is total and deterministic:
//
//  1. scope specificity: machine, then group, then tenant
//  2. priority, descending
//  3. creation time, ascending — an older policy wins, so adding a new one is
//     non-disruptive by default
//  4. id, ascending — an absolute tiebreak, so the answer never depends on the
//     order the database happened to return rows in
//
// Rules are then concatenated in that order and the first match wins.
func Resolve(machine *store.Machine, policies []*store.AppPolicy, enforcementEnabled bool) Effective {
	eff := Effective{
		AgentID:  machine.AgentID,
		TenantID: machine.TenantID,
		Mode:     store.ModeAudit,
		// Allow unless a rule says otherwise. A default of block would mean
		// that enabling application control at all bricks every machine.
		DefaultAction: store.ActionAllow,
	}

	applicable := make([]*store.AppPolicy, 0, len(policies))
	for _, p := range policies {
		if p.Enabled && appliesTo(p, machine) {
			applicable = append(applicable, p)
		}
	}
	if len(applicable) == 0 {
		return eff
	}

	sort.SliceStable(applicable, func(i, j int) bool {
		a, b := applicable[i], applicable[j]
		if ra, rb := scopeRank(a.Scope.Kind), scopeRank(b.Scope.Kind); ra != rb {
			return ra > rb
		}
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		return a.ID.Hex() < b.ID.Hex()
	})

	for _, p := range applicable {
		eff.Sources = append(eff.Sources, Source{
			PolicyID: p.ID.Hex(), PolicyName: p.Name,
			Scope: p.Scope.Kind, Priority: p.Priority,
		})

		// The most specific policy decides the fallback, which is the first
		// one in this order.
		if len(eff.Sources) == 1 && p.DefaultAction != "" {
			eff.DefaultAction = p.DefaultAction
		}

		mode := p.Mode
		if mode == "" {
			mode = store.ModeAudit
		}
		for _, rule := range p.Rules {
			if !rule.Enabled {
				continue
			}
			eff.Rules = append(eff.Rules, EffectiveRule{
				Rule: rule, PolicyID: p.ID.Hex(), PolicyName: p.Name,
				Scope: p.Scope.Kind, Mode: mode,
				RemoveBlocked: p.RemoveBlocked,
			})
		}
	}

	eff.Conflicts = findConflicts(applicable)

	// The tenant's enforcement switch is read here, in one place, so that a
	// bug anywhere else in the policy path still cannot block anybody's
	// software. While it is off, every policy resolves to audit however its
	// own Mode is set — and the endpoint is SENT audit, rather than being
	// trusted to work that out for itself.
	if enforcementEnabled {
		eff.Mode = strongestMode(eff.Rules)
	}
	return eff
}

// strongestMode returns enforce when any contributing rule asked for it.
func strongestMode(rules []EffectiveRule) string {
	for _, r := range rules {
		if r.Mode == store.ModeEnforce {
			return store.ModeEnforce
		}
	}
	return store.ModeAudit
}

// findConflicts reports same-tier policies that disagree.
//
// Specifically the multi-group case: a machine in two groups, where one
// group's policy allows something another blocks. Priority decides, which is
// deterministic but arbitrary from the operator's point of view — so they are
// told it happened instead of discovering it during an incident.
func findConflicts(ordered []*store.AppPolicy) []Conflict {
	var out []Conflict

	for i := 0; i < len(ordered); i++ {
		for j := i + 1; j < len(ordered); j++ {
			a, b := ordered[i], ordered[j]
			if a.Scope.Kind != b.Scope.Kind || a.Scope.Kind != store.PolicyScopeGroup {
				continue
			}
			for _, ra := range a.Rules {
				for _, rb := range b.Rules {
					if !ra.Enabled || !rb.Enabled || ra.Action == rb.Action {
						continue
					}
					if !overlapping(ra.Match, rb.Match) {
						continue
					}
					out = append(out, Conflict{
						Scope:   store.PolicyScopeGroup,
						PolicyA: a.Name, PolicyB: b.Name,
						RuleA: ra.Name, RuleB: rb.Name,
						Explanation: "both groups match the same applications and disagree (" +
							ra.Action + " vs " + rb.Action + "); “" + a.Name + "” wins by order",
					})
				}
			}
		}
	}
	return out
}

// overlapping reports whether two criteria plainly target the same thing.
//
// Deliberately conservative: it compares the literal values rather than
// attempting to intersect wildcard languages. Reporting a conflict that turns
// out not to bite is a mild annoyance; claiming there is none when there is
// would make the whole conflict report untrustworthy.
func overlapping(a, b store.MatchCriteria) bool {
	return sharesValue(a.AppName, b.AppName) ||
		sharesValue(a.Publisher, b.Publisher) ||
		sharesValue(a.BundleID, b.BundleID) ||
		sharesValue(a.FilePath, b.FilePath)
}

func sharesValue(a, b store.StringMatch) bool {
	if a.Empty() || b.Empty() {
		return false
	}
	for _, x := range a.Values {
		for _, y := range b.Values {
			if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(y)) {
				return true
			}
		}
	}
	return false
}

// Decide evaluates one application against a machine's effective policy.
//
// First match wins, top to bottom. Not "most specific wins" — a numbered list
// is something an operator can read and predict, whereas a specificity score
// is something they argue with while an incident is running.
func (e Effective) Decide(app *store.InstalledApp) Decision {
	for _, r := range e.Rules {
		if !matches(r.Rule.Match, app) {
			continue
		}
		if r.Rule.Action == store.ActionDefault {
			// An explicit carve-out: stop looking, fall through to the
			// default. Without this there is no way to say "this one is an
			// exception to the rule below".
			break
		}
		return Decision{
			Action: r.Rule.Action, RuleID: r.Rule.ID, RuleName: r.Rule.Name,
			PolicyID: r.PolicyID, PolicyName: r.PolicyName,
			Scope: r.Scope, Mode: e.Mode, Matched: true,
		}
	}
	return Decision{Action: e.DefaultAction, Mode: e.Mode, Matched: false}
}
