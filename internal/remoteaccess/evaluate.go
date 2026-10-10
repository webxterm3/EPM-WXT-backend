// Package remoteaccess decides whether a remote session may start.
//
// It is a second gate, never the first. Ownership and allowed-user checks run
// before this and decide whether somebody may touch a machine at all; a policy
// here can only narrow that further. A policy cannot grant access to anyone
// who was not already entitled to it, which is what keeps a mistyped scope
// from handing out sessions.
//
// Everything here is a pure function over values so the rules — especially the
// time windows, which are the easiest thing to get subtly wrong — can be
// tested exhaustively rather than reasoned about.
package remoteaccess

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// Request is one attempt to open a session.
type Request struct {
	AccessKind string // store.AccessAttended / Unattended / Terminal

	// Caller identity, as already established by authentication.
	Role     string
	Username string
	GroupIDs []string

	// Reason is what the operator typed, when they typed one.
	Reason string

	// RecordingAvailable says whether a recording destination is configured.
	// A policy that requires recording refuses when it is not.
	RecordingAvailable bool

	// Now is the moment the session would start. Passed in rather than read
	// from the clock so time-window behaviour is testable.
	Now time.Time
}

// Decision is the outcome.
type Decision struct {
	Allowed bool

	// Reason explains a refusal in terms the person can act on — which window,
	// which group — rather than a bare "forbidden".
	Reason string

	// PolicyName and PolicyID identify the policy that decided, when one did.
	PolicyName string
	PolicyID   string

	// Conditions the session must run under. These come from the policy, and
	// the caller is responsible for honouring them.
	RequireConsent    bool
	RequireRecording  bool
	MaxSessionMinutes int
}

// Evaluate applies the most specific applicable policy.
//
// With no policy at all it allows, because this feature is being added to
// deployments that already work: appearing in an upgrade and locking everybody
// out of their own machines would be the wrong default by a wide margin.
func Evaluate(machine *store.Machine, policies []*store.RemoteAccessPolicy, req Request) Decision {
	policy := mostSpecific(machine, policies)
	if policy == nil {
		return Decision{
			Allowed: true,
			Reason:  "no remote access policy applies to this machine",
			// Consent is the product's existing behaviour for attended
			// sessions and stays on when no policy says otherwise.
			RequireConsent: req.AccessKind == store.AccessAttended,
		}
	}

	decision := Decision{
		PolicyName:        policy.Name,
		PolicyID:          policy.ID.Hex(),
		RequireConsent:    policy.RequireConsent,
		RequireRecording:  policy.RequireRecording,
		MaxSessionMinutes: policy.MaxSessionMinutes,
	}

	if reason := checkKind(policy, req.AccessKind); reason != "" {
		decision.Reason = reason
		return decision
	}
	if reason := checkRole(policy, req.Role); reason != "" {
		decision.Reason = reason
		return decision
	}
	if reason := checkGroups(policy, req.GroupIDs); reason != "" {
		decision.Reason = reason
		return decision
	}
	if reason := checkWindows(policy, req.Now); reason != "" {
		decision.Reason = reason
		return decision
	}
	if policy.RequireReason && strings.TrimSpace(req.Reason) == "" {
		decision.Reason = "this policy requires a reason for connecting"
		return decision
	}
	if policy.RequireRecording && !req.RecordingAvailable {
		// Refusing is the point: a policy that says sessions are recorded has
		// to mean it, and letting an unrecorded session through would make
		// every later audit a lie.
		decision.Reason = "this policy requires session recording, but no recording storage is configured"
		return decision
	}

	decision.Allowed = true
	return decision
}

// mostSpecific picks the policy that governs a machine.
//
// Machine beats group beats tenant, then higher priority, then the older
// policy, then the id — the same total ordering as application policy, so an
// operator learns it once. One policy decides, rather than merging several:
// merging "allow weekdays" with "allow weekends" has no obvious right answer,
// and a rule nobody can predict is worse than a rule they disagree with.
func mostSpecific(machine *store.Machine, policies []*store.RemoteAccessPolicy) *store.RemoteAccessPolicy {
	applicable := make([]*store.RemoteAccessPolicy, 0, len(policies))
	for _, p := range policies {
		if p.Enabled && appliesTo(p, machine) {
			applicable = append(applicable, p)
		}
	}
	if len(applicable) == 0 {
		return nil
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
	return applicable[0]
}

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

func appliesTo(p *store.RemoteAccessPolicy, machine *store.Machine) bool {
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

// checkKind reports why this way in is not permitted, or "".
func checkKind(p *store.RemoteAccessPolicy, kind string) string {
	allowed := map[string]bool{
		store.AccessAttended:   p.AllowAttended,
		store.AccessUnattended: p.AllowUnattended,
		store.AccessTerminal:   p.AllowTerminal,
	}
	if allowed[kind] {
		return ""
	}
	return fmt.Sprintf("%s access is not permitted by the policy %q", friendlyKind(kind), p.Name)
}

func friendlyKind(kind string) string {
	switch kind {
	case store.AccessAttended:
		return "Attended remote control"
	case store.AccessUnattended:
		return "Unattended desktop"
	case store.AccessTerminal:
		return "Terminal"
	default:
		return kind
	}
}

// checkRole reports why the caller's role is not permitted, or "".
func checkRole(p *store.RemoteAccessPolicy, role string) string {
	if len(p.AllowedRoles) == 0 {
		return ""
	}
	for _, allowed := range p.AllowedRoles {
		if allowed == role {
			return ""
		}
	}
	return fmt.Sprintf("the policy %q allows only these roles: %s",
		p.Name, strings.Join(p.AllowedRoles, ", "))
}

// checkGroups reports why the caller's group membership is not permitted.
func checkGroups(p *store.RemoteAccessPolicy, callerGroups []string) string {
	if len(p.AllowedGroupIDs) == 0 {
		return ""
	}
	have := make(map[string]bool, len(callerGroups))
	for _, g := range callerGroups {
		have[g] = true
	}
	for _, want := range p.AllowedGroupIDs {
		if have[want] {
			return ""
		}
	}
	return fmt.Sprintf("the policy %q restricts access to specific groups, and you are not in one of them", p.Name)
}

// checkWindows reports why now is outside the permitted hours, or "".
func checkWindows(p *store.RemoteAccessPolicy, now time.Time) string {
	if len(p.TimeWindows) == 0 {
		return ""
	}
	if now.IsZero() {
		now = time.Now()
	}

	for _, w := range p.TimeWindows {
		if windowContains(w, now) {
			return ""
		}
	}
	return fmt.Sprintf("the policy %q only permits sessions during %s",
		p.Name, describeWindows(p.TimeWindows))
}

// windowContains reports whether a moment falls inside one window.
//
// The window is evaluated in its own timezone, not the server's: "business
// hours" is a statement about where the people are, and a support team in Pune
// working to a window set in UTC would find it opened at half past two in the
// morning.
func windowContains(w store.TimeWindow, now time.Time) bool {
	loc := time.UTC
	if w.Timezone != "" {
		if parsed, err := time.LoadLocation(w.Timezone); err == nil {
			loc = parsed
		}
		// An unloadable zone falls back to UTC rather than matching
		// everything: a window that silently stopped restricting anything
		// would be worse than one that restricts too much and gets noticed.
	}
	local := now.In(loc)

	if len(w.Days) > 0 {
		day := int(local.Weekday())
		found := false
		for _, d := range w.Days {
			if d == day {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	minute := local.Hour()*60 + local.Minute()

	// A window that ends before it starts crosses midnight — a night shift,
	// 22:00 to 06:00. Comparing it as a simple range would make it match
	// nothing at all, which is exactly when somebody is on call.
	if w.EndMinute < w.StartMinute {
		return minute >= w.StartMinute || minute < w.EndMinute
	}
	return minute >= w.StartMinute && minute < w.EndMinute
}

// describeWindows renders the windows for a refusal message.
func describeWindows(windows []store.TimeWindow) string {
	parts := make([]string, 0, len(windows))
	for _, w := range windows {
		zone := w.Timezone
		if zone == "" {
			zone = "UTC"
		}
		parts = append(parts, fmt.Sprintf("%s %s–%s %s",
			describeDays(w.Days), clock(w.StartMinute), clock(w.EndMinute), zone))
	}
	return strings.Join(parts, "; ")
}

var dayNames = [...]string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

func describeDays(days []int) string {
	if len(days) == 0 {
		return "every day"
	}
	names := make([]string, 0, len(days))
	for _, d := range days {
		if d >= 0 && d < len(dayNames) {
			names = append(names, dayNames[d])
		}
	}
	return strings.Join(names, ", ")
}

func clock(minutes int) string {
	return fmt.Sprintf("%02d:%02d", minutes/60%24, minutes%60)
}
