package policy

import (
	"sort"
	"strings"
	"time"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// EffectivePrivilege is the least-privilege policy in force for one machine.
//
// Flatter than Effective because the decision is flatter: there is no ordered
// rule list to evaluate, only a set of instructions the endpoint carries out
// under invariants it enforces for itself.
type EffectivePrivilege struct {
	AgentID  string `json:"agent_id"`
	TenantID string `json:"tenant_id"`

	// Mode is the strongest mode any contributing policy asked for, or audit
	// whenever the tenant's privilege-enforcement switch is off.
	Mode string `json:"mode"`

	// DemoteAdmins is the instruction. False unless a policy asked for it.
	DemoteAdmins bool `json:"demote_admins"`

	// KeepAdmin is the UNION of every applicable policy's exemptions, not the
	// most specific policy's alone.
	//
	// Union is the fail-safe direction. If a tenant-wide policy protects a
	// service account and a machine-scoped policy protects one person,
	// letting the machine policy win would demote the service account that
	// somebody explicitly wrote down — silently, and only on the machines
	// that happened to have a second policy. An exemption is a statement that
	// something must not be touched, and the narrower policy's author was not
	// asked about it.
	KeepAdmin []string `json:"keep_admin,omitempty"`

	// BreakGlass comes from the most specific policy that enables one.
	//
	// Not unioned: two managed administrator accounts on one machine is twice
	// the standing privilege for no additional recoverability.
	BreakGlass store.BreakGlassSpec `json:"break_glass"`

	// Elevation is merged permissively — see mergeElevation.
	Elevation store.ElevationSpec `json:"elevation"`

	Sources []Source `json:"sources"`

	// Grants are time-bounded administrator rights an approver handed out,
	// usually in answer to a request raised from the machine itself.
	//
	// Carried BESIDE the policy rather than folded into KeepAdmin, for the
	// same reason ApprovedInstalls is kept out of the application resolver:
	// ResolvePrivilege is called by the portal's simulation as well as by the
	// push, and a simulation that invented grants would report a fleet nobody
	// has. Keeping it pure is what lets the two agree.
	Grants []AdminGrant `json:"grants,omitempty"`
}

// AdminGrant is one person's temporary administrator rights.
type AdminGrant struct {
	Username string    `json:"username"`
	Until    time.Time `json:"until"`

	// RequestID is carried so the endpoint's report can be tied back to the
	// approval that caused it. Without it, "why did this person have
	// administrator rights on Tuesday" has no answer.
	RequestID string `json:"request_id,omitempty"`
}

// ResolvePrivilege produces the least-privilege policy in force for one
// machine.
//
// Pure: no I/O, no clock. Every caller — the push on save, the push on
// connect, and the simulation — goes through this one function, so they
// cannot disagree about what a machine is under. The application-policy
// resolver is built the same way for the same reason.
//
// Ordering is identical to Resolve, and deliberately shares scopeRank and
// AppliesTo rather than re-deriving them: a machine must not be in scope for
// one kind of policy and out of scope for the other.
func ResolvePrivilege(machine *store.Machine, policies []*store.PrivilegePolicy, enforcementEnabled bool) EffectivePrivilege {
	eff := EffectivePrivilege{
		AgentID:  machine.AgentID,
		TenantID: machine.TenantID,
		Mode:     store.ModeAudit,
		// Nobody is demoted unless a policy says so. A default of true would
		// mean that creating any privilege policy at all strips the fleet.
		DemoteAdmins: false,
	}

	applicable := make([]*store.PrivilegePolicy, 0, len(policies))
	for _, p := range policies {
		if p != nil && p.Enabled && appliesToPrivilege(p, machine) {
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

	keep := map[string]bool{}
	enforcing := false

	for i, p := range applicable {
		eff.Sources = append(eff.Sources, Source{
			PolicyID: p.ID.Hex(), PolicyName: p.Name,
			Scope: p.Scope.Kind, Priority: p.Priority,
		})

		// The most specific policy decides whether rights come off. It is the
		// instruction itself, and an instruction is not something to merge:
		// a machine-scoped "leave this machine alone" has to be able to
		// override a tenant-wide "demote everybody", or there is no way to
		// exempt a build server.
		if i == 0 {
			eff.DemoteAdmins = p.DemoteAdmins
		}

		// Exemptions union across every applicable policy. See KeepAdmin.
		for _, name := range p.KeepAdmin {
			if n := strings.ToLower(strings.TrimSpace(name)); n != "" {
				keep[n] = true
			}
		}

		// The first policy that specifies a break-glass account provides it,
		// which in this order is the most specific one that does.
		if !eff.BreakGlass.Enabled && p.BreakGlass.Enabled {
			eff.BreakGlass = p.BreakGlass
		}

		eff.Elevation = mergeElevation(eff.Elevation, p.Elevation)

		if p.Mode == store.ModeEnforce {
			enforcing = true
		}
	}

	eff.KeepAdmin = sortedKeys(keep)

	// The break-glass account is never demoted by the policy that created it.
	//
	// Added here rather than left to the endpoint because the simulation has
	// to show the same answer the endpoint will reach, and an operator
	// looking at a count that included their own recovery account would be
	// reading a number that will not happen.
	if eff.BreakGlass.Enabled && eff.BreakGlass.Username != "" {
		eff.KeepAdmin = appendUnique(eff.KeepAdmin, strings.ToLower(eff.BreakGlass.Username))
	}

	// The tenant's privilege-enforcement switch is read here, in one place,
	// so that a bug anywhere else in this path still cannot take anybody's
	// administrator rights away. While it is off, every policy resolves to
	// audit however its own Mode is set — and the endpoint is SENT audit,
	// rather than being trusted to work that out for itself.
	if enforcementEnabled && enforcing {
		eff.Mode = store.ModeEnforce
	}
	return eff
}

// Enforcing reports whether this policy will actually change anything.
//
// Both conditions, in one place, because the two of them apart are the shape
// of the bug: a reader who checks Mode alone acts on a policy that only meant
// to watch, and one who checks DemoteAdmins alone acts while the tenant
// switch is off.
func (e EffectivePrivilege) Enforcing() bool {
	return e.Mode == store.ModeEnforce && e.DemoteAdmins
}

// KeepsAdmin reports whether an account is exempt, case-insensitively.
//
// Case-insensitive because the three places a username is typed — the policy
// editor, the account database, and the OS — do not agree about case, and on
// both supported platforms usernames are matched case-insensitively anyway.
// An exemption that failed to match because somebody typed "Priya" would
// demote the person it was written to protect.
func (e EffectivePrivilege) KeepsAdmin(username string) bool {
	target := strings.ToLower(strings.TrimSpace(username))
	if target == "" {
		return false
	}
	for _, name := range e.KeepAdmin {
		if name == target {
			return true
		}
	}
	return false
}

// appliesToPrivilege is the scope test, sharing the application policy's
// implementation through a converted view.
//
// It delegates rather than reimplementing because the two must agree: a
// machine in scope for one kind of policy and out of scope for the other
// would be a fleet where the privilege simulation counts machines the
// enforcement never reaches.
func appliesToPrivilege(p *store.PrivilegePolicy, machine *store.Machine) bool {
	return AppliesTo(&store.AppPolicy{Scope: p.Scope}, machine)
}

// mergeElevation combines what two policies allow, permissively.
//
// Permissive because every field here grants a way to GET privilege back
// after it has been taken away. Resolving two policies by letting the
// narrower win would produce a machine where rights were removed by one
// policy and the route back was closed by another — which is the state in
// which somebody cannot work and nothing in the portal explains why.
//
// The time limit is the exception and takes the SHORTEST non-zero value: it
// is a ceiling, and a ceiling that rose when a second policy applied would be
// the one field here where merging loosened a deliberate restriction.
func mergeElevation(into, from store.ElevationSpec) store.ElevationSpec {
	into.AllowInstallRequests = into.AllowInstallRequests || from.AllowInstallRequests
	into.AllowAdminRequests = into.AllowAdminRequests || from.AllowAdminRequests
	into.AllowFullAdminGrant = into.AllowFullAdminGrant || from.AllowFullAdminGrant

	if from.MaxGrantMinutes > 0 {
		if into.MaxGrantMinutes == 0 || from.MaxGrantMinutes < into.MaxGrantMinutes {
			into.MaxGrantMinutes = from.MaxGrantMinutes
		}
	}

	for _, cmd := range from.SudoCommands {
		if !hasSudoCommand(into.SudoCommands, cmd) {
			into.SudoCommands = append(into.SudoCommands, cmd)
		}
	}
	return into
}

// hasSudoCommand reports an equivalent command already present.
func hasSudoCommand(list []store.SudoCommand, want store.SudoCommand) bool {
	for _, c := range list {
		if c.Path == want.Path &&
			c.AnyArguments == want.AnyArguments &&
			strings.Join(c.Args, "\x00") == strings.Join(want.Args, "\x00") {
			return true
		}
	}
	return false
}

func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func appendUnique(list []string, value string) []string {
	for _, v := range list {
		if v == value {
			return list
		}
	}
	return append(list, value)
}
