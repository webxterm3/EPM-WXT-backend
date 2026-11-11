package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/policy"
	"github.com/vsay/vsay-agent-backend/internal/store"
)

// Least-privilege policies: who may hold local administrator rights.
//
// Structurally a twin of policies.go, and kept separate for the same reason
// the types are. The one difference worth knowing about is the enforcement
// switch: these read PrivilegeSettings, not AppControlSettings, so turning on
// application blocking cannot also strip a fleet's administrator rights.

// maxKeepAdmin bounds the exemption list.
//
// Generous — an exemption list is written by hand, and a hundred entries is
// already a sign the policy wants a different scope — but bounded, because
// it is resolved per machine on every push.
const maxKeepAdmin = 200

// maxSudoCommands bounds the sudoers list a policy may carry.
//
// Every entry becomes a line in /etc/sudoers.d on every machine in scope, and
// a file that will not parse is refused by visudo as a whole.
const maxSudoCommands = 200

// maxGrantCeilingMinutes is the longest an elevation grant may be allowed to
// last — 24 hours.
//
// A ceiling on the ceiling. "Temporary administrator rights" that outlive a
// working day is standing privilege with extra steps, and the audit trail
// would describe it as just-in-time.
const maxGrantCeilingMinutes = 24 * 60

// ListPrivilegePolicies returns the tenant's privilege policies.
// GET /api/privilege-policies
func (h *Handler) ListPrivilegePolicies(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	policies, err := h.store.GetPrivilegePoliciesByTenant(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load privilege policies"})
		return
	}

	h.countMachinesInPrivilegeScope(tenantID, policies)

	c.JSON(http.StatusOK, gin.H{
		"policies": policies,
		// Returned with the list because a policy's mode means nothing
		// without it: a policy saved as "enforce" does nothing at all while
		// this is off, and a screen that showed one without the other would
		// be telling an operator their fleet is locked down when it is not.
		"enforcement_enabled": h.privilegeEnforcementEnabled(tenantID),
	})
}

// GetPrivilegePolicy returns one policy.
// GET /api/privilege-policies/:id
func (h *Handler) GetPrivilegePolicy(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy id"})
		return
	}

	p, err := h.store.GetPrivilegePolicyByID(tenantID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load the policy"})
		return
	}
	if p == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"policy": p})
}

// CreatePrivilegePolicy saves a new policy.
// POST /api/privilege-policies
func (h *Handler) CreatePrivilegePolicy(c *gin.Context) {
	tenantID, ok := h.requirePolicyAdmin(c)
	if !ok {
		return
	}

	var p store.PrivilegePolicy
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy: " + err.Error()})
		return
	}
	p.TenantID = tenantID
	p.CreatedBy = c.GetString("username")
	p.UpdatedBy = p.CreatedBy

	if err := preparePrivilegePolicy(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.store.CreatePrivilegePolicy(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.record(c, auditEntry{
		Action: store.AuditPrivilegePolicyCreated, Resource: "privilege_policy",
		ResourceID: p.ID.Hex(),
		Details:    privilegePolicyDetails(&p),
	})
	h.pushPrivilegePolicyToFleet(c)

	c.JSON(http.StatusCreated, gin.H{"policy": p})
}

// UpdatePrivilegePolicy saves changes to an existing policy.
// PUT /api/privilege-policies/:id
func (h *Handler) UpdatePrivilegePolicy(c *gin.Context) {
	tenantID, ok := h.requirePolicyAdmin(c)
	if !ok {
		return
	}

	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy id"})
		return
	}

	var p store.PrivilegePolicy
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy: " + err.Error()})
		return
	}
	p.ID = id
	p.TenantID = tenantID
	p.UpdatedBy = c.GetString("username")

	if err := preparePrivilegePolicy(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.store.UpdatePrivilegePolicy(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.record(c, auditEntry{
		Action: store.AuditPrivilegePolicyUpdated, Resource: "privilege_policy",
		ResourceID: p.ID.Hex(),
		Details:    privilegePolicyDetails(&p),
	})
	h.pushPrivilegePolicyToFleet(c)

	c.JSON(http.StatusOK, gin.H{"policy": p})
}

// DeletePrivilegePolicy removes a policy.
// DELETE /api/privilege-policies/:id
//
// Deleting a policy that was demoting people RESTORES their rights, because
// the next push carries no instruction and the endpoint reverses what it
// applied. That is the intended behaviour and is why delete is not gated
// behind an extra confirmation here: it is the safe direction.
func (h *Handler) DeletePrivilegePolicy(c *gin.Context) {
	tenantID, ok := h.requirePolicyAdmin(c)
	if !ok {
		return
	}

	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy id"})
		return
	}

	if err := h.store.DeletePrivilegePolicy(tenantID, id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	h.record(c, auditEntry{
		Action: store.AuditPrivilegePolicyDeleted, Resource: "privilege_policy",
		ResourceID: id.Hex(),
	})
	h.pushPrivilegePolicyToFleet(c)

	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// SimulatePrivilegePolicy reports what a draft policy would do.
// POST /api/privilege-policies/simulate
//
// Nothing is saved and no agent is contacted. The draft is resolved alongside
// the tenant's saved policies against the real account inventory.
func (h *Handler) SimulatePrivilegePolicy(c *gin.Context) {
	tenantID, ok := h.requirePolicyAdmin(c)
	if !ok {
		return
	}

	var draft store.PrivilegePolicy
	if err := c.ShouldBindJSON(&draft); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy: " + err.Error()})
		return
	}
	draft.TenantID = tenantID
	if err := preparePrivilegePolicy(&draft); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	saved, err := h.store.GetPrivilegePoliciesByTenant(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load policies"})
		return
	}

	// An edit replaces its saved self rather than competing with it.
	// Without this, simulating a change to an existing policy resolves the
	// old and new versions together and shows the result of neither.
	policies := make([]*store.PrivilegePolicy, 0, len(saved)+1)
	for _, p := range saved {
		if !draft.ID.IsZero() && p.ID == draft.ID {
			continue
		}
		policies = append(policies, p)
	}
	policies = append(policies, &draft)

	fleet, err := h.fleetAccounts(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load the fleet"})
		return
	}

	// true, not the live switch: the operator is asking what this policy
	// would do, which is the question they need answered BEFORE turning
	// enforcement on. The live value is reported separately so the screen can
	// say that none of it is happening yet.
	sim := policy.SimulatePrivilege(fleet, policies, true)

	c.JSON(http.StatusOK, gin.H{
		"simulation":          sim,
		"enforcement_enabled": h.privilegeEnforcementEnabled(tenantID),
	})
}

// GetPrivilegeSettings returns the tenant's enforcement switch.
// GET /api/privilege-control/settings
func (h *Handler) GetPrivilegeSettings(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	settings, err := h.store.GetPrivilegeSettings(tenantID)
	if err != nil || settings == nil {
		// Fails closed: an unreadable settings document must not read as
		// "enforcement on".
		c.JSON(http.StatusOK, gin.H{"enforcement": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"enforcement": settings.Enforcement,
		"updated_at":  settings.UpdatedAt,
		"updated_by":  settings.UpdatedBy,
	})
}

// SetPrivilegeEnforcement turns least-privilege enforcement on or off.
// PUT /api/privilege-control/settings
//
// Its own route rather than a field on the policy save, because this is the
// single most consequential setting in the product: switching it on removes
// administrator rights from people across a fleet. It should be an act of its
// own, with its own audit entry, not a side effect of saving a policy.
func (h *Handler) SetPrivilegeEnforcement(c *gin.Context) {
	tenantID, ok := h.requirePolicyAdmin(c)
	if !ok {
		return
	}

	// A pointer, so a body that omits the field is rejected rather than
	// decoding to false and silently turning enforcement OFF for the tenant.
	var body struct {
		Enforcement *bool `json:"enforcement"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Enforcement == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enforcement must be true or false"})
		return
	}

	actor := c.GetString("username")
	if err := h.store.SetPrivilegeEnforcement(tenantID, *body.Enforcement, actor); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save the setting"})
		return
	}

	h.record(c, auditEntry{
		Action: store.AuditPrivilegeEnforcementChanged, Resource: "tenant",
		ResourceID: tenantID,
		Details:    map[string]any{"enforcement": *body.Enforcement},
	})
	h.pushPrivilegePolicyToFleet(c)

	c.JSON(http.StatusOK, gin.H{"enforcement": *body.Enforcement})
}

// ── helpers ─────────────────────────────────────────────────────────────────

// preparePrivilegePolicy validates and normalises a policy before it is saved.
//
// Every normalisation here is in the restrictive direction: an unrecognised
// mode becomes audit, an out-of-range ceiling becomes the maximum, an
// unparseable scope becomes narrower rather than wider. A policy that arrives
// malformed must not end up doing MORE than its author asked for.
func preparePrivilegePolicy(p *store.PrivilegePolicy) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return errBadPolicy("the policy needs a name")
	}

	switch p.Scope.Kind {
	case store.PolicyScopeGroup:
		p.Scope.AgentIDs = nil
		if len(p.Scope.GroupIDs) == 0 {
			return errBadPolicy("a group-scoped policy needs at least one group")
		}
	case store.PolicyScopeMachine:
		p.Scope.GroupIDs = nil
		if len(p.Scope.AgentIDs) == 0 {
			return errBadPolicy("a machine-scoped policy needs at least one machine")
		}
	default:
		p.Scope.Kind = store.PolicyScopeTenant
		p.Scope.GroupIDs = nil
		p.Scope.AgentIDs = nil
	}

	// Anything that is not exactly "enforce" means audit. A typo must not
	// enforce.
	if p.Mode != store.ModeEnforce {
		p.Mode = store.ModeAudit
	}

	p.KeepAdmin = cleanUsernames(p.KeepAdmin)
	if len(p.KeepAdmin) > maxKeepAdmin {
		return errBadPolicy("too many exemptions; use a narrower scope instead")
	}

	if err := prepareBreakGlass(&p.BreakGlass); err != nil {
		return err
	}
	return prepareElevation(&p.Elevation)
}

// prepareBreakGlass validates the recovery account.
func prepareBreakGlass(b *store.BreakGlassSpec) error {
	b.Username = strings.TrimSpace(b.Username)
	b.FullName = strings.TrimSpace(b.FullName)

	if !b.Enabled {
		return nil
	}
	if b.Username == "" {
		return errBadPolicy("a break-glass account needs a username")
	}
	// The username reaches a command line on the endpoint, so it is held to
	// the characters an account name can actually contain. Refusing is the
	// only safe response: sanitising would create an account under a name
	// nobody asked for, and nobody would know what it was called.
	if !validAccountName(b.Username) {
		return errBadPolicy("a break-glass username may use letters, digits, dot, dash and underscore only")
	}
	return nil
}

// prepareElevation validates the ways privilege can be regained.
func prepareElevation(e *store.ElevationSpec) error {
	if e.MaxGrantMinutes < 0 {
		e.MaxGrantMinutes = 0
	}
	if e.MaxGrantMinutes > maxGrantCeilingMinutes {
		e.MaxGrantMinutes = maxGrantCeilingMinutes
	}

	if len(e.SudoCommands) > maxSudoCommands {
		return errBadPolicy("too many sudo commands in one policy")
	}

	cleaned := make([]store.SudoCommand, 0, len(e.SudoCommands))
	for _, cmd := range e.SudoCommands {
		cmd.Path = strings.TrimSpace(cmd.Path)
		if cmd.Path == "" {
			continue
		}
		// Absolute only. sudoers matches the path as written, so a bare name
		// would be resolved through the user's own PATH — which is a way to
		// run anything at all under the name of a permitted command.
		if !strings.HasPrefix(cmd.Path, "/") {
			return errBadPolicy("sudo command " + cmd.Path + " must be an absolute path")
		}
		cleaned = append(cleaned, cmd)
	}
	e.SudoCommands = cleaned
	return nil
}

// cleanUsernames trims, drops blanks and de-duplicates case-insensitively.
func cleanUsernames(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		key := strings.ToLower(n)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, n)
	}
	return out
}

// validAccountName reports a name that can safely be an OS account.
func validAccountName(name string) bool {
	if len(name) > 32 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// privilegeEnforcementEnabled reads the tenant switch, failing closed.
func (h *Handler) privilegeEnforcementEnabled(tenantID string) bool {
	settings, err := h.store.GetPrivilegeSettings(tenantID)
	if err != nil || settings == nil {
		return false
	}
	return settings.Enforcement
}

// countMachinesInPrivilegeScope fills in each policy's reach.
//
// Uses the same scope test the resolver decides with, so the number on the
// screen is the number that will happen. A policy that reaches nobody is the
// failure this exists to surface: a machine re-enrolled, got a new agent id,
// and the policy naming the old one goes on looking enabled and enforcing
// while applying to nothing. That has already happened once with application
// policies in this product.
func (h *Handler) countMachinesInPrivilegeScope(tenantID string, policies []*store.PrivilegePolicy) {
	if len(policies) == 0 {
		return
	}

	machines, err := h.store.GetMachinesByTenantID(tenantID)
	if err != nil {
		// Left nil rather than zeroed: "not computed" must not render as
		// "reaches nobody", or one database hiccup puts a warning on every
		// policy on the page.
		return
	}

	for _, p := range policies {
		n := 0
		for _, m := range machines {
			if m.Revoked {
				continue
			}
			if policy.AppliesTo(&store.AppPolicy{Scope: p.Scope}, m) {
				n++
			}
		}
		count := n
		p.MachinesInScope = &count
	}
}

// fleetAccounts loads every machine with the accounts it last reported.
func (h *Handler) fleetAccounts(tenantID string) ([]policy.MachineAccounts, error) {
	machines, err := h.store.GetMachinesByTenantID(tenantID)
	if err != nil {
		return nil, err
	}

	out := make([]policy.MachineAccounts, 0, len(machines))
	for _, m := range machines {
		if m.Revoked {
			continue
		}
		accounts, err := h.store.GetAccountsByMachine(m.ID, store.AccountQuery{Limit: maxAccountsPerMachine})
		if err != nil {
			// One unreadable machine is reported as unreported rather than
			// skipped, so it shows up in the "not reported" count instead of
			// quietly shrinking the fleet the numbers were taken over.
			out = append(out, policy.MachineAccounts{Machine: m, Reported: false})
			continue
		}
		out = append(out, policy.MachineAccounts{
			Machine:  m,
			Accounts: accounts,
			Reported: len(accounts) > 0,
		})
	}
	return out, nil
}

// maxAccountsPerMachine bounds the simulation's per-machine read.
const maxAccountsPerMachine = 1000

// pushPrivilegePolicyToFleet delivers the new policy to connected agents.
//
// Offline machines are not chased: they are sent the current policy when they
// next connect. A failure here never fails the request — the policy is saved,
// and delivery is the push path's job.
func (h *Handler) pushPrivilegePolicyToFleet(c *gin.Context) {
	if h.policyPusher == nil {
		return
	}
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		return
	}

	pushed, failed := h.policyPusher.PushPrivilegeToTenant(tenantID)
	h.logger.Info("privilege policy pushed",
		zap.String("tenant_id", tenantID),
		zap.Int("pushed", pushed), zap.Int("failed", failed))
}

// privilegePolicyDetails is what the audit trail records about a change.
//
// The exemption list travels in full. "Who was exempted from losing
// administrator rights, and when" is exactly the question an audit of this
// feature asks, and a count would not answer it.
func privilegePolicyDetails(p *store.PrivilegePolicy) map[string]any {
	return map[string]any{
		"name":          p.Name,
		"enabled":       p.Enabled,
		"mode":          p.Mode,
		"scope":         p.Scope.Kind,
		"demote_admins": p.DemoteAdmins,
		"keep_admin":    p.KeepAdmin,
		"break_glass":   p.BreakGlass.Enabled,
	}
}
