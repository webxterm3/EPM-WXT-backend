package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/policy"
	"github.com/vsay/vsay-agent-backend/internal/store"
)

// enforcementEnabled is the global kill switch for application control.
//
// It is false for the whole of Phase A: policies are authored and simulated,
// and nothing is enforced on any endpoint. Keeping it as one named constant
// read in one place means a bug anywhere else in the policy path still cannot
// block somebody's software, and switching it on later is one deliberate
// change rather than an archaeology exercise.
const enforcementEnabled = false

// simulationTimeout bounds one projection. A tenant with a very large fleet
// should get a clear failure rather than a request that hangs.
const simulationTimeout = 60 * time.Second

// ListAppPolicies handles GET /api/app-policies.
func (h *Handler) ListAppPolicies(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	policies, err := h.store.GetAppPoliciesByTenant(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load policies"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"policies": policies,
		// Said out loud on every read so the UI never has to assume: in
		// Phase A these are authored and projected, never applied.
		"enforcement_enabled": enforcementEnabled,
	})
}

// GetAppPolicy handles GET /api/app-policies/:id.
func (h *Handler) GetAppPolicy(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy id"})
		return
	}

	p, err := h.store.GetAppPolicyByID(tenantID, id)
	if err != nil || p == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}
	c.JSON(http.StatusOK, p)
}

// CreateAppPolicy handles POST /api/app-policies.
func (h *Handler) CreateAppPolicy(c *gin.Context) {
	tenantID, ok := h.requirePolicyAdmin(c)
	if !ok {
		return
	}

	var body store.AppPolicy
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	p, err := preparePolicy(body, tenantID, c.GetString("username"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p.CreatedBy = c.GetString("username")

	if err := h.store.CreateAppPolicy(p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.record(c, auditEntry{
		Action: store.AuditPolicyCreated, Resource: "application_policy",
		ResourceID: p.ID.Hex(),
		Details: map[string]any{
			"name": p.Name, "scope": p.Scope.Kind, "rules": len(p.Rules),
			"default_action": p.DefaultAction, "enabled": p.Enabled,
		},
	})
	c.JSON(http.StatusCreated, p)
}

// UpdateAppPolicy handles PUT /api/app-policies/:id.
func (h *Handler) UpdateAppPolicy(c *gin.Context) {
	tenantID, ok := h.requirePolicyAdmin(c)
	if !ok {
		return
	}
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy id"})
		return
	}

	var body store.AppPolicy
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	p, err := preparePolicy(body, tenantID, c.GetString("username"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p.ID = id

	if err := h.store.UpdateAppPolicy(p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.record(c, auditEntry{
		Action: store.AuditPolicyUpdated, Resource: "application_policy",
		ResourceID: p.ID.Hex(),
		Details: map[string]any{
			"name": p.Name, "scope": p.Scope.Kind, "rules": len(p.Rules),
			"default_action": p.DefaultAction, "enabled": p.Enabled,
		},
	})
	c.JSON(http.StatusOK, p)
}

// DeleteAppPolicy handles DELETE /api/app-policies/:id.
func (h *Handler) DeleteAppPolicy(c *gin.Context) {
	tenantID, ok := h.requirePolicyAdmin(c)
	if !ok {
		return
	}
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy id"})
		return
	}

	// Read it before deleting: afterwards there is nothing left to say WHICH
	// policy went, and "a policy was deleted" answers nobody's question.
	existing, _ := h.store.GetAppPolicyByID(tenantID, id)

	if err := h.store.DeleteAppPolicy(tenantID, id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	details := map[string]any{}
	if existing != nil {
		details["name"] = existing.Name
		details["scope"] = existing.Scope.Kind
		details["rules"] = len(existing.Rules)
	}
	h.record(c, auditEntry{
		Action: store.AuditPolicyDeleted, Resource: "application_policy",
		ResourceID: id.Hex(), Details: details,
	})
	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted"})
}

// SimulateAppPolicy handles POST /api/app-policies/simulate.
//
// The draft is never persisted. It is resolved alongside the tenant's saved
// policies at its own scope and priority, so the answer is "what changes if I
// save this" rather than "what would this do in isolation" — the second being
// a confidently wrong number, which is worse than none.
func (h *Handler) SimulateAppPolicy(c *gin.Context) {
	tenantID, ok := h.requirePolicyAdmin(c)
	if !ok {
		return
	}

	var body struct {
		Policy store.AppPolicy `json:"policy"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	draft, err := preparePolicy(body.Policy, tenantID, c.GetString("username"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// A draft has no id yet, and resolution orders by id as its final
	// tiebreak. Giving it one keeps the projection deterministic.
	if draft.ID.IsZero() {
		draft.ID = primitive.NewObjectID()
	}

	saved, err := h.store.GetAppPoliciesByTenant(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load policies"})
		return
	}
	// Replace the saved copy of a policy being edited, rather than evaluating
	// both versions of it.
	combined := make([]*store.AppPolicy, 0, len(saved)+1)
	for _, p := range saved {
		if p.ID != draft.ID {
			combined = append(combined, p)
		}
	}
	combined = append(combined, draft)

	machines, err := h.store.GetMachinesByTenantID(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load machines"})
		return
	}

	sim := &policy.Simulator{
		Effective: make(map[string]policy.Effective, len(machines)),
		Machines:  make(map[string]*store.Machine, len(machines)),
	}
	for _, m := range machines {
		if m.AgentID == "" || m.Revoked {
			continue
		}
		sim.Effective[m.AgentID] = policy.Resolve(m, combined, enforcementEnabled)
		sim.Machines[m.AgentID] = m
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), simulationTimeout)
	defer cancel()

	result, err := sim.Run(func(fn func(*store.InstalledApp) error) error {
		return h.store.StreamInstalledAppsByTenant(ctx, tenantID, fn)
	})
	if err != nil {
		h.logger.Warn("policy simulation failed", zap.String("tenant", tenantID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Simulation failed"})
		return
	}

	coverage, _ := h.store.GetInventoryCoverage(tenantID, inventoryStaleAfter)

	c.JSON(http.StatusOK, gin.H{
		"simulation": result,
		// Coverage travels with the result because the headline counts are
		// only honest next to how much of the fleet they are drawn from.
		"coverage":            coverage,
		"enforcement_enabled": enforcementEnabled,
	})
}

// requirePolicyAdmin checks the caller may author policy.
func (h *Handler) requirePolicyAdmin(c *gin.Context) (string, bool) {
	role := c.GetString("role")
	if role != "super_admin" && role != "company_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin access required"})
		return "", false
	}
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return "", false
	}
	return tenantID, true
}

// preparePolicy validates and normalises a submitted policy.
//
// It rejects anything that would be silently useless or silently dangerous
// once saved, rather than storing it and letting the operator find out from
// the fleet.
func preparePolicy(p store.AppPolicy, tenantID, actor string) (*store.AppPolicy, error) {
	p.TenantID = tenantID
	p.UpdatedBy = actor
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return nil, errBadPolicy("a policy needs a name")
	}

	switch p.Scope.Kind {
	case store.PolicyScopeTenant:
		p.Scope.GroupIDs, p.Scope.AgentIDs = nil, nil
	case store.PolicyScopeGroup:
		if len(p.Scope.GroupIDs) == 0 {
			return nil, errBadPolicy("a group-scoped policy must name at least one group")
		}
		p.Scope.AgentIDs = nil
	case store.PolicyScopeMachine:
		if len(p.Scope.AgentIDs) == 0 {
			return nil, errBadPolicy("a machine-scoped policy must name at least one machine")
		}
		p.Scope.GroupIDs = nil
	default:
		return nil, errBadPolicy("scope must be tenant, group or machine")
	}

	if p.Mode != store.ModeEnforce {
		p.Mode = store.ModeAudit
	}
	if p.DefaultAction != store.ActionBlock {
		// Anything other than an explicit block defaults to allow. A policy
		// that defaults to block the moment it is saved would take a fleet out.
		p.DefaultAction = store.ActionAllow
	}

	for i := range p.Rules {
		rule := &p.Rules[i]
		rule.Name = strings.TrimSpace(rule.Name)
		if rule.Name == "" {
			rule.Name = "Rule " + strconv.Itoa(i+1)
		}
		// A stable id survives reordering, so a simulation result or an audit
		// entry still points at a recognisable rule after the list is edited.
		if strings.TrimSpace(rule.ID) == "" {
			rule.ID = uuid.NewString()
		}
		switch rule.Action {
		case store.ActionAllow, store.ActionBlock, store.ActionElevate, store.ActionDefault:
		default:
			return nil, errBadPolicy("rule " + rule.Name + " has an unknown action " + rule.Action)
		}
		// Caught here as well as in the matcher. The matcher failing closed
		// protects the fleet; rejecting it here tells the operator, so they do
		// not sit looking at a rule that silently does nothing.
		if rule.Match.Empty() {
			return nil, errBadPolicy("rule " + rule.Name + " has no criteria, so it would match nothing")
		}
	}
	return &p, nil
}

type errBadPolicy string

func (e errBadPolicy) Error() string { return string(e) }
