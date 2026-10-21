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

// enforcementEnabled reports whether a tenant has switched enforcement on.
//
// There is one source of truth for this — the tenant's settings document, read
// through the shared policy pusher — and both the portal's answer and the mode
// an endpoint is sent come from it. They used to come from a build-time
// constant, which meant turning enforcement on was a deployment and turning it
// off in a hurry was a deployment too.
//
// Everything fails closed: no pusher wired in, or a settings read that errors,
// reports false. An unreachable switch must mean "do not act on anybody's
// machine", never "act on whatever the policies happen to say".
func (h *Handler) enforcementEnabled(tenantID string) bool {
	if h.policyPusher == nil || tenantID == "" {
		return false
	}
	return h.policyPusher.EnforcementEnabled(tenantID)
}

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
		// Said out loud on every read so the UI never has to assume whether
		// these are being applied or only projected.
		"enforcement_enabled": h.enforcementEnabled(tenantID),
		// Likewise for the alerts. An administrator who switches on a rule
		// that mails when administrator rights are granted, and never receives
		// anything, has no way to tell a quiet fleet from a server with no
		// SMTP configured. The list is the screen they are already looking at.
		"email_notifications": emailService.Configured(),
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
	h.pushPolicyToFleet(c)
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
	h.pushPolicyToFleet(c)
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
	h.pushPolicyToFleet(c)
	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted"})
}

// pushPolicyToFleet delivers the tenant's policy to every connected machine.
//
// Called after every change, because a policy that exists only in the database
// governs nothing. Offline machines are not chased: they are sent the current
// policy when they next connect, through the same resolver.
//
// A failure here never fails the request. The policy IS saved, the portal
// should say so, and the push retries on the machine's next connect — whereas
// returning an error after a successful write would leave the operator unsure
// whether to press the button again.
func (h *Handler) pushPolicyToFleet(c *gin.Context) {
	if h.policyPusher == nil {
		return
	}
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		return
	}

	pushed, failed := h.policyPusher.PushToTenant(tenantID)
	h.logger.Info("application policy pushed",
		zap.String("tenant_id", tenantID),
		zap.Int("pushed", pushed), zap.Int("failed", failed))
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

	// Resolved against the tenant's real switch, so the projection says what
	// saving this would actually do rather than what it would do in some other
	// configuration.
	enforcing := h.enforcementEnabled(tenantID)

	sim := &policy.Simulator{
		Effective: make(map[string]policy.Effective, len(machines)),
		Machines:  make(map[string]*store.Machine, len(machines)),
	}
	for _, m := range machines {
		if m.AgentID == "" || m.Revoked {
			continue
		}
		sim.Effective[m.AgentID] = policy.Resolve(m, combined, enforcing)
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
		"enforcement_enabled": enforcing,
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
	// Removal only means anything for a policy that blocks something, and a
	// default-deny policy must not be able to reach it: the rules in such a
	// policy are the ALLOW list, so nothing a rule matched is blocked, and
	// everything else would be swept off the machine by the catch-all.
	if p.DefaultAction == store.ActionBlock {
		p.RemoveBlocked = false
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

// GetAppControlSettings handles GET /api/app-control/settings.
func (h *Handler) GetAppControlSettings(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	settings, err := h.store.GetAppControlSettings(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load settings"})
		return
	}

	// Whether an alert would actually be delivered, stated rather than left to
	// be inferred from its absence.
	//
	// Send is a no-op when no SMTP is configured, which is the right default
	// for an optional notification and the wrong thing to be quiet about: an
	// administrator who expects mail about administrator rights being granted,
	// and never receives any, cannot tell "nothing happened" from "nothing was
	// ever going to be sent". This is the difference, on the screen where the
	// alerts are switched on.
	// Embedded rather than rebuilt field by field, so adding this cannot drop
	// one the portal already reads.
	c.JSON(http.StatusOK, struct {
		*store.AppControlSettings
		EmailNotifications bool `json:"email_notifications"`
	}{settings, emailService.Configured()})
}

// SetAppControlEnforcement handles PUT /api/app-control/settings.
//
// This is the switch between a product that watches and one that closes
// somebody's browser, so it is deliberately its own endpoint rather than a
// field on a policy: turning it on is one decision, made once, recorded in the
// audit trail with a name against it, and not something that can ride along
// unnoticed with an ordinary policy edit.
func (h *Handler) SetAppControlEnforcement(c *gin.Context) {
	tenantID, ok := h.requirePolicyAdmin(c)
	if !ok {
		return
	}

	var body struct {
		// A pointer so that an omitted field is rejected rather than read as
		// false. "Turn enforcement off" and "I forgot to send the field" must
		// not be the same request.
		Enforcement *bool `json:"enforcement"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Enforcement == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enforcement must be true or false"})
		return
	}

	actor := c.GetString("username")
	if err := h.store.SetAppControlEnforcement(tenantID, *body.Enforcement, actor); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save settings"})
		return
	}

	h.record(c, auditEntry{
		Action: store.AuditPolicyUpdated, Resource: "application_control",
		ResourceID: tenantID,
		Details: map[string]any{
			"setting": "enforcement", "enabled": *body.Enforcement,
		},
	})
	// Info, not Warn.
	//
	// Somebody deliberately flipping a switch is not a warning, and this
	// logger attaches a stack trace to everything at Warn and above — so every
	// time an operator turned enforcement on or off the server log grew a
	// twenty-line stack that reads exactly like a crash. It was reported as
	// one. The audit entry above is the record that matters; this line is for
	// whoever is tailing the log.
	h.logger.Info("application-control enforcement changed",
		zap.String("tenant_id", tenantID), zap.String("actor", actor),
		zap.Bool("enforcement", *body.Enforcement))

	// Pushed immediately. The switch only means anything once the endpoints
	// have been told, and an operator who has just turned enforcement off is
	// very likely doing it because something is going wrong right now.
	h.pushPolicyToFleet(c)

	c.JSON(http.StatusOK, gin.H{
		"enforcement": *body.Enforcement,
		"message":     enforcementMessage(*body.Enforcement),
	})
}

func enforcementMessage(on bool) string {
	if on {
		return "Enforcement is on. Policies set to enforce will now block software on your machines."
	}
	return "Enforcement is off. Policies are evaluated and reported, and nothing is blocked."
}

// searchTermLimit caps a typed search before it reaches the database.
// Unbounded input becomes an unbounded regex, which is a way to make the
// database do arbitrary work from a query string.
const searchTermLimit = 200

// ListEnforcementEvents handles GET /api/app-control/events.
//
// This is the answer to "why did my application stop working", and the only
// one there is: the decision was made on an endpoint, by a process nobody was
// watching, possibly while the machine was offline.
func (h *Handler) ListEnforcementEvents(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}

	// Searching happens here rather than in the browser, because the browser
	// only ever holds one page. Filtering those fifty rows would answer
	// "where is Steam on this page", which is never the question — the whole
	// point of the search is to find the one event somewhere in a year of
	// them.
	search := strings.TrimSpace(c.Query("q"))
	if len(search) > searchTermLimit {
		search = search[:searchTermLimit]
	}

	events, total, err := h.store.GetEnforcementEvents(store.EnforcementEventQuery{
		TenantID: tenantID,
		AgentID:  strings.TrimSpace(c.Query("agent_id")),
		Search:   search,
		Limit:    limit,
		Skip:     (page - 1) * limit,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load enforcement activity"})
		return
	}
	if events == nil {
		events = []*store.EnforcementEvent{}
	}

	c.JSON(http.StatusOK, gin.H{
		"events": events, "total": total, "page": page, "limit": limit,
		// Echoed back so the UI can say "no events match X" rather than
		// "no events", which are different facts and send people looking in
		// different places.
		"search":              search,
		"enforcement_enabled": h.enforcementEnabled(tenantID),
	})
}
