package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// ListRemoteAccessPolicies handles GET /api/remote-access-policies.
func (h *Handler) ListRemoteAccessPolicies(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	policies, err := h.store.GetRemoteAccessPoliciesByTenant(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load policies"})
		return
	}

	// Whether recording is actually possible changes what a "require
	// recording" policy will do, so the UI is told rather than left to guess.
	c.JSON(http.StatusOK, gin.H{
		"policies":            policies,
		"recording_available": h.recordingAvailable(tenantID),
	})
}

// GetRemoteAccessPolicy handles GET /api/remote-access-policies/:id.
func (h *Handler) GetRemoteAccessPolicy(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy id"})
		return
	}
	p, err := h.store.GetRemoteAccessPolicyByID(c.GetString("tenant_id"), id)
	if err != nil || p == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}
	c.JSON(http.StatusOK, p)
}

// CreateRemoteAccessPolicy handles POST /api/remote-access-policies.
func (h *Handler) CreateRemoteAccessPolicy(c *gin.Context) {
	tenantID, ok := h.requirePolicyAdmin(c)
	if !ok {
		return
	}

	var body store.RemoteAccessPolicy
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	p, err := prepareRemoteAccessPolicy(body, tenantID, c.GetString("username"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p.CreatedBy = c.GetString("username")

	if err := h.store.CreateRemoteAccessPolicy(p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.record(c, auditEntry{
		Action: store.AuditPolicyCreated, Resource: "remote_access_policy",
		ResourceID: p.ID.Hex(), Details: remoteAccessAuditDetails(p),
	})
	c.JSON(http.StatusCreated, p)
}

// UpdateRemoteAccessPolicy handles PUT /api/remote-access-policies/:id.
func (h *Handler) UpdateRemoteAccessPolicy(c *gin.Context) {
	tenantID, ok := h.requirePolicyAdmin(c)
	if !ok {
		return
	}
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy id"})
		return
	}

	var body store.RemoteAccessPolicy
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	p, err := prepareRemoteAccessPolicy(body, tenantID, c.GetString("username"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p.ID = id

	if err := h.store.UpdateRemoteAccessPolicy(p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.record(c, auditEntry{
		Action: store.AuditPolicyUpdated, Resource: "remote_access_policy",
		ResourceID: p.ID.Hex(), Details: remoteAccessAuditDetails(p),
	})
	c.JSON(http.StatusOK, p)
}

// DeleteRemoteAccessPolicy handles DELETE /api/remote-access-policies/:id.
func (h *Handler) DeleteRemoteAccessPolicy(c *gin.Context) {
	tenantID, ok := h.requirePolicyAdmin(c)
	if !ok {
		return
	}
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy id"})
		return
	}
	existing, _ := h.store.GetRemoteAccessPolicyByID(tenantID, id)

	if err := h.store.DeleteRemoteAccessPolicy(tenantID, id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	details := map[string]any{}
	if existing != nil {
		details = remoteAccessAuditDetails(existing)
	}
	h.record(c, auditEntry{
		Action: store.AuditPolicyDeleted, Resource: "remote_access_policy",
		ResourceID: id.Hex(), Details: details,
	})
	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted"})
}

// prepareRemoteAccessPolicy validates and normalises a submitted policy.
func prepareRemoteAccessPolicy(p store.RemoteAccessPolicy, tenantID, actor string) (*store.RemoteAccessPolicy, error) {
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

	if !p.AllowAttended && !p.AllowUnattended && !p.AllowTerminal {
		// Saving this would lock every route to those machines. It is almost
		// certainly a half-filled form, and it is cheap to say so.
		return nil, errBadPolicy("this policy forbids every way in, which would make the machines unreachable — allow at least one")
	}

	for i := range p.TimeWindows {
		w := &p.TimeWindows[i]
		if w.StartMinute < 0 || w.StartMinute > 24*60 || w.EndMinute < 0 || w.EndMinute > 24*60 {
			return nil, errBadPolicy("a time window must fall within a day")
		}
		if w.StartMinute == w.EndMinute {
			// A zero-length window permits nothing, which is a confusing way
			// to express "never".
			return nil, errBadPolicy("a time window that starts and ends at the same minute permits nothing")
		}
		for _, d := range w.Days {
			if d < 0 || d > 6 {
				return nil, errBadPolicy("a time window's days must be 0 (Sunday) to 6 (Saturday)")
			}
		}
		w.Timezone = strings.TrimSpace(w.Timezone)
	}

	if p.MaxSessionMinutes < 0 {
		p.MaxSessionMinutes = 0
	}
	return &p, nil
}

// remoteAccessAuditDetails records what a policy actually permits.
//
// The restrictions themselves, not just the name: a reader six months later
// needs to know what the policy said at the time, and the policy may have been
// edited or deleted since.
func remoteAccessAuditDetails(p *store.RemoteAccessPolicy) map[string]any {
	return map[string]any{
		"name":              p.Name,
		"scope":             p.Scope.Kind,
		"enabled":           p.Enabled,
		"allow_attended":    p.AllowAttended,
		"allow_unattended":  p.AllowUnattended,
		"allow_terminal":    p.AllowTerminal,
		"time_windows":      len(p.TimeWindows),
		"require_consent":   p.RequireConsent,
		"require_recording": p.RequireRecording,
		"max_session_mins":  p.MaxSessionMinutes,
	}
}
