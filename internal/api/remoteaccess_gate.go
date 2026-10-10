package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/remoteaccess"
	"github.com/vsay/vsay-agent-backend/internal/store"
)

// enforceRemoteAccessPolicy applies the tenant's remote-access policy and
// writes the refusal itself when the session may not start.
//
// It runs AFTER the ownership and allowed-user checks, never instead of them.
// A policy here can only narrow what somebody may already do; it can never
// grant access to a person who was not already entitled to the machine. That
// ordering is what keeps a mistyped scope from handing out sessions.
//
// It fails OPEN on a storage error, which is a deliberate trade. This gate
// guards a support tool that an operator reaches for when something is already
// broken, and the access check in front of it has already run. Making a
// database blip the reason nobody can reach a failing machine would cause more
// harm than the narrow window it closes — but it is logged loudly, because a
// policy silently not applying is not something to discover later.
func (h *Handler) enforceRemoteAccessPolicy(c *gin.Context, machine *store.Machine, kind, reason string) (remoteaccess.Decision, bool) {
	policies, err := h.store.GetRemoteAccessPoliciesByTenant(machine.TenantID)
	if err != nil {
		h.logger.Error("Remote access policy could not be loaded — allowing the session",
			zap.String("machine", machine.Name),
			zap.String("tenant", machine.TenantID),
			zap.Error(err))
		return remoteaccess.Decision{Allowed: true, RequireConsent: kind == store.AccessAttended}, true
	}

	decision := remoteaccess.Evaluate(machine, policies, remoteaccess.Request{
		AccessKind:         kind,
		Role:               c.GetString("role"),
		Username:           c.GetString("username"),
		GroupIDs:           callerGroupIDs(c),
		Reason:             reason,
		RecordingAvailable: h.recordingAvailable(machine.TenantID),
		Now:                time.Now(),
	})

	if !decision.Allowed {
		h.logger.Info("Remote session refused by policy",
			zap.String("machine", machine.Name),
			zap.String("user", c.GetString("username")),
			zap.String("kind", kind),
			zap.String("policy", decision.PolicyName),
			zap.String("reason", decision.Reason))

		// A refusal is the most important thing this log holds: it is the
		// evidence that a control actually did something, and the first thing
		// an auditor asks for. An allowed session leaves its own trail further
		// down the start path.
		h.record(c, auditEntry{
			Action: store.AuditRemoteRefused, Resource: "machine",
			ResourceID: machine.AgentID, Status: "denied", Machine: machine,
			Details: map[string]any{
				"access_kind": kind,
				"policy":      decision.PolicyName,
				"reason":      decision.Reason,
			},
		})

		c.JSON(http.StatusForbidden, gin.H{
			"error":  decision.Reason,
			"policy": decision.PolicyName,
		})
		return decision, false
	}
	return decision, true
}

// callerGroupIDs reads the caller's groups from the gateway headers.
//
// vsay-auth puts them there after authentication; this service never looks
// them up itself, which is what keeps the two from disagreeing about who is in
// what.
func callerGroupIDs(c *gin.Context) []string {
	raw := c.GetHeader("X-User-Groups")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// recordingAvailable reports whether sessions can actually be recorded.
//
// A policy that requires recording refuses when this is false, rather than
// letting an unrecorded session through and making every later audit a lie.
func (h *Handler) recordingAvailable(tenantID string) bool {
	cfg, err := h.store.GetTenantConfig(tenantID)
	return err == nil && cfg != nil && cfg.S3.Enabled
}
