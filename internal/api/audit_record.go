package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// auditEntry describes something worth recording.
type auditEntry struct {
	Action     string
	Resource   string
	ResourceID string
	Status     string
	Details    map[string]any

	// Machine is optional. When given, its name and agent id are denormalised
	// onto the entry so the record still reads correctly after the machine is
	// removed — which is exactly when somebody goes looking.
	Machine *store.Machine
}

// record writes one audit entry.
//
// Actor and tenant come from the gateway-injected identity, never from the
// request body: an audit trail a caller can forge is not an audit trail.
//
// A failure to write is logged but never fails the request. The alternative —
// refusing an operation because its audit entry could not be stored — would
// make a database hiccup break remote support, and the operation itself is
// already logged to the service log.
func (h *Handler) record(c *gin.Context, e auditEntry) {
	status := e.Status
	if status == "" {
		status = "success"
	}

	entry := &store.AuditLog{
		ActorID:    c.GetHeader("X-User-ID"),
		ActorName:  c.GetHeader("X-Username"),
		ActorRole:  c.GetHeader("X-User-Role"),
		TenantID:   c.GetString("tenant_id"),
		Action:     e.Action,
		Resource:   e.Resource,
		ResourceID: e.ResourceID,
		Details:    e.Details,
		IPAddress:  c.ClientIP(),
		Status:     status,
		Timestamp:  time.Now(),
	}

	if e.Machine != nil {
		entry.MachineName = e.Machine.Name
		entry.AgentID = e.Machine.AgentID
		// A machine-scoped action belongs to the machine's tenant, which is
		// the one a compliance report for that fleet will filter on.
		if entry.TenantID == "" {
			entry.TenantID = e.Machine.TenantID
		}
	}

	if err := h.store.CreateAuditLog(entry); err != nil {
		h.logger.Warn("Could not write an audit entry",
			zap.String("action", e.Action), zap.Error(err))
	}
}
