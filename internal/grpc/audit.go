package grpc

import (
	"time"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// Agent-side audit entries.
//
// These are written without a request context: nobody is making a request.
// The actor is the agent itself, recorded as such rather than left blank —
// "who registered this machine" has an answer, and it is not a person.

// recordAgentEvent writes one entry attributed to a machine's own agent.
//
// Failures are swallowed on purpose. An audit write that could stop a machine
// registering, or block a policy push, would turn a database hiccup into a
// fleet outage; the operation is already in the service log either way.
func (s *AgentServer) recordAgentEvent(machine *store.Machine, action string, details map[string]any) {
	if machine == nil {
		return
	}
	_ = s.store.CreateAuditLog(&store.AuditLog{
		ActorName:   "agent",
		ActorRole:   "system",
		TenantID:    machine.TenantID,
		Action:      action,
		Resource:    "machine",
		ResourceID:  machine.AgentID,
		MachineName: machine.Name,
		AgentID:     machine.AgentID,
		Details:     details,
		Status:      "success",
		Timestamp:   time.Now(),
	})
}
