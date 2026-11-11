package grpc

import (
	"encoding/json"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// PrivEnforcementDiscriminator is the tag agents report least-privilege
// actions under. Mirrored by a constant in the agent and pinned by a drift
// test.
const PrivEnforcementDiscriminator = "__priv_enforcement__"

// maxPrivEvents bounds one report. The agent caps its own buffer at 500.
const maxPrivEvents = 2000

// privEventReport mirrors the agent's envelope.
type privEventReport struct {
	ReportedAt   time.Time   `json:"reported_at"`
	AgentVersion string      `json:"agent_version"`
	Events       []privEvent `json:"events"`
}

// privEvent is one thing the endpoint did.
type privEvent struct {
	At        time.Time `json:"at"`
	Mechanism string    `json:"mechanism"`
	Outcome   string    `json:"outcome"`
	Username  string    `json:"username"`
	Reason    string    `json:"reason"`
	Detail    string    `json:"detail"`
}

// Mechanisms, mirroring the agent.
const (
	privMechanismDemoted    = "admin-demoted"
	privMechanismRestored   = "admin-restored"
	privMechanismRefused    = "admin-refused"
	privMechanismDeferred   = "admin-deferred"
	privMechanismBreakGlass = "break-glass-created"
	privMechanismSudo       = "sudo-rules"
	privMechanismAccountNew = "account-created"
	privMechanismPromoted   = "admin-granted"
	privMechanismGrantEnded = "admin-grant-expired"
	privMechanismEnabled    = "account-enabled"
)

// handlePrivEnforcement records what the endpoint did about administrator
// rights.
//
// These are the only record of decisions made on the machine itself. The
// endpoint re-checks every invariant against the live account database at the
// moment of the change, so a refusal here is the product declining to do
// something the portal believed it would do — which is exactly the event an
// operator needs to see and the one a silent implementation would hide.
func (s *AgentServer) handlePrivEnforcement(agentID, raw string) {
	var report privEventReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		s.logger.Warn("privilege enforcement: bad payload",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}
	if len(report.Events) == 0 {
		return
	}
	if len(report.Events) > maxPrivEvents {
		s.logger.Warn("privilege enforcement: oversized report",
			zap.String("agent_id", agentID), zap.Int("events", len(report.Events)))
		report.Events = report.Events[:maxPrivEvents]
	}

	machine, err := s.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		return
	}

	for _, ev := range report.Events {
		at := ev.At
		if at.IsZero() {
			at = report.ReportedAt
		}
		if at.IsZero() {
			at = time.Now()
		}

		details := map[string]any{
			"mechanism": ev.Mechanism,
			"outcome":   ev.Outcome,
		}
		if ev.Username != "" {
			details["username"] = ev.Username
		}
		if ev.Reason != "" {
			details["reason"] = ev.Reason
		}

		// The detail field carries the break-glass password on creation, and
		// ONLY then. It is deliberately not written to the audit trail: an
		// audit log is read by more people than should hold a standing
		// administrator credential for every machine in the fleet. It is
		// handled separately below.
		if ev.Mechanism != privMechanismBreakGlass && ev.Detail != "" {
			details["detail"] = ev.Detail
		}

		_ = s.store.CreateAuditLog(&store.AuditLog{
			ActorName: "agent", ActorRole: "system",
			TenantID:    machine.TenantID,
			Action:      privAuditAction(ev.Mechanism),
			Resource:    "machine",
			ResourceID:  agentID,
			MachineName: machine.Name, AgentID: agentID,
			Status:    privAuditStatus(ev.Outcome),
			Timestamp: at,
			Details:   details,
		})
	}

	s.logger.Info("Least privilege: endpoint activity recorded",
		zap.String("machine", machine.Name),
		zap.Int("events", len(report.Events)),
		zap.Int("demotions", countMechanism(report.Events, privMechanismDemoted)),
		zap.Int("refusals", countMechanism(report.Events, privMechanismRefused)))
}

// privAuditAction maps a mechanism to the audit vocabulary.
//
// Mapped rather than passed through so an agent reporting an unknown
// mechanism — an older or newer build — lands somewhere findable rather than
// minting an action nothing in the portal filters on.
func privAuditAction(mechanism string) string {
	switch mechanism {
	case privMechanismDemoted:
		return store.AuditAdminRightsRemoved
	case privMechanismRestored:
		return store.AuditAdminRightsRestored
	case privMechanismBreakGlass:
		return store.AuditBreakGlassCreated
	case privMechanismAccountNew:
		return store.AuditAccountCreated
	case privMechanismPromoted, privMechanismGrantEnded, privMechanismEnabled:
		// All three are an administrator changing an existing account, which
		// is one audit question: "what was done to this account, by whom,
		// and when". The mechanism in the details says which.
		return store.AuditAccountManaged
	case privMechanismRefused, privMechanismDeferred, privMechanismSudo:
		return store.AuditPrivilegeEnforcementSkipped
	default:
		return store.AuditPrivilegeEnforcementSkipped
	}
}

// privAuditStatus maps an outcome to the audit status vocabulary.
func privAuditStatus(outcome string) string {
	switch strings.ToLower(outcome) {
	case "applied":
		return "success"
	case "failed":
		return "failure"
	default:
		return "skipped"
	}
}

func countMechanism(events []privEvent, mechanism string) int {
	n := 0
	for _, e := range events {
		if e.Mechanism == mechanism {
			n++
		}
	}
	return n
}
