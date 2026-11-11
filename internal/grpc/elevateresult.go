package grpc

import (
	"encoding/json"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// ElevateResultDiscriminator is the tag agents report brokered commands
// under. Mirrored by a constant in the agent and pinned by a drift test.
//
// Its own channel rather than riding the privilege enforcement report,
// because these arrive at human pace — somebody pressed a button — and
// burying them in a batch that flushes every few minutes would show a
// privileged command in the portal minutes after it ran.
const ElevateResultDiscriminator = "__elevate_result__"

// maxElevateResults bounds one report.
//
// A person runs one command at a time. A report carrying hundreds is either a
// bug or a machine whose queue somebody filled deliberately.
const maxElevateResults = 200

// elevateReport mirrors the agent's envelope.
type elevateReport struct {
	ReportedAt   time.Time       `json:"reported_at"`
	AgentVersion string          `json:"agent_version"`
	Results      []elevateResult `json:"results"`
}

// elevateResult is one command the agent ran on somebody's behalf.
type elevateResult struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	Command   string    `json:"command"`
	Allowed   bool      `json:"allowed"`
	Verdict   string    `json:"verdict"`
	Reason    string    `json:"reason"`
	ExitCode  int       `json:"exit_code"`
	Output    string    `json:"output"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
}

// maxStoredOutput bounds what reaches the audit trail.
//
// The agent already truncates at 8KB. This is the second bound, because the
// agent is a thing on somebody's machine and the size of what it sends is not
// something this side should take on trust.
const maxStoredOutput = 8 * 1024

// handleElevateResult records a command the agent ran with elevated rights on
// a standard user's behalf.
//
// This is the Windows half of sudo management. On macOS and Linux the
// equivalent command runs as the person's own process through sudoers and is
// not reported here — which is a real gap in the trail, and the compliance
// report says so rather than letting these entries imply full coverage.
func (s *AgentServer) handleElevateResult(agentID, raw string) {
	var report elevateReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		s.logger.Warn("command elevation: bad payload",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}
	if len(report.Results) == 0 {
		return
	}
	if len(report.Results) > maxElevateResults {
		s.logger.Warn("command elevation: oversized report",
			zap.String("agent_id", agentID), zap.Int("results", len(report.Results)))
		report.Results = report.Results[:maxElevateResults]
	}

	machine, err := s.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		return
	}

	for _, r := range report.Results {
		at := r.EndedAt
		if at.IsZero() {
			at = report.ReportedAt
		}
		if at.IsZero() {
			at = time.Now()
		}

		details := map[string]any{
			"command": r.Command,
			"verdict": r.Verdict,
			"allowed": r.Allowed,
		}
		if r.User != "" {
			details["os_user"] = r.User
		}
		if r.Reason != "" {
			details["reason"] = r.Reason
		}
		if r.Allowed {
			details["exit_code"] = r.ExitCode
			if out := strings.TrimSpace(r.Output); out != "" {
				if len(out) > maxStoredOutput {
					out = out[:maxStoredOutput] + "\n… (truncated)"
				}
				details["output"] = out
			}
		}

		status := "success"
		switch {
		case !r.Allowed:
			status = "blocked"
		case r.ExitCode != 0:
			// The command ran and failed on its own terms. Recorded as a
			// failure of the command, not of the permission — the two are
			// different findings and an auditor filtering for refused
			// privilege should not see this one.
			status = "failure"
		}

		_ = s.store.CreateAuditLog(&store.AuditLog{
			ActorName: r.User, ActorRole: "endpoint_user",
			TenantID:    machine.TenantID,
			Action:      store.AuditCommandElevated,
			Resource:    "machine",
			ResourceID:  agentID,
			MachineName: machine.Name, AgentID: agentID,
			Status:    status,
			Timestamp: at,
			Details:   details,
		})
	}

	allowed := 0
	for _, r := range report.Results {
		if r.Allowed {
			allowed++
		}
	}
	s.logger.Info("Command elevation: results recorded",
		zap.String("machine", machine.Name),
		zap.Int("results", len(report.Results)),
		zap.Int("allowed", allowed),
		zap.Int("refused", len(report.Results)-allowed))
}
