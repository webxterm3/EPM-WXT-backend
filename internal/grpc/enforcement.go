package grpc

import (
	"encoding/json"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// EnforcementDiscriminator is the StatusUpdate tag agents report enforcement
// activity under. It is mirrored by a constant in the agent and pinned by a
// cross-repo drift test — a mismatch is not a compile error, the reports
// simply stop arriving and the portal shows a fleet where nothing was ever
// blocked.
const EnforcementDiscriminator = "__app_enforcement__"

// maxEnforcementBatch bounds one report.
//
// The agent's own queue is capped at 500, so a batch bigger than that is a bug
// or something hostile, and accepting it is the easy way to let one machine
// fill the collection.
const maxEnforcementBatch = 1000

// maxEnforcementFieldLength truncates free text arriving from an endpoint.
//
// Application names and paths come off somebody's machine, where they can be
// anything, and they are rendered in the portal. Length is bounded here
// because it reaches storage; escaping is the renderer's job.
const maxEnforcementFieldLength = 512

// enforcementReport mirrors the agent's report envelope.
type enforcementReport struct {
	ReportedAt   time.Time          `json:"reported_at"`
	AgentVersion string             `json:"agent_version"`
	Mechanism    string             `json:"mechanism"`
	Events       []enforcementEvent `json:"events"`
}

// enforcementEvent mirrors the agent's Event record.
type enforcementEvent struct {
	At        time.Time `json:"at"`
	Mechanism string    `json:"mechanism"`
	Outcome   string    `json:"outcome"`
	AppName   string    `json:"app_name"`
	Path      string    `json:"path"`
	BundleID  string    `json:"bundle_id"`
	Rule      string    `json:"rule"`
	Policy    string    `json:"policy"`
	PID       int       `json:"pid"`
	Detail    string    `json:"detail"`
}

// handleEnforcementReport stores what an agent did to the software on its
// machine.
//
// This is the only record of those decisions. They were made on the endpoint,
// in a process nobody was watching, possibly while it was offline — so if this
// is dropped there is no second place to look, and "why did my browser close"
// has no answer at all.
func (s *AgentServer) handleEnforcementReport(agentID, payload string) {
	var report enforcementReport
	if err := json.Unmarshal([]byte(payload), &report); err != nil {
		s.logger.Warn("enforcement report: could not decode",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}
	if len(report.Events) == 0 {
		return
	}
	if len(report.Events) > maxEnforcementBatch {
		s.logger.Warn("enforcement report: oversized batch truncated",
			zap.String("agent_id", agentID), zap.Int("events", len(report.Events)))
		report.Events = report.Events[:maxEnforcementBatch]
	}

	machine, err := s.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		s.logger.Warn("enforcement report: unknown agent",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}

	now := time.Now()
	rows := make([]store.EnforcementEvent, 0, len(report.Events))
	for _, e := range report.Events {
		at := e.At
		// A machine with a wrong clock would otherwise file events in the far
		// future or the distant past, where nobody looking at a recent window
		// would ever see them.
		if at.IsZero() || at.After(now.Add(time.Hour)) {
			at = now
		}
		rows = append(rows, store.EnforcementEvent{
			TenantID:    machine.TenantID,
			AgentID:     agentID,
			MachineID:   machine.ID,
			MachineName: machine.Name,
			At:          at,
			CreatedAt:   now,
			Mechanism:   clampField(e.Mechanism),
			Outcome:     clampField(e.Outcome),
			AppName:     clampField(e.AppName),
			Path:        clampField(e.Path),
			BundleID:    clampField(e.BundleID),
			Rule:        clampField(e.Rule),
			Policy:      clampField(e.Policy),
			PID:         e.PID,
			Detail:      clampField(e.Detail),
			EnforcedBy:  clampField(report.Mechanism),
		})
	}

	if err := s.store.RecordEnforcementEvents(rows); err != nil {
		s.logger.Error("enforcement report: could not be stored",
			zap.String("agent_id", agentID), zap.Int("events", len(rows)), zap.Error(err))
		return
	}

	s.logger.Info("enforcement activity recorded",
		zap.String("agent_id", agentID),
		zap.String("machine", machine.Name),
		zap.Int("events", len(rows)),
		zap.String("enforced_by", report.Mechanism))
}

// clampField bounds one piece of agent-supplied text.
func clampField(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > maxEnforcementFieldLength {
		return v[:maxEnforcementFieldLength]
	}
	return v
}
