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

	// Alerting runs after the write, and never blocks it. The record is the
	// thing that must not be lost; the mail is a convenience on top of it.
	go s.alertOnElevation(machine, rows)
}

// Cooldowns for the two elevation alerts.
//
// They differ because the things they report differ. An application actually
// running with administrator rights is an event, and worth hearing about each
// time it happens on a new day. A rule that cannot be honoured is a standing
// condition the endpoint re-reports for as long as the rule exists — so it is
// worth saying once a day, not every five minutes for ever.
const (
	elevationGrantedCooldown   = time.Hour
	elevationUnavailableCooldn = 24 * time.Hour
	// Short, because what matters about a refusal is that it is happening
	// repeatedly, and a long window would report a hundred attempts as one.
	elevationRefusedCooldown = 15 * time.Minute
)

// The four things that can be said about an elevation event.
const (
	elevationGranted     = "granted"
	elevationLaunched    = "launched"
	elevationUnavailable = "unavailable"
	elevationRefused     = "refused"
)

// classifyElevation decides which of the four an event is, and how long to
// stay quiet about another like it.
//
// Pure, and separate from the sending, because the routing is the part that
// was wrong: the first version had two branches and keyed only on the outcome,
// so a FAILED elevate-launch — somebody trying to start something with
// administrator rights and being refused — was mailed as "this rule is not
// being honoured on this machine". Those are opposite facts. One says the
// administrator's configuration is broken; the other says their configuration
// is working and somebody is pushing against it. Sending the first when the
// second is true dispatches them to repair a rule that is doing its job, while
// the probing continues.
func classifyElevation(mechanism, outcome string) (kind string, cooldown time.Duration, ok bool) {
	switch {
	case mechanism == store.EnforceElevate && outcome == store.OutcomeApplied:
		return elevationGranted, elevationGrantedCooldown, true

	// An application actually RAN elevated: the most security-relevant event
	// this product can report, and given its own kind so it claims separately
	// from the grant that permitted it.
	case mechanism == store.EnforceElevateLaunch && outcome == store.OutcomeApplied:
		return elevationLaunched, elevationGrantedCooldown, true

	// A standing condition. The endpoint re-reports it for as long as the rule
	// exists, so it is said once a day.
	case mechanism == store.EnforceElevate && outcome == store.OutcomeFailed:
		return elevationUnavailable, elevationUnavailableCooldn, true

	// An attempt, not a condition. What matters is REPETITION, so the window
	// is short — a daily digest would report a hundred attempts as one.
	case mechanism == store.EnforceElevateLaunch && outcome == store.OutcomeFailed:
		return elevationRefused, elevationRefusedCooldown, true
	}
	return "", 0, false
}

// alertOnElevation mails about privileges being GIVEN.
//
// Everything else application control reports is a restriction, where the
// worst case of a mistake is software that will not start. This is the one
// direction that hands out administrator rights, and the one where finding out
// a month later from a report is too late.
//
// The second case — a rule the machine cannot honour — is mailed for the
// opposite reason: the administrator who wrote it believes software is running
// elevated and it is not. That is the failure this product has already shipped
// twice, and a notification is what stops the third time being discovered
// months later.
func (s *AgentServer) alertOnElevation(machine *store.Machine, rows []store.EnforcementEvent) {
	// NotifyEmails is collected from authorised people who have opened this
	// machine in the portal. None yet is not a failure.
	if len(machine.NotifyEmails) == 0 {
		return
	}

	for _, e := range rows {
		isElevation := e.Mechanism == store.EnforceElevate || e.Mechanism == store.EnforceElevateLaunch
		if !isElevation {
			continue
		}

		var send func() error

		kind, cooldown, ok := classifyElevation(e.Mechanism, e.Outcome)
		if !ok {
			continue
		}

		switch kind {
		case elevationGranted, elevationLaunched:
			send = func() error {
				return s.email.SendElevationAlert(machine.NotifyEmails,
					machine.Name, e.AppName, e.Path, e.Rule, e.Policy, "", e.At)
			}
		case elevationUnavailable:
			send = func() error {
				return s.email.SendElevationUnavailable(machine.NotifyEmails,
					machine.Name, e.AppName, e.Rule, e.Policy, e.Detail)
			}
		case elevationRefused:
			send = func() error {
				return s.email.SendElevationRefused(machine.NotifyEmails,
					machine.Name, e.AppName, e.Path, "", e.Detail, e.At)
			}
		}

		// The key deliberately leaves out the time and the event id: both
		// would make every claim unique and turn the suppression off without
		// anything appearing to be wrong.
		key := store.NotificationKey("elevation", kind, machine.TenantID, machine.AgentID, e.AppName)
		ok, err := s.store.ClaimNotification(key, cooldown)
		if err != nil {
			// Claiming fails open, so this is a warning about the dedup, not
			// about the alert — which is being sent.
			s.logger.Warn("elevation alert: could not record the notification claim",
				zap.String("key", key), zap.Error(err))
		}
		if !ok {
			continue
		}

		if err := send(); err != nil {
			s.logger.Warn("elevation alert: email failed",
				zap.String("machine", machine.Name),
				zap.String("app", e.AppName), zap.Error(err))
		}
	}
}

// clampField bounds one piece of agent-supplied text.
func clampField(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > maxEnforcementFieldLength {
		return v[:maxEnforcementFieldLength]
	}
	return v
}
