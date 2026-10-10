package grpc

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/policy"
	"github.com/vsay/vsay-agent-backend/internal/store"
)

// AppInventoryDiscriminator is the StatusUpdate tag agents report installed
// software under. It is mirrored by a constant in the agent and pinned by a
// cross-repo drift test — a mismatch is not a compile error, the reports
// simply stop arriving and the whole fleet shows no software.
const AppInventoryDiscriminator = "__app_inventory__"

// maxInventoryChunkApps bounds one report.
//
// The agent chunks at 250. A report claiming far more than that is either a
// bug or something hostile, and allocating for it is the easiest way to let
// one machine exhaust the backend.
const maxInventoryChunkApps = 5000

// maxScanIDLength bounds the snapshot id, which reaches a database filter.
const maxScanIDLength = 64

// inventoryReport mirrors the agent's report envelope.
type inventoryReport struct {
	SnapshotID string `json:"snapshot_id"`
	Chunk      int    `json:"chunk"`
	Chunks     int    `json:"chunks"`

	CollectedAt  time.Time `json:"collected_at"`
	OS           string    `json:"os"`
	AgentVersion string    `json:"agent_version"`
	CollectError string    `json:"collect_error"`

	Apps []inventoryApp `json:"apps"`
}

// inventoryApp mirrors the agent's Application record.
type inventoryApp struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Publisher   string    `json:"publisher"`
	InstallPath string    `json:"install_path"`
	ExePath     string    `json:"exe_path"`
	BundleID    string    `json:"bundle_id"`
	Scope       string    `json:"scope"`
	OSUser      string    `json:"os_user"`
	Source      string    `json:"source"`
	InstalledAt time.Time `json:"installed_at"`
	Arch        string    `json:"arch"`
}

// final reports whether this chunk completes its snapshot.
func (r inventoryReport) final() bool { return r.Chunk == r.Chunks-1 }

// mayMarkRemoved reports whether this report is allowed to conclude that
// software it does NOT mention is gone.
//
// Two conditions, and both matter. A non-final chunk is only part of the
// picture. A scan whose collector errored is a picture with holes in it — the
// agent reached its timeout, or a registry hive would not open — and the
// missing entries are missing because of the error, not because anybody
// uninstalled anything.
//
// Getting this wrong turns one crashed agent into a machine that reports its
// entire software estate as uninstalled, and a policy simulation built on top
// of that fiction.
func (r inventoryReport) mayMarkRemoved() bool {
	return r.final() && strings.TrimSpace(r.CollectError) == ""
}

// validate rejects a report that cannot be trusted to reconcile.
func (r inventoryReport) validate() error {
	id := strings.TrimSpace(r.SnapshotID)
	if id == "" {
		return fmt.Errorf("no snapshot id")
	}
	if len(id) > maxScanIDLength {
		return fmt.Errorf("snapshot id is %d characters", len(id))
	}
	// The id reaches a database filter, so it is restricted to characters that
	// cannot mean anything there.
	for _, c := range id {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex && c != '-' {
			return fmt.Errorf("snapshot id contains %q", c)
		}
	}
	if r.Chunks < 1 || r.Chunk < 0 || r.Chunk >= r.Chunks {
		return fmt.Errorf("chunk %d of %d is not a valid position", r.Chunk, r.Chunks)
	}
	if len(r.Apps) > maxInventoryChunkApps {
		return fmt.Errorf("chunk carries %d applications", len(r.Apps))
	}
	return nil
}

// toInstalledApps converts the reported records, dropping any that cannot be
// stored. A record with no identity cannot be reconciled against the next
// scan; a record with no name cannot be displayed or matched by a policy.
func (r inventoryReport) toInstalledApps() []store.InstalledApp {
	out := make([]store.InstalledApp, 0, len(r.Apps))
	for _, a := range r.Apps {
		if strings.TrimSpace(a.ID) == "" || strings.TrimSpace(a.Name) == "" {
			continue
		}
		app := store.InstalledApp{
			AppKey:      a.ID,
			Name:        a.Name,
			Version:     a.Version,
			Publisher:   a.Publisher,
			InstallPath: a.InstallPath,
			ExePath:     a.ExePath,
			BundleID:    a.BundleID,
			Scope:       a.Scope,
			OSUser:      a.OSUser,
			Source:      a.Source,
			Arch:        a.Arch,
		}
		if !a.InstalledAt.IsZero() {
			t := a.InstalledAt
			app.InstalledAt = &t
		}
		out = append(out, app)
	}
	return out
}

// handleAppInventory stores one chunk of a machine's installed-software
// snapshot.
//
// The removal sweep runs only on the final chunk of a scan that collected
// cleanly. A partial or failed scan says nothing about what is missing, and
// treating it as if it did would turn one crashed agent into a machine that
// looks wiped — with every application marked uninstalled, and a policy
// simulation built on that fiction.
func (s *AgentServer) handleAppInventory(agentID, raw string) {
	var report inventoryReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		s.logger.Warn("app inventory: bad payload",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}
	if err := report.validate(); err != nil {
		s.logger.Warn("app inventory: rejected report",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}

	machine, err := s.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		return
	}

	now := time.Now()

	// The scan row is created by the first chunk and only by it, so the
	// counters below accumulate against one record.
	if report.Chunk == 0 {
		scan := &store.InventoryScan{
			MachineID:    machine.ID,
			AgentID:      agentID,
			TenantID:     machine.TenantID,
			ScanID:       report.SnapshotID,
			OS:           report.OS,
			AgentVersion: report.AgentVersion,
			Chunks:       report.Chunks,
			CollectError: report.CollectError,
			StartedAt:    now,
		}
		if err := s.store.CreateInventoryScan(scan); err != nil {
			s.logger.Warn("app inventory: could not record the scan",
				zap.String("agent_id", agentID), zap.Error(err))
		}
	}

	apps := report.toInstalledApps()
	added, updated, newApps, err := s.store.UpsertInventoryChunk(machine, report.SnapshotID, apps, now)
	if err != nil {
		s.logger.Warn("app inventory: could not store a chunk",
			zap.String("machine", machine.Name),
			zap.Int("chunk", report.Chunk), zap.Error(err))
		return
	}

	var removed int64
	complete := report.final()

	// Newly-installed software is checked against policy as it arrives. This
	// is detection, not enforcement: nothing is blocked, and the events say so
	// by name. It is what makes application control produce evidence before
	// the endpoint side of it exists.
	s.flagPolicyViolations(machine, newApps)

	if report.mayMarkRemoved() {
		removed, err = s.store.SweepRemovedApps(agentID, report.SnapshotID, now)
		if err != nil {
			s.logger.Warn("app inventory: removal sweep failed",
				zap.String("machine", machine.Name), zap.Error(err))
		}
	} else if complete {
		// Finished, but with holes in it. Recording what was found is still
		// worth doing; concluding that everything else is gone is not.
		s.logger.Warn("app inventory: scan reported an error — nothing marked removed",
			zap.String("machine", machine.Name),
			zap.String("collect_error", report.CollectError))
	}

	if err := s.store.UpdateInventoryScan(agentID, report.SnapshotID,
		added, updated, removed, len(apps), complete, now); err != nil {
		s.logger.Warn("app inventory: could not update the scan record",
			zap.String("agent_id", agentID), zap.Error(err))
	}

	if complete {
		// Recorded so "when did this machine last tell us what it has" is
		// answerable from the audit trail rather than only from a log file.
		_ = s.store.CreateAuditLog(&store.AuditLog{
			ActorName: "agent", ActorRole: "system",
			TenantID: machine.TenantID,
			Action:   store.AuditInventoryReported, Resource: "machine",
			ResourceID: agentID, MachineName: machine.Name, AgentID: agentID,
			Status: "success", Timestamp: now,
			Details: map[string]any{
				"applications": len(apps), "added": added,
				"updated": updated, "removed": removed,
			},
		})

		s.logger.Info("Application inventory reconciled",
			zap.String("machine", machine.Name),
			zap.Int("chunks", report.Chunks),
			zap.Int64("added", added),
			zap.Int64("updated", updated),
			zap.Int64("removed", removed))
	}
}

// flagPolicyViolations records newly-installed software that policy forbids.
//
// Deliberately NOT named "blocked": nothing was blocked. These events say that
// an application matching a block or elevate rule has appeared on a machine,
// which is a real compliance finding and a real thing to act on — but calling
// it "blocked" would read as evidence that execution was prevented, which it
// was not. That distinction is the whole reason the audit trail is worth
// trusting.
//
// Only applications new to the machine are reported. Evaluating the whole
// inventory on every scan would re-report the same findings twice a day
// forever, and a trail that repeats itself is one nobody reads.
func (s *AgentServer) flagPolicyViolations(machine *store.Machine, newApps []store.InstalledApp) {
	if len(newApps) == 0 {
		return
	}

	policies, err := s.store.GetAppPoliciesByTenant(machine.TenantID)
	if err != nil || len(policies) == 0 {
		return
	}

	// Enforcement is off for the whole of this phase; resolving with it off
	// keeps the decision identical to what the portal's simulation shows.
	effective := policy.Resolve(machine, policies, false)
	if len(effective.Rules) == 0 {
		return
	}

	for i := range newApps {
		app := newApps[i]
		app.MachineID = machine.ID
		app.AgentID = machine.AgentID
		app.TenantID = machine.TenantID

		decision := effective.Decide(&app)
		if !decision.Matched || decision.Action == store.ActionAllow {
			continue
		}

		_ = s.store.CreateAuditLog(&store.AuditLog{
			ActorName: "agent", ActorRole: "system",
			TenantID:    machine.TenantID,
			Action:      store.AuditAppPolicyViolation,
			Resource:    "application",
			ResourceID:  app.AppKey,
			MachineName: machine.Name,
			AgentID:     machine.AgentID,
			Status:      "detected",
			Timestamp:   time.Now(),
			Details: map[string]any{
				"application":   app.Name,
				"publisher":     app.Publisher,
				"version":       app.Version,
				"would_be":      decision.Action,
				"rule":          decision.RuleName,
				"policy":        decision.PolicyName,
				"install_scope": app.Scope,
				"os_user":       app.OSUser,
			},
		})

		s.logger.Info("Newly installed software matches a policy rule",
			zap.String("machine", machine.Name),
			zap.String("application", app.Name),
			zap.String("would_be", decision.Action),
			zap.String("policy", decision.PolicyName))
	}
}
