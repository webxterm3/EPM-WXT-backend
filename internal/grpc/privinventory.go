package grpc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// PrivInventoryDiscriminator is the StatusUpdate tag agents report local
// accounts under. It is mirrored by a constant in the agent and pinned by a
// cross-repo drift test — a mismatch is not a compile error, the reports
// simply stop arriving and the fleet silently shows no accounts, which reads
// as a fleet with no administrators.
const PrivInventoryDiscriminator = "__priv_inventory__"

// PrivScanCommandID asks an agent to scan its accounts now. Mirrored by the
// agent and pinned by the same drift test.
const PrivScanCommandID = "__vsay_priv_scan__"

// maxReportedAccounts bounds one report.
//
// A machine has accounts in the tens; a shared terminal server with directory
// accounts cached locally is the high end and is still far below this. A
// report claiming more is either a bug or something hostile, and allocating
// for it is the easiest way to let one machine exhaust the backend.
const maxReportedAccounts = 5000

// privReport mirrors the agent's report envelope.
//
// Unlike the software inventory there are no chunk counters: an account
// snapshot arrives whole. That absence is the point — there is no partial
// state to reason about, so the reconcile can never run on half a picture.
type privReport struct {
	CollectedAt  time.Time     `json:"collected_at"`
	OS           string        `json:"os"`
	AdminGroup   string        `json:"admin_group"`
	AgentVersion string        `json:"agent_version"`
	Accounts     []privAccount `json:"accounts"`
}

// privAccount mirrors the agent's Account record.
type privAccount struct {
	ID         string     `json:"id"`
	Username   string     `json:"username"`
	FullName   string     `json:"full_name"`
	UID        int        `json:"uid"`
	SID        string     `json:"sid"`
	IsAdmin    bool       `json:"is_admin"`
	IsLocal    bool       `json:"is_local"`
	Source     string     `json:"source"`
	Shell      string     `json:"shell"`
	HomeDir    string     `json:"home_dir"`
	Disabled   bool       `json:"disabled"`
	Hidden     bool       `json:"hidden"`
	LastLogin  time.Time  `json:"last_login"`
	AdminUntil *time.Time `json:"admin_until"`
}

// validate rejects a report that cannot be trusted to reconcile.
func (r privReport) validate() error {
	if len(r.Accounts) == 0 {
		// Every machine has at least root or Administrator, so an empty
		// snapshot is never a true answer — it is a broken collector. The
		// store refuses it too; this is the earlier of the two refusals, so
		// the reason reaches the log next to the agent that sent it.
		return fmt.Errorf("report carries no accounts")
	}
	if len(r.Accounts) > maxReportedAccounts {
		return fmt.Errorf("report carries %d accounts", len(r.Accounts))
	}
	return nil
}

// hasAdministrator reports whether anybody in the snapshot holds rights.
//
// Checked separately from validate because it is not a malformed report — it
// is a well-formed report that cannot be true. A machine with accounts but no
// administrator at all means the membership check failed while the account
// listing succeeded, and storing it would show the machine as compliant.
func (r privReport) hasAdministrator() bool {
	for _, a := range r.Accounts {
		if a.IsAdmin {
			return true
		}
	}
	return false
}

// toLocalAccounts converts the reported records, dropping any that cannot be
// stored. A record with no identity cannot be reconciled against the next
// snapshot; one with no username cannot be displayed or named in a policy.
func (r privReport) toLocalAccounts() []store.LocalAccount {
	out := make([]store.LocalAccount, 0, len(r.Accounts))
	for _, a := range r.Accounts {
		if strings.TrimSpace(a.ID) == "" || strings.TrimSpace(a.Username) == "" {
			continue
		}
		acc := store.LocalAccount{
			AccountKey: a.ID,
			Username:   a.Username,
			FullName:   a.FullName,
			UID:        a.UID,
			SID:        a.SID,
			IsAdmin:    a.IsAdmin,
			IsLocal:    a.IsLocal,
			Demotable:  demotable(a),
			Source:     a.Source,
			Shell:      a.Shell,
			HomeDir:    a.HomeDir,
			Disabled:   a.Disabled,
			Hidden:     a.Hidden,
		}
		if !a.LastLogin.IsZero() {
			t := a.LastLogin
			acc.LastLogin = &t
		}
		if a.AdminUntil != nil && !a.AdminUntil.IsZero() {
			acc.AdminUntil = a.AdminUntil
		}
		out = append(out, acc)
	}
	return out
}

// demotable answers "could policy remove this account's administrator rights"
// from what the agent reported.
//
// It is computed here rather than trusted from the wire because the agent's
// answer is not carried in the payload — Account.Demotable is a method, not a
// field — and because the backend has to be able to answer the question for
// the simulation without asking a machine that may be offline.
//
// The rule is deliberately the conservative half of the agent's: local, an
// administrator, and not a platform built-in. When this and the endpoint
// disagree the endpoint wins, because the endpoint is where the invariants
// are enforced and it is the only party that can see the live account
// database at the moment of the change.
func demotable(a privAccount) bool {
	if !a.IsAdmin || !a.IsLocal {
		return false
	}
	if a.SID != "" {
		// Windows names its built-ins by well-known RID, not by a numeric
		// range: -500 is Administrator, -501 Guest.
		return !strings.HasSuffix(a.SID, "-500") && !strings.HasSuffix(a.SID, "-501")
	}
	// Unix-like: ordinary accounts start above 500, everything at or below
	// belongs to the operating system, and root is UID 0.
	return a.UID > 500
}

// handlePrivInventory stores a machine's local-account snapshot.
//
// There is no "final chunk" condition to check, because the snapshot is whole
// by construction, and no "collect error" condition either, because the agent
// does not send a scan that failed. What remains is one sanity check the
// agent cannot make on its own behalf — that somebody on the machine holds
// administrator rights — and the reconcile.
func (s *AgentServer) handlePrivInventory(agentID, raw string) {
	var report privReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		s.logger.Warn("account inventory: bad payload",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}
	if err := report.validate(); err != nil {
		s.logger.Warn("account inventory: rejected report",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}
	if !report.hasAdministrator() {
		// Refused, not stored. See hasAdministrator: this is a well-formed
		// report that cannot be true, and storing it would show the machine
		// as having no administrators to remove.
		s.logger.Warn("account inventory: no account holds administrator rights — refusing the snapshot",
			zap.String("agent_id", agentID),
			zap.Int("accounts", len(report.Accounts)))
		return
	}

	machine, err := s.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		return
	}

	now := time.Now()
	accounts := report.toLocalAccounts()

	added, updated, removed, err := s.store.ReconcileAccounts(machine, newPrivScanID(), accounts, now)
	if err != nil {
		s.logger.Warn("account inventory: could not store the snapshot",
			zap.String("machine", machine.Name), zap.Error(err))
		return
	}

	admins := 0
	demotables := 0
	for _, a := range accounts {
		if a.IsAdmin {
			admins++
		}
		if a.Demotable {
			demotables++
		}
	}

	_ = s.store.CreateAuditLog(&store.AuditLog{
		ActorName: "agent", ActorRole: "system",
		TenantID: machine.TenantID,
		Action:   store.AuditAccountsReported, Resource: "machine",
		ResourceID: agentID, MachineName: machine.Name, AgentID: agentID,
		Status: "success", Timestamp: now,
		Details: map[string]any{
			"accounts": len(accounts), "administrators": admins,
			"demotable": demotables,
			"added":     added, "updated": updated, "removed": removed,
		},
	})

	s.logger.Info("Account inventory reconciled",
		zap.String("machine", machine.Name),
		zap.Int("accounts", len(accounts)),
		zap.Int("administrators", admins),
		zap.Int("demotable", demotables),
		zap.Int64("added", added),
		zap.Int64("updated", updated),
		zap.Int64("removed", removed))
}

// newPrivScanID mints the marker the reconcile sweep keys on.
//
// Generated here rather than by the agent because, unlike the software
// inventory, it is not part of the wire format: nothing is chunked, so no
// second message has to agree about which snapshot it belongs to. Keeping it
// server-side means a machine cannot choose its own marker and so cannot
// replay one to make an older snapshot look current.
func newPrivScanID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A collision would mean a sweep skipping rows it should have marked.
		// The clock is a poor substitute but a strictly increasing one, and
		// this path only runs if the OS entropy source fails.
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
