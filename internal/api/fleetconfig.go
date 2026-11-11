package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/secret"
	"github.com/vsay/vsay-agent-backend/internal/store"
)

// Fleet-wide configuration.
//
// Gated on super_admin, and not because it is more technical than the other
// settings: it decides what happens on machines that have not been enrolled
// yet, and it can upgrade every agent in the estate at once. Those are
// different in kind from managing one organisation's policies.

// requireSuperAdmin gates the fleet configuration.
//
// Its own gate rather than requirePolicyAdmin, which also admits
// company_admin. The difference is the point: a company administrator runs
// their own machines, while everything here reaches machines that do not
// exist yet and agents across the whole estate.
func (h *Handler) requireSuperAdmin(c *gin.Context) (string, bool) {
	if c.GetString("role") != "super_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "this requires super administrator access"})
		return "", false
	}
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return "", false
	}
	return tenantID, true
}

// GetFleetConfig returns the organisation's fleet configuration.
// GET /api/fleet-config
func (h *Handler) GetFleetConfig(c *gin.Context) {
	tenantID, ok := h.requireSuperAdmin(c)
	if !ok {
		return
	}

	cfg, err := h.store.GetFleetConfig(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load the configuration"})
		return
	}

	// The password is json:"-" and never travels back. has_password says one
	// is set; an API that returned the credential for an account on every
	// machine in the fleet is one browser extension away from being a leak.
	c.JSON(http.StatusOK, gin.H{
		"config": cfg,
		// Said so the screen can explain WHY saving a password is refused,
		// rather than showing a failure somebody cannot act on.
		"secrets_available": h.sealer != nil,
	})
}

// fleetConfigBody is what the portal sends.
type fleetConfigBody struct {
	DefaultUser struct {
		Enabled  bool   `json:"enabled"`
		Username string `json:"username"`
		FullName string `json:"full_name"`
		// Password is only sent when it is being CHANGED. An empty string
		// leaves the stored one alone, so editing the full name does not
		// require re-typing a credential nobody can read back.
		Password string `json:"password"`
		Admin    bool   `json:"admin"`
		Hidden   bool   `json:"hidden"`
	} `json:"default_user"`
}

// SaveFleetConfig writes the organisation's fleet configuration.
// PUT /api/fleet-config
func (h *Handler) SaveFleetConfig(c *gin.Context) {
	tenantID, ok := h.requireSuperAdmin(c)
	if !ok {
		return
	}

	var body fleetConfigBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	existing, err := h.store.GetFleetConfig(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load the configuration"})
		return
	}

	du := store.DefaultUserConfig{
		Enabled:  body.DefaultUser.Enabled,
		Username: strings.TrimSpace(body.DefaultUser.Username),
		FullName: strings.TrimSpace(body.DefaultUser.FullName),
		Admin:    body.DefaultUser.Admin,
		Hidden:   body.DefaultUser.Hidden,
		// Kept unless a new one is supplied below.
		Password: existing.DefaultUser.Password,
	}

	if body.DefaultUser.Password != "" {
		if h.sealer == nil {
			// Refused rather than stored in the clear. The alternative to an
			// encrypted password here is not a slightly-less-safe password,
			// it is a plaintext credential for an account on every machine
			// in the fleet, in a collection that backups copy.
			c.JSON(http.StatusPreconditionFailed, gin.H{
				"error": "This server has no " + secret.KeyEnv + " configured, so a password " +
					"cannot be stored. Set it and restart the server.",
			})
			return
		}
		if len(body.DefaultUser.Password) < minAccountPassword {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "The password must be at least 10 characters",
			})
			return
		}
		sealed, err := h.sealer.Seal(body.DefaultUser.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not store the password"})
			return
		}
		du.Password = sealed
	}

	// Checked only when the feature is ON. A half-filled form that is
	// switched off is somebody saving their place, not an error.
	if du.Enabled {
		if !validAccountName(du.Username) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "A username may use letters, digits, dot, dash and underscore only",
			})
			return
		}
		if du.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Set a password before turning this on — the machines need one to create the account",
			})
			return
		}
	}

	cfg := &store.FleetConfig{
		TenantID:    tenantID,
		DefaultUser: du,
		UpdatedBy:   c.GetString("username"),
	}
	if err := h.store.SaveFleetConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save the configuration"})
		return
	}

	// The password is never in the audit entry. An audit log is read by more
	// people than should hold a credential for every machine in the fleet.
	h.record(c, auditEntry{
		Action: store.AuditFleetConfigChanged, Resource: "tenant",
		ResourceID: tenantID,
		Details: map[string]any{
			"default_user_enabled": du.Enabled,
			"default_user":         du.Username,
			"admin":                du.Admin,
			"password_changed":     body.DefaultUser.Password != "",
		},
	})

	cfg.DefaultUser.HasPassword = du.Password != ""

	// Applied to the machines that already exist, right away.
	//
	// Without this the setting only ever reaches machines that connect AFTER
	// it was turned on — which on an estate that is already enrolled is
	// almost nobody, so switching it on appears to do nothing at all.
	//
	// Offline machines are not asked here and do not need to be: the connect
	// hook catches them the moment they come back.
	var sweep DefaultUserSweep
	if defaultUserReady(du) {
		if s, err := h.applyDefaultUserToFleet(tenantID); err == nil {
			sweep = s
		} else {
			// The configuration IS saved; only the immediate sweep failed.
			// Reported rather than turned into a save failure, because
			// re-saving would not fix it and the setting is now live.
			h.logger.Warn("Fleet configuration saved, but the default account could not be "+
				"applied to existing machines",
				zap.String("tenant_id", tenantID), zap.Error(err))
		}
	}

	c.JSON(http.StatusOK, gin.H{"config": cfg, "sweep": sweep})
}

// UpgradeFleet asks every connected agent in the tenant to update itself.
// POST /api/fleet-config/upgrade-agents
//
// Offline machines are counted, not failed. A fleet always has some machines
// asleep, and an error because one laptop in a bag did not answer would make
// the button useless on any real estate — while hiding the number would make
// the result look complete when it is not.
func (h *Handler) UpgradeFleet(c *gin.Context) {
	tenantID, ok := h.requireSuperAdmin(c)
	if !ok {
		return
	}

	machines, err := h.store.GetMachinesByTenantID(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list the machines"})
		return
	}

	var (
		requested int
		offline   int
		revoked   int
		failed    []string
		noPackage []string
	)

	for _, m := range machines {
		if m.Revoked {
			// A revoked machine is cut off deliberately. Handing it a new
			// binary would be the one instruction this product still sent to
			// a machine it had disowned.
			revoked++
			continue
		}
		if !h.agentManager.IsAgentConnected(m.AgentID) {
			offline++
			continue
		}

		osName, arch := detectOSArch(m.OS)
		downloadURL := selfUpdateURL(osName, arch)
		if downloadURL == "" {
			// Counted separately from a failure: nothing is broken, there is
			// simply no package published for that platform, and an operator
			// seeing "3 failed" would go looking for a fault that is not
			// there.
			noPackage = append(noPackage, m.Name)
			continue
		}

		if err := h.agentManager.SendUpdateCommand(m.AgentID, downloadURL); err != nil {
			h.logger.Warn("Fleet upgrade: could not reach an agent",
				zap.String("agent_id", m.AgentID), zap.Error(err))
			failed = append(failed, m.Name)
			continue
		}
		requested++
	}

	h.record(c, auditEntry{
		Action: store.AuditFleetUpgradeRequested, Resource: "tenant",
		ResourceID: tenantID,
		Details: map[string]any{
			"requested": requested, "offline": offline,
			"failed": len(failed), "no_package": len(noPackage),
			"total": len(machines),
		},
	})

	c.JSON(http.StatusAccepted, gin.H{
		"requested":  requested,
		"offline":    offline,
		"revoked":    revoked,
		"failed":     failed,
		"no_package": noPackage,
		"total":      len(machines),
		"message": "Each machine downloads and installs on its own. " +
			"Offline machines are not updated and are not retried automatically.",
	})
}

// ApplyDefaultUser creates the organisation's default account on a machine
// that has just connected.
//
// Called on connect rather than at registration, because registration happens
// before the agent has a command stream to receive anything on.
//
// Once per machine, recorded on the machine. Without that every reconnect
// would re-send the request and the endpoint would answer "an account named X
// already exists" into the audit trail each time.
func (h *Handler) ApplyDefaultUser(machine *store.Machine) {
	if shouldSkipDefaultUser(machine) {
		return
	}

	cfg, err := h.store.GetFleetConfig(machine.TenantID)
	if err != nil || cfg == nil || !defaultUserReady(cfg.DefaultUser) {
		return
	}

	if h.sealer == nil {
		h.logger.Warn("Default account: no key is configured, so the stored password cannot be read",
			zap.String("agent_id", machine.AgentID))
		return
	}
	password, err := h.sealer.Open(cfg.DefaultUser.Password)
	if err != nil || password == "" {
		// Surfaced rather than skipped quietly: the key changed, or the
		// record was tampered with, and every machine enrolling from now on
		// is silently missing its account.
		h.logger.Error("Default account: the stored password could not be read",
			zap.String("tenant_id", machine.TenantID), zap.Error(err))
		return
	}

	spec := accountSpec{
		Username:    cfg.DefaultUser.Username,
		FullName:    cfg.DefaultUser.FullName,
		Password:    password,
		Admin:       cfg.DefaultUser.Admin,
		Hidden:      cfg.DefaultUser.Hidden,
		RequestedBy: "fleet configuration",
	}
	payload, err := json.Marshal(spec)
	if err != nil {
		return
	}

	if err := h.agentManager.SendCreateAccount(machine.AgentID, string(payload)); err != nil {
		// NOT marked applied: the machine never got the message, so the next
		// connect should try again.
		h.logger.Warn("Default account: could not reach the machine",
			zap.String("agent_id", machine.AgentID), zap.Error(err))
		return
	}

	// Marked on DISPATCH, not on success. The endpoint reports what it did
	// through the ordinary channel, and a machine that refused because the
	// name was taken must not be asked again on every reconnect forever.
	if err := h.store.MarkDefaultUserApplied(machine.AgentID, time.Now()); err != nil {
		h.logger.Warn("Default account: could not record that it was requested",
			zap.String("agent_id", machine.AgentID), zap.Error(err))
	}

	h.logger.Info("Default account requested on a newly enrolled machine",
		zap.String("machine", machine.Name),
		zap.String("user", spec.Username),
		zap.Bool("admin", spec.Admin))
}

// shouldSkipDefaultUser reports a machine that must not be asked.
//
// Split out so each reason can be tested on its own. The once-per-machine
// case is the one that matters most: without it every reconnect re-sends the
// request, and the endpoint answers "an account named X already exists" into
// the audit trail each time.
func shouldSkipDefaultUser(machine *store.Machine) bool {
	return machine == nil ||
		machine.Revoked ||
		machine.DefaultUserAppliedAt != nil
}

// defaultUserReady reports a configuration complete enough to act on.
//
// Enabled is not sufficient: a configuration with no password would send
// machines a request they must refuse, and the operator would see nothing
// but failures in the trail.
func defaultUserReady(u store.DefaultUserConfig) bool {
	return u.Enabled && u.Username != "" && u.Password != ""
}

// DefaultUserSweep is what applying the default account to a fleet produced.
type DefaultUserSweep struct {
	// Requested is how many machines were asked.
	Requested int `json:"requested"`

	// AlreadyDone is how many had it already — either from an earlier sweep
	// or because they enrolled after the setting was turned on.
	AlreadyDone int `json:"already_done"`

	// Offline machines are not failures. They are asked the moment they next
	// connect, by the same hook that handles a brand-new enrolment, so there
	// is nothing to retry and nothing lost.
	Offline int `json:"offline"`

	Revoked int      `json:"revoked"`
	Failed  []string `json:"failed"`
	Total   int      `json:"total"`
}

// applyDefaultUserToFleet asks every machine that has not had the default
// account yet.
//
// Existing machines, not just new ones. The connect hook alone only ever
// reaches a machine that connects AFTER the setting was turned on — which on
// an estate that is already enrolled is almost nobody, and reads as the
// setting doing nothing.
//
// Safe to run repeatedly: the per-machine record is what stops a second run
// asking the same machine again.
func (h *Handler) applyDefaultUserToFleet(tenantID string) (DefaultUserSweep, error) {
	var sweep DefaultUserSweep

	cfg, err := h.store.GetFleetConfig(tenantID)
	if err != nil {
		return sweep, err
	}
	if !defaultUserReady(cfg.DefaultUser) {
		return sweep, nil
	}

	machines, err := h.store.GetMachinesByTenantID(tenantID)
	if err != nil {
		return sweep, err
	}
	sweep.Total = len(machines)

	for _, m := range machines {
		switch {
		case m.Revoked:
			sweep.Revoked++
			continue
		case m.DefaultUserAppliedAt != nil:
			sweep.AlreadyDone++
			continue
		case !h.agentManager.IsAgentConnected(m.AgentID):
			// Asked when it next connects, by the same hook that handles a
			// new enrolment. Nothing to retry here.
			sweep.Offline++
			continue
		}

		before := m.DefaultUserAppliedAt
		h.ApplyDefaultUser(m)

		// ApplyDefaultUser records the dispatch on the machine, so re-reading
		// is how this tells "sent" from "could not be sent" without the
		// function having to report it twice.
		updated, err := h.store.GetMachineByAgentID(m.AgentID)
		if err != nil || updated == nil || updated.DefaultUserAppliedAt == before {
			sweep.Failed = append(sweep.Failed, m.Name)
			continue
		}
		sweep.Requested++
	}

	h.logger.Info("Default account applied across the fleet",
		zap.String("tenant_id", tenantID),
		zap.Int("requested", sweep.Requested),
		zap.Int("already_done", sweep.AlreadyDone),
		zap.Int("offline", sweep.Offline),
		zap.Int("failed", len(sweep.Failed)))

	return sweep, nil
}

// ApplyDefaultUserToExisting asks every machine that has not had the default
// account yet.
// POST /api/fleet-config/apply-default-user
func (h *Handler) ApplyDefaultUserToExisting(c *gin.Context) {
	tenantID, ok := h.requireSuperAdmin(c)
	if !ok {
		return
	}

	cfg, err := h.store.GetFleetConfig(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load the configuration"})
		return
	}
	if !defaultUserReady(cfg.DefaultUser) {
		c.JSON(http.StatusPreconditionFailed, gin.H{
			"error": "Set a username and password and switch the default account on first",
		})
		return
	}

	sweep, err := h.applyDefaultUserToFleet(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reach the machines"})
		return
	}

	h.record(c, auditEntry{
		Action: store.AuditFleetConfigChanged, Resource: "tenant",
		ResourceID: tenantID,
		Details: map[string]any{
			"applied_default_user": true,
			"username":             cfg.DefaultUser.Username,
			"requested":            sweep.Requested,
			"offline":              sweep.Offline,
			"already_done":         sweep.AlreadyDone,
		},
	})

	c.JSON(http.StatusAccepted, gin.H{"sweep": sweep})
}
