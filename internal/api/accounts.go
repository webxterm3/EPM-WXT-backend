package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// Local-account inventory.
//
// These endpoints answer the question least-privilege enforcement has to be
// planned from and which nothing in this product could answer before: who
// holds local administrator rights, on which machines, and which of those the
// product could actually act on.
//
// Nothing here changes anything on any endpoint. Reading who is an
// administrator and changing who is an administrator are different risks, and
// they are kept in different files so that no future edit turns one into the
// other by accident.

// GetMachineAccounts lists the user accounts on one machine.
// GET /api/machines/:agent_id/accounts
func (h *Handler) GetMachineAccounts(c *gin.Context) {
	machine, ok := h.authorizeMachineRead(c)
	if !ok {
		return
	}

	accounts, err := h.store.GetAccountsByMachine(machine.ID, accountQueryFrom(c))
	if err != nil {
		h.logger.Warn("accounts: machine listing failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load accounts"})
		return
	}

	admins, demotable := countAccounts(accounts)

	c.JSON(http.StatusOK, gin.H{
		"accounts": accounts,
		"total":    len(accounts),

		// Returned alongside rather than left to the client to compute,
		// because the two numbers differ and the difference is the point: the
		// gap between them is root and any directory accounts, which hold
		// administrator rights that this product will not remove.
		"administrators": admins,
		"demotable":      demotable,

		// Lets the UI tell "this machine has no accounts" — which is never
		// true — apart from "this machine has never reported", which is
		// common and is the first thing support is asked about.
		"reported": len(accounts) > 0,
	})
}

// GetFleetAccounts lists accounts across the tenant's fleet.
// GET /api/accounts
//
// This is the view that makes the case for the whole feature: N people hold
// local administrator rights across M machines. It is paged, because on a
// real estate that list is long.
func (h *Handler) GetFleetAccounts(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	accounts, total, err := h.store.GetAccountsByTenant(tenantID, accountQueryFrom(c))
	if err != nil {
		h.logger.Warn("accounts: fleet listing failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load accounts"})
		return
	}

	admins, demotable := countAccounts(accounts)

	c.JSON(http.StatusOK, gin.H{
		"accounts": accounts,
		"total":    total,

		// These count the page, not the fleet, and are named so the caller
		// cannot mistake them for a fleet-wide total. A page's worth of
		// administrators presented as "your fleet has 12 administrators"
		// would understate every estate larger than one page.
		"page_administrators": admins,
		"page_demotable":      demotable,
	})
}

// RequestMachineAccountScan asks one machine to re-scan its accounts now.
// POST /api/machines/:agent_id/accounts/scan
//
// The response says only that the request was delivered. It cannot say the
// scan succeeded, because the agent reports through the ordinary inventory
// channel some seconds later — and claiming otherwise would have the UI show
// a stale list under the word "done".
func (h *Handler) RequestMachineAccountScan(c *gin.Context) {
	machine, ok := h.authorizeMachineRead(c)
	if !ok {
		return
	}

	if !h.agentManager.IsAgentConnected(machine.AgentID) {
		// 409, not 500: nothing is broken. The machine is off or offline, and
		// the caller needs to be told which of the two this is.
		c.JSON(http.StatusConflict, gin.H{
			"error": "This machine is offline. Its account list will refresh on its own when the agent reconnects.",
		})
		return
	}

	if err := h.agentManager.SendAccountScan(machine.AgentID); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "Could not reach the agent: " + err.Error()})
		return
	}

	h.record(c, auditEntry{
		Action: store.AuditAccountsScanRequested, Resource: "machine",
		ResourceID: machine.AgentID,
		Machine:    machine,
	})

	c.JSON(http.StatusAccepted, gin.H{
		"requested": true,
		"message":   "Scan requested. The list updates when the agent reports back.",
	})
}

// accountQueryFrom reads the shared filter parameters.
func accountQueryFrom(c *gin.Context) store.AccountQuery {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	skip, _ := strconv.Atoi(c.DefaultQuery("skip", "0"))

	return store.AccountQuery{
		AdminsOnly:     c.Query("admins_only") == "true",
		DemotableOnly:  c.Query("demotable_only") == "true",
		IncludeRemoved: c.Query("include_removed") == "true",
		Search:         c.Query("search"),
		Limit:          limit,
		Skip:           skip,
	}
}

// countAccounts counts administrators and demotable accounts in one pass.
func countAccounts(accounts []*store.LocalAccount) (admins, demotable int) {
	for _, a := range accounts {
		if a == nil {
			continue
		}
		if a.IsAdmin {
			admins++
		}
		if a.Demotable {
			demotable++
		}
	}
	return admins, demotable
}

// Creating a local account from the portal.
//
// # Where the password goes
//
// The administrator supplies it. It travels from the browser over TLS to
// here, and over mTLS to the agent, is used once, and is never stored: not in
// Mongo, not in the audit trail, not in a log on either side.
//
// The alternative — generating it on the endpoint and showing it once in the
// portal — means a plaintext credential at rest somewhere on the way back to
// the person who needs it, for every machine in the fleet. That is a worse
// problem than the one it solves. The break-glass account is generated that
// way because nobody chooses its password and it exists before anybody is
// watching; this one is created because somebody asked, and they are there.

// minAccountPassword is the shortest password this will pass on.
//
// A floor rather than a policy: the endpoint's own rules still apply and may
// refuse a longer one. The point is to catch the empty and the three-letter
// before they reach a machine.
const minAccountPassword = 10

// createAccountBody is what the portal sends.
type createAccountBody struct {
	Username string `json:"username"`
	FullName string `json:"full_name"`
	Password string `json:"password"`
	Admin    bool   `json:"admin"`
	Hidden   bool   `json:"hidden"`
}

// accountSpec is what travels to the agent. Mirrors privcontrol.AccountSpec.
type accountSpec struct {
	Username    string `json:"username"`
	FullName    string `json:"full_name,omitempty"`
	Password    string `json:"password"`
	Admin       bool   `json:"admin,omitempty"`
	Hidden      bool   `json:"hidden,omitempty"`
	RequestedBy string `json:"requested_by,omitempty"`
}

// CreateMachineAccount creates a local account on one machine.
// POST /api/machines/:agent_id/accounts
//
// Admin-only, and audited by name. Creating an account on somebody's endpoint
// is the most consequential thing this screen can do — an account created as
// an administrator is a standing way around everything least privilege
// enforces on that machine.
func (h *Handler) CreateMachineAccount(c *gin.Context) {
	if _, ok := h.requirePolicyAdmin(c); !ok {
		return
	}

	machine, ok := h.authorizeMachineRead(c)
	if !ok {
		return
	}

	var body createAccountBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	body.Username = strings.TrimSpace(body.Username)
	body.FullName = strings.TrimSpace(body.FullName)

	if !validAccountName(body.Username) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "A username may use letters, digits, dot, dash and underscore only, up to 32 characters",
		})
		return
	}
	if len(body.Password) < minAccountPassword {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("The password must be at least %d characters", minAccountPassword),
		})
		return
	}

	if !h.agentManager.IsAgentConnected(machine.AgentID) {
		// 409, not 500: nothing is broken. Deliberately NOT queued for the
		// machine's next connect either — a password waiting in a queue is a
		// password at rest, which is exactly what this design avoids.
		c.JSON(http.StatusConflict, gin.H{
			"error": "This machine is offline. Try again when it reconnects.",
		})
		return
	}

	spec := accountSpec{
		Username:    body.Username,
		FullName:    body.FullName,
		Password:    body.Password,
		Admin:       body.Admin,
		Hidden:      body.Hidden,
		RequestedBy: c.GetString("username"),
	}

	payload, err := json.Marshal(spec)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not prepare the request"})
		return
	}

	if err := h.agentManager.SendCreateAccount(machine.AgentID, string(payload)); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "Could not reach the agent: " + err.Error()})
		return
	}

	// The audit entry records WHAT was asked for and BY WHOM, and never the
	// password. An audit log is read by more people than should hold a
	// credential for an endpoint.
	h.record(c, auditEntry{
		Action: store.AuditAccountCreateRequested, Resource: "machine",
		ResourceID: machine.AgentID,
		Machine:    machine,
		Details: map[string]any{
			"username": spec.Username,
			"admin":    spec.Admin,
			"hidden":   spec.Hidden,
		},
	})

	// 202, not 201. The account does not exist yet: the agent creates it a
	// second or two from now and reports back through the ordinary
	// enforcement channel. Returning 201 would have the portal show an
	// account that may yet fail to be created.
	c.JSON(http.StatusAccepted, gin.H{
		"requested": true,
		"message":   "Creating the account. It appears in this list once the machine confirms it.",
	})
}

// Managing an existing account from the portal.
//
// Three things an administrator can do to an account on an endpoint: grant or
// remove administrator rights, grant them for a limited time, and switch the
// account on or off.
//
// There is deliberately no delete. A deleted account takes its home directory
// and its file ownership with it, and on Windows a replacement with the same
// name gets a different SID, orphaning everything that referenced the old one
// — including this product's own history of who held rights and when.
// Disabling answers the same need and is reversible.

// maxGrantHours bounds a time-limited grant of administrator rights.
//
// A week. Beyond that it is not a temporary grant, it is standing privilege
// with an end date nobody will remember, and the audit trail would describe
// it as just-in-time.
const maxGrantHours = 7 * 24

// accountActionBody is what the portal sends.
type accountActionBody struct {
	Action   string `json:"action"`
	Username string `json:"username"`
	Value    bool   `json:"value"`

	// DurationMinutes bounds a grant of administrator rights, counted from
	// the moment the endpoint receives it. Zero means it does not end.
	DurationMinutes int `json:"duration_minutes"`

	// Until is an absolute end time, for when an administrator picked a date
	// rather than a length.
	//
	// RFC3339 WITH an offset, so it names an instant rather than a wall
	// clock. The portal sends the admin's own local choice converted to UTC;
	// a naive "2026-11-12T17:00" would mean five o'clock in whichever
	// timezone the server happens to run in, which is nobody's five o'clock.
	Until *time.Time `json:"until,omitempty"`
}

// accountAction is what travels to the agent. Mirrors
// privcontrol.AccountAction.
type accountAction struct {
	Action      string     `json:"action"`
	Username    string     `json:"username"`
	Value       bool       `json:"value"`
	Until       *time.Time `json:"until,omitempty"`
	RequestedBy string     `json:"requested_by,omitempty"`
}

// Actions, mirroring the agent's vocabulary.
const (
	actionSetAdmin   = "set-admin"
	actionSetEnabled = "set-enabled"
)

// ManageMachineAccount changes one account on one machine.
// POST /api/machines/:agent_id/account-action
//
// A single route with the action in the body, rather than a route per action
// with the username in the path. The username in a path would sit where the
// existing /accounts/scan route already has a static segment, and a router
// that has to choose between them is a startup panic waiting for the first
// person called "scan".
func (h *Handler) ManageMachineAccount(c *gin.Context) {
	if _, ok := h.requirePolicyAdmin(c); !ok {
		return
	}

	machine, ok := h.authorizeMachineRead(c)
	if !ok {
		return
	}

	var body accountActionBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	body.Username = strings.TrimSpace(body.Username)
	if !validAccountName(body.Username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "That is not a usable account name"})
		return
	}

	if body.Action != actionSetAdmin && body.Action != actionSetEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown action"})
		return
	}

	action := accountAction{
		Action:      body.Action,
		Username:    body.Username,
		Value:       body.Value,
		RequestedBy: c.GetString("username"),
	}

	// An end time only means anything when granting rights. Silently ignored
	// otherwise rather than refused: a portal that sends a stale field should
	// not fail an administrator's click.
	if body.Action == actionSetAdmin && body.Value {
		until, err := grantEnd(body, time.Now())
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		action.Until = until
	}

	if !h.agentManager.IsAgentConnected(machine.AgentID) {
		// 409, not 500: nothing is broken. Not queued either — a grant
		// delivered when the machine next comes online would start its clock
		// at an unpredictable moment, which is not what anybody chose.
		c.JSON(http.StatusConflict, gin.H{
			"error": "This machine is offline. Try again when it reconnects.",
		})
		return
	}

	payload, err := json.Marshal(action)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not prepare the request"})
		return
	}

	if err := h.agentManager.SendAccountAction(machine.AgentID, string(payload)); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "Could not reach the agent: " + err.Error()})
		return
	}

	details := map[string]any{
		"username": action.Username,
		"action":   action.Action,
		"value":    action.Value,
	}
	if action.Until != nil {
		details["until"] = *action.Until
		details["duration_minutes"] = body.DurationMinutes
	}

	h.record(c, auditEntry{
		Action: store.AuditAccountManaged, Resource: "machine",
		ResourceID: machine.AgentID,
		Machine:    machine,
		Details:    details,
	})

	// 202, not 200. Nothing has changed yet: the agent does it a second or
	// two from now and reports back. Returning 200 would have the portal show
	// a change that may yet be refused by the endpoint.
	c.JSON(http.StatusAccepted, gin.H{
		"requested": true,
		"message":   accountActionMessage(action),
	})
}

// accountActionMessage says what was asked for, in words.
func accountActionMessage(a accountAction) string {
	switch {
	case a.Action == actionSetEnabled && a.Value:
		return "Enabling the account. The list updates once the machine confirms it."
	case a.Action == actionSetEnabled:
		return "Disabling the account. The list updates once the machine confirms it."
	case a.Value && a.Until != nil:
		// Stated in UTC and labelled as such. The portal re-renders it in the
		// reader's own timezone; this string may be read in a log or an API
		// response where there is nothing to say which zone was meant.
		return "Granting administrator rights until " +
			a.Until.UTC().Format("15:04 on 2 January 2006") + " UTC. " +
			"They are removed automatically."
	case a.Value:
		return "Granting administrator rights. The list updates once the machine confirms it."
	default:
		return "Removing administrator rights. The list updates once the machine confirms it."
	}
}

// minGrantMinutes is the shortest grant worth making.
//
// Below this the rights would end before the person had finished the thing
// they asked for them to do, and the request would read as the feature being
// broken rather than as the duration being wrong.
const minGrantMinutes = 5

// grantEnd works out when a grant of administrator rights ends.
//
// Returns nil for one that does not end, which is a real and deliberate
// choice rather than an omission: some accounts are supposed to be
// administrators. The caller distinguishes it from an error.
//
// An absolute Until wins over a duration when both arrive. They can only both
// be present through a client bug, and the absolute time is the one an
// administrator actually looked at and chose.
func grantEnd(body accountActionBody, now time.Time) (*time.Time, error) {
	if body.Until != nil {
		until := body.Until.UTC()

		// Checked against the server's clock, which is the same clock the
		// endpoint's will be compared to in UTC. A browser whose clock is
		// wrong would otherwise send a time that looks fine to the person
		// choosing it and is already past by the time it arrives.
		if !until.After(now) {
			return nil, fmt.Errorf("that end time has already passed")
		}
		if until.Sub(now) < minGrantMinutes*time.Minute {
			return nil, fmt.Errorf("a grant must last at least %d minutes", minGrantMinutes)
		}
		if until.Sub(now) > maxGrantHours*time.Hour {
			return nil, fmt.Errorf("a temporary grant may last at most %d days", maxGrantHours/24)
		}
		return &until, nil
	}

	if body.DurationMinutes <= 0 {
		// No end. Administrator rights that do not expire.
		return nil, nil
	}
	if body.DurationMinutes < minGrantMinutes {
		return nil, fmt.Errorf("a grant must last at least %d minutes", minGrantMinutes)
	}
	if body.DurationMinutes > maxGrantHours*60 {
		return nil, fmt.Errorf("a temporary grant may last at most %d days", maxGrantHours/24)
	}

	until := now.Add(time.Duration(body.DurationMinutes) * time.Minute).UTC()
	return &until, nil
}
