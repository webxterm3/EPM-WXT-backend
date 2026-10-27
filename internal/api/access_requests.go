package api

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-agent-backend/internal/approvers"
	emailsvc "github.com/vsay/vsay-agent-backend/internal/email"
	"github.com/vsay/vsay-agent-backend/internal/policy"
	"github.com/vsay/vsay-agent-backend/internal/store"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// validAccessRequestStatuses are the five lifecycle states the admin-facing
// Access Requests page filters by (one tab per status).
var validAccessRequestStatuses = map[string]bool{
	"pending":  true,
	"approved": true, // "Active" tab — approved and not yet expired/revoked
	"expired":  true, // ran its full granted duration
	"rejected": true,
	"revoked":  true, // manually revoked by an admin while still active

	// "completed" — the thing that was approved has been DONE.
	//
	// Only an install request ever reaches it, and only when the endpoint
	// says the software went on. An install is not a session: it either
	// happened or it did not, and leaving it sitting in "Active" for the
	// rest of its 24-hour window told an approver nothing about which.
	// "expired" was the nearest existing state and means something else —
	// that the clock ran out, which is exactly the case this distinguishes.
	"completed": true,
}

// emailService is a package-level stateless email service instance.
var emailService = emailsvc.New()

// POST /api/access-requests
func (h *Handler) CreateAccessRequest(c *gin.Context) {
	var req struct {
		MachineID string `json:"machine_id" binding:"required"`
		// Minutes, so a fifteen-minute window can be asked for. Ignored when
		// an explicit from/to window is given, which states its own length.
		DurationMinutes int `json:"duration_minutes"`
		// Accepted from clients that have not been updated.
		DurationHours int    `json:"duration_hours"`
		Title         string `json:"title"`
		RequestNote   string `json:"request_note"`

		// The window the session may run in. RFC3339, both optional.
		NotBefore string `json:"not_before"`
		NotAfter  string `json:"not_after"`

		Asks struct {
			RemoteSupport *struct {
				Reason  string `json:"reason"`
				Control string `json:"control"`
			} `json:"remote_support"`
			AdminAccess *struct {
				Reason string `json:"reason"`
			} `json:"admin_access"`
			AppInstall *struct {
				Reason       string   `json:"reason"`
				Applications []string `json:"applications"`
			} `json:"app_install"`
		} `json:"asks"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// The window first, because it can decide the duration.
	notBefore, notAfter, err := parseWindow(req.NotBefore, req.NotAfter)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	minutes := req.DurationMinutes
	if minutes == 0 && req.DurationHours > 0 {
		minutes = req.DurationHours * 60
	}
	// A from/to window states its own length, and two sources of truth for
	// how long a grant lasts is one of them being wrong. The window wins.
	if notBefore != nil && notAfter != nil {
		minutes = int(notAfter.Sub(*notBefore).Minutes())
	}

	// A duration is required.
	//
	// It used to be optional, and zero meant NEVER EXPIRES — so a client that
	// forgot the field, or asked for a window shorter than the hour it was
	// rounded into, was granted permanent access. For a feature whose whole
	// purpose is that access ends on its own, that default was backwards.
	if minutes <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "how long the access is needed for is required, and must be at least a minute",
		})
		return
	}
	if minutes > maxAccessMinutes {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "access cannot be requested for longer than 30 days",
		})
		return
	}

	// Build the asks, refusing anything that would be approved without
	// meaning something.
	var asks store.AccessAsks
	if a := req.Asks.RemoteSupport; a != nil {
		control := a.Control
		if control == "" {
			// The narrower of the two. Somebody who does not say must not be
			// handed the larger grant by default.
			control = store.AccessLevelView
		}
		if !validAccessLevel(control) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown control level for remote support"})
			return
		}
		asks.RemoteSupport = &store.RemoteSupportAsk{
			Reason: strings.TrimSpace(a.Reason), Control: control,
		}
	}
	if a := req.Asks.AdminAccess; a != nil {
		asks.AdminAccess = &store.AdminAccessAsk{Reason: strings.TrimSpace(a.Reason)}
	}
	if a := req.Asks.AppInstall; a != nil {
		apps := make([]string, 0, len(a.Applications))
		for _, name := range a.Applications {
			if n := strings.TrimSpace(name); n != "" {
				apps = append(apps, n)
			}
		}
		// "May install software" and "may install Docker Desktop" are
		// different grants, and only the second is one an approver can weigh.
		if len(apps) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "name at least one application to install, or turn that off",
			})
			return
		}
		asks.AppInstall = &store.AppInstallAsk{
			Reason: strings.TrimSpace(a.Reason), Applications: apps,
		}
	}

	if !asks.Any() {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "choose at least one thing you need — a request that asks for nothing cannot be approved",
		})
		return
	}

	machineID, err := primitive.ObjectIDFromHex(req.MachineID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid machine_id"})
		return
	}

	machine, err := h.store.GetMachineByID(machineID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}

	requesterID := c.GetString("user_id")
	requesterUsername := c.GetString("username")
	requesterEmail := c.GetString("email")
	tenantID := c.GetString("tenant_id")

	// Check same tenant
	if machine.TenantID != tenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "machine belongs to a different tenant"})
		return
	}

	// Check not already owner
	userID, _ := primitive.ObjectIDFromHex(requesterID)
	if machine.OwnerID == userID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "you are the owner of this machine"})
		return
	}

	// Check not already pending for this machine+requester
	existingRequests, err := h.store.GetAccessRequestsByMachine(machineID)
	if err == nil {
		for _, ar := range existingRequests {
			if ar.RequesterID == requesterID && ar.Status == "pending" {
				c.JSON(http.StatusConflict, gin.H{"error": "you already have a pending access request for this machine"})
				return
			}
		}
	}

	accessReq := &store.AccessRequest{
		MachineID:         machineID,
		MachineName:       machine.Name,
		MachineAgentID:    machine.AgentID,
		RequesterID:       requesterID,
		RequesterUsername: requesterUsername,
		RequesterEmail:    requesterEmail,
		TenantID:          tenantID,
		OwnerID:           machine.OwnerID.Hex(),
		OwnerEmail:        "", // not available at creation time
		Title:             strings.TrimSpace(req.Title),
		RequestNote:       req.RequestNote,
		DurationMinutes:   minutes,
		Asks:              asks,
		NotBefore:         notBefore,
		NotAfter:          notAfter,
		Status:            "pending",
	}

	if err := h.store.CreateAccessRequest(accessReq); err != nil {
		h.logger.Error("Failed to create access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create access request"})
		return
	}

	// Notify the people who can act on this request.
	//
	// This block used to be guarded by `accessReq.OwnerEmail != ""`, and
	// OwnerEmail is assigned the empty string a few lines above with the
	// comment "not available at creation time" — so the guard was never true
	// and SendAccessRequestNotification was dead code. Nobody has ever been
	// emailed about a request, which makes the whole approval flow depend on
	// somebody happening to notice a pending count in a portal page.
	//
	// The backend holds no user records, so there is genuinely no way to look
	// up the owner's address here. What it does have is the machine's
	// NotifyEmails: the people who have opened this machine in the portal and
	// were authorised to. That is a superset of the approvers rather than
	// exactly them, which is the right direction to err for a request that is
	// waiting on a human.
	// The group's administrators first.
	//
	// These are the people named as approvers for the machines in this
	// machine's groups, and they are the right answer: somebody who knows
	// whether this person should reach THIS machine. Falling back to everyone
	// who has opened it in the portal is what happens when no group names an
	// approver, which is also what happened before group administrators
	// existed.
	var recipients []string
	if len(machine.GroupIDs) > 0 {
		list, err := h.approvers.ForGroups(c.Request.Context(), machine.GroupIDs)
		if err != nil {
			h.logger.Warn("access request: could not resolve the group's approvers",
				zap.String("machine", machine.Name), zap.Error(err))
		}
		recipients = approvers.Emails(list)
	}
	if len(recipients) == 0 {
		recipients = machine.NotifyEmails
	}

	// The requester is dropped last, so they are removed whichever list they
	// came from. They know; they just asked.
	filtered := make([]string, 0, len(recipients))
	seen := map[string]bool{}
	for _, addr := range recipients {
		key := strings.ToLower(strings.TrimSpace(addr))
		if key == "" || seen[key] || strings.EqualFold(addr, requesterEmail) {
			continue
		}
		seen[key] = true
		filtered = append(filtered, addr)
	}
	recipients = filtered
	if len(recipients) > 0 {
		go func() {
			for _, addr := range recipients {
				if err := emailService.SendAccessRequestNotification(
					addr, "", requesterUsername, machine.Name,
					minutes, req.RequestNote,
				); err != nil {
					h.logger.Warn("access request: notification email failed",
						zap.String("to", addr), zap.Error(err))
				}
			}
		}()
	}

	h.record(c, auditEntry{
		Action: store.AuditJITRequested, Resource: "access_request",
		ResourceID: accessReq.ID.Hex(),
		Details: map[string]any{
			"machine":          accessReq.MachineName,
			"duration_minutes": accessReq.DurationMinutes,
			"asks":             store.DescribeAsks(accessReq.Asks),
			"note":             accessReq.RequestNote,
		},
	})
	c.JSON(http.StatusCreated, accessReq)
}

// GET /api/access-requests/my
func (h *Handler) GetMyAccessRequests(c *gin.Context) {
	requesterID := c.GetString("user_id")
	tenantID := c.GetString("tenant_id")

	requests, err := h.store.GetAccessRequestsByRequester(
		requesterID, c.GetString("email"), tenantID)
	if err != nil {
		h.logger.Error("Failed to get access requests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access requests"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"requests": requests, "total": len(requests)})
}

// GET /api/machines/:agent_id/access-requests
func (h *Handler) GetMachineAccessRequests(c *gin.Context) {
	agentID := c.Param("agent_id")
	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	role := c.GetString("role")

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}

	// Only owner or admin can view access requests
	if machine.OwnerID != userID && role != "company_admin" && role != "super_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "not authorized"})
		return
	}

	requests, err := h.store.GetAccessRequestsByMachine(machine.ID)
	if err != nil {
		h.logger.Error("Failed to get machine access requests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access requests"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"requests": requests, "total": len(requests)})
}

// GET /api/machines/:agent_id/pending-requests-count
func (h *Handler) GetPendingRequestsCount(c *gin.Context) {
	agentID := c.Param("agent_id")
	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	role := c.GetString("role")

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}

	// Only owner or admin can view count
	if machine.OwnerID != userID && role != "company_admin" && role != "super_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "not authorized"})
		return
	}

	requests, err := h.store.GetAccessRequestsByMachine(machine.ID)
	if err != nil {
		h.logger.Error("Failed to get machine access requests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access requests"})
		return
	}

	count := 0
	for _, r := range requests {
		if r.Status == "pending" {
			count++
		}
	}

	c.JSON(http.StatusOK, gin.H{"count": count})
}

// POST /api/access-requests/:id/approve
func (h *Handler) ApproveAccessRequest(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request id"})
		return
	}

	approverUsername := c.GetString("username")

	ar, err := h.store.GetAccessRequestByID(id)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "access request not found"})
			return
		}
		h.logger.Error("Failed to get access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access request"})
		return
	}

	if ar.Status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "access request is not pending"})
		return
	}

	// Verify caller is owner of the machine or admin
	machine, err := h.store.GetMachineByID(ar.MachineID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}

	if !h.mayDecide(c, ar, machine) {
		return
	}

	// Refuse to approve what the endpoint will not honour.
	//
	// A rule that blocks an application beats any approval on the machine —
	// a standing rule is a decision about every endpoint, an approval is one
	// person's answer to one ask. So recording an approval here would record
	// one that cannot take effect: the approver clicks yes, nothing happens
	// on the Mac, and the product looks broken rather than the policy
	// looking deliberate.
	//
	// Said plainly, with the way out, because the way out is a policy change
	// and that is not something an approver can guess.
	if blocked, rule := h.blockedByPolicy(ar); blocked {
		c.JSON(http.StatusConflict, gin.H{
			"error": "Your organisation blocks this application, under the rule \"" +
				rule + "\". It cannot be approved from here, because the endpoint " +
				"will refuse it however this request is answered. To allow it, an " +
				"administrator has to change or remove that rule in the policy.",
			"blocked_by_rule": rule,
		})
		return
	}

	now := time.Now()

	// "approved" is a session that is running; an install is not one.
	//
	// A request to install software is finished for the approver the moment
	// they decide — there is no window to watch, nothing to revoke mid-way,
	// and nobody to cut off. Leaving it in Active meant an administrator's
	// queue filled with rows that would sit there for a day and then turn
	// into "expired", which reads as nobody having dealt with them.
	//
	// The permission still reaches the machine: the live-approvals query
	// reads approved AND completed, and what ends it is UsedAt or the
	// expiry, not the status.
	//
	// Only when installing is ALL it asks for. A request that also asks for
	// remote support has a session to run, and that one is genuinely active.
	ar.Status = "approved"
	if installOnly(ar.Asks) {
		ar.Status = "completed"
	}
	ar.ApprovedBy = approverUsername
	ar.ApprovedAt = &now

	// The clock starts when the window opens, not when the approver clicks.
	//
	// Somebody can ask on Monday for a window on Saturday. Starting the
	// countdown at approval would spend the grant before the person could use
	// it, and the shorter the window the worse that is — a fifteen-minute
	// grant approved an hour early is simply gone.
	start := now
	if ar.NotBefore != nil && ar.NotBefore.After(now) {
		start = *ar.NotBefore
	}

	var expiresAt *time.Time
	switch {
	case ar.NotAfter != nil:
		// An explicit window says when it ends. Honoured over the duration,
		// which is derived from it anyway — and if the two ever disagreed,
		// the one the requester SAW is the one to keep.
		expiresAt = ar.NotAfter
		ar.ExpiresAt = expiresAt
	default:
		if mins := ar.Minutes(); mins > 0 {
			t := start.Add(time.Duration(mins) * time.Minute)
			expiresAt = &t
			ar.ExpiresAt = expiresAt
		}
	}
	// A request with no duration at all is one stored before durations were
	// required, in an encoding where zero meant never expires. Left alone:
	// changing what an existing grant means, in either direction, is a
	// decision for whoever made it.

	if err := h.store.UpdateAccessRequest(ar); err != nil {
		h.logger.Error("Failed to update access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to approve request"})
		return
	}

	// Grant machine access — but only where that is what was asked for.
	//
	// This used to run for EVERY approval, and machine.AllowedUsers is the
	// remote-access list: api/terminal.go checks it to decide who may open a
	// session on a machine. So approving "let me install Visual Studio Code"
	// also handed that person remote access to the Mac, which nobody asked
	// for and no approver saw.
	//
	// Worse on an endpoint-raised request, where RequesterUsername is the
	// macOS console account rather than a portal user: a Unix account name
	// was being written into a portal authorisation list, where it would
	// match any portal user who happened to share the name.
	if ar.Asks.GrantsMachineAccess() {
		if err := h.store.GrantMachineAccess(ar.MachineID, ar.RequesterUsername); err != nil {
			h.logger.Error("Failed to grant machine access", zap.Error(err))
			// Non-fatal — request is marked approved, access grant can be retried
		}
	}

	// Tell the machine, now.
	//
	// An approval for software is a change to what that endpoint is allowed
	// to install, and until the endpoint has been told, nothing about it has
	// changed there. Approving used to push nothing at all: the portal said
	// approved, and the Mac went on refusing the software until somebody
	// happened to edit a policy — which is what triggered the only sweep
	// that carried exceptions.
	h.pushInstallApprovals(ar)

	// Send approval email (best-effort, async)
	if ar.RequesterEmail != "" {
		go func() {
			if err := emailService.SendAccessRequestDecision(
				ar.RequesterEmail, ar.RequesterUsername,
				ar.MachineName, "approved", "", expiresAt,
			); err != nil {
				h.logger.Warn("Failed to send approval email", zap.Error(err))
			}
		}()
	}

	h.record(c, auditEntry{
		Action: store.AuditJITApproved, Resource: "access_request",
		ResourceID: ar.ID.Hex(),
		Details: map[string]any{
			"requester":        ar.RequesterUsername,
			"machine":          ar.MachineName,
			"duration_minutes": ar.Minutes(),
			"asks":             store.DescribeAsks(ar.Asks),
			"expires_at":       ar.ExpiresAt,
		},
	})
	c.JSON(http.StatusOK, gin.H{"message": "access request approved", "request": ar})
}

// markBlockedByPolicy annotates a page of requests with the rule forbidding
// each, where one does.
//
// The policies are read ONCE for the page rather than once per row: a page
// is twenty-five requests and the answer is the same for all of them.
func (h *Handler) markBlockedByPolicy(tenantID string, reqs []*store.AccessRequest) {
	if tenantID == "" || len(reqs) == 0 {
		return
	}
	policies, err := h.store.GetAppPoliciesByTenant(tenantID)
	if err != nil {
		h.logger.Warn("could not read policies to mark blocked requests",
			zap.String("tenant_id", tenantID), zap.Error(err))
		return
	}

	for _, ar := range reqs {
		if ar == nil || ar.Asks.AppInstall == nil {
			continue
		}
		for _, app := range ar.Asks.AppInstall.Applications {
			exception := policy.ApprovedInstall{
				Application: app,
				Publisher:   ar.Asks.AppInstall.Publisher,
				BundleID:    ar.Asks.AppInstall.BundleID,
				InstallPath: ar.Asks.AppInstall.InstallPath,
			}
			if policy.BlockedByRule(policies, exception) {
				ar.BlockedByRule = ruleForbidding(policies, exception)
				break
			}
		}
	}
}

// installOnly reports whether installing software is the whole of what this
// request asks for.
func installOnly(a store.AccessAsks) bool {
	return a.AppInstall != nil && a.RemoteSupport == nil && a.AdminAccess == nil
}

// blockedByPolicy reports whether a rule forbids the software this request
// asks for, and names the rule.
//
// Only an install ask can be blocked this way; remote support and admin
// access are not application policy.
func (h *Handler) blockedByPolicy(ar *store.AccessRequest) (bool, string) {
	if ar.Asks.AppInstall == nil || len(ar.Asks.AppInstall.Applications) == 0 {
		return false, ""
	}

	policies, err := h.store.GetAppPoliciesByTenant(ar.TenantID)
	if err != nil {
		// Unknown rather than blocked. Refusing an approval because the
		// policy store could not be read would stop somebody doing their
		// job over a database blip, and the endpoint still refuses the
		// software either way.
		h.logger.Warn("could not read policies to check an approval",
			zap.String("tenant_id", ar.TenantID), zap.Error(err))
		return false, ""
	}

	for _, app := range ar.Asks.AppInstall.Applications {
		exception := policy.ApprovedInstall{
			Application: app,
			Publisher:   ar.Asks.AppInstall.Publisher,
			BundleID:    ar.Asks.AppInstall.BundleID,
			InstallPath: ar.Asks.AppInstall.InstallPath,
		}
		if policy.BlockedByRule(policies, exception) {
			return true, ruleForbidding(policies, exception)
		}
	}
	return false, ""
}

// ruleForbidding names the rule, so the message can say which one to change.
func ruleForbidding(policies []*store.AppPolicy, app policy.ApprovedInstall) string {
	for _, p := range policies {
		if p == nil || !p.Enabled {
			continue
		}
		for _, r := range p.Rules {
			if !r.Enabled || r.Action != store.ActionBlock {
				continue
			}
			if policy.BlockedByRule([]*store.AppPolicy{{
				Enabled: true, Rules: []store.PolicyRule{r},
			}}, app) {
				return r.Name
			}
		}
	}
	return "a block rule"
}

// pushInstallApprovals re-sends one machine's policy after a decision about
// software it may install.
//
// Only for requests that actually carry an install ask — approving remote
// support changes nothing the agent's application policy depends on, and a
// push per decision would be a round trip bought for nothing.
//
// Best effort, and deliberately not fatal to the decision: the decision is
// recorded, and an endpoint that was offline or unreachable picks the same
// exception up on its next connect, which goes through the same resolver.
func (h *Handler) pushInstallApprovals(ar *store.AccessRequest) {
	if ar.Asks.AppInstall == nil || h.policyPusher == nil {
		return
	}

	machine, err := h.store.GetMachineByID(ar.MachineID)
	if err != nil || machine == nil {
		h.logger.Warn("could not reach the machine to deliver an install decision",
			zap.String("request_id", ar.ID.Hex()), zap.Error(err))
		return
	}
	if err := h.policyPusher.PushTo(machine); err != nil {
		h.logger.Warn("could not deliver an install decision to the machine",
			zap.String("machine", machine.Name), zap.Error(err))
	}
}

// POST /api/access-requests/:id/reject
func (h *Handler) RejectAccessRequest(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request id"})
		return
	}

	var body struct {
		Comment string `json:"comment"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if body.Comment == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "comment is required when rejecting an access request"})
		return
	}

	rejectorUsername := c.GetString("username")

	ar, err := h.store.GetAccessRequestByID(id)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "access request not found"})
			return
		}
		h.logger.Error("Failed to get access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access request"})
		return
	}

	if ar.Status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "access request is not pending"})
		return
	}

	// Verify caller is owner of the machine or admin
	machine, err := h.store.GetMachineByID(ar.MachineID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}

	if !h.mayDecide(c, ar, machine) {
		return
	}

	ar.Status = "rejected"
	ar.RejectedBy = rejectorUsername
	ar.RejectComment = body.Comment

	if err := h.store.UpdateAccessRequest(ar); err != nil {
		h.logger.Error("Failed to update access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reject request"})
		return
	}

	// Send rejection email (best-effort, async)
	if ar.RequesterEmail != "" {
		go func() {
			if err := emailService.SendAccessRequestDecision(
				ar.RequesterEmail, ar.RequesterUsername,
				ar.MachineName, "rejected", body.Comment, nil,
			); err != nil {
				h.logger.Warn("Failed to send rejection email", zap.Error(err))
			}
		}()
	}

	h.record(c, auditEntry{
		Action: store.AuditJITRejected, Resource: "access_request",
		ResourceID: ar.ID.Hex(), Status: "denied",
		Details: map[string]any{
			"requester": ar.RequesterUsername,
			"machine":   ar.MachineName,
			"comment":   ar.RejectComment,
		},
	})
	c.JSON(http.StatusOK, gin.H{"message": "access request rejected", "request": ar})
}

// GET /api/access-requests — admin/super_admin only (route-gated).
// Powers the sidebar "Access Requests" page: one status tab at a time, with
// server-side search + pagination. company_admin is scoped to their own
// tenant; super_admin sees all tenants, or one via ?tenant_id=.
func (h *Handler) ListAccessRequests(c *gin.Context) {
	role := c.GetString("role")
	tenantID := c.GetString("tenant_id")

	status := c.Query("status")
	if !validAccessRequestStatuses[status] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be one of pending, approved, expired, rejected, revoked"})
		return
	}

	search := strings.TrimSpace(c.Query("search"))

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	if limit < 1 || limit > 200 {
		limit = 25
	}

	filterTenantID := tenantID
	if role == "super_admin" {
		filterTenantID = c.Query("tenant_id")
	}

	skip := (page - 1) * limit
	reqs, total, err := h.store.GetAccessRequestsFiltered(filterTenantID, status, search, limit, skip)
	if err != nil {
		h.logger.Error("Failed to list access requests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list access requests"})
		return
	}

	// Marked before the list goes out, so an approver sees which of these
	// cannot be approved without having to click one to find out.
	h.markBlockedByPolicy(filterTenantID, reqs)

	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	if totalPages < 1 {
		totalPages = 1
	}

	c.JSON(http.StatusOK, gin.H{
		"requests":    reqs,
		"total":       total,
		"page":        page,
		"limit":       limit,
		"total_pages": totalPages,
	})
}

// POST /api/access-requests/:id/revoke — admin/super_admin only (route-gated).
// Cuts short an active (approved) grant mid-session — distinct from natural
// expiry, which the background ticker marks "expired" instead.
func (h *Handler) RevokeAccessRequest(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request id"})
		return
	}

	revokerUsername := c.GetString("username")

	ar, err := h.store.GetAccessRequestByID(id)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "access request not found"})
			return
		}
		h.logger.Error("Failed to get access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access request"})
		return
	}

	if ar.Status != "approved" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only an active access request can be revoked"})
		return
	}

	// Revoking had NO authorization check whatsoever: any authenticated
	// caller holding a request id could cut short any active grant, in any
	// organisation. Cutting access short is the safe direction of the three,
	// which is presumably why it was never noticed — but it is still somebody
	// else's session ended by a stranger, and the id is in every notification
	// email already sent.
	machine, err := h.store.GetMachineByID(ar.MachineID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}
	if !h.mayDecide(c, ar, machine) {
		return
	}

	now := time.Now()
	ar.Status = "revoked"
	ar.RevokedBy = revokerUsername
	ar.RevokedAt = &now

	// Guarded the same way the grant is. Revoking for an install-only
	// request would take away access somebody holds from a different
	// request that is still live.
	if ar.Asks.GrantsMachineAccess() {
		if err := h.store.RevokeMachineAccess(ar.MachineID, ar.RequesterUsername); err != nil {
			h.logger.Error("Failed to revoke machine access", zap.Error(err))
			// Non-fatal — the request is still marked revoked below
		}
	}

	if err := h.store.UpdateAccessRequest(ar); err != nil {
		h.logger.Error("Failed to update access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke request"})
		return
	}

	if ar.RequesterEmail != "" {
		go func() {
			if err := emailService.SendAccessRequestDecision(
				ar.RequesterEmail, ar.RequesterUsername,
				ar.MachineName, "revoked", "", nil,
			); err != nil {
				h.logger.Warn("Failed to send revoke email", zap.Error(err))
			}
		}()
	}

	h.record(c, auditEntry{
		Action: store.AuditJITExpired, Resource: "access_request",
		ResourceID: ar.ID.Hex(), Status: "denied",
		Details: map[string]any{
			"requester": ar.RequesterUsername,
			"machine":   ar.MachineName,
			"revoked":   true,
		},
	})
	// Withdrawing it from the machine matters more than granting it did: an
	// exception that outlives its revocation is a permission nobody believes
	// is still in force.
	h.pushInstallApprovals(ar)

	c.JSON(http.StatusOK, gin.H{"message": "access request revoked", "request": ar})
}

// mayDecide reports whether this caller may approve, reject or revoke this
// request, and writes the refusal itself.
//
// One function for all three, because they are the same question and three
// copies of it is two chances to let one drift. It replaces a check that was
// repeated verbatim and was missing two things:
//
//	The TENANT. The check was "owns the machine, or is an admin" — and
//	"is an admin" was read off a header with no reference to WHICH
//	organisation. A company_admin holding another tenant's request id could
//	approve it. Creation checked the tenant; deciding did not.
//
//	SELF-APPROVAL. Nothing stopped the requester approving their own
//	request, and a company_admin asking for access to a machine could
//	grant it to themselves — which is every approval workflow's first
//	requirement and the reason one exists at all.
//
// Group administrators are the new path: somebody who administers a group the
// machine belongs to decides for it. That is the point of naming them — the
// person who knows whether somebody should reach a finance laptop is not the
// person who knows about an engineering one.
func (h *Handler) mayDecide(c *gin.Context, ar *store.AccessRequest, machine *store.Machine) bool {
	userID := c.GetString("user_id")
	role := c.GetString("role")
	tenantID := c.GetString("tenant_id")

	// A super_admin is deliberately exempt from the tenant check and from
	// nothing else: they operate across organisations by definition, but they
	// still may not approve their own request.
	if role != middlewareRoleSuperAdmin && machine.TenantID != tenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "not authorized"})
		return false
	}

	// Nobody decides their own request, whatever else they are.
	//
	// The id is the reliable comparison — a username can be changed, and a
	// gate that turns on a display name is one rename away from opening.
	//
	// The username is compared AS WELL, for requests raised from an endpoint.
	// Those carry no RequesterID: the machine knows which OS account is
	// logged in, the portal knows people with accounts, and those namespaces
	// do not reliably map, so guessing an id would attribute somebody else's
	// request. With only the id check, an administrator whose portal account
	// happens to share a name with their Mac account could approve their own.
	self := ar.RequesterID != "" && ar.RequesterID == userID
	if !self && ar.RequesterUsername != "" {
		self = strings.EqualFold(ar.RequesterUsername, c.GetString("username"))
	}
	if self {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "You cannot decide your own access request. Someone else has to.",
		})
		return false
	}

	if machine.OwnerID.Hex() == userID {
		return true
	}
	if role == "company_admin" || role == middlewareRoleSuperAdmin {
		return true
	}

	// Finally, the group administrators. Asked last because it is the only
	// branch that makes a network call, and the common cases are decided
	// above without one.
	if len(machine.GroupIDs) > 0 {
		list, err := h.approvers.ForGroups(c.Request.Context(), machine.GroupIDs)
		if err != nil {
			// Reported, not swallowed. A lookup that fails silently would
			// deny a legitimate approver with the same message as a genuine
			// refusal, and nothing would say which happened.
			h.logger.Warn("access request: could not resolve the group's approvers",
				zap.String("machine", machine.Name), zap.Error(err))
		}
		if approvers.Includes(list, userID) {
			return true
		}
	}

	c.JSON(http.StatusForbidden, gin.H{"error": "not authorized"})
	return false
}

// middlewareRoleSuperAdmin is the role string vsay-auth puts in the header.
const middlewareRoleSuperAdmin = "super_admin"

// maxAccessMinutes caps a request at thirty days.
//
// Not a security boundary — an approver still decides — but a request for a
// year is almost always a typo, and granting one is harder to notice than
// refusing it.
const maxAccessMinutes = 30 * 24 * 60

func validAccessLevel(v string) bool {
	switch v {
	case store.AccessLevelView, store.AccessLevelControl:
		return true
	}
	return false
}

// parseWindow reads the optional from/to the session may run in.
//
// A window that has already closed is refused rather than stored: it would
// sit in the queue looking schedulable, and an approver clicking it would
// create a grant that expired before it existed.
func parseWindow(fromStr, toStr string) (from, to *time.Time, err error) {
	parse := func(v, field string) (*time.Time, error) {
		if strings.TrimSpace(v) == "" {
			return nil, nil
		}
		t, perr := time.Parse(time.RFC3339, v)
		if perr != nil {
			return nil, fmt.Errorf("%s must be an RFC3339 timestamp", field)
		}
		return &t, nil
	}

	if from, err = parse(fromStr, "not_before"); err != nil {
		return nil, nil, err
	}
	if to, err = parse(toStr, "not_after"); err != nil {
		return nil, nil, err
	}

	// A start in the past is the same as no start, and storing it would make
	// the request look scheduled when it is not.
	if from != nil && !from.After(time.Now()) {
		from = nil
	}
	if to != nil && !to.After(time.Now()) {
		return nil, nil, errors.New("that window has already closed")
	}
	if from != nil && to != nil && !to.After(*from) {
		return nil, nil, errors.New("the window has to end after it starts")
	}
	return from, to, nil
}
