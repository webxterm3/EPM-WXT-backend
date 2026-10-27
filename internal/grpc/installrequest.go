package grpc

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/approvers"
	"github.com/vsay/vsay-agent-backend/internal/store"
)

// InstallRequestDiscriminator is an endpoint asking for software policy
// currently forbids.
//
// Must match the constant in the agent — pinned by a drift test, because a
// rename on either side would not fail a build here. The button would simply
// stop producing requests, and the person who pressed it would be told it had
// worked.
const InstallRequestDiscriminator = "__install_request__"

// InstallResultDiscriminator is the endpoint reporting what became of an
// approval. Must match the constant in the agent — pinned by a drift test.
const InstallResultDiscriminator = "__install_result__"

// installApprovalWindow is how long an approval lasts.
//
// An install is not a session, so "how long" is a slightly odd question — but
// an approval that never expires is a policy change made by whoever happened
// to click once, and it would outlive the reason for it. A day is long enough
// for somebody to come back to their machine and short enough that it is
// clearly an exception rather than a rule.
const installApprovalWindow = 24 * 60 // minutes

// endpointInstallRequest is what the agent reports.
//
// Every field is read off the BUNDLE the agent refused — its own name,
// publisher and identifier — not from anything the person typed. An approver
// is deciding about one specific signed application.
type endpointInstallRequest struct {
	Application string `json:"application"`
	Publisher   string `json:"publisher"`
	BundleID    string `json:"bundle_id"`
	Version     string `json:"version"`
	OSUser      string `json:"os_user"`
	OSUserEmail string `json:"os_user_email"`
	InstallPath string `json:"install_path,omitempty"`
	Rule        string `json:"rule"`
	Policy      string `json:"policy"`
}

// handleInstallRequest turns an endpoint's request into an access request an
// administrator can act on.
func (s *AgentServer) handleInstallRequest(agentID, payload string) {
	var req endpointInstallRequest
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		s.logger.Warn("install request: could not decode",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}
	if strings.TrimSpace(req.Application) == "" {
		return
	}

	machine, err := s.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		s.logger.Warn("install request: unknown agent", zap.String("agent_id", agentID))
		return
	}

	// One pending request per application per machine.
	//
	// The button is in a menu somebody can open repeatedly, and an image that
	// stays mounted keeps offering it. Without this, an approver's queue
	// fills with the same ask and the real ones are lost among them.
	if s.hasPendingInstallRequest(machine, req) {
		s.logger.Debug("install request: one is already pending",
			zap.String("application", req.Application))
		return
	}

	ar := &store.AccessRequest{
		MachineID:      machine.ID,
		MachineName:    machine.Name,
		MachineAgentID: agentID,
		TenantID:       machine.TenantID,
		OwnerID:        machine.OwnerID.Hex(),

		Source: store.SourceEndpoint,

		// The OS account, not a portal user.
		//
		// The endpoint knows who is logged into the Mac; the portal knows
		// people with accounts, and those are different namespaces that do
		// not reliably map. RequesterID is deliberately left empty rather
		// than guessed — a wrong id would attribute somebody else's request.
		//
		// The self-approval check compares usernames as well as ids for
		// exactly this case, so an administrator whose account name matches
		// the OS account still cannot approve their own.
		RequesterUsername: req.OSUser,

		// The directory address, when the endpoint could establish one.
		//
		// Without it an approver sees a Mac account name and cannot tell who
		// it is, searching the queue by email matches nothing, and the
		// decision mail has nowhere to go — the sender is guarded on this
		// field being set.
		RequesterEmail: req.OSUserEmail,

		Title:       "Install " + req.Application,
		RequestNote: installRequestNote(req, machine.Name),

		DurationMinutes: installApprovalWindow,
		Asks: store.AccessAsks{
			AppInstall: &store.AppInstallAsk{
				Reason:       "Blocked by " + req.Policy,
				Applications: []string{req.Application},
				// Read off the bundle the agent refused, so the approval
				// cannot be claimed by something else of the same name.
				Publisher: req.Publisher,
				BundleID:  req.BundleID,
				// Where the endpoint judged the policy. Carried so the
				// portal can reach the same verdict about a rule that
				// matches on a path.
				InstallPath: req.InstallPath,
			},
		},
		Status:      "pending",
		RequestedAt: time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.store.CreateAccessRequest(ar); err != nil {
		s.logger.Error("install request: could not be recorded",
			zap.String("application", req.Application), zap.Error(err))
		return
	}

	s.logger.Info("install request raised from an endpoint",
		zap.String("application", req.Application),
		zap.String("publisher", req.Publisher),
		zap.String("machine", machine.Name),
		zap.String("os_user", req.OSUser))

	go s.notifyInstallApprovers(machine, req)
}

// installRequestNote is what the approver reads.
//
// Branched on whether a rule actually matched, because in a default-deny
// estate most requests are for software NO rule mentions: Evaluate returns
// the default action with Rule and PolicyName unset, and the one-shape note
// rendered that as `was blocked by the rule "" in policy ""` — which reads
// like a fault in the product at the exact moment somebody is being asked to
// make a decision about it.
func installRequestNote(req endpointInstallRequest, machineName string) string {
	who := "somebody"
	if req.OSUser != "" {
		who = req.OSUser
	}
	opened := "\n\nRaised from " + machineName + " itself, when " + who +
		" opened the installer."

	if req.Rule != "" && req.Policy != "" {
		return req.Application + " was blocked by the rule \"" + req.Rule +
			"\" in policy \"" + req.Policy + "\"." + opened
	}
	return "No policy rule covers " + req.Application + ", so it was not " +
		"installed." + opened
}

// hasPendingInstallRequest reports whether this machine already has one
// waiting for this application.
func (s *AgentServer) hasPendingInstallRequest(machine *store.Machine, req endpointInstallRequest) bool {
	pending, err := s.store.HasPendingInstallRequest(machine.AgentID, req.Application)
	if err != nil {
		// Unknown rather than true: raising a duplicate is less harmful than
		// losing a real request, so an unreadable store errs towards raising
		// it. The approver sees two rows; the alternative is somebody who
		// cannot install their software and no record that they asked.
		s.logger.Warn("install request: duplicate check failed, raising anyway",
			zap.String("application", req.Application), zap.Error(err))
		return false
	}
	return pending
}

// notifyInstallApprovers mails whoever decides for this machine.
func (s *AgentServer) notifyInstallApprovers(machine *store.Machine, req endpointInstallRequest) {
	recipients := machine.NotifyEmails
	if len(machine.GroupIDs) > 0 && s.approvers != nil {
		if list, err := s.approvers.ForGroups(context.Background(), machine.GroupIDs); err == nil {
			if emails := approvers.Emails(list); len(emails) > 0 {
				recipients = emails
			}
		}
	}
	if len(recipients) == 0 || s.email == nil {
		return
	}

	if err := s.email.SendAccessRequestNotification(
		recipients[0], "", req.OSUser, machine.Name,
		installApprovalWindow, "Asked to install "+req.Application,
	); err != nil {
		s.logger.Warn("install request: notification failed", zap.Error(err))
	}
}

// endpointInstallResult is what the agent reports after acting on an
// approval.
type endpointInstallResult struct {
	Application string `json:"application"`
	BundleID    string `json:"bundle_id"`
	Publisher   string `json:"publisher"`
	OSUser      string `json:"os_user"`
	Problem     string `json:"problem,omitempty"`
}

// handleInstallResult closes the loop on an approval.
//
// An install is not a session. It either happened or it did not, and until
// the endpoint said so, an approved request sat in "Active" for the whole of
// its 24-hour window whether the software went on in the first minute or
// never went on at all — and the exception stayed live the entire time,
// long after it had been used.
func (s *AgentServer) handleInstallResult(agentID, payload string) {
	var res endpointInstallResult
	if err := json.Unmarshal([]byte(payload), &res); err != nil {
		s.logger.Warn("install result: could not decode",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}
	if strings.TrimSpace(res.Application) == "" {
		s.logger.Warn("install result: no application named",
			zap.String("agent_id", agentID))
		return
	}

	// A failure is NOT completed.
	//
	// It leaves the approval live so the person can try again — the disk
	// image may have been ejected mid-copy, or the disk may have been full.
	// Marking it done would close the only route they have.
	if res.Problem != "" {
		s.logger.Warn("an approved install failed on the endpoint",
			zap.String("application", res.Application),
			zap.String("agent_id", agentID),
			zap.String("problem", res.Problem))
		return
	}

	ar, err := s.store.ApprovedInstallRequest(agentID, res.Application)
	if err != nil || ar == nil {
		// Nothing to close. Installing something that was allowed by a
		// POLICY RULE rather than by an approval is the ordinary case and
		// has no request behind it.
		s.logger.Debug("install result: no approved request matches",
			zap.String("application", res.Application))
		return
	}

	now := time.Now()
	// The status is already terminal — an install request is finished for
	// the approver the moment they decide. What this records is that the
	// permission has now been SPENT, so uninstalling the software and
	// wanting it back is a new ask.
	ar.UsedAt = &now
	ar.UpdatedAt = now
	if err := s.store.UpdateAccessRequest(ar); err != nil {
		s.logger.Error("install result: could not record completion",
			zap.String("application", res.Application), zap.Error(err))
		return
	}

	s.logger.Info("approved software was installed",
		zap.String("application", res.Application),
		zap.String("agent_id", agentID))

	// The exception has been used, so it stops being delivered: the next
	// push resolves without it, because approvedInstallsFor reads only
	// requests that are still "approved".
	if machine, err := s.store.GetMachineByAgentID(agentID); err == nil && machine != nil && s.policyPusher != nil {
		if err := s.policyPusher.PushTo(machine); err != nil {
			s.logger.Warn("install result: could not refresh the machine's policy",
				zap.String("machine", machine.Name), zap.Error(err))
		}
	}
}
