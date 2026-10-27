package grpc

import (
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/policy"
	"github.com/vsay/vsay-agent-backend/internal/store"
)

// PolicyPusher resolves a machine's application policy and delivers it.
//
// One type, used by both the on-connect path and the admin-save path, so the
// two can never disagree about what a machine's policy is — the same reason
// policy.Resolve is a single pure function. A machine that was offline when a
// policy changed gets it on reconnect; a machine that is online gets it the
// moment an administrator saves.
type PolicyPusher struct {
	store   store.Store
	manager *AgentManager
	logger  *zap.Logger
}

func NewPolicyPusher(s store.Store, m *AgentManager, logger *zap.Logger) *PolicyPusher {
	return &PolicyPusher{store: s, manager: m, logger: logger}
}

// EnforcementEnabled reports whether a tenant has switched enforcement on.
//
// Read from the store on every resolution rather than cached: the switch is
// the difference between a product that watches and one that closes somebody's
// browser, and an operator turning it off expects that to take effect now, not
// after the next restart.
//
// A read that fails returns false. The failure direction matters: an
// unreachable settings document must mean "do not enforce", never "enforce
// whatever the policies happen to say".
func (p *PolicyPusher) EnforcementEnabled(tenantID string) bool {
	settings, err := p.store.GetAppControlSettings(tenantID)
	if err != nil || settings == nil {
		p.logger.Warn("could not read application-control settings; treating enforcement as off",
			zap.String("tenant_id", tenantID), zap.Error(err))
		return false
	}
	return settings.Enforcement
}

// PushTo delivers one machine's policy to it.
//
// An offline machine is not an error: it will be sent its policy when it next
// connects, which is the whole reason the on-connect path exists.
//
// This goes through pushResolved, so a single-machine push and a fleet sweep
// send the same thing. It used to resolve and marshal here instead, under a
// comment claiming the two could not drift — and they had already drifted in
// the way that mattered most: only pushResolved attached ApprovedInstalls.
//
// Every route that delivers policy to ONE machine runs through here — the
// on-connect push and the menu bar's "Sync Now" — so an approval reached a
// Mac only if somebody happened to edit a policy afterwards and trigger a
// tenant-wide sweep. Approving a request appeared to work, delivered a
// policy with no exceptions in it, and the endpoint went on refusing the
// software with nothing anywhere reporting a fault.
func (p *PolicyPusher) PushTo(machine *store.Machine) error {
	if !p.manager.IsAgentConnected(machine.AgentID) {
		return nil
	}

	policies, err := p.store.GetAppPoliciesByTenant(machine.TenantID)
	if err != nil {
		return fmt.Errorf("loading policies: %w", err)
	}
	return p.pushResolved(machine, policies, p.EnforcementEnabled(machine.TenantID))
}

// PushToTenant delivers the current policy to every connected machine in a
// tenant. Used after any policy is created, changed or deleted.
//
// One machine failing costs that machine, not the sweep: a fleet is never
// fully reachable, and refusing to update ninety-nine machines because the
// hundredth is wedged is the wrong trade.
func (p *PolicyPusher) PushToTenant(tenantID string) (pushed int, failed int) {
	machines, err := p.store.GetMachinesByTenantID(tenantID)
	if err != nil {
		p.logger.Warn("policy push: could not list machines", zap.String("tenant_id", tenantID), zap.Error(err))
		return 0, 0
	}

	// Read once for the whole sweep. Per machine it would be one database
	// round trip per endpoint, and worse, a switch flipped mid-sweep would
	// leave half the fleet enforcing and half not.
	enforcing := p.EnforcementEnabled(tenantID)
	policies, err := p.store.GetAppPoliciesByTenant(tenantID)
	if err != nil {
		p.logger.Warn("policy push: could not load policies", zap.String("tenant_id", tenantID), zap.Error(err))
		return 0, 0
	}

	for _, m := range machines {
		if !p.manager.IsAgentConnected(m.AgentID) {
			continue
		}
		if err := p.pushResolved(m, policies, enforcing); err != nil {
			p.logger.Warn("policy push failed",
				zap.String("agent_id", m.AgentID), zap.Error(err))
			failed++
			continue
		}
		pushed++
	}
	return pushed, failed
}

// pushResolved delivers a policy resolved from an already-loaded set.
//
// It exists so a fleet-wide push reads the policies and the enforcement switch
// once rather than once per machine. PushTo remains the single-machine entry
// point and goes through the same resolver, so the two cannot drift.
func (p *PolicyPusher) pushResolved(machine *store.Machine, policies []*store.AppPolicy, enforcing bool) error {
	eff := policy.Resolve(machine, policies, enforcing)

	// Exceptions are attached AFTER resolution, never inside it.
	//
	// Resolve is called by the portal's simulation as well as by this push,
	// and a simulation that invented exceptions would report a fleet nobody
	// has. Keeping it pure is also what lets the two agree about what a
	// policy does, which is the whole reason they share the function.
	eff.ApprovedInstalls = p.approvedInstallsFor(machine, policies)

	encoded, err := json.Marshal(eff)
	if err != nil {
		return fmt.Errorf("encoding the policy: %w", err)
	}
	return p.manager.SendAppPolicy(machine.AgentID, string(encoded))
}

// PolicyRequestDiscriminator is the agent asking for its policy now, because
// somebody pressed "Sync Now" in the menu bar.
//
// Must match the constant in the agent — pinned by the drift test, because a
// rename on either side would not fail a build here. The button would simply
// stop working, and the menu bar cannot tell: it writes a file and has no way
// to learn whether anything answered.
const PolicyRequestDiscriminator = "__policy_request__"

// policyRequestMinGap is the shortest time between two honoured requests from
// one machine.
//
// The button is pressed by a person, so the honest rate is a few per minute at
// most. The limit is not there to protect against that: it is there because
// the request arrives over a channel an endpoint controls, and a machine that
// sent it in a loop would have the backend resolve policy for it as fast as it
// could ask.
const policyRequestMinGap = 5 * time.Second

// handlePolicyRequest pushes this machine's policy, on request.
//
// The agent sends no policy and asks for none in particular — only "send me
// mine". Everything about what that means is resolved here from the machine
// record, so the request is not a way to obtain somebody else's policy or to
// get a policy earlier than the fleet would.
func (s *AgentServer) handlePolicyRequest(agentID string) {
	if s.policyPusher == nil {
		return
	}

	if !s.allowPolicyRequest(agentID) {
		s.logger.Debug("policy sync: ignoring a request that arrived too soon",
			zap.String("agent_id", agentID))
		return
	}

	machine, err := s.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		s.logger.Warn("policy sync: unknown agent asked for a policy",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}

	if err := s.policyPusher.PushTo(machine); err != nil {
		s.logger.Warn("policy sync: could not push on request",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}
	s.logger.Info("policy sync: pushed on request",
		zap.String("agent_id", agentID), zap.String("machine", machine.Name))
}

// allowPolicyRequest rate-limits one machine's requests.
func (s *AgentServer) allowPolicyRequest(agentID string) bool {
	s.policyReqMu.Lock()
	defer s.policyReqMu.Unlock()

	if s.policyReqAt == nil {
		s.policyReqAt = map[string]time.Time{}
	}
	now := time.Now()
	if last, ok := s.policyReqAt[agentID]; ok && now.Sub(last) < policyRequestMinGap {
		return false
	}
	s.policyReqAt[agentID] = now
	return true
}

// approvedInstallsFor is the live exceptions for one machine.
//
// Read at push time rather than cached: an approval that has been revoked, or
// has lapsed, must stop being delivered on the next push, and a cache is a
// second place for the answer to be wrong.
func (p *PolicyPusher) approvedInstallsFor(machine *store.Machine, policies []*store.AppPolicy) []policy.ApprovedInstall {
	requests, err := p.store.ApprovedInstallsForMachine(machine.AgentID)
	if err != nil {
		// Nothing rather than everything. An unreadable store must not open
		// a machine up; it must leave policy as it was.
		p.logger.Warn("could not read this machine's approved installs",
			zap.String("agent_id", machine.AgentID), zap.Error(err))
		return nil
	}

	now := time.Now()
	var out []policy.ApprovedInstall
	for _, r := range requests {
		if r.Asks.AppInstall == nil {
			continue
		}
		// An approval with no end, or one that has passed, delivers nothing.
		// The sweep marks these expired within five minutes, and until it
		// does this is what stops them applying.
		if r.ExpiresAt == nil || !r.ExpiresAt.After(now) {
			continue
		}
		for _, app := range r.Asks.AppInstall.Applications {
			exception := policy.ApprovedInstall{
				Application: app,
				// Carried through so the endpoint can refuse an application
				// of the same name signed by somebody else.
				Publisher:   r.Asks.AppInstall.Publisher,
				BundleID:    r.Asks.AppInstall.BundleID,
				InstallPath: r.Asks.AppInstall.InstallPath,
				Until:       *r.ExpiresAt,
				Operation:   r.Asks.AppInstall.InstallOperation(),
				Spent:       r.UsedAt != nil,
			}

			// A block written AFTER the approval supersedes it.
			//
			// Without this, blocking an application did not stick: it was
			// removed from the machine, and then reinstalled itself on the
			// next mount because an approval granted before the rule existed
			// still said it was allowed.
			if r.ApprovedAt != nil && policy.BlockedAfter(policies, *r.ApprovedAt, exception) {
				p.logger.Info("an approval is superseded by a later block rule",
					zap.String("application", app),
					zap.String("machine", machine.Name))
				continue
			}
			out = append(out, exception)
		}
	}
	return out
}
