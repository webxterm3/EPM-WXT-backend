package grpc

import (
	"encoding/json"
	"fmt"

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

// EffectiveFor resolves one machine's policy.
func (p *PolicyPusher) EffectiveFor(machine *store.Machine) (policy.Effective, error) {
	policies, err := p.store.GetAppPoliciesByTenant(machine.TenantID)
	if err != nil {
		return policy.Effective{}, fmt.Errorf("loading policies: %w", err)
	}
	return policy.Resolve(machine, policies, p.EnforcementEnabled(machine.TenantID)), nil
}

// PushTo delivers one machine's policy to it.
//
// An offline machine is not an error: it will be sent its policy when it next
// connects, which is the whole reason the on-connect path exists.
func (p *PolicyPusher) PushTo(machine *store.Machine) error {
	if !p.manager.IsAgentConnected(machine.AgentID) {
		return nil
	}

	eff, err := p.EffectiveFor(machine)
	if err != nil {
		return err
	}

	encoded, err := json.Marshal(eff)
	if err != nil {
		// A policy that cannot be serialised must not be silently skipped:
		// the machine would keep running its previous one while the portal
		// showed the new one as applied.
		return fmt.Errorf("encoding the policy: %w", err)
	}

	return p.manager.SendAppPolicy(machine.AgentID, string(encoded))
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

	encoded, err := json.Marshal(eff)
	if err != nil {
		return fmt.Errorf("encoding the policy: %w", err)
	}
	return p.manager.SendAppPolicy(machine.AgentID, string(encoded))
}
