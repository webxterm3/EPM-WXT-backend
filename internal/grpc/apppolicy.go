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

	// enforcementEnabled mirrors the API's kill switch. It is passed to
	// Resolve, which is where audit-versus-enforce is decided, so a machine
	// cannot be sent an enforcing policy while the product says enforcement is
	// off.
	enforcementEnabled bool
}

func NewPolicyPusher(s store.Store, m *AgentManager, enforcementEnabled bool, logger *zap.Logger) *PolicyPusher {
	return &PolicyPusher{store: s, manager: m, enforcementEnabled: enforcementEnabled, logger: logger}
}

// EffectiveFor resolves one machine's policy.
func (p *PolicyPusher) EffectiveFor(machine *store.Machine) (policy.Effective, error) {
	policies, err := p.store.GetAppPoliciesByTenant(machine.TenantID)
	if err != nil {
		return policy.Effective{}, fmt.Errorf("loading policies: %w", err)
	}
	return policy.Resolve(machine, policies, p.enforcementEnabled), nil
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

	for _, m := range machines {
		if !p.manager.IsAgentConnected(m.AgentID) {
			continue
		}
		if err := p.PushTo(m); err != nil {
			p.logger.Warn("policy push failed",
				zap.String("agent_id", m.AgentID), zap.Error(err))
			failed++
			continue
		}
		pushed++
	}
	return pushed, failed
}
