package grpc

import (
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/policy"
	"github.com/vsay/vsay-agent-backend/internal/store"
)

// PrivPolicyCommandID carries a machine's resolved least-privilege policy.
//
// Must match the constant in the agent, and is pinned by a cross-repo drift
// test. A rename on either side would not fail a build here — and it would
// not merely stop working either: the agent falls through to SHELL EXECUTION
// for a command id it does not recognise, so a drifted id turns a policy
// document into a string handed to the executor.
const PrivPolicyCommandID = "__vsay_privpolicy__"

// PushPrivilegeTo delivers the least-privilege policy to one machine.
//
// A separate push from the application policy rather than a field on it. The
// two have different lifecycles — an approval changes the application policy
// several times a day, while a privilege policy changes rarely — and
// combining them would mean every install approval rewrites the document that
// decides who holds administrator rights.
func (p *PolicyPusher) PushPrivilegeTo(machine *store.Machine) error {
	if !p.manager.IsAgentConnected(machine.AgentID) {
		return nil
	}

	policies, err := p.store.GetPrivilegePoliciesByTenant(machine.TenantID)
	if err != nil {
		return fmt.Errorf("loading privilege policies: %w", err)
	}
	return p.pushPrivilegeResolved(machine, policies, p.PrivilegeEnforcementEnabled(machine.TenantID))
}

// PushPrivilegeToTenant delivers it to every connected machine in a tenant.
//
// One machine failing costs that machine, not the sweep.
func (p *PolicyPusher) PushPrivilegeToTenant(tenantID string) (pushed int, failed int) {
	machines, err := p.store.GetMachinesByTenantID(tenantID)
	if err != nil {
		p.logger.Warn("privilege push: could not list machines",
			zap.String("tenant_id", tenantID), zap.Error(err))
		return 0, 0
	}

	// Read once for the whole sweep. Per machine it would be a round trip per
	// endpoint — and worse, a switch flipped mid-sweep would leave half the
	// fleet enforcing and half not, which for this policy means half the
	// fleet losing administrator rights.
	enforcing := p.PrivilegeEnforcementEnabled(tenantID)
	policies, err := p.store.GetPrivilegePoliciesByTenant(tenantID)
	if err != nil {
		p.logger.Warn("privilege push: could not load policies",
			zap.String("tenant_id", tenantID), zap.Error(err))
		return 0, 0
	}

	for _, m := range machines {
		if !p.manager.IsAgentConnected(m.AgentID) {
			continue
		}
		if err := p.pushPrivilegeResolved(m, policies, enforcing); err != nil {
			p.logger.Warn("privilege push failed",
				zap.String("agent_id", m.AgentID), zap.Error(err))
			failed++
			continue
		}
		pushed++
	}
	return pushed, failed
}

// pushPrivilegeResolved resolves and sends, from an already-loaded set.
func (p *PolicyPusher) pushPrivilegeResolved(machine *store.Machine, policies []*store.PrivilegePolicy, enforcing bool) error {
	eff := policy.ResolvePrivilege(machine, policies, enforcing)

	// Grants are attached AFTER resolution, never inside it. ResolvePrivilege
	// is called by the portal's simulation as well as by this push, and a
	// simulation that invented grants would report a fleet nobody has.
	eff.Grants = p.adminGrantsFor(machine, eff)

	encoded, err := json.Marshal(eff)
	if err != nil {
		return fmt.Errorf("encoding the privilege policy: %w", err)
	}
	return p.manager.SendPrivilegePolicy(machine.AgentID, string(encoded))
}

// PrivilegeEnforcementEnabled reads the tenant's least-privilege switch.
//
// Fails closed: an unreadable settings document must leave the fleet not
// enforcing. This is the single read point for the switch, so a bug anywhere
// else in this path still cannot take anybody's administrator rights away.
func (p *PolicyPusher) PrivilegeEnforcementEnabled(tenantID string) bool {
	settings, err := p.store.GetPrivilegeSettings(tenantID)
	if err != nil || settings == nil {
		if err != nil {
			p.logger.Warn("privilege settings unreadable — treating enforcement as off",
				zap.String("tenant_id", tenantID), zap.Error(err))
		}
		return false
	}
	return settings.Enforcement
}

// adminGrantsFor returns the live, time-bounded administrator grants for one
// machine.
//
// This is what finally gives the just-in-time admin request an effect on the
// endpoint. The request workflow — raise, route to an approver, approve,
// expire, revoke — has existed and been tested for some time; what it did was
// write Machine.AllowedUsers, which is portal remote access, not an operating
// system privilege. Nothing in the push path turned it into one.
//
// Expiry is enforced HERE as well as by the five-minute sweep that marks
// requests expired. The sweep is the bookkeeping; this is what stops a grant
// applying in the minutes before it runs, and it is why a machine that
// reconnects after an approval has lapsed is not handed it.
func (p *PolicyPusher) adminGrantsFor(machine *store.Machine, eff policy.EffectivePrivilege) []policy.AdminGrant {
	// A policy that does not allow admin requests does not honour grants.
	//
	// Checked at push time rather than only at approval time, so that
	// tightening the policy takes effect on the machines already holding a
	// grant rather than only on the next request.
	if !eff.Elevation.AllowAdminRequests {
		return nil
	}

	requests, err := p.store.ApprovedAdminAccessForMachine(machine.AgentID)
	if err != nil {
		// Nothing rather than everything. An unreadable store must not hand
		// out administrator rights; it must leave policy as it was.
		p.logger.Warn("could not read this machine's approved requests",
			zap.String("agent_id", machine.AgentID), zap.Error(err))
		return nil
	}

	now := time.Now()
	var out []policy.AdminGrant

	for _, r := range requests {
		if r.Asks.AdminAccess == nil {
			continue
		}
		// An approval with no end, or one that has passed, delivers nothing.
		if r.ExpiresAt == nil || !r.ExpiresAt.After(now) {
			continue
		}
		if r.RequesterUsername == "" {
			// A grant with nobody to grant it to cannot be applied, and
			// guessing at the account would be the worst possible guess.
			continue
		}

		until := *r.ExpiresAt

		// The policy's ceiling wins over what the request asked for.
		//
		// Applied at push time so that shortening the ceiling cuts short the
		// grants already out, rather than only the ones issued afterwards.
		if eff.Elevation.MaxGrantMinutes > 0 && r.ApprovedAt != nil {
			ceiling := r.ApprovedAt.Add(time.Duration(eff.Elevation.MaxGrantMinutes) * time.Minute)
			if ceiling.Before(until) {
				until = ceiling
			}
			if !until.After(now) {
				continue
			}
		}

		out = append(out, policy.AdminGrant{
			Username:  r.RequesterUsername,
			Until:     until,
			RequestID: r.ID.Hex(),
		})
	}
	return out
}
