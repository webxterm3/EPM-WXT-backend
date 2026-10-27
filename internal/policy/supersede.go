package policy

import (
	"strings"
	"time"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// BlockedAfter reports whether a policy rule that BLOCKS this application was
// written, or last changed, after the approval was granted.
//
// An approval is a deliberate exception to the rules, so it has to be able to
// override a block — that is the whole of the JIT route, and an administrator
// who approves a request for software a rule forbids means exactly what they
// clicked.
//
// What it must NOT override is a block written LATER. An administrator who
// decides on Tuesday that an application is no longer allowed has not had
// their decision overruled by Monday's one-off exception — and that is what
// was happening: software was blocked, removed from the machine, and then
// reinstalled itself on the next mount because a still-live approval from
// before the rule existed said it was fine.
//
// Compared against the SOURCE POLICY's UpdatedAt rather than a global
// timestamp, so editing an unrelated policy does not quietly cancel live
// approvals across the tenant.
func BlockedAfter(policies []*store.AppPolicy, approvedAt time.Time, app ApprovedInstall) bool {
	if approvedAt.IsZero() {
		// Nothing to compare against. Left standing rather than cancelled:
		// an approval somebody made is not something to withdraw because its
		// timestamp is missing.
		return false
	}
	return blockedByRule(policies, app, approvedAt)
}

// BlockedByRule reports whether any enabled rule in these policies forbids
// this application, whenever it was written.
//
// A standing rule is a decision about every machine; an approval is one
// person's answer to one ask. The endpoint will not install software a rule
// blocks however many people approve it, so the portal refuses the approval
// rather than recording one that cannot take effect — an approver who clicks
// yes and watches nothing happen has been told the product is broken.
func BlockedByRule(policies []*store.AppPolicy, app ApprovedInstall) bool {
	return blockedByRule(policies, app, time.Time{})
}

// blockedByRule is the shared matcher. A zero `after` considers every rule;
// otherwise only rules whose policy was changed after that moment.
func blockedByRule(policies []*store.AppPolicy, app ApprovedInstall, after time.Time) bool {
	// The path matters as much as the rest.
	//
	// matchPath needs one: with both ExePath and InstallPath empty it
	// returns false, so EVERY rule carrying a path criterion failed to
	// match here while matching perfectly well on the endpoint. The portal
	// then showed no warning at all about software the machine was about to
	// refuse.
	subject := &store.InstalledApp{
		Name:           app.Application,
		NameLower:      strings.ToLower(app.Application),
		Publisher:      app.Publisher,
		PublisherLower: strings.ToLower(app.Publisher),
		BundleID:       app.BundleID,
		InstallPath:    app.InstallPath,
	}

	for _, p := range policies {
		if p == nil || !p.Enabled {
			continue
		}
		if !after.IsZero() && !p.UpdatedAt.After(after) {
			continue
		}
		for _, rule := range p.Rules {
			if !rule.Enabled || rule.Action != store.ActionBlock {
				continue
			}
			if matches(rule.Match, subject) {
				return true
			}
		}
	}
	return false
}
