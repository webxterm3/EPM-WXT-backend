package policy

import (
	"testing"
	"time"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

func blockRule(name string) store.PolicyRule {
	return store.PolicyRule{
		ID: "r1", Name: "no " + name, Enabled: true, Action: store.ActionBlock,
		Match: store.MatchCriteria{AppName: store.StringMatch{Op: "equals", Values: []string{name}}},
	}
}

func policyAt(updated time.Time, rules ...store.PolicyRule) *store.AppPolicy {
	return &store.AppPolicy{Name: "p", Enabled: true, UpdatedAt: updated, Rules: rules}
}

var vscode = ApprovedInstall{Application: "Visual Studio Code"}

// An administrator who blocks an application on Tuesday has not been
// overruled by Monday's one-off exception.
//
// This is what made blocking fail to stick: the application was removed from
// the machine, and then reinstalled itself on the next mount because a still
// live approval from before the rule existed said it was allowed.
func TestABlockWrittenAfterTheApprovalSupersedesIt(t *testing.T) {
	approved := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	later := approved.Add(24 * time.Hour)

	if !BlockedAfter([]*store.AppPolicy{policyAt(later, blockRule("Visual Studio Code"))}, approved, vscode) {
		t.Error("a block rule written a day after the approval did not supersede it")
	}
}

// And the other direction must keep working, because it is the whole of the
// JIT route: an approver who says yes to software a rule forbids means
// exactly what they clicked.
func TestAnApprovalStillOverridesABlockThatPredatesIt(t *testing.T) {
	earlier := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	approved := earlier.Add(24 * time.Hour)

	if BlockedAfter([]*store.AppPolicy{policyAt(earlier, blockRule("Visual Studio Code"))}, approved, vscode) {
		t.Error("an approval granted after the block rule was discarded, so the " +
			"approver's decision does nothing")
	}
}

// Editing an unrelated policy must not quietly cancel live approvals across
// the tenant — which is what comparing against a global timestamp would do.
func TestEditingAnUnrelatedPolicyLeavesTheApprovalAlone(t *testing.T) {
	approved := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	later := approved.Add(time.Hour)

	policies := []*store.AppPolicy{policyAt(later, blockRule("qBittorrent"))}
	if BlockedAfter(policies, approved, vscode) {
		t.Error("blocking a DIFFERENT application cancelled this approval")
	}
}

// A disabled rule, or a disabled policy, decides nothing.
func TestADisabledBlockDoesNotSupersedeAnything(t *testing.T) {
	approved := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	later := approved.Add(time.Hour)

	off := blockRule("Visual Studio Code")
	off.Enabled = false
	if BlockedAfter([]*store.AppPolicy{policyAt(later, off)}, approved, vscode) {
		t.Error("a disabled rule superseded an approval")
	}

	disabled := policyAt(later, blockRule("Visual Studio Code"))
	disabled.Enabled = false
	if BlockedAfter([]*store.AppPolicy{disabled}, approved, vscode) {
		t.Error("a disabled policy superseded an approval")
	}
}

// An approval with no timestamp is left standing rather than cancelled: it
// is not something to withdraw because its metadata is missing.
func TestAnApprovalWithNoTimestampIsNotCancelled(t *testing.T) {
	later := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	if BlockedAfter([]*store.AppPolicy{policyAt(later, blockRule("Visual Studio Code"))}, time.Time{}, vscode) {
		t.Error("an approval was cancelled because it had no recorded time")
	}
}

// An allow rule written later is not a block.
func TestALaterAllowRuleDoesNotSupersedeAnApproval(t *testing.T) {
	approved := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	allow := blockRule("Visual Studio Code")
	allow.Action = store.ActionAllow

	if BlockedAfter([]*store.AppPolicy{policyAt(approved.Add(time.Hour), allow)}, approved, vscode) {
		t.Error("an allow rule was treated as superseding the approval")
	}
}

// The portal must refuse an approval the endpoint will not honour.
//
// A rule that blocks beats any approval on the machine. Recording an
// approval anyway records one that cannot take effect: the approver clicks
// yes, nothing happens on the Mac, and the product looks broken rather than
// the policy looking deliberate.
func TestARuleBlockingTheApplicationIsFoundWhateverItsAge(t *testing.T) {
	long := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	policies := []*store.AppPolicy{policyAt(long, blockRule("Visual Studio Code"))}

	if !BlockedByRule(policies, vscode) {
		t.Error("an old block rule was not found, so the approval would be " +
			"recorded and the endpoint would go on refusing the software")
	}
}

// And software no rule names is approvable, which is the ordinary case.
func TestSoftwareNoRuleNamesIsApprovable(t *testing.T) {
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	policies := []*store.AppPolicy{policyAt(now, blockRule("qBittorrent"))}

	if BlockedByRule(policies, vscode) {
		t.Error("a rule about a different application blocked this approval")
	}
}

// A disabled rule decides nothing, here as everywhere else.
func TestADisabledRuleDoesNotRefuseAnApproval(t *testing.T) {
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	off := blockRule("Visual Studio Code")
	off.Enabled = false

	if BlockedByRule([]*store.AppPolicy{policyAt(now, off)}, vscode) {
		t.Error("a disabled rule refused an approval")
	}
}

// A rule that matches on a PATH has to be evaluable here too.
//
// matchPath returns false when the subject has no path at all, and the
// subject was built without one — so every rule carrying a path criterion
// silently failed to match in the portal while matching perfectly well on
// the machine. The administrator was shown no warning, approved the request,
// and the endpoint went on refusing the software.
//
// Written against a rule exactly as the editor saves one: name AND publisher
// AND path AND bundle id, all at once.
func TestARuleThatMatchesOnAPathIsFoundHereToo(t *testing.T) {
	claude := store.PolicyRule{
		ID: "r1", Name: "Block Claude", Enabled: true, Action: store.ActionBlock,
		Match: store.MatchCriteria{
			AppName:   store.StringMatch{Op: "equals", Values: []string{"Claude"}},
			Publisher: store.StringMatch{Op: "contains", Values: []string{"Q6L2SF6YDW"}},
			FilePath:  store.StringMatch{Op: "contains", Values: []string{"/Applications/Claude.app"}},
			BundleID:  store.StringMatch{Op: "equals", Values: []string{"com.anthropic.claudefordesktop"}},
		},
	}
	policies := []*store.AppPolicy{policyAt(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), claude)}

	asked := ApprovedInstall{
		Application: "Claude",
		Publisher:   "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)",
		BundleID:    "com.anthropic.claudefordesktop",
		InstallPath: "/Applications/Claude.app",
	}
	if !BlockedByRule(policies, asked) {
		t.Error("a rule the machine matches was not found here, so the portal " +
			"shows no warning and lets an administrator approve software " +
			"their own policy forbids")
	}

	// And without the path the rule genuinely cannot be judged — which is
	// why the endpoint sends it.
	blind := asked
	blind.InstallPath = ""
	if BlockedByRule(policies, blind) {
		t.Error("a path rule matched something with no path, which is a guess " +
			"rather than an answer")
	}
}
