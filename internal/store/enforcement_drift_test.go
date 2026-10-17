package store

import (
	"strings"
	"testing"
)

// The enforcement report is the only record of decisions made on an endpoint.
// A mismatch here is not a compile error on either side: the reports simply
// stop arriving, and the portal shows a fleet where nothing was ever blocked —
// which is indistinguishable from a fleet where nothing needed blocking.

func TestEnforcementDiscriminatorMatchesTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/agent/appcontrol.go")

	const want = `EnforcementDiscriminator = "__app_enforcement__"`
	if !strings.Contains(src, want) {
		t.Fatalf("the agent no longer defines %s — enforcement activity would never be recorded", want)
	}
}

// Every key the backend decodes must exist as a json tag on the agent's own
// types. A renamed field decodes to its zero value rather than failing, so a
// drift in "mechanism" would file every block under the empty mechanism and
// the compliance report's counts would all read zero.
func TestEnforcementEventFieldsExistOnTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/appcontrol/appcontrol.go")

	for _, tag := range []string{
		`json:"at"`, `json:"mechanism"`, `json:"outcome"`,
		`json:"app_name,omitempty"`, `json:"path,omitempty"`,
		`json:"bundle_id,omitempty"`, `json:"rule,omitempty"`,
		`json:"policy,omitempty"`, `json:"pid,omitempty"`,
		`json:"detail,omitempty"`,
	} {
		if !strings.Contains(src, tag) {
			t.Errorf("the agent's Event no longer carries %s — that field would arrive empty", tag)
		}
	}
}

func TestEnforcementReportEnvelopeMatchesTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/agent/appcontrol.go")

	for _, tag := range []string{
		`json:"reported_at"`, `json:"agent_version"`,
		`json:"mechanism"`, `json:"events"`,
	} {
		if !strings.Contains(src, tag) {
			t.Errorf("the agent's enforcement report no longer carries %s", tag)
		}
	}
}

// The mechanism names are a shared vocabulary: the backend groups the
// compliance report by them, and the portal labels rows with them. A rename on
// the agent would produce a category nothing counts.
func TestEnforcementMechanismNamesMatchTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/appcontrol/appcontrol.go")

	for name, want := range map[string]string{
		EnforceTerminate: `MechanismTerminate = "terminate"`,
		EnforceLock:      `MechanismLock      = "launch-lock"`,
		EnforceUnlock:    `MechanismUnlock    = "launch-unlock"`,
		EnforceRefused:   `MechanismRefused   = "refused"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the agent no longer spells %q as the backend expects (%s)", name, want)
		}
	}
}

// Enforcement must not be able to start without the agent having the guard
// that stops one mis-saved rule taking a machine out. It is tested properly in
// the agent's own package; this only pins that it still exists, because the
// backend is what turns enforcement on.
func TestTheAgentStillHasABlastRadiusLimit(t *testing.T) {
	src := readAgentFile(t, "internal/appcontrol/appcontrol.go")

	if !strings.Contains(src, "maxBlockedPerPass") {
		t.Fatal("the agent's blast-radius circuit breaker is gone — a policy that matched everything would be applied in full")
	}
}

// Removal is the one policy field that can move a user's software, so the
// agent must be able to read it. A renamed tag does not error on either side —
// it decodes to false, and every block quietly goes back to being a lock.
func TestRemoveBlockedReachesTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/apppolicy/policy.go")

	if !strings.Contains(src, `json:"remove_blocked,omitempty"`) {
		t.Fatal("the agent's EffectiveRule no longer carries remove_blocked — " +
			"policies asking for removal would silently only lock")
	}
	if !strings.Contains(src, "RemoveBlocked") {
		t.Fatal("the agent no longer has a RemoveBlocked field at all")
	}

	// And it must only ever apply to a block decided by a RULE. A policy
	// default that could quarantine would sweep an entire machine.
	if !strings.Contains(src, "er.RemoveBlocked && action == ActionBlock") {
		t.Error("the agent no longer restricts removal to a rule-matched block — " +
			"a default-deny policy could move every application on the machine")
	}
}

// The enforcer has to distinguish an application it MOVED from one it merely
// locked: they are undone in completely different ways.
func TestTheAgentTracksQuarantineSeparately(t *testing.T) {
	state := readAgentFile(t, "internal/appcontrol/state.go")
	if !strings.Contains(state, "Quarantined") {
		t.Fatal("the agent's lock record no longer distinguishes a quarantine from a lock")
	}

	quarantine := readAgentFile(t, "internal/appcontrol/quarantine.go")
	// A move is recoverable and a delete is not. If this ever becomes a
	// delete, a mis-aimed rule destroys somebody's software permanently.
	if !strings.Contains(quarantine, "os.Rename") {
		t.Error("quarantine no longer moves the application — it must never delete one")
	}
	if strings.Contains(quarantine, "os.RemoveAll(src)") {
		t.Error("quarantine deletes the original application instead of moving it")
	}
}
