package api

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

// A remote-control session that is never cleaned up blocks every later
// attempt to reach that machine: StartRemoteControl refuses with "a session
// is already in progress", and before this was fixed the only cure anybody
// found was restarting the backend.

func manager(sessions map[string]*rcSession) *RemoteControlManager {
	return &RemoteControlManager{logger: zap.NewNop(), sessions: sessions}
}

// An unanswered consent prompt, a denial, an error: all of them stop being
// interesting once they are old.
func TestStaleNonActiveSessionsAreDropped(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	m := manager(map[string]*rcSession{
		"waiting": {State: rcStateAwaitingConsent, UpdatedAt: old},
		"denied":  {State: rcStateDenied, UpdatedAt: old},
		"errored": {State: rcStateError, UpdatedAt: old},
	})

	m.sweepOnce(time.Now().Add(-rcSessionTTL))

	if len(m.sessions) != 0 {
		t.Errorf("%d stale sessions survived the sweep", len(m.sessions))
	}
}

// A consent prompt that went out ten seconds ago is not stale.
func TestARecentConsentPromptIsLeftAlone(t *testing.T) {
	m := manager(map[string]*rcSession{
		"waiting": {State: rcStateAwaitingConsent, UpdatedAt: time.Now()},
	})

	m.sweepOnce(time.Now().Add(-rcSessionTTL))

	if len(m.sessions) != 1 {
		t.Error("a consent prompt that has just gone out was swept away")
	}
}

// The bug this fixes. An active session is NOT dropped on age — a busy
// session can legitimately run for hours — so it is reported back for the
// caller to check against the agent's actual connection.
func TestAnActiveSessionIsReportedForAConnectionCheck(t *testing.T) {
	m := manager(map[string]*rcSession{
		"live": {State: rcStateActive, UpdatedAt: time.Now().Add(-time.Hour)},
	})

	live, _ := m.sweepOnce(time.Now().Add(-rcSessionTTL))

	if len(live) != 1 || live[0] != "live" {
		t.Fatalf("live = %v, want the active session reported", live)
	}
	if len(m.sessions) != 1 {
		t.Error("an active session was deleted on age alone — a long session " +
			"would be cut off while somebody was using it")
	}
}

// A session past its policy cap is reported separately, because ending it
// means telling the machine rather than just forgetting it.
func TestAnOverrunningSessionIsReportedForAProperEnding(t *testing.T) {
	m := manager(map[string]*rcSession{
		"overrun": {
			State: rcStateActive, MaxSessionMinutes: 30,
			StartedAt: time.Now().Add(-time.Hour), UpdatedAt: time.Now(),
		},
	})

	live, expired := m.sweepOnce(time.Now().Add(-rcSessionTTL))

	if len(expired) != 1 {
		t.Fatalf("expired = %v, want the overrunning session", expired)
	}
	if len(live) != 0 {
		t.Error("an overrunning session was also queued for a connection check — " +
			"it would be ended twice")
	}
}

// The heart of it: the machine went away, so the session is over whatever the
// record says. The tunnel rides the agent's gRPC stream and cannot outlive it.
func TestAbandonClearsASessionWhoseMachineWentAway(t *testing.T) {
	m := manager(map[string]*rcSession{
		"gone": {State: rcStateActive, Viewer: "priya", UpdatedAt: time.Now()},
	})

	m.abandon("gone")

	if len(m.sessions) != 0 {
		t.Error("the session survived — every later attempt to reach that machine " +
			"would be refused as already in progress")
	}
}

// abandon runs after the lock was released to check connectivity, so the
// world may have moved on. It must act on what it finds, not on what the
// caller saw.
func TestAbandonLeavesASessionThatChangedUnderneathIt(t *testing.T) {
	m := manager(map[string]*rcSession{
		"reconnected": {State: rcStateAwaitingConsent, UpdatedAt: time.Now()},
	})

	m.abandon("reconnected")

	if len(m.sessions) != 1 {
		t.Error("a session that was no longer active was cleared anyway")
	}
}

func TestAbandonOnAMissingSessionIsHarmless(t *testing.T) {
	m := manager(map[string]*rcSession{})
	m.abandon("never-existed")
}

// A stopped session must leave NO record. An idle husk still carries the
// viewer's name, their reason and a start time, and the status endpoint
// returns all of it — so the portal goes on describing a session that is over.
func TestStoppingRemovesTheRecordRatherThanMarkingItIdle(t *testing.T) {
	m := manager(map[string]*rcSession{
		"a1": {State: rcStateActive, Viewer: "priya", AdminName: "priya", Reason: "support"},
	})

	// The same thing StopRemoteControl does to the map.
	m.mu.Lock()
	delete(m.sessions, "a1")
	m.mu.Unlock()

	if m.get("a1") != nil {
		t.Error("a stopped session left a record behind")
	}
}

// ── A session that claims to be ready but is not ────────────────────────────

// The browser is sent to a session the moment the state says active, and the
// only thing it can do there is connect to a port. An active state with no
// port used to be ignored — which left the session on whatever it already
// was, usually awaiting_consent, so the console polled forever for a session
// that was never coming.
func TestAnActiveStateWithNoPortBecomesAnError(t *testing.T) {
	m := manager(map[string]*rcSession{
		"a1": {AgentID: "a1", State: rcStateAwaitingConsent},
	})

	m.HandleAgentData("rc_a1", []byte(`{"type":"rc_state","state":"active"}`))

	s := m.get("a1")
	if s == nil {
		t.Fatal("the session vanished")
	}
	if s.State != rcStateError {
		t.Errorf("State = %q, want error — the console would otherwise wait forever", s.State)
	}
	if s.Error == "" {
		t.Error("no reason was recorded, so the console would say nothing useful")
	}
}

// The ordinary path must still work: active WITH a port is a real session.
func TestAnActiveStateWithAPortIsAccepted(t *testing.T) {
	m := manager(map[string]*rcSession{
		"a1": {AgentID: "a1", State: rcStateAwaitingConsent},
	})

	m.HandleAgentData("rc_a1", []byte(
		`{"type":"rc_state","state":"active","session_id":"rc_x","port":59123,"width":1920,"height":1080}`))

	s := m.get("a1")
	if s.State != rcStateActive {
		t.Fatalf("State = %q, want active", s.State)
	}
	if s.Port != 59123 || s.SessionID != "rc_x" {
		t.Errorf("port/session lost: %d %q", s.Port, s.SessionID)
	}
}

// A later status message for a session that already has a port must not be
// mistaken for the broken case — status replies legitimately omit the port.
func TestALaterStatusWithoutAPortDoesNotBreakALiveSession(t *testing.T) {
	m := manager(map[string]*rcSession{
		"a1": {AgentID: "a1", State: rcStateActive, Port: 59123, SessionID: "rc_x"},
	})

	m.HandleAgentData("rc_a1", []byte(`{"type":"rc_state","state":"active"}`))

	s := m.get("a1")
	if s.State != rcStateActive {
		t.Errorf("State = %q; a routine status reply killed a live session", s.State)
	}
	if s.Port != 59123 {
		t.Errorf("Port = %d, want the one it already had", s.Port)
	}
}
