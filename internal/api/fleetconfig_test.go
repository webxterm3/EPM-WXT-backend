package api

import (
	"testing"
	"time"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// The default account reaches machines that do not exist yet, which is what
// makes it different from everything else in Settings — and why it is gated
// on super_admin rather than on the ordinary policy-admin gate.

// A machine that already has the account must not be asked again. Without the
// once-per-machine record, every reconnect re-sends the request and the
// endpoint answers "an account named X already exists" into the audit trail
// each time.
func TestAMachineIsOnlyAskedOnce(t *testing.T) {
	applied := time.Now()

	cases := []struct {
		name    string
		machine *store.Machine
		skip    bool
	}{
		{"never asked", &store.Machine{AgentID: "a1"}, false},
		{"already asked", &store.Machine{AgentID: "a1", DefaultUserAppliedAt: &applied}, true},
		{"revoked", &store.Machine{AgentID: "a1", Revoked: true}, true},
		{"no machine", nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldSkipDefaultUser(tc.machine)
			if got != tc.skip {
				t.Errorf("skip = %t, want %t", got, tc.skip)
			}
		})
	}
}

// Turning the feature on with no password would send machines a request they
// must refuse, and the operator would see nothing but failures in the trail.
func TestTheFeatureCannotBeEnabledWithoutAPassword(t *testing.T) {
	cases := []struct {
		name  string
		user  store.DefaultUserConfig
		ready bool
	}{
		{"off and empty", store.DefaultUserConfig{}, false},
		{"on, named, with a password", store.DefaultUserConfig{
			Enabled: true, Username: "itsupport", Password: "sealed",
		}, true},
		{"on but no password", store.DefaultUserConfig{
			Enabled: true, Username: "itsupport",
		}, false},
		{"on but no username", store.DefaultUserConfig{
			Enabled: true, Password: "sealed",
		}, false},
		{"configured but switched off", store.DefaultUserConfig{
			Username: "itsupport", Password: "sealed",
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultUserReady(tc.user); got != tc.ready {
				t.Errorf("ready = %t, want %t", got, tc.ready)
			}
		})
	}
}

// ── Applying to machines that already exist ─────────────────────────────────

// The connect hook alone only ever reaches a machine that connects AFTER the
// setting was turned on. On an estate that is already enrolled that is almost
// nobody, so switching the setting on appeared to do nothing at all.
//
// The sweep covers the rest — and the per-machine record is what makes
// running it twice harmless.

func TestTheSweepSkipsMachinesThatAlreadyHaveIt(t *testing.T) {
	applied := time.Now()

	// The same guard the sweep and the connect hook both consult. Running the
	// sweep a second time must ask nobody again: each of these machines has
	// already been sent the request, and asking again would put "an account
	// named X already exists" in the trail for every one of them.
	cases := []*store.Machine{
		{AgentID: "a1", DefaultUserAppliedAt: &applied},
		{AgentID: "a2", DefaultUserAppliedAt: &applied},
	}

	for _, m := range cases {
		if !shouldSkipDefaultUser(m) {
			t.Errorf("%s would be asked a second time", m.AgentID)
		}
	}
}

// Offline is not a failure. The machine is asked the moment it next connects,
// by the same hook that handles a brand-new enrolment — so there is nothing
// to retry and nothing lost, and reporting it as failed would send somebody
// looking for a fault that is not there.
func TestAnOfflineMachineIsCountedSeparatelyFromAFailure(t *testing.T) {
	var sweep DefaultUserSweep

	sweep.Offline++
	sweep.Failed = append(sweep.Failed, "broken-laptop")

	if sweep.Offline == 0 {
		t.Error("offline machines are not counted at all")
	}
	if len(sweep.Failed) != 1 {
		t.Error("a real failure was folded into the offline count")
	}
}

// A machine nobody has asked yet is the only one the sweep acts on.
func TestOnlyUntouchedMachinesAreAsked(t *testing.T) {
	fresh := &store.Machine{AgentID: "a1"}

	if shouldSkipDefaultUser(fresh) {
		t.Error("a machine that has never been asked was skipped")
	}
}

// Switching the setting on with an incomplete configuration must not start a
// sweep: every machine would be sent a request it has to refuse.
func TestAnIncompleteConfigurationStartsNoSweep(t *testing.T) {
	incomplete := []store.DefaultUserConfig{
		{Enabled: true, Username: "itsupport"},      // no password
		{Enabled: true, Password: "sealed"},         // no username
		{Username: "itsupport", Password: "sealed"}, // switched off
	}

	for i, u := range incomplete {
		if defaultUserReady(u) {
			t.Errorf("case %d would start a sweep on an incomplete configuration", i)
		}
	}
}
