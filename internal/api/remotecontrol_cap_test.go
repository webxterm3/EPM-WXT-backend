package api

import (
	"testing"
	"time"
)

// The session cap has to be absolute, measured from when the session started.
// The idle timeout is a different thing and a busy session never reaches it —
// somebody moving the mouse continuously would otherwise stay connected
// indefinitely under a policy that says thirty minutes.
func TestSessionCapIsAbsoluteNotIdle(t *testing.T) {
	m := &RemoteControlManager{}

	cases := []struct {
		name    string
		session *rcSession
		want    bool
	}{
		{
			name: "active and past its limit",
			session: &rcSession{
				State: rcStateActive, MaxSessionMinutes: 30,
				StartedAt: time.Now().Add(-31 * time.Minute),
				// Updated a moment ago: the session is busy, so an idle
				// timeout would never fire. The cap still must.
				UpdatedAt: time.Now(),
			},
			want: true,
		},
		{
			name: "active and within its limit",
			session: &rcSession{
				State: rcStateActive, MaxSessionMinutes: 30,
				StartedAt: time.Now().Add(-29 * time.Minute),
			},
			want: false,
		},
		{
			name: "exactly at the limit",
			session: &rcSession{
				State: rcStateActive, MaxSessionMinutes: 30,
				StartedAt: time.Now().Add(-30 * time.Minute),
			},
			want: true,
		},
		{
			name: "no cap configured",
			session: &rcSession{
				State: rcStateActive, MaxSessionMinutes: 0,
				StartedAt: time.Now().Add(-10 * time.Hour),
			},
			want: false,
		},
		{
			name: "not active yet",
			session: &rcSession{
				State: rcStateAwaitingConsent, MaxSessionMinutes: 1,
				StartedAt: time.Now().Add(-10 * time.Minute),
			},
			want: false,
		},
		{
			name: "active but never recorded a start",
			session: &rcSession{
				// Without a start time there is nothing to measure from, and
				// guessing would cut a session that just began.
				State: rcStateActive, MaxSessionMinutes: 5,
			},
			want: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := m.overRunning(c.session); got != c.want {
				t.Errorf("overRunning = %v, want %v", got, c.want)
			}
		})
	}
}
