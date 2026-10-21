package email

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Everything these alerts interpolate is attacker-influenced.
//
// A machine name and an access-request note are typed by a user. An
// application name and a path are read off the ENDPOINT by the inventory
// collector, out of a bundle's own Info.plist or a PE header — files a local
// user on that machine can author. So a user who can install software can also
// choose what lands in an administrator's inbox.
func TestAlertBodiesEscapeWhatTheyInterpolate(t *testing.T) {
	s := New()
	const payload = `<img src=x onerror="alert(1)">`

	// The dangerous form is a LITERAL "<" opening a tag. "onerror=" on its own
	// survives escaping as inert text inside &lt;…&gt;, so looking for it finds
	// a false positive in a body that is perfectly safe — which is what the
	// first version of this test did.
	const marker = `<img`

	at := time.Date(2026, 10, 21, 9, 30, 0, 0, time.UTC)

	cases := []struct {
		name string
		body func() string
	}{
		{"elevation alert — application name", func() string {
			return captureBody(t, s, func() { _ = s.SendElevationAlert([]string{"a@b.c"}, "mac-01", payload, "/tmp/x", "r", "p", "u", at) })
		}},
		{"elevation alert — path", func() string {
			return captureBody(t, s, func() { _ = s.SendElevationAlert([]string{"a@b.c"}, "mac-01", "App", payload, "r", "p", "u", at) })
		}},
		{"elevation unavailable — reason", func() string {
			return captureBody(t, s, func() { _ = s.SendElevationUnavailable([]string{"a@b.c"}, "mac-01", "App", "r", "p", payload) })
		}},
		{"remote session — operator", func() string {
			return captureBody(t, s, func() { _ = s.SendRemoteSessionAlert([]string{"a@b.c"}, "mac-01", payload, "attended", "1.2.3.4", at) })
		}},
		{"remote session — machine name", func() string {
			return captureBody(t, s, func() { _ = s.SendRemoteSessionAlert([]string{"a@b.c"}, payload, "op", "attended", "1.2.3.4", at) })
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := c.body()
			if body == "" {
				t.Fatal("no body captured — the test harness did not intercept the send")
			}
			if strings.Contains(body, marker) {
				t.Errorf("an attacker-supplied value opened a real tag in the HTML:\n%s",
					excerpt(body, marker))
			}
			if !strings.Contains(body, "&lt;img") {
				t.Error("the value does not appear in escaped form either — it was dropped " +
					"rather than escaped, which hides the fact being reported")
			}
		})
	}
}

// Send skips silently when SMTP is not set up. That is right for an optional
// alert and wrong to be silent about, so Configured answers it for callers.
func TestConfiguredSaysWhetherMailWouldActuallyGo(t *testing.T) {
	s := New()

	t.Run("nothing set up", func(t *testing.T) {
		t.Setenv("AUTH_EMAIL_URL", "")
		t.Setenv("SMTP_USERNAME", "")
		if s.Configured() {
			t.Error("reported configured with neither a relay nor SMTP credentials")
		}
	})

	t.Run("routed through vsay-auth", func(t *testing.T) {
		t.Setenv("AUTH_EMAIL_URL", "http://auth/internal/send-email")
		t.Setenv("SMTP_USERNAME", "")
		if !s.Configured() {
			t.Error("a relay URL is set, so mail would go")
		}
	})

	t.Run("direct SMTP", func(t *testing.T) {
		t.Setenv("AUTH_EMAIL_URL", "")
		t.Setenv("SMTP_USERNAME", "bot@example.com")
		if !s.Configured() {
			t.Error("SMTP credentials are set, so mail would go")
		}
	})

	t.Run("whitespace is not configuration", func(t *testing.T) {
		t.Setenv("AUTH_EMAIL_URL", "   ")
		t.Setenv("SMTP_USERNAME", "\t")
		if s.Configured() {
			t.Error("a blank-but-present env var reported as configured — that is how " +
				"an empty value in a compose file becomes a silent non-delivery")
		}
	})
}

// No recipients is not an error. An alert for a machine nobody has viewed yet
// has nowhere to go, and that must not surface as a failure.
func TestNoRecipientsIsNotAFailure(t *testing.T) {
	s := New()
	at := time.Now()
	if err := s.SendElevationAlert(nil, "m", "a", "p", "r", "pol", "u", at); err != nil {
		t.Errorf("elevation alert with no recipients returned %v", err)
	}
	if err := s.SendRemoteSessionAlert([]string{}, "m", "o", "attended", "", at); err != nil {
		t.Errorf("remote session alert with no recipients returned %v", err)
	}
	if err := s.SendElevationUnavailable(nil, "m", "a", "r", "p", "why"); err != nil {
		t.Errorf("elevation-unavailable with no recipients returned %v", err)
	}
}

// captureBody runs a send with SMTP pointed at nothing and recovers the body
// the template built, by reading what Send would have transmitted.
//
// The templates are pure functions of their arguments, so the body is captured
// by letting Send reach its relay branch against a URL that records the
// payload.
func captureBody(t *testing.T, _ *Service, send func()) string {
	t.Helper()
	rec := newRecorder(t)
	t.Setenv("AUTH_EMAIL_URL", rec.URL())
	t.Setenv("GATEWAY_SECRET", "test")
	send()
	return rec.Body()
}

func excerpt(body, marker string) string {
	i := strings.Index(body, marker)
	start := i - 120
	if start < 0 {
		start = 0
	}
	end := i + 120
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}

var _ = os.Getenv
