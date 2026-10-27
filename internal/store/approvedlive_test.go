package store

import (
	"os"
	"strings"
	"testing"
)

// Completing a request records that the software went on. It does not
// withdraw the permission.
//
// Reading only "approved" meant the exception vanished the instant the
// endpoint reported success. The agent's enforcement pass consults the same
// list, so it then saw a bundle no exception covered and quarantined back
// off the machine the very thing it had just installed — on a timer, a few
// seconds after every successful install.
//
// The approval ends when ExpiresAt says so; that is the only thing that
// should end it.
func TestACompletedRequestStillCarriesItsApproval(t *testing.T) {
	src, err := os.ReadFile("mongodb.go")
	if err != nil {
		t.Fatal(err)
	}
	body := between(t, string(src), "func (m *MongoDB) ApprovedInstallsForMachine", "\nfunc ")

	if !strings.Contains(body, `"completed"`) {
		t.Error("the live-approvals query excludes completed requests, so an " +
			"approval is destroyed by its own success and the software is " +
			"quarantined again seconds after it is installed")
	}
	if !strings.Contains(body, `"approved"`) {
		t.Error("the live-approvals query no longer includes approved requests")
	}
	// Rejected and revoked must NOT be live.
	for _, dead := range []string{`"rejected"`, `"revoked"`} {
		if strings.Contains(body, dead) {
			t.Errorf("the live-approvals query includes %s", dead)
		}
	}
}

func between(t *testing.T, src, start, end string) string {
	t.Helper()
	i := strings.Index(src, start)
	if i < 0 {
		t.Fatalf("%s is gone", start)
	}
	rest := src[i+len(start):]
	if j := strings.Index(rest, end); j >= 0 {
		return rest[:j]
	}
	return rest
}
