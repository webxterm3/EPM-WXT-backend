package grpc

import (
	"os"
	"strings"
	"testing"
)

// The duplicate check must not be written against the admin search box.
//
// GetAccessRequestsFiltered's search covers who asked and which machine —
// requester_username, requester_email, machine_name. It matches no field
// naming the software, by design: those are what an administrator types.
//
// Passing an application name to it therefore LOOKS like a lookup and returns
// nothing. A duplicate check written that way answers "no" every time, so a
// mounted disk image raises a fresh request on every refresh and the
// approver's queue fills with the same ask until the real ones are lost in
// it. It was written that way once; this is here so it is not again.
func TestTheDuplicateCheckDoesNotSearchByApplicationName(t *testing.T) {
	handler := readFile(t, "internal/grpc/installrequest.go")
	dedup := between(t, handler,
		"func (s *AgentServer) hasPendingInstallRequest", "\nfunc ")

	if strings.Contains(dedup, "GetAccessRequestsFiltered") {
		t.Error("the duplicate check calls GetAccessRequestsFiltered, whose search " +
			"matches no application field — it will never find the pending request " +
			"it is looking for, and every refresh will raise another one")
	}
	if !strings.Contains(dedup, "HasPendingInstallRequest") {
		t.Error("the duplicate check no longer asks the store about pending installs")
	}
}

// And the reason it cannot be used: the search really does not cover the
// application. If that ever changes this test fails, which is the moment to
// reconsider — not silently inherit an assumption that has stopped holding.
func TestTheAdminSearchStillCoversOnlyPeopleAndMachines(t *testing.T) {
	query := between(t, readFile(t, "internal/store/mongodb.go"),
		"func (m *MongoDB) GetAccessRequestsFiltered", "\nfunc ")

	for _, field := range []string{"requester_username", "requester_email", "machine_name"} {
		if !strings.Contains(query, field) {
			t.Errorf("the admin search no longer covers %s", field)
		}
	}
	if strings.Contains(query, "app_install") || strings.Contains(query, "title") {
		t.Error("the admin search now covers the application too — the separate " +
			"HasPendingInstallRequest query may no longer be needed")
	}
}

// The focused query matches the machine and the exact name.
func TestThePendingInstallQueryIsNarrowedToTheMachineAndTheName(t *testing.T) {
	query := between(t, readFile(t, "internal/store/mongodb.go"),
		"func (m *MongoDB) HasPendingInstallRequest", "\nfunc ")

	for _, want := range []string{
		`"status":`,                        // only what is still waiting
		`"machine_agent_id":`,              // another machine's request is not this one's
		`"asks.app_install.applications":`, // the software actually asked for
		`"^"`,                              // anchored: "Docker" must not match "Docker Desktop"
	} {
		if !strings.Contains(query, want) {
			t.Errorf("the pending-install query no longer narrows on %s", want)
		}
	}
}

func readFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile("../../" + rel)
	if err != nil {
		t.Fatalf("could not read %s: %v", rel, err)
	}
	return string(b)
}

// between returns the source from start up to the next top-level declaration,
// so a test about one function cannot be satisfied by its neighbour.
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
