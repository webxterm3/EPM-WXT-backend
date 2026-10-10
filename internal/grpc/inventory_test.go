package grpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

func validReport() inventoryReport {
	return inventoryReport{
		SnapshotID: "a1b2c3d4e5f60718", Chunk: 0, Chunks: 1,
		CollectedAt: time.Now().UTC(), OS: "darwin",
		Apps: []inventoryApp{{ID: "bundle:com.example", Name: "Example"}},
	}
}

// The snapshot id reaches a database filter, so it is restricted to characters
// that cannot mean anything there. The chunk position has to be coherent or
// the reconcile logic cannot tell which report completes a scan.
func TestReportValidation(t *testing.T) {
	if err := validReport().validate(); err != nil {
		t.Fatalf("a well-formed report was rejected: %v", err)
	}

	cases := map[string]func(*inventoryReport){
		"no snapshot id":        func(r *inventoryReport) { r.SnapshotID = "" },
		"blank snapshot id":     func(r *inventoryReport) { r.SnapshotID = "   " },
		"oversized snapshot id": func(r *inventoryReport) { r.SnapshotID = strings.Repeat("a", 65) },
		"id with a dollar":      func(r *inventoryReport) { r.SnapshotID = "abc$ne" },
		"id with a dot":         func(r *inventoryReport) { r.SnapshotID = "abc.def" },
		"id with a brace":       func(r *inventoryReport) { r.SnapshotID = "{abc}" },
		"zero chunks":           func(r *inventoryReport) { r.Chunks = 0 },
		"negative chunk":        func(r *inventoryReport) { r.Chunk = -1 },
		"chunk past the end":    func(r *inventoryReport) { r.Chunk, r.Chunks = 3, 3 },
		"absurd app count": func(r *inventoryReport) {
			r.Apps = make([]inventoryApp, maxInventoryChunkApps+1)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validReport()
			mutate(&r)
			if err := r.validate(); err == nil {
				t.Error("accepted a report that cannot be reconciled safely")
			}
		})
	}
}

// This is the rule that stops one crashed agent from looking like a wiped
// machine. Both conditions matter and both are easy to lose in a refactor.
func TestOnlyACompleteCleanScanMayMarkSoftwareRemoved(t *testing.T) {
	cases := []struct {
		name         string
		chunk        int
		chunks       int
		collectError string
		want         bool
	}{
		{"single clean chunk", 0, 1, "", true},
		{"final clean chunk", 2, 3, "", true},

		// A partial picture says nothing about what is missing.
		{"first of three", 0, 3, "", false},
		{"middle of three", 1, 3, "", false},

		// A scan that errored has holes in it. The entries it did not report
		// are missing because of the error, not because anybody uninstalled
		// anything.
		{"final but collector failed", 2, 3, "context deadline exceeded", false},
		{"single chunk but collector failed", 0, 1, "registry hive unreadable", false},
		{"whitespace-only error is not an error", 0, 1, "   ", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := inventoryReport{Chunk: c.chunk, Chunks: c.chunks, CollectError: c.collectError}
			if got := r.mayMarkRemoved(); got != c.want {
				t.Errorf("mayMarkRemoved() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestToInstalledAppsPreservesWhatPolicyMatchesOn(t *testing.T) {
	installed := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	r := inventoryReport{Apps: []inventoryApp{{
		ID: `registry:user:corp\yesveer:chrome`, Name: "Google Chrome", Version: "120.0",
		Publisher: "Google LLC", InstallPath: `C:\Users\yesveer\Chrome`,
		ExePath: `C:\Users\yesveer\Chrome\chrome.exe`, BundleID: "",
		Scope: "user", OSUser: `CORP\yesveer`, Source: "registry",
		InstalledAt: installed, Arch: "x64",
	}}}

	apps := r.toInstalledApps()
	if len(apps) != 1 {
		t.Fatalf("got %d apps", len(apps))
	}
	got := apps[0]

	if got.AppKey != `registry:user:corp\yesveer:chrome` {
		t.Errorf("AppKey = %q — this is what reconciliation keys on", got.AppKey)
	}
	// Each of these is something a policy rule can match against; losing any
	// silently narrows what an operator can express.
	if got.Name != "Google Chrome" || got.Publisher != "Google LLC" {
		t.Errorf("name/publisher lost: %+v", got)
	}
	if got.ExePath != `C:\Users\yesveer\Chrome\chrome.exe` {
		t.Errorf("ExePath = %q — path rules match the executable", got.ExePath)
	}
	if got.Scope != "user" || got.OSUser != `CORP\yesveer` {
		t.Errorf("scope/owner lost: %+v", got)
	}
	if got.InstalledAt == nil || !got.InstalledAt.Equal(installed) {
		t.Errorf("InstalledAt = %v", got.InstalledAt)
	}
}

// A record with no identity cannot be reconciled against the next scan, and
// one with no name cannot be displayed or matched. Storing either creates a
// row nothing can ever act on.
func TestUnusableRecordsAreDropped(t *testing.T) {
	r := inventoryReport{Apps: []inventoryApp{
		{ID: "", Name: "No Identity"},
		{ID: "x", Name: ""},
		{ID: "  ", Name: "Blank Identity"},
		{ID: "y", Name: "   "},
		{ID: "good", Name: "Keeper"},
	}}

	apps := r.toInstalledApps()
	if len(apps) != 1 {
		t.Fatalf("kept %d records, want only the usable one: %+v", len(apps), apps)
	}
	if apps[0].Name != "Keeper" {
		t.Errorf("kept %q", apps[0].Name)
	}
}

// An app with no install date must not be stored as if it were installed at
// the zero time, which would sort to the beginning of every list.
func TestMissingInstallDateStaysAbsent(t *testing.T) {
	apps := inventoryReport{Apps: []inventoryApp{{ID: "a", Name: "A"}}}.toInstalledApps()
	if apps[0].InstalledAt != nil {
		t.Errorf("InstalledAt = %v, want nil", apps[0].InstalledAt)
	}
}

// The agent and backend envelopes are separate structs in separate
// repositories; this is the shape the agent actually sends.
func TestAgentEnvelopeDecodes(t *testing.T) {
	raw := `{"snapshot_id":"a1b2c3","chunk":0,"chunks":2,"collected_at":"2026-10-06T10:00:00Z",
	         "os":"windows","agent_version":"1.2.3","collect_error":"",
	         "apps":[{"id":"registry:machine:chrome","name":"Google Chrome","version":"120.0",
	                  "publisher":"Google LLC","exe_path":"C:\\chrome.exe","scope":"machine",
	                  "source":"registry","arch":"x64"}]}`

	var r inventoryReport
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("the agent's envelope did not decode: %v", err)
	}
	if r.SnapshotID != "a1b2c3" || r.Chunks != 2 || r.OS != "windows" {
		t.Errorf("envelope fields wrong: %+v", r)
	}
	if len(r.Apps) != 1 || r.Apps[0].ExePath != `C:\chrome.exe` {
		t.Errorf("app fields wrong: %+v", r.Apps)
	}
	if r.final() {
		t.Error("chunk 0 of 2 reported itself as final")
	}
}

// The event must not be called "blocked": nothing was blocked. Naming it so
// would read as evidence that execution was prevented, which it was not — and
// that distinction is the whole reason the audit trail is worth trusting.
func TestViolationEventIsNamedAsDetectionNotEnforcement(t *testing.T) {
	if store.AuditAppPolicyViolation == store.AuditAppBlocked {
		t.Fatal("detection and enforcement share an action name")
	}
	if strings.Contains(store.AuditAppPolicyViolation, "blocked") {
		t.Errorf("%q reads as though execution was prevented", store.AuditAppPolicyViolation)
	}
	if !strings.Contains(store.AuditAppPolicyViolation, "violation") {
		t.Errorf("%q does not describe what actually happened", store.AuditAppPolicyViolation)
	}
}

// Deleting a machine and kicking its agent is a routine operation. It used to
// produce an ERROR with a stack trace in the production log, which buries the
// failures someone actually needs to see.
func TestRoutineDisconnectsAreNotErrors(t *testing.T) {
	expected := []error{
		context.Canceled,
		io.EOF,
		status.Error(codes.Canceled, "context canceled"),
		status.Error(codes.Unavailable, "transport is closing"),
		fmt.Errorf("wrapped: %w", context.Canceled),
	}
	for _, err := range expected {
		if !isExpectedStreamEnd(err) {
			t.Errorf("%v was treated as a fault", err)
		}
	}

	// Real faults must still reach Error level.
	faults := []error{
		errors.New("decode failure"),
		status.Error(codes.Internal, "server blew up"),
		status.Error(codes.DataLoss, "stream corrupted"),
	}
	for _, err := range faults {
		if isExpectedStreamEnd(err) {
			t.Errorf("%v was dismissed as a routine disconnect", err)
		}
	}
}
