package grpc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// agentRepo is where the agent source sits when both repositories are checked
// out side by side.
const agentRepo = "../../../wxt-agent"

// The agent and the backend describe the same inventory report with two
// separate structs in two separate repositories, and nothing makes them agree.
// A renamed json key does not fail to compile — encoding/json leaves the field
// at its zero value, so the reports keep arriving and quietly lose a field.
// These read the agent's source directly.

func readAgentFile(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join(agentRepo, rel)
	data, err := os.ReadFile(path) // #nosec G304 -- fixed test fixture path
	if err != nil {
		t.Skipf("agent source not available at %s — this contract is unverified in this checkout", path)
	}
	return string(data)
}

func TestInventoryDiscriminatorMatchesTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/appinventory/report.go")

	want := `ReportDiscriminator = "` + AppInventoryDiscriminator + `"`
	if !strings.Contains(src, want) {
		t.Fatalf("the agent no longer declares %s — inventory reports would be ignored and the fleet would show no software", want)
	}
}

// Every field the backend reads must exist as a json tag on the agent's
// structs. A mismatch loses that field silently.
func TestEveryFieldWeReadExistsOnTheAgent(t *testing.T) {
	reportSrc := readAgentFile(t, "internal/appinventory/report.go")
	appSrc := readAgentFile(t, "internal/appinventory/inventory.go")

	check := func(v any, src, what string) {
		typ := reflect.TypeOf(v)
		for i := 0; i < typ.NumField(); i++ {
			tag := typ.Field(i).Tag.Get("json")
			name := strings.Split(tag, ",")[0]
			if name == "" || name == "-" {
				continue
			}
			if !strings.Contains(src, `json:"`+name+`"`) &&
				!strings.Contains(src, `json:"`+name+`,omitempty"`) {
				t.Errorf("we read %q from the %s but the agent has no such json tag — that field would silently arrive empty", name, what)
			}
		}
	}

	check(inventoryReport{}, reportSrc, "report envelope")
	check(inventoryApp{}, appSrc, "application record")
}

// The agent's chunk size must stay within what we accept, or complete scans
// start being rejected in the field.
func TestAgentChunkSizeIsWithinOurLimit(t *testing.T) {
	src := readAgentFile(t, "internal/appinventory/report.go")

	const marker = "DefaultChunkSize = "
	i := strings.Index(src, marker)
	if i < 0 {
		t.Fatal("the agent no longer declares DefaultChunkSize")
	}
	rest := src[i+len(marker):]
	end := strings.IndexAny(rest, "\n\t ")
	if end < 0 {
		t.Fatal("could not read the agent's chunk size")
	}

	size, err := strconv.Atoi(strings.TrimSpace(rest[:end]))
	if err != nil {
		t.Fatalf("could not parse the agent's chunk size %q: %v", rest[:end], err)
	}
	if size > maxInventoryChunkApps {
		t.Errorf("the agent chunks at %d but we reject anything over %d — every report would be dropped",
			size, maxInventoryChunkApps)
	}
}

// A report the agent produces must be one we accept. This is the end-to-end
// shape check: the agent's own json, through our validator.
func TestAnAgentShapedReportPassesValidation(t *testing.T) {
	// Byte-for-byte what the agent marshals for a single-chunk scan.
	raw := `{"snapshot_id":"4f2a1c9b8e7d6a5b4c3d2e1f0a9b8c7d","chunk":0,"chunks":1,
	         "collected_at":"2026-10-06T10:00:00Z","os":"darwin","agent_version":"1.4.0",
	         "apps":[{"id":"bundle:com.google.chrome","name":"Google Chrome"}]}`

	var r inventoryReport
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := r.validate(); err != nil {
		t.Fatalf("a report in the agent's own shape was rejected: %v", err)
	}
	if !r.mayMarkRemoved() {
		t.Error("a complete, clean single-chunk scan was not allowed to reconcile removals")
	}
}
