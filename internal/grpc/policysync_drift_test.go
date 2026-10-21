package grpc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// "Sync Now" is a file the menu bar writes, a discriminator the agent sends
// and a handler here. None of the three fails to compile when another is
// renamed: the button would simply stop working, and nothing could tell.
//
// The menu bar is the worst-placed of the three to notice — it writes a file
// and has no way to learn whether anything ever answered.
func TestThePolicySyncDiscriminatorMatchesTheAgent(t *testing.T) {
	src := readAgentSource(t, "internal/agent/apppolicy.go")

	want := `PolicyRequestDiscriminator = "` + PolicyRequestDiscriminator + `"`
	if !strings.Contains(src, want) {
		t.Errorf("the agent no longer sends %q — the Sync Now button would go quiet "+
			"with nothing reporting a fault", PolicyRequestDiscriminator)
	}
}

// The agent must still ASK. If the loop that watches for the request file goes
// away, the file is written for ever and nothing reads it.
func TestTheAgentStillWatchesForASyncRequest(t *testing.T) {
	src := readAgentSource(t, "internal/agent/apppolicy.go")

	for _, want := range []string{
		"agentstatus.TakeSyncRequest()",
		"SendStatusUpdate(PolicyRequestDiscriminator",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the agent no longer does %q, so a pressed button does nothing", want)
		}
	}

	started := readAgentSource(t, "internal/agent/agent.go")
	if !strings.Contains(started, "go a.syncRequestLoop(ctx)") {
		t.Error("syncRequestLoop is no longer started — the request file would pile up unread")
	}
}

func readAgentSource(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join(agentRepo, rel)
	data, err := os.ReadFile(path) // #nosec G304 -- fixed test fixture path
	if err != nil {
		t.Skipf("agent source not available at %s — this contract is unverified in this checkout", path)
	}
	return string(data)
}
