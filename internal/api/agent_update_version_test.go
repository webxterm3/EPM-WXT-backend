package api

import (
	"os"
	"path/filepath"
	"testing"
)

// The version offered for download and the version called "latest" must come
// from the same place.
//
// When they did not, the symptom was not a wrong number on a page: an update
// is offered whenever current != latest, so an agent would update, report the
// version it had genuinely installed, still fail to match the hand-set
// LATEST_AGENT_VERSION, and be offered the same update again on every check.
// It reads as an update that never applies, which is a far harder thing to
// diagnose than a version string being wrong.
func TestLatestVersionComesFromTheDeployedPackages(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_BINARIES_DIR", dir)

	writeVersion := func(v string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("the deployed version is what is advertised", func(t *testing.T) {
		writeVersion("1.0.0-rc4\n")
		// Set deliberately to something else: a stale override must not be
		// able to re-create the drift this file exists to remove.
		t.Setenv("LATEST_AGENT_VERSION", "1.2.1-rc3")

		if got := latestAgentVersion(); got != "1.0.0-rc4" {
			t.Errorf("advertised %q, but the deployed package is 1.0.0-rc4 — "+
				"agents on 1.0.0-rc4 would be offered an update they already have", got)
		}
	})

	t.Run("an env override still works where packages are served elsewhere", func(t *testing.T) {
		os.Remove(filepath.Join(dir, "VERSION"))
		t.Setenv("LATEST_AGENT_VERSION", "2.0.0")

		if got := latestAgentVersion(); got != "2.0.0" {
			t.Errorf("got %q, want the env override 2.0.0", got)
		}
	})

	t.Run("an empty VERSION file does not blank out the answer", func(t *testing.T) {
		writeVersion("   \n")
		t.Setenv("LATEST_AGENT_VERSION", "2.0.0")

		if got := latestAgentVersion(); got != "2.0.0" {
			t.Errorf("got %q — a truncated VERSION file must fall through to the "+
				"override, not report an empty version as latest", got)
		}
	})

	t.Run("nothing known means no update is offered", func(t *testing.T) {
		os.Remove(filepath.Join(dir, "VERSION"))
		t.Setenv("LATEST_AGENT_VERSION", "")

		if got := latestAgentVersion(); got != "unknown" {
			t.Errorf("got %q, want %q — CheckAgentUpdate only suppresses the "+
				"update prompt on exactly this string", got, "unknown")
		}
	})
}
