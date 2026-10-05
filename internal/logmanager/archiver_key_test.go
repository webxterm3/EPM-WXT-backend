package logmanager

import (
	"strings"
	"testing"
	"time"
)

// Batches within one run take milliseconds, while the key's timestamp has
// one-second resolution. Identical keys meant each upload overwrote the last
// while every batch was still deleted from the database — so all but the final
// batch was silently lost.
func TestArchiveKeysAreUniqueWithinARun(t *testing.T) {
	now := time.Date(2026, time.September, 27, 10, 3, 1, 0, time.UTC)
	runID := "68f2a1c4e9b70a1234567890"

	seen := map[string]bool{}
	for seq := 0; seq < 50; seq++ {
		// Same second for every batch, which is the realistic case.
		key := BuildArchiveKey("", now, runID, seq)
		if seen[key] {
			t.Fatalf("batch %d reused key %q — it would overwrite an earlier batch", seq, key)
		}
		seen[key] = true
	}
}

// Two runs that start in the same second must not collide either.
func TestArchiveKeysAreUniqueAcrossRuns(t *testing.T) {
	now := time.Date(2026, time.September, 27, 10, 3, 1, 0, time.UTC)

	first := BuildArchiveKey("", now, "68f2a1c4e9b70a1234567890", 0)
	second := BuildArchiveKey("", now, "68f2a1c4e9b70a0987654321", 0)

	if first == second {
		t.Fatalf("two runs in the same second produced the same key %q", first)
	}
}

func TestArchiveKeyShape(t *testing.T) {
	now := time.Date(2026, time.September, 27, 10, 3, 1, 0, time.UTC)
	key := BuildArchiveKey("my-prefix/", now, "abc123", 7)

	if !strings.HasPrefix(key, "my-prefix/archive-20260927T100301Z-abc123-007") {
		t.Errorf("key = %q", key)
	}
	if !strings.HasSuffix(key, ".ndjson.gz") {
		t.Errorf("key = %q, want a .ndjson.gz suffix", key)
	}
	// A trailing slash on the prefix must not produce an empty path segment.
	if strings.Contains(key, "//") {
		t.Errorf("key = %q has an empty segment", key)
	}
}

func TestArchiveKeyFallsBackWhenUnidentified(t *testing.T) {
	// A missing prefix or run id must still yield a usable, non-colliding key
	// rather than one starting with a separator.
	key := BuildArchiveKey("", time.Now(), "", 0)

	if strings.HasPrefix(key, "/") {
		t.Errorf("key = %q starts with a separator", key)
	}
	if !strings.HasPrefix(key, "vsay-logs/") {
		t.Errorf("key = %q, want the default prefix", key)
	}
}
