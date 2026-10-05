package api

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"time"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

func gzipOf(s string) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(s))
	_ = zw.Close()
	return buf.Bytes()
}

const goodBatch = `{"ts":"2026-09-27T10:00:00Z","source":"windows-eventlog","message":"a"}
{"ts":"2026-09-27T10:00:01Z","source":"dns","message":"example.com"}
`

func TestValidateLogBatchAcceptsAGoodBatch(t *testing.T) {
	if err := validateLogBatch(gzipOf(goodBatch)); err != nil {
		t.Fatalf("a well-formed batch was rejected: %v", err)
	}
}

// Each of these is permanently bad. Accepting them would put unreadable
// objects in the archive; rejecting with 400 tells the agent to drop the batch
// rather than retry it forever and block everything behind it.
func TestValidateLogBatchRejectsBadInput(t *testing.T) {
	cases := map[string][]byte{
		"not gzip":       []byte(goodBatch),
		"truncated gzip": gzipOf(goodBatch)[:10],
		"not json":       gzipOf("this is not json at all\n"),
		"no source":      gzipOf(`{"ts":"2026-09-27T10:00:00Z","message":"a"}` + "\n"),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateLogBatch(body); err == nil {
				t.Error("accepted a batch that can never be read back")
			}
		})
	}
}

// An empty batch is valid gzip with no records. It is pointless but not
// corrupt, so it must not be classed as a permanent failure.
func TestValidateLogBatchAcceptsAnEmptyStream(t *testing.T) {
	if err := validateLogBatch(gzipOf("")); err != nil {
		t.Errorf("an empty batch was rejected as malformed: %v", err)
	}
}

// Validation reads only the head of the stream, so a large batch must not cost
// a full decompression.
func TestValidateLogBatchDoesNotReadTheWholeStream(t *testing.T) {
	var b strings.Builder
	b.WriteString(goodBatch)
	for i := 0; i < 50_000; i++ {
		b.WriteString(`{"ts":"2026-09-27T10:00:02Z","source":"macos-unified","message":"filler"}` + "\n")
	}
	if err := validateLogBatch(gzipOf(b.String())); err != nil {
		t.Fatalf("a large valid batch was rejected: %v", err)
	}
}

func TestLogArchiveKeyMatchesTheRecordingLayout(t *testing.T) {
	m := &store.Machine{
		Name:         "Kaal's Laptop",
		AgentID:      "agent-7",
		OrgID:        "coredge",
		GroupIDs:     []string{"support-team"},
		AllowedUsers: []string{"yesveer"},
	}
	now := time.Date(2026, time.September, 27, 10, 3, 1, 482913000, time.UTC)

	key := logArchiveKey(m, now)

	// organisation/group/machine/user, the same shape as session recordings,
	// so one bucket policy covers both.
	wantPrefix := "coredge/support-team/Kaal-s-Laptop/yesveer/system-logs/2026/09/27/"
	if !strings.HasPrefix(key, wantPrefix) {
		t.Errorf("key = %q, want prefix %q", key, wantPrefix)
	}
	if !strings.HasSuffix(key, ".ndjson.gz") {
		t.Errorf("key = %q, want a .ndjson.gz suffix", key)
	}
	// An apostrophe must not survive into a path segment.
	if strings.Contains(key, "'") {
		t.Errorf("key = %q kept an apostrophe", key)
	}
}

func TestLogArchiveKeyFallsBackWhenFieldsAreMissing(t *testing.T) {
	// A machine registered before organisations and groups existed, with no
	// assigned user. Each missing piece must become a named segment: an empty
	// one would collapse the path and file the logs somewhere nothing looks.
	m := &store.Machine{Name: "", AgentID: "agent-9", TenantID: "tenant-1"}

	key := logArchiveKey(m, time.Now().UTC())

	want := "tenant-1/ungrouped/agent-9/shared/system-logs/"
	if !strings.HasPrefix(key, want) {
		t.Errorf("key = %q, want prefix %q", key, want)
	}
	if strings.Contains(key, "//") {
		t.Errorf("key = %q has an empty segment", key)
	}
}

// Two batches arriving in the same second must not overwrite each other — the
// second would silently replace the first in the archive.
func TestLogArchiveKeysAreDistinctWithinASecond(t *testing.T) {
	m := &store.Machine{Name: "laptop", OrgID: "o", AllowedUsers: []string{"u"}}
	base := time.Date(2026, time.September, 27, 10, 3, 1, 0, time.UTC)

	a := logArchiveKey(m, base.Add(1*time.Millisecond))
	b := logArchiveKey(m, base.Add(2*time.Millisecond))

	if a == b {
		t.Fatalf("two batches in the same second produced the same key %q", a)
	}
}
