package logmanager

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// fakeExpiryStore holds three collections in memory and serves them by page.
type fakeExpiryStore struct {
	logs      []*store.LogEntry
	sessions  []*store.Session
	auditLogs []*store.AuditLog

	deleteLogsErr     error
	deleteSessionsErr error
	// deletesSilentlyFail simulates a delete that reports success without
	// removing anything — the shape that turns a retry loop into a hang.
	deletesSilentlyFail bool
	// reportZeroDeleted simulates a delete that removes nothing and says so.
	reportZeroDeleted bool
}

func (f *fakeExpiryStore) GetLogsOlderThan(_ time.Time, limit int) ([]*store.LogEntry, error) {
	return f.logs[:min(limit, len(f.logs))], nil
}

func (f *fakeExpiryStore) GetSessionsOlderThan(_ time.Time, limit int) ([]*store.Session, error) {
	return f.sessions[:min(limit, len(f.sessions))], nil
}

func (f *fakeExpiryStore) GetAuditLogsOlderThan(_ time.Time, limit int) ([]*store.AuditLog, error) {
	return f.auditLogs[:min(limit, len(f.auditLogs))], nil
}

func (f *fakeExpiryStore) DeleteLogsByIDs(ids []primitive.ObjectID) (int64, error) {
	if f.deleteLogsErr != nil {
		return 0, f.deleteLogsErr
	}
	if f.reportZeroDeleted {
		return 0, nil
	}
	if f.deletesSilentlyFail {
		return int64(len(ids)), nil // reports success, removes nothing
	}
	f.logs = f.logs[min(len(ids), len(f.logs)):]
	return int64(len(ids)), nil
}

func (f *fakeExpiryStore) DeleteSessionsByIDs(ids []primitive.ObjectID) (int64, error) {
	if f.deleteSessionsErr != nil {
		return 0, f.deleteSessionsErr
	}
	if f.deletesSilentlyFail {
		return int64(len(ids)), nil
	}
	f.sessions = f.sessions[min(len(ids), len(f.sessions)):]
	return int64(len(ids)), nil
}

func (f *fakeExpiryStore) DeleteAuditLogsByIDs(ids []primitive.ObjectID) (int64, error) {
	if f.deletesSilentlyFail {
		return int64(len(ids)), nil
	}
	f.auditLogs = f.auditLogs[min(len(ids), len(f.auditLogs)):]
	return int64(len(ids)), nil
}

func makeLogs(n int) []*store.LogEntry {
	out := make([]*store.LogEntry, n)
	for i := range out {
		out[i] = &store.LogEntry{ID: primitive.NewObjectID()}
	}
	return out
}

func makeSessions(n int) []*store.Session {
	out := make([]*store.Session, n)
	for i := range out {
		out[i] = &store.Session{ID: primitive.NewObjectID()}
	}
	return out
}

func makeAuditLogs(n int) []*store.AuditLog {
	out := make([]*store.AuditLog, n)
	for i := range out {
		out[i] = &store.AuditLog{ID: primitive.NewObjectID()}
	}
	return out
}

func sweep(t *testing.T, f *fakeExpiryStore, limit int, before beforeDelete) sweepCounts {
	t.Helper()
	counts, err := sweepExpired(context.Background(), f, time.Now(), limit, before)
	if err != nil {
		t.Fatalf("sweepExpired: %v", err)
	}
	return counts
}

func TestSweepDeletesEverythingPastTheCutoff(t *testing.T) {
	f := &fakeExpiryStore{
		logs:      makeLogs(2500),
		sessions:  makeSessions(1200),
		auditLogs: makeAuditLogs(300),
	}

	counts := sweep(t, f, 1000, nil)

	if counts.LogsDeleted != 2500 {
		t.Errorf("LogsDeleted = %d, want 2500", counts.LogsDeleted)
	}
	if counts.SessionsDeleted != 1200 {
		t.Errorf("SessionsDeleted = %d, want 1200", counts.SessionsDeleted)
	}
	if counts.AuditLogsDeleted != 300 {
		t.Errorf("AuditLogsDeleted = %d, want 300", counts.AuditLogsDeleted)
	}
	if len(f.logs)+len(f.sessions)+len(f.auditLogs) != 0 {
		t.Errorf("%d logs, %d sessions, %d audit logs survived the sweep",
			len(f.logs), len(f.sessions), len(f.auditLogs))
	}
}

// The failure that made retention a no-op for two of the three collections:
// with no expired machine logs, nothing else was ever deleted either.
func TestSweepDeletesSessionsWhenThereAreNoExpiredLogs(t *testing.T) {
	f := &fakeExpiryStore{
		logs:      nil,
		sessions:  makeSessions(40),
		auditLogs: makeAuditLogs(15),
	}

	counts := sweep(t, f, 1000, nil)

	if counts.SessionsDeleted != 40 {
		t.Errorf("SessionsDeleted = %d, want 40 — sessions must expire on their own schedule", counts.SessionsDeleted)
	}
	if counts.AuditLogsDeleted != 15 {
		t.Errorf("AuditLogsDeleted = %d, want 15", counts.AuditLogsDeleted)
	}
}

// The same failure in its subtler form: the collections are different sizes, so
// stopping when the smallest runs out strands the rest.
func TestSweepDrainsCollectionsOfDifferentSizes(t *testing.T) {
	f := &fakeExpiryStore{
		logs:      makeLogs(10),
		sessions:  makeSessions(4500),
		auditLogs: makeAuditLogs(1),
	}

	counts := sweep(t, f, 1000, nil)

	if counts.SessionsDeleted != 4500 {
		t.Errorf("SessionsDeleted = %d, want 4500 — the short log page must not end the sweep", counts.SessionsDeleted)
	}
	if len(f.sessions) != 0 {
		t.Errorf("%d sessions were stranded", len(f.sessions))
	}
}

func TestSweepOnEmptyDatabaseDoesNothing(t *testing.T) {
	f := &fakeExpiryStore{}
	counts := sweep(t, f, 1000, nil)
	if counts.total() != 0 {
		t.Errorf("deleted %d records from an empty database", counts.total())
	}
}

// "Archive, then delete" is only safe if a failed archive stops the delete.
// Deleting anyway is unrecoverable data loss.
func TestFailedArchiveLeavesTheRecordsInPlace(t *testing.T) {
	f := &fakeExpiryStore{logs: makeLogs(100), sessions: makeSessions(50)}

	_, err := sweepExpired(context.Background(), f, time.Now(), 1000,
		func(context.Context, expiredBatch) error {
			return errors.New("bucket unreachable")
		})

	if err == nil {
		t.Fatal("a failed archive was reported as success")
	}
	if len(f.logs) != 100 || len(f.sessions) != 50 {
		t.Errorf("records were deleted after the archive failed: %d logs, %d sessions remain",
			len(f.logs), len(f.sessions))
	}
}

// Every record handed to the archive must be one that is then deleted, and vice
// versa — otherwise the archive and the database disagree about what happened.
func TestArchiveSeesExactlyWhatIsDeleted(t *testing.T) {
	f := &fakeExpiryStore{
		logs:      makeLogs(1500),
		sessions:  makeSessions(700),
		auditLogs: makeAuditLogs(20),
	}

	var archivedLogs, archivedSessions, archivedAudit int
	counts := sweep(t, f, 1000, func(_ context.Context, b expiredBatch) error {
		archivedLogs += len(b.logs)
		archivedSessions += len(b.sessions)
		archivedAudit += len(b.auditLogs)
		return nil
	})

	if int64(archivedLogs) != counts.LogsDeleted {
		t.Errorf("archived %d logs but deleted %d", archivedLogs, counts.LogsDeleted)
	}
	if int64(archivedSessions) != counts.SessionsDeleted {
		t.Errorf("archived %d sessions but deleted %d", archivedSessions, counts.SessionsDeleted)
	}
	if int64(archivedAudit) != counts.AuditLogsDeleted {
		t.Errorf("archived %d audit logs but deleted %d", archivedAudit, counts.AuditLogsDeleted)
	}
}

// A delete that reports success without removing anything leaves a full page
// coming back every time, so the sweep would re-read it forever and hold the
// database while it did. It has to give up and let the next run try.
func TestSweepTerminatesWhenDeletesSilentlyFail(t *testing.T) {
	// The page stays full, which is what makes the loop continue.
	f := &fakeExpiryStore{logs: makeLogs(100), deletesSilentlyFail: true}

	done := make(chan error, 1)
	go func() {
		_, err := sweepExpired(context.Background(), f, time.Now(), 100, nil)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a sweep that removed nothing reported success")
		}
		if !strings.Contains(err.Error(), "passes") {
			t.Errorf("error = %v, want it to say the sweep was cut short", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the sweep did not terminate")
	}
}

// The other shape of the same hazard: the store reports zero deleted while
// still returning matching records. That is detectable immediately.
func TestSweepStopsWhenDeletesReportNothingRemoved(t *testing.T) {
	f := &fakeExpiryStore{logs: makeLogs(50), reportZeroDeleted: true}

	_, err := sweepExpired(context.Background(), f, time.Now(), 1000, nil)
	if err == nil {
		t.Fatal("a sweep that deleted nothing reported success")
	}
	if !strings.Contains(err.Error(), "no progress") {
		t.Errorf("error = %v, want it to name the lack of progress", err)
	}
}

func TestSweepReportsDeleteFailures(t *testing.T) {
	f := &fakeExpiryStore{
		logs:     makeLogs(10),
		sessions: makeSessions(10),
	}
	f.deleteLogsErr = errors.New("index missing")

	// A failure in one collection must not silently stop the others: a broken
	// sessions index should not also keep audit logs forever.
	counts, err := sweepExpired(context.Background(), f, time.Now(), 1000, nil)
	if err == nil {
		t.Fatal("a delete failure was reported as success")
	}
	if counts.SessionsDeleted != 10 {
		t.Errorf("SessionsDeleted = %d, want 10 — the other collections should still be swept", counts.SessionsDeleted)
	}
}

func TestSweepHonoursCancellation(t *testing.T) {
	f := &fakeExpiryStore{logs: makeLogs(10_000)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := sweepExpired(ctx, f, time.Now(), 100, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled — a shutdown must not be blocked by a long sweep", err)
	}
}
