package logmanager

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// expiryStore is the slice of store.Store that expiry needs.
//
// It is declared here rather than using store.Store directly so this logic can
// be tested against a small fake. store.Store has well over a hundred methods;
// requiring all of them to test a retention loop is how retention ends up
// untested, which is how it ends up silently not deleting anything.
type expiryStore interface {
	GetLogsOlderThan(before time.Time, limit int) ([]*store.LogEntry, error)
	DeleteLogsByIDs(ids []primitive.ObjectID) (int64, error)
	GetSessionsOlderThan(before time.Time, limit int) ([]*store.Session, error)
	DeleteSessionsByIDs(ids []primitive.ObjectID) (int64, error)
	GetAuditLogsOlderThan(before time.Time, limit int) ([]*store.AuditLog, error)
	DeleteAuditLogsByIDs(ids []primitive.ObjectID) (int64, error)
}

// expiredBatch is one page of records past the retention cutoff.
type expiredBatch struct {
	logs      []*store.LogEntry
	sessions  []*store.Session
	auditLogs []*store.AuditLog
}

func (b expiredBatch) empty() bool {
	return len(b.logs) == 0 && len(b.sessions) == 0 && len(b.auditLogs) == 0
}

// full reports whether any collection filled its page, meaning there is more
// behind it.
func (b expiredBatch) full(limit int) bool {
	return len(b.logs) >= limit || len(b.sessions) >= limit || len(b.auditLogs) >= limit
}

// sweepCounts reports what a sweep removed.
type sweepCounts struct {
	LogsDeleted      int64
	SessionsDeleted  int64
	AuditLogsDeleted int64
}

func (c sweepCounts) total() int64 {
	return c.LogsDeleted + c.SessionsDeleted + c.AuditLogsDeleted
}

// beforeDelete is called with each batch before anything is removed. Returning
// an error stops the sweep with that batch still in the database, which is what
// makes "archive, then delete" safe: nothing is dropped that was not stored.
type beforeDelete func(ctx context.Context, batch expiredBatch) error

// maxSweepPasses bounds one sweep.
//
// The loop re-queries after deleting, so a delete that reports success without
// removing anything would otherwise spin forever holding the database. At a
// thousand records a pass this still covers millions of rows per run, and the
// next run picks up whatever is left.
const maxSweepPasses = 5000

// sweepExpired removes everything older than cutoff.
//
// Each of the three collections is paged independently. An earlier version
// drove the whole loop from the machine-log page and stopped as soon as that
// page came back short — which meant sessions and audit logs were only ever
// deleted as a side effect of there being expired machine logs, and never at
// all once that collection ran dry. Retention silently stopped applying to two
// of the three things it claims to cover.
func sweepExpired(ctx context.Context, s expiryStore, cutoff time.Time, limit int, before beforeDelete) (sweepCounts, error) {
	var counts sweepCounts

	for pass := 0; pass < maxSweepPasses; pass++ {
		if err := ctx.Err(); err != nil {
			return counts, err
		}

		batch, err := readExpired(s, cutoff, limit)
		if err != nil {
			return counts, err
		}
		if batch.empty() {
			return counts, nil
		}

		if before != nil {
			if err := before(ctx, batch); err != nil {
				// Deliberately returns before deleting: the records stay in the
				// database and the next run tries again. Keeping them costs
				// storage; deleting them after a failed archive loses them.
				return counts, err
			}
		}

		removed, err := deleteBatch(s, batch)
		counts.LogsDeleted += removed.LogsDeleted
		counts.SessionsDeleted += removed.SessionsDeleted
		counts.AuditLogsDeleted += removed.AuditLogsDeleted
		if err != nil {
			return counts, err
		}

		if removed.total() == 0 {
			// Nothing was removed although records matched. Continuing would
			// re-read the same rows forever.
			return counts, fmt.Errorf("expiry made no progress: %d records matched but none were deleted",
				len(batch.logs)+len(batch.sessions)+len(batch.auditLogs))
		}

		if !batch.full(limit) {
			return counts, nil
		}
	}

	return counts, fmt.Errorf("expiry stopped after %d passes; the remainder is left for the next run", maxSweepPasses)
}

// readExpired fetches one page from each collection.
func readExpired(s expiryStore, cutoff time.Time, limit int) (expiredBatch, error) {
	var batch expiredBatch
	var err error

	if batch.logs, err = s.GetLogsOlderThan(cutoff, limit); err != nil {
		return batch, fmt.Errorf("read expired logs: %w", err)
	}
	if batch.sessions, err = s.GetSessionsOlderThan(cutoff, limit); err != nil {
		return batch, fmt.Errorf("read expired sessions: %w", err)
	}
	if batch.auditLogs, err = s.GetAuditLogsOlderThan(cutoff, limit); err != nil {
		return batch, fmt.Errorf("read expired audit logs: %w", err)
	}
	return batch, nil
}

// deleteBatch removes one batch, returning what it managed to remove.
//
// A failure in one collection does not skip the others: a broken sessions
// index should not also stop audit logs from expiring.
func deleteBatch(s expiryStore, batch expiredBatch) (sweepCounts, error) {
	var counts sweepCounts
	var firstErr error

	if len(batch.logs) > 0 {
		ids := make([]primitive.ObjectID, len(batch.logs))
		for i, l := range batch.logs {
			ids[i] = l.ID
		}
		n, err := s.DeleteLogsByIDs(ids)
		counts.LogsDeleted = n
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("delete logs: %w", err)
		}
	}

	if len(batch.sessions) > 0 {
		ids := make([]primitive.ObjectID, len(batch.sessions))
		for i, sess := range batch.sessions {
			ids[i] = sess.ID
		}
		n, err := s.DeleteSessionsByIDs(ids)
		counts.SessionsDeleted = n
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("delete sessions: %w", err)
		}
	}

	if len(batch.auditLogs) > 0 {
		ids := make([]primitive.ObjectID, len(batch.auditLogs))
		for i, a := range batch.auditLogs {
			ids[i] = a.ID
		}
		n, err := s.DeleteAuditLogsByIDs(ids)
		counts.AuditLogsDeleted = n
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("delete audit logs: %w", err)
		}
	}

	return counts, firstErr
}
