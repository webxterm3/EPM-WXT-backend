package logmanager

import (
	"context"
	"fmt"
	"time"

	"github.com/vsay/vsay-agent-backend/internal/store"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

const batchSize = 1000

// Manager orchestrates log archival and deletion.
type Manager struct {
	store  store.Store
	logger *zap.Logger
}

func NewManager(s store.Store, logger *zap.Logger) *Manager {
	return &Manager{store: s, logger: logger}
}

// RunArchival archives logs older than the configured retention period and removes them from DB.
// trigger is "auto" or "manual".
func (m *Manager) RunArchival(ctx context.Context, trigger string) error {
	cfg, err := m.store.GetLogManagementConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.RetentionDays <= 0 {
		return fmt.Errorf("retention_days not set — nothing to archive")
	}

	cutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)

	run := &store.ArchiveRun{
		StartedAt:   time.Now(),
		Status:      "running",
		StorageType: cfg.StorageType,
		Trigger:     trigger,
	}
	if err := m.store.CreateArchiveRun(run); err != nil {
		return fmt.Errorf("create archive run: %w", err)
	}

	m.logger.Info("Log archival started",
		zap.String("trigger", trigger),
		zap.Time("cutoff", cutoff),
		zap.String("storage", cfg.StorageType),
		zap.String("run_id", run.ID.Hex()))

	var (
		logsArchived     int64
		sessionsArchived int64
		bytesArchived    int64
		archiveKeys      []string
		runErr           string
	)

	// ── Determine archiver ────────────────────────────────────────────────────
	//
	// A nil archiver means "delete without archiving", which is the documented
	// behaviour when no destination is configured: logs still stop
	// accumulating past the retention period.
	var arch Archiver
	if cfg.ArchiveEnabled && cfg.StorageType != "" && len(cfg.StorageCredsEnc) > 0 {
		arch, err = NewArchiver(cfg.StorageType, cfg.StorageCredsEnc)
		if err != nil {
			runErr = err.Error()
			m.finishRun(run.ID, "failed", runErr, 0, 0, 0, 0, nil)
			return fmt.Errorf("build archiver: %w", err)
		}
	}

	// ── Archive each batch, then delete it ────────────────────────────────────
	var archiveBatch beforeDelete
	if arch != nil {
		runID := run.ID.Hex()
		seq := 0
		archiveBatch = func(ctx context.Context, batch expiredBatch) error {
			data, err := MarshalArchive(batch.logs, batch.sessions, batch.auditLogs)
			if err != nil {
				// Returning stops the sweep with this batch still in the
				// database. The previous version logged and carried on into
				// the delete, which threw the records away unarchived.
				return fmt.Errorf("encode archive batch: %w", err)
			}

			key := BuildArchiveKey(prefixFor(cfg), time.Now(), runID, seq)
			if err := arch.Upload(ctx, key, data); err != nil {
				return fmt.Errorf("upload archive batch: %w", err)
			}

			seq++
			archiveKeys = append(archiveKeys, key)
			bytesArchived += int64(len(data))
			logsArchived += int64(len(batch.logs))
			sessionsArchived += int64(len(batch.sessions))
			return nil
		}
	}

	counts, sweepErr := sweepExpired(ctx, m.store, cutoff, batchSize, archiveBatch)
	if sweepErr != nil {
		runErr = sweepErr.Error()
	}
	logsDeleted := counts.LogsDeleted

	m.logger.Info("Log expiry swept",
		zap.Int64("logs_deleted", counts.LogsDeleted),
		zap.Int64("sessions_deleted", counts.SessionsDeleted),
		zap.Int64("audit_logs_deleted", counts.AuditLogsDeleted))

	// ── Update config: last/next archive timestamps ──────────────────────────
	now := time.Now()
	cfg.LastArchiveAt = &now
	if cfg.ArchiveEveryDays > 0 {
		next := now.AddDate(0, 0, cfg.ArchiveEveryDays)
		cfg.NextArchiveAt = &next
	}
	if err := m.store.UpsertLogManagementConfig(cfg); err != nil {
		m.logger.Warn("archive: failed to persist last/next archive timestamps", zap.Error(err))
	}

	status := "success"
	if runErr != "" {
		// "partial" means some records did make it out. Counting only machine
		// logs would report a run that expired thousands of sessions as a
		// total failure.
		if counts.total() > 0 {
			status = "partial"
		} else {
			status = "failed"
		}
	}

	m.finishRun(run.ID, status, runErr, logsArchived, sessionsArchived, logsDeleted, bytesArchived, archiveKeys)
	m.logger.Info("Log archival finished",
		zap.String("status", status),
		zap.Int64("logs_archived", logsArchived),
		zap.Int64("logs_deleted", logsDeleted),
		zap.Int64("bytes_archived", bytesArchived))

	if runErr != "" {
		return fmt.Errorf("archival completed with error: %s", runErr)
	}
	return nil
}

// prefixFor returns the storage path prefix for a config. The archivers apply
// their own per-backend prefix from the credentials, so this stays empty
// unless a config-level one is introduced.
func prefixFor(_ *store.LogManagementConfig) string { return "" }

// TestConnection verifies that the external storage configuration is reachable.
func (m *Manager) TestConnection(ctx context.Context, storageType string, encCreds []byte) error {
	arch, err := NewArchiver(storageType, encCreds)
	if err != nil {
		return err
	}
	return arch.TestConnection(ctx)
}

// RestoreFromRun re-inserts archived records from a previous ArchiveRun back into MongoDB.
func (m *Manager) RestoreFromRun(ctx context.Context, runID primitive.ObjectID) (int, int, error) {
	run, err := m.store.GetArchiveRunByID(runID)
	if err != nil {
		return 0, 0, fmt.Errorf("run not found: %w", err)
	}
	// Older runs recorded a single key; runs that span several batches record
	// one per object. Both are read so a run from before that change is still
	// restorable.
	keys := run.ArchiveKeys
	if len(keys) == 0 && run.ArchiveKey != "" {
		keys = []string{run.ArchiveKey}
	}
	if len(keys) == 0 {
		return 0, 0, fmt.Errorf("run has no archive key — nothing to restore")
	}

	cfg, err := m.store.GetLogManagementConfig()
	if err != nil {
		return 0, 0, fmt.Errorf("load config: %w", err)
	}
	if !cfg.ArchiveEnabled || cfg.StorageType == "" {
		return 0, 0, fmt.Errorf("archive storage not configured")
	}

	arch, err := NewArchiver(cfg.StorageType, cfg.StorageCredsEnc)
	if err != nil {
		return 0, 0, fmt.Errorf("build archiver: %w", err)
	}

	var (
		logs      []*store.LogEntry
		sessions  []*store.Session
		auditLogs []*store.AuditLog
	)
	for _, key := range keys {
		data, err := arch.Download(ctx, key)
		if err != nil {
			return 0, 0, fmt.Errorf("download archive %s: %w", key, err)
		}
		l, sess, a, err := UnmarshalArchive(data)
		if err != nil {
			return 0, 0, fmt.Errorf("parse archive %s: %w", key, err)
		}
		logs = append(logs, l...)
		sessions = append(sessions, sess...)
		auditLogs = append(auditLogs, a...)
	}

	var restoredLogs, restoredSessions int
	for _, l := range logs {
		l.ID = primitive.NilObjectID
		if err := m.store.CreateLog(l); err == nil {
			restoredLogs++
		}
	}
	for _, s := range sessions {
		s.ID = primitive.NilObjectID
		if err := m.store.CreateSession(s); err == nil {
			restoredSessions++
		}
	}
	restoredAuditLogs := 0
	for _, a := range auditLogs {
		a.ID = primitive.NilObjectID
		if err := m.store.CreateAuditLog(a); err == nil {
			restoredAuditLogs++
		}
	}

	m.logger.Info("Log restore completed",
		zap.String("run_id", runID.Hex()),
		zap.Int("logs", restoredLogs),
		zap.Int("sessions", restoredSessions),
		zap.Int("audit_logs", restoredAuditLogs))

	return restoredLogs, restoredSessions, nil
}

func (m *Manager) finishRun(id primitive.ObjectID, status, errMsg string, logsArchived, sessionsArchived, logsDeleted, bytesArchived int64, archiveKeys []string) {
	if err := m.store.UpdateArchiveRunFinished(id, status, errMsg, logsArchived, sessionsArchived, logsDeleted, bytesArchived, archiveKeys); err != nil {
		m.logger.Warn("failed to update archive run", zap.Error(err))
	}
}
