package logmanager

import (
	"context"
	"time"

	"github.com/vsay/vsay-agent-backend/internal/store"
	"go.uber.org/zap"
)

// reconcileBatchSize is smaller than the archival batch size: this path runs
// hourly on a live database and should not hold it for long.
const reconcileBatchSize = 500

// Reconciler runs on a schedule and triggers archival/deletion when due.
type Reconciler struct {
	manager  *Manager
	store    store.Store
	logger   *zap.Logger
	interval time.Duration
}

func NewReconciler(m *Manager, s store.Store, logger *zap.Logger) *Reconciler {
	return &Reconciler{
		manager:  m,
		store:    s,
		logger:   logger,
		interval: 1 * time.Hour,
	}
}

// Run starts the reconcile loop and blocks until ctx is cancelled.
func (r *Reconciler) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	r.reconcile(ctx)

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Log management reconciler stopped")
			return
		case <-ticker.C:
			r.reconcile(ctx)
		}
	}
}

func (r *Reconciler) reconcile(ctx context.Context) {
	cfg, err := r.store.GetLogManagementConfig()
	if err != nil {
		r.logger.Warn("reconciler: load config failed", zap.Error(err))
		return
	}
	if cfg.RetentionDays <= 0 {
		return
	}

	if cfg.ArchiveEnabled && cfg.ArchiveEveryDays > 0 {
		due := cfg.NextArchiveAt == nil || time.Now().After(*cfg.NextArchiveAt)
		if due {
			r.logger.Info("Scheduled log archival triggered")
			if err := r.manager.RunArchival(ctx, "auto"); err != nil {
				r.logger.Error("Scheduled log archival failed", zap.Error(err))
			}
		}
		return
	}

	// Archiving disabled, or enabled without a frequency — expired records are
	// still removed, so "retention" means the same thing either way.
	cutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)
	r.deleteExpired(ctx, cutoff)
}

// deleteExpired removes everything past the cutoff without archiving it.
//
// It shares sweepExpired with the archival path rather than repeating the
// loop. The two copies had drifted into the same bug — both stopped as soon as
// the machine-log page came back short, so sessions and audit logs outlived
// their retention period indefinitely.
func (r *Reconciler) deleteExpired(ctx context.Context, cutoff time.Time) {
	counts, err := sweepExpired(ctx, r.store, cutoff, reconcileBatchSize, nil)
	if err != nil {
		r.logger.Warn("Expired log cleanup did not finish", zap.Error(err))
	}

	if counts.total() > 0 {
		r.logger.Info("Expired records deleted",
			zap.Int64("logs", counts.LogsDeleted),
			zap.Int64("sessions", counts.SessionsDeleted),
			zap.Int64("audit_logs", counts.AuditLogsDeleted))
	}
}
