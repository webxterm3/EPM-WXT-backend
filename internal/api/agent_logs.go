package api

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	s3client "github.com/vsay/vsay-agent-backend/internal/s3"
	"github.com/vsay/vsay-agent-backend/internal/store"
)

// maxLogBatchBytes caps one upload. The agent batches to a few hundred
// kilobytes, so this is generous; its job is to stop a broken or hostile agent
// from making the backend allocate without limit.
const maxLogBatchBytes = 32 << 20

// logValidationLines is how many records are checked before the batch is
// stored. Parsing all of them would mean decompressing every byte the fleet
// sends just to re-compress it; checking the head catches a malformed sender
// without paying that on every upload.
const logValidationLines = 5

// LogIngestHandler receives system-log batches from agents and archives them.
type LogIngestHandler struct {
	store  store.Store
	logger *zap.Logger

	// warned keeps the "no archive destination" notice to one line per tenant
	// rather than one per upload from every machine in the fleet.
	warnedMu sync.Mutex
	warned   map[string]time.Time
}

// NewLogIngestHandler builds the agent log intake.
func NewLogIngestHandler(st store.Store, logger *zap.Logger) *LogIngestHandler {
	return &LogIngestHandler{store: st, logger: logger, warned: map[string]time.Time{}}
}

// Ingest handles POST /agent/logs.
//
// Auth is the agent's registration token, matching /agent/sign-cert — the same
// credential the agent already holds, so log shipping needs no second secret.
func (h *LogIngestHandler) Ingest(c *gin.Context) {
	machine, ok := h.authenticate(c)
	if !ok {
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxLogBatchBytes))
	if err != nil {
		// Too large is permanent: the agent must not retry this batch forever.
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "batch too large"})
		return
	}
	if len(body) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "empty batch"})
		return
	}

	if err := validateLogBatch(body); err != nil {
		// 400 tells the agent to drop this batch and move on rather than
		// wedging its bookmark on something we will never accept.
		h.logger.Warn("Log ingest: rejected a malformed batch",
			zap.String("machine", machine.Name),
			zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	records, _ := strconv.Atoi(c.GetHeader("X-Record-Count"))

	tenantCfg, err := h.store.GetTenantConfig(machine.TenantID)
	if err != nil || tenantCfg == nil || !tenantCfg.S3.Enabled {
		// Accepted and discarded, on purpose.
		//
		// Returning an error instead would make every agent retry forever,
		// never advance its bookmark, and burn its daily budget re-sending the
		// same batch — so a missing destination would escalate into every
		// machine in the fleet spinning. The loss is made loud here instead.
		h.warnNoDestination(machine)
		c.JSON(http.StatusOK, gin.H{
			"stored":  false,
			"reason":  "no archive destination is configured for this tenant",
			"records": records,
		})
		return
	}

	key := logArchiveKey(machine, time.Now().UTC())

	client, err := s3client.NewClient(tenantCfg.S3.Endpoint, tenantCfg.S3.Protocol,
		tenantCfg.S3.AccessKey, tenantCfg.S3.SecretKey, tenantCfg.S3.Region, tenantCfg.S3.Bucket)
	if err != nil {
		h.logger.Warn("Log ingest: storage client init failed",
			zap.String("machine", machine.Name), zap.Error(err))
		// 5xx: the agent should keep this batch and try again.
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "archive unavailable"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer cancel()

	// The body is already gzipped by the agent and is stored exactly as it
	// arrived, tagged so anything fetching it decompresses transparently.
	// Re-compressing here would spend CPU on every upload in the fleet to save
	// nothing.
	if err := client.UploadRaw(ctx, key, body, "application/x-ndjson", "gzip"); err != nil {
		h.logger.Warn("Log ingest: archive upload failed",
			zap.String("machine", machine.Name),
			zap.String("key", key), zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "archive write failed"})
		return
	}

	h.logger.Info("Log ingest: batch archived",
		zap.String("machine", machine.Name),
		zap.String("key", key),
		zap.Int("records", records),
		zap.Int("bytes", len(body)))

	c.JSON(http.StatusAccepted, gin.H{"stored": true, "key": key, "records": records})
}

// authenticate resolves the agent's bearer token to a machine.
func (h *LogIngestHandler) authenticate(c *gin.Context) (*store.Machine, bool) {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
		return nil, false
	}

	machine, err := h.store.GetMachineByRegistrationToken(strings.TrimPrefix(authHeader, "Bearer "))
	if err != nil || machine == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return nil, false
	}
	if machine.Revoked {
		// A revoked machine keeps no foothold anywhere, including here.
		c.JSON(http.StatusForbidden, gin.H{"error": "machine has been revoked"})
		return nil, false
	}
	return machine, true
}

// warnNoDestination logs the missing-archive problem at most hourly per tenant.
func (h *LogIngestHandler) warnNoDestination(machine *store.Machine) {
	h.warnedMu.Lock()
	defer h.warnedMu.Unlock()

	if last, ok := h.warned[machine.TenantID]; ok && time.Since(last) < time.Hour {
		return
	}
	h.warned[machine.TenantID] = time.Now()

	h.logger.Warn("Log ingest: DISCARDING agent logs — no archive destination is configured",
		zap.String("tenant", machine.TenantID),
		zap.String("machine", machine.Name),
		zap.String("remedy", "configure S3 storage in Settings, or disable log shipping on the agents"))
}

// validateLogBatch checks that the upload is the gzipped NDJSON we expect.
//
// It reads only the first few records: enough to catch a sender that is
// misconfigured or corrupting its output, without decompressing the fleet's
// entire log volume on the way past.
func validateLogBatch(body []byte) error {
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("body is not gzip: %w", err)
	}
	defer zr.Close()

	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)

	for i := 0; i < logValidationLines && sc.Scan(); i++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var probe struct {
			Timestamp time.Time `json:"ts"`
			Source    string    `json:"source"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return fmt.Errorf("record %d is not JSON: %w", i+1, err)
		}
		if probe.Source == "" {
			return fmt.Errorf("record %d has no source", i+1)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("batch is unreadable: %w", err)
	}
	return nil
}

// logArchiveKey builds the object key for a batch.
//
// It mirrors the recording layout — organisation/group/machine/user — so a
// machine's screen recordings and its system logs sit side by side in the
// bucket and one access policy covers both. The date path below that is what
// makes a lifecycle rule ("delete logs older than 90 days") expressible at all.
func logArchiveKey(machine *store.Machine, now time.Time) string {
	org := machine.OrgID
	if org == "" {
		// Machines registered before organisations existed carry only a tenant.
		org = machine.TenantID
	}

	group := "ungrouped"
	if len(machine.GroupIDs) > 0 && machine.GroupIDs[0] != "" {
		group = machine.GroupIDs[0]
	}

	// System logs belong to the machine, not to one session, so the user
	// segment names whoever the machine is assigned to.
	user := "shared"
	if len(machine.AllowedUsers) > 0 && machine.AllowedUsers[0] != "" {
		user = machine.AllowedUsers[0]
	}

	return strings.Join([]string{
		keySegment(org, "unknown-org"),
		keySegment(group, "ungrouped"),
		keySegment(machine.Name, machine.AgentID),
		keySegment(user, "shared"),
		"system-logs",
		now.Format("2006"),
		now.Format("01"),
		now.Format("02"),
		fmt.Sprintf("%s.ndjson.gz", now.Format("150405.000000000")),
	}, "/")
}
