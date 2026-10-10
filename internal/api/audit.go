package api

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// defaultReportDays is the window a compliance report covers when none is given.
const defaultReportDays = 30

// maxExportRows bounds a CSV download.
//
// An export is streamed, so memory is not the limit — but a file with millions
// of rows is one nobody opens, and an unbounded download against a shared
// database is a denial of service with a friendly name.
const maxExportRows = 500_000

// ListAuditEvents handles GET /api/audit-events.
//
// These are the endpoint-side events — remote sessions, policy changes,
// inventory reports. They are deliberately separate from the portal's own
// sign-in and user-management log, which lives in the auth service: merging
// two logs with different actors and retention would make both harder to trust.
func (h *Handler) ListAuditEvents(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	q := auditQueryFrom(c, tenantID)
	q.Limit, q.Skip = pagination(c, 50, 500)

	events, err := h.store.GetAuditLogs(q)
	if err != nil {
		h.logger.Warn("audit listing failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load events"})
		return
	}
	total, _ := h.store.CountAuditLogs(q)

	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"total":  total,
		// The whole taxonomy, so the filter UI offers every event the product
		// claims to record rather than only the ones that happen to exist in
		// this tenant's data today.
		"known_actions": knownActions(),
	})
}

// ExportAuditEvents handles GET /api/audit-events/export — a CSV download.
//
// CSV rather than a rendered document because this is the format somebody
// actually does something with: opens in a spreadsheet, feeds to a SIEM,
// attaches to an audit response. It streams, so a quarter's worth of events
// does not have to fit in memory first.
func (h *Handler) ExportAuditEvents(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	q := auditQueryFrom(c, tenantID)

	filename := fmt.Sprintf("epm-audit-%s.csv", time.Now().Format("2006-01-02"))
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)

	w := csv.NewWriter(c.Writer)
	defer w.Flush()

	_ = w.Write([]string{
		"timestamp", "action", "status", "actor", "actor_role",
		"machine", "agent_id", "resource", "resource_id", "ip_address", "details",
	})

	rows := 0
	err := h.store.StreamAuditLogs(c.Request.Context(), q, func(e *store.AuditLog) error {
		if rows >= maxExportRows {
			// Stopping is better than a file nobody can open. The truncation
			// is visible as a final row rather than silent.
			return errExportTruncated
		}
		rows++
		return w.Write([]string{
			e.Timestamp.UTC().Format(time.RFC3339),
			e.Action, e.Status, e.ActorName, e.ActorRole,
			e.MachineName, e.AgentID, e.Resource, e.ResourceID, e.IPAddress,
			encodeDetails(e.Details),
		})
	})

	if err == errExportTruncated {
		_ = w.Write([]string{"", "export.truncated", "", "", "", "", "", "", "", "",
			fmt.Sprintf("stopped at %d rows; narrow the date range or filter by action", maxExportRows)})
		return
	}
	if err != nil {
		h.logger.Warn("audit export failed", zap.Error(err))
		// The response has already begun, so the error cannot become a status
		// code. A final row says so, rather than the file simply stopping and
		// looking complete.
		_ = w.Write([]string{"", "export.failed", "", "", "", "", "", "", "", "", err.Error()})
	}
}

type exportTruncated struct{}

func (exportTruncated) Error() string { return "export truncated" }

var errExportTruncated = exportTruncated{}

// encodeDetails renders the details map for one CSV cell.
func encodeDetails(details map[string]any) string {
	if len(details) == 0 {
		return ""
	}
	// Sorted so two exports of the same data are byte-identical, which is what
	// makes them diffable and what stops a spreadsheet column order shifting
	// between downloads.
	keys := make([]string, 0, len(details))
	for k := range details {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, details[k]))
	}
	return strings.Join(parts, "; ")
}

// ComplianceReport handles GET /api/compliance-report.
//
// A summary over a window: what was recorded, who did it, what the fleet looks
// like, and — stated plainly — what this product does not yet record. The last
// part matters most: a compliance report that quietly omits a control nobody
// has built reads as evidence that the control exists.
func (h *Handler) ComplianceReport(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	q := auditQueryFrom(c, tenantID)
	if q.From.IsZero() {
		q.From = time.Now().AddDate(0, 0, -defaultReportDays)
	}
	if q.To.IsZero() {
		q.To = time.Now()
	}

	byAction, err := h.store.CountAuditByAction(q)
	if err != nil {
		h.logger.Warn("compliance report failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build the report"})
		return
	}
	byActor, _ := h.store.CountAuditByActor(q, 20)
	total, _ := h.store.CountAuditLogs(q)

	counts := make(map[string]int64, len(byAction))
	for _, row := range byAction {
		counts[row.Action] = row.Count
	}

	coverage, _ := h.store.GetInventoryCoverage(tenantID, inventoryStaleAfter)
	appPolicies, _ := h.store.GetAppPoliciesByTenant(tenantID)
	accessPolicies, _ := h.store.GetRemoteAccessPoliciesByTenant(tenantID)

	c.JSON(http.StatusOK, gin.H{
		"from":  q.From,
		"to":    q.To,
		"total": total,

		"by_action": byAction,
		"by_actor":  byActor,

		"remote_access": gin.H{
			"sessions_started": counts[store.AuditRemoteStarted],
			"sessions_ended":   counts[store.AuditRemoteStopped],
			"refused":          counts[store.AuditRemoteRefused],
		},
		"policy_changes": counts[store.AuditPolicyCreated] +
			counts[store.AuditPolicyUpdated] + counts[store.AuditPolicyDeleted],

		"application_control": gin.H{
			// Detected is a real figure today; the other three stay at zero
			// until enforcement exists, and the gaps section says so.
			"policy_violations_detected": counts[store.AuditAppPolicyViolation],
			"blocked":                    counts[store.AuditAppBlocked],
			"elevated":                   counts[store.AuditAppElevated],
			"allowed":                    counts[store.AuditAppAllowed],
		},

		"policies": gin.H{
			"application":    len(appPolicies),
			"remote_access":  len(accessPolicies),
			"enforcement_on": enforcementEnabled,
		},

		"inventory_coverage": coverage,

		// Named gaps, returned by the server so the report cannot be rendered
		// without them.
		"not_yet_recorded": notYetRecorded(),
	})
}

// notYetRecorded lists controls the product does not enforce yet, and
// therefore cannot produce events for.
//
// Returned with every report on purpose. An empty "applications blocked: 0" is
// indistinguishable from "nothing was blocked" unless the report says the
// control does not exist — and that difference is the whole value of the
// document.
func notYetRecorded() []string {
	return []string{
		"Application allowed / blocked / elevated — nothing is prevented from running. Policy violations are DETECTED when software is installed and reported above, but execution is not intercepted, so no run-time decision exists to record.",
		"Sudo command activity — sudo management is not implemented.",
		"Local administrator rights — least-privilege enforcement is not implemented.",
		"Just-in-time approvals — the request model exists but the workflow is not switched on.",
		"Portal sign-ins and user management are recorded separately by the authentication service and are not included here.",
	}
}

// knownActions is the full taxonomy, ordered for a filter menu.
func knownActions() []string {
	return []string{
		store.AuditRemoteStarted, store.AuditRemoteStopped, store.AuditRemoteRefused,
		store.AuditPolicyCreated, store.AuditPolicyUpdated, store.AuditPolicyDeleted,
		store.AuditPolicySynced,
		store.AuditInventoryReported,
		store.AuditAgentRegistered, store.AuditAgentUpdated,
		store.AuditAppPolicyViolation,
		store.AuditAppAllowed, store.AuditAppBlocked, store.AuditAppElevated,
		store.AuditJITRequested, store.AuditJITApproved, store.AuditJITRejected, store.AuditJITExpired,
		store.AuditSudoExecuted, store.AuditSudoDenied,
	}
}

// auditQueryFrom reads the filters off the request.
func auditQueryFrom(c *gin.Context, tenantID string) store.AuditQuery {
	q := store.AuditQuery{
		TenantID: tenantID,
		Actor:    strings.TrimSpace(c.Query("actor")),
		AgentID:  strings.TrimSpace(c.Query("agent_id")),
		Status:   strings.TrimSpace(c.Query("status")),
		Search:   strings.TrimSpace(c.Query("search")),
	}
	if actions := strings.TrimSpace(c.Query("actions")); actions != "" {
		for _, a := range strings.Split(actions, ",") {
			if trimmed := strings.TrimSpace(a); trimmed != "" {
				q.Actions = append(q.Actions, trimmed)
			}
		}
	}
	q.From = parseTimeQuery(c.Query("from"))
	q.To = parseTimeQuery(c.Query("to"))
	return q
}

// parseTimeQuery accepts a date or a full timestamp.
//
// A bare date is what a human types; it is read as the start of that day in
// UTC rather than rejected, because rejecting it would mean the filter only
// works for people who know the RFC.
func parseTimeQuery(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// pagination reads limit and skip with a ceiling.
func pagination(c *gin.Context, def, max int) (limit, skip int) {
	return paginationFrom(c.DefaultQuery("limit", ""), c.DefaultQuery("skip", ""), def, max)
}

// paginationFrom applies the bounds. Split out from the gin plumbing so the
// ceiling — the part that stops a caller asking for a million rows — is
// testable on its own.
func paginationFrom(rawLimit, rawSkip string, def, max int) (limit, skip int) {
	limit, _ = strconv.Atoi(rawLimit)
	skip, _ = strconv.Atoi(rawSkip)
	if limit <= 0 || limit > max {
		limit = def
	}
	if skip < 0 {
		skip = 0
	}
	return limit, skip
}
