package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// inventoryStaleAfter is when a machine's last report stops being current
// enough to reason about.
//
// Agents scan every 24 hours, so this must be comfortably MORE than a day: at
// exactly 24h a machine reporting perfectly on schedule would be called stale
// in the minutes before each scan, and the coverage notice would permanently
// accuse a healthy fleet of not reporting. 36 hours means one missed scan is
// tolerated and a second one is not.
//
// The number matters because every count the portal shows is only as honest as
// the share of the fleet behind it.
const inventoryStaleAfter = 36 * time.Hour

// GetMachineApplications lists the software installed on one machine.
// GET /api/machines/:agent_id/applications
func (h *Handler) GetMachineApplications(c *gin.Context) {
	machine, ok := h.authorizeMachineRead(c)
	if !ok {
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	skip, _ := strconv.Atoi(c.DefaultQuery("skip", "0"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	q := store.InventoryQuery{
		Search:         c.Query("search"),
		Source:         c.Query("source"),
		IncludeRemoved: c.Query("include_removed") == "true",
		Limit:          limit,
		Skip:           skip,
	}

	apps, err := h.store.GetInstalledAppsByMachine(machine.ID, q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load applications"})
		return
	}
	total, _ := h.store.CountInstalledAppsByMachine(machine.ID, q)

	// The last scan is returned alongside the list so the UI can tell "this
	// machine has no software" apart from "this machine has never reported" —
	// which look identical otherwise and are the most common support question
	// any inventory product gets.
	scan, _ := h.store.GetLatestInventoryScan(machine.AgentID)

	c.JSON(http.StatusOK, gin.H{
		"applications": apps,
		"total":        total,
		"last_scan":    scan,
	})
}

// RequestMachineInventoryScan asks one machine to re-scan its software now.
// POST /api/machines/:agent_id/applications/scan
//
// The response says only that the request was delivered. It cannot say the
// scan succeeded, because the agent reports through the ordinary inventory
// channel some seconds later — and claiming otherwise would have the UI show
// a stale list under the word "done".
func (h *Handler) RequestMachineInventoryScan(c *gin.Context) {
	machine, ok := h.authorizeMachineRead(c)
	if !ok {
		return
	}

	if !h.agentManager.IsAgentConnected(machine.AgentID) {
		// 409, not 500: nothing is broken. The machine is off or offline, and
		// the caller needs to be told which of the two situations this is.
		c.JSON(http.StatusConflict, gin.H{
			"error": "This machine is offline. Its software list will refresh on its own when the agent reconnects.",
		})
		return
	}

	if err := h.agentManager.SendInventoryScan(machine.AgentID); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "Could not reach the agent: " + err.Error()})
		return
	}

	h.record(c, auditEntry{
		Action: store.AuditInventoryScanRequested, Resource: "machine",
		ResourceID: machine.AgentID,
		Machine:    machine,
	})

	c.JSON(http.StatusAccepted, gin.H{
		"requested": true,
		"message":   "Scan requested. The list updates when the agent reports back.",
	})
}

// RequestFleetInventoryScan asks every connected machine in the tenant to
// re-scan its software now.
// POST /api/applications/scan
//
// Offline machines are counted, not failed. A fleet always has some machines
// asleep, and an error because one laptop in a bag did not answer would make
// the button useless on any real estate — while hiding the number would make
// the result look complete when it is not.
func (h *Handler) RequestFleetInventoryScan(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	// Scanning the whole fleet is an administrator's action: it is cheap per
	// machine and noisy across hundreds of them.
	if role := c.GetString("role"); role != "company_admin" && role != "super_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only an administrator can scan the whole fleet"})
		return
	}

	machines, err := h.store.GetMachinesByTenantID(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load machines"})
		return
	}

	var requested, offline int
	var failed []string
	for _, m := range machines {
		if !h.agentManager.IsAgentConnected(m.AgentID) {
			offline++
			continue
		}
		if err := h.agentManager.SendInventoryScan(m.AgentID); err != nil {
			// One unreachable agent costs that machine, not the sweep.
			failed = append(failed, m.Name)
			continue
		}
		requested++
	}

	h.record(c, auditEntry{
		Action: store.AuditInventoryScanRequested, Resource: "fleet",
		ResourceID: tenantID,
		Details: map[string]any{
			"requested": requested, "offline": offline, "failed": len(failed),
		},
	})

	c.JSON(http.StatusAccepted, gin.H{
		"requested": requested,
		"offline":   offline,
		"failed":    failed,
		"total":     len(machines),
	})
}

// GetAppCatalog lists the distinct applications across the tenant's fleet.
// GET /api/applications/catalog
func (h *Handler) GetAppCatalog(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	skip, _ := strconv.Atoi(c.DefaultQuery("skip", "0"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	entries, total, err := h.store.GetAppCatalog(tenantID, store.CatalogQuery{
		Search: c.Query("search"), Limit: limit, Skip: skip,
	})
	if err != nil {
		h.logger.Warn("application catalog failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build the application catalog"})
		return
	}

	// Coverage travels with the catalog rather than being a separate call the
	// UI might not make. "412 applications" means something different when 17
	// of your 100 machines have never reported.
	coverage, _ := h.store.GetInventoryCoverage(tenantID, inventoryStaleAfter)

	c.JSON(http.StatusOK, gin.H{
		"applications": entries,
		"total":        total,
		"coverage":     coverage,
	})
}

// GetMachinesWithApp lists which machines carry one catalog entry.
// GET /api/applications/machines?name=&publisher=
func (h *Handler) GetMachinesWithApp(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}
	name := c.Query("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	skip, _ := strconv.Atoi(c.DefaultQuery("skip", "0"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	installs, total, err := h.store.GetMachinesWithApp(tenantID, name, c.Query("publisher"), limit, skip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load machines"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"installs": installs, "total": total})
}

// authorizeMachineRead resolves :agent_id and checks the caller may read it.
//
// Extracted because every per-machine endpoint repeats it, and a read
// endpoint that forgets it is a cross-tenant data leak rather than a bug.
func (h *Handler) authorizeMachineRead(c *gin.Context) (*store.Machine, bool) {
	agentID := c.Param("agent_id")
	userID, _ := primitive.ObjectIDFromHex(c.GetString("user_id"))
	username := c.GetString("username")
	role := c.GetString("role")

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return nil, false
	}

	authorized := machine.OwnerID == userID || role == "company_admin" || role == "super_admin"
	if !authorized {
		for _, u := range machine.AllowedUsers {
			if u == username {
				authorized = true
				break
			}
		}
	}
	if !authorized {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
		return nil, false
	}
	return machine, true
}
