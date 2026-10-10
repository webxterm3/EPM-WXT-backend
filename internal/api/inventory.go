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
// Agents scan every 12 hours, so a machine that has not reported in a day is
// either off or not reporting. The number matters because every count the
// portal shows is only as honest as the share of the fleet behind it.
const inventoryStaleAfter = 24 * time.Hour

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
