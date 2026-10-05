package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// defaultLogDailyBudgetMB bounds a machine's daily upload when the operator has
// not chosen a number.
//
// Whole-system log collection is open-ended: a machine logging an error in a
// loop can produce gigabytes in an hour. Defaulting to unlimited would put that
// on somebody's bandwidth and storage bill before anybody noticed.
const defaultLogDailyBudgetMB = 256

// GetLogShippingConfig handles GET /api/config/log-shipping.
func (h *Handler) GetLogShippingConfig(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	cfg, err := h.store.GetTenantConfig(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load config"})
		return
	}

	// Collection without a destination silently discards everything, so the
	// UI is told whether one exists rather than having to infer it.
	c.JSON(http.StatusOK, gin.H{
		"settings":             cfg.LogShipping,
		"archive_configured":   cfg.S3.Enabled,
		"default_daily_budget": defaultLogDailyBudgetMB,
	})
}

// SaveLogShippingConfig handles POST /api/config/log-shipping.
//
// Saving also pushes the settings to every connected agent in the tenant, so a
// change takes effect within seconds instead of at the next agent restart.
func (h *Handler) SaveLogShippingConfig(c *gin.Context) {
	role := c.GetString("role")
	if role != "super_admin" && role != "company_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin access required"})
		return
	}

	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	var body store.LogShippingConfig
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if body.DailyBudgetMB == 0 {
		body.DailyBudgetMB = defaultLogDailyBudgetMB
	}

	existing, err := h.store.GetTenantConfig(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load existing config"})
		return
	}

	cfg := &store.TenantConfig{
		TenantID:    tenantID,
		S3:          existing.S3, // see SaveS3Config: the upsert replaces the document
		LogShipping: body,
	}
	if err := h.store.UpsertTenantConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save config"})
		return
	}

	pushed, total := h.pushLogShippingToAgents(tenantID, body)

	c.JSON(http.StatusOK, gin.H{
		"message":            "Log collection settings saved",
		"agents_updated":     pushed,
		"agents_total":       total,
		"archive_configured": existing.S3.Enabled,
	})
}

// pushLogShippingToAgents sends the settings to every connected agent in the
// tenant, returning how many took them and how many machines exist.
//
// Offline machines are not an error: they pick the settings up on their next
// registration. The counts are returned so the UI can say "12 of 40 updated"
// instead of implying the whole fleet changed.
func (h *Handler) pushLogShippingToAgents(tenantID string, cfg store.LogShippingConfig) (pushed, total int) {
	machines, err := h.store.GetMachinesByTenantID(tenantID)
	if err != nil {
		h.logger.Warn("Log shipping: could not list machines to push settings",
			zap.String("tenant", tenantID), zap.Error(err))
		return 0, 0
	}

	payload, err := json.Marshal(cfg.AgentPayload())
	if err != nil {
		h.logger.Error("Log shipping: could not encode settings", zap.Error(err))
		return 0, len(machines)
	}

	for _, m := range machines {
		if m.AgentID == "" || m.Revoked {
			continue
		}
		if err := h.agentManager.SendLogShipConfig(m.AgentID, string(payload)); err != nil {
			continue // offline; it will be applied on reconnect
		}
		pushed++
	}
	return pushed, len(machines)
}
