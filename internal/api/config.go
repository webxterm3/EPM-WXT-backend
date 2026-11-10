package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	s3client "github.com/vsay/vsay-agent-backend/internal/s3"
	"github.com/vsay/vsay-agent-backend/internal/store"
)

// GET /api/config/s3 — returns the S3 config for the caller's tenant
func (h *Handler) GetS3Config(c *gin.Context) {
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

	// Never expose the secret key in the response
	resp := gin.H{
		"enabled":        cfg.S3.Enabled,
		"endpoint":       cfg.S3.Endpoint,
		"protocol":       cfg.S3.Protocol,
		"access_key":     cfg.S3.AccessKey,
		"secret_key_set": cfg.S3.SecretKey != "",
		"bucket":         cfg.S3.Bucket,
		"region":         cfg.S3.Region,
	}
	c.JSON(http.StatusOK, resp)
}

// POST /api/config/s3 — upserts S3 config for the caller's tenant (admin only)
func (h *Handler) SaveS3Config(c *gin.Context) {
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

	var body struct {
		Enabled   bool   `json:"enabled"`
		Endpoint  string `json:"endpoint"`
		Protocol  string `json:"protocol"`
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"` // empty means "keep existing"
		Bucket    string `json:"bucket"`
		Region    string `json:"region"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Load existing config so we can preserve the secret key if not provided
	existing, err := h.store.GetTenantConfig(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load existing config"})
		return
	}

	secretKey := body.SecretKey
	if secretKey == "" {
		secretKey = existing.S3.SecretKey // keep existing secret key
	}

	cfg := &store.TenantConfig{
		TenantID: tenantID,
		// Carried over explicitly: this upsert replaces the whole document, so
		// anything not copied here would be silently wiped by an unrelated
		// settings save.
		LogShipping: existing.LogShipping,
		S3: store.S3Config{
			Enabled:   body.Enabled,
			Endpoint:  body.Endpoint,
			Protocol:  body.Protocol,
			AccessKey: body.AccessKey,
			SecretKey: secretKey,
			Bucket:    body.Bucket,
			Region:    body.Region,
		},
	}

	if err := h.store.UpsertTenantConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save config"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "S3 configuration saved"})
}

// TestS3Config reports whether the session-recording bucket can be reached.
//
// POST /api/config/s3/test
//
// The archive destination has had a test button since it was built; this one
// did not, so the only way to find out that recordings were going nowhere
// was to run a session, end it, and look for a recording that never arrived.
func (h *Handler) TestS3Config(c *gin.Context) {
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

	var body struct {
		Endpoint  string `json:"endpoint"`
		Protocol  string `json:"protocol"`
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"` // empty means "use the stored one"
		Bucket    string `json:"bucket"`
		Region    string `json:"region"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// An empty secret means "test what is saved", exactly as saving does.
	//
	// The form shows the stored key as dots, so a test typed over an
	// existing configuration sends none — and testing with an empty secret
	// would fail every time, telling somebody their working setup is broken.
	secretKey := body.SecretKey
	if secretKey == "" {
		existing, err := h.store.GetTenantConfig(tenantID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load existing config"})
			return
		}
		secretKey = existing.S3.SecretKey
	}

	if body.Bucket == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a bucket is required"})
		return
	}

	client, err := s3client.NewClient(body.Endpoint, body.Protocol,
		body.AccessKey, secretKey, body.Region, body.Bucket)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "failed", "error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	if err := client.TestConnection(ctx); err != nil {
		// 502 and the real message. The reason is S3's, and it is the only
		// thing that tells anybody which of a dozen settings is wrong.
		c.JSON(http.StatusBadGateway, gin.H{"status": "failed", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
