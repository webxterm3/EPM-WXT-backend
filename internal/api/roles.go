package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Role gates.
//
// These lived in logmanager.go until retention moved out to
// wxt-log-manager. They are kept because other routes use them — access
// requests among them — and deleting them with the file they happened to
// share would have taken those gates away with it.

// SuperAdminOnly aborts with 403 if the caller is not super_admin.
func (h *Handler) SuperAdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("role") != "super_admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "super_admin only"})
			return
		}
		c.Next()
	}
}

// AdminOrSuperAdmin aborts unless the caller is company_admin or super_admin.
func (h *Handler) AdminOrSuperAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetString("role")
		if role != "super_admin" && role != "company_admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin access required"})
			return
		}
		c.Next()
	}
}
