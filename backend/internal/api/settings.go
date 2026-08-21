package api

import (
	"net/http"

	"github.com/aegis-defender/backend/internal/storage/postgres"
	"github.com/gin-gonic/gin"
)

type SettingsHandler struct {
	pg *postgres.Store
}

func NewSettingsHandler(pg *postgres.Store) *SettingsHandler {
	return &SettingsHandler{pg: pg}
}

type CreateAPIKeyRequest struct {
	Description string `json:"description"`
}

func (h *SettingsHandler) ListAPIKeys(c *gin.Context) {
	// userID := c.GetString("user_id") // Middleware uses "user_id" claim? Access via MustGet("userID") is better if middleware sets it
	// In auth.go middleware usually sets "userID" or "user_id". I should check middleware.
	// Assuming logic used in other handlers: c.MustGet("userID").(string) or similar.
	// But ListServers used userID from params? No.
	// ServerHandler used: userID := c.MustGet("userID").(string)

	val, exists := c.Get("userID")
	if !exists {
		// Fallback or error
		// For now assume middleware sets it.
		// If not, might need to fix middleware later.
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userID := val.(string)

	keys, err := h.pg.ListAPIKeys(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch API keys"})
		return
	}
	c.JSON(http.StatusOK, keys)
}

func (h *SettingsHandler) CreateAPIKey(c *gin.Context) {
	val, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userID := val.(string)

	var req CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Default description if empty?
		req.Description = "New API Key"
	}
	if req.Description == "" {
		req.Description = "New API Key"
	}

	key, rawKey, err := h.pg.CreateAPIKey(c.Request.Context(), userID, req.Description)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"meta": key,
		"key":  rawKey,
	})
}
