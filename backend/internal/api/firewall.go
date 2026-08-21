package api

import (
	"net/http"

	"github.com/aegis-defender/backend/internal/storage/postgres"
	"github.com/gin-gonic/gin"
)

type FirewallHandler struct {
	pg *postgres.Store
}

func NewFirewallHandler(pg *postgres.Store) *FirewallHandler {
	return &FirewallHandler{pg: pg}
}

func (h *FirewallHandler) ListBlocks(c *gin.Context) {
	userID := c.GetString("userID")
	blocks, err := h.pg.ListBlockedIPs(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch firewall block rules"})
		return
	}
	if blocks == nil {
		blocks = []postgres.BlockedIP{}
	}
	c.JSON(http.StatusOK, gin.H{"blocks": blocks})
}

type CreateBlockRequest struct {
	ServerID *string `json:"server_id"`
	IP       string  `json:"ip" binding:"required"`
	Reason   string  `json:"reason"`
}

func (h *FirewallHandler) CreateBlock(c *gin.Context) {
	userID := c.GetString("userID")
	var req CreateBlockRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	reason := req.Reason
	if reason == "" {
		reason = "Manual block via Aegis Firewall"
	}

	// 1. Create blocked IP record
	block, err := h.pg.CreateBlockedIP(c.Request.Context(), userID, req.ServerID, req.IP, reason)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save block rule"})
		return
	}

	// 2. Queue block command
	if req.ServerID != nil && *req.ServerID != "" && *req.ServerID != "all" {
		_ = h.pg.CreateCommand(c.Request.Context(), *req.ServerID, "block_ip", req.IP)
	} else {
		// Global block: dispatch to all user servers
		servers, err := h.pg.ListServers(c.Request.Context(), userID)
		if err == nil {
			for _, s := range servers {
				_ = h.pg.CreateCommand(c.Request.Context(), s.ID, "block_ip", req.IP)
			}
		}
	}

	c.JSON(http.StatusCreated, block)
}

func (h *FirewallHandler) RemoveBlock(c *gin.Context) {
	userID := c.GetString("userID")
	blockID := c.Param("id")

	block, err := h.pg.RemoveBlockedIP(c.Request.Context(), userID, blockID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove block rule"})
		return
	}
	if block == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Block rule not found"})
		return
	}

	// Queue unblock command
	if block.ServerID != nil && *block.ServerID != "" {
		_ = h.pg.CreateCommand(c.Request.Context(), *block.ServerID, "unblock_ip", block.IP)
	} else {
		// Global unblock: dispatch to all user servers
		servers, err := h.pg.ListServers(c.Request.Context(), userID)
		if err == nil {
			for _, s := range servers {
				_ = h.pg.CreateCommand(c.Request.Context(), s.ID, "unblock_ip", block.IP)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "IP rule removed and unblock command dispatched", "block": block})
}
