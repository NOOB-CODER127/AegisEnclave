package api

import (
	"net/http"
	"time"

	"github.com/aegis-defender/backend/internal/storage/clickhouse"
	"github.com/aegis-defender/backend/internal/storage/postgres"
	"github.com/gin-gonic/gin"
)

type ServerHandler struct {
	PGStore *postgres.Store
	CHStore *clickhouse.Store
}

func NewServerHandler(pgStore *postgres.Store, chStore *clickhouse.Store) *ServerHandler {
	return &ServerHandler{
		PGStore: pgStore,
		CHStore: chStore,
	}
}

type CreateServerRequest struct {
	Name  string  `json:"name" binding:"required"`
	AppID *string `json:"app_id"`
}

func (h *ServerHandler) CreateServer(c *gin.Context) {
	// userID := c.GetString("user_id") // Use MustGet for consistency with middleware
	userID := c.MustGet("userID").(string)

	var req CreateServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	server, err := h.PGStore.CreateServer(c.Request.Context(), userID, req.AppID, req.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create server"})
		return
	}

	c.JSON(http.StatusCreated, server)
}

func (h *ServerHandler) ListServers(c *gin.Context) {
	userID := c.MustGet("userID").(string)

	servers, err := h.PGStore.ListServers(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch servers"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"servers": servers})
}

func (h *ServerHandler) GetInfrastructureStatus(c *gin.Context) {
	// 1. Get User
	userID := c.MustGet("userID").(string)

	// 2. Get Servers
	servers, err := h.PGStore.ListServers(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch servers"})
		return
	}

	if len(servers) == 0 {
		c.JSON(http.StatusOK, gin.H{"nodes": []interface{}{}})
		return
	}

	// 3. Get Metrics for servers
	serverIDs := make([]string, len(servers))
	for i, s := range servers {
		serverIDs[i] = s.ID
	}

	metricsMap, err := h.CHStore.GetLatestMetrics(c.Request.Context(), serverIDs)
	if err != nil {
		// Log error but return servers with offline status
		// log.Println("Failed to fetch metrics", err)
	}

	// 4. Construct Response
	type NodeStatus struct {
		ID       string  `json:"id"`
		Name     string  `json:"name"`
		Status   string  `json:"status"` // online, offline, warning, critical
		CPU      float64 `json:"cpu"`
		Memory   float64 `json:"memory"`
		LastSeen string  `json:"last_seen"`
	}

	var nodes []NodeStatus
	for _, s := range servers {
		status := "offline"
		cpu := 0.0
		mem := 0.0

		if m, ok := metricsMap[s.ID]; ok {
			// Check if stale (older than 1 min)
			if time.Since(m.Timestamp) < 1*time.Minute {
				cpu = m.CPUUsage
				mem = m.MemoryUsage

				// Determine Health
				if cpu > 90 || mem > 90 {
					status = "critical"
				} else if cpu > 70 || mem > 70 {
					status = "warning"
				} else {
					status = "online" // healthy
				}
			}
		}

		nodes = append(nodes, NodeStatus{
			ID:       s.ID,
			Name:     s.Name,
			Status:   status,
			CPU:      cpu,
			Memory:   mem,
			LastSeen: s.LastSeen.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, gin.H{"nodes": nodes})
}

type AssignServerRequest struct {
	ServerID string  `json:"server_id" binding:"required"`
	AppID    *string `json:"app_id"`
}

func (h *ServerHandler) AssignServer(c *gin.Context) {
	var req AssignServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.PGStore.AssignServerToApp(c.Request.Context(), req.ServerID, req.AppID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign server"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Server assigned successfully"})
}

func (h *ServerHandler) ListUnassignedServers(c *gin.Context) {
	userID := c.MustGet("userID").(string)

	servers, err := h.PGStore.ListUnassignedServers(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch unassigned servers"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"servers": servers})
}
