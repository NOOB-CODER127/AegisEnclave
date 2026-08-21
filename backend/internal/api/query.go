package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/aegis-defender/backend/internal/storage/clickhouse"
	"github.com/aegis-defender/backend/internal/storage/postgres"
	"github.com/gin-gonic/gin"
)

type QueryHandler struct {
	CHStore *clickhouse.Store
	PGStore *postgres.Store
}

func NewQueryHandler(chStore *clickhouse.Store, pgStore *postgres.Store) *QueryHandler {
	return &QueryHandler{
		CHStore: chStore,
		PGStore: pgStore,
	}
}

func (h *QueryHandler) GetLogs(c *gin.Context) {
	userID := c.MustGet("userID").(string)
	serverID := c.Query("server_id")
	limitStr := c.Query("limit")
	limit := 100

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// 1. Get User's Servers
	servers, err := h.PGStore.ListServers(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve servers"})
		return
	}

	if len(servers) == 0 {
		c.JSON(http.StatusOK, gin.H{"logs": []interface{}{}})
		return
	}

	var targetIDs []string
	userServerMap := make(map[string]bool)
	for _, s := range servers {
		userServerMap[s.ID] = true
	}

	// 2. Validate/Select Target IDs
	if serverID != "" {
		if !userServerMap[serverID] {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to this server"})
			return
		}
		targetIDs = []string{serverID}
	} else {
		// Fetch for all
		for _, s := range servers {
			targetIDs = append(targetIDs, s.ID)
		}
	}

	logs, err := h.CHStore.GetLogs(c.Request.Context(), targetIDs, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch logs", "details": err.Error()})
		return
	}

	if logs == nil {
		logs = []clickhouse.LogEntry{}
	}

	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

// New Endpoint: Get Dashboard Stats
func (h *QueryHandler) GetDashboardStats(c *gin.Context) {
	userID := c.MustGet("userID").(string)

	// 1. Get User's Servers
	servers, err := h.PGStore.ListServers(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve servers"})
		return
	}

	h.respondWithStats(c, servers)
}

// New Endpoint: Get App Stats
func (h *QueryHandler) GetAppStats(c *gin.Context) {
	userID := c.MustGet("userID").(string)
	appID := c.Param("id")

	// 1. Get App's Servers
	servers, err := h.PGStore.ListServersByApp(c.Request.Context(), userID, appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve servers"})
		return
	}

	h.respondWithStats(c, servers)
}

// Helper to respond with stats for a given list of servers
func (h *QueryHandler) respondWithStats(c *gin.Context, servers []postgres.Server) {
	if len(servers) == 0 {
		// No servers = empty stats
		c.JSON(http.StatusOK, gin.H{
			"events":    []interface{}{},
			"telemetry": []interface{}{},
		})
		return
	}

	var serverIDs []string
	for _, s := range servers {
		serverIDs = append(serverIDs, s.ID)
	}

	// 2. Get Recent Events (Logs) - Limit 50 for app details
	events, err := h.CHStore.GetLogs(c.Request.Context(), serverIDs, 50)
	if err != nil {
		fmt.Printf("Error fetching stats logs: %v\n", err)
		events = []clickhouse.LogEntry{}
	}

	// 3. Get Telemetry History
	telemetry, err := h.CHStore.GetMetricHistory(c.Request.Context(), serverIDs)
	if err != nil {
		fmt.Printf("Error fetching stats telemetry: %v\n", err)
		telemetry = []clickhouse.AggregatedMetric{}
	}

	// Format response
	var mappedEvents []map[string]interface{}
	if events != nil {
		for i, e := range events {
			typ := "info"
			if e.Level == "error" || e.Level == "ERROR" || e.Level == "critical" || e.Level == "CRITICAL" {
				typ = "error"
			} else if e.Level == "warn" || e.Level == "warning" || e.Level == "WARN" {
				typ = "warning"
			} else if e.Level == "alert" || e.Level == "ALERT" {
				typ = "alert"
			}

			mappedEvents = append(mappedEvents, map[string]interface{}{
				"id":        fmt.Sprintf("evt-%d", i),
				"timestamp": e.Timestamp,
				"type":      typ,
				"message":   e.Message,
				"source":    e.Service,
			})
		}
	} else {
		mappedEvents = []map[string]interface{}{}
	}

	var mappedTelemetry []map[string]interface{}
	if telemetry != nil {
		for _, t := range telemetry {
			mappedTelemetry = append(mappedTelemetry, map[string]interface{}{
				"time":         t.TimeBucket.Format("15:00"),
				"cpu":          t.AvgCPU,
				"memory":       t.AvgMem,
				"memory_total": t.MaxMemTotal,
			})
		}
	} else {
		mappedTelemetry = []map[string]interface{}{}
	}

	// Ensure we return empty arrays if nil
	if mappedEvents == nil {
		mappedEvents = []map[string]interface{}{}
	}
	if mappedTelemetry == nil {
		mappedTelemetry = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"events":    mappedEvents,
		"telemetry": mappedTelemetry,
	})
}
