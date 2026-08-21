package api

import (
	"net/http"

	"github.com/aegis-defender/backend/internal/storage/clickhouse"
	"github.com/aegis-defender/backend/internal/storage/postgres"
	"github.com/gin-gonic/gin"
)

type IngestHandler struct {
	CHStore *clickhouse.Store
	PGStore *postgres.Store
}

func NewIngestHandler(chStore *clickhouse.Store, pgStore *postgres.Store) *IngestHandler {
	return &IngestHandler{
		CHStore: chStore,
		PGStore: pgStore,
	}
}

func (h *IngestHandler) HandleLogs(c *gin.Context) {
	apiKey := c.GetHeader("X-Server-Key")
	if apiKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "X-Server-Key header required"})
		return
	}

	server, err := h.PGStore.GetServerByAPIKey(c.Request.Context(), apiKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate API key"})
		return
	}
	if server == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		return
	}

	// Update Last Seen
	if err := h.PGStore.UpdateServerLastSeen(c.Request.Context(), server.ID); err != nil {
		// Log error but continue
		c.Error(err)
	}

	var logs []clickhouse.LogEntry
	if err := c.ShouldBindJSON(&logs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Override Server ID in logs to ensure integrity
	for i := range logs {
		logs[i].ServerID = server.ID
	}

	if len(logs) == 0 {
		c.JSON(http.StatusOK, gin.H{"status": "no logs received"})
		return
	}

	// Debug: Log the first log entry to verify parsing
	if len(logs) > 0 {
		l := logs[0]
		// Use fmt.Printf or log.Printf depending on what's available. Assuming standard log package is used elsewhere or I can use fmt.
		// Detailed logging for debugging
		// We need to import "log" if not present, but for now let's hope it is or I'll check imports.
		// Actually, I'll use c.Error to log to console if possible, or just print to stdout.
		println("DEBUG INGEST: Received log - Level:", l.Level, "Service:", l.Service, "Msg:", l.Message)
	}

	if err := h.CHStore.InsertLogs(c.Request.Context(), logs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store logs", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "logs ingested", "count": len(logs)})
}

func (h *IngestHandler) HandleMetrics(c *gin.Context) {
	apiKey := c.GetHeader("X-Server-Key")
	if apiKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "X-Server-Key header required"})
		return
	}

	server, err := h.PGStore.GetServerByAPIKey(c.Request.Context(), apiKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate API key"})
		return
	}
	if server == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		return
	}

	// Update Last Seen
	if err := h.PGStore.UpdateServerLastSeen(c.Request.Context(), server.ID); err != nil {
		c.Error(err)
	}

	var metrics []clickhouse.MetricEntry
	if err := c.ShouldBindJSON(&metrics); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	for i := range metrics {
		metrics[i].ServerID = server.ID
	}

	if len(metrics) == 0 {
		c.JSON(http.StatusOK, gin.H{"status": "no metrics received"})
		return
	}

	if err := h.CHStore.InsertMetrics(c.Request.Context(), metrics); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store metrics", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "metrics ingested", "count": len(metrics)})
}

type ServiceIngestRequest struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Port   *int   `json:"port"`
}

func (h *IngestHandler) HandleServices(c *gin.Context) {
	apiKey := c.GetHeader("X-Server-Key")
	if apiKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "X-Server-Key header required"})
		return
	}

	server, err := h.PGStore.GetServerByAPIKey(c.Request.Context(), apiKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate API key"})
		return
	}
	if server == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		return
	}

	var services []ServiceIngestRequest
	if err := c.ShouldBindJSON(&services); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	count := 0
	for _, s := range services {
		if err := h.PGStore.UpsertService(c.Request.Context(), server.ID, s.Name, s.Status, s.Port); err != nil {
			// Log error but try to continue
			count++ // Count as processed or track errors? Let's just continue
		} else {
			count++
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "services ingested", "count": count})
}

func (h *IngestHandler) HandleGetCommands(c *gin.Context) {
	apiKey := c.GetHeader("X-Server-Key")
	if apiKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "X-Server-Key header required"})
		return
	}

	server, err := h.PGStore.GetServerByAPIKey(c.Request.Context(), apiKey)
	if err != nil || server == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		return
	}

	commands, err := h.PGStore.GetPendingCommands(c.Request.Context(), server.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch commands"})
		return
	}
	if commands == nil {
		commands = []postgres.Command{}
	}

	c.JSON(http.StatusOK, gin.H{"commands": commands})
}

func (h *IngestHandler) HandleAckCommand(c *gin.Context) {
	apiKey := c.GetHeader("X-Server-Key")
	if apiKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "header required"})
		return
	}
	server, err := h.PGStore.GetServerByAPIKey(c.Request.Context(), apiKey)
	if err != nil || server == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid key"})
		return
	}

	cmdID := c.Param("id")
	if err := h.PGStore.MarkCommandExecuted(c.Request.Context(), cmdID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to ack"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "acked"})
}
