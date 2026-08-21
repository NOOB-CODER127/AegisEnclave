package api

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/aegis-defender/backend/internal/storage/postgres"
	"github.com/gin-gonic/gin"
)

type IncidentHandler struct {
	pg *postgres.Store
}

var ipExtractor = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

func NewIncidentHandler(pg *postgres.Store) *IncidentHandler {
	return &IncidentHandler{pg: pg}
}

func (h *IncidentHandler) ListIncidents(c *gin.Context) {
	userID := c.GetString("userID")
	incidents, err := h.pg.ListIncidents(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch incidents"})
		return
	}
	c.JSON(http.StatusOK, incidents)
}

type CreateIncidentRequest struct {
	ServerID    *string `json:"server_id"`
	Title       string  `json:"title" binding:"required"`
	Description string  `json:"description"`
	Type        string  `json:"type" binding:"required"`
	Severity    string  `json:"severity" binding:"required"`
	Status      string  `json:"status"`
}

func (h *IncidentHandler) CreateIncident(c *gin.Context) {
	var req CreateIncidentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetString("userID")
	inc := &postgres.Incident{
		UserID:      userID,
		ServerID:    req.ServerID,
		Title:       req.Title,
		Description: req.Description,
		Type:        req.Type,
		Severity:    req.Severity,
		Status:      req.Status,
	}

	if inc.Status == "" {
		inc.Status = "active"
	}

	if err := h.pg.CreateIncident(c.Request.Context(), inc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create incident"})
		return
	}

	c.JSON(http.StatusCreated, inc)
}

type AssignIncidentRequest struct {
	AssignedTo *string `json:"assigned_to"`
}

func (h *IncidentHandler) AssignIncident(c *gin.Context) {
	incidentID := c.Param("id")
	userID := c.GetString("userID")

	var req AssignIncidentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.pg.AssignIncident(c.Request.Context(), incidentID, userID, req.AssignedTo); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign incident"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Incident assigned successfully"})
}

type UpdateIncidentStatusRequest struct {
	Status          string  `json:"status" binding:"required"`
	ResolutionNotes *string `json:"resolution_notes"`
}

func (h *IncidentHandler) UpdateIncidentStatus(c *gin.Context) {
	incidentID := c.Param("id")
	userID := c.GetString("userID")

	var req UpdateIncidentStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.pg.UpdateIncidentStatus(c.Request.Context(), incidentID, userID, req.Status, req.ResolutionNotes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update incident status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Incident status updated successfully"})
}

type MitigateIncidentRequest struct {
	Action string  `json:"action"` // "block_ip", "resolve", "full_mitigation"
	IP     *string `json:"ip"`
	Notes  *string `json:"notes"`
}

func (h *IncidentHandler) MitigateIncident(c *gin.Context) {
	incidentID := c.Param("id")
	userID := c.GetString("userID")

	var req MitigateIncidentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Optional body
	}

	// 1. Fetch incident details
	incident, err := h.pg.GetIncidentByID(c.Request.Context(), incidentID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch incident details"})
		return
	}
	if incident == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Incident not found"})
		return
	}

	// 2. Identify IP to block
	ipToBlock := ""
	if req.IP != nil && *req.IP != "" {
		ipToBlock = *req.IP
	} else {
		// Attempt to extract from description
		found := ipExtractor.FindString(incident.Description)
		if found != "" {
			ipToBlock = found
		}
	}

	// 3. Queue block command to server if server is set and IP is identified
	blocked := false
	if ipToBlock != "" && incident.ServerID != nil && *incident.ServerID != "" {
		_ = h.pg.CreateCommand(c.Request.Context(), *incident.ServerID, "block_ip", ipToBlock)
		_, _ = h.pg.CreateBlockedIP(c.Request.Context(), userID, incident.ServerID, ipToBlock, fmt.Sprintf("Mitigated from incident: %s", incident.Title))
		blocked = true
	}

	// 4. Mark incident as resolved
	notes := "Mitigated threat automatically"
	if blocked {
		notes = fmt.Sprintf("Mitigated threat and blocked attacker IP: %s", ipToBlock)
	}
	if req.Notes != nil && *req.Notes != "" {
		notes = fmt.Sprintf("%s. Notes: %s", notes, *req.Notes)
	}

	if err := h.pg.UpdateIncidentStatus(c.Request.Context(), incidentID, userID, "resolved", &notes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark incident as resolved"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Threat mitigation executed successfully",
		"blocked":   blocked,
		"ip":        ipToBlock,
		"status":    "resolved",
		"notes":     notes,
	})
}
