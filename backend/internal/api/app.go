package api

import (
	"net/http"

	"github.com/aegis-defender/backend/internal/storage/postgres"
	"github.com/gin-gonic/gin"
)

type AppHandler struct {
	PGStore *postgres.Store
}

func NewAppHandler(pgStore *postgres.Store) *AppHandler {
	return &AppHandler{PGStore: pgStore}
}

type CreateAppRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

func (h *AppHandler) CreateApp(c *gin.Context) {
	var req CreateAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.MustGet("userID").(string)

	app, err := h.PGStore.CreateApplication(c.Request.Context(), userID, req.Name, req.Description)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create application"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"application": app})
}

func (h *AppHandler) ListApps(c *gin.Context) {
	userID := c.MustGet("userID").(string)

	apps, err := h.PGStore.ListApplications(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch applications"})
		return
	}

	if apps == nil {
		apps = []postgres.Application{}
	}

	c.JSON(http.StatusOK, gin.H{"applications": apps})
}

// Get app details + servers
func (h *AppHandler) GetApp(c *gin.Context) {
	userID := c.MustGet("userID").(string)
	appID := c.Param("id")

	app, err := h.PGStore.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch application"})
		return
	}
	if app == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Application not found"})
		return
	}

	if app.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	servers, err := h.PGStore.ListServersByApp(c.Request.Context(), userID, appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch app servers"})
		return
	}
	if servers == nil {
		servers = []postgres.Server{}
	}

	// Fetch services for each server
	// This is N+1 but acceptable for MVP with low server count per app
	type ServerWithServices struct {
		postgres.Server
		Services []postgres.Service `json:"services"`
	}

	var serversWithServices []ServerWithServices
	for _, srv := range servers {
		svcs, err := h.PGStore.ListServices(c.Request.Context(), srv.ID)
		if err != nil {
			// Log error but continue
			svcs = []postgres.Service{}
		}
		if svcs == nil {
			svcs = []postgres.Service{}
		}
		serversWithServices = append(serversWithServices, ServerWithServices{
			Server:   srv,
			Services: svcs,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"application": app,
		"servers":     serversWithServices,
	})
}
