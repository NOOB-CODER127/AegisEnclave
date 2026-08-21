package api

import (
	"net/http"

	"github.com/aegis-defender/backend/internal/storage/postgres"
	"github.com/gin-gonic/gin"
)

type TeamHandler struct {
	pg *postgres.Store
}

func NewTeamHandler(pg *postgres.Store) *TeamHandler {
	return &TeamHandler{pg: pg}
}

func (h *TeamHandler) ListMembers(c *gin.Context) {
	// In a real app, we might filter by "OrganizationID"
	// For now, we list all users as we are single-tenant/monolithic
	members, err := h.pg.ListUsers(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch team members"})
		return
	}
	c.JSON(http.StatusOK, members)
}

type InviteRequest struct {
	Email string `json:"email" binding:"required,email"`
	Role  string `json:"role" binding:"required"`
}

func (h *TeamHandler) InviteMember(c *gin.Context) {
	var req InviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// For MVP, "inviting" just creates the user with a temporary password
	// In production, this would send an email link
	tempPassword := "welcome123" // Insecure, but fine for MVP demo

	// Create user
	user, err := h.pg.CreateUser(c.Request.Context(), req.Email, tempPassword, "Invited User", req.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to invite member: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, user)
}
