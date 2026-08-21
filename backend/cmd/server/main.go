package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/aegis-defender/backend/internal/api"
	"github.com/aegis-defender/backend/internal/monitor"
	"github.com/aegis-defender/backend/internal/storage/clickhouse"
	"github.com/aegis-defender/backend/internal/storage/postgres"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	_ = godotenv.Load()

	// Initialize ClickHouse
	// Retry connection loop since Docker takes time to spin up
	var chStore *clickhouse.Store
	var err error
	for i := 0; i < 10; i++ {
		chStore, err = clickhouse.New("localhost", 9000)
		if err == nil {
			break
		}
		log.Printf("Failed to connect to ClickHouse, retrying in 2s... (%v)", err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatal("Could not connect to ClickHouse after retries:", err)
	}
	log.Println("Connected to ClickHouse")

	// Initialize Schema
	if err := chStore.InitializeSchema(context.Background()); err != nil {
		log.Fatal("Failed to initialize ClickHouse schema:", err)
	}

	// Initialize Postgres
	var pgStore *postgres.Store
	for i := 0; i < 10; i++ {
		// DSN: postgres://aegis:aegis_password@localhost:5432/aegis_core
		pgStore, err = postgres.New("localhost", 5432, "aegis", "aegis_password", "aegis_core")
		if err == nil {
			break
		}
		log.Printf("Failed to connect to Postgres, retrying in 2s... (%v)", err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatal("Could not connect to Postgres after retries:", err)
	}
	log.Println("Connected to Postgres")

	if err := pgStore.InitializeSchema(context.Background()); err != nil {
		log.Fatal("Failed to initialize Postgres schema:", err)
	}

	// Start Background Monitor
	mon := monitor.New(pgStore, chStore)
	go mon.Start(context.Background())

	// Setup Router
	r := gin.Default()

	// CORS Setup
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"}, // Added Authorization
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	ingestHandler := api.NewIngestHandler(chStore, pgStore)
	queryHandler := api.NewQueryHandler(chStore, pgStore)
	authHandler := api.NewAuthHandler(pgStore)
	serverHandler := api.NewServerHandler(pgStore, chStore)
	appHandler := api.NewAppHandler(pgStore)
	teamHandler := api.NewTeamHandler(pgStore)
	incidentHandler := api.NewIncidentHandler(pgStore)
	settingsHandler := api.NewSettingsHandler(pgStore)
	firewallHandler := api.NewFirewallHandler(pgStore)
	securityStatsHandler := api.NewSecurityStatsHandler(pgStore, chStore)

	// Public Routes
	r.POST("/api/v1/auth/register", authHandler.Register)
	r.POST("/api/v1/auth/login", authHandler.Login)
	r.POST("/api/v1/ingest/logs", ingestHandler.HandleLogs)       // Keep ingestion public for now (agent uses it)
	r.POST("/api/v1/ingest/metrics", ingestHandler.HandleMetrics) // Public for agents
	r.POST("/api/v1/ingest/services", ingestHandler.HandleServices)
	r.GET("/api/v1/ingest/commands", ingestHandler.HandleGetCommands)
	r.POST("/api/v1/ingest/commands/:id/ack", ingestHandler.HandleAckCommand)

	// Protected Routes
	protected := r.Group("/api/v1")
	protected.Use(api.AuthMiddleware())
	{
		protected.GET("/logs", queryHandler.GetLogs)
		protected.POST("/servers", serverHandler.CreateServer)
		protected.GET("/servers", serverHandler.ListServers)
		protected.GET("/infrastructure/status", serverHandler.GetInfrastructureStatus)
		protected.GET("/dashboard/stats", queryHandler.GetDashboardStats)
		protected.POST("/servers/assign", serverHandler.AssignServer)
		protected.GET("/servers/unassigned", serverHandler.ListUnassignedServers)

		// Apps
		protected.POST("/apps", appHandler.CreateApp)
		protected.GET("/apps", appHandler.ListApps)
		protected.GET("/apps/:id", appHandler.GetApp)
		protected.GET("/apps/:id/stats", queryHandler.GetAppStats)

		// Team
		protected.GET("/team/members", teamHandler.ListMembers)
		protected.POST("/team/invite", teamHandler.InviteMember)

		// Incidents & Response
		protected.GET("/incidents", incidentHandler.ListIncidents)
		protected.POST("/incidents", incidentHandler.CreateIncident)
		protected.POST("/incidents/:id/assign", incidentHandler.AssignIncident)
		protected.PATCH("/incidents/:id/status", incidentHandler.UpdateIncidentStatus)
		protected.POST("/incidents/:id/mitigate", incidentHandler.MitigateIncident)

		// Firewall & Active Defense (IPS)
		protected.GET("/firewall/blocks", firewallHandler.ListBlocks)
		protected.POST("/firewall/block", firewallHandler.CreateBlock)
		protected.DELETE("/firewall/blocks/:id", firewallHandler.RemoveBlock)
		protected.POST("/firewall/unblock", firewallHandler.RemoveBlock)

		// Security & SIEM Metrics
		protected.GET("/security/stats", securityStatsHandler.GetSecurityStats)

		// Settings
		protected.GET("/settings/apikeys", settingsHandler.ListAPIKeys)
		protected.POST("/settings/apikeys", settingsHandler.CreateAPIKey)
	}

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	// TODO: Add Ingestion Endpoints

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}
