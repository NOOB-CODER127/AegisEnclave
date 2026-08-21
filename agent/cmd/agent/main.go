package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aegis-defender/agent/internal/collector"
	"github.com/aegis-defender/agent/internal/executor"
	"github.com/aegis-defender/agent/internal/sender"
	"github.com/google/uuid"
)

func main() {
	serverID := os.Getenv("SERVER_ID")
	// If SERVER_ID is not provided, we might generate one, BUT the backend requires a registered ID/Key pair now.
	// We will log a warning if it's missing but proceed to let the user know.
	if serverID == "" {
		log.Println("WARNING: SERVER_ID not set. Logs may be rejected.")
		serverID = uuid.New().String()
	}
	apiKey := os.Getenv("SERVER_KEY")
	if apiKey == "" {
		log.Fatal("SERVER_KEY is required. Please register this server in the dashboard.")
	}

	log.Printf("Starting Aegis Agent (ServerID: %s)", serverID)

	// Channel for log lines
	logChan := make(chan collector.LogLine, 100)
	metricChan := make(chan collector.SystemMetric, 100)
	serviceChan := make(chan []collector.DetectedService, 10)

	// Start Sender
	// Assuming Backend is running on localhost:8080
	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" {
		backendURL = "http://localhost:8082"
	}
	// Start HTTP Sender
	logSender := sender.NewHTTPSender(backendURL, serverID, apiKey, logChan, metricChan, serviceChan)
	go logSender.Start()

	// Start Log Collector
	// For demo, we watch a local dummy file
	logFile := "./dummy.log"
	// Create if not exists
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		os.Create(logFile)
	}
	logTailer, err := collector.NewLogTailer(logFile, logChan)
	if err != nil {
		log.Fatal(err)
	}

	if err := logTailer.Start(); err != nil {
		log.Fatal(err)
	}
	defer logTailer.Stop()

	// Start Metrics Collector
	metricsCollector := collector.NewMetricsCollector(metricChan, 5*time.Second)
	go metricsCollector.Start()
	defer metricsCollector.Stop()

	// Start Service Collector
	serviceCollector := collector.NewServiceCollector(serviceChan, 30*time.Second) // Every 30s
	go serviceCollector.Start()
	defer serviceCollector.Stop()

	// Start Command Executor (IPS)
	commandExecutor := executor.NewCommandExecutor(backendURL, apiKey)
	go commandExecutor.Start()
	defer commandExecutor.Stop()

	// Keep running until SIGINT
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
}
