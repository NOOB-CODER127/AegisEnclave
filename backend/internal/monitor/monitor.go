package monitor

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/aegis-defender/backend/internal/storage/clickhouse"
	"github.com/aegis-defender/backend/internal/storage/postgres"
)

type Monitor struct {
	PG           *postgres.Store
	CH           *clickhouse.Store
	lastLogCheck time.Time
}

var (
	ipRegex = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

	sqlKeywords     = []string{"sql", "union", "select", "drop table", "1=1", "information_schema", "xp_cmdshell"}
	xssKeywords     = []string{"<script", "javascript:", "onerror=", "onload=", "document.cookie", "alert("}
	bruteKeywords   = []string{"unauthorized", "login failed", "invalid password", "authentication failure", "failed password for", "brute"}
	rceKeywords     = []string{"exploit", "shell_exec", "eval(", "system(", "passthru(", "popen("}
	cmdKeywords     = []string{"/bin/sh", "/bin/bash", "nc -e", "bash -i", "curl | sh", "wget | sh", "curl | bash", "wget | bash", "powershell -enc"}
	lfiKeywords     = []string{"/etc/passwd", "/etc/shadow", "..%2f", "..\\", "boot.ini", "win.ini", "web.config"}
	scannerKeywords = []string{"sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "nuclei", "zgrab"}
)

func New(pg *postgres.Store, ch *clickhouse.Store) *Monitor {
	return &Monitor{
		PG:           pg,
		CH:           ch,
		lastLogCheck: time.Now().Add(-10 * time.Minute),
	}
}

func (m *Monitor) Start(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Println("Starting Aegis SIEM Alert Monitor...")

	for {
		select {
		case <-ctx.Done():
			log.Println("Stopping Alert Monitor...")
			return
		case <-ticker.C:
			m.checkResourceUsage(ctx)
			m.checkSecurityEvents(ctx)
		}
	}
}

func (m *Monitor) checkResourceUsage(ctx context.Context) {
	// 1. Check for High CPU (> 90%) in the last 5 minutes
	serverIDs, err := m.CH.GetServersWithHighUsage(ctx, 90.0, 5)
	if err != nil {
		log.Printf("Monitor: Failed to fetch high usage servers: %v", err)
		return
	}

	for _, serverID := range serverIDs {
		// Dedup: Check if there's already an active incident
		active, err := m.PG.GetActiveIncident(ctx, serverID, "High CPU Usage")
		if err != nil {
			log.Printf("Monitor: DB error checking active incidents: %v", err)
			continue
		}
		if active != nil {
			continue // Already alerting
		}

		server, err := m.PG.GetServerByID(ctx, serverID)
		if err != nil || server == nil {
			log.Printf("Monitor: Server not found %s: %v", serverID, err)
			continue
		}

		log.Printf("Monitor: Creating High CPU Incident for %s", server.Name)
		incident := &postgres.Incident{
			UserID:      server.UserID,
			ServerID:    &server.ID,
			Title:       "High CPU Usage Detected",
			Description: fmt.Sprintf("Server %s is experiencing sustained high CPU usage (>90%%). Potential resource exhaustion or crypto-mining activity.", server.Name),
			Type:        "High CPU Usage",
			Severity:    "HIGH",
			Status:      "active",
		}
		if err := m.PG.CreateIncident(ctx, incident); err != nil {
			log.Printf("Monitor: Failed to create incident: %v", err)
		}
	}
}

func (m *Monitor) checkSecurityEvents(ctx context.Context) {
	logsEntries, err := m.CH.GetSecurityLogsSince(ctx, m.lastLogCheck)
	if err != nil {
		log.Printf("Monitor: Failed to fetch security logs: %v", err)
		return
	}

	maxTimestamp := m.lastLogCheck

	for _, l := range logsEntries {
		if l.Timestamp.After(maxTimestamp) {
			maxTimestamp = l.Timestamp
		}

		incidentType := "Security Alert"
		severity := "MEDIUM"
		description := fmt.Sprintf("Suspicious activity detected on Server: %s", l.Message)

		msgLower := strings.ToLower(l.Message)

		if containsLower(msgLower, cmdKeywords) {
			incidentType = "Command Injection / Reverse Shell"
			severity = "CRITICAL"
		} else if containsLower(msgLower, rceKeywords) {
			incidentType = "Remote Code Execution"
			severity = "CRITICAL"
		} else if containsLower(msgLower, sqlKeywords) {
			incidentType = "SQL Injection Attempt"
			severity = "CRITICAL"
		} else if containsLower(msgLower, lfiKeywords) {
			incidentType = "Directory Traversal / LFI"
			severity = "HIGH"
		} else if containsLower(msgLower, xssKeywords) {
			incidentType = "Cross-Site Scripting (XSS)"
			severity = "HIGH"
		} else if containsLower(msgLower, bruteKeywords) {
			incidentType = "Brute Force / Auth Attack"
			severity = "HIGH"
		} else if containsLower(msgLower, scannerKeywords) {
			incidentType = "Automated Security Scanner"
			severity = "MEDIUM"
		} else if l.Level == "error" || l.Level == "ERROR" {
			incidentType = "Critical System Error"
			severity = "MEDIUM"
		}

		// Extract Attacker IP
		ip := extractIP(l.Message)
		if ip != "" {
			description += fmt.Sprintf(" (Attacker IP: %s)", ip)
		}

		// Dedup
		active, err := m.PG.GetActiveIncident(ctx, l.ServerID, incidentType)
		if err != nil {
			log.Printf("Monitor: Error checking active incident: %v", err)
			continue
		}
		if active != nil {
			continue
		}

		server, err := m.PG.GetServerByID(ctx, l.ServerID)
		if err != nil || server == nil {
			log.Printf("Monitor: Server not found for ID %s", l.ServerID)
			continue
		}

		log.Printf("Monitor: Creating %s Incident for %s [Severity: %s]", incidentType, server.Name, severity)
		incident := &postgres.Incident{
			UserID:      server.UserID,
			ServerID:    &server.ID,
			Title:       fmt.Sprintf("%s Detected", incidentType),
			Description: fmt.Sprintf("%s on server %s. Raw Log: %s", incidentType, server.Name, l.Message),
			Type:        incidentType,
			Severity:    severity,
			Status:      "active",
		}
		if err := m.PG.CreateIncident(ctx, incident); err != nil {
			log.Printf("Monitor: Failed to create incident: %v", err)
		}

		// --- IPS: Auto-Response ---
		if ip != "" && isBlockingWorthy(incidentType) {
			log.Printf("Monitor: IPS TRIGGERED. Blocking IP %s on server %s", ip, server.Name)
			_ = m.PG.CreateCommand(ctx, *incident.ServerID, "block_ip", ip)
			_, _ = m.PG.CreateBlockedIP(ctx, server.UserID, incident.ServerID, ip, fmt.Sprintf("Automated IPS ban for %s", incidentType))
		}
	}

	m.lastLogCheck = maxTimestamp
}

func isBlockingWorthy(t string) bool {
	switch t {
	case "SQL Injection Attempt", "Remote Code Execution", "Command Injection / Reverse Shell", "Brute Force / Auth Attack", "Directory Traversal / LFI":
		return true
	default:
		return false
	}
}

func containsLower(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func extractIP(s string) string {
	return ipRegex.FindString(s)
}
