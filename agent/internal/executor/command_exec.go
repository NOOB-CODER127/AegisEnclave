package executor

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"time"
)

type Command struct {
	ID        string    `json:"id"`
	Command   string    `json:"command"`
	Args      string    `json:"args"`
	CreatedAt time.Time `json:"created_at"`
}

type CommandExecutor struct {
	BackendURL string
	APIKey     string
	Client     *http.Client
	Interval   time.Duration
	stop       chan struct{}
}

func NewCommandExecutor(backendURL, apiKey string) *CommandExecutor {
	return &CommandExecutor{
		BackendURL: backendURL,
		APIKey:     apiKey,
		Client:     &http.Client{Timeout: 10 * time.Second},
		Interval:   2 * time.Second, // Poll every 2s
		stop:       make(chan struct{}),
	}
}

func (e *CommandExecutor) Start() {
	ticker := time.NewTicker(e.Interval)
	defer ticker.Stop()

	log.Printf("Starting IPS Command Executor (Polling %s)...", e.BackendURL)

	for {
		select {
		case <-e.stop:
			return
		case <-ticker.C:
			e.poll()
		}
	}
}

func (e *CommandExecutor) Stop() {
	close(e.stop)
}

func (e *CommandExecutor) poll() {
	url := fmt.Sprintf("%s/api/v1/ingest/commands", e.BackendURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Executor: Failed to create request: %v", err)
		return
	}
	req.Header.Set("X-Server-Key", e.APIKey)

	resp, err := e.Client.Do(req)
	if err != nil {
		log.Printf("Executor: Poll failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return // Silent fail if no content or error
	}

	var response struct {
		Commands []Command `json:"commands"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return
	}

	for _, cmd := range response.Commands {
		e.execute(cmd)
	}
}

func (e *CommandExecutor) execute(cmd Command) {
	log.Printf("Executor: Received command %s %s", cmd.Command, cmd.Args)

	var err error
	switch cmd.Command {
	case "block_ip":
		err = e.blockIP(cmd.Args)
	case "unblock_ip":
		err = e.unblockIP(cmd.Args)
	default:
		log.Printf("Executor: Unknown command %s", cmd.Command)
	}

	if err == nil {
		e.ack(cmd.ID)
	} else {
		log.Printf("Executor: Failed to execute %s: %v", cmd.Command, err)
	}
}

func (e *CommandExecutor) blockIP(ip string) error {
	// Command: iptables -A INPUT -s <IP> -j DROP
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables error: %s: %s", err, string(output))
	}
	log.Printf("Executor: IPS BLOCKED IP %s", ip)
	return nil
}

func (e *CommandExecutor) unblockIP(ip string) error {
	// Command: iptables -D INPUT -s <IP> -j DROP
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables error: %s: %s", err, string(output))
	}
	log.Printf("Executor: IPS UNBLOCKED IP %s", ip)
	return nil
}

func (e *CommandExecutor) ack(id string) {
	url := fmt.Sprintf("%s/api/v1/ingest/commands/%s/ack", e.BackendURL, id)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Server-Key", e.APIKey)
	e.Client.Do(req)
}
