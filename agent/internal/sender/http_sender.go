package sender

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aegis-defender/agent/internal/collector"
)

type LogEntry struct {
	Timestamp time.Time         `json:"timestamp"`
	ServerID  string            `json:"server_id"`
	Level     string            `json:"level"`
	Service   string            `json:"service"`
	Message   string            `json:"message"`
	Metadata  map[string]string `json:"metadata"`
}

type HTTPSender struct {
	BackendURL   string
	ServerID     string
	APIKey       string
	Client       *http.Client
	Input        chan collector.LogLine
	MetricInput  chan collector.SystemMetric
	ServiceInput chan []collector.DetectedService
	Buffer       []LogEntry
	MetricBuffer []collector.SystemMetric
	MaxBuffer    int
	Interval     time.Duration
}

func NewHTTPSender(backendURL, serverID, apiKey string, input chan collector.LogLine, metricInput chan collector.SystemMetric, serviceInput chan []collector.DetectedService) *HTTPSender {
	return &HTTPSender{
		BackendURL:   backendURL,
		ServerID:     serverID,
		APIKey:       apiKey,
		Client:       &http.Client{Timeout: 10 * time.Second},
		Input:        input,
		MetricInput:  metricInput,
		ServiceInput: serviceInput,
		Buffer:       make([]LogEntry, 0, 100),
		MetricBuffer: make([]collector.SystemMetric, 0, 100),
		MaxBuffer:    100,
		Interval:     5 * time.Second,
	}
}

func (s *HTTPSender) Start() {
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()

	for {
		select {
		case line := <-s.Input:
			level := "INFO"
			service := "system"
			message := line.Content

			// Simple parsing for [level] [service] format
			// Example: [alert] [security-agent] ...
			// Simple parsing for [level] [service] format
			// Example: [alert] [security-agent] ...
			if matches := regexp.MustCompile(`\[(\w+)\]\s+\[([\w-]+)\]`).FindStringSubmatch(message); len(matches) == 3 {
				level = strings.ToLower(matches[1])
				service = matches[2]
			} else if matches := regexp.MustCompile(`^\[(\w+)\]`).FindStringSubmatch(message); len(matches) == 2 {
				// Fallback for [LEVEL] Message
				level = strings.ToLower(matches[1])
			}

			s.Buffer = append(s.Buffer, LogEntry{
				Timestamp: line.Timestamp,
				ServerID:  s.ServerID,
				Level:     level,
				Service:   service,
				Message:   message,
				Metadata:  map[string]string{"path": line.Path},
			})
			if len(s.Buffer) >= s.MaxBuffer {
				s.FlushLogs()
			}
		case metric := <-s.MetricInput:
			s.MetricBuffer = append(s.MetricBuffer, metric)
			if len(s.MetricBuffer) >= s.MaxBuffer {
				s.FlushMetrics()
			}
		case services := <-s.ServiceInput:
			s.SendServices(services)
		case <-ticker.C:
			if len(s.Buffer) > 0 {
				s.FlushLogs()
			}
			if len(s.MetricBuffer) > 0 {
				s.FlushMetrics()
			}
		}
	}
}

func (s *HTTPSender) FlushLogs() {
	payload, err := json.Marshal(s.Buffer)
	if err != nil {
		log.Printf("Failed to marshal logs: %v", err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/ingest/logs", s.BackendURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if s.APIKey != "" {
		req.Header.Set("X-Server-Key", s.APIKey)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		log.Printf("Failed to send logs: %v", err)
		// TODO: Retry logic (store in local queue)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("Backend returned error: %s", resp.Status)
	} else {
		log.Printf("Sent %d logs to %s", len(payload)/100, s.BackendURL)
	}

	// Reset buffer
	s.Buffer = s.Buffer[:0]
}

func (s *HTTPSender) FlushMetrics() {
	payload, err := json.Marshal(s.MetricBuffer)
	if err != nil {
		log.Printf("Failed to marshal metrics: %v", err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/ingest/metrics", s.BackendURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if s.APIKey != "" {
		req.Header.Set("X-Server-Key", s.APIKey)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		log.Printf("Failed to send metrics: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("Backend returned error for metrics: %s", resp.Status)
	} else {
		// log.Printf("Sent %d metrics", len(s.MetricBuffer))
	}

	// Reset buffer
	s.MetricBuffer = s.MetricBuffer[:0]
}

func (s *HTTPSender) SendServices(services []collector.DetectedService) {
	payload, err := json.Marshal(services)
	if err != nil {
		log.Printf("Failed to marshal services: %v", err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/ingest/services", s.BackendURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if s.APIKey != "" {
		req.Header.Set("X-Server-Key", s.APIKey)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		log.Printf("Failed to send services: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("Backend returned error for services: %s", resp.Status)
	} else {
		log.Printf("Sent %d discovered services", len(services))
	}
}
