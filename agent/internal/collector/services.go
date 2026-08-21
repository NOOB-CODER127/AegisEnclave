package collector

import (
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

type DetectedService struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Port   *int   `json:"port"`
}

type ServiceCollector struct {
	Out      chan []DetectedService
	Interval time.Duration
	stop     chan struct{}
}

func NewServiceCollector(out chan []DetectedService, interval time.Duration) *ServiceCollector {
	return &ServiceCollector{
		Out:      out,
		Interval: interval,
		stop:     make(chan struct{}),
	}
}

func (sc *ServiceCollector) Start() {
	ticker := time.NewTicker(sc.Interval)
	defer ticker.Stop()

	// Initial collect
	sc.collect()

	for {
		select {
		case <-sc.stop:
			return
		case <-ticker.C:
			sc.collect()
		}
	}
}

func (sc *ServiceCollector) Stop() {
	close(sc.stop)
}

func (sc *ServiceCollector) collect() {
	// 1. Get all listening TCP connections
	connections, err := net.Connections("tcp")
	pidPorts := make(map[int32]int)
	if err == nil {
		for _, c := range connections {
			if c.Status == "LISTEN" && c.Pid > 0 {
				pidPorts[c.Pid] = int(c.Laddr.Port)
			}
		}
	}
	// log.Printf("Debug: Found %d listening connections, %d distinct PIDs", len(connections), len(pidPorts))

	// 2. Scan only processes with active connections (Optimization: Avoids scanning all system processes)
	found := make(map[string]DetectedService)

	interesting := map[string]bool{
		"nginx":        true,
		"postgres":     true,
		"mysqld":       true,
		"redis-server": true,
		"docker":       true,
		"node":         true,
		"python":       true,
		"python3":      true,
		"java":         true,
		"go":           true,
		"httpd":        true,
		"sshd":         true,
		"mongod":       true,
		"server":       true,
		"next-server":  true,
		"agent":        true, // Verify self
	}

	for pid, port := range pidPorts {
		p, err := process.NewProcess(pid)
		if err != nil {
			continue // Process might have ended
		}

		name, err := p.Name()
		if err != nil {
			continue
		}

		simpleName := strings.Fields(name)[0]

		if interesting[simpleName] || interesting[name] {
			// Found an interesting service listening on a port
			portVal := port

			// Use simple name as key to dedup
			found[simpleName] = DetectedService{
				Name:   simpleName,
				Status: "running",
				Port:   &portVal,
			}
		}
	}

	var services []DetectedService
	for _, s := range found {
		services = append(services, s)
	}

	if len(services) > 0 {
		sc.Out <- services
	}
}
