package clickhouse

import "time"

type LogEntry struct {
	Timestamp time.Time         `json:"timestamp"`
	ServerID  string            `json:"server_id"`
	Level     string            `json:"level"`
	Service   string            `json:"service"`
	Message   string            `json:"message"`
	Metadata  map[string]string `json:"metadata"`
}

type AggregatedMetric struct {
	TimeBucket  time.Time `json:"time_bucket"`
	AvgCPU      float64   `json:"avg_cpu"`
	AvgMem      float64   `json:"avg_mem"`
	MaxMemTotal uint64    `json:"max_mem_total"`
}

type MetricEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	ServerID    string    `json:"server_id"`
	CPUUsage    float64   `json:"cpu_usage"`
	MemoryUsage float64   `json:"memory_usage"`
	MemoryTotal uint64    `json:"memory_total"`
}
