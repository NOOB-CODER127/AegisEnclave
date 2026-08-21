package collector

import (
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

type SystemMetric struct {
	Timestamp   time.Time `json:"timestamp"`
	CPUUsage    float64   `json:"cpu_usage"`
	MemoryUsage float64   `json:"memory_usage"`
	MemoryTotal uint64    `json:"memory_total"`
}

type MetricsCollector struct {
	Out      chan SystemMetric
	Interval time.Duration
	stop     chan struct{}
}

func NewMetricsCollector(out chan SystemMetric, interval time.Duration) *MetricsCollector {
	return &MetricsCollector{
		Out:      out,
		Interval: interval,
		stop:     make(chan struct{}),
	}
}

func (mc *MetricsCollector) Start() {
	ticker := time.NewTicker(mc.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-mc.stop:
			return
		case <-ticker.C:
			mc.collect()
		}
	}
}

func (mc *MetricsCollector) Stop() {
	close(mc.stop)
}

func (mc *MetricsCollector) collect() {
	v, _ := mem.VirtualMemory()
	c, _ := cpu.Percent(0, false)

	cpuVal := 0.0
	if len(c) > 0 {
		cpuVal = c[0]
	}

	mc.Out <- SystemMetric{
		Timestamp:   time.Now(),
		CPUUsage:    cpuVal,
		MemoryUsage: float64(v.UsedPercent),
		MemoryTotal: v.Total,
	}
}
