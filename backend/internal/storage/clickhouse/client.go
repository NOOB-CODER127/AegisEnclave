package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type Store struct {
	Conn driver.Conn
}

func New(host string, port int) (*Store, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", host, port)},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: "default",
			Password: "", // Default password is empty
		},
		Debug: true,
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
	})

	if err != nil {
		return nil, err
	}

	if err := conn.Ping(context.Background()); err != nil {
		return nil, err
	}

	return &Store{Conn: conn}, nil
}

func (s *Store) InitializeSchema(ctx context.Context) error {
	// Create Logs Table
	queryLogs := `
	CREATE TABLE IF NOT EXISTS logs (
		timestamp DateTime,
		server_id UUID,
		level String,
		service String,
		message String,
		metadata Map(String, String)
	) ENGINE = MergeTree()
	PARTITION BY toYYYYMM(timestamp)
	ORDER BY (server_id, timestamp)
	`
	if err := s.Conn.Exec(ctx, queryLogs); err != nil {
		return err
	}

	// Create Metrics Table
	queryMetrics := `
	CREATE TABLE IF NOT EXISTS metrics (
		timestamp DateTime,
		server_id UUID,
		cpu_usage Float64,
		memory_usage Float64,
		memory_total UInt64
	) ENGINE = MergeTree()
	PARTITION BY toYYYYMM(timestamp)
	ORDER BY (server_id, timestamp)
	`
	return s.Conn.Exec(ctx, queryMetrics)
}

func (s *Store) InsertLogs(ctx context.Context, logs []LogEntry) error {
	batch, err := s.Conn.PrepareBatch(ctx, "INSERT INTO logs")
	if err != nil {
		return err
	}

	for _, l := range logs {
		if err := batch.Append(
			l.Timestamp,
			l.ServerID,
			l.Level,
			l.Service,
			l.Message,
			l.Metadata,
		); err != nil {
			return err
		}
	}

	return batch.Send()
}

func (s *Store) InsertMetrics(ctx context.Context, metrics []MetricEntry) error {
	batch, err := s.Conn.PrepareBatch(ctx, "INSERT INTO metrics")
	if err != nil {
		return err
	}

	for _, m := range metrics {
		if err := batch.Append(
			m.Timestamp,
			m.ServerID,
			m.CPUUsage,
			m.MemoryUsage,
			m.MemoryTotal,
		); err != nil {
			return err
		}
	}

	return batch.Send()
}

func (s *Store) GetLogs(ctx context.Context, serverIDs []string, limit int) ([]LogEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	if len(serverIDs) == 0 {
		return []LogEntry{}, nil
	}

	query := `
		SELECT timestamp, server_id, level, service, message, metadata
		FROM logs
		WHERE server_id IN (@serverIDs)
		ORDER BY timestamp DESC
		LIMIT @limit
	`

	rows, err := s.Conn.Query(ctx, query, clickhouse.Named("serverIDs", serverIDs), clickhouse.Named("limit", limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []LogEntry
	for rows.Next() {
		var l LogEntry
		if err := rows.Scan(
			&l.Timestamp,
			&l.ServerID,
			&l.Level,
			&l.Service,
			&l.Message,
			&l.Metadata,
		); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}

	return logs, nil
}

// New method: Fetch metric history (for dashboard charts), specific to user's servers
func (s *Store) GetMetricHistory(ctx context.Context, serverIDs []string) ([]AggregatedMetric, error) {
	if len(serverIDs) == 0 {
		return []AggregatedMetric{}, nil
	}

	// Aggregated history for the last 24h
	query := `
		SELECT 
			toStartOfHour(timestamp) as bucket,
			avg(cpu_usage) as avg_cpu,
			avg(memory_usage) as avg_mem,
			max(memory_total) as max_mem_total
		FROM metrics
		WHERE server_id IN (@serverIDs) AND timestamp > now() - INTERVAL 24 HOUR
		GROUP BY bucket
		ORDER BY bucket ASC
	`

	rows, err := s.Conn.Query(ctx, query, clickhouse.Named("serverIDs", serverIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []AggregatedMetric
	for rows.Next() {
		var m AggregatedMetric
		if err := rows.Scan(&m.TimeBucket, &m.AvgCPU, &m.AvgMem, &m.MaxMemTotal); err != nil {
			return nil, err
		}
		metrics = append(metrics, m)
	}
	return metrics, nil
}

func (s *Store) GetLatestMetrics(ctx context.Context, serverIDs []string) (map[string]MetricEntry, error) {
	if len(serverIDs) == 0 {
		return map[string]MetricEntry{}, nil
	}

	query := `
		SELECT timestamp, server_id, cpu_usage, memory_usage, memory_total
		FROM metrics
		WHERE server_id IN (@serverIDs)
		ORDER BY timestamp DESC
		LIMIT 1 BY server_id
	`

	rows, err := s.Conn.Query(ctx, query, clickhouse.Named("serverIDs", serverIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]MetricEntry)
	for rows.Next() {
		var m MetricEntry
		if err := rows.Scan(&m.Timestamp, &m.ServerID, &m.CPUUsage, &m.MemoryUsage, &m.MemoryTotal); err != nil {
			continue
		}
		result[m.ServerID] = m
	}
	return result, nil
}

func (s *Store) GetServersWithHighUsage(ctx context.Context, cpuThreshold float64, durationMinutes int) ([]string, error) {
	query := `
		SELECT server_id
		FROM metrics
		WHERE timestamp > now() - INTERVAL @duration MINUTE
		GROUP BY server_id
		HAVING avg(cpu_usage) > @threshold
	`
	rows, err := s.Conn.Query(ctx, query, clickhouse.Named("duration", durationMinutes), clickhouse.Named("threshold", cpuThreshold))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var serverIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			continue // Or return error
		}
		serverIDs = append(serverIDs, id)
	}
	return serverIDs, nil
}

func (s *Store) GetRecentSecurityLogs(ctx context.Context, lookbackMinutes int) ([]LogEntry, error) {
	query := `
		SELECT timestamp, server_id, level, service, message, metadata
		FROM logs
		WHERE timestamp > now() - INTERVAL @lookback MINUTE
		  AND (level = 'alert' OR level = 'error' OR service = 'security-agent')
		ORDER BY timestamp DESC
	`
	rows, err := s.Conn.Query(ctx, query, clickhouse.Named("lookback", lookbackMinutes))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []LogEntry
	for rows.Next() {
		var l LogEntry
		if err := rows.Scan(&l.Timestamp, &l.ServerID, &l.Level, &l.Service, &l.Message, &l.Metadata); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}

func (s *Store) GetSecurityLogsSince(ctx context.Context, since time.Time) ([]LogEntry, error) {
	query := `
		SELECT timestamp, server_id, level, service, message, metadata
		FROM logs
		WHERE timestamp > @since
		  AND (level = 'alert' OR level = 'error' OR service = 'security-agent')
		ORDER BY timestamp ASC
	`
	rows, err := s.Conn.Query(ctx, query, clickhouse.Named("since", since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []LogEntry
	for rows.Next() {
		var l LogEntry
		if err := rows.Scan(&l.Timestamp, &l.ServerID, &l.Level, &l.Service, &l.Message, &l.Metadata); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}
