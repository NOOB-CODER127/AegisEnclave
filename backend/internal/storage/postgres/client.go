package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	Pool *pgxpool.Pool
}

func New(host string, port int, user, password, dbname string) (*Store, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", user, password, host, port, dbname)
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(context.Background()); err != nil {
		return nil, err
	}

	return &Store{Pool: pool}, nil
}

func (s *Store) InitializeSchema(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			name VARCHAR(255) NOT NULL,
			role VARCHAR(50) DEFAULT 'viewer',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'viewer';`,
		`CREATE TABLE IF NOT EXISTS applications (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			name VARCHAR(255) NOT NULL,
			description TEXT,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS servers (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			app_id UUID REFERENCES applications(id) ON DELETE SET NULL,
			name VARCHAR(255) NOT NULL,
			api_key VARCHAR(64) UNIQUE NOT NULL,
			status VARCHAR(50) DEFAULT 'offline',
			last_seen TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS incidents (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			server_id UUID REFERENCES servers(id) ON DELETE SET NULL,
			title VARCHAR(255) NOT NULL,
			description TEXT,
			type VARCHAR(100) NOT NULL,
			severity VARCHAR(20) NOT NULL,
			status VARCHAR(20) DEFAULT 'active',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			resolved_at TIMESTAMP WITH TIME ZONE,
			assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
			resolution_notes TEXT
		)`,
		`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS assigned_to UUID REFERENCES users(id) ON DELETE SET NULL;`,
		`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolution_notes TEXT;`,
		`CREATE TABLE IF NOT EXISTS blocked_ips (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			server_id UUID REFERENCES servers(id) ON DELETE CASCADE,
			ip VARCHAR(100) NOT NULL,
			reason VARCHAR(255),
			status VARCHAR(50) DEFAULT 'active',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			key_hash VARCHAR(255) NOT NULL,
			description VARCHAR(255),
			status VARCHAR(20) DEFAULT 'active',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			last_used_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE TABLE IF NOT EXISTS commands (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			server_id UUID REFERENCES servers(id) ON DELETE CASCADE,
			command VARCHAR(255) NOT NULL,
			args TEXT,
			status VARCHAR(50) DEFAULT 'pending', 
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			executed_at TIMESTAMP WITH TIME ZONE
		)`,
	}

	for _, query := range queries {
		if _, err := s.Pool.Exec(ctx, query); err != nil {
			return err
		}
	}
	return nil
}
