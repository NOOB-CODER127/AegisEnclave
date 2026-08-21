package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Name         string    `json:"name"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

type Server struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	AppID     *string   `json:"app_id,omitempty"` // Nullable
	Name      string    `json:"name"`
	ApiKey    string    `json:"api_key"`
	Status    string    `json:"status"`
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
}

type Incident struct {
	ID              string     `json:"id"`
	UserID          string     `json:"user_id"`
	ServerID        *string    `json:"server_id,omitempty"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	Type            string     `json:"type"`
	Severity        string     `json:"severity"`
	Status          string     `json:"status"`
	CreatedAt       time.Time  `json:"created_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	AssignedTo      *string    `json:"assigned_to,omitempty"`
	ResolutionNotes *string    `json:"resolution_notes,omitempty"`
}

type BlockedIP struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	ServerID   *string   `json:"server_id,omitempty"`
	ServerName *string   `json:"server_name,omitempty"`
	IP         string    `json:"ip"`
	Reason     string    `json:"reason"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

type APIKey struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	KeyHash     string     `json:"-"`
	Description string     `json:"description"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

type Service struct {
	ID       string    `json:"id"`
	ServerID string    `json:"server_id"`
	Name     string    `json:"name"`
	Version  *string   `json:"version,omitempty"`
	Port     *int      `json:"port,omitempty"`
	Status   string    `json:"status"`
	LastSeen time.Time `json:"last_seen"`
}

// Service Methods

func (s *Store) UpsertService(ctx context.Context, serverID, name, status string, port *int) error {
	query := `
		INSERT INTO services (server_id, name, status, port, last_seen)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (server_id, name) 
		DO UPDATE SET status = EXCLUDED.status, port = EXCLUDED.port, last_seen = NOW()
	`
	_, err := s.Pool.Exec(ctx, query, serverID, name, status, port)
	return err
}

func (s *Store) ListServices(ctx context.Context, serverID string) ([]Service, error) {
	query := `SELECT id, server_id, name, version, port, status, last_seen FROM services WHERE server_id = $1 ORDER BY name ASC`
	rows, err := s.Pool.Query(ctx, query, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []Service
	for rows.Next() {
		var svc Service
		if err := rows.Scan(&svc.ID, &svc.ServerID, &svc.Name, &svc.Version, &svc.Port, &svc.Status, &svc.LastSeen); err != nil {
			return nil, err
		}
		services = append(services, svc)
	}
	return services, nil
}

// User Methods

func (s *Store) CreateUser(ctx context.Context, email, passwordHash, name, role string) (*User, error) {
	var user User
	if role == "" {
		role = "viewer"
	}
	query := `
		INSERT INTO users (email, password_hash, name, role) 
		VALUES ($1, $2, $3, $4) 
		RETURNING id, email, name, role, created_at`

	err := s.Pool.QueryRow(ctx, query, email, passwordHash, name, role).Scan(&user.ID, &user.Email, &user.Name, &user.Role, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	query := `SELECT id, email, password_hash, name, role, created_at FROM users WHERE email = $1`
	err := s.Pool.QueryRow(ctx, query, email).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Name, &user.Role, &user.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // Not found
		}
		return nil, err
	}
	return &user, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	query := `SELECT id, email, name, role, created_at FROM users ORDER BY created_at DESC`
	rows, err := s.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// Server Methods

func generateAPIKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (s *Store) CreateServer(ctx context.Context, userID string, appID *string, name string) (*Server, error) {
	apiKey, err := generateAPIKey()
	if err != nil {
		return nil, err
	}

	var server Server
	query := `
		INSERT INTO servers (user_id, app_id, name, api_key) 
		VALUES ($1, $2, $3, $4) 
		RETURNING id, user_id, app_id, name, api_key, status, created_at`

	err = s.Pool.QueryRow(ctx, query, userID, appID, name, apiKey).Scan(&server.ID, &server.UserID, &server.AppID, &server.Name, &server.ApiKey, &server.Status, &server.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &server, nil
}

func (s *Store) GetServerByAPIKey(ctx context.Context, apiKey string) (*Server, error) {
	var server Server
	query := `SELECT id, user_id, app_id, name, api_key, status, COALESCE(last_seen, '1970-01-01 00:00:00+00'), created_at FROM servers WHERE api_key = $1`
	err := s.Pool.QueryRow(ctx, query, apiKey).Scan(&server.ID, &server.UserID, &server.AppID, &server.Name, &server.ApiKey, &server.Status, &server.LastSeen, &server.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // Not found
		}
		return nil, err
	}
	return &server, nil
}

func (s *Store) GetServerByID(ctx context.Context, serverID string) (*Server, error) {
	var server Server
	query := `SELECT id, user_id, app_id, name, api_key, status, COALESCE(last_seen, '1970-01-01 00:00:00+00'), created_at FROM servers WHERE id = $1`
	err := s.Pool.QueryRow(ctx, query, serverID).Scan(&server.ID, &server.UserID, &server.AppID, &server.Name, &server.ApiKey, &server.Status, &server.LastSeen, &server.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // Not found
		}
		return nil, err
	}
	return &server, nil
}

func (s *Store) ListServers(ctx context.Context, userID string) ([]Server, error) {
	query := `SELECT id, user_id, app_id, name, status, COALESCE(last_seen, '1970-01-01 00:00:00+00'), created_at FROM servers WHERE user_id = $1 ORDER BY created_at DESC`
	rows, err := s.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []Server
	for rows.Next() {
		var srv Server
		if err := rows.Scan(&srv.ID, &srv.UserID, &srv.AppID, &srv.Name, &srv.Status, &srv.LastSeen, &srv.CreatedAt); err != nil {
			return nil, err
		}
		servers = append(servers, srv)
	}
	return servers, nil
}

// New method: List servers by AppID
func (s *Store) ListServersByApp(ctx context.Context, userID, appID string) ([]Server, error) {
	query := `
		SELECT id, user_id, app_id, name, status, COALESCE(last_seen, '1970-01-01 00:00:00+00'), created_at 
		FROM servers 
		WHERE user_id = $1 AND app_id = $2 
		ORDER BY created_at DESC
	`
	rows, err := s.Pool.Query(ctx, query, userID, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []Server
	for rows.Next() {
		var srv Server
		if err := rows.Scan(&srv.ID, &srv.UserID, &srv.AppID, &srv.Name, &srv.Status, &srv.LastSeen, &srv.CreatedAt); err != nil {
			return nil, err
		}
		servers = append(servers, srv)
	}
	return servers, nil
}

func (s *Store) AssignServerToApp(ctx context.Context, serverID string, appID *string) error {
	query := `UPDATE servers SET app_id = $1 WHERE id = $2`
	_, err := s.Pool.Exec(ctx, query, appID, serverID)
	return err
}

func (s *Store) ListUnassignedServers(ctx context.Context, userID string) ([]Server, error) {
	query := `
		SELECT id, user_id, app_id, name, status, COALESCE(last_seen, '1970-01-01 00:00:00+00'), created_at 
		FROM servers 
		WHERE user_id = $1 AND app_id IS NULL 
		ORDER BY created_at DESC
	`
	rows, err := s.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []Server
	for rows.Next() {
		var srv Server
		if err := rows.Scan(&srv.ID, &srv.UserID, &srv.AppID, &srv.Name, &srv.Status, &srv.LastSeen, &srv.CreatedAt); err != nil {
			return nil, err
		}
		servers = append(servers, srv)
	}
	return servers, nil
}

func (s *Store) UpdateServerLastSeen(ctx context.Context, serverID string) error {
	query := `UPDATE servers SET last_seen = NOW(), status = 'online' WHERE id = $1`
	_, err := s.Pool.Exec(ctx, query, serverID)
	return err
}

// --- Applications ---

type Application struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Store) CreateApplication(ctx context.Context, userID, name, description string) (*Application, error) {
	query := `
		INSERT INTO applications (user_id, name, description)
		VALUES ($1, $2, $3)
		RETURNING id, created_at
	`
	var app Application
	app.UserID = userID
	app.Name = name
	app.Description = description

	err := s.Pool.QueryRow(ctx, query, userID, name, description).Scan(&app.ID, &app.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &app, nil
}

func (s *Store) ListApplications(ctx context.Context, userID string) ([]Application, error) {
	query := `
		SELECT id, name, description, created_at
		FROM applications
		WHERE user_id = $1
		ORDER BY created_at DESC
	`
	rows, err := s.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []Application
	for rows.Next() {
		var a Application
		a.UserID = userID
		var desc *string // Handle nullable description
		if err := rows.Scan(&a.ID, &a.Name, &desc, &a.CreatedAt); err != nil {
			return nil, err
		}
		if desc != nil {
			a.Description = *desc
		}
		apps = append(apps, a)
	}
	return apps, nil
}

// GetApplication by ID
func (s *Store) GetApplication(ctx context.Context, appID string) (*Application, error) {
	query := `
		SELECT id, user_id, name, description, created_at
		FROM applications
		WHERE id = $1
	`
	var app Application
	var desc *string
	err := s.Pool.QueryRow(ctx, query, appID).Scan(&app.ID, &app.UserID, &app.Name, &desc, &app.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if desc != nil {
		app.Description = *desc
	}
	return &app, nil
}

// --- Incidents ---

func (s *Store) GetActiveIncident(ctx context.Context, serverID string, incidentType string) (*Incident, error) {
	query := `
		SELECT id, user_id, server_id, title, description, type, severity, status, created_at, resolved_at, assigned_to, resolution_notes 
		FROM incidents 
		WHERE server_id = $1 AND type = $2 AND status = 'active' 
		LIMIT 1
	`
	var i Incident
	if err := s.Pool.QueryRow(ctx, query, serverID, incidentType).Scan(&i.ID, &i.UserID, &i.ServerID, &i.Title, &i.Description, &i.Type, &i.Severity, &i.Status, &i.CreatedAt, &i.ResolvedAt, &i.AssignedTo, &i.ResolutionNotes); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &i, nil
}

func (s *Store) GetIncidentByID(ctx context.Context, incidentID, userID string) (*Incident, error) {
	query := `
		SELECT id, user_id, server_id, title, description, type, severity, status, created_at, resolved_at, assigned_to, resolution_notes
		FROM incidents
		WHERE id = $1 AND user_id = $2
	`
	var i Incident
	if err := s.Pool.QueryRow(ctx, query, incidentID, userID).Scan(&i.ID, &i.UserID, &i.ServerID, &i.Title, &i.Description, &i.Type, &i.Severity, &i.Status, &i.CreatedAt, &i.ResolvedAt, &i.AssignedTo, &i.ResolutionNotes); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &i, nil
}

func (s *Store) CreateIncident(ctx context.Context, inc *Incident) error {
	query := `
		INSERT INTO incidents (user_id, server_id, title, description, type, severity, status, resolved_at, assigned_to, resolution_notes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at
	`
	return s.Pool.QueryRow(ctx, query, inc.UserID, inc.ServerID, inc.Title, inc.Description, inc.Type, inc.Severity, inc.Status, inc.ResolvedAt, inc.AssignedTo, inc.ResolutionNotes).Scan(&inc.ID, &inc.CreatedAt)
}

func (s *Store) ListIncidents(ctx context.Context, userID string) ([]Incident, error) {
	query := `
		SELECT id, user_id, server_id, title, description, type, severity, status, created_at, resolved_at, assigned_to, resolution_notes 
		FROM incidents 
		WHERE user_id = $1 
		ORDER BY created_at DESC
	`
	rows, err := s.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var incidents []Incident
	for rows.Next() {
		var i Incident
		if err := rows.Scan(&i.ID, &i.UserID, &i.ServerID, &i.Title, &i.Description, &i.Type, &i.Severity, &i.Status, &i.CreatedAt, &i.ResolvedAt, &i.AssignedTo, &i.ResolutionNotes); err != nil {
			return nil, err
		}
		incidents = append(incidents, i)
	}
	return incidents, nil
}

func (s *Store) AssignIncident(ctx context.Context, incidentID, userID string, assignedTo *string) error {
	var query string
	if assignedTo == nil || *assignedTo == "" {
		query = `UPDATE incidents SET assigned_to = NULL WHERE id = $1 AND user_id = $2`
		_, err := s.Pool.Exec(ctx, query, incidentID, userID)
		return err
	}
	query = `UPDATE incidents SET assigned_to = $1 WHERE id = $2 AND user_id = $3`
	_, err := s.Pool.Exec(ctx, query, *assignedTo, incidentID, userID)
	return err
}

func (s *Store) UpdateIncidentStatus(ctx context.Context, incidentID, userID, status string, notes *string) error {
	var query string
	if status == "resolved" || status == "dismissed" {
		query = `UPDATE incidents SET status = $1, resolved_at = NOW(), resolution_notes = COALESCE($2, resolution_notes) WHERE id = $3 AND user_id = $4`
		_, err := s.Pool.Exec(ctx, query, status, notes, incidentID, userID)
		return err
	}
	query = `UPDATE incidents SET status = $1, resolution_notes = COALESCE($2, resolution_notes) WHERE id = $3 AND user_id = $4`
	_, err := s.Pool.Exec(ctx, query, status, notes, incidentID, userID)
	return err
}

// --- Blocked IPs (Firewall / IPS) ---

func (s *Store) CreateBlockedIP(ctx context.Context, userID string, serverID *string, ip, reason string) (*BlockedIP, error) {
	query := `
		INSERT INTO blocked_ips (user_id, server_id, ip, reason, status)
		VALUES ($1, $2, $3, $4, 'active')
		RETURNING id, created_at
	`
	var b BlockedIP
	b.UserID = userID
	b.ServerID = serverID
	b.IP = ip
	b.Reason = reason
	b.Status = "active"

	err := s.Pool.QueryRow(ctx, query, userID, serverID, ip, reason).Scan(&b.ID, &b.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func (s *Store) ListBlockedIPs(ctx context.Context, userID string) ([]BlockedIP, error) {
	query := `
		SELECT b.id, b.user_id, b.server_id, s.name, b.ip, b.reason, b.status, b.created_at
		FROM blocked_ips b
		LEFT JOIN servers s ON b.server_id = s.id
		WHERE b.user_id = $1 AND b.status = 'active'
		ORDER BY b.created_at DESC
	`
	rows, err := s.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blocks []BlockedIP
	for rows.Next() {
		var b BlockedIP
		var srvName *string
		if err := rows.Scan(&b.ID, &b.UserID, &b.ServerID, &srvName, &b.IP, &b.Reason, &b.Status, &b.CreatedAt); err != nil {
			return nil, err
		}
		if srvName != nil {
			b.ServerName = srvName
		}
		blocks = append(blocks, b)
	}
	return blocks, nil
}

func (s *Store) RemoveBlockedIP(ctx context.Context, userID, blockID string) (*BlockedIP, error) {
	query := `
		UPDATE blocked_ips 
		SET status = 'removed' 
		WHERE id = $1 AND user_id = $2
		RETURNING id, user_id, server_id, ip, reason, status, created_at
	`
	var b BlockedIP
	err := s.Pool.QueryRow(ctx, query, blockID, userID).Scan(&b.ID, &b.UserID, &b.ServerID, &b.IP, &b.Reason, &b.Status, &b.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &b, nil
}

// --- API Keys ---

func (s *Store) CreateAPIKey(ctx context.Context, userID, description string) (*APIKey, string, error) {
	rawKey, err := generateAPIKey()
	if err != nil {
		return nil, "", err
	}

	// Simple SHA256 hash for storage
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])

	var key APIKey
	query := `
		INSERT INTO api_keys (user_id, key_hash, description)
		VALUES ($1, $2, $3)
		RETURNING id, user_id, description, status, created_at`

	err = s.Pool.QueryRow(ctx, query, userID, keyHash, description).Scan(&key.ID, &key.UserID, &key.Description, &key.Status, &key.CreatedAt)
	if err != nil {
		return nil, "", err
	}

	return &key, rawKey, nil
}

func (s *Store) ListAPIKeys(ctx context.Context, userID string) ([]APIKey, error) {
	query := `SELECT id, user_id, description, status, created_at, last_used_at FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`
	rows, err := s.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Description, &k.Status, &k.CreatedAt, &k.LastUsedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// --- Commands (IPS) ---

type Command struct {
	ID         string     `json:"id"`
	ServerID   string     `json:"server_id"`
	Command    string     `json:"command"` // e.g., "block_ip"
	Args       string     `json:"args"`    // e.g., "192.168.1.50"
	Status     string     `json:"status"`  // pending, executed, failed
	CreatedAt  time.Time  `json:"created_at"`
	ExecutedAt *time.Time `json:"executed_at,omitempty"`
}

func (s *Store) CreateCommand(ctx context.Context, serverID, cmd, args string) error {
	query := `
		INSERT INTO commands (server_id, command, args, status)
		VALUES ($1, $2, $3, 'pending')
	`
	_, err := s.Pool.Exec(ctx, query, serverID, cmd, args)
	return err
}

func (s *Store) GetPendingCommands(ctx context.Context, serverID string) ([]Command, error) {
	query := `
		SELECT id, server_id, command, args, status, created_at
		FROM commands
		WHERE server_id = $1 AND status = 'pending'
		ORDER BY created_at ASC
	`
	rows, err := s.Pool.Query(ctx, query, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var commands []Command
	for rows.Next() {
		var c Command
		if err := rows.Scan(&c.ID, &c.ServerID, &c.Command, &c.Args, &c.Status, &c.CreatedAt); err != nil {
			return nil, err
		}
		commands = append(commands, c)
	}
	return commands, nil
}

func (s *Store) MarkCommandExecuted(ctx context.Context, commandID string) error {
	query := `UPDATE commands SET status = 'executed', executed_at = NOW() WHERE id = $1`
	_, err := s.Pool.Exec(ctx, query, commandID)
	return err
}
