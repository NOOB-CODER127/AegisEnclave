const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "default-secret-do-not-use-in-prod";

// --- Middleware ---
app.use(cors({
  origin: "http://localhost:3000",
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
  allowedHeaders: ["Origin", "Content-Type", "Accept", "Authorization"],
  credentials: true,
}));
app.use(express.json());

// --- Database Setup ---
const db = new Database(path.join(__dirname, "aegis.db"));
db.pragma("journal_mode = WAL");

function initializeSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT DEFAULT 'admin',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS servers (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      app_id TEXT,
      name TEXT NOT NULL,
      status TEXT DEFAULT 'offline',
      last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS applications (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS services (
      id TEXT PRIMARY KEY,
      server_id TEXT NOT NULL,
      name TEXT NOT NULL,
      status TEXT DEFAULT 'running',
      port INTEGER,
      FOREIGN KEY (server_id) REFERENCES servers(id)
    );

    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      server_id TEXT,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      type TEXT NOT NULL,
      severity TEXT NOT NULL,
      status TEXT DEFAULT 'active',
      assigned_to TEXT,
      resolution_notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      resolved_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS blocked_ips (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      server_id TEXT,
      ip TEXT NOT NULL,
      reason TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      key_prefix TEXT NOT NULL,
      description TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS commands (
      id TEXT PRIMARY KEY,
      server_id TEXT NOT NULL,
      type TEXT NOT NULL,
      payload TEXT,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      acked_at DATETIME,
      FOREIGN KEY (server_id) REFERENCES servers(id)
    );

    CREATE TABLE IF NOT EXISTS log_entries (
      id TEXT PRIMARY KEY,
      server_id TEXT NOT NULL,
      service TEXT,
      level TEXT DEFAULT 'info',
      message TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS metrics (
      id TEXT PRIMARY KEY,
      server_id TEXT NOT NULL,
      cpu_usage REAL DEFAULT 0,
      memory_usage REAL DEFAULT 0,
      memory_total REAL DEFAULT 0,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS threat_intel (
      id TEXT PRIMARY KEY,
      ip TEXT NOT NULL,
      reputation_score REAL DEFAULT 50,
      country TEXT DEFAULT 'Unknown',
      asn TEXT DEFAULT 'Unknown',
      org TEXT DEFAULT 'Unknown',
      threat_type TEXT DEFAULT 'unknown',
      first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
      tags TEXT DEFAULT '[]',
      whois_data TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id TEXT PRIMARY KEY,
      server_id TEXT,
      cve_id TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      cvss_score REAL DEFAULT 0,
      status TEXT DEFAULT 'open',
      found_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      remediation TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS compliance_frameworks (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      score INTEGER DEFAULT 0,
      total_checks INTEGER DEFAULT 0,
      passed_checks INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS compliance_checks (
      id TEXT PRIMARY KEY,
      framework_id TEXT NOT NULL,
      check_name TEXT NOT NULL,
      description TEXT DEFAULT '',
      status TEXT DEFAULT 'pending',
      last_checked DATETIME,
      FOREIGN KEY (framework_id) REFERENCES compliance_frameworks(id)
    );

    CREATE TABLE IF NOT EXISTS playbooks (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      trigger_type TEXT DEFAULT 'manual',
      trigger_config TEXT DEFAULT '{}',
      actions TEXT DEFAULT '[]',
      enabled INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS playbook_executions (
      id TEXT PRIMARY KEY,
      playbook_id TEXT NOT NULL,
      status TEXT DEFAULT 'running',
      triggered_by TEXT DEFAULT 'manual',
      result TEXT DEFAULT '',
      started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME,
      FOREIGN KEY (playbook_id) REFERENCES playbooks(id)
    );

    CREATE TABLE IF NOT EXISTS hunt_queries (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      query TEXT NOT NULL,
      description TEXT DEFAULT '',
      result_count INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

initializeSchema();

// --- Auth Middleware ---
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: "Authorization header required" });
  }

  const tokenString = authHeader.replace("Bearer ", "");
  try {
    const decoded = jwt.verify(tokenString, JWT_SECRET);
    req.userID = decoded.user_id;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// =============================================
// PUBLIC ROUTES
// =============================================

// --- Auth: Register ---
app.post("/api/v1/auth/register", (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ error: "email, password, and name are required" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "password must be at least 8 characters" });
  }

  // Check if user exists
  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) {
    return res.status(409).json({ error: "User already exists" });
  }

  // Hash password
  const passwordHash = bcrypt.hashSync(password, bcrypt.genSaltSync(10));

  // Create user
  const id = uuidv4();
  db.prepare("INSERT INTO users (id, email, password_hash, name, role) VALUES (?, ?, ?, ?, 'admin')")
    .run(id, email, passwordHash, name);

  res.status(201).json({ message: "User created", user_id: id });
});

// --- Auth: Login ---
app.post("/api/v1/auth/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign({ user_id: user.id }, JWT_SECRET, { expiresIn: "24h" });

  res.json({
    token,
    user: { name: user.name, email: user.email, role: user.role },
  });
});

// --- Health Check ---
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// --- Ingest Endpoints (stubs for agent compatibility) ---
app.post("/api/v1/ingest/logs", (req, res) => {
  const logs = Array.isArray(req.body) ? req.body : [req.body];
  const stmt = db.prepare("INSERT INTO log_entries (id, server_id, service, level, message, timestamp) VALUES (?, ?, ?, ?, ?, ?)");
  for (const log of logs) {
    stmt.run(
      log.id || uuidv4(),
      log.server_id || "unknown",
      log.service || "unknown",
      log.level || "info",
      log.message || "",
      log.timestamp || new Date().toISOString()
    );
  }
  res.status(201).json({ message: "Logs ingested", count: logs.length });
});

app.post("/api/v1/ingest/metrics", (req, res) => {
  const metrics = Array.isArray(req.body) ? req.body : [req.body];
  const stmt = db.prepare("INSERT INTO metrics (id, server_id, cpu_usage, memory_usage, memory_total, timestamp) VALUES (?, ?, ?, ?, ?, ?)");
  for (const m of metrics) {
    stmt.run(
      m.id || uuidv4(),
      m.server_id || "unknown",
      m.cpu_usage || 0,
      m.memory_usage || 0,
      m.memory_total || 0,
      m.timestamp || new Date().toISOString()
    );
  }
  res.status(201).json({ message: "Metrics ingested", count: metrics.length });
});

app.post("/api/v1/ingest/services", (req, res) => {
  const services = Array.isArray(req.body) ? req.body : [req.body];
  const stmt = db.prepare(
    "INSERT OR REPLACE INTO services (id, server_id, name, status, port) VALUES (?, ?, ?, ?, ?)"
  );
  for (const svc of services) {
    stmt.run(
      svc.id || uuidv4(),
      svc.server_id || "unknown",
      svc.name || "unknown",
      svc.status || "running",
      svc.port || 0
    );
  }
  res.status(201).json({ message: "Services ingested", count: services.length });
});

app.get("/api/v1/ingest/commands", (req, res) => {
  const serverId = req.query.server_id;
  let pending;
  if (serverId) {
    pending = db.prepare("SELECT * FROM commands WHERE server_id = ? AND status = 'pending'").all(serverId);
  } else {
    pending = db.prepare("SELECT * FROM commands WHERE status = 'pending'").all();
  }
  res.json(pending);
});

app.post("/api/v1/ingest/commands/:id/ack", (req, res) => {
  const cmd = db.prepare("SELECT * FROM commands WHERE id = ?").get(req.params.id);
  if (!cmd) {
    return res.status(404).json({ error: "Command not found" });
  }
  db.prepare("UPDATE commands SET status = 'acked', acked_at = CURRENT_TIMESTAMP WHERE id = ?").run(req.params.id);
  res.json({ message: "Command acknowledged" });
});

// =============================================
// PROTECTED ROUTES
// =============================================
app.use("/api/v1/logs", authMiddleware);
app.use("/api/v1/servers", authMiddleware);
app.use("/api/v1/infrastructure", authMiddleware);
app.use("/api/v1/dashboard", authMiddleware);
app.use("/api/v1/apps", authMiddleware);
app.use("/api/v1/team", authMiddleware);
app.use("/api/v1/incidents", authMiddleware);
app.use("/api/v1/firewall", authMiddleware);
app.use("/api/v1/security", authMiddleware);
app.use("/api/v1/settings", authMiddleware);
app.use("/api/v1/threat-intel", authMiddleware);
app.use("/api/v1/vulnerabilities", authMiddleware);
app.use("/api/v1/compliance", authMiddleware);
app.use("/api/v1/playbooks", authMiddleware);
app.use("/api/v1/hunt", authMiddleware);

// --- Logs ---
app.get("/api/v1/logs", (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const serverId = req.query.server_id;

  const servers = db.prepare("SELECT id FROM servers WHERE user_id = ?").all(req.userID);
  const serverIds = servers.map((s) => s.id);

  if (serverIds.length === 0) {
    return res.json({ logs: [] });
  }

  let logs;
  if (serverId) {
    if (!serverIds.includes(serverId)) {
      return res.status(403).json({ error: "Access denied to this server" });
    }
    logs = db.prepare("SELECT * FROM log_entries WHERE server_id = ? ORDER BY timestamp DESC LIMIT ?").all(serverId, limit);
  } else {
    const placeholders = serverIds.map(() => "?").join(",");
    logs = db.prepare(`SELECT * FROM log_entries WHERE server_id IN (${placeholders}) ORDER BY timestamp DESC LIMIT ?`)
      .all(...serverIds, limit);
  }

  res.json({ logs: logs || [] });
});

// --- Servers ---
app.get("/api/v1/servers", (req, res) => {
  const servers = db.prepare("SELECT * FROM servers WHERE user_id = ?").all(req.userID);
  res.json({ servers: servers || [] });
});

app.post("/api/v1/servers", (req, res) => {
  const { name, app_id } = req.body;
  if (!name) {
    return res.status(400).json({ error: "name is required" });
  }

  const id = uuidv4();
  db.prepare("INSERT INTO servers (id, user_id, app_id, name) VALUES (?, ?, ?, ?)")
    .run(id, req.userID, app_id || null, name);

  const server = db.prepare("SELECT * FROM servers WHERE id = ?").get(id);
  res.status(201).json(server);
});

app.get("/api/v1/servers/unassigned", (req, res) => {
  const servers = db.prepare("SELECT * FROM servers WHERE user_id = ? AND (app_id IS NULL OR app_id = '')").all(req.userID);
  res.json({ servers: servers || [] });
});

app.post("/api/v1/servers/assign", (req, res) => {
  const { server_id, app_id } = req.body;
  if (!server_id) {
    return res.status(400).json({ error: "server_id is required" });
  }
  db.prepare("UPDATE servers SET app_id = ? WHERE id = ? AND user_id = ?")
    .run(app_id || null, server_id, req.userID);
  res.json({ message: "Server assigned successfully" });
});

// --- Infrastructure Status ---
app.get("/api/v1/infrastructure/status", (req, res) => {
  const servers = db.prepare("SELECT * FROM servers WHERE user_id = ?").all(req.userID);

  if (servers.length === 0) {
    return res.json({ nodes: [] });
  }

  const nodes = servers.map((s) => {
    // Get latest metrics
    const metric = db.prepare("SELECT * FROM metrics WHERE server_id = ? ORDER BY timestamp DESC LIMIT 1").get(s.id);

    let status = "offline";
    let cpu = 0;
    let mem = 0;

    if (metric) {
      const lastSeen = new Date(metric.timestamp);
      const diffMs = Date.now() - lastSeen.getTime();
      if (diffMs < 60000) { // within 1 minute
        cpu = metric.cpu_usage;
        mem = metric.memory_usage;
        if (cpu > 90 || mem > 90) status = "critical";
        else if (cpu > 70 || mem > 70) status = "warning";
        else status = "online";
      }
    }

    return {
      id: s.id,
      name: s.name,
      status,
      cpu,
      memory: mem,
      last_seen: s.last_seen,
    };
  });

  res.json({ nodes });
});

// --- Dashboard Stats ---
app.get("/api/v1/dashboard/stats", (req, res) => {
  const servers = db.prepare("SELECT * FROM servers WHERE user_id = ?").all(req.userID);
  const serverIds = servers.map((s) => s.id);

  let events = [];
  let telemetry = [];

  if (serverIds.length > 0) {
    const placeholders = serverIds.map(() => "?").join(",");
    events = db.prepare(`SELECT * FROM log_entries WHERE server_id IN (${placeholders}) ORDER BY timestamp DESC LIMIT 50`)
      .all(...serverIds);
    telemetry = db.prepare(`SELECT * FROM metrics WHERE server_id IN (${placeholders}) ORDER BY timestamp DESC LIMIT 50`)
      .all(...serverIds);
  }

  // Format events
  const mappedEvents = (events || []).map((e, i) => {
    let type = "info";
    const level = (e.level || "").toLowerCase();
    if (["error", "critical"].includes(level)) type = "error";
    else if (["warn", "warning"].includes(level)) type = "warning";
    else if (level === "alert") type = "alert";

    return {
      id: `evt-${i}`,
      timestamp: e.timestamp,
      type,
      message: e.message,
      source: e.service,
    };
  });

  // Format telemetry
  const mappedTelemetry = (telemetry || []).map((t) => ({
    time: new Date(t.timestamp).toTimeString().slice(0, 5),
    cpu: t.cpu_usage,
    memory: t.memory_usage,
    memory_total: t.memory_total,
  }));

  res.json({
    events: mappedEvents || [],
    telemetry: mappedTelemetry || [],
  });
});

// --- Apps ---
app.post("/api/v1/apps", (req, res) => {
  const { name, description } = req.body;
  if (!name) {
    return res.status(400).json({ error: "name is required" });
  }

  const id = uuidv4();
  db.prepare("INSERT INTO applications (id, user_id, name, description) VALUES (?, ?, ?, ?)")
    .run(id, req.userID, name, description || "");

  const app = db.prepare("SELECT * FROM applications WHERE id = ?").get(id);
  res.status(201).json({ application: app });
});

app.get("/api/v1/apps", (req, res) => {
  const apps = db.prepare("SELECT * FROM applications WHERE user_id = ?").all(req.userID);
  res.json({ applications: apps || [] });
});

app.get("/api/v1/apps/:id", (req, res) => {
  const appRecord = db.prepare("SELECT * FROM applications WHERE id = ?").get(req.params.id);
  if (!appRecord) {
    return res.status(404).json({ error: "Application not found" });
  }
  if (appRecord.user_id !== req.userID) {
    return res.status(403).json({ error: "Access denied" });
  }

  const servers = db.prepare("SELECT * FROM servers WHERE user_id = ? AND app_id = ?").all(req.userID, req.params.id);
  const serversWithServices = (servers || []).map((s) => {
    const services = db.prepare("SELECT * FROM services WHERE server_id = ?").all(s.id);
    return { ...s, services: services || [] };
  });

  res.json({
    application: appRecord,
    servers: serversWithServices || [],
  });
});

app.get("/api/v1/apps/:id/stats", (req, res) => {
  const servers = db.prepare("SELECT * FROM servers WHERE user_id = ? AND app_id = ?").all(req.userID, req.params.id);
  const serverIds = servers.map((s) => s.id);

  let events = [];
  let telemetry = [];

  if (serverIds.length > 0) {
    const placeholders = serverIds.map(() => "?").join(",");
    events = db.prepare(`SELECT * FROM log_entries WHERE server_id IN (${placeholders}) ORDER BY timestamp DESC LIMIT 50`)
      .all(...serverIds);
    telemetry = db.prepare(`SELECT * FROM metrics WHERE server_id IN (${placeholders}) ORDER BY timestamp DESC LIMIT 50`)
      .all(...serverIds);
  }

  const mappedEvents = (events || []).map((e, i) => {
    let type = "info";
    const level = (e.level || "").toLowerCase();
    if (["error", "critical"].includes(level)) type = "error";
    else if (["warn", "warning"].includes(level)) type = "warning";
    else if (level === "alert") type = "alert";
    return { id: `evt-${i}`, timestamp: e.timestamp, type, message: e.message, source: e.service };
  });

  const mappedTelemetry = (telemetry || []).map((t) => ({
    time: new Date(t.timestamp).toTimeString().slice(0, 5),
    cpu: t.cpu_usage,
    memory: t.memory_usage,
    memory_total: t.memory_total,
  }));

  res.json({ events: mappedEvents || [], telemetry: mappedTelemetry || [] });
});

// --- Team ---
app.get("/api/v1/team/members", (req, res) => {
  const members = db.prepare("SELECT id, email, name, role, created_at FROM users").all();
  res.json(members || []);
});

app.post("/api/v1/team/invite", (req, res) => {
  const { email, role } = req.body;
  if (!email || !role) {
    return res.status(400).json({ error: "email and role are required" });
  }

  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) {
    return res.status(409).json({ error: "User already exists" });
  }

  const tempPassword = "welcome123";
  const passwordHash = bcrypt.hashSync(tempPassword, bcrypt.genSaltSync(10));
  const id = uuidv4();
  db.prepare("INSERT INTO users (id, email, password_hash, name, role) VALUES (?, ?, ?, ?, ?)")
    .run(id, email, passwordHash, "Invited User", role);

  const user = db.prepare("SELECT id, email, name, role, created_at FROM users WHERE id = ?").get(id);
  res.status(201).json(user);
});

// --- Incidents ---
app.get("/api/v1/incidents", (req, res) => {
  const incidents = db.prepare("SELECT * FROM incidents WHERE user_id = ? ORDER BY created_at DESC").all(req.userID);
  res.json(incidents || []);
});

app.post("/api/v1/incidents", (req, res) => {
  const { server_id, title, description, type, severity, status } = req.body;
  if (!title || !type || !severity) {
    return res.status(400).json({ error: "title, type, and severity are required" });
  }

  const id = uuidv4();
  db.prepare(
    "INSERT INTO incidents (id, user_id, server_id, title, description, type, severity, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).run(id, req.userID, server_id || null, title, description || "", type, severity, status || "active");

  const incident = db.prepare("SELECT * FROM incidents WHERE id = ?").get(id);
  res.status(201).json(incident);
});

app.post("/api/v1/incidents/:id/assign", (req, res) => {
  const { assigned_to } = req.body;
  const incident = db.prepare("SELECT * FROM incidents WHERE id = ? AND user_id = ?").get(req.params.id, req.userID);
  if (!incident) {
    return res.status(404).json({ error: "Incident not found" });
  }

  db.prepare("UPDATE incidents SET assigned_to = ? WHERE id = ?").run(assigned_to || null, req.params.id);
  res.json({ message: "Incident assigned successfully" });
});

app.patch("/api/v1/incidents/:id/status", (req, res) => {
  const { status, resolution_notes } = req.body;
  if (!status) {
    return res.status(400).json({ error: "status is required" });
  }

  const incident = db.prepare("SELECT * FROM incidents WHERE id = ? AND user_id = ?").get(req.params.id, req.userID);
  if (!incident) {
    return res.status(404).json({ error: "Incident not found" });
  }

  const isResolved = ["resolved", "dismissed"].includes(status.toLowerCase());
  if (isResolved) {
    db.prepare("UPDATE incidents SET status = ?, resolution_notes = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?")
      .run(status, resolution_notes || null, req.params.id);
  } else {
    db.prepare("UPDATE incidents SET status = ?, resolution_notes = ? WHERE id = ?")
      .run(status, resolution_notes || null, req.params.id);
  }

  res.json({ message: "Incident status updated successfully" });
});

app.post("/api/v1/incidents/:id/mitigate", (req, res) => {
  const { action, ip, notes } = req.body;
  const incident = db.prepare("SELECT * FROM incidents WHERE id = ? AND user_id = ?").get(req.params.id, req.userID);
  if (!incident) {
    return res.status(404).json({ error: "Incident not found" });
  }

  // Try to extract IP from description
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
  let ipToBlock = ip || "";
  if (!ipToBlock && incident.description) {
    const match = incident.description.match(ipRegex);
    if (match) ipToBlock = match[0];
  }

  let blocked = false;
  if (ipToBlock && incident.server_id) {
    // Create block command and record
    db.prepare("INSERT INTO commands (id, server_id, type, payload) VALUES (?, ?, 'block_ip', ?)")
      .run(uuidv4(), incident.server_id, ipToBlock);
    db.prepare("INSERT INTO blocked_ips (id, user_id, server_id, ip, reason) VALUES (?, ?, ?, ?, ?)")
      .run(uuidv4(), req.userID, incident.server_id, ipToBlock, `Mitigated from incident: ${incident.title}`);
    blocked = true;
  }

  let mitigationNotes = "Mitigated threat automatically";
  if (blocked) {
    mitigationNotes = `Mitigated threat and blocked attacker IP: ${ipToBlock}`;
  }
  if (notes) {
    mitigationNotes += `. Notes: ${notes}`;
  }

  db.prepare("UPDATE incidents SET status = 'resolved', resolution_notes = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?")
    .run(mitigationNotes, req.params.id);

  res.json({
    message: "Threat mitigation executed successfully",
    blocked,
    ip: ipToBlock,
    status: "resolved",
    notes: mitigationNotes,
  });
});

// --- Firewall ---
app.get("/api/v1/firewall/blocks", (req, res) => {
  const blocks = db.prepare("SELECT * FROM blocked_ips WHERE user_id = ? ORDER BY created_at DESC").all(req.userID);
  res.json({ blocks: blocks || [] });
});

app.post("/api/v1/firewall/block", (req, res) => {
  const { server_id, ip, reason } = req.body;
  if (!ip) {
    return res.status(400).json({ error: "ip is required" });
  }

  const blockReason = reason || "Manual block via Aegis Firewall";
  const id = uuidv4();
  db.prepare("INSERT INTO blocked_ips (id, user_id, server_id, ip, reason) VALUES (?, ?, ?, ?, ?)")
    .run(id, req.userID, server_id || null, ip, blockReason);

  // Queue block commands
  if (server_id && server_id !== "all") {
    db.prepare("INSERT INTO commands (id, server_id, type, payload) VALUES (?, ?, 'block_ip', ?)")
      .run(uuidv4(), server_id, ip);
  } else {
    const servers = db.prepare("SELECT id FROM servers WHERE user_id = ?").all(req.userID);
    const stmt = db.prepare("INSERT INTO commands (id, server_id, type, payload) VALUES (?, ?, 'block_ip', ?)");
    for (const s of servers) {
      stmt.run(uuidv4(), s.id, ip);
    }
  }

  const block = db.prepare("SELECT * FROM blocked_ips WHERE id = ?").get(id);
  res.status(201).json(block);
});

app.delete("/api/v1/firewall/blocks/:id", (req, res) => {
  const block = db.prepare("SELECT * FROM blocked_ips WHERE id = ? AND user_id = ?").get(req.params.id, req.userID);
  if (!block) {
    return res.status(404).json({ error: "Block rule not found" });
  }

  db.prepare("DELETE FROM blocked_ips WHERE id = ?").run(req.params.id);

  // Queue unblock commands
  if (block.server_id) {
    db.prepare("INSERT INTO commands (id, server_id, type, payload) VALUES (?, ?, 'unblock_ip', ?)")
      .run(uuidv4(), block.server_id, block.ip);
  } else {
    const servers = db.prepare("SELECT id FROM servers WHERE user_id = ?").all(req.userID);
    const stmt = db.prepare("INSERT INTO commands (id, server_id, type, payload) VALUES (?, ?, 'unblock_ip', ?)");
    for (const s of servers) {
      stmt.run(uuidv4(), s.id, block.ip);
    }
  }

  res.json({ message: "IP rule removed and unblock command dispatched", block });
});

// Also support POST /unblock for frontend compatibility
app.post("/api/v1/firewall/unblock", (req, res) => {
  const { block_id } = req.body;
  if (!block_id) {
    return res.status(400).json({ error: "block_id is required" });
  }

  const block = db.prepare("SELECT * FROM blocked_ips WHERE id = ? AND user_id = ?").get(block_id, req.userID);
  if (!block) {
    return res.status(404).json({ error: "Block rule not found" });
  }

  db.prepare("DELETE FROM blocked_ips WHERE id = ?").run(block_id);
  res.json({ message: "IP rule removed", block });
});

// --- Security Stats ---
app.get("/api/v1/security/stats", (req, res) => {
  const incidents = db.prepare("SELECT * FROM incidents WHERE user_id = ?").all(req.userID);
  const servers = db.prepare("SELECT * FROM servers WHERE user_id = ?").all(req.userID);
  const blockedIPs = db.prepare("SELECT * FROM blocked_ips WHERE user_id = ?").all(req.userID);

  const serverMap = {};
  let offlineServers = 0;
  const now = new Date();
  for (const s of servers) {
    serverMap[s.id] = s.name;
    if (s.status === "offline" || (now - new Date(s.last_seen)) > 120000) {
      offlineServers++;
    }
  }

  // Counters
  let activeIncidents = 0, resolvedIncidents = 0;
  let criticalIncidents = 0, highIncidents = 0, mediumIncidents = 0, lowIncidents = 0;
  let totalResolutionTime = 0, resolvedCount = 0;

  const vectorCounts = {};
  const targetCounts = {};
  const threatActorCounts = {};

  // 24h timeline
  const timelineBuckets = [];
  for (let i = 0; i < 24; i++) {
    const t = new Date(now.getTime() - (23 - i) * 3600000);
    let label = t.toLocaleTimeString("en-US", { hour: "numeric", hour12: true });
    timelineBuckets.push({ hour: t.getHours(), label, count: 0 });
  }

  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

  for (const inc of incidents) {
    const isResolved = ["resolved", "dismissed"].includes((inc.status || "").toLowerCase());
    if (isResolved) {
      resolvedIncidents++;
      if (inc.resolved_at) {
        const dur = new Date(inc.resolved_at) - new Date(inc.created_at);
        if (dur > 0) {
          totalResolutionTime += dur;
          resolvedCount++;
        }
      }
    } else {
      activeIncidents++;
      switch ((inc.severity || "").toUpperCase()) {
        case "CRITICAL": criticalIncidents++; break;
        case "HIGH": highIncidents++; break;
        case "MEDIUM": mediumIncidents++; break;
        case "LOW": lowIncidents++; break;
        default: highIncidents++;
      }
    }

    const vType = inc.type || inc.title;
    vectorCounts[vType] = (vectorCounts[vType] || 0) + 1;

    if (inc.server_id) {
      targetCounts[inc.server_id] = (targetCounts[inc.server_id] || 0) + 1;
    }

    const ipMatch = (inc.description || "").match(ipRegex);
    if (ipMatch) {
      threatActorCounts[ipMatch[0]] = (threatActorCounts[ipMatch[0]] || 0) + 1;
    }

    // 24h timeline
    const diffHours = (now - new Date(inc.created_at)) / 3600000;
    if (diffHours >= 0 && diffHours < 24) {
      const idx = 23 - Math.floor(diffHours);
      if (idx >= 0 && idx < 24) {
        timelineBuckets[idx].count++;
      }
    }
  }

  const avgMTTRMinutes = resolvedCount > 0 ? Math.round(totalResolutionTime / 60000 / resolvedCount) : 0;

  // Health score
  let score = 100;
  score -= criticalIncidents * 18;
  score -= highIncidents * 10;
  score -= mediumIncidents * 4;
  score -= lowIncidents * 1;
  score -= offlineServers * 6;
  score = Math.max(0, Math.min(100, score));

  // Build attack vectors
  const attackVectors = Object.entries(vectorCounts).map(([name, count]) => {
    let severity = "MEDIUM", color = "#3b82f6";
    const lower = name.toLowerCase();
    if (["injection", "rce", "code execution"].some((w) => lower.includes(w))) { severity = "CRITICAL"; color = "#ef4444"; }
    else if (["xss", "traversal", "brute"].some((w) => lower.includes(w))) { severity = "HIGH"; color = "#f59e0b"; }
    else if (["scan", "recon"].some((w) => lower.includes(w))) { severity = "LOW"; color = "#10b981"; }
    return { name, count, severity, color };
  }).sort((a, b) => b.count - a.count);

  // Build top targets
  const topTargets = Object.entries(targetCounts).map(([serverId, count]) => ({
    server_id: serverId,
    server_name: serverMap[serverId] || `Server ${serverId.slice(0, 8)}`,
    count,
  })).sort((a, b) => b.count - a.count);

  // Build top threat actors
  const topThreatActors = Object.entries(threatActorCounts).map(([ip, count]) => ({
    ip,
    count,
    country: "External",
    classification: "Threat Origin",
  })).sort((a, b) => b.count - a.count);

  res.json({
    health_score: score,
    metrics: {
      total_incidents: incidents.length,
      active_incidents: activeIncidents,
      resolved_incidents: resolvedIncidents,
      critical_incidents: criticalIncidents,
      high_incidents: highIncidents,
      attacks_blocked: blockedIPs.length,
      mttr_minutes: avgMTTRMinutes,
      mttd_seconds: 3.2,
    },
    attack_vectors: attackVectors,
    top_targets: topTargets,
    top_threat_actors: topThreatActors,
    timeline_24h: timelineBuckets,
  });
});

// --- Settings / API Keys ---
app.get("/api/v1/settings/apikeys", (req, res) => {
  const keys = db.prepare("SELECT id, user_id, key_prefix, description, created_at FROM api_keys WHERE user_id = ?").all(req.userID);
  res.json(keys || []);
});

app.post("/api/v1/settings/apikeys", (req, res) => {
  const { description } = req.body;
  const desc = description || "New API Key";

  const rawKey = `aegis_${uuidv4().replace(/-/g, "")}`;
  const keyHash = bcrypt.hashSync(rawKey, bcrypt.genSaltSync(10));
  const keyPrefix = rawKey.slice(0, 12) + "...";
  const id = uuidv4();

  db.prepare("INSERT INTO api_keys (id, user_id, key_hash, key_prefix, description) VALUES (?, ?, ?, ?, ?)")
    .run(id, req.userID, keyHash, keyPrefix, desc);

  res.status(201).json({
    meta: { id, user_id: req.userID, key_prefix: keyPrefix, description: desc, created_at: new Date().toISOString() },
    key: rawKey,
  });
});

// =============================================
// NEW FEATURES: Threat Intelligence, Vulnerability Scanner, Compliance, SOAR, Threat Hunting
// =============================================

// --- Threat Intelligence Feed ---
app.get("/api/v1/threat-intel", (req, res) => {
  const intel = db.prepare("SELECT * FROM threat_intel ORDER BY last_seen DESC").all();
  res.json(intel || []);
});

app.post("/api/v1/threat-intel/lookup", (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: "ip is required" });

  // Check if we already have intel for this IP
  let existing = db.prepare("SELECT * FROM threat_intel WHERE ip = ?").get(ip);
  if (existing) {
    // Update last_seen
    db.prepare("UPDATE threat_intel SET last_seen = CURRENT_TIMESTAMP WHERE ip = ?").run(ip);
    return res.json(existing);
  }

  // Simulate threat intelligence enrichment
  const countries = ["Russia", "China", "North Korea", "Iran", "Brazil", "India", "USA", "Germany", "Netherlands", "Romania"];
  const orgs = ["Evil Corp", "APT28", "Lazarus Group", "Unknown ISP", "DigitalOcean", "OVH", "Amazon AWS", "Cloudflare"];
  const threatTypes = ["scanner", "brute_force", "malware_c2", "phishing", "ddos", "reconnaissance"];
  const tags = [["known-attacker"], ["botnet"], ["proxy"], ["tor-exit"], ["vpn"], []];

  const score = Math.floor(Math.random() * 100);
  const country = countries[Math.floor(Math.random() * countries.length)];
  const org = orgs[Math.floor(Math.random() * orgs.length)];
  const threatType = threatTypes[Math.floor(Math.random() * threatTypes.length)];
  const tagSet = tags[Math.floor(Math.random() * tags.length)];
  const asn = `AS${Math.floor(Math.random() * 90000) + 10000}`;

  const id = uuidv4();
  db.prepare(`INSERT INTO threat_intel (id, ip, reputation_score, country, asn, org, threat_type, tags)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, ip, score, country, asn, org, threatType, JSON.stringify(tagSet));

  const result = db.prepare("SELECT * FROM threat_intel WHERE id = ?").get(id);
  res.status(201).json(result);
});

app.get("/api/v1/threat-intel/:ip", (req, res) => {
  const intel = db.prepare("SELECT * FROM threat_intel WHERE ip = ?").get(req.params.ip);
  if (!intel) return res.status(404).json({ error: "IP not found in threat intel database" });
  res.json(intel);
});

// --- Vulnerability Scanner ---
app.get("/api/v1/vulnerabilities", (req, res) => {
  const vulns = db.prepare("SELECT v.*, s.name as server_name FROM vulnerabilities v LEFT JOIN servers s ON v.server_id = s.id ORDER BY v.found_at DESC").all();
  res.json(vulns || []);
});

app.post("/api/v1/vulnerabilities/scan", (req, res) => {
  const { server_id } = req.body;
  const servers = server_id
    ? db.prepare("SELECT * FROM servers WHERE id = ? AND user_id = ?").all(server_id, req.userID)
    : db.prepare("SELECT * FROM servers WHERE user_id = ?").all(req.userID);

  if (servers.length === 0) return res.json({ message: "No servers to scan", vulnerabilities: [] });

  // Simulate vulnerability scan results
  const cvePool = [
    { cve: "CVE-2024-3094", severity: "CRITICAL", title: "XZ Utils Backdoor", desc: "Malicious backdoor in XZ Utils compression library allowing unauthorized SSH access.", cvss: 10.0, fix: "Update xz-utils to patched version or downgrade to 5.4.x" },
    { cve: "CVE-2024-21762", severity: "CRITICAL", title: "FortiOS Out-of-Bound Write", desc: "Fortinet FortiOS contains an out-of-bound write vulnerability in SSL VPN.", cvss: 9.8, fix: "Apply FortiOS patch 7.2.5 or later" },
    { cve: "CVE-2023-44487", severity: "HIGH", title: "HTTP/2 Rapid Reset DDoS", desc: "HTTP/2 protocol vulnerability enabling amplified DDoS attacks.", cvss: 7.5, fix: "Update web server and apply rate limiting" },
    { cve: "CVE-2023-46747", severity: "HIGH", title: "F5 BIG-IP Auth Bypass", desc: "Authentication bypass vulnerability in F5 BIG-IP configuration utility.", cvss: 9.8, fix: "Apply F5 hotfix or upgrade to patched version" },
    { cve: "CVE-2024-0012", severity: "CRITICAL", title: "PAN-OS Auth Bypass", desc: "Palo Alto Networks PAN-OS management interface authentication bypass.", cvss: 9.3, fix: "Update PAN-OS to latest patched version" },
    { cve: "CVE-2023-36884", severity: "MEDIUM", title: "Microsoft Office RCE", desc: "Remote code execution through crafted Office documents.", cvss: 6.8, fix: "Apply Microsoft security update" },
    { cve: "CVE-2023-22527", severity: "HIGH", title: "Confluence Template Injection", desc: "Atlassian Confluence Server template injection leading to RCE.", cvss: 8.6, fix: "Update Confluence to latest version" },
    { cve: "CVE-2024-23897", severity: "CRITICAL", title: "Jenkins Arbitrary File Read", desc: "Jenkins CLI allows arbitrary file read via crafted HTTP requests.", cvss: 9.8, fix: "Update Jenkins to 2.442+ or LTS 2.426.3+" },
    { cve: "CVE-2023-4966", severity: "CRITICAL", title: "Citrix Bleed", desc: "Sensitive information disclosure in Citrix NetScaler ADC/Gateway.", cvss: 9.4, fix: "Apply Citrix security update and rotate sessions" },
    { cve: "CVE-2024-1709", severity: "CRITICAL", title: "ConnectWise ScreenConnect Auth Bypass", desc: "Authentication bypass in ScreenConnect allowing unauthorized access.", cvss: 10.0, fix: "Update to ScreenConnect 23.9.8 or later" }
  ];

  const found = [];
  for (const srv of servers) {
    const numVulns = Math.floor(Math.random() * 4) + 1;
    const shuffled = [...cvePool].sort(() => Math.random() - 0.5).slice(0, numVulns);
    for (const v of shuffled) {
      const id = uuidv4();
      db.prepare(`INSERT INTO vulnerabilities (id, server_id, cve_id, severity, title, description, cvss_score, remediation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(id, srv.id, v.cve, v.severity, v.title, v.desc, v.cvss, v.fix);
      found.push({ id, server_id: srv.id, server_name: srv.name, ...v });
    }
  }

  res.json({ message: `Scan complete. Found ${found.length} vulnerabilities.`, vulnerabilities: found });
});

app.patch("/api/v1/vulnerabilities/:id", (req, res) => {
  const { status } = req.body;
  if (!status) return res.status(400).json({ error: "status is required" });
  db.prepare("UPDATE vulnerabilities SET status = ? WHERE id = ?").run(status, req.params.id);
  res.json({ message: "Vulnerability updated" });
});

// --- Compliance Dashboard ---
app.get("/api/v1/compliance", (req, res) => {
  const frameworks = db.prepare("SELECT * FROM compliance_frameworks").all();
  const result = frameworks.map((fw) => {
    const checks = db.prepare("SELECT * FROM compliance_checks WHERE framework_id = ?").all(fw.id);
    return { ...fw, checks };
  });
  res.json(result || []);
});

app.post("/api/v1/compliance/scan", (req, res) => {
  // Initialize frameworks if empty
  const existing = db.prepare("SELECT COUNT(*) as cnt FROM compliance_frameworks").get();
  if (existing.cnt === 0) {
    const frameworks = [
      { id: uuidv4(), name: "SOC 2 Type II", desc: "Service Organization Control 2 - Security, Availability, Processing Integrity, Confidentiality, Privacy" },
      { id: uuidv4(), name: "ISO 27001", desc: "Information Security Management System standard" },
      { id: uuidv4(), name: "PCI DSS v4.0", desc: "Payment Card Industry Data Security Standard" },
      { id: uuidv4(), name: "NIST CSF", desc: "NIST Cybersecurity Framework - Identify, Protect, Detect, Respond, Recover" },
    ];

    const checks = {
      0: [
        { name: "Access Control Policy", desc: "Role-based access control enforced across all systems" },
        { name: "Encryption at Rest", desc: "AES-256 encryption for data at rest" },
        { name: "Encryption in Transit", desc: "TLS 1.3 for all data in transit" },
        { name: "Incident Response Plan", desc: "Documented IR plan with defined roles" },
        { name: "Audit Logging", desc: "Comprehensive audit trail for all access" },
        { name: "Vulnerability Management", desc: "Regular vulnerability scanning and remediation" },
        { name: "Change Management", desc: "Formal change control process" },
        { name: "Data Retention Policy", desc: "Defined data retention and disposal procedures" },
      ],
      1: [
        { name: "ISMS Scope", desc: "Information Security Management System scope defined" },
        { name: "Risk Assessment", desc: "Regular risk assessments conducted" },
        { name: "Security Policies", desc: "Information security policies documented" },
        { name: "Asset Management", desc: "Asset inventory and classification" },
        { name: "Access Control", desc: "Access rights management process" },
        { name: "Cryptographic Controls", desc: "Use of cryptography for data protection" },
        { name: "Physical Security", desc: "Physical entry controls and security" },
        { name: "Operations Security", desc: "Protection against malware and backup" },
      ],
      2: [
        { name: "Firewall Configuration", desc: "Firewall rules restrict cardholder data access" },
        { name: "Default Passwords Changed", desc: "All vendor-supplied defaults changed" },
        { name: "Cardholder Data Encryption", desc: "PAN rendered unreadable anywhere stored" },
        { name: "Anti-Malware", desc: "Anti-malware mechanisms deployed and updated" },
        { name: "Secure Development", desc: "Secure coding practices for custom software" },
        { name: "Penetration Testing", desc: "Regular penetration testing conducted" },
        { name: "Security Training", desc: "Security awareness training for all personnel" },
      ],
      3: [
        { name: "Asset Management", desc: "Physical and software assets identified" },
        { name: "Access Control", desc: "Access rights and privileges managed" },
        { name: "Awareness & Training", desc: "Security awareness program in place" },
        { name: "Data Security", desc: "Data at rest and in transit protected" },
        { name: "Monitoring & Detection", desc: "Continuous monitoring and anomaly detection" },
        { name: "Recovery Planning", desc: "Recovery processes and procedures tested" },
      ]
    };

    for (const fw of frameworks) {
      db.prepare("INSERT INTO compliance_frameworks (id, name, description) VALUES (?, ?, ?)").run(fw.id, fw.name, fw.desc);
      const fwChecks = checks[frameworks.indexOf(fw)] || [];
      for (const check of fwChecks) {
        const passed = Math.random() > 0.3;
        db.prepare("INSERT INTO compliance_checks (id, framework_id, check_name, description, status, last_checked) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)")
          .run(uuidv4(), fw.id, check.name, check.desc, passed ? "passed" : "failed");
      }
    }
  }

  // Update scores
  const frameworks2 = db.prepare("SELECT * FROM compliance_frameworks").all();
  for (const fw of frameworks2) {
    const checks = db.prepare("SELECT * FROM compliance_checks WHERE framework_id = ?").all(fw.id);
    const passed = checks.filter((c) => c.status === "passed").length;
    const total = checks.length;
    const score = total > 0 ? Math.round((passed / total) * 100) : 0;
    db.prepare("UPDATE compliance_frameworks SET score = ?, total_checks = ?, passed_checks = ? WHERE id = ?")
      .run(score, total, passed, fw.id);
  }

  const result = db.prepare("SELECT * FROM compliance_frameworks").all().map((fw) => {
    const checks = db.prepare("SELECT * FROM compliance_checks WHERE framework_id = ?").all(fw.id);
    return { ...fw, checks };
  });

  res.json({ message: "Compliance scan completed", frameworks: result });
});

app.patch("/api/v1/compliance/checks/:id", (req, res) => {
  const { status } = req.body;
  if (!status) return res.status(400).json({ error: "status is required" });
  db.prepare("UPDATE compliance_checks SET status = ?, last_checked = CURRENT_TIMESTAMP WHERE id = ?")
    .run(status, req.params.id);

  // Recalculate framework score
  const check = db.prepare("SELECT framework_id FROM compliance_checks WHERE id = ?").get(req.params.id);
  if (check) {
    const checks = db.prepare("SELECT * FROM compliance_checks WHERE framework_id = ?").all(check.framework_id);
    const passed = checks.filter((c) => c.status === "passed").length;
    const total = checks.length;
    const score = total > 0 ? Math.round((passed / total) * 100) : 0;
    db.prepare("UPDATE compliance_frameworks SET score = ?, total_checks = ?, passed_checks = ? WHERE id = ?")
      .run(score, total, passed, check.framework_id);
  }

  res.json({ message: "Check updated" });
});

// --- SOAR Playbooks ---
app.get("/api/v1/playbooks", (req, res) => {
  const playbooks = db.prepare("SELECT * FROM playbooks WHERE user_id = ? ORDER BY created_at DESC").all(req.userID);
  const result = playbooks.map((pb) => {
    const executions = db.prepare("SELECT * FROM playbook_executions WHERE playbook_id = ? ORDER BY started_at DESC LIMIT 5").all(pb.id);
    return { ...pb, actions: JSON.parse(pb.actions || "[]"), trigger_config: JSON.parse(pb.trigger_config || "{}"), recent_executions: executions };
  });
  res.json(result || []);
});

app.post("/api/v1/playbooks", (req, res) => {
  const { name, description, trigger_type, trigger_config, actions } = req.body;
  if (!name) return res.status(400).json({ error: "name is required" });

  const id = uuidv4();
  db.prepare("INSERT INTO playbooks (id, user_id, name, description, trigger_type, trigger_config, actions) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run(id, req.userID, name, description || "", trigger_type || "manual", JSON.stringify(trigger_config || {}), JSON.stringify(actions || []));

  const playbook = db.prepare("SELECT * FROM playbooks WHERE id = ?").get(id);
  res.status(201).json({ ...playbook, actions: JSON.parse(playbook.actions), trigger_config: JSON.parse(playbook.trigger_config) });
});

app.patch("/api/v1/playbooks/:id", (req, res) => {
  const { enabled } = req.body;
  if (enabled !== undefined) {
    db.prepare("UPDATE playbooks SET enabled = ? WHERE id = ? AND user_id = ?").run(enabled ? 1 : 0, req.params.id, req.userID);
  }
  res.json({ message: "Playbook updated" });
});

app.post("/api/v1/playbooks/:id/execute", (req, res) => {
  const playbook = db.prepare("SELECT * FROM playbooks WHERE id = ? AND user_id = ?").get(req.params.id, req.userID);
  if (!playbook) return res.status(404).json({ error: "Playbook not found" });

  const execId = uuidv4();
  db.prepare("INSERT INTO playbook_executions (id, playbook_id, status, triggered_by) VALUES (?, ?, 'running', 'manual')")
    .run(execId, playbook.id);

  // Simulate execution (complete immediately for demo)
  const actions = JSON.parse(playbook.actions || "[]");
  const results = actions.map((a) => ({ action: a.type || a.name, status: "completed", timestamp: new Date().toISOString() }));

  db.prepare("UPDATE playbook_executions SET status = 'completed', result = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?")
    .run(JSON.stringify(results), execId);

  res.json({ message: "Playbook executed successfully", execution_id: execId, results });
});

app.get("/api/v1/playbooks/:id/executions", (req, res) => {
  const executions = db.prepare("SELECT * FROM playbook_executions WHERE playbook_id = ? ORDER BY started_at DESC").all(req.params.id);
  res.json(executions || []);
});

// --- Threat Hunting ---
app.get("/api/v1/hunt", (req, res) => {
  const { query, server_id, level, from, to, limit: lim } = req.query;
  const limitNum = parseInt(lim) || 200;

  const servers = db.prepare("SELECT id FROM servers WHERE user_id = ?").all(req.userID);
  const serverIds = servers.map((s) => s.id);
  if (serverIds.length === 0) return res.json({ results: [], total: 0 });

  const placeholders = serverIds.map(() => "?").join(",");
  let sql = `SELECT * FROM log_entries WHERE server_id IN (${placeholders})`;
  const params = [...serverIds];

  if (query) {
    sql += ` AND message LIKE ?`;
    params.push(`%${query}%`);
  }
  if (server_id) {
    sql = sql.replace(`server_id IN (${placeholders})`, `server_id = ?`);
    params.length = 0;
    params.push(server_id);
    if (query) {
      sql += ` AND message LIKE ?`;
      params.push(`%${query}%`);
    }
  }
  if (level) {
    sql += ` AND level = ?`;
    params.push(level);
  }
  if (from) {
    sql += ` AND timestamp >= ?`;
    params.push(from);
  }
  if (to) {
    sql += ` AND timestamp <= ?`;
    params.push(to);
  }

  sql += ` ORDER BY timestamp DESC LIMIT ?`;
  params.push(limitNum);

  const results = db.prepare(sql).all(...params);

  // Save query for history
  db.prepare("INSERT INTO hunt_queries (id, user_id, query, description, result_count) VALUES (?, ?, ?, ?, ?)")
    .run(uuidv4(), req.userID, query || "*", `Server: ${server_id || 'all'}, Level: ${level || 'all'}`, results.length);

  res.json({ results: results || [], total: results.length });
});

app.get("/api/v1/hunt/history", (req, res) => {
  const history = db.prepare("SELECT * FROM hunt_queries WHERE user_id = ? ORDER BY created_at DESC LIMIT 50").all(req.userID);
  res.json(history || []);
});

// =============================================
// START SERVER
// =============================================
app.listen(PORT, () => {
  console.log(`🚀 Aegis Backend running on http://localhost:${PORT}`);
  console.log(`📋 Health check: http://localhost:${PORT}/health`);
  console.log(`🔐 Auth endpoints: POST /api/v1/auth/register, POST /api/v1/auth/login`);
});
