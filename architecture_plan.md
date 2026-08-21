# Aegis Defender - Architecture & Roadmap

## 1. Product Vision
**"The DevOps & Security Engineer in a Box"**
For agencies and freelancers who build on VPS (DigitalOcean, Linode) or bare metal but lack the time/budget for Splunk, Datadog, or a dedicated SOC.

## 2. Core Architecture
The system consists of three main pillars:

### A. The Aegis Eye (Agent/Sidecar)
A lightweight binary (written in **Go** or **Rust**) that runs on the server.
*   **Role**: The "Eyes and Ears".
*   **Capabilities**:
    *   **Log Tailing**: auto-detects `/var/log/nginx`, `/var/log/syslog`, Docker logs.
    *   **Host Metrics**: CPU, RAM, Disk, Network I/O.
    *   **Intrusion Detection**: Monitors critical file changes (`/etc/passwd`, ssh keys) and suspicious process spawning.
    *   **Network Guard**: Manages `iptables` or `nftables` to ban IPs dynamically.

### B. The Aegis Shield (SDK)
A language-specific library (Node.js, Python, PHP, Go) integrated into the user's application.
*   **Role**: The "Inside Man".
*   **Capabilities**:
    *   **APM (Application Performance Monitoring)**: Request latency, error rates, database query times.
    *   **WAF (Web Application Firewall)**: Inspects incoming HTTP requests for SQLi, XSS, and bad user agents *before* they hit business logic.
    *   **Virtual Patching**: Can block specific routes or payloads remotely if a vulnerability is found.

### C. The Aegis Command (Central Dashboard)
A modern Web App (Next.js) where the user manages everything.
*   **Role**: The "Brain".
*   **Capabilities**:
    *   **Unified Feed**: Logs, Alerts, and Metrics in one timeline.
    *   **One-Click Actions**: "Block this IP across all servers", "Lock down file system".
    *   **AI Insights**: "Your API latency spiked 500% after the last deploy."

## 3. Key Differentiators (The "Better" Part)
To win against established players, we need to be **simpler** and **more actionable**.
1.  **Zero-Config Magic**: Run `curl | bash` and it *automatically* detects Nginx, Postgre, Node apps. No writing 500 lines of YAML config.
2.  **Lite SIEM**: Don't just show logs. Correlate them. (e.g., "High CPU usage + 500 Failed Login attempts = Brute Force Attack").
3.  **Active Defense**: Unlike Datadog (which just watches), Aegis can *act* (block IPs, kill processes).

## 4. Implementation Roadmap (Revised)

### Phase 1: The Core (Backend & Ingestion)
**Goal**: Build the brain that receives and stores data.
*   **Tech**: Go (Golang), ClickHouse (Logs/Metrics), PostgreSQL (Metadata).
*   **Tasks**:
    1. Setup Infrastructure (Docker Compose: Clickhouse, Postgres).
    2. Design Database Schemas (Clickhouse tables for logs, Postgres for users/servers).
    3. Build Ingestion API (gRPC/HTTP endpoint to receive logs).
    4. Implement Query API (Fetch aggregated logs/stats).

### Phase 2: The Agent (Sidecar)
**Goal**: Build the collector that runs on user servers.
*   **Tech**: Go.
*   **Capabilities**:
    1. System Stats Collector (CPU, RAM).
    2. Log Tailer (File watcher).
    3. Secure communication with Backend.

### Phase 3: The Dashboard (Frontend)
**Goal**: The user interface.
*   **Tech**: Next.js 14, TailwindCSS.
*   **Features**:
    1. Server List & Status.
    2. Log Explorer with Filters.
    3. Metric Graphs.
