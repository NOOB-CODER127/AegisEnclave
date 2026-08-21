# AegisDefender - Project Documentation

## 1. Project Overview
**AegisDefender** (also known as AegisEnclave) is a comprehensive **Security Operations Center (SOC) and Incident Response Platform**. It provides real-time visibility into server fleets, application health, and security threats. The platform connects to remote servers via lightweight agents, ingesting logs and metrics to detect anomalies, block attacks (IPS/IDS), and visualize infrastructure status in a modern, hex-based interface.

## 2. Architecture
The system follows a modern 3-tier architecture designed for high throughput and real-time visualization:

*   **Frontend**: Next.js 14 (App Router) application serving the dashboard and management interfaces.
*   **Backend**: High-performance Go (Golang) API handling agent communication, data ingestion, and user requests.
*   **Data Layer**:
    *   **PostgreSQL**: Stores relational data: Users, Teams, Servers, Applications, and metadata.
    *   **ClickHouse**: Stores high-volume telemetry data: System Logs, Application Metrics, and Traffic Stats.

---

## 3. Core Features - Frontend

### A. Executive Dashboard (Fleet Overview)
The central command center providing a "God Mode" view of the entire digital estate.
*   **Honeycomb Fleet Visualization**:
    *   **Application Fleet**: Displays applications as hexagonal nodes. Color-coded health status (Green=Healthy, Amber=Issues, Red=Critical).
    *   **Server Drill-down**: Clicking an app reveals its connected servers.
    *   **Server Nodes**: Rich tooltips showing real-time CPU/Memory usage, Uptime, and a historical load sparkline.
*   **Network Telemetry**:
    *   Real-time charts for **Traffic Volume** (Req/sec), **Latency** (ms), and **Error Rates** (%).
    *   Tabbed interface for clean data presentation.
*   **Live Operations Log**:
    *   Scrolling feed of system events (Deployments, Autoscaling, Alerts, Backups).
    *   Severity coding (Info, Success, Warning, Error).
*   **System Health Index**:
    *   Aggregated score (0-100) based on Security Threats, Uptime, and Performance metrics.
*   **Cost Estimation**: Real-time estimated monthly infrastructure cost.

### B. Incident Management & Response
A dedicated SOC interface for investigating and mitigating security threats.
*   **Threat Intelligence Feed**:
    *   Real-time list of detected incidents.
    *   **Fields**: Severity (Critical/High/Medium/Low), Attack Type (e.g., SQLi, XSS), Target Asset, Attacker IP/Country, Status.
*   **Investigation Drawer (Deep Dive)**:
    *   **Context**: Displays Target Asset and Attacker Origin details.
    *   **Attack Timeline**: Visual lifecycle of the attack (Detected -> AI Analysis -> Response Triggered).
    *   **AI Analysis**: "AI Sentinel" feedback correlating IPs with known botnets.
    *   **Payload Evidence**: Raw HTTP request dumps showing the malicious payload (e.g., SQL injection strings).
    *   **Response Actions**: One-click "Block IP" or "Mitigate Threat".
*   **Key Metrics**: Active Incidents, MTTR (Mean Time To Resolution), Attacks Blocked count.
*   **Visual Analysis**: Threat Volume over time and Attack Vector distribution (Pie Chart).

### C. Infrastructure Map
A physical topology view of all connected resources.
*   **Global Hex Map**: Visual grid of all servers, independent of application grouping.
*   **Status Coding**: Immediate visual feedback on server health.
    *   **Green**: Online & Healthy.
    *   **Amber**: Warning (High Load/Minor Alerts).
    *   **Red**: Critical (Offline/Severe Alerts).
*   **Quick Stats**: Hovering over a node reveals CPU, Memory, and Last Seen timestamps.
*   **Auto-Refresh**: Polls backend every 3 seconds for live status updates.

### D. Application/Service Management
Inventory of all business services running on the infrastructure.
*   **Service Grid**: Card-based view of all registered applications.
*   **Health Indicators**: Top-border status bars indicating service health.
*   **Metadata**: Displays Cloud Region (e.g., us-east-1), Server Count, and Description.
*   **Filtering**: Real-time search by service name or description.
*   **Management**: Create new service entries.

### E. Server Management
The onboarding hub for infrastructure.
*   **Server Inventory**: Tabular list of all registered agents.
*   **Agent Installation**:
    *   "Connect Server" wizard.
    *   **One-Line Installer**: Generates a secure command (`curl ... | sudo SERVER_KEY=... bash`) to install the agent on remote Linux machines.
    *   **API Key Generation**: Automatically creates and displays a unique `SERVER_KEY` for the agent.

### F. Team Management
Role-Based Access Control (RBAC) for the platform.
*   **Member List**: Management of team members.
*   **Roles**:
    *   **Admin**: Full access.
    *   **Developer**: Access to apps and logs.
    *   **Viewer**: Read-only access.
    *   **Billing**: Financial views only.
    *   **Service Account**: For bots/automations (e.g., "AI Sentinel").
*   **Invitation System**: Invite new users via email.

---

## 4. Backend Capabilities (Go API)

### A. Data Ingestion (Agent API)
High-throughput endpoints designed for machine consumption.
*   **Log Ingestion** (`POST /api/v1/ingest/logs`):
    *   Accepts batched log entries from agents.
    *   **Security**: Validates `X-Server-Key` header against Postgres database.
    *   **Integrity**: Overrides `ServerID` in payload to prevent spoofing.
    *   **Storage**: Writes directly to ClickHouse for efficient long-term storage.
*   **Metric Ingestion** (`POST /api/v1/ingest/metrics`):
    *   Accepts system metrics (CPU, Mem, Net).
    *   Follows same security and storage patterns as logs.

### B. Data Querying (User API)
Secure endpoints for frontend data visualization.
*   **Log Querying** (`GET /api/v1/query/logs`):
    *   **Security**: Requires Valid User JWT.
    *   **Scoping**: Enforces ownership checks (Users can only query logs for servers they have access to).
    *   **Filtering**: specific server filtering supported.
    *   **Pagination**: Limit-based fetching.

### C. Authentication & Security
*   **Agent Auth**: Static API Keys (`X-Server-Key`).
*   **User Auth**: JWT Bearer Tokens.
*   **RBAC**: Middleware-enforced role checks (implied by frontend roles).

---

## 5. Technology Stack

### Frontend
*   **Framework**: Next.js 14 (App Router)
*   **Language**: TypeScript
*   **Styling**: Tailwind CSS
*   **Charts**: Recharts (Area, Line, Pie, Donut charts)
*   **Icons**: Lucide React
*   **Animations**: Native CSS transitions + Tailwind animate utilities (e.g., `animate-pulse`, `animate-in`).

### Backend
*   **Language**: Go (Golang)
*   **Web Framework**: Gin Gonic
*   **Databases**:
    *   **PostgreSQL**: Metadata & Relational Data.
    *   **ClickHouse**: Time-series Telemetry Data.
