#!/bin/bash

# Aegis Defender Agent Installer
# Usage: ./install.sh <SERVER_ID> <SERVER_KEY> <BACKEND_URL>

set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

SERVER_ID=$1
SERVER_KEY=$2
BACKEND_URL=$3

if [ -z "$SERVER_ID" ] || [ -z "$SERVER_KEY" ] || [ -z "$BACKEND_URL" ]; then
    echo "Usage: ./install.sh <SERVER_ID> <SERVER_KEY> <BACKEND_URL>"
    exit 1
fi

echo "Installing Aegis Agent..."

# 1. Install Binary
# In a real scenario, this would download from a release URL.
# For now, we assume 'agent' binary is in the current directory or we build it.
if [ -f "./agent" ]; then
    echo "Found agent binary, installing to /usr/local/bin/aegis-agent..."
    cp ./agent /usr/local/bin/aegis-agent
    chmod +x /usr/local/bin/aegis-agent
elif command -v go &> /dev/null; then
    echo "Agent binary not found, building from source..."
    if [ -d "./cmd/agent" ]; then
        go build -o aegis-agent ./cmd/agent/main.go
        mv aegis-agent /usr/local/bin/
        chmod +x /usr/local/bin/aegis-agent
    else
        echo "Error: Source code not found in current directory."
        exit 1
    fi
else
    echo "Error: 'agent' binary not found and Go is not installed to build it."
    exit 1
fi

# 2. Create Systemd Service
echo "Creating systemd service..."
cat <<EOF > /etc/systemd/system/aegis-agent.service
[Unit]
Description=Aegis Defender Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aegis-agent
Restart=always
RestartSec=5
Environment="SERVER_ID=${SERVER_ID}"
Environment="SERVER_KEY=${SERVER_KEY}"
Environment="BACKEND_URL=${BACKEND_URL}"
# Assuming dummy log for now, but in prod this defaults to /var/log/syslog or similar
Environment="LOG_FILE=/var/log/syslog" 

[Install]
WantedBy=multi-user.target
EOF

# 3. Enable and Start Service
echo "Enabling and starting service..."
systemctl daemon-reload
systemctl enable aegis-agent
systemctl restart aegis-agent

echo "Aegis Agent installed and started successfully!"
echo "Check status with: systemctl status aegis-agent"
