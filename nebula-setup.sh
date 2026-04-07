#!/bin/bash
set -e

# Script to install Nebula on Kali Linux server

# Define variables
NEBULA_VERSION="v1.7.2"
NEBULA_DIR="/opt/nebula"
CERTS_DIR="/etc/nebula/certs"
SERVICE_FILE="/etc/systemd/system/nebula.service"

# Download and install Nebula if not already present
if [ ! -d "$NEBULA_DIR" ]; then
    echo "Downloading Nebula..."
    wget https://github.com/slackhq/nebula/releases/download/$NEBULA_VERSION/nebula-linux-amd64.tar.gz -O /tmp/nebula.tar.gz
    echo "Extracting Nebula..."
    mkdir -p "$NEBULA_DIR"
    tar -xzf /tmp/nebula.tar.gz -C "$NEBULA_DIR"
    chmod +x "$NEBULA_DIR/nebula"
fi

# Create directory structure for certificates
mkdir -p "$CERTS_DIR"

# Generate initial CA certificate
if [ ! -f "$CERTS_DIR/ca.pem" ]; then
    echo "Generating CA certificate..."
    openssl req -new -x509 -days 3650 -keyout "$CERTS_DIR/ca.key" -out "$CERTS_DIR/ca.pem" -subj "/C=US/ST=State/L=City/O=Organization/CN=CA"
fi

# Create example configuration files if they do not exist
CONFIG_FILE="$CERTS_DIR/config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Creating example configuration..."
    echo 'pki:
  ca: /etc/nebula/certs/ca.pem
  cert: /etc/nebula/certs/server.pem
  key: /etc/nebula/certs/server.key' > "$CONFIG_FILE"
fi

# Set proper permissions
chown -R root:root "$CERTS_DIR"
chmod -R 700 "$CERTS_DIR"

# Create systemd service file if it does not exist
if [ ! -f "$SERVICE_FILE" ]; then
    echo "Creating systemd service file..."
    echo '[Unit]
Description=Nebula VPN service

[Service]
ExecStart=/opt/nebula/nebula run
Restart=on-failure

[Install]
WantedBy=multi-user.target' > "$SERVICE_FILE"
    systemctl enable nebula
fi

# Reload systemd to recognize new service
systemctl daemon-reload

echo "Nebula installation and setup completed successfully."