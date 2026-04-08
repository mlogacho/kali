#!/bin/bash
# nebula-setup.sh — Instala Nebula y genera la PKI en el servidor Kali
# Uso: sudo ./nebula-setup.sh
set -e

NEBULA_VERSION="v1.9.5"
NEBULA_DIR="/opt/nebula"
CERTS_DIR="/etc/nebula/certs"
CONFIG_DIR="/etc/nebula"
SERVICE_FILE="/etc/systemd/system/nebula.service"
SERVER_NEBULA_IP="192.168.100.1/24"   # IP overlay del lighthouse (este servidor)
SERVER_PUBLIC_IP="3.143.18.161"
LISTEN_PORT=4242

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[ "$EUID" -ne 0 ] && error "Ejecutar como root: sudo $0"

# ── 1. Instalar Nebula ────────────────────────────────────────────────────────
if [ ! -f "$NEBULA_DIR/nebula" ] || [ ! -f "$NEBULA_DIR/nebula-cert" ]; then
    info "Descargando Nebula $NEBULA_VERSION..."
    TMP=$(mktemp -d)
    curl -fsSL "https://github.com/slackhq/nebula/releases/download/${NEBULA_VERSION}/nebula-linux-amd64.tar.gz" \
         -o "$TMP/nebula.tar.gz"
    mkdir -p "$NEBULA_DIR"
    tar -xzf "$TMP/nebula.tar.gz" -C "$NEBULA_DIR"
    chmod +x "$NEBULA_DIR/nebula" "$NEBULA_DIR/nebula-cert"
    rm -rf "$TMP"
    info "Nebula instalado en $NEBULA_DIR"
else
    info "Nebula ya está instalado en $NEBULA_DIR"
fi

# ── 2. Crear directorios ──────────────────────────────────────────────────────
mkdir -p "$CERTS_DIR"
chmod 700 "$CERTS_DIR"

# ── 3. Generar CA con nebula-cert ─────────────────────────────────────────────
if [ ! -f "$CERTS_DIR/ca.crt" ]; then
    info "Generando CA Nebula..."
    "$NEBULA_DIR/nebula-cert" ca \
        -name "Datacom Security Nebula CA" \
        -duration 87600h \
        -out-crt "$CERTS_DIR/ca.crt" \
        -out-key "$CERTS_DIR/ca.key"
    chmod 600 "$CERTS_DIR/ca.key"
    # ca.crt es público — lo distribuimos a todos los clientes
    chmod 644 "$CERTS_DIR/ca.crt"
    chown root:kali "$CERTS_DIR/ca.crt" 2>/dev/null || true
    info "CA generada: $CERTS_DIR/ca.crt"
else
    warn "CA ya existe en $CERTS_DIR/ca.crt — omitiendo"
fi

# ── 4. Generar certificado del servidor (lighthouse) ─────────────────────────
if [ ! -f "$CERTS_DIR/server.crt" ]; then
    info "Generando certificado del servidor..."
    "$NEBULA_DIR/nebula-cert" sign \
        -ca-crt "$CERTS_DIR/ca.crt" \
        -ca-key "$CERTS_DIR/ca.key" \
        -name   "kali-lighthouse" \
        -ip     "$SERVER_NEBULA_IP" \
        -groups "lighthouse,servers" \
        -duration 87600h \
        -out-crt "$CERTS_DIR/server.crt" \
        -out-key "$CERTS_DIR/server.key"
    chmod 600 "$CERTS_DIR/server.key"
    chmod 644 "$CERTS_DIR/server.crt"
    chown root:kali "$CERTS_DIR/server.crt" "$CERTS_DIR/server.key" 2>/dev/null || true
    info "Cert servidor: $CERTS_DIR/server.crt"
else
    warn "Cert servidor ya existe — omitiendo"
fi

# ── 5. Crear configuración del lighthouse ────────────────────────────────────
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    info "Creando config.yaml del lighthouse..."
    cat > "$CONFIG_DIR/config.yaml" <<YAML
# Nebula config — Lighthouse (Kali AWS)
pki:
  ca: ${CERTS_DIR}/ca.crt
  cert: ${CERTS_DIR}/server.crt
  key: ${CERTS_DIR}/server.key

static_host_map: {}

lighthouse:
  am_lighthouse: true
  interval: 60

listen:
  host: 0.0.0.0
  port: ${LISTEN_PORT}

punchy:
  punch: true

relay:
  am_relay: false
  use_relays: false

tun:
  disabled: false
  dev: nebula0
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300

logging:
  level: info
  format: text

firewall:
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: icmp
      host: any
    - port: any
      proto: any
      group: clients
    - port: any
      proto: any
      group: servers
    - port: any
      proto: any
      group: lighthouse
YAML
    info "Config creada: $CONFIG_DIR/config.yaml"
else
    warn "Config ya existe — omitiendo"
fi

# ── 6. Abrir puerto UDP en el firewall ────────────────────────────────────────
if command -v ufw &>/dev/null; then
    ufw allow ${LISTEN_PORT}/udp 2>/dev/null && info "UFW: UDP $LISTEN_PORT abierto" || true
fi

# ── 7. Crear servicio systemd ─────────────────────────────────────────────────
if [ ! -f "$SERVICE_FILE" ]; then
    info "Creando servicio systemd nebula.service..."
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Nebula VPN — Datacom Security
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=${NEBULA_DIR}/nebula -config ${CONFIG_DIR}/config.yaml
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable nebula
systemctl restart nebula || warn "No se pudo reiniciar nebula (puede ser normal si la interfaz ya existe)"

sleep 2
if systemctl is-active --quiet nebula; then
    info "Servicio nebula ACTIVO"
else
    warn "Servicio nebula no está activo. Revisa: journalctl -u nebula -n 30"
fi

# ── Resumen ───────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✓ Nebula configurado como Lighthouse"
echo "  IP overlay del servidor : ${SERVER_NEBULA_IP}"
echo "  IP pública (AWS)        : ${SERVER_PUBLIC_IP}:${LISTEN_PORT}/udp"
echo "  CA                      : ${CERTS_DIR}/ca.crt"
echo "  Gestión de certs        : ./nebula-cert-manager.sh"
echo "  Web UI (certs)          : http://${SERVER_PUBLIC_IP}:8040  → pestaña Nebula VPN"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
