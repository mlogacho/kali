#!/bin/bash
# probe-setup.sh — Convierte este equipo en una sonda de escaneo para el servidor Kali
# Funciona con Tailscale y Nebula automáticamente
# Ejecución: curl -fsSL http://<KALI_IP>:8040/api/probe/install | sudo bash

KALI_SERVER="${KALI_SERVER:-3.143.18.161}"
KALI_API="http://${KALI_SERVER}:8040"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*"; exit 1; }
debug() { echo -e "${CYAN}[*]${NC} $*"; }

[ "$EUID" -ne 0 ] && error "Este script debe ejecutarse como root (sudo)"

OS=$(uname -s)

# ── 1. Detectar tipo de VPN activa ──
detect_vpn() {
    # Intentar Tailscale primero
    if command -v tailscale &>/dev/null; then
        TS_IP=$(tailscale ip -4 2>/dev/null)
        if [ -n "$TS_IP" ]; then
            VPN_TYPE="tailscale"
            MY_VPN_IP="$TS_IP"
            VPN_IFACE="tailscale0"
            VPN_SOURCE_NET="100.64.0.0/10"  # CGNAT range de Tailscale
            return 0
        fi
    fi
    # Intentar Nebula
    if [ "$OS" = "Darwin" ]; then
        NEB_IP=$(ifconfig 2>/dev/null | grep -A2 "utun" | grep "inet 10.255.255." | awk '{print $2}' | head -1)
    else
        NEB_IP=$(ip addr show dev nebula0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    fi
    if [ -z "$NEB_IP" ]; then
        NEB_IP=$(ifconfig 2>/dev/null | grep "inet 10.255.255." | awk '{print $2}' | cut -d: -f2 | head -1)
    fi
    if [ -n "$NEB_IP" ]; then
        VPN_TYPE="nebula"
        MY_VPN_IP="$NEB_IP"
        VPN_IFACE="nebula0"
        VPN_SOURCE_NET="10.255.255.0/24"
        return 0
    fi
    return 1
}

info "Detectando VPN activa..."
if ! detect_vpn; then
    error "No se detectó VPN activa (Tailscale ni Nebula). Asegúrate de que esté corriendo."
fi
info "VPN detectada: ${VPN_TYPE} (IP: ${MY_VPN_IP})"

# ── 2. Detectar interfaz LAN ──
if [ "$OS" = "Darwin" ]; then
    LAN_IF=$(route -n get default 2>/dev/null | grep interface | awk '{print $2}')
else
    LAN_IF=$(ip route | grep default | awk '{print $5}' | head -1)
    [ -z "$LAN_IF" ] && LAN_IF=$(ifconfig | grep -B1 "inet " | grep -v "inet " | head -1 | awk '{print $1}' | tr -d ':')
fi
[ -z "$LAN_IF" ] && error "No se detectó interfaz de red con salida a internet."

# ── 3. Habilitar IP Forwarding ──
info "Habilitando IP Forwarding (SO: $OS)..."
if [ "$OS" = "Darwin" ]; then
    sysctl -w net.inet.ip.forwarding=1 >/dev/null
else
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-kali-probe.conf 2>/dev/null || true
fi

# ── 4. Configurar NAT / Masquerade ──
info "Configurando NAT (source: $VPN_SOURCE_NET → $LAN_IF)..."
if [ "$OS" = "Darwin" ]; then
    PF_CONF=$(mktemp)
    echo "nat on $LAN_IF from $VPN_SOURCE_NET to any -> ($LAN_IF)" > "$PF_CONF"
    pfctl -e -f "$PF_CONF" 2>/dev/null || pfctl -f "$PF_CONF"
    info "NAT (PF) activo en macOS."
else
    iptables -t nat -C POSTROUTING -s "$VPN_SOURCE_NET" -o "$LAN_IF" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "$VPN_SOURCE_NET" -o "$LAN_IF" -j MASQUERADE
    info "NAT (IPTables) activo en interfaz: $LAN_IF"
fi

# ── 5. Detectar subnets locales ──
info "Buscando subnets locales..."
if [ "$OS" = "Darwin" ]; then
    SUBNETS=$(netstat -rn -f inet | awk '$3~/[0-9]/ && $6!~/lo0|utun/ {print $1}' | grep '/' | sort -u | head -5)
else
    SUBNETS=$(ip route show | awk '$1~/\// && $1!~/^10\.255\.255\.|^100\.64\.|^127\.|^169\.254\./ {print $1}' | sort -u | head -5)
fi
[ -z "$SUBNETS" ] && warn "No se encontraron subnets locales automáticas."

# ── 6. Tailscale: anunciar subnets como subnet router ──
if [ "$VPN_TYPE" = "tailscale" ] && [ -n "$SUBNETS" ]; then
    ROUTES_CSV=$(echo "$SUBNETS" | tr '\n' ',' | sed 's/,$//')
    info "Tailscale: anunciando subnets como subnet router: $ROUTES_CSV"
    tailscale set --advertise-routes="$ROUTES_CSV" 2>/dev/null || \
    warn "No se pudo anunciar rutas en Tailscale. Verificar: tailscale set --advertise-routes=$ROUTES_CSV"
    info "IMPORTANTE: Aprueba las rutas en https://login.tailscale.com/admin/machines"
fi

# ── 7. Anunciar al servidor Kali (endpoint universal) ──
info "Anunciando al servidor Kali: $KALI_API"
JSON="{\"vpn_ip\":\"$MY_VPN_IP\",\"vpn_type\":\"$VPN_TYPE\",\"name\":\"$(hostname)\",\"subnets\":["
first=1
for s in $SUBNETS; do
  [ $first -eq 0 ] && JSON+=","
  JSON+="\"$s\""
  first=0
done
JSON+="]}"

curl -sf -X POST "${KALI_API}/api/probe/announce" \
  -H "Content-Type: application/json" -d "$JSON" && info "Registro en servidor EXITOSO" || \
  warn "Error al contactar con el servidor Kali"

# ── 8. Ejecutar primer escaneo local ──
info "Ejecutando primer escaneo local con probe-agent..."
curl -fsSL "${KALI_API}/api/probe/agent" -o /tmp/probe-agent.sh 2>/dev/null
if [ -f /tmp/probe-agent.sh ]; then
    for s in $SUBNETS; do
        info "Escaneando $s..."
        KALI_SERVER="$KALI_SERVER" bash /tmp/probe-agent.sh "$s" &
    done
    wait
    info "Escaneo local completado."
else
    warn "No se pudo descargar probe-agent.sh"
fi

echo -e "\n${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  SONDA CONFIGURADA (${VPN_TYPE^^})"
echo -e "  IP VPN     : ${MY_VPN_IP}"
echo -e "  Subnets    : ${SUBNETS}"
echo -e "  Interface  : ${LAN_IF} (con NAT)"
echo -e ""
echo -e "  Para escaneos continuos:"
echo -e "  curl -fsSL ${KALI_API}/api/probe/agent | sudo bash -s -- <SUBNET> --loop 300"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
