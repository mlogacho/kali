#!/bin/bash
# probe-setup.sh — Convierte este equipo en una sonda de escaneo para el servidor Kali AWS
# Ejecución: curl -fsSL http://3.143.18.161:8040/api/probe/install | sudo bash

KALI_SERVER="3.143.18.161"
KALI_API="http://${KALI_SERVER}:8040"
NEBULA_VERSION="v1.9.5"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[ "$EUID" -ne 0 ] && error "Este script debe ejecutarse como root (sudo)"

OS=$(uname -s)

# 1. Habilitar IP Forwarding
info "Habilitando IP Forwarding (SO: $OS)..."
if [ "$OS" = "Darwin" ]; then
    sysctl -w net.inet.ip.forwarding=1 >/dev/null
    # En macOS no hay /etc/sysctl.d/ por defecto de la misma forma
else
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-kali-probe.conf 2>/dev/null || true
fi

# 2. Configurar NAT / Masquerade
info "Configurando NAT..."
if [ "$OS" = "Darwin" ]; then
    # Detectar interfaz LAN en macOS
    LAN_IF=$(route -n get default | grep interface | awk '{print $2}')
    [ -z "$LAN_IF" ] && error "No se detectó interfaz de red en macOS."
    
    info "Configurando PF (Packet Filter) en macOS para interfaz $LAN_IF..."
    # Crear archivo temporal para PF
    PF_CONF=$(mktemp)
    echo "nat on $LAN_IF from 10.255.255.0/24 to any -> ($LAN_IF)" > "$PF_CONF"
    pfctl -e -f "$PF_CONF" 2>/dev/null || pfctl -f "$PF_CONF"
    info "NAT (PF) activo en macOS."
else
    # Linux logic
    LAN_IF=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$LAN_IF" ]; then
        # Fallback para sistemas sin comando 'ip' pero con 'ifconfig'
        LAN_IF=$(ifconfig | grep -B1 "inet " | grep -v "inet " | head -n1 | awk '{print $1}' | tr -d ':')
    fi
    [ -z "$LAN_IF" ] && error "No se detectó interfaz de red con salida a internet."
    
    iptables -t nat -A POSTROUTING -s 10.255.255.0/24 -o "$LAN_IF" -j MASQUERADE
    info "NAT (IPTables) activo en interfaz: $LAN_IF"
fi

# 3. Detectar Nebula
if ! command -v nebula &>/dev/null; then
    warn "Nebula no se encuentra en el PATH. Buscando en /etc/nebula..."
    if [ ! -f "/usr/local/bin/nebula" ]; then
        info "Instalando Nebula $NEBULA_VERSION..."
        TMP=$(mktemp -d)
        curl -fsSL "https://github.com/slackhq/nebula/releases/download/${NEBULA_VERSION}/nebula-linux-amd64.tar.gz" -o "$TMP/nebula.tar.gz"
        tar -xzf "$TMP/nebula.tar.gz" -C /usr/local/bin/
        chmod +x /usr/local/bin/nebula /usr/local/bin/nebula-cert
        rm -rf "$TMP"
    fi
fi

# 4. Anunciar subnets al servidor Kali
info "Buscando subnets locales para anunciar..."
if [ "$OS" = "Darwin" ]; then
    # macOS subnet discovery
    SUBNETS=$(netstat -rn -f inet | awk '$3~/[0-9]/ && $6!~/lo0|utun/ {print $1}' | grep '/' | sort -u | head -5)
    # Detectar IP Nebula (buscando interfaz utun con IP 10.255.255.x)
    MY_NEBULA_IP=$(ifconfig | grep -A2 "utun" | grep "inet 10.255.255." | awk '{print $2}')
else
    # Linux subnet discovery
    SUBNETS=$(ip route show | awk '$1~/\// && $1!~/^10\.255\.255\.|^172\.|^127\.|^169\.254\./ {print $1}' | sort -u | head -5)
    # Obtener IP Nebula
    MY_NEBULA_IP=$(ip addr show dev nebula0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
fi

if [ -z "$SUBNETS" ]; then
    warn "No se encontraron subnets locales automáticas."
    SUBNETS=""
fi

if [ -z "$MY_NEBULA_IP" ]; then
    # Intento final por grep global
    MY_NEBULA_IP=$(ifconfig 2>/dev/null | grep "inet 10.255.255." | awk '{print $2}' | cut -d: -f2)
fi

if [ -z "$MY_NEBULA_IP" ]; then
    error "No se pudo detectar tu IP Nebula (10.255.255.x). Asegúrate de que Nebula esté corriendo."
fi

info "Anunciando subnets: $SUBNETS"
JSON="{\"nebula_ip\":\"$MY_NEBULA_IP\",\"subnets\":["
first=1
for s in $SUBNETS; do
  [ $first -eq 0 ] && JSON+=","
  JSON+="\"$s\""
  first=0
done
JSON+="]}"

curl -sf -X POST "${KALI_API}/api/nebula/announce" \
  -H "Content-Type: application/json" -d "$JSON" && info "Configuración en servidor Kali EXITOSA" || warn "Error al contactar con el servidor Kali"

# 5. Ejecutar agente de escaneo local (primera vez)
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
    warn "No se pudo descargar probe-agent.sh — ejecutar manualmente:"
    warn "  curl -fsSL ${KALI_API}/api/probe/agent | sudo bash -s -- <SUBNET>"
fi

echo -e "\n${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  EQUIPO CONFIGURADO COMO SONDA (PROBE)"
echo -e "  IP Nebula  : ${MY_NEBULA_IP}"
echo -e "  Subnets    : ${SUBNETS}"
echo -e "  Interface  : ${LAN_IF} (con NAT)"
echo -e ""
echo -e "  Para escaneos continuos:"
echo -e "  curl -fsSL ${KALI_API}/api/probe/agent | sudo bash -s -- <SUBNET> --loop 300"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
