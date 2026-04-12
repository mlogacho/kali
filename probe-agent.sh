#!/bin/bash
# probe-agent.sh — Agente de escaneo local para sonda Kali
# Ejecuta escaneo ARP + nbtscan + nmap en la red local y envía resultados al servidor
# Uso: sudo bash probe-agent.sh [subnet] [--loop N]
#
# Ejecución directa:   sudo bash probe-agent.sh 192.168.10.0/24
# Ejecución continua:  sudo bash probe-agent.sh 192.168.10.0/24 --loop 300
# Desde servidor:      curl -fsSL http://<KALI>:8040/api/probe/agent | sudo bash -s -- 192.168.10.0/24

KALI_SERVER="${KALI_SERVER:-3.143.18.161}"
KALI_API="http://${KALI_SERVER}:8040"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*"; }
debug() { echo -e "${CYAN}[*]${NC} $*"; }

[ "$EUID" -ne 0 ] && { error "Ejecutar como root (sudo)"; exit 1; }

# ── Parse args ──
SUBNET="$1"
LOOP_INTERVAL=0
if [ "$2" = "--loop" ] && [ -n "$3" ]; then
    LOOP_INTERVAL="$3"
fi

# ── Detect OS ──
OS=$(uname -s)

# ── Detect Nebula IP ──
detect_nebula_ip() {
    if [ "$OS" = "Darwin" ]; then
        ifconfig 2>/dev/null | grep -A2 "utun" | grep "inet 10.255.255." | awk '{print $2}' | head -1
    else
        ip addr show dev nebula0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1
    fi
}

MY_NEBULA_IP=$(detect_nebula_ip)
if [ -z "$MY_NEBULA_IP" ]; then
    MY_NEBULA_IP=$(ifconfig 2>/dev/null | grep "inet 10.255.255." | awk '{print $2}' | cut -d: -f2 | head -1)
fi
[ -z "$MY_NEBULA_IP" ] && { error "No se detectó IP Nebula (10.255.255.x). Nebula corriendo?"; exit 1; }
info "IP Nebula: $MY_NEBULA_IP"

# ── Auto-detect subnet if not provided ──
if [ -z "$SUBNET" ]; then
    if [ "$OS" = "Darwin" ]; then
        LAN_IF=$(route -n get default 2>/dev/null | grep interface | awk '{print $2}')
        LAN_IP=$(ifconfig "$LAN_IF" 2>/dev/null | grep "inet " | grep -v 127 | awk '{print $2}')
        SUBNET="${LAN_IP%.*}.0/24"
    else
        LAN_IF=$(ip route | grep default | awk '{print $5}' | head -1)
        LAN_IP=$(ip addr show "$LAN_IF" 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
        SUBNET=$(echo "$LAN_IP" | sed 's|\.[0-9]*/|.0/|')
    fi
    [ -z "$SUBNET" ] && { error "No se pudo detectar subnet. Uso: $0 192.168.10.0/24"; exit 1; }
    info "Subnet auto-detectado: $SUBNET"
fi

# ── Check tools ──
HAS_ARPSCAN=false
HAS_NBTSCAN=false
HAS_NMAP=false
command -v arp-scan &>/dev/null && HAS_ARPSCAN=true
command -v nbtscan  &>/dev/null && HAS_NBTSCAN=true
command -v nmap     &>/dev/null && HAS_NMAP=true

if ! $HAS_ARPSCAN && ! $HAS_NMAP; then
    error "Se necesita arp-scan o nmap. Instalar: apt install arp-scan nmap"
    exit 1
fi

# ── Scan function ──
run_scan() {
    local HOSTS_JSON="[]"
    local TMPDIR=$(mktemp -d)

    # Phase 1: ARP scan (Layer 2 — gets MAC addresses and vendors)
    if $HAS_ARPSCAN; then
        info "Fase 1: ARP scan en $SUBNET..."
        arp-scan --localnet --interface="$LAN_IF" "$SUBNET" 2>/dev/null > "$TMPDIR/arp.txt" || \
        arp-scan "$SUBNET" 2>/dev/null > "$TMPDIR/arp.txt"

        # Parse arp-scan output: IP\tMAC\tVendor
        HOSTS_JSON=$(awk -F'\t' '
            /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {
                ip=$1; mac=$2; vendor=$3;
                gsub(/"/, "\\\"", vendor);
                printf "{\"ip\":\"%s\",\"mac\":\"%s\",\"vendor\":\"%s\",\"hostname\":\"\",\"ports\":[],\"status\":\"up\"},\n", ip, mac, vendor
            }
        ' "$TMPDIR/arp.txt")
    elif $HAS_NMAP; then
        info "Fase 1: nmap ping sweep en $SUBNET (sin arp-scan)..."
        nmap -sn -T4 "$SUBNET" -oG "$TMPDIR/ping.txt" 2>/dev/null

        # Also get MAC from nmap -sn normal output
        nmap -sn -T4 "$SUBNET" 2>/dev/null > "$TMPDIR/nmap_sn.txt"

        HOSTS_JSON=$(awk '
            /^Host:/ && /Status: Up/ {
                ip=$2; hostname="";
                if (match($0, /\(([^)]+)\)/, m)) hostname=m[1];
                printf "{\"ip\":\"%s\",\"mac\":\"\",\"vendor\":\"\",\"hostname\":\"%s\",\"ports\":[],\"status\":\"up\"},\n", ip, hostname
            }
        ' "$TMPDIR/ping.txt")
    fi

    # Phase 2: NetBIOS names
    if $HAS_NBTSCAN; then
        info "Fase 2: nbtscan (nombres NetBIOS)..."
        nbtscan -s '|' "$SUBNET" 2>/dev/null > "$TMPDIR/nbt.txt"
    fi

    # Phase 3: Port scan on discovered hosts
    if $HAS_NMAP; then
        # Extract IPs from Phase 1
        local IPS=$(echo "$HOSTS_JSON" | grep -oP '"ip":"[^"]+' | cut -d'"' -f4 | sort -u)
        if [ -n "$IPS" ]; then
            local IP_LIST=$(echo "$IPS" | tr '\n' ' ')
            info "Fase 3: Escaneo de puertos en $(echo "$IPS" | wc -l | tr -d ' ') hosts..."
            nmap -sT -T4 --open -p 21,22,23,25,53,80,110,135,139,443,445,993,995,3306,3389,5432,8080,8443 \
                 $IP_LIST -oG "$TMPDIR/ports.txt" 2>/dev/null
        fi
    fi

    # ── Build final JSON ──
    # Use Python if available for reliable JSON building, otherwise awk
    if command -v python3 &>/dev/null; then
        python3 << 'PYEOF' "$TMPDIR" "$SUBNET" "$MY_NEBULA_IP" "$KALI_API"
import sys, json, re, os
from urllib.request import Request, urlopen

tmpdir, subnet, nebula_ip, kali_api = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
hosts = {}  # ip → host dict

# Parse ARP scan
arp_file = os.path.join(tmpdir, "arp.txt")
if os.path.exists(arp_file):
    for line in open(arp_file):
        parts = line.strip().split('\t')
        if len(parts) >= 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
            ip = parts[0]
            mac = parts[1] if len(parts) > 1 else ""
            vendor = parts[2] if len(parts) > 2 else ""
            hosts[ip] = {"ip": ip, "mac": mac, "vendor": vendor, "hostname": "", "ports": [], "status": "up"}

# Parse nmap -sn output (if no arp-scan)
nmap_sn = os.path.join(tmpdir, "nmap_sn.txt")
if os.path.exists(nmap_sn):
    cur = None
    for line in open(nmap_sn):
        m = re.match(r'Nmap scan report for (.+)', line)
        if m:
            s = m.group(1).strip()
            ip_m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', s)
            if ip_m:
                ip = ip_m.group(1)
                hn = s[:s.rfind('(')].strip()
            else:
                ip = s; hn = ""
            if ip not in hosts:
                hosts[ip] = {"ip": ip, "mac": "", "vendor": "", "hostname": hn, "ports": [], "status": "up"}
            elif hn and not hosts[ip]["hostname"]:
                hosts[ip]["hostname"] = hn
            cur = ip
        elif cur and cur in hosts:
            mac_m = re.match(r'\s*MAC Address: ([0-9A-Fa-f:]+)\s*(?:\(([^)]*)\))?', line)
            if mac_m:
                hosts[cur]["mac"] = mac_m.group(1)
                hosts[cur]["vendor"] = mac_m.group(2) or hosts[cur].get("vendor", "")

# Parse nbtscan
nbt_file = os.path.join(tmpdir, "nbt.txt")
if os.path.exists(nbt_file):
    for line in open(nbt_file):
        parts = line.strip().split('|')
        if len(parts) >= 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0].strip()):
            ip = parts[0].strip()
            name = parts[1].strip() if len(parts) > 1 else ""
            if ip in hosts and name and not hosts[ip]["hostname"]:
                hosts[ip]["hostname"] = name
            elif ip not in hosts:
                hosts[ip] = {"ip": ip, "mac": "", "vendor": "", "hostname": name, "ports": [], "status": "up"}

# Parse ports
ports_file = os.path.join(tmpdir, "ports.txt")
if os.path.exists(ports_file):
    for line in open(ports_file):
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        m = re.match(r'Host:\s+([\d.]+)', line)
        if not m:
            continue
        ip = m.group(1)
        ports_section = line.split("Ports:")[1] if "Ports:" in line else ""
        for pm in re.finditer(r'(\d+)/open/tcp//([^/]*)', ports_section):
            port = int(pm.group(1))
            service = pm.group(2).strip() or "unknown"
            if ip in hosts:
                hosts[ip]["ports"].append({"port": port, "service": service})

host_list = sorted(hosts.values(), key=lambda h: [int(p) for p in h["ip"].split(".")])
print(f"[+] Total hosts encontrados: {len(host_list)}")

# Send to Kali server
payload = json.dumps({
    "nebula_ip": nebula_ip,
    "subnet": subnet,
    "hosts": host_list,
}).encode()

try:
    req = Request(f"{kali_api}/api/probe/scan-results",
                  data=payload,
                  headers={"Content-Type": "application/json"},
                  method="POST")
    resp = urlopen(req, timeout=15)
    result = json.loads(resp.read())
    print(f"[+] Resultados enviados al servidor: {result.get('received', 0)} hosts")
except Exception as e:
    print(f"[!] Error al enviar resultados: {e}")
PYEOF
    else
        warn "Python3 no disponible — enviando JSON básico"
        # Fallback: send what we have via curl
        JSON_PAYLOAD="{\"nebula_ip\":\"$MY_NEBULA_IP\",\"subnet\":\"$SUBNET\",\"hosts\":[$HOSTS_JSON]}"
        # Remove trailing comma before ]
        JSON_PAYLOAD=$(echo "$JSON_PAYLOAD" | sed 's/,\]/]/')
        curl -sf -X POST "${KALI_API}/api/probe/scan-results" \
            -H "Content-Type: application/json" \
            -d "$JSON_PAYLOAD" && info "Resultados enviados" || warn "Error al enviar"
    fi

    rm -rf "$TMPDIR"
}

# ── Detect LAN interface ──
if [ "$OS" = "Darwin" ]; then
    LAN_IF=$(route -n get default 2>/dev/null | grep interface | awk '{print $2}')
else
    LAN_IF=$(ip route | grep default | awk '{print $5}' | head -1)
fi

# ── Main ──
info "Iniciando agente de sonda para $SUBNET"
info "Servidor Kali: $KALI_API"
info "Interfaz LAN: ${LAN_IF:-auto}"

if [ "$LOOP_INTERVAL" -gt 0 ] 2>/dev/null; then
    info "Modo continuo: escaneo cada ${LOOP_INTERVAL}s"
    while true; do
        debug "=== Escaneo $(date) ==="
        run_scan
        info "Próximo escaneo en ${LOOP_INTERVAL}s..."
        sleep "$LOOP_INTERVAL"
    done
else
    run_scan
fi
