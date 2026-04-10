#!/bin/bash
# nebula-cert-manager.sh — Gestión de certificados Nebula
# Uso:
#   sudo ./nebula-cert-manager.sh issue <nombre> <ip-nebula/mask> [grupos] [duracion]
#   sudo ./nebula-cert-manager.sh list
#   sudo ./nebula-cert-manager.sh info  <nombre>
#   sudo ./nebula-cert-manager.sh revoke <nombre>
#   sudo ./nebula-cert-manager.sh config <nombre>  [servidor-publico]
#   sudo ./nebula-cert-manager.sh bundle <nombre>  [directorio-salida]
set -e

NEBULA_CERT="/opt/nebula/nebula-cert"
CERTS_DIR="/etc/nebula/certs"
CONFIG_DIR="/etc/nebula"
SERVER_PUBLIC_IP="3.143.18.161"
SERVER_NEBULA_IP="192.168.100.1"
LISTEN_PORT=4242

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
title() { echo -e "\n${CYAN}━━ $* ━━${NC}"; }

[ "$EUID" -ne 0 ] && error "Ejecutar como root: sudo $0 $*"
[ ! -f "$NEBULA_CERT" ] && error "nebula-cert no encontrado en $NEBULA_CERT. Ejecuta nebula-setup.sh primero."
[ ! -f "$CERTS_DIR/ca.crt" ] && error "CA no encontrada en $CERTS_DIR/ca.crt. Ejecuta nebula-setup.sh primero."

_safe_name() { echo "$1" | sed 's/[^a-zA-Z0-9_-]/_/g'; }

cmd_issue() {
    local name groups dur crt key
    name="$(_safe_name "${1:-}")"
    local nip="${2:-}"
    groups="${3:-clients}"
    dur="${4:-8760h}"

    [ -z "$name" ] || [ -z "$nip" ] && { echo "Uso: $0 issue <nombre> <ip/mask> [grupos] [duracion]"; exit 1; }

    crt="$CERTS_DIR/${name}.crt"
    key="$CERTS_DIR/${name}.key"

    [ -f "$crt" ] && warn "Sobreescribiendo certificado existente para '$name'"

    title "Emitiendo certificado para $name"
    "$NEBULA_CERT" sign \
        -ca-crt "$CERTS_DIR/ca.crt" \
        -ca-key "$CERTS_DIR/ca.key" \
        -name   "$name" \
        -ip     "$nip" \
        -groups "$groups" \
        -duration "$dur" \
        -out-crt "$crt" \
        -out-key "$key"
    chmod 600 "$key"
    info "Certificado emitido:"
    info "  CRT : $crt"
    info "  KEY : $key"
    info "  IP  : $nip"
    info "  Grupos: $groups | Duración: $dur"
    echo ""
    info "Para descargar el bundle completo:"
    echo "  sudo $0 bundle $name"
}

cmd_list() {
    title "Certificados Nebula emitidos"
    local found=0
    printf "%-30s %-22s %-20s %s\n" "NOMBRE" "IP OVERLAY" "GRUPOS" "EXPIRA"
    echo "────────────────────────────────────────────────────────────────────────────────"
    for f in "$CERTS_DIR"/*.crt; do
        [ -f "$f" ] || continue
        local bname
        bname=$(basename "$f" .crt)
        [ "$bname" = "ca" ] || [ "$bname" = "server" ] && continue
        local info_out ip groups not_after
        info_out=$("$NEBULA_CERT" print -path "$f" 2>/dev/null || echo "")
        ip=$(echo "$info_out"      | grep -E '^\s+ip:' | head -1 | sed 's/.*ip://' | tr -d ' ')
        groups=$(echo "$info_out"  | grep -E '^\s+groups:' | head -1 | sed 's/.*groups://' | tr -d ' []')
        not_after=$(echo "$info_out" | grep -E '^\s+not after:' | head -1 | sed 's/.*not after://' | tr -d ' ')
        printf "%-30s %-22s %-20s %s\n" "$bname" "${ip:---}" "${groups:---}" "${not_after:---}"
        ((found++)) || true
    done
    [ "$found" -eq 0 ] && echo "  (sin certificados de cliente)"
}

cmd_info() {
    local name crt
    name="$(_safe_name "${1:-}")"
    [ -z "$name" ] && { echo "Uso: $0 info <nombre>"; exit 1; }
    crt="$CERTS_DIR/${name}.crt"
    [ ! -f "$crt" ] && error "Certificado no encontrado: $crt"
    title "Info: $name"
    "$NEBULA_CERT" print -path "$crt"
}

cmd_revoke() {
    local name
    name="$(_safe_name "${1:-}")"
    [ -z "$name" ] && { echo "Uso: $0 revoke <nombre>"; exit 1; }
    local crt="$CERTS_DIR/${name}.crt"
    local key="$CERTS_DIR/${name}.key"
    [ ! -f "$crt" ] && error "Certificado no encontrado: $crt"
    read -rp "¿Eliminar definitivamente el certificado de '$name'? [s/N] " resp
    [[ "$resp" =~ ^[sS]$ ]] || { warn "Operación cancelada."; exit 0; }
    rm -f "$crt" "$key"
    info "Certificado '$name' eliminado."
    warn "Nota: Nebula no soporta CRL nativa. Para bloqueo inmediato, actualiza el firewall"
    warn "o regenera la CA y todos los certificados."
}

cmd_config() {
    local name server_pub
    name="$(_safe_name "${1:-}")"
    server_pub="${2:-$SERVER_PUBLIC_IP}"
    [ -z "$name" ] && { echo "Uso: $0 config <nombre> [servidor-publico]"; exit 1; }
    local crt="$CERTS_DIR/${name}.crt"
    local ip
    ip=$("$NEBULA_CERT" print -path "$crt" 2>/dev/null | grep -E '^\s+ip:' | head -1 | sed 's/.*ip://' | tr -d ' ' || echo "")

    title "Config YAML para $name (IP: ${ip:---})"
    cat <<YAML
# Nebula config — nodo: ${name}
# Generado por nebula-cert-manager.sh

pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/${name}.crt
  key: /etc/nebula/${name}.key

static_host_map:
  "${SERVER_NEBULA_IP}": ["${server_pub}:${LISTEN_PORT}"]

lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "${SERVER_NEBULA_IP}"

listen:
  host: 0.0.0.0
  port: 0

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

# ── Exponer tu red local al servidor Kali ─────────────────────────────────────
# Ejecuta el script incluido en el bundle para registrar tus subnets:
#   Linux/macOS : sudo bash announce.sh
#   Windows     : PowerShell (como Admin) > .\announce.ps1
YAML
}

cmd_bundle() {
    local name outdir
    name="$(_safe_name "${1:-}")"
    outdir="${2:-/tmp/nebula_${name}_bundle}"
    [ -z "$name" ] && { echo "Uso: $0 bundle <nombre> [directorio-salida]"; exit 1; }

    local crt="$CERTS_DIR/${name}.crt"
    local key="$CERTS_DIR/${name}.key"
    local ca="$CERTS_DIR/ca.crt"
    [ ! -f "$crt" ] && error "Certificado no encontrado: $crt"

    mkdir -p "$outdir"
    cp "$crt"   "$outdir/${name}.crt"
    [ -f "$key" ] && cp "$key" "$outdir/${name}.key" && chmod 600 "$outdir/${name}.key"
    [ -f "$ca"  ] && cp "$ca"  "$outdir/ca.crt"
    cmd_config "$name" > "$outdir/${name}_config.yaml"

    # ── announce.sh (Linux / macOS) ──────────────────────────────────────────
    cat > "$outdir/announce.sh" <<'ANNOUNCE_SH'
#!/bin/bash
# Registra las subnets locales de este nodo en el servidor Kali
# Uso: sudo bash announce.sh
set -e
KALI_URL="http://3.143.18.161:8040"
NEBULA_IF="nebula0"

MY_NEBULA_IP=$(ip addr show "$NEBULA_IF" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
[ -z "$MY_NEBULA_IP" ] && { echo "[!] $NEBULA_IF no está activa. Arranca Nebula primero."; exit 1; }

# Habilitar reenvío IP
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# MASQUERADE: el tráfico del overlay Nebula sale con nuestra IP local
iptables -t nat -C POSTROUTING -s 192.168.100.0/24 ! -o nebula0 -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s 192.168.100.0/24 ! -o nebula0 -j MASQUERADE

# Obtener subnets locales (excluye nebula, loopback y rutas host /32)
SUBNETS=$(ip route show | awk '$1~/\// && $1!~/^192\.168\.100\.|^127\./ {print $1}' | sort -u | head -10)

[ -z "$SUBNETS" ] && { echo "[!] No se encontraron subnets locales."; exit 1; }

# Construir JSON
JSON="{\"nebula_ip\":\"$MY_NEBULA_IP\",\"subnets\":["
first=1
for s in $SUBNETS; do
  [ $first -eq 0 ] && JSON+=","
  JSON+="\"$s\""
  first=0
done
JSON+="]}"

echo "[*] Registrando en Kali: $JSON"
curl -sf -X POST "$KALI_URL/api/nebula/announce" \
  -H "Content-Type: application/json" -d "$JSON" && echo "[+] Rutas registradas OK" || echo "[!] Error al contactar Kali"
ANNOUNCE_SH
    chmod +x "$outdir/announce.sh"

    # ── announce.ps1 (Windows) ───────────────────────────────────────────────
    cat > "$outdir/announce.ps1" <<'ANNOUNCE_PS1'
# Registra las subnets locales de este nodo en el servidor Kali
# Ejecutar como Administrador: PowerShell -ExecutionPolicy Bypass -File announce.ps1
$KaliUrl   = "http://3.143.18.161:8040"
$NebulaIf  = "nebula0"

$NebulaIP = (Get-NetIPAddress -InterfaceAlias $NebulaIf -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
if (-not $NebulaIP) { Write-Host "[!] $NebulaIf no está activa. Arranca Nebula primero." ; exit 1 }

# Habilitar reenvío IP (requiere Admin)
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        -Name "IPEnableRouter" -Value 1 -ErrorAction Stop
} catch { Write-Host "[!] No se pudo habilitar IPEnableRouter: $_" }

# NAT: tráfico del overlay Nebula sale con nuestra IP local
$existingNat = Get-NetNat -Name "NebulaNAT" -ErrorAction SilentlyContinue
if (-not $existingNat) {
    try { New-NetNat -Name "NebulaNAT" -InternalIPInterfaceAddressPrefix "192.168.100.0/24" | Out-Null
          Write-Host "[+] NAT NebulaNAT creado" }
    catch { Write-Host "[!] No se pudo crear NAT: $_" }
}

# Obtener subnets locales (excluye nebula, loopback, /32)
$subnets = Get-NetRoute -AddressFamily IPv4 |
    Where-Object { $_.NextHop -eq "0.0.0.0" -and $_.PrefixLength -lt 32 -and
                   $_.DestinationPrefix -notmatch "^127\.|^192\.168\.100\." } |
    Select-Object -ExpandProperty DestinationPrefix | Select-Object -First 10

if (-not $subnets) { Write-Host "[!] No se encontraron subnets locales." ; exit 1 }

$body = @{ nebula_ip = $NebulaIP; subnets = @($subnets) } | ConvertTo-Json
Write-Host "[*] Registrando en Kali: $body"
try {
    $resp = Invoke-RestMethod -Uri "$KaliUrl/api/nebula/announce" -Method Post `
                               -Body $body -ContentType "application/json"
    Write-Host "[+] Rutas registradas: $($resp.added -join ', ')"
} catch { Write-Host "[!] Error al contactar Kali: $_" }
ANNOUNCE_PS1

    title "Bundle generado en: $outdir"
    ls -lh "$outdir"
    echo ""
    info "Instrucciones para el cliente:"
    echo "  1. Copia los archivos a /etc/nebula/ en el nodo cliente"
    echo "  2. Instala nebula: https://github.com/slackhq/nebula/releases"
    echo "  3. sudo nebula -config /etc/nebula/${name}_config.yaml"

    # Crear ZIP si zip está disponible
    if command -v zip &>/dev/null; then
        local zipf="/tmp/nebula_${name}.zip"
        zip -j "$zipf" "$outdir"/* &>/dev/null
        info "ZIP listo: $zipf"
    fi
}

# ── Dispatcher ────────────────────────────────────────────────────────────────
case "${1:-help}" in
    issue)  shift; cmd_issue  "$@" ;;
    list)   shift; cmd_list   "$@" ;;
    info)   shift; cmd_info   "$@" ;;
    revoke) shift; cmd_revoke "$@" ;;
    config) shift; cmd_config "$@" ;;
    bundle) shift; cmd_bundle "$@" ;;
    help|*)
        echo ""
        echo "Uso: sudo $0 <comando> [opciones]"
        echo ""
        echo "Comandos:"
        echo "  issue  <nombre> <ip/mask> [grupos] [duración]   Emite un nuevo certificado"
        echo "  list                                             Lista certificados emitidos"
        echo "  info   <nombre>                                  Muestra detalles del certificado"
        echo "  revoke <nombre>                                  Elimina el certificado"
        echo "  config <nombre> [servidor-publico]               Imprime config YAML de cliente"
        echo "  bundle <nombre> [directorio]                     Genera bundle descargable (crt+key+ca+yaml)"
        echo ""
        echo "Ejemplos:"
        echo "  sudo $0 issue empresa-gw 192.168.100.10/24 clients 8760h"
        echo "  sudo $0 list"
        echo "  sudo $0 bundle empresa-gw /tmp/bundle_empresa"
        echo "  sudo $0 revoke empresa-gw"
        echo ""
        ;;
esac
