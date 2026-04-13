# Kali VPN Vulnerability Scanner

Consola web de seguridad ofensiva construida sobre **Kali Linux**. Permite ejecutar escaneos de red, enumerar servicios, auditar credenciales, capturar tráfico en tiempo real y monitorear alertas IDS — todo desde una interfaz gráfica accesible por navegador.

## Arquitectura

| Componente | Tecnología |
|---|---|
| Backend | Python 3 / Flask (archivo único `web_scanner.py`) |
| Frontend | HTML/JS/CSS embebido, Chart.js 4.4, D3.js v7 |
| Streaming | Server-Sent Events (SSE) |
| Reportes | `reportlab` (PDF con tema claro) |
| IDS | Suricata (daemon, alertas vía `fast.log`) |
| Tráfico | tcpdump + ntopng (Docker) |
| VPN | OpenVPN · WireGuard · **Nebula** (lighthouse) |
| Despliegue | systemd (`vuln-scanner.service`) en AWS EC2 |

## Pestañas

1. **Escaneo** — Ejecutar perfiles de escaneo contra objetivos de red
2. **Historial** — Revisar resultados anteriores y descargar PDFs
3. **Mapa de Red** — Visualización D3.js de hosts descubiertos
4. **Captura de Tráfico** — tcpdump en vivo con filtros BPF, gráficos en tiempo real (paquetes/s, top IPs, puertos, flags TCP, entrada vs salida)
5. **IDS Suricata** — Alertas en vivo, gráficos de timeline, firmas top, severidad, IPs origen
6. **Nebula VPN** — Gestión de PKI Nebula: emitir/listar/revocar/descargar certificados de cliente desde el navegador

## Perfiles de Escaneo

### Fase 1 — Descubrimiento y Escaneo
- Descubrimiento de hosts vivos (sin `-Pn` para host discovery real)
- Puertos top-1000 / completos (1-65535)
- Scripts NSE (vuln, http-title, ssh-hostkey, ftp-anon)
- CVEs con CVSS (vulners, mincvss=5.0)
- Nikto (análisis web)
- SMB vulnerabilidades (`smb-vuln*`)
- SSL/TLS (nmap `ssl-enum-ciphers` + sslscan)

### Fase 2 — Enumeración de Servicios
- enum4linux (enumeración SMB completa)
- smbclient (shares anónimos)
- Banner grabbing (puertos clave: 21,22,23,25,80,110,143,443,3389,8080)
- SNMP walk (community public/private)

### Fase 3 — Análisis de Aplicaciones Web
- Gobuster (directorios HTTP/HTTPS, wordlists: common.txt y big.txt)
- SQLMap (GET básico y POST login, level=3, risk=2)

### Fase 4 — Auditoría de Credenciales
- Hydra (SSH, RDP, HTTP-form POST, FTP con rockyou.txt)
- John the Ripper (wordlist estándar y formato NTLM)
- Hashcat (NTLM mode 1000, MD5 mode 0)

> **Nota:** No se usa `-sV` en perfiles nmap (causa hangs sobre VPN). Scripts SSL excluidos de la categoría vuln por la misma razón.

## Captura de Tráfico

- Captura en vivo con tcpdump sobre cualquier interfaz (eth0, any, tailscale0, nebula0)
- Filtros BPF personalizados
- Gráficos en tiempo real (ventana rolling de 5 minutos):
  - Paquetes por segundo
  - Top 5 IPs origen/destino
  - Top 5 puertos
  - Distribución de flags TCP
  - Tráfico de entrada vs salida
- Soporte para paquetes TCP y UDP
- Descarga de archivos pcap

## IDS Suricata

- Inicio/parada de Suricata desde la interfaz web
- Selección de interfaz de monitoreo
- Parseo en tiempo real de `/var/log/suricata/fast.log`
- 4 gráficos Chart.js (ventana rolling de 5 minutos):
  - Timeline de alertas
  - Top firmas (signatures)
  - Distribución de severidad (doughnut)
  - Top IPs origen
- Tabla de alertas en vivo con columnas: Hora, Severidad, Origen, Destino, Protocolo, Firma
- Polling: alertas cada 1.5s, estadísticas cada 2.5s

## Nebula VPN

El servidor Kali actúa como **lighthouse** (nodo central de coordinación) de una red Nebula superpuesta (`192.168.100.0/24`). Cada cliente recibe un certificado firmado por la CA del servidor y se conecta directamente con hole-punching UDP.

### Arquitectura Nebula

```
                        ┌─────────────────────────────────────┐
                        │   Kali AWS  (EC2)                    │
                        │   nebula0 → 192.168.100.1/24        │
                        │   Puerto UDP: 4242                   │
                        │   Rol: Lighthouse                    │
                        └──────────────┬──────────────────────┘
                                       │ UDP hole-punching
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
   ┌──────────▼───────┐    ┌───────────▼──────┐    ┌──────────▼──────────┐
   │  Cliente A       │    │  Cliente B       │    │  Cliente C          │
   │  192.168.100.10  │    │  192.168.100.20  │    │  192.168.100.30     │
   │  grupo: clients  │    │  grupo: clients  │    │  grupo: servers     │
   └──────────────────┘    └──────────────────┘    └─────────────────────┘
```

### Instalación del Servidor (Lighthouse)

```bash
sudo ./nebula-setup.sh
```

El script descarga Nebula v1.9.5, genera la CA, crea el certificado del lighthouse, configura y activa `nebula.service` con systemd.

### Gestión de Certificados (CLI)

```bash
sudo ./nebula-cert-manager.sh issue <nombre> <ip>/24 <grupo> <duración>
sudo ./nebula-cert-manager.sh list
sudo ./nebula-cert-manager.sh info <nombre>
sudo ./nebula-cert-manager.sh bundle <nombre> /tmp/bundle
sudo ./nebula-cert-manager.sh config <nombre>
sudo ./nebula-cert-manager.sh revoke <nombre>
```

### Gestión de Certificados (Web UI)

Desde la pestaña **Nebula VPN** del scanner:
- Estado del servidor: proceso nebula, interfaz nebula0, IP overlay, CA
- Emitir certificado: nombre, IP overlay, grupos, duración
- Tabla de certs: IP, grupos, expiración, botones Descargar ZIP / Ver YAML / Revocar

### Instalación en Nodo Cliente

```bash
sudo mkdir -p /etc/nebula
# Copiar archivos del bundle ZIP descargado desde la Web UI
sudo cp <nombre>.crt <nombre>.key ca.crt /etc/nebula/

# macOS — limpiar sesiones previas:
sudo pkill -f nebula 2>/dev/null; true
sudo route delete -net 192.168.100.0/24 2>/dev/null; true

# Iniciar:
sudo nebula -config /etc/nebula/<nombre>_config.yaml

# Verificar:
ping 192.168.100.1
```

> **macOS:** el config.yaml descargado usa `tun.dev: utun`. **Linux:** cambiar a `dev: nebula0`.

### Servicio de Routing (Servidor)

Si Tailscale está activo con `RouteAll: true`, instalar el servicio de prioridad de routing:

```bash
sudo cp nebula-routing.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nebula-routing.service
```

### Troubleshooting Nebula

| Síntoma | Solución |
|---|---|
| `interface name must be utun[0-9]+` (macOS) | Config descargado ya usa `dev: utun` |
| `failed to write route: file exists` | `sudo route delete -net 192.168.100.0/24` antes de arrancar |
| Ping timeout de cliente a servidor | Instalar `nebula-routing.service` (conflicto con Tailscale tabla 52) |
| `CA no encontrada` en Web UI | Usar botón "Inicializar CA" |
| `certificate expires after signing certificate` | El backend auto-recorta la duración al límite de la CA |

### Comparativa VPN

| Característica | OpenVPN | WireGuard | Nebula |
|---|---|---|---|
| Protocolo | TCP/UDP | UDP | UDP |
| PKI propia | No | No | Sí (`nebula-cert`) |
| Hole-punching | No | Limitado | Sí (nativo) |
| Firewall integrado | No | No | Sí |
| Lighthouse | No | No | Sí |
| Certs en Web UI | No | No | **Sí** |

## Reportes PDF

- Generación automática desde el historial de escaneos
- Tema claro (fondo blanco, texto negro)
- Tabla de hosts muestra solo hosts con puertos abiertos confirmados
- Incluye logo corporativo (`logo_datacom.png`)

## Requisitos del Servidor

- Kali Linux (2025.x+)
- Python 3.11+ con Flask, reportlab
- nmap, nikto, gobuster, sqlmap, hydra, john, hashcat
- enum4linux, smbclient, snmpwalk
- tcpdump, suricata
- Docker (para ntopng)
- Nebula v1.9.5+ (instalado por `nebula-setup.sh`)

## Instalación

```bash
git clone https://github.com/mlogacho/kali.git
cd kali

pip install flask reportlab

sudo mkdir -p /opt/scanner/scans /opt/scanner/vpn_configs
sudo cp web_scanner.py /opt/scanner/web_scanner.py

# Crear servicio systemd
sudo tee /etc/systemd/system/vuln-scanner.service > /dev/null <<EOF
[Unit]
Description=Kali VPN Vulnerability Scanner
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/scanner
ExecStart=/usr/bin/python3 /opt/scanner/web_scanner.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vuln-scanner

# Instalar Nebula (opcional)
sudo ./nebula-setup.sh
```

## Despliegue Rápido (desde Mac)

```bash
# Script automatizado
bash deploy.sh

# O manualmente:
scp -i kali-aws.pem web_scanner.py kali@<IP>:/opt/scanner/web_scanner.py
ssh -i kali-aws.pem kali@<IP> "sudo systemctl restart vuln-scanner"
```

## ntopng (opcional)

```bash
docker run -d --name ntopng --net=host \
  --memory=512m --cpus=0.5 \
  ntop/ntopng:latest -i eth0 -i nebula0
```

Acceder en `http://<IP>:3000` (admin/admin).

## Puertos

| Puerto | Servicio |
|---|---|
| 8040 | Vulnerability Scanner (Flask) |
| 3000 | ntopng (Docker) |
| 4242/UDP | Nebula VPN lighthouse |

## Estructura de Archivos

```
kali/
├── web_scanner.py               # App principal (Flask + HTML/JS/CSS embebido)
├── vuln_scanner.py              # Versión legacy del scanner (GUI Tkinter)
├── deploy.sh                    # Script de despliegue automatizado
├── nebula-setup.sh              # Instalación y configuración del lighthouse Nebula
├── nebula-cert-manager.sh       # Gestión de certificados Nebula (CLI)
├── nebula-routing.service       # Systemd: reglas de routing Nebula vs Tailscale
├── probe-agent.sh               # Agente de sonda para escaneo distribuido
├── probe-gateway.sh             # Gateway de sondas
├── generar_manual.py            # Generador de manual PDF
├── logo_datacom.png             # Logo corporativo para PDFs
├── reporte_vulnerabilidades.html # Reporte HTML de ejemplo
├── Informe_Ejecutivo_Seguridad.pdf
├── Manual_Kali_VPN_Scanner.pdf
├── .gitignore
└── README.md
```

## Uso

1. Acceder a `http://<kali-ip>:8040`
2. Configurar clientes VPN en el sidebar (OpenVPN / WireGuard / Nebula)
3. Seleccionar perfil de escaneo y objetivo
4. Ver resultados en tiempo real vía SSE
5. Descargar reportes PDF desde Historial
6. Monitorear tráfico en Captura de Tráfico
7. Activar detección de intrusos en IDS Suricata
8. Gestionar certificados Nebula desde la pestaña Nebula VPN

## Licencia

Uso interno — Herramienta de auditoría de seguridad.
