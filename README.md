# Kali VPN Vulnerability Scanner

Consola web de seguridad ofensiva construida sobre **Kali Linux**. Permite ejecutar escaneos de red, enumerar servicios, auditar credenciales, capturar tráfico en tiempo real y monitorear alertas IDS — todo desde una interfaz gráfica accesible por navegador.

## Arquitectura

| Componente | Tecnología |
|---|---|
| Backend | Python 3 / Flask (archivo único `web_scanner.py`) |
| Frontend | HTML/JS/CSS embebido, Chart.js 4.4, D3.js v7 |
| Streaming | Server-Sent Events (SSE) |
| Reportes | `reportlab` (PDF) |
| IDS | Suricata (daemon) |
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
- Descubrimiento de hosts vivos
- Puertos top-1000 / completos (1-65535)
- Scripts NSE (vuln, http-title, ssh-hostkey, ftp-anon)
- CVEs con CVSS (vulners)
- Nikto (web)
- SMB vulnerabilidades
- SSL/TLS (nmap + sslscan)

### Fase 2 — Enumeración de Servicios
- enum4linux (SMB completo)
- smbclient (shares anónimos)
- Banner grabbing (puertos clave)
- SNMP walk (community public/private)

### Fase 3 — Análisis de Aplicaciones Web
- Gobuster (directorios HTTP/HTTPS, common.txt y big.txt)
- SQLMap (GET básico, POST login)

### Fase 4 — Auditoría de Credenciales
- Hydra (SSH, RDP, HTTP-form, FTP)
- John the Ripper (wordlist, NTLM)
- Hashcat (NTLM, MD5)

---

## Nebula VPN

El servidor Kali actúa como **lighthouse** (nodo central de coordinación) de una red Nebula superpuesta (`192.168.100.0/24`). Cada cliente recibe un certificado firmado por la CA del servidor y se conecta directamente con hole-punching UDP.

### Arquitectura Nebula

```
                        ┌─────────────────────────────────────┐
                        │   Kali AWS  3.143.18.161             │
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
# En el servidor Kali:
sudo ./nebula-setup.sh
```

El script:
1. Descarga Nebula v1.9.5 + nebula-cert en `/opt/nebula/`
2. Genera la CA en `/etc/nebula/certs/ca.crt`
3. Genera el certificado del lighthouse
4. Crea `/etc/nebula/config.yaml`
5. Crea y activa `nebula.service` con systemd

### Gestión de Certificados (CLI)

```bash
# Emitir certificado para un cliente
sudo ./nebula-cert-manager.sh issue empresa-router01 192.168.100.10/24 clients 8760h

# Listar certificados emitidos
sudo ./nebula-cert-manager.sh list

# Ver detalles de un certificado
sudo ./nebula-cert-manager.sh info empresa-router01

# Generar bundle ZIP descargable (crt + key + ca + config.yaml)
sudo ./nebula-cert-manager.sh bundle empresa-router01 /tmp/bundle

# Ver config YAML de cliente (para copiar en el nodo)
sudo ./nebula-cert-manager.sh config empresa-router01

# Revocar certificado
sudo ./nebula-cert-manager.sh revoke empresa-router01
```

### Gestión de Certificados (Web UI)

Desde `http://3.143.18.161:8040` → pestaña **🌐 Nebula VPN**:

- **Estado del servidor**: proceso nebula, interfaz nebula0, IP overlay, CA
- **Emitir certificado**: nombre, IP overlay, grupos, duración
- **Tabla de certs**: IP, grupos, fecha de expiración, botones Descargar ZIP / Ver YAML / Revocar

### Instalación en Nodo Cliente

```bash
# En el nodo cliente (Linux):
sudo mkdir -p /etc/nebula
# Copiar archivos del bundle:
sudo cp empresa-router01.crt empresa-router01.key ca.crt /etc/nebula/

# Descargar nebula para la plataforma del cliente:
# https://github.com/slackhq/nebula/releases

# Iniciar Nebula:
sudo nebula -config /etc/nebula/empresa-router01_config.yaml

# Verificar conexión:
ping 192.168.100.1   # lighthouse
```

### Integración con el Scanner

Al configurar un cliente con **Tipo VPN = Nebula** en el sidebar:
- Ingresar la IP Nebula del nodo cliente (campo "IP Nebula")
- Los grupos determinan las reglas de firewall Nebula
- Al hacer clic en "Conectar VPN" se lanza `nebula -config <ruta>` en el servidor
- La interfaz `nebula0` se detecta automáticamente al conectar

### Puertos Nebula

| Puerto | Protocolo | Uso |
|---|---|---|
| 4242 | UDP | Lighthouse — coordinación y datos |

### Comparativa VPN

| Característica | OpenVPN | WireGuard | Nebula |
|---|---|---|---|
| Protocolo | TCP/UDP | UDP | UDP |
| PKI propia | No (usa tls/ssl) | No (claves ed25519) | Sí (`nebula-cert`) |
| Hole-punching | No | Limitado | Sí (nativo) |
| Firewall integrado | No | No | Sí |
| Lighthouse (coordinador) | No | No | Sí |
| Certificados gestionados en UI | No | No | **Sí** |

---

## Requisitos del Servidor

- Kali Linux (2025.x+)
- Python 3.11+ con Flask, reportlab
- nmap, nikto, gobuster, sqlmap, hydra, john, hashcat
- enum4linux, smbclient, snmpwalk
- tcpdump, suricata
- Docker (para ntopng)
- Nebula v1.9.5+ en `/opt/nebula/` (instalado por `nebula-setup.sh`)

## Instalación

```bash
# Clonar repositorio
git clone https://github.com/mlogacho/kali.git
cd kali

# Instalar dependencias Python
pip install flask reportlab

# Crear directorios
sudo mkdir -p /opt/scanner/scans /opt/scanner/vpn_configs

# Copiar app
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

# Instalar y configurar Nebula (opcional)
sudo ./nebula-setup.sh
```

## Despliegue Rápido (desde Mac)

```bash
# Subir y reiniciar
bash deploy.sh

# O manualmente:
scp -i kali-aws.pem web_scanner.py kali@3.143.18.161:/opt/scanner/web_scanner.py
ssh -i kali-aws.pem kali@3.143.18.161 "sudo systemctl restart vuln-scanner"
```

## ntopng (opcional)

```bash
docker run -d --name ntopng --net=host \
  --memory=512m --cpus=0.5 \
  ntop/ntopng:latest -i eth0 -i nebula0
```

Acceder en `http://3.143.18.161:3000` (admin/admin).

## Puertos

| Puerto | Servicio |
|---|---|
| 8040 | Vulnerability Scanner (Flask) |
| 3000 | ntopng (Docker) |
| 4242/UDP | Nebula VPN lighthouse |

## Estructura de Archivos

```
├── web_scanner.py            # App principal (Flask + HTML/JS/CSS)
├── deploy.sh                 # Script de despliegue automatizado
├── nebula-setup.sh           # Instalación y configuración del lighthouse Nebula
├── nebula-cert-manager.sh    # Gestión de certificados Nebula (issue/list/bundle/revoke)
├── generar_manual.py         # Generador de manual PDF
├── vuln_scanner.py           # Versión legacy del scanner (GUI Tkinter)
├── logo_datacom.png          # Logo corporativo para PDFs
├── reporte_vulnerabilidades.html  # Reporte HTML de ejemplo
└── README.md
```

## Uso

1. Acceder a `http://3.143.18.161:8040`
2. Configurar clientes VPN (sidebar izquierdo — Tipo: OpenVPN / WireGuard / Nebula)
3. Seleccionar perfil de escaneo y objetivo
4. Ver resultados en tiempo real vía SSE
5. Descargar reportes PDF desde Historial
6. Monitorear tráfico en Captura de Tráfico
7. Activar detección de intrusos en IDS Suricata
8. Gestionar certificados Nebula desde pestaña **🌐 Nebula VPN**

## Licencia

Uso interno — Herramienta de auditoría de seguridad.


## Pestañas

1. **Escaneo** — Ejecutar perfiles de escaneo contra objetivos de red
2. **Historial** — Revisar resultados anteriores y descargar PDFs
3. **Mapa de Red** — Visualización D3.js de hosts descubiertos
4. **Captura de Tráfico** — tcpdump en vivo con filtros BPF, gráficos en tiempo real (paquetes/s, top IPs, puertos, flags TCP, entrada vs salida)
5. **IDS Suricata** — Alertas en vivo, gráficos de timeline, firmas top, severidad, IPs origen

## Perfiles de Escaneo

### Fase 1 — Descubrimiento y Escaneo
- Descubrimiento de hosts vivos
- Puertos top-1000 / completos (1-65535)
- Scripts NSE (vuln, http-title, ssh-hostkey, ftp-anon)
- CVEs con CVSS (vulners)
- Nikto (web)
- SMB vulnerabilidades
- SSL/TLS (nmap + sslscan)

### Fase 2 — Enumeración de Servicios
- enum4linux (SMB completo)
- smbclient (shares anónimos)
- Banner grabbing (puertos clave)
- SNMP walk (community public/private)

### Fase 3 — Análisis de Aplicaciones Web
- Gobuster (directorios HTTP/HTTPS, common.txt y big.txt)
- SQLMap (GET básico, POST login)

### Fase 4 — Auditoría de Credenciales
- Hydra (SSH, RDP, HTTP-form, FTP)
- John the Ripper (wordlist, NTLM)
- Hashcat (NTLM, MD5)

## Requisitos del Servidor

- Kali Linux (2025.x+)
- Python 3.11+ con Flask, reportlab
- nmap, nikto, gobuster, sqlmap, hydra, john, hashcat
- enum4linux, smbclient, snmpwalk
- tcpdump, suricata
- Docker (para ntopng)

## Instalación

```bash
# Clonar repositorio
git clone https://github.com/mlogacho/kali.git
cd kali

# Instalar dependencias Python
pip install flask reportlab

# Crear directorios
sudo mkdir -p /opt/scanner/scans /opt/scanner/vpn_configs

# Copiar app
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
```

## Despliegue Rápido (desde Mac)

```bash
# Subir y reiniciar
scp -i kali-aws.pem web_scanner.py kali@<IP>:/opt/scanner/web_scanner.py
ssh -i kali-aws.pem kali@<IP> "sudo systemctl restart vuln-scanner"
```

## ntopng (opcional)

```bash
docker run -d --name ntopng --net=host \
  --memory=512m --cpus=0.5 \
  ntop/ntopng:latest -i eth0 -i tailscale0
```

Acceder en `http://<IP>:3000` (admin/admin).

## Puertos

| Puerto | Servicio |
|---|---|
| 8040 | Vulnerability Scanner (Flask) |
| 3000 | ntopng (Docker) |

## Estructura de Archivos

```
├── web_scanner.py          # App principal (Flask + HTML/JS/CSS)
├── deploy.sh               # Script de despliegue automatizado
├── generar_manual.py       # Generador de manual PDF
├── vuln_scanner.py         # Versión legacy del scanner
├── logo_datacom.png        # Logo corporativo para PDFs
├── reporte_vulnerabilidades.html  # Reporte HTML de ejemplo
└── README.md
```

## Uso

1. Acceder a `http://<kali-ip>:8040`
2. Configurar clientes VPN (pestaña Escaneo)
3. Seleccionar perfil de escaneo y objetivo
4. Ver resultados en tiempo real vía SSE
5. Descargar reportes PDF desde Historial
6. Monitorear tráfico en Captura de Tráfico
7. Activar detección de intrusos en IDS Suricata

## Licencia

Uso interno — Herramienta de auditoría de seguridad.
