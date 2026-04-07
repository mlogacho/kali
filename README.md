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
| Despliegue | systemd (`vuln-scanner.service`) en AWS EC2 |

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
