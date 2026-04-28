# Kali VPN Vulnerability Scanner

Consola web de seguridad ofensiva construida sobre **Kali / Debian Linux**. Permite ejecutar escaneos de red, enumerar servicios, auditar credenciales, capturar tráfico en tiempo real y monitorear alertas IDS — todo desde una interfaz accesible por navegador, sin dependencias de CDN externas.

## Índice

1. [Arquitectura](#arquitectura)
2. [Acceso rápido](#acceso-rápido)
3. [Pestaña Escaneo](#1-pestaña-escaneo)
4. [Pestaña Historial](#2-pestaña-historial)
5. [Pestaña Mapa de Red](#3-pestaña-mapa-de-red)
6. [Pestaña Captura de Tráfico](#4-pestaña-captura-de-tráfico)
7. [Pestaña IDS Suricata](#5-pestaña-ids-suricata)
8. [Pestaña Nebula VPN](#6-pestaña-nebula-vpn)
9. [Pestaña Pentesting Externo](#7-pestaña-pentesting-externo-ffuf)
10. [Pestaña Túnel Chisel](#8-pestaña-túnel-chisel)
11. [Perfiles de Escaneo](#perfiles-de-escaneo)
12. [Reportes y Exportación](#reportes-y-exportación)
13. [Gestión de Clientes VPN](#gestión-de-clientes-vpn)
14. [Escaneo Distribuido con Sondas](#escaneo-distribuido-con-sondas)
15. [Instalación en Debian / Kali](#instalación-en-debian--kali)
16. [Despliegue Rápido desde Mac](#despliegue-rápido-desde-mac)
17. [Puertos y Firewall](#puertos-y-firewall)
18. [Estructura del Repositorio](#estructura-del-repositorio)
19. [Notas Técnicas](#notas-técnicas)

---

## Arquitectura

| Componente | Tecnología |
|---|---|
| Backend | Python 3 / Flask — archivo único `web_scanner.py` |
| Frontend | HTML/JS/CSS embebido en el propio `.py` |
| Gráficos | Chart.js 4.4 + D3.js v7 (servidos localmente en `/static/`) |
| Streaming | Server-Sent Events (SSE) — output en tiempo real sin WebSockets |
| Reportes PDF | `reportlab` — tema claro, firma del ingeniero, logo corporativo |
| Reportes HTML | Generador ejecutivo por perfil, sin dependencias externas |
| IDS | Suricata — alertas vía `fast.log` |
| Captura | tcpdump — pcap + estadísticas en ventana rolling de 5 min |
| VPN | OpenVPN · WireGuard · Nebula (lighthouse) · Tailscale (autodetección) |
| Túnel | Chisel (reverse SOCKS5) |
| Fuzzing | ffuf con auto-calibración anti-falsos positivos |
| Sondas | Agentes remotos vía Nebula/Tailscale para escaneo distribuido |
| Despliegue | systemd `vuln-scanner.service` |

---

## Acceso rápido

| Entorno | URL |
|---|---|
| Servidor Datacom (VM local) | http://10.11.121.101:8040 |
| Servidor AWS EC2 | http://`<IP-AWS>`:8040 |

---

## 1. Pestaña Escaneo

Panel principal de operaciones. Agrupa todos los controles de un escaneo en una sola pantalla.

### Barra de ingeniero
Campo persistente (localStorage) con el nombre del operador. Se incluye automáticamente en todos los reportes PDF y HTML.

### Sidebar de clientes
- Lista de clientes configurados (nombre, red objetivo)
- Botón **+ Nuevo** para crear un cliente
- Click en un cliente → rellena automáticamente el formulario de escaneo con la red y VPN del cliente
- Botón de eliminar por cliente

### Formulario de configuración
| Campo | Descripción |
|---|---|
| Cliente | Selección del cliente activo (desplegable sincronizado con sidebar) |
| Objetivo | IP, CIDR o hostname destino del escaneo |
| Perfil de escaneo | 30 perfiles predefinidos en 4 fases (ver [Perfiles](#perfiles-de-escaneo)) |
| Comando personalizado | Editable manualmente — el perfil rellena el comando, el operador puede modificarlo |

### Barra de estadísticas en vivo
Durante un escaneo muestra en tiempo real:
- **Dispositivos** — contador de hosts descubiertos (chips con IP que aparecen al instante)
- **Duración** — cronómetro desde el inicio
- **ETA** — estimación de tiempo restante (extraída de las líneas `--stats-every` de nmap)
- **Progreso** — barra de avance porcentual (extraído del output de nmap)

### Ping integrado
- Campo IP/hostname + contador de paquetes
- Resultado en tiempo real vía SSE (líneas coloreadas: verde OK, rojo fallo)
- No interrumpe ni bloquea el escaneo activo

### Terminal de output
- Output en tiempo real con coloración por severidad:
  - 🔴 **CRITICAL** — exploits confirmados, RCE, EternalBlue
  - 🟠 **HIGH** — CVEs conocidos, inyección
  - 🟡 **MEDIUM** — configuraciones débiles, SSL
  - 🔵 **LOW** — info leak, disclosure
  - ⬜ **INFO** — output normal
- Auto-scroll al fondo (desactivable)
- Barra de progreso animada durante el escaneo

### Panel de hallazgos
Panel lateral derecho que muestra únicamente las líneas de severidad HIGH/CRITICAL/MEDIUM — filtrado en vivo del output completo.

### Botones de exportación
Aparecen al terminar el escaneo:
| Botón | Formato |
|---|---|
| Descargar PDF | Informe técnico completo (reportlab) |
| Informe Ejecutivo | HTML para Gerencia (sin output crudo, adaptado al perfil) |
| TXT | Output plano |
| JSON | Metadatos + líneas en JSON |
| HTML | Tabla coloreada por severidad (oscuro) |

---

## 2. Pestaña Historial

Lista de todos los escaneos ejecutados en la sesión actual.

| Columna | Descripción |
|---|---|
| ID | Identificador único de 8 caracteres |
| Ingeniero | Nombre del operador |
| Cliente | Nombre del cliente |
| Objetivo | IP/CIDR escaneado |
| Perfil | Nombre del perfil usado |
| Inicio | Fecha y hora de inicio |
| Estado | `Completado` (verde) / `En curso` (azul) |
| Acciones | PDF · Informe Ejecutivo · TXT · Ver |

- **Ver** — reproduce el output del escaneo en el terminal de la pestaña Escaneo, restaurando también los botones de exportación
- Los escaneos persisten mientras el servidor Flask esté activo (en memoria)

---

## 3. Pestaña Mapa de Red

Visualización gráfica interactiva de la topología de red descubierta.

### Escaneo de red
1. Introducir CIDR objetivo
2. El servidor ejecuta dos nmap internamente:
   - `nmap -sn` → descubrimiento de hosts vivos (sin `-Pn`)
   - `nmap -sT -Pn --open -p <puertos clave>` → detección de servicios por host
3. Los resultados aparecen como un grafo D3.js con física de partículas

### Tipos de nodo (iconos y colores)
| Tipo | Detección |
|---|---|
| 🔵 Gateway | Último octeto .1/.254, hostname con "router/fw/gateway", vendor Cisco/Fortinet/Mikrotik |
| 🪟 Windows | Puerto 3389 abierto, o 445 sin HTTP |
| 🌐 Web | Puertos 80/443/8080/8443 |
| 🐧 Linux | Puerto 22 sin los anteriores |
| 🗄️ Base de datos | Puertos 3306/5432/1521/27017 |
| ⚫ Desconocido | Sin clasificación definitiva |

### Interacción
- Arrastrar nodos para reorganizar el grafo
- Hover → tooltip con IP, hostname, MAC, vendor y lista de puertos abiertos
- Zoom con scroll
- Reset de vista

### Tabla de inventario
Debajo del grafo: tabla ordenable (click en cabecera) con columnas Hostname, IP, Fabricante, Tipo, Puertos abiertos.

### Escaneo con sonda local
Botón **Sonda Local** — lanza el escaneo desde un agente remoto registrado en lugar del servidor central (ver [Sondas](#escaneo-distribuido-con-sondas)).

---

## 4. Pestaña Captura de Tráfico

Captura de paquetes en vivo directamente desde el servidor Kali.

### Controles
| Control | Descripción |
|---|---|
| Interfaz | Desplegable con todas las interfaces del sistema (`eth0`, `any`, `tailscale0`, `nebula0`, etc.) |
| Filtro BPF | Expresión Berkeley Packet Filter (`tcp port 80`, `host 192.168.1.1`, etc.) |
| Iniciar / Detener | Inicia o para tcpdump |
| Limpiar | Borra el output de pantalla |

### Terminal de captura
Output en tiempo real de tcpdump (SSE), con todas las líneas de paquetes.

### Descarga PCAP
El archivo `.pcap` se guarda en `/opt/scanner/scans/capture_<id>.pcap`. Desde la UI se puede leer y filtrar un pcap existente indicando su ruta.

### Estadísticas en tiempo real (ventana rolling 5 min)
Cuatro gráficos Chart.js que se actualizan cada 2 segundos:

| Gráfico | Métrica |
|---|---|
| Línea temporal | Paquetes por segundo — entrada (verde) vs salida (azul) |
| Barras horizontales | Top 5 IPs origen por volumen |
| Barras horizontales | Top 5 puertos destino |
| Doughnut | Distribución de flags TCP (SYN, ACK, FIN, RST, PSH) + UDP |

- Soporta paquetes TCP y UDP
- Las estadísticas usan buckets de 1 segundo con poda automática de los más viejos

---

## 5. Pestaña IDS Suricata

Monitor de detección de intrusos integrado con Suricata.

### Controles
| Control | Descripción |
|---|---|
| Interfaz | Selección de interfaz de monitoreo |
| Iniciar Suricata | Arranca `suricata -i <iface>` como subproceso |
| Detener | Para el proceso y registra el evento |

### Alertas en vivo
Tabla con las últimas alertas parseadas de `/var/log/suricata/fast.log`:
| Columna | Descripción |
|---|---|
| Hora | Timestamp de la alerta |
| Severidad | Prioridad numérica de Suricata |
| Origen | IP:puerto origen |
| Destino | IP:puerto destino |
| Protocolo | TCP/UDP/ICMP |
| Firma | Nombre de la regla activada |

- Polling cada 1.5 segundos
- Solo se leen las líneas nuevas (offset incremental)

### Estadísticas (ventana rolling 5 min)
Cuatro gráficos actualizados cada 2.5 segundos:

| Gráfico | Métrica |
|---|---|
| Línea temporal | Alertas por segundo |
| Barras | Top firmas (signatures) más activas |
| Doughnut | Distribución de severidad 1/2/3 |
| Barras | Top IPs origen atacantes |

---

## 6. Pestaña Nebula VPN

Gestión completa de la PKI Nebula desde el navegador. El servidor actúa como **lighthouse** de la red superpuesta.

### Topología

```
                     ┌──────────────────────────────┐
                     │  Servidor Kali / Datacom      │
                     │  nebula0 → 10.255.255.101/24  │
                     │  Puerto UDP: 4242             │
                     │  Rol: Lighthouse              │
                     └──────────────┬───────────────┘
                                    │ UDP hole-punching
           ┌────────────────────────┼────────────────────────┐
           │                        │                        │
  ┌────────▼───────┐    ┌───────────▼──────┐    ┌──────────▼──────┐
  │  Cliente A     │    │  Cliente B       │    │  Cliente C      │
  │  10.255.255.10 │    │  10.255.255.20   │    │  10.255.255.30  │
  │  grupo: clients│    │  grupo: clients  │    │  grupo: servers │
  └────────────────┘    └──────────────────┘    └─────────────────┘
```

### Panel de estado
- Estado del proceso nebula (activo/inactivo)
- IP de la interfaz `nebula0`
- Nombre y expiración de la CA activa
- Botón **Inicializar CA** — descarga Nebula v1.9.5 (si no está), crea la CA y genera el certificado del lighthouse

### Emisión de certificados
| Campo | Descripción |
|---|---|
| Nombre | Identificador del nodo cliente |
| IP Nebula | Dirección en la red superpuesta (ej. `10.255.255.10/24`) |
| Grupos | Grupos de firewall Nebula (ej. `clients`, `servers`) |
| Duración | Validez del certificado (ej. `8760h` = 1 año) |

El backend firma automáticamente con la CA y sirve el resultado.

### Tabla de certificados
Lista de todos los certs emitidos con columnas: Nombre, IP overlay, Grupos, Expiración y acciones:
- **ZIP** — descarga bundle listo para usar (`<nombre>.crt`, `<nombre>.key`, `ca.crt`, `<nombre>_config.yaml`)
- **YAML** — muestra el config Nebula generado para ese nodo
- **Revocar** — elimina el par de archivos del servidor

### Configuración automática generada
El YAML descargado incluye:
- Dirección IP overlay del nodo
- Referencia a `ca.crt`, `<nombre>.crt`, `<nombre>.key`
- Lighthouse configurado con la IP pública del servidor
- Reglas de firewall (inbound/outbound por grupo)
- `tun.dev: utun` para macOS / `dev: nebula0` para Linux

### Instalación en nodo cliente
```bash
# 1. Descargar el ZIP desde la Web UI y extraerlo
# 2. Copiar archivos
sudo mkdir -p /etc/nebula
sudo cp *.crt *.key ca.crt /etc/nebula/

# macOS — limpiar sesiones previas
sudo pkill -f nebula 2>/dev/null; true
sudo route delete -net 10.255.255.0/24 2>/dev/null; true

# Iniciar
sudo nebula -config /etc/nebula/<nombre>_config.yaml

# Verificar conectividad
ping 10.255.255.101
```

### Gestión CLI (alternativa a la Web UI)
```bash
sudo ./nebula-cert-manager.sh issue  <nombre> <ip>/24 <grupo> <duración>
sudo ./nebula-cert-manager.sh list
sudo ./nebula-cert-manager.sh info   <nombre>
sudo ./nebula-cert-manager.sh bundle <nombre> /tmp/bundle
sudo ./nebula-cert-manager.sh config <nombre>
sudo ./nebula-cert-manager.sh revoke <nombre>
```

### Troubleshooting Nebula

| Síntoma | Solución |
|---|---|
| `interface name must be utun[0-9]+` (macOS) | El YAML descargado ya usa `tun.dev: utun` — correcto |
| `failed to write route: file exists` | `sudo route delete -net 10.255.255.0/24` antes de arrancar |
| Ping timeout cliente → servidor | Instalar `nebula-routing.service` (conflicto con Tailscale tabla 52) |
| `CA no encontrada` en Web UI | Usar botón **Inicializar CA** |
| `certificate expires after signing certificate` | El backend recorta automáticamente la duración (-720h) |
| `sudo: a terminal is required` | Verificar `/etc/sudoers.d/scanner` con reglas NOPASSWD |

---

## 7. Pestaña Pentesting Externo (ffuf)

Fuzzing web avanzado con ffuf, con auto-calibración para eliminar falsos positivos.

### Parámetros
| Parámetro | Descripción |
|---|---|
| URL con `FUZZ` | URL objetivo — el marcador `FUZZ` indica el punto de inyección |
| Wordlist | Ruta al diccionario en el servidor (por defecto `dirb/common.txt`) |
| Método HTTP | GET, POST, PUT, PATCH, DELETE, HEAD |
| Extensiones | Sufijos a añadir a cada palabra (ej. `php,html,txt`) |
| Headers | Cabeceras HTTP personalizadas separadas por `;` |
| Cookies | Cookie de sesión para endpoints autenticados |
| Threads | Número de hilos concurrentes |
| Timeout | Tiempo límite por petición (segundos) |
| Auto-calibración | Detecta y filtra respuestas baseline para eliminar falsos positivos (`-ac`) |

### Ejemplos de URL con FUZZ
```
http://10.11.121.50/FUZZ                     # directorios
http://10.11.121.50/api/v1/FUZZ              # endpoints API
http://10.11.121.50/FUZZ.php                 # archivos PHP
http://10.11.121.50/admin/FUZZ               # subruta específica
```

### Resultados
Tabla con columnas: URL encontrada, Código HTTP, Tamaño de respuesta, Palabras, Líneas. Los resultados se parsean del output JSON de ffuf y se actualizan durante la ejecución.

### Instalación de ffuf (si no está disponible)
```bash
sudo apt install ffuf
# o
go install github.com/ffuf/ffuf/v2@latest
```

---

## 8. Pestaña Túnel Chisel

Crea un túnel TCP reverso con SOCKS5 para alcanzar redes internas desde el servidor Kali.

### Arquitectura
```
[Servidor Kali]                      [Cliente en red interna]
chisel server --reverse              chisel client <kali-ip>:8080 R:socks
  escucha en :8080                     abre túnel SOCKS5 en :1080 del server
        ↑                                        ↑
        └────────────── TCP/HTTP ────────────────┘
```

### Controles
| Botón | Acción |
|---|---|
| Iniciar Servidor | Arranca `chisel server --port 8080 --reverse --socks5` |
| Detener | Para el servidor y todos los túneles activos |
| Ver log | Muestra las últimas líneas del log de chisel |

### Estado
- Indicador de proceso activo/inactivo
- Puerto SOCKS5 local: `1080`
- Lista de clientes conectados (actualización automática)

### Escaneo a través del túnel
Una vez activo el túnel, la UI permite lanzar nmap a través de proxychains por el SOCKS5:
- Ingresar objetivo y perfiles
- El scan viaja por el túnel → llega a la red interna del cliente
- Output en tiempo real via SSE

### Instalación de Chisel
```bash
# En el servidor Kali
sudo apt install chisel
# o descargar binario desde GitHub releases
sudo curl -L https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz \
  | gunzip > /usr/local/bin/chisel && sudo chmod +x /usr/local/bin/chisel

# En el cliente (red interna del cliente)
chisel client <kali-ip>:8080 R:socks
```

---

## Perfiles de Escaneo

30 perfiles organizados en 4 fases metodológicas.

### Fase 1 — Descubrimiento y Escaneo

| Perfil | Herramienta | Descripción |
|---|---|---|
| Descubrimiento (hosts vivos) | nmap -sn | Ping sweep con host discovery real (sin -Pn) |
| Escaneo rápido (puertos comunes) | nmap -sT | 15 puertos de alto impacto |
| Puertos top-1000 | nmap -sT | Los 1000 puertos más comunes |
| Puertos completos (1-65535) | nmap -sT -p- | Escaneo exhaustivo — tarda varios minutos |
| Info HTTP/SSH/FTP | nmap NSE | Scripts: http-title, http-headers, ssh-hostkey, ftp-anon |
| Vulnerabilidades NSE | nmap NSE | Categoría `vuln` completa (sin scripts SSL que cuelgan sobre VPN) |
| Vuln + Info HTTP/SSH (completo) | nmap NSE | Combinación de vuln + info web/SSH |
| CVEs con CVSS (vulners) | nmap + vulners | CVEs con puntuación CVSS ≥ 5.0 |
| Web / HTTP (nikto) | nikto | Análisis de seguridad del servidor web |
| SMB vulnerabilidades | nmap NSE | Scripts `smb-vuln*` (MS17-010, MS08-067, etc.) |
| SSL/TLS — red/subred | nmap NSE | Ciphers, certificados, parámetros DH |
| SSL/TLS — host único | sslscan | Análisis detallado de configuración TLS |

### Fase 2 — Enumeración de Servicios

| Perfil | Herramienta | Descripción |
|---|---|---|
| Enum SMB completo | enum4linux | Usuarios, shares, políticas, grupos, RID cycling |
| SMB shares anónimo | smbclient | Lista de recursos compartidos sin autenticación |
| Banner grabbing (puertos clave) | nmap NSE banner | Versiones de servicio en 21,22,23,25,80,110,143,443,3389,8080 |
| SNMP walk — community public | snmpwalk | OIDs con community `public` |
| SNMP walk — community private | snmpwalk | OIDs con community `private` |

### Fase 3 — Análisis de Aplicaciones Web

| Perfil | Herramienta | Descripción |
|---|---|---|
| Web — Gobuster dirs (HTTP) | gobuster | Directorios con `common.txt` (~4.600 palabras) |
| Web — Gobuster dirs (HTTPS) | gobuster | Directorios HTTPS con `common.txt` |
| Web — Gobuster dirs (big.txt HTTP) | gobuster | Directorios con `big.txt` (~20.000 palabras) |
| Web — SQLMap GET básico | sqlmap | SQLi en parámetros GET — level 3, risk 2 |
| Web — SQLMap POST login | sqlmap | SQLi en formulario de login POST |

### Fase 4 — Auditoría de Credenciales

| Perfil | Herramienta | Descripción |
|---|---|---|
| Creds — Hydra SSH (admin) | hydra | Fuerza bruta SSH con usuario `admin` y rockyou.txt |
| Creds — Hydra SSH (root) | hydra | Fuerza bruta SSH con usuario `root` |
| Creds — Hydra RDP (administrator) | hydra | Fuerza bruta RDP |
| Creds — Hydra HTTP-form POST | hydra | Fuerza bruta en formulario web |
| Creds — Hydra FTP (admin) | hydra | Fuerza bruta FTP |
| Creds — John (objetivo=ruta/hashes) | john | Cracking con wordlist rockyou.txt |
| Creds — John NTLM (objetivo=ruta/hashes) | john | Cracking de hashes NTLM |
| Creds — Hashcat NTLM (objetivo=ruta/hashes) | hashcat | Modo 1000 — hashes NTLM/NTHash |
| Creds — Hashcat MD5 (objetivo=ruta/hashes) | hashcat | Modo 0 — hashes MD5 |

> **Nota técnica:** No se usa `-sV` en perfiles nmap — causa timeouts sobre VPN. Los scripts SSL de la categoría `vuln` están excluidos por la misma razón (`ssl-heartbleed`, `ssl-poodle`, `sslv2-drown`, etc.).

---

## Reportes y Exportación

Disponibles al finalizar cada escaneo (toolbar) y desde la tabla de Historial.

### Formatos disponibles

| Formato | Botón | Descripción |
|---|---|---|
| **PDF técnico** | 📄 Descargar PDF | Informe completo con portada, tabla de hosts, hallazgos por severidad, output completo, firma del ingeniero. Generado con `reportlab`. |
| **Informe Ejecutivo** | 📊 Informe Ejecutivo | HTML autocontenido para Gerencia — sin output crudo, adaptado al perfil de escaneo |
| **TXT** | ⬇ TXT | Output plano del terminal |
| **JSON** | ⬇ JSON | Metadatos del scan + líneas de output |
| **HTML técnico** | ⬇ HTML | Tabla coloreada por severidad (tema oscuro) |

### Informe Ejecutivo — 11 variantes por perfil

El informe HTML ejecutivo adapta sus secciones, métricas y acciones recomendadas según el perfil ejecutado:

| Perfil | Métricas clave | Panel central |
|---|---|---|
| CVEs con CVSS | CVEs por severidad CVSS | Tarjetas CVE-XXXX con puntuación |
| Banner grabbing | Servicios, sin cifrado, desactualizados | Inventario de servicios por host |
| Hashcat / John | Hashes procesados, descifrados, tasa % | Contraseñas descifradas con análisis de debilidad |
| Hydra | Hosts atacados, credenciales válidas | Credenciales comprometidas (usuario:contraseña) |
| Nikto | Hallazgos OSVDB/CVE, rutas | Lista de findings web categorizados |
| Gobuster | Rutas sensibles, acceso 200 | Paths `.git`/`.env`/`admin` marcados en rojo |
| SQLMap | Parámetros vulnerables, bases expuestas | Puntos de inyección + bases de datos |
| SMB | Vulns SMB, EternalBlue, shares | Tarjetas MS17-010/MS08-067 destacadas |
| SSL/TLS | Cifrados débiles, certs vencidos | Ciphers y protocolos inseguros |
| SNMP | OIDs expuestos, community string | Información del sistema expuesta |
| Descubrimiento / Puertos / NSE | Hosts activos, scoring por puerto | Top-6 hosts por puntuación de riesgo |

Todos los informes incluyen: badge de riesgo global (CRÍTICO/ALTO/MODERADO/BAJO), resumen de 4 métricas, gráfico de barras de distribución, panel central de hallazgos y acciones ejecutivas con etiquetas URGENTE / 2 SEMANAS / 30 DÍAS.

---

## Gestión de Clientes VPN

El sidebar izquierdo gestiona los clientes de auditoría. Cada cliente almacena:

| Campo | Descripción |
|---|---|
| Nombre | Identificador del cliente |
| Red objetivo | CIDR por defecto del escaneo |
| Descripción | Notas internas |
| Tipo VPN | OpenVPN / WireGuard / Nebula / Tailscale |
| Archivo de configuración VPN | `.ovpn`, `.conf`, o ruta de perfil WireGuard |
| Usuario / Contraseña VPN | Para OpenVPN con autenticación |
| IP Nebula | IP del nodo en la red superpuesta |
| Grupos Nebula | Grupos de firewall del cliente |
| Hostname Tailscale | Para clientes Tailscale |

### Conexión VPN
El badge **VPN** en el encabezado permite:
- **Autodetectar** VPNs activas (Tailscale, tun0, wg0, nebula0) — se detecta y muestra automáticamente al cargar la página
- **Conectar** manualmente un cliente configurado (OpenVPN o WireGuard)
- **Desconectar** la VPN activa

### Rutas de red automáticas
Al conectar un cliente, el backend intenta añadir automáticamente la ruta de red del cliente hacia la interfaz VPN activa (`ip route replace`).

---

## Escaneo Distribuido con Sondas

Permite que agentes remotos (sondas) instalados en la red del cliente ejecuten escaneos de forma local y reporten los resultados al servidor central.

### Arquitectura

```
[Servidor Kali — Hub central]
  ↑ recibe resultados via API
  ↑ registra sondas
  |
  |  (Nebula VPN o Tailscale)
  |
[Sonda A — red cliente 192.168.1.0/24]   [Sonda B — red cliente 10.0.0.0/8]
  ejecuta nmap localmente                   ejecuta nmap localmente
  publica resultados al hub                 publica resultados al hub
```

### Instalación de sonda (Linux)
```bash
# Descargar e instalar desde el servidor Kali
curl http://<kali-ip>:8040/api/probe/install | sudo bash

# O manualmente
bash probe-gateway.sh <kali-nebula-ip>
```

### Instalación de sonda (Windows — PowerShell)
```powershell
# Descarga automática desde la Web UI
Invoke-WebRequest http://<kali-ip>:8040/api/probe/install.ps1 | iex
```

### Operación desde Mapa de Red
- Botón **Sonda Local** → seleccionar sonda registrada → lanzar escaneo
- Los resultados del agente aparecen en el mapa como nodos regulares
- Tabla de inventario se actualiza con los hosts de cada sonda

---

## Instalación en Debian / Kali

### Prerrequisitos del sistema
```bash
sudo apt update
sudo apt install -y \
  nmap nikto gobuster hydra sqlmap sslscan \
  smbclient snmp snmp-mibs-downloader \
  tcpdump john john-data hashcat hashcat-data \
  suricata ffuf chisel \
  python3-flask python3-reportlab \
  net-tools curl wget git

# enum4linux-ng (no en repos Debian estándar)
sudo git clone https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng
sudo pip3 install -r /opt/enum4linux-ng/requirements.txt --break-system-packages
sudo ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng
```

### Crear estructura de directorios
```bash
sudo mkdir -p /opt/scanner/scans /opt/scanner/vpn_configs /opt/scanner/static
sudo chown -R $USER:$USER /opt/scanner
```

### Descargar librerías JS (sin dependencia de CDN)
```bash
curl -L https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js \
     -o /opt/scanner/static/d3.min.js
curl -L https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js \
     -o /opt/scanner/static/chart.umd.min.js
```

### Copiar archivos del scanner
```bash
cp web_scanner.py /opt/scanner/web_scanner.py
cp logo_datacom.png /opt/scanner/logo_datacom.png
```

### Configurar servicio systemd
```bash
sudo tee /etc/systemd/system/vuln-scanner.service > /dev/null <<EOF
[Unit]
Description=Kali VPN Vulnerability Scanner — Datacom Security
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=/opt/scanner
ExecStart=/usr/bin/python3 /opt/scanner/web_scanner.py
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vuln-scanner
```

### Configurar sudo sin contraseña (requerido para operaciones de red)
```bash
sudo tee /etc/sudoers.d/scanner > /dev/null <<EOF
Defaults:$USER !requiretty
$USER ALL=(ALL) NOPASSWD: /usr/bin/bash
$USER ALL=(ALL) NOPASSWD: /usr/bin/chmod
$USER ALL=(ALL) NOPASSWD: /usr/bin/chown
$USER ALL=(ALL) NOPASSWD: /usr/bin/ip
$USER ALL=(ALL) NOPASSWD: /usr/bin/pkill
$USER ALL=(ALL) NOPASSWD: /usr/bin/tcpdump
$USER ALL=(ALL) NOPASSWD: /usr/sbin/suricata
$USER ALL=(ALL) NOPASSWD: /usr/bin/tailscale
$USER ALL=(ALL) NOPASSWD: /opt/nebula/nebula
$USER ALL=(ALL) NOPASSWD: /opt/nebula/nebula-cert
EOF
sudo chmod 440 /etc/sudoers.d/scanner
```

### Abrir puerto en firewall
```bash
sudo ufw allow 8040/tcp comment 'Kali Scanner UI'
```

### Instalar Nebula (opcional)
```bash
sudo ./nebula-setup.sh
# O desde la Web UI: pestaña Nebula VPN → Inicializar CA
```

---

## Despliegue Rápido desde Mac

### Hacia servidor Datacom (contraseña SSH)
```bash
# Subir y reiniciar
sshpass -p 'DATAcom4dm1n' scp web_scanner.py datacomerp@10.11.121.101:/opt/scanner/
sshpass -p 'DATAcom4dm1n' ssh datacomerp@10.11.121.101 \
  "sudo systemctl restart vuln-scanner && systemctl is-active vuln-scanner"
```

### Hacia servidor AWS EC2 (clave PEM)
```bash
# Desde el directorio del repo
bash deploy.sh
# O con IP personalizada
KALI_HOST=<nueva-ip-aws> bash deploy.sh
```

---

## Puertos y Firewall

| Puerto | Protocolo | Servicio | Notas |
|---|---|---|---|
| 8040 | TCP | Scanner Web UI (Flask) | Abrir en UFW: `ufw allow 8040/tcp` |
| 4242 | UDP | Nebula VPN lighthouse | Para clientes Nebula |
| 8080 | TCP | Chisel reverse tunnel server | Solo cuando el túnel esté activo |
| 1080 | TCP | SOCKS5 local (Chisel) | Solo localhost |
| 3000 | TCP | ntopng (Docker, opcional) | `ufw allow 3000/tcp` |

---

## Estructura del Repositorio

```
kali/
├── web_scanner.py               # Aplicación principal — Flask + HTML/JS/CSS embebido
├── vuln_scanner.py              # Scanner desktop legacy (GUI Tkinter + paramiko)
├── deploy.sh                    # Script de despliegue automatizado a AWS
├── nebula-setup.sh              # Instalación del lighthouse Nebula en el servidor
├── nebula-cert-manager.sh       # Gestión de certificados Nebula (CLI completa)
├── nebula-routing.service       # Systemd: resuelve conflictos de routing Nebula vs Tailscale
├── probe-agent.sh               # Agente de sonda para escaneo distribuido (Linux)
├── probe-gateway.sh             # Gateway de sonda — comunica resultados al hub
├── generar_manual.py            # Generador del Manual PDF (reportlab)
├── logo_datacom.png             # Logo corporativo usado en reportes PDF
├── reporte_vulnerabilidades.html # Plantilla HTML de reporte ejecutivo (referencia)
├── Informe_Ejecutivo_Seguridad.pdf
├── Manual_Kali_VPN_Scanner.pdf
├── .gitignore
└── README.md
```

---

## Notas Técnicas

| Aspecto | Detalle |
|---|---|
| **Sin `-sV` en nmap sobre VPN** | La detección de versiones cuelga indefinidamente sobre Tailscale/Nebula — todos los perfiles usan `-sT` con scripts NSE en su lugar |
| **Scripts SSL excluidos** | `ssl-heartbleed`, `ssl-poodle`, `sslv2-drown`, `ssl-ccs-injection` causan timeouts sobre VPN |
| **Discovery sin `-Pn`** | El perfil de descubrimiento usa `-sn -PS<puertos>` para host discovery real |
| **CDN → local** | D3.js y Chart.js se sirven desde `/opt/scanner/static/` — no se requiere internet en el cliente |
| **SSE en lugar de WebSockets** | Los scans, capturas e IDS usan Server-Sent Events unidireccionales — más simples y sin estado de conexión |
| **Duración Nebula certs** | El backend resta automáticamente 720h (30 días) a la duración del cert firmado para que siempre expire antes que la CA |
| **sudo sin terminal** | El servicio Flask corre sin TTY — `/etc/sudoers.d/scanner` con `NOPASSWD` + `!requiretty` es obligatorio |
| **Grupo dinámico en chown** | Los `chown` usan `os.environ.get("USER")` — no hay grupo `kali` hardcodeado, funciona en cualquier distro |
| **Historial en memoria** | Los escaneos persisten mientras corre el proceso Flask (no hay base de datos) |
| **Archivos pcap** | Se guardan en `/opt/scanner/scans/capture_<id>.pcap` — limpieza manual necesaria |
| **Firewall UFW** | Si UFW está activo, el puerto 8040 debe abrirse explícitamente: `sudo ufw allow 8040/tcp` |

---

## Licencia

Uso interno — Herramienta de auditoría de seguridad ofensiva. Datacom Security.
