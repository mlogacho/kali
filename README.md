# Kali VPN Vulnerability Scanner

Plataforma web de escaneo de vulnerabilidades desplegada sobre un servidor **Kali Linux en AWS (EC2)**. Permite gestionar clientes, conectarse a sus redes internas via VPN y ejecutar escaneos con **nmap**, **vulners** y **nikto** directamente desde el navegador.

---

## Arquitectura

```
Tu navegador → http://18.117.130.45:8040
                        ↓
              Flask App (Kali Linux AWS)
                        ↓
              VPN cliente (OpenVPN / WireGuard)
                        ↓
              Red interna del cliente
                        ↓
              nmap · vulners · nikto
```

---

## Infraestructura AWS

| Parámetro | Valor |
|---|---|
| Instancia | `i-0149996bf2a11dbdd` |
| Tipo | `t3.micro` |
| IP Pública | `18.117.130.45` |
| Región | `us-east-2` |
| SO | Kali Linux 2025.4 amd64 |
| Puerto app | `8040` |

---

## Archivos

| Archivo | Descripción |
|---|---|
| `web_scanner.py` | Aplicación Flask — backend + frontend (puerto 8040) |
| `deploy.sh` | Script de deploy automático via SSH/SCP |

---

## Deploy

### Requisitos locales
- Python 3.x
- `paramiko` (`pip3 install paramiko`)
- Clave SSH `kali-aws.pem`

### Desplegar en el servidor

```bash
chmod 600 kali-aws.pem
./deploy.sh
```

El script realiza automáticamente:
1. Crea `/opt/scanner/` en el servidor Kali
2. Sube `web_scanner.py`
3. Instala Flask en el servidor
4. Configura y activa el servicio **systemd** `vuln-scanner`

### Deploy manual (paso a paso)

```bash
# Subir archivo
scp -i kali-aws.pem web_scanner.py kali@18.117.130.45:/opt/scanner/

# Instalar dependencia
ssh -i kali-aws.pem kali@18.117.130.45 "pip3 install flask --break-system-packages"

# Reiniciar servicio
ssh -i kali-aws.pem kali@18.117.130.45 "sudo systemctl restart vuln-scanner"
```

---

## Uso

Abre en el navegador:

```
http://18.117.130.45:8040
```

### Flujo de trabajo

1. **Clientes** — Registra el cliente con nombre, red interna (CIDR) y config VPN (`.ovpn` o WireGuard `.conf`)
2. **VPN** — Conecta el servidor Kali a la red interna del cliente desde el badge superior
3. **Escaneo** — Selecciona cliente, objetivo y perfil → Iniciar Escaneo
4. **Resultados** — Visualiza en tiempo real, exporta en TXT / JSON / HTML

---

## Perfiles de escaneo

| Perfil | Comando |
|---|---|
| Descubrimiento (hosts vivos) | `nmap -sn` |
| Puertos top-1000 | `nmap -sS -T4 --open` |
| Puertos completos (1-65535) | `nmap -sS -T4 -p-` |
| Versiones + Sistema Operativo | `nmap -sS -sV -O -T4` |
| Vulnerabilidades NSE | `nmap -sV --script vuln` |
| Vuln + SO + Versiones *(completo)* | `nmap -sS -sV -O --script vuln` |
| CVEs con CVSS (vulners) | `nmap -sV --script vulners --script-args mincvss=5.0` |
| Web / HTTP | `nikto -h` |
| SMB vulnerabilidades | `nmap -p445 --script smb-vuln*` |
| SSL/TLS | `sslscan` |

---

## Gestión del servicio

```bash
# Ver logs en tiempo real
ssh -i kali-aws.pem kali@18.117.130.45 'sudo journalctl -u vuln-scanner -f'

# Estado del servicio
ssh -i kali-aws.pem kali@18.117.130.45 'sudo systemctl status vuln-scanner'

# Reiniciar
ssh -i kali-aws.pem kali@18.117.130.45 'sudo systemctl restart vuln-scanner'

# Detener
ssh -i kali-aws.pem kali@18.117.130.45 'sudo systemctl stop vuln-scanner'
```

---

## Seguridad

- El servidor Kali actúa como **jump host** — los escaneos se originan desde la red del cliente via VPN
- Acceso SSH con clave `.pem` (sin contraseña)
- Se recomienda restringir el puerto 8040 en el Security Group de AWS a IPs autorizadas
- Los archivos de config VPN se almacenan en `/opt/scanner/vpn_configs/`
- Los reportes se guardan en `/opt/scanner/scans/`

---

## Autor

**Datacom Security** — Marco Logacho
`mlogacho@gmail.com`
