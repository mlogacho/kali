#!/usr/bin/env python3
"""
Kali VPN Vulnerability Scanner — Web UI
Corre en el servidor Kali en el puerto 8040.
Acceder desde: http://<kali-ip>:8040
"""

import os, json, re, datetime, subprocess, threading, time, uuid, io, ipaddress
from flask import Flask, render_template_string, request, jsonify, Response, stream_with_context, send_file

app = Flask(__name__)
app.secret_key = os.urandom(32)

CLIENTS_FILE     = "/opt/scanner/clients.json"
UPLOAD_DIR       = "/opt/scanner/vpn_configs"
SCANS_DIR        = "/opt/scanner/scans"
NEBULA_BIN       = "/opt/nebula/nebula"
NEBULA_CERT_BIN  = "/opt/nebula/nebula-cert"
NEBULA_CERTS_DIR = "/etc/nebula/certs"  # CA y certs generados por nebula-setup.sh
NEBULA_CONFIG_DIR= "/etc/nebula"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SCANS_DIR,  exist_ok=True)
# /etc/nebula lo crea nebula-setup.sh (requiere root); aquí sólo intentamos sin fallar
try:
    os.makedirs(NEBULA_CERTS_DIR, exist_ok=True)
except PermissionError:
    pass
if not os.path.exists(CLIENTS_FILE):
    with open(CLIENTS_FILE, "w") as f:
        json.dump({}, f)

# ── State ──────────────────────────────────────────────────────────────────────
active_scans: dict[str, dict] = {}
network_maps: dict[str, dict] = {}
vpn_state = {"active": False, "client": "", "iface": ""}
# Probe (sonda) state — registered probes and their scan results
registered_probes: dict[str, dict] = {}   # nebula_ip → {name, subnets, last_seen, ...}
probe_scan_results: dict[str, dict] = {}  # probe_ip → {hosts: [...], timestamp, status}

SCAN_PROFILES = {
    "Descubrimiento (hosts vivos)":      "nmap -sn -PS21,22,23,53,80,110,135,139,443,445,3306,3389,8080 -T4 {target}",
    "Escaneo rápido (puertos comunes)":   "nmap -sT -PS21,22,23,53,80,110,135,139,443,445,3306,3389,8080 -T4 -p 22,80,443,445,3306,3389,8080,8443,21,25,110,8000 {target}",
    "Puertos top-1000":                   "nmap -sT -PS21,22,23,53,80,110,135,139,443,445,3306,3389,8080 -T4 {target}",
    "Puertos completos (1-65535)":        "nmap -sT -PS21,22,23,53,80,110,135,139,443,445,3306,3389,8080 -T4 -p- {target}",
    "Info HTTP/SSH/FTP":                  "nmap -sT -PS21,22,23,53,80,110,135,139,443,445,3306,3389,8080 -T4 --script http-title,http-headers,ssh-hostkey,ftp-anon {target}",
    "Vulnerabilidades NSE":               "nmap -sT -PS21,22,23,53,80,110,135,139,443,445,3306,3389,8080 -T4 --script 'vuln and not ssl-heartbleed and not ssl-poodle and not sslv2-drown and not ssl-ccs-injection and not ssl-cert-intaddr and not ssl-known-key and not tls-ticketbleed' {target}",
    "Vuln + Info HTTP/SSH (completo)":    "nmap -sT -PS21,22,23,53,80,110,135,139,443,445,3306,3389,8080 -T4 --script 'vuln and not ssl-heartbleed and not ssl-poodle and not sslv2-drown and not ssl-ccs-injection and not ssl-cert-intaddr and not ssl-known-key and not tls-ticketbleed',http-title,http-headers,ssh-hostkey {target}",
    "CVEs con CVSS (vulners)":            "nmap -sT -PS21,22,23,53,80,110,135,139,443,445,3306,3389,8080 -T4 --script vulners --script-args mincvss=5.0 {target}",
    "Web / HTTP (nikto)":                 "nikto -h {target}",
    "SMB vulnerabilidades":               "nmap -sT -PS21,22,23,53,80,110,135,139,443,445,3306,3389,8080 -p445 --script 'smb-vuln*' -T4 {target}",
    "SSL/TLS — red/subred (nmap)":        "nmap -sT -PS21,22,23,53,80,110,135,139,443,445,3306,3389,8080 --script ssl-enum-ciphers,ssl-cert,ssl-dh-params -p 443,8443,8080,8888,8000 -T4 {target}",
    "SSL/TLS — host único (sslscan)":     "sslscan --no-colour {target}",
    # ── Fase 2: Enumeración de servicios ──────────────────────────────────────
    "Enum SMB completo (enum4linux)":     "enum4linux -a {target}",
    "SMB shares anónimo (smbclient)":     "smbclient -L //{target} -N",
    "Banner grabbing (puertos clave)":    "nmap -sT -PS21,22,23,53,80,110,135,139,443,445,3306,3389,8080 -T4 --script=banner -p 21,22,23,25,80,110,143,443,3389,8080 {target}",
    "SNMP walk — community public":       "snmpwalk -v2c -c public -t 10 {target}",
    "SNMP walk — community private":      "snmpwalk -v2c -c private -t 10 {target}",
    # ── Fase 3: Análisis de aplicaciones web ──────────────────────────────────
    "Web — Gobuster dirs (HTTP)":         "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -q --no-progress",
    "Web — Gobuster dirs (HTTPS)":        "gobuster dir -u https://{target} -w /usr/share/wordlists/dirb/common.txt -q --no-progress",
    "Web — Gobuster dirs (big.txt HTTP)": "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/big.txt -q --no-progress",
    "Web — SQLMap GET básico":            "sqlmap -u \"http://{target}\" --level=3 --risk=2 --batch --timeout=10",
    "Web — SQLMap POST login":            "sqlmap -u \"http://{target}\" --data=\"user=admin&pass=test\" --level=3 --risk=2 --batch --timeout=10",
    # ── Fase 4: Auditoría de credenciales ─────────────────────────────────────
    "Creds — Hydra SSH (admin)":          "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://{target} -t 4 -V",
    "Creds — Hydra SSH (root)":           "hydra -l root  -P /usr/share/wordlists/rockyou.txt ssh://{target} -t 4 -V",
    "Creds — Hydra RDP (administrator)":  "hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://{target} -t 4 -V",
    "Creds — Hydra HTTP-form POST":       "hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-post-form \"/login:user=^USER^&pass=^PASS^:F=incorrect\" -t 4 -V",
    "Creds — Hydra FTP (admin)":          "hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{target} -t 4 -V",
    "Creds — John (objetivo=ruta/hashes)":        "john --wordlist=/usr/share/wordlists/rockyou.txt {target}",
    "Creds — John NTLM (objetivo=ruta/hashes)":   "john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT {target}",
    "Creds — Hashcat NTLM (objetivo=ruta/hashes)":"hashcat -m 1000 {target} /usr/share/wordlists/rockyou.txt --force --potfile-disable",
    "Creds — Hashcat MD5 (objetivo=ruta/hashes)": "hashcat -m 0    {target} /usr/share/wordlists/rockyou.txt --force --potfile-disable",
}

SEV_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#44aaff",
    "INFO":     "#c9d1d9",
}

# ── Helpers ────────────────────────────────────────────────────────────────────

def load_clients():
    with open(CLIENTS_FILE) as f:
        return json.load(f)

def save_clients(data):
    with open(CLIENTS_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def detect_severity(line):
    low = line.lower()
    if any(k in low for k in ["critical","rce","exploit","ms17-010","eternalblue","shellshock","ms08-067"]):
        return "CRITICAL"
    if any(k in low for k in ["high","vuln","cve-","sqli","rfi","lfi","backdoor","injection","command execution"]):
        return "HIGH"
    if any(k in low for k in ["medium","warning","deprecated","weak cipher","ssl error","tls"]):
        return "MEDIUM"
    if any(k in low for k in ["low","info leak","disclosure"]):
        return "LOW"
    return "INFO"

def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def now_display():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

# Elimina códigos de escape ANSI del output de los comandos
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mABCDEFGHJKLMSTfhin]|\x1b\(B|\x1b=|\x1b>')
def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub('', text)

# ── PDF: Host table parser ─────────────────────────────────────────────────────

def _parse_hosts_from_lines(lines: list) -> list:
    """
    Extract structured host data from nmap scan output lines.
    Returns list of dicts: {hostname, ip, mac, vendor, ports}.
    """
    hosts, cur = [], None
    for raw in lines:
        line = raw.strip() if isinstance(raw, str) else ""
        # New host block
        m = re.match(r'Nmap scan report for (.+)', line)
        if m:
            if cur:
                hosts.append(cur)
            s = m.group(1).strip()
            ip_m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', s)
            if ip_m:
                ip = ip_m.group(1)
                hn = s[:s.rfind('(')].strip()
            else:
                ip = s; hn = ""
            # Strip AWS reverse-DNS noise
            if "compute.internal" in hn or "ec2.internal" in hn:
                hn = ""
            cur = {"hostname": hn, "ip": ip, "mac": "—", "vendor": "—", "ports": []}
            continue
        if cur is None:
            continue
        # MAC address line
        mac_m = re.match(r'MAC Address: ([0-9A-Fa-f:]{17})\s*(?:\(([^)]*)\))?', line)
        if mac_m:
            cur["mac"]    = mac_m.group(1)
            cur["vendor"] = mac_m.group(2) or "—"
            continue
        # Open port line
        pm = re.match(r'(\d+)/tcp\s+open\s+(\S+)', line)
        if pm:
            cur["ports"].append(f"{pm.group(1)}/{pm.group(2)}")
    if cur:
        hosts.append(cur)
    # Return all discovered hosts, even if no ports are open
    return hosts


# ── PDF Generation ─────────────────────────────────────────────────────────────

def generate_pdf_report(scan: dict) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY, TA_RIGHT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether
    )

    W, H = A4

    # ── Light professional palette ──────────────────────────────────────────
    C_NAVY   = colors.HexColor("#1a2e4a")   # header/cover bg, section titles
    C_BLUE   = colors.HexColor("#1565c0")   # accent: links, port text
    C_GREEN  = colors.HexColor("#2e7d32")   # sub-headings
    C_BORDER = colors.HexColor("#c5cdd8")   # table grid lines
    C_HDR    = colors.HexColor("#2c3e50")   # table header bg
    C_LABEL  = colors.HexColor("#546e7a")   # label text (muted)
    C_BODY   = colors.HexColor("#212121")   # main body text
    C_ROW1   = colors.HexColor("#f0f4f8")   # alternating row (light blue-gray)
    C_ROW2   = colors.white                 # alternating row (white)
    C_CRIT   = colors.HexColor("#c62828")   # CRITICAL – dark red
    C_HIGH   = colors.HexColor("#e65100")   # HIGH – dark orange
    C_MED    = colors.HexColor("#f9a825")   # MEDIUM – amber
    C_LOW    = colors.HexColor("#1565c0")   # LOW – blue
    C_CODE   = colors.HexColor("#263238")   # code text
    C_CODEBG = colors.HexColor("#eceff1")   # code block bg
    WHITE    = colors.white

    engineer   = scan.get("engineer", "Sin especificar")
    client     = scan.get("client",   "N/A")
    target     = scan.get("target",   "N/A")
    profile    = scan.get("profile",  "N/A")
    command    = scan.get("command",  "N/A")
    start_time = scan.get("start",    now_str())
    end_time   = scan.get("end",      now_str())
    scan_id    = scan.get("id",       "N/A")
    lines      = scan.get("lines",    [])

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for line in lines:
        sev = detect_severity(line if isinstance(line, str) else "")
        counts[sev] += 1

    buf = io.BytesIO()

    def on_page(canvas, doc):
        canvas.saveState()
        # ── Header bar ──
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, H - 1.4*cm, W, 1.4*cm, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(WHITE)
        canvas.drawString(1.5*cm, H - 0.82*cm,
                          "INFORME DE ESCANEO DE VULNERABILIDADES — CONFIDENCIAL")
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#90caf9"))
        canvas.drawRightString(W - 1.5*cm, H - 0.82*cm, f"ID: {scan_id}")
        # Accent line below header
        canvas.setStrokeColor(C_BLUE)
        canvas.setLineWidth(2)
        canvas.line(0, H - 1.4*cm, W, H - 1.4*cm)
        # ── Footer ──
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(1.5*cm, 1.1*cm, W - 1.5*cm, 1.1*cm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_LABEL)
        canvas.drawString(1.5*cm, 0.55*cm,
                          f"Datacom Security  •  Generado: {now_display()}  •  Confidencial")
        canvas.drawRightString(W - 1.5*cm, 0.55*cm, f"Página {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm,
        topMargin=2.0*cm, bottomMargin=1.8*cm,
    )

    base = getSampleStyleSheet()
    def S(name, parent="Normal", **kw):
        return ParagraphStyle(name, parent=base[parent], **kw)

    st = {
        "title": S("t",  fontSize=22, leading=28, textColor=WHITE,
                   fontName="Helvetica-Bold", alignment=TA_CENTER),
        "sub":   S("s",  fontSize=10, leading=14, textColor=colors.HexColor("#90caf9"),
                   fontName="Helvetica-Bold", alignment=TA_CENTER),
        "h1":    S("h1", fontSize=13, leading=18, textColor=C_NAVY,
                   fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=4),
        "h2":    S("h2", fontSize=10, leading=14, textColor=C_GREEN,
                   fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=3),
        "body":  S("b",  fontSize=9, leading=13, textColor=C_BODY,
                   fontName="Helvetica", alignment=TA_JUSTIFY,
                   spaceBefore=2, spaceAfter=3),
        "code":  S("c",  fontSize=7.5, leading=11, textColor=C_CODE,
                   fontName="Courier", backColor=C_CODEBG,
                   leftIndent=8, rightIndent=8, spaceBefore=2, spaceAfter=2),
        "sign_name": S("sn", fontSize=13, leading=18, textColor=C_NAVY,
                       fontName="Helvetica-Bold", alignment=TA_CENTER),
        "label": S("l",  fontSize=8, leading=12, textColor=C_LABEL,
                   fontName="Helvetica-Bold"),
    }

    def hr(c=C_NAVY, t=0.6):
        return HRFlowable(width="100%", thickness=t, color=c,
                          spaceAfter=6, spaceBefore=4)

    def meta_table(rows):
        t = Table(rows, colWidths=[4.8*cm, 10.4*cm])
        t.setStyle(TableStyle([
            ("FONTNAME",        (0,0), (0,-1),  "Helvetica-Bold"),
            ("FONTNAME",        (1,0), (1,-1),  "Helvetica"),
            ("FONTSIZE",        (0,0), (-1,-1), 8.5),
            ("TEXTCOLOR",       (0,0), (0,-1),  C_LABEL),
            ("TEXTCOLOR",       (1,0), (1,-1),  C_BODY),
            ("VALIGN",          (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",      (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",   (0,0), (-1,-1), 5),
            ("LEFTPADDING",     (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",  (0,0), (-1,-1), [C_ROW1, C_ROW2]),
            ("GRID",            (0,0), (-1,-1), 0.4, C_BORDER),
            ("BOX",             (0,0), (-1,-1), 0.8, C_NAVY),
        ]))
        return t

    story = []

    # ── COVER BLOCK ──────────────────────────────────────────────────────────
    cover = Table(
        [[Paragraph("INFORME DE ESCANEO DE VULNERABILIDADES", st["title"])],
         [Paragraph("Datacom Security — Ethical Hacking", st["sub"])]],
        colWidths=[W - 3.6*cm]
    )
    cover.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_NAVY),
        ("TOPPADDING",    (0,0), (-1,-1), 18),
        ("BOTTOMPADDING", (0,0), (-1,-1), 18),
        ("LEFTPADDING",   (0,0), (-1,-1), 20),
        ("RIGHTPADDING",  (0,0), (-1,-1), 20),
        ("LINEBELOW",     (0,-1),(-1,-1), 3, C_BLUE),
    ]))
    story.append(cover)
    story.append(Spacer(1, 0.5*cm))

    # ── META TABLE ────────────────────────────────────────────────────────────
    story.append(Paragraph("Información del Test", st["h1"]))
    story.append(hr())
    story.append(meta_table([
        ["Ingeniero responsable", engineer],
        ["Cliente / Empresa",     client],
        ["Objetivo escaneado",    target],
        ["Perfil de escaneo",     profile],
        ["Fecha y hora de inicio", start_time],
        ["Fecha y hora de fin",    end_time],
        ["ID del escaneo",        scan_id],
        ["VPN activa",            scan.get("vpn_client", "No")],
    ]))

    # ── SUMMARY ───────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("Resumen de Hallazgos", st["h1"]))
    story.append(hr())

    sev_info = [
        ("CRITICAL", C_CRIT, "Vulnerabilidades críticas explotables remotamente"),
        ("HIGH",     C_HIGH, "Vulnerabilidades con CVE conocido o alto impacto"),
        ("MEDIUM",   C_MED,  "Configuraciones débiles o riesgo moderado"),
        ("LOW",      C_LOW,  "Información de baja criticidad"),
        ("INFO",     C_LABEL,"Líneas informativas sin implicación de riesgo"),
    ]
    sev_rows = [[
        Paragraph("<b>Severidad</b>",  S("sh", fontSize=8.5, textColor=WHITE, fontName="Helvetica-Bold")),
        Paragraph("<b>Cantidad</b>",   S("sh2",fontSize=8.5, textColor=WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph("<b>Descripción</b>",S("sh3",fontSize=8.5, textColor=WHITE, fontName="Helvetica-Bold")),
    ]]
    for sev, col, desc in sev_info:
        cnt = counts[sev]
        sev_rows.append([
            Paragraph(f"<b>{sev}</b>", S(f"sv{sev}", fontSize=8.5, textColor=col, fontName="Helvetica-Bold")),
            Paragraph(str(cnt),        S(f"sc{sev}", fontSize=9,   textColor=col if cnt>0 else C_BODY,
                                          fontName="Helvetica-Bold" if cnt>0 else "Helvetica", alignment=TA_CENTER)),
            Paragraph(desc,            S(f"sd{sev}", fontSize=8.5, textColor=C_BODY, fontName="Helvetica")),
        ])

    sev_t = Table(sev_rows, colWidths=[2.8*cm, 2.2*cm, 10.2*cm])
    sev_t.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,0),  C_HDR),
        ("FONTSIZE",     (0,0), (-1,-1), 8.5),
        ("ALIGN",        (1,0), (1,-1),  "CENTER"),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",   (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0), (-1,-1), 6),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
        ("GRID",         (0,0), (-1,-1), 0.4, C_BORDER),
        ("BOX",          (0,0), (-1,-1), 0.8, C_NAVY),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_ROW2, C_ROW1]),
    ]))
    story.append(sev_t)

    # ── COMMAND ───────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("Comando ejecutado:", st["h2"]))
    story.append(Paragraph(
        command.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"),
        st["code"]))

    # ── HOST TABLE ────────────────────────────────────────────────────────────
    avail = W - 3.6*cm
    discovered = _parse_hosts_from_lines(lines)
    if discovered:
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph("Hosts Activos Descubiertos", st["h1"]))
        story.append(hr())
        story.append(Paragraph(
            f"Se identificaron <b>{len(discovered)}</b> host(s) con servicios confirmados:",
            st["body"]))
        story.append(Spacer(1, 0.15*cm))
        col_w = [3.2*cm, 3.0*cm, 4.2*cm, 2.8*cm, avail - 13.2*cm]

        host_rows = [[
            Paragraph("<b>Hostname</b>",        S("hh0",fontSize=8,textColor=WHITE,fontName="Helvetica-Bold")),
            Paragraph("<b>IP</b>",              S("hi0",fontSize=8,textColor=WHITE,fontName="Helvetica-Bold")),
            Paragraph("<b>MAC</b>",             S("hm0",fontSize=8,textColor=WHITE,fontName="Helvetica-Bold")),
            Paragraph("<b>Vendor</b>",          S("hv0",fontSize=8,textColor=WHITE,fontName="Helvetica-Bold")),
            Paragraph("<b>Puertos abiertos</b>",S("hp0",fontSize=8,textColor=WHITE,fontName="Helvetica-Bold")),
        ]]
        for i, h in enumerate(discovered):
            bg = C_ROW1 if i % 2 == 0 else C_ROW2
            ports_str = ", ".join(h["ports"]) if h["ports"] else "—"
            host_rows.append([
                Paragraph(h["hostname"] or "—",   S(f"hb{i}",fontSize=8,textColor=C_BODY, fontName="Helvetica")),
                Paragraph(h["ip"],                S(f"hI{i}",fontSize=8,textColor=C_BLUE, fontName="Courier")),
                Paragraph(h["mac"],               S(f"hM{i}",fontSize=8,textColor=C_CODE, fontName="Courier")),
                Paragraph(h["vendor"],            S(f"hV{i}",fontSize=8,textColor=C_BODY, fontName="Helvetica")),
                Paragraph(ports_str,              S(f"hP{i}",fontSize=8,textColor=C_GREEN,fontName="Courier")),
            ])

        ht = Table(host_rows, colWidths=col_w, repeatRows=1)
        ht.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  C_HDR),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_ROW1, C_ROW2]),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 7),
            ("RIGHTPADDING",  (0,0), (-1,-1), 7),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("GRID",          (0,0), (-1,-1), 0.4, C_BORDER),
            ("BOX",           (0,0), (-1,-1), 0.8, C_NAVY),
        ]))
        story.append(ht)

    # ── FINDINGS TABLE ────────────────────────────────────────────────────────
    findings = [(l, detect_severity(l)) for l in lines
                if detect_severity(l) in ("CRITICAL","HIGH","MEDIUM")]
    if findings:
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph("Hallazgos Relevantes", st["h1"]))
        story.append(hr())
        story.append(Paragraph(
            f"Se detectaron <b>{len(findings)}</b> hallazgos (CRITICAL / HIGH / MEDIUM):",
            st["body"]))
        story.append(Spacer(1, 0.15*cm))

        sev_col = {"CRITICAL": C_CRIT, "HIGH": C_HIGH, "MEDIUM": C_MED}
        find_rows = [[
            Paragraph("<b>SEV</b>",      S("fh0",fontSize=8,textColor=WHITE,fontName="Helvetica-Bold")),
            Paragraph("<b>Hallazgo</b>", S("fh1",fontSize=8,textColor=WHITE,fontName="Helvetica-Bold")),
        ]]
        for i, (line, sev) in enumerate(findings[:80]):
            col = sev_col.get(sev, C_BODY)
            find_rows.append([
                Paragraph(f"<b>{sev}</b>", S(f"fs{i}",fontSize=8,textColor=col,fontName="Helvetica-Bold")),
                Paragraph(line.strip()[:200].replace("&","&amp;").replace("<","&lt;"),
                          S(f"fl{i}",fontSize=7.5,textColor=C_BODY,fontName="Courier")),
            ])

        ft = Table(find_rows, colWidths=[2.2*cm, avail - 2.2*cm])
        ft.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  C_HDR),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_ROW2, C_ROW1]),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING",   (0,0), (-1,-1), 7),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ("GRID",          (0,0), (-1,-1), 0.4, C_BORDER),
            ("BOX",           (0,0), (-1,-1), 0.8, C_NAVY),
            ("WORDWRAP",      (1,1), (1,-1),  True),
        ]))
        story.append(ft)
        story.append(Spacer(1, 0.3*cm))

    # ── FULL OUTPUT ───────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("Salida completa del escaneo", st["h1"]))
    story.append(hr())
    MAX_LINES = 300
    output_lines = [l for l in lines if isinstance(l, str) and l.strip()]
    truncated = len(output_lines) > MAX_LINES
    for line in output_lines[:MAX_LINES]:
        clean = line.rstrip()
        if clean:
            story.append(Paragraph(
                clean[:200].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"),
                st["code"]))
    if truncated:
        story.append(Paragraph(
            f"[ ... salida truncada — {len(output_lines)-MAX_LINES} líneas adicionales en /opt/scanner/scans/ ]",
            S("tr", fontSize=7.5, leading=10, textColor=C_LABEL, fontName="Helvetica-Oblique")))

    # ── SIGNATURE BLOCK ───────────────────────────────────────────────────────
    story.append(Spacer(1, 0.8*cm))
    story.append(hr(C_NAVY, 1))
    story.append(Spacer(1, 0.4*cm))

    sig_date = end_time or start_time
    sig_data = [
        [
            Paragraph("Firma del Ingeniero Responsable",
                      S("slh", fontSize=8, textColor=WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)),
            Paragraph("Fecha y Hora del Test",
                      S("sdh", fontSize=8, textColor=WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        ],
        [
            Table([
                [Paragraph("_" * 38, S("ul",fontSize=10,textColor=C_LABEL,fontName="Helvetica",alignment=TA_CENTER))],
                [Paragraph(engineer,  st["sign_name"])],
                [Paragraph("Ingeniero de Seguridad — Datacom Security",
                           S("ro",fontSize=8,textColor=C_LABEL,fontName="Helvetica-Oblique",alignment=TA_CENTER))],
            ], style=TableStyle([
                ("ALIGN",(0,0),(-1,-1),"CENTER"),
                ("TOPPADDING",(0,0),(-1,-1),5),
                ("BOTTOMPADDING",(0,0),(-1,-1),5),
            ])),
            Table([
                [Paragraph(sig_date,
                           S("dt",fontSize=13,textColor=C_NAVY,fontName="Helvetica-Bold",alignment=TA_CENTER))],
                [Paragraph("Inicio del escaneo",
                           S("dt2",fontSize=8,textColor=C_LABEL,fontName="Helvetica",alignment=TA_CENTER))],
                [Paragraph(f"Generado: {now_display()}",
                           S("dt3",fontSize=8,textColor=C_GREEN,fontName="Helvetica",alignment=TA_CENTER))],
            ], style=TableStyle([
                ("ALIGN",(0,0),(-1,-1),"CENTER"),
                ("TOPPADDING",(0,0),(-1,-1),5),
                ("BOTTOMPADDING",(0,0),(-1,-1),5),
            ])),
        ],
    ]

    sig_table = Table(sig_data, colWidths=[8*cm, 7.2*cm])
    sig_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  C_HDR),
        ("BACKGROUND",    (0,1), (-1,-1), C_ROW1),
        ("BOX",           (0,0), (-1,-1), 0.8, C_NAVY),
        ("LINEAFTER",     (0,0), (0,-1),  0.5, C_BORDER),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,0),  8),
        ("BOTTOMPADDING", (0,0), (-1,0),  8),
        ("TOPPADDING",    (0,1), (-1,1),  16),
        ("BOTTOMPADDING", (0,1), (-1,1),  20),
    ]))
    story.append(sig_table)
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        "Este informe ha sido generado automáticamente por el sistema Kali VPN Vulnerability Scanner "
        "de Datacom Security. Su contenido es confidencial y de uso exclusivo del cliente indicado. "
        "Queda prohibida su reproducción o distribución sin autorización escrita.",
        S("disc", fontSize=7, leading=10, textColor=C_LABEL,
          fontName="Helvetica-Oblique", alignment=TA_CENTER)))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    buf.seek(0)
    return buf.read()


# ── Executive HTML Report ──────────────────────────────────────────────────────

def generate_executive_html_report(scan: dict) -> str:
    """Generate a management-facing executive HTML report, tailored per scan profile."""
    import html as _html

    engineer   = scan.get("engineer",   "Sin especificar") or "Sin especificar"
    client     = scan.get("client",     "N/A") or "N/A"
    target     = scan.get("target",     "N/A")
    profile    = scan.get("profile",    "N/A")
    start_time = scan.get("start",      now_str())
    end_time   = scan.get("end",        now_str()) or now_str()
    scan_id    = scan.get("id",         "N/A")
    vpn_iface  = scan.get("vpn_client", "No") or "No"
    lines      = scan.get("lines",      [])

    # ── Parse hosts ────────────────────────────────────────────────────────────
    hosts = _parse_hosts_from_lines(lines)

    # ── Count severities (skip retransmission noise) ───────────────────────────
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for line in lines:
        if isinstance(line, str) and "retransmission" not in line.lower():
            sev = detect_severity(line)
            if sev in counts:
                counts[sev] += 1

    # ── Overall risk badge ─────────────────────────────────────────────────────
    if counts["CRITICAL"] > 0:
        risk_class, risk_label = "badge-risk-critico",  "RIESGO: CRÍTICO"
    elif counts["HIGH"] > 0:
        risk_class, risk_label = "badge-risk-alto",     "RIESGO: ALTO"
    elif counts["MEDIUM"] > 5:
        risk_class, risk_label = "badge-risk-moderado", "RIESGO: MODERADO"
    else:
        risk_class, risk_label = "badge-risk-bajo",     "RIESGO: BAJO"

    # ── Bar chart widths (% of max) ────────────────────────────────────────────
    max_c = max(counts.values(), default=1) or 1
    pct   = {k: max(round(v / max_c * 100), 2) if v > 0 else 0 for k, v in counts.items()}

    # ── Host risk scoring ──────────────────────────────────────────────────────
    _PORT_SCORE = {
        23: 3, 21: 3, 5900: 3, 3389: 3, 3306: 3, 1433: 3,
        25: 2, 110: 2, 143: 2, 514: 2, 111: 2,
        80: 1, 22: 1, 443: 1,
    }
    _SVC_LABEL = {
        21: "FTP (sin cifrado)",        22: "Acceso SSH",
        23: "Telnet (sin cifrado)",     25: "Correo SMTP",
        80: "Web HTTP",                 110: "Correo POP3",
        111: "RPC",                     143: "Correo IMAP",
        443: "Web HTTPS",               445: "Compartición SMB",
        514: "Acceso Shell remoto",     1433: "Base de datos MSSQL",
        3306: "Base de datos MySQL",    3389: "Escritorio Remoto (RDP)",
        5432: "Base de datos PostgreSQL", 5900: "Control Remoto VNC",
        8080: "Web HTTP alternativo",   8443: "Web HTTPS alternativo",
        8000: "Web HTTP alternativo",   27017: "Base de datos MongoDB",
    }
    _DANGER = {23, 21, 3389, 5900, 1433, 3306, 5432}
    _WARN   = {25, 110, 143, 514, 111, 445}

    def _pnum(ps):
        try: return int(ps.split("/")[0])
        except: return 0

    def _score(h):
        return sum(_PORT_SCORE.get(_pnum(ps), 0) for ps in h.get("ports", []))

    for h in hosts:
        h["_score"] = _score(h)
    top6 = sorted(hosts, key=lambda h: -h["_score"])[:6]

    # ── Discover all open port numbers across all hosts ────────────────────────
    all_ports = {_pnum(ps) for h in hosts for ps in h.get("ports", [])}
    all_svcs  = " ".join(
        (ps.split("/")[1] if "/" in ps else ps)
        for h in hosts for ps in h.get("ports", [])
    ).lower()

    # ── Action items ───────────────────────────────────────────────────────────
    actions = []
    if all_ports & {21, 23}:
        actions.append(("URGENTE", "action-urgente",
            "Deshabilitar protocolos sin cifrado (Telnet y FTP) en todos los equipos afectados "
            "y reemplazarlos por alternativas seguras: SSH para administración remota y SFTP para transferencia de archivos."))
    if 3389 in all_ports:
        actions.append(("URGENTE", "action-urgente",
            "Proteger el acceso remoto al escritorio (RDP) con autenticación de doble factor "
            "y restringir las conexiones únicamente a redes internas autorizadas."))
    if all_ports & {3306, 1433, 5432}:
        actions.append(("URGENTE", "action-urgente",
            "Bloquear el acceso directo a las bases de datos desde la red general mediante reglas de cortafuegos. "
            "Solo los servidores de aplicación autorizados deben poder conectarse."))
    if 5900 in all_ports:
        actions.append(("2 SEMANAS", "action-2semanas",
            "Auditar todos los equipos con control remoto de pantalla (VNC) activo: verificar que cuentan con "
            "contraseña fuerte y que el acceso está limitado a usuarios específicos."))
    if all_ports & {445, 137, 138, 139}:
        actions.append(("2 SEMANAS", "action-2semanas",
            "Revisar la configuración de compartición de archivos en red (Windows/SMB): este protocolo es el "
            "vector de entrada más común en ataques de ransomware. Deshabilitar en equipos que no lo necesiten."))
    if any(s in all_svcs for s in ["rtsp", "jetdirect", "sccp", "sip"]):
        actions.append(("30 DÍAS", "action-30dias",
            "Segmentar la red en zonas separadas (VLANs) según el tipo de dispositivo: servidores, "
            "equipos de usuario, cámaras, impresoras y teléfonos IP. Esto limita el impacto de cualquier incidente futuro."))
    actions.append(("30 DÍAS", "action-30dias",
        "Repetir el escaneo de seguridad en 30 días para verificar que las acciones correctivas "
        "han sido implementadas y medir la reducción del riesgo."))

    # ── Helpers ────────────────────────────────────────────────────────────────
    def e(s): return _html.escape(str(s))

    def risk_cls(score):
        if score >= 6: return "risk-high"
        if score >= 3: return "risk-medium"
        return "risk-low"

    def svc_tag(ps):
        p   = _pnum(ps)
        lbl = _SVC_LABEL.get(p, ps)
        cls = " danger" if p in _DANGER else (" warn" if p in _WARN else "")
        return f'<span class="service-tag{cls}">{e(lbl)}</span>'

    host_cards = "".join(f"""
      <div class="host-card {risk_cls(h['_score'])}">
        <div class="host-ip">{e(h['ip'])}</div>
        <div class="host-score">Puntuación de riesgo: {h['_score']}</div>
        <div class="host-services">{''.join(svc_tag(ps) for ps in h.get('ports',[])[:8])}</div>
      </div>""" for h in top6) or \
      '<div style="color:#8A94A6;font-size:13px;padding:12px 0;">No se detectaron hosts prioritarios relevantes.</div>'

    def _sort_ip(h):
        try: return [int(p) for p in h['ip'].split('.')]
        except: return [0,0,0,0]

    inventory_rows = "".join(f"""
      <tr>
        <td style="font-family:monospace;font-weight:600;">{e(h['ip'])}</td>
        <td>{e(h.get('hostname') or '—')}</td>
        <td style="font-family:monospace;color:#5C6B8A;">{e(h.get('mac') or '—')}</td>
        <td>{e(h.get('vendor') or '—')}</td>
        <td style="color:#185FA5;">{e(", ".join(h.get('ports',[])) or '—')}</td>
      </tr>""" for h in sorted(hosts, key=_sort_ip))


    action_items = "".join(f"""
      <li class="action-item {css}">
        <span class="action-tag">{e(tag)}</span>
        <span class="action-text">{e(text)}</span>
      </li>""" for tag, css, text in actions)

    def bar_row(label, lc, bc, cnt, pw):
        w = pw if cnt > 0 else 0
        return (f'<div class="chart-row">'
                f'<span class="chart-label {lc}">{label}</span>'
                f'<div class="chart-bar-bg"><div class="chart-bar {bc}" style="width:{w}%;"></div></div>'
                f'<span class="chart-count {lc}">{cnt}</span></div>')

    chart = (
        bar_row("CRÍTICO", "label-critico", "bar-critico", counts["CRITICAL"], pct["CRITICAL"]) +
        bar_row("ALTO",    "label-alto",    "bar-alto",    counts["HIGH"],     pct["HIGH"])     +
        bar_row("MEDIO",   "label-medio",   "bar-medio",   counts["MEDIUM"],   pct["MEDIUM"])   +
        bar_row("BAJO",    "label-bajo",    "bar-bajo",    counts["LOW"],      pct["LOW"])
    )

    try:
        from datetime import datetime as _dt
        _fmt = "%Y-%m-%d %H:%M:%S"
        dur_str = str(_dt.strptime(end_time, _fmt) - _dt.strptime(start_time, _fmt))
    except Exception:
        dur_str = "—"

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reporte Ejecutivo — {e(client)}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;
     font-size:14px;line-height:1.6;background:#F4F6F9;color:#1A1A2E}}
.page{{max-width:900px;margin:32px auto;background:#fff;border-radius:10px;
       box-shadow:0 4px 24px rgba(0,0,0,.10);overflow:hidden}}
.report-header{{background:linear-gradient(135deg,#0D1B2A 0%,#1B3556 100%);
               color:#fff;padding:36px 40px 28px}}
.header-top{{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}}
.header-logo{{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#7BAFD4;font-weight:600}}
.report-title{{font-size:22px;font-weight:700;margin:6px 0 2px;letter-spacing:-.3px}}
.report-subtitle{{font-size:13px;color:#A8C4DC}}
.badges{{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-start}}
.badge{{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:700;
        letter-spacing:.06em;text-transform:uppercase;white-space:nowrap}}
.badge-vpn{{background:#1E4D78;color:#7EC8E3;border:1px solid #2A6099}}
.badge-risk-critico{{background:#A32D2D;color:#fff;border:1px solid #c84040}}
.badge-risk-alto{{background:#854F0B;color:#fff;border:1px solid #b06a10}}
.badge-risk-moderado{{background:#7D6008;color:#fff;border:1px solid #a8820a}}
.badge-risk-bajo{{background:#3B6D11;color:#fff;border:1px solid #5a9e1a}}
.header-meta{{margin-top:22px;display:grid;
             grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px 24px}}
.meta-label{{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:#7BAFD4;font-weight:600}}
.meta-value{{font-size:13px;color:#E8F1F8;font-weight:500}}
.report-body{{padding:32px 40px}}
.section{{margin-bottom:36px}}
.section-title{{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.10em;
               color:#5C6B8A;border-bottom:2px solid #E8ECF2;padding-bottom:8px;margin-bottom:18px}}
.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}}
.card{{border-radius:8px;padding:18px 16px 14px;text-align:center;border-width:1px;border-style:solid}}
.card-num{{font-size:36px;font-weight:800;line-height:1}}
.card-label{{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.09em;margin-top:5px}}
.card-hosts{{background:#E6F1FB;border-color:#B5D4F4;color:#185FA5}}
.card-critico{{background:#FCEBEB;border-color:#F09595;color:#A32D2D}}
.card-alto{{background:#FAEEDA;border-color:#FAC775;color:#854F0B}}
.card-medio{{background:#E6F1FB;border-color:#B5D4F4;color:#185FA5}}
.chart-wrap{{padding:6px 0}}
.chart-row{{display:flex;align-items:center;gap:10px;margin-bottom:12px}}
.chart-label{{width:78px;font-size:12px;font-weight:600;text-align:right;flex-shrink:0}}
.chart-bar-bg{{flex:1;background:#F0F2F6;border-radius:4px;height:26px;overflow:hidden}}
.chart-bar{{height:100%;border-radius:4px;min-width:0}}
.chart-count{{font-size:13px;font-weight:700;width:28px;text-align:left;flex-shrink:0}}
.bar-critico{{background:#C94040}}.bar-alto{{background:#D4780A}}
.bar-medio{{background:#2274C8}}.bar-bajo{{background:#4E9E1A}}
.label-critico{{color:#A32D2D}}.label-alto{{color:#854F0B}}
.label-medio{{color:#185FA5}}.label-bajo{{color:#3B6D11}}
.hosts-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:14px}}
.host-card{{border-radius:8px;border:1px solid #E0E6EF;border-left-width:5px;
            padding:14px 16px;background:#FAFBFD}}
.host-card.risk-high{{border-left-color:#C94040}}
.host-card.risk-medium{{border-left-color:#D4780A}}
.host-card.risk-low{{border-left-color:#2274C8}}
.host-ip{{font-size:15px;font-weight:700;color:#1A1A2E;font-family:'SF Mono','Fira Code',monospace}}
.host-score{{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:#8A94A6;margin:2px 0 8px}}
.host-services{{display:flex;flex-wrap:wrap;gap:5px}}
.service-tag{{font-size:11px;padding:2px 8px;border-radius:12px;font-weight:500;
              background:#E6EDF6;color:#3B5278}}
.service-tag.danger{{background:#FCEBEB;color:#A32D2D}}
.service-tag.warn{{background:#FAEEDA;color:#854F0B}}
.actions-list{{list-style:none;display:flex;flex-direction:column;gap:10px}}
.action-item{{display:flex;align-items:flex-start;gap:14px;padding:14px 16px;
              border-radius:8px;border-width:1px;border-style:solid}}
.action-tag{{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;
             padding:3px 10px;border-radius:20px;white-space:nowrap;flex-shrink:0;margin-top:1px}}
.action-text{{font-size:13px;line-height:1.5}}
.action-urgente{{background:#FCEBEB;border-color:#F09595}}
.action-urgente .action-tag{{background:#A32D2D;color:#fff}}
.action-urgente .action-text{{color:#5A1515}}
.action-2semanas{{background:#FAEEDA;border-color:#FAC775}}
.action-2semanas .action-tag{{background:#854F0B;color:#fff}}
.action-2semanas .action-text{{color:#4A2B05}}
.action-30dias{{background:#E6F1FB;border-color:#B5D4F4}}
.action-30dias .action-tag{{background:#185FA5;color:#fff}}
.action-30dias .action-text{{color:#0D2E4E}}
.report-footer{{background:#F0F2F6;border-top:1px solid #DDE2EC;padding:20px 40px;
               display:flex;justify-content:space-between;align-items:flex-start;
               flex-wrap:wrap;gap:12px}}
.footer-meta{{font-size:11px;color:#5C6B8A;line-height:1.8}}
.footer-meta strong{{color:#1A1A2E}}
.footer-confidential{{font-size:10px;color:#8A94A6;text-align:right;max-width:260px;line-height:1.5}}
.confidential-badge{{display:inline-block;background:#1A1A2E;color:#fff;font-size:9px;font-weight:700;
                    letter-spacing:.15em;text-transform:uppercase;padding:2px 8px;border-radius:3px;margin-bottom:4px}}
.inventory-table{{width:100%;border-collapse:collapse;margin-top:10px;font-size:12px;}}
.inventory-table th{{text-align:left;background:#E8ECF2;padding:10px 12px;color:#5C6B8A;font-weight:700;text-transform:uppercase;letter-spacing:.05em;}}
.inventory-table td{{padding:10px 12px;border-bottom:1px solid #E0E6EF;color:#1A1A2E;}}
.inventory-table tr:nth-child(even){{background:#FAFBFD;}}
@media print{{
  body{{background:#fff}}
  .page{{box-shadow:none;border-radius:0;margin:0}}
  .report-header,.card,.host-card,.action-item,.chart-bar{{
    -webkit-print-color-adjust:exact;print-color-adjust:exact}}
}}
</style>
</head>
<body>
<div class="page">
  <header class="report-header">
    <div class="header-top">
      <div>
        <div class="header-logo">Reporte Ejecutivo de Seguridad &mdash; Datacom Security</div>
        <div class="report-title">Análisis de Vulnerabilidades de Red</div>
        <div class="report-subtitle">{e(client)} &mdash; Gerencia General</div>
      </div>
      <div class="badges">
        <span class="badge badge-vpn">VPN: {e(vpn_iface)}</span>
        <span class="badge {risk_class}">{e(risk_label)}</span>
      </div>
    </div>
    <div class="header-meta">
      <div><div class="meta-label">Cliente</div><div class="meta-value">{e(client)}</div></div>
      <div><div class="meta-label">Objetivo</div><div class="meta-value">{e(target)}</div></div>
      <div><div class="meta-label">Fecha de escaneo</div><div class="meta-value">{e(start_time)}</div></div>
      <div><div class="meta-label">Ingeniero responsable</div><div class="meta-value">{e(engineer)}</div></div>
      <div><div class="meta-label">ID de escaneo</div>
           <div class="meta-value" style="font-family:monospace;font-size:12px;">{e(scan_id)}</div></div>
    </div>
  </header>

  <div class="report-body">

    <section class="section">
      <div class="section-title">Resumen Ejecutivo</div>
      <div class="cards">
        <div class="card card-hosts">
          <div class="card-num">{len(hosts)}</div>
          <div class="card-label">Hosts Activos</div>
        </div>
        <div class="card card-critico">
          <div class="card-num">{counts["CRITICAL"]}</div>
          <div class="card-label">Críticos</div>
        </div>
        <div class="card card-alto">
          <div class="card-num">{counts["HIGH"]}</div>
          <div class="card-label">Altos</div>
        </div>
        <div class="card card-medio">
          <div class="card-num">{counts["MEDIUM"]}</div>
          <div class="card-label">Medios</div>
        </div>
      </div>
    </section>

    <section class="section">
      <div class="section-title">Distribución de Riesgo</div>
      <div class="chart-wrap">{chart}</div>
    </section>

    <section class="section">
      <div class="section-title">Hosts Prioritarios</div>
      <div class="hosts-grid">{host_cards}</div>
    </section>

    <section class="section">
      <div class="section-title">Inventario de Red Descubierto</div>
      <div style="overflow-x:auto;">
        <table class="inventory-table">
          <thead>
            <tr>
              <th>IP</th>
              <th>Hostname</th>
              <th>Dirección MAC</th>
              <th>Fabricante</th>
              <th>Puertos Abiertos</th>
            </tr>
          </thead>
          <tbody>
            {inventory_rows}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <div class="section-title">Acciones Recomendadas para Gerencia</div>
      <ul class="actions-list">{action_items}</ul>
    </section>

  </div>

  <footer class="report-footer">
    <div class="footer-meta">
      <div><strong>Perfil de escaneo:</strong> {e(profile)}</div>
      <div><strong>Duración:</strong> {e(start_time)} &rarr; {e(end_time)} ({e(dur_str)})</div>
      <div><strong>Ingeniero:</strong> {e(engineer)} &nbsp;|&nbsp;
           <strong>ID:</strong> <span style="font-family:monospace;">{e(scan_id)}</span></div>
    </div>
    <div class="footer-confidential">
      <div class="confidential-badge">Confidencial</div>
      <div>Este documento contiene información sensible sobre la infraestructura de {e(client)}.
      Su distribución está restringida a la Gerencia General y al equipo de TI autorizado.</div>
    </div>
  </footer>
</div>
</body>
</html>"""


# ── Network Map ────────────────────────────────────────────────────────────────

def _parse_discovery(output: str) -> list:
    """Parse `nmap -sn` output → list of host dicts."""
    hosts, cur = [], None
    for line in output.splitlines():
        m = re.match(r'Nmap scan report for (.+)', line)
        if m:
            if cur: hosts.append(cur)
            s = m.group(1).strip()
            ip_m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', s)
            if ip_m:
                ip = ip_m.group(1)
                hn = s[:s.rfind('(')].strip()
            else:
                ip = s; hn = ""
            if "compute.internal" in hn or "ec2.internal" in hn:
                hn = ""
            cur = {"ip": ip, "hostname": hn, "mac": "", "vendor": "", "ports": []}
        elif cur:
            mac_m = re.match(r'\s*MAC Address: ([0-9A-Fa-f:]+)\s*(?:\(([^)]*)\))?', line)
            if mac_m:
                cur["mac"]    = mac_m.group(1)
                cur["vendor"] = mac_m.group(2) or ""
    if cur: hosts.append(cur)
    return hosts


def _parse_ports(output: str, by_ip: dict):
    """Append open ports to existing host dicts from nmap -sT output."""
    cur = None
    for line in output.splitlines():
        m = re.match(r'Nmap scan report for (.+)', line)
        if m:
            s = m.group(1).strip()
            ip_m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', s)
            cur = ip_m.group(1) if ip_m else s
        elif cur and cur in by_ip:
            pm = re.match(r'\s*(\d+)/tcp\s+open\s+(\S+)', line)
            if pm:
                by_ip[cur]["ports"].append({"port": int(pm.group(1)), "service": pm.group(2)})


def _classify_node(h: dict) -> str:
    ports = [p["port"] for p in h.get("ports", [])]
    last  = h["ip"].split(".")[-1]
    hn    = h.get("hostname", "").lower()
    vn    = h.get("vendor",   "").lower()
    if last in ("1", "254") \
       or any(k in hn for k in ("router","gateway","fw","firewall","fortigate","edge","pfsense")) \
       or any(k in vn for k in ("fortinet","cisco","juniper","mikrotik","ubiquiti","palo alto","sonicwall")):
        return "gateway"
    if 3389 in ports or (445 in ports and 80 not in ports and 443 not in ports):
        return "windows"
    if 443 in ports or 80 in ports or 8080 in ports or 8443 in ports:
        return "web"
    if 22 in ports:
        return "linux"
    if any(p in ports for p in (3306, 5432, 1521, 27017)):
        return "database"
    return "unknown"


def _run_network_map(map_id: str, target: str):
    state = network_maps[map_id]
    try:
        state["status"] = "Descubriendo hosts activos..."
        disc = subprocess.run(
            f"nmap -sn -T4 {target}",
            shell=True, capture_output=True, text=True, timeout=120
        )
        all_hosts = _parse_discovery(disc.stdout)
        total_discovered = len(all_hosts)
        state["status"] = f"Escaneando puertos en {total_discovered} host(s)..."

        by_ip = {h["ip"]: h for h in all_hosts}
        if all_hosts:
            ips_str = " ".join(h["ip"] for h in all_hosts)
            port_out = subprocess.run(
                f"nmap -sT -Pn -T4 --open -p 21,22,25,80,110,443,445,3306,3389,5432,8080,8443 {ips_str}",
                shell=True, capture_output=True, text=True, timeout=180
            )
            _parse_ports(port_out.stdout, by_ip)

        # Classify all hosts first so gateway detection works correctly
        for h in all_hosts:
            h["type"] = _classify_node(h)

        # Keep only hosts that are gateways OR have at least one open port confirmed.
        # Hosts that only responded to ping but expose no services are excluded —
        # they add visual noise without actionable information.
        hosts = [h for h in all_hosts if h["type"] == "gateway" or len(h["ports"]) > 0]
        filtered_out = total_discovered - len(hosts)

        # If no gateway found among filtered hosts, promote the first host
        gateways = [h["ip"] for h in hosts if h["type"] == "gateway"]
        if not gateways and hosts:
            hosts[0]["type"] = "gateway"
            gateways = [hosts[0]["ip"]]

        edges = []
        if gateways:
            for h in hosts:
                if h["ip"] not in gateways:
                    edges.append({"source": gateways[0], "target": h["ip"]})
        for i in range(len(gateways) - 1):
            edges.append({"source": gateways[i], "target": gateways[i + 1]})

        note = f" ({filtered_out} sin servicios excluidos)" if filtered_out else ""
        state["nodes"]  = hosts
        state["edges"]  = edges
        state["status"] = "done"
        state["summary"] = f"{total_discovered} descubiertos · {len(hosts)} con servicios activos{note}"
    except Exception as e:
        state["status"] = f"error: {e}"
    finally:
        state["done"] = True


@app.route("/api/network/scan", methods=["POST"])
def api_network_scan():
    target = (request.json or {}).get("target", "").strip()
    if not target:
        return jsonify({"error": "target requerido"}), 400
    if not re.match(r'^[\w./:@\-]+$', target):
        return jsonify({"error": "target inválido"}), 400
    map_id = str(uuid.uuid4())[:8]
    network_maps[map_id] = {
        "done": False, "status": "Iniciando...",
        "nodes": [], "edges": [], "target": target,
    }
    threading.Thread(target=_run_network_map, args=(map_id, target), daemon=True).start()
    return jsonify({"map_id": map_id})


@app.route("/api/network/stream/<map_id>")
def api_network_stream(map_id):
    def generate():
        last = None
        while True:
            m = network_maps.get(map_id)
            if not m:
                yield f"data: {json.dumps({'error': 'id inválido'})}\n\n"; break
            if m["status"] != last:
                last = m["status"]
                yield f"data: {json.dumps({'type': 'status', 'msg': m['status']})}\n\n"
            if m["done"]:
                yield f"data: {json.dumps({'type': 'result', 'nodes': m['nodes'], 'edges': m['edges'], 'summary': m.get('summary','')})}\n\n"
                break
            time.sleep(0.5)
    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Traffic Capture (tcpdump) ─────────────────────────────────────────────────
capture_sessions: dict[str, dict] = {}

@app.route("/api/capture/ifaces", methods=["GET"])
def api_capture_ifaces():
    try:
        r = subprocess.run("ip -o link show | awk -F': ' '{print $2}'",
                           shell=True, capture_output=True, text=True)
        ifaces = [i.strip().split('@')[0] for i in r.stdout.strip().split('\n')
                  if i.strip() and 'lo' not in i]
        return jsonify({"ifaces": ifaces or ["eth0"]})
    except:
        return jsonify({"ifaces": ["eth0", "tailscale0"]})

@app.route("/api/capture/start", methods=["POST"])
def api_capture_start():
    data  = request.json or {}
    iface = data.get("iface", "eth0").strip()
    bpf   = data.get("bpf", "").strip()
    if not re.match(r'^[a-zA-Z0-9_.\-]+$', iface):
        return jsonify({"error": "Interfaz inválida"}), 400
    cap_id = str(uuid.uuid4())[:8]
    fname  = f"/opt/scanner/scans/capture_{cap_id}.pcap"
    cmd    = ["tcpdump", "-i", iface, "-w", fname, "-n", "--print"]
    if bpf:
        cmd.append(bpf)
    capture_sessions[cap_id] = {
        "status": "running", "lines": [], "file": fname, "proc": None, "done": False,
        "stats": {"buckets": [], "top_src": {}, "top_dst_port": {}, "flags": {"S":0,"A":0,"F":0,"R":0,"P":0,"U":0}}
    }
    # Regex flexible: matches both formats
    #  eth0:  "18:17:59.728 IP 172.31.30.212.22 > 186.4.168.33.53318: Flags [P.], ..."
    #  any:   "18:18:08.304 eth0  Out IP 172.31.30.212.22 > 186.4.168.33.53325: Flags [P.], ..."
    #  UDP:   "18:17:59.744 IP 172.31.30.212.41641 > 186.4.168.33.41641: UDP, length 96"
    _pkt_tcp = re.compile(
        r'IP\s+([\d.]+)\.(\d+)\s+>\s+([\d.]+)\.(\d+):.*?Flags\s+\[([^\]]*)\]'
    )
    _pkt_udp = re.compile(
        r'IP\s+([\d.]+)\.(\d+)\s+>\s+([\d.]+)\.(\d+):.*?UDP'
    )
    _WINDOW = 300  # 5 minutes in seconds

    def _update_stats(state, line, ts_epoch):
        m = _pkt_tcp.search(line)
        is_udp = False
        if not m:
            m = _pkt_udp.search(line)
            is_udp = True
        if not m:
            return
        direction = "In" if " In " in line else "Out"
        src_ip, src_port = m.group(1), m.group(2)
        dst_ip, dst_port_s = m.group(3), m.group(4)
        flags_s = "" if is_udp else m.group(5)
        stats = state["stats"]
        now_s = int(ts_epoch)
        buckets = stats["buckets"]
        cutoff = ts_epoch - _WINDOW
        # Prune old buckets
        while buckets and buckets[0]["t"] < cutoff:
            old = buckets.pop(0)
            for ip, n in old.get("srcs", {}).items():
                stats["top_src"][ip] = max(0, stats["top_src"].get(ip, 0) - n)
            for p, n in old.get("ports", {}).items():
                stats["top_dst_port"][p] = max(0, stats["top_dst_port"].get(p, 0) - n)
            for f, n in old.get("fl", {}).items():
                stats["flags"][f] = max(0, stats["flags"].get(f, 0) - n)
        # Current bucket
        if not buckets or buckets[-1]["t"] != now_s:
            buckets.append({"t": now_s, "in": 0, "out": 0, "srcs": {}, "ports": {}, "fl": {}})
        b = buckets[-1]
        if direction == "In": b["in"] += 1
        else:                  b["out"] += 1
        b["srcs"][src_ip]      = b["srcs"].get(src_ip, 0) + 1
        b["ports"][dst_port_s] = b["ports"].get(dst_port_s, 0) + 1
        # Flag chars (TCP only; UDP counted as 'U')
        if is_udp:
            b["fl"]["U"]     = b["fl"].get("U", 0) + 1
            stats["flags"]["U"] = stats["flags"].get("U", 0) + 1
        else:
            for fc in ("S","A","F","R","P"):
                if fc in flags_s:
                    b["fl"][fc]     = b["fl"].get(fc, 0) + 1
                    stats["flags"][fc] = stats["flags"].get(fc, 0) + 1
        stats["top_src"][src_ip]          = stats["top_src"].get(src_ip, 0) + 1
        stats["top_dst_port"][dst_port_s] = stats["top_dst_port"].get(dst_port_s, 0) + 1

    def run():
        state = capture_sessions[cap_id]
        try:
            state["lines"].append(f"[tcpdump] Interfaz: {iface}")
            if bpf:
                state["lines"].append(f"[tcpdump] Filtro BPF: {bpf}")
            state["lines"].append(f"[tcpdump] Guardando en: {fname}")
            state["lines"].append("")
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
            state["proc"] = proc
            for line in proc.stdout:
                stripped = line.rstrip()
                state["lines"].append(stripped)
                _update_stats(state, stripped, time.time())
            proc.wait()
            state["lines"].append(f"\n[tcpdump] Finalizado (código {proc.returncode})")
        except Exception as e:
            state["lines"].append(f"[ERROR] {e}")
        finally:
            state["done"] = True
    threading.Thread(target=run, daemon=True).start()
    return jsonify({"cap_id": cap_id, "file": fname})

@app.route("/api/capture/stream/<cap_id>")
def api_capture_stream(cap_id):
    def gen():
        sent = 0
        while True:
            state = capture_sessions.get(cap_id)
            if not state:
                yield "data: [sesión no encontrada]\n\n"; break
            lines = state["lines"]
            while sent < len(lines):
                yield f"data: {lines[sent]}\n\n"
                sent += 1
            if state["done"] and sent >= len(lines):
                yield "data: __DONE__\n\n"; break
            time.sleep(0.3)
    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/capture/stop/<cap_id>", methods=["POST"])
def api_capture_stop(cap_id):
    state = capture_sessions.get(cap_id)
    if state and state.get("proc"):
        state["proc"].terminate()
        return jsonify({"ok": True})
    return jsonify({"ok": False})

@app.route("/api/capture/stats/<cap_id>")
def api_capture_stats(cap_id):
    state = capture_sessions.get(cap_id)
    if not state or "stats" not in state:
        return jsonify({"error": "not found"}), 404
    stats = state["stats"]
    buckets = stats["buckets"]
    # Time series: last 300 seconds, fill missing with zeros
    now_s = int(time.time())
    series_in, series_out, series_labels = [], [], []
    bucket_map = {b["t"]: b for b in buckets}
    for s in range(max(now_s - 299, buckets[0]["t"] if buckets else now_s), now_s + 1):
        b = bucket_map.get(s, {})
        series_labels.append(str(s))
        series_in.append(b.get("in", 0))
        series_out.append(b.get("out", 0))
    # Top 10 src IPs
    top_src = sorted(stats["top_src"].items(), key=lambda x: -x[1])[:10]
    # Top 10 dst ports
    top_ports = sorted(stats["top_dst_port"].items(), key=lambda x: -x[1])[:10]
    return jsonify({
        "labels":     series_labels,
        "series_in":  series_in,
        "series_out": series_out,
        "top_src":    top_src,
        "top_ports":  top_ports,
        "flags":      stats["flags"],
        "total":      sum(series_in) + sum(series_out),
    })

@app.route("/api/capture/read", methods=["POST"])
def api_capture_read():
    data   = request.json or {}
    fname  = data.get("file", "").strip()
    filt   = data.get("filter", "").strip()
    if not re.match(r'^/opt/scanner/scans/[a-zA-Z0-9_.\-]+\.pcap$', fname):
        return jsonify({"error": "Ruta de archivo inválida"}), 400
    cap_id = str(uuid.uuid4())[:8]
    capture_sessions[cap_id] = {"status": "running", "lines": [], "done": False, "proc": None}
    def run():
        state = capture_sessions[cap_id]
        try:
            cmd = ["tcpdump", "-r", fname, "-n", "-tttt"]
            if filt:
                cmd.append(filt)
            state["lines"].append(f"[tcpdump] Leyendo: {fname}")
            if filt:
                state["lines"].append(f"[tcpdump] Filtro: {filt}")
            state["lines"].append("")
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
            for line in proc.stdout:
                state["lines"].append(line.rstrip())
            proc.wait()
        except Exception as e:
            state["lines"].append(f"[ERROR] {e}")
        finally:
            state["done"] = True
    threading.Thread(target=run, daemon=True).start()
    return jsonify({"cap_id": cap_id})


# ── Suricata IDS ──────────────────────────────────────────────────────────────
ids_state = {"proc": None, "running": False, "alerts": [], "stats": {
    "buckets": [], "top_sig": {}, "top_src": {}, "severity": {1:0,2:0,3:0}
}}
_IDS_WINDOW = 300

# Regex for suricata fast.log:
# 04/07/2026-20:00:00.123456  [**] [1:2001219:20] ET SCAN ... [**] [Classification: ...] [Priority: 2] {TCP} 1.2.3.4:12345 -> 5.6.7.8:80
_ids_re = re.compile(
    r'(\d+/\d+/\d+-\d+:\d+:\d+)\.\d+\s+\[\*\*\]\s+\[[\d:]+\]\s+(.*?)\s+\[\*\*\]'
    r'(?:\s+\[Classification:\s*(.*?)\])?'
    r'\s+\[Priority:\s*(\d+)\]'
    r'\s+\{(\w+)\}\s+([\d.]+):\d+\s+->\s+([\d.]+):\d+'
)

@app.route("/api/ids/start", methods=["POST"])
def api_ids_start():
    if ids_state["running"]:
        return jsonify({"error": "Suricata ya está corriendo"}), 400
    data  = request.json or {}
    iface = data.get("iface", "eth0").strip()
    if not re.match(r'^[a-zA-Z0-9_.\-]+$', iface):
        return jsonify({"error": "Interfaz inválida"}), 400
    ids_state["alerts"] = []
    ids_state["stats"]  = {"buckets": [], "top_sig": {}, "top_src": {}, "severity": {1:0,2:0,3:0}}
    ids_state["running"] = True

    def run():
        try:
            # Clear old fast.log
            subprocess.run("sudo truncate -s 0 /var/log/suricata/fast.log", shell=True)
            # Start suricata
            proc = subprocess.Popen(
                ["sudo", "suricata", "-c", "/etc/suricata/suricata.yaml",
                 "-i", iface, "--runmode=autofp", "-D"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            proc.wait()
            ids_state["proc"] = True  # suricata runs as daemon
            ids_state["alerts"].append({"t": time.strftime("%H:%M:%S"), "msg": f"[IDS] Suricata iniciado en {iface}", "sev": 0, "src": "", "dst": "", "proto": "", "cat": ""})
            # Tail fast.log for alerts
            tail = subprocess.Popen(
                ["sudo", "tail", "-F", "/var/log/suricata/fast.log"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1
            )
            ids_state["tail"] = tail
            for line in tail.stdout:
                if not ids_state["running"]:
                    break
                line = line.rstrip()
                if not line:
                    continue
                m = _ids_re.search(line)
                if m:
                    ts_raw, sig, cat, prio, proto, src, dst = m.groups()
                    prio = int(prio)
                    ts_short = ts_raw.split("-")[1] if "-" in ts_raw else ts_raw
                    alert = {"t": ts_short, "msg": sig.strip(), "sev": prio,
                             "src": src, "dst": dst, "proto": proto, "cat": cat or "Sin clasificar"}
                    ids_state["alerts"].append(alert)
                    # Keep max 2000 alerts
                    if len(ids_state["alerts"]) > 2000:
                        ids_state["alerts"] = ids_state["alerts"][-1500:]
                    # Update rolling stats
                    now_s = int(time.time())
                    stats = ids_state["stats"]
                    buckets = stats["buckets"]
                    cutoff = now_s - _IDS_WINDOW
                    while buckets and buckets[0]["t"] < cutoff:
                        old = buckets.pop(0)
                        for s, n in old.get("sigs", {}).items():
                            stats["top_sig"][s] = max(0, stats["top_sig"].get(s, 0) - n)
                        for s, n in old.get("srcs", {}).items():
                            stats["top_src"][s] = max(0, stats["top_src"].get(s, 0) - n)
                        for s, n in old.get("sevs", {}).items():
                            stats["severity"][s] = max(0, stats["severity"].get(s, 0) - n)
                    if not buckets or buckets[-1]["t"] != now_s:
                        buckets.append({"t": now_s, "count": 0, "sigs": {}, "srcs": {}, "sevs": {}})
                    b = buckets[-1]
                    b["count"] += 1
                    b["sigs"][sig.strip()[:60]] = b["sigs"].get(sig.strip()[:60], 0) + 1
                    b["srcs"][src]              = b["srcs"].get(src, 0) + 1
                    b["sevs"][prio]             = b["sevs"].get(prio, 0) + 1
                    stats["top_sig"][sig.strip()[:60]] = stats["top_sig"].get(sig.strip()[:60], 0) + 1
                    stats["top_src"][src]              = stats["top_src"].get(src, 0) + 1
                    stats["severity"][prio]            = stats["severity"].get(prio, 0) + 1
                else:
                    ids_state["alerts"].append({"t": time.strftime("%H:%M:%S"), "msg": line[:200], "sev": 0, "src": "", "dst": "", "proto": "", "cat": ""})
        except Exception as e:
            ids_state["alerts"].append({"t": time.strftime("%H:%M:%S"), "msg": f"[ERROR] {e}", "sev": 0, "src":"","dst":"","proto":"","cat":""})
        finally:
            ids_state["running"] = False

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"ok": True})

@app.route("/api/ids/stop", methods=["POST"])
def api_ids_stop():
    ids_state["running"] = False
    if ids_state.get("tail"):
        try: ids_state["tail"].terminate()
        except: pass
    subprocess.run("sudo killall suricata 2>/dev/null", shell=True)
    ids_state["alerts"].append({"t": time.strftime("%H:%M:%S"), "msg": "[IDS] Suricata detenido", "sev": 0, "src":"","dst":"","proto":"","cat":""})
    return jsonify({"ok": True})

@app.route("/api/ids/alerts")
def api_ids_alerts():
    since = int(request.args.get("since", 0))
    alerts = ids_state["alerts"][since:]
    return jsonify({"alerts": alerts, "total": len(ids_state["alerts"]), "running": ids_state["running"]})

@app.route("/api/ids/stats")
def api_ids_stats():
    stats = ids_state["stats"]
    buckets = stats["buckets"]
    now_s = int(time.time())
    labels, counts = [], []
    bmap = {b["t"]: b for b in buckets}
    start = max(now_s - 299, buckets[0]["t"] if buckets else now_s)
    for s in range(start, now_s + 1):
        labels.append(str(s))
        counts.append(bmap.get(s, {}).get("count", 0))
    top_sig  = sorted(stats["top_sig"].items(), key=lambda x: -x[1])[:10]
    top_src  = sorted(stats["top_src"].items(), key=lambda x: -x[1])[:10]
    sev = stats["severity"]
    return jsonify({
        "labels": labels, "counts": counts,
        "top_sig": top_sig, "top_src": top_src,
        "severity": {"high": sev.get(1,0), "medium": sev.get(2,0), "low": sev.get(3,0)},
        "total": sum(counts)
    })


# ── API: Clients ───────────────────────────────────────────────────────────────

@app.route("/api/clients", methods=["GET"])
def api_clients_get():
    return jsonify(load_clients())

@app.route("/api/clients", methods=["POST"])
def api_clients_save():
    data = request.form
    clients = load_clients()
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "Nombre requerido"}), 400
    vpn_file = request.files.get("vpn_config")
    vpn_path = clients.get(name, {}).get("vpn_path", "")
    if vpn_file and vpn_file.filename:
        ext = os.path.splitext(vpn_file.filename)[1]
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
        vpn_path = os.path.join(UPLOAD_DIR, f"{safe_name}{ext}")
        vpn_file.save(vpn_path)
    clients[name] = {
        "network":       data.get("network", "").strip(),
        "desc":          data.get("desc", "").strip(),
        "vpn_path":      vpn_path,
        "vpn_type":      data.get("vpn_type", "OpenVPN"),
        "vpn_user":      data.get("vpn_user", "").strip(),
        "vpn_pass":      data.get("vpn_pass", "").strip(),
        "nebula_ip":     data.get("nebula_ip", "").strip(),
        "nebula_groups": data.get("nebula_groups", "clients").strip(),
    }
    save_clients(clients)
    return jsonify({"ok": True})

@app.route("/api/clients/<name>", methods=["DELETE"])
def api_clients_delete(name):
    clients = load_clients()
    if name in clients:
        del clients[name]
        save_clients(clients)
    return jsonify({"ok": True})

# ── API: VPN ───────────────────────────────────────────────────────────────────

@app.route("/api/vpn/connect", methods=["POST"])
def api_vpn_connect():
    name = request.json.get("client", "")
    clients = load_clients()
    if name not in clients:
        return jsonify({"error": "Cliente no encontrado"}), 404
    threading.Thread(target=_vpn_connect_bg, args=(name, clients[name]), daemon=True).start()
    return jsonify({"ok": True, "msg": f"Conectando VPN para {name}..."})

def _vpn_connect_bg(name, c):
    vpn_type = c.get("vpn_type", "OpenVPN")
    vpn_path = c.get("vpn_path", "")
    vpn_user = c.get("vpn_user", "")
    vpn_pass = c.get("vpn_pass", "")
    if vpn_type == "OpenVPN":
        if vpn_user and vpn_pass:
            cred = "/tmp/vpn_creds.txt"
            with open(cred, "w") as f:
                f.write(f"{vpn_user}\n{vpn_pass}\n")
            cmd = ["sudo","openvpn","--config",vpn_path,"--auth-user-pass",cred,
                   "--daemon","--log","/tmp/openvpn_scanner.log"]
        else:
            cmd = ["sudo","openvpn","--config",vpn_path,"--daemon",
                   "--log","/tmp/openvpn_scanner.log"]
        subprocess.run(cmd, capture_output=True)
        iface = "tun0"
    elif vpn_type == "Nebula":
        # Nebula no tiene --daemon flag; lo lanzamos como proceso desacoplado
        config = vpn_path or f"{NEBULA_CONFIG_DIR}/config.yaml"
        import shlex
        subprocess.Popen(
            ["sudo", NEBULA_BIN, "-config", config],
            stdout=open("/tmp/nebula_scanner.log", "a"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        iface = "nebula0"
    else:
        cmd = ["sudo","wg-quick","up",vpn_path]
        subprocess.run(cmd, capture_output=True)
        iface = "wg0"
    for _ in range(20):
        time.sleep(2)
        r = subprocess.run(["ip","a","show",iface], capture_output=True, text=True)
        if "inet " in r.stdout:
            vpn_state.update({"active": True, "client": name, "iface": iface})
            return
    vpn_state["active"] = False

@app.route("/api/vpn/disconnect", methods=["POST"])
def api_vpn_disconnect():
    iface = vpn_state.get("iface", "")
    c = load_clients().get(vpn_state.get("client", ""), {})
    if iface == "tun0":
        subprocess.run(["sudo","pkill","openvpn"], capture_output=True)
    elif iface in ("nebula0", "nebula1") or c.get("vpn_type") == "Nebula":
        subprocess.run(["sudo","pkill","-f", NEBULA_BIN], capture_output=True)
    else:
        subprocess.run(["sudo","wg-quick","down", c.get("vpn_path","")], capture_output=True)
    vpn_state.update({"active": False, "client": "", "iface": ""})
    return jsonify({"ok": True})

VPN_IFACES = ["tailscale0", "tun0", "tun1", "wg0", "wg1", "nebula0", "nebula1", "ppp0", "nordlynx"]

def _detect_vpn_ifaces():
    """Devuelve lista de interfaces VPN activas con sus IPs."""
    found = []
    for iface in VPN_IFACES:
        r = subprocess.run(["ip","a","show", iface], capture_output=True, text=True)
        if r.returncode == 0 and "inet " in r.stdout:
            ip = next((l.strip() for l in r.stdout.splitlines() if "inet " in l), "")
            found.append({"iface": iface, "ip": ip})
    return found

@app.route("/api/vpn/autodetect", methods=["POST"])
def api_vpn_autodetect():
    """Detecta VPNs activas en el servidor y actualiza el estado global."""
    detected = _detect_vpn_ifaces()
    if detected:
        best = detected[0]   # Tailscale primero por orden en VPN_IFACES
        vpn_state["active"] = True
        vpn_state["iface"]  = best["iface"]
        if not vpn_state["client"]:
            vpn_state["client"] = best["iface"]   # nombre temporal
        return jsonify({"detected": True, "interfaces": detected, **vpn_state, "ip": best["ip"]})
    return jsonify({"detected": False, **vpn_state})

@app.route("/api/vpn/status")
def api_vpn_status():
    # Re-verificar si la interfaz sigue activa
    if vpn_state["active"] and vpn_state["iface"]:
        r = subprocess.run(["ip","a","show", vpn_state["iface"]], capture_output=True, text=True)
        if "inet " not in r.stdout:
            # Interfaz caída — intentar re-detectar automáticamente
            detected = _detect_vpn_ifaces()
            if detected:
                vpn_state["iface"] = detected[0]["iface"]
                if not vpn_state["client"]:
                    vpn_state["client"] = detected[0]["iface"]
            else:
                vpn_state["active"] = False
                vpn_state["iface"]  = ""
        ip = next((l.strip() for l in r.stdout.splitlines() if "inet " in l), "")
        return jsonify({**vpn_state, "ip": ip})
    # Si no hay estado activo, intentar detección automática silenciosa
    detected = _detect_vpn_ifaces()
    if detected:
        vpn_state["active"] = True
        vpn_state["iface"]  = detected[0]["iface"]
        if not vpn_state["client"]:
            vpn_state["client"] = detected[0]["iface"]
        return jsonify({**vpn_state, "ip": detected[0]["ip"], "autodetected": True})
    return jsonify(vpn_state)

# ── API: Nebula ────────────────────────────────────────────────────────────────

def _nebula_cert_info(cert_file: str) -> dict:
    """Devuelve metadatos de un certificado Nebula usando nebula-cert print."""
    info = {"name": os.path.basename(cert_file).replace(".crt", ""), "file": cert_file,
            "ip": "", "groups": [], "not_after": "", "is_ca": False}
    if not os.path.exists(NEBULA_CERT_BIN):
        return info
    r = subprocess.run(["sudo", NEBULA_CERT_BIN, "print", "-path", cert_file],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("ip:"):
            info["ip"] = line.split(":",1)[1].strip()
        elif line.startswith("groups:"):
            raw = line.split(":",1)[1].strip().strip("[]")
            info["groups"] = [g.strip() for g in raw.split(",") if g.strip()]
        elif line.startswith("not after:"):
            info["not_after"] = line.split(":",1)[1].strip()
        elif "is ca: true" in line.lower():
            info["is_ca"] = True
    return info

@app.route("/api/nebula/setup", methods=["POST"])
def api_nebula_setup():
    """Inicializa la PKI Nebula: descarga binario (si falta) y genera CA + cert del servidor."""
    data      = request.json or {}
    ca_name   = data.get("ca_name", "Datacom Security Nebula CA")
    server_ip = data.get("server_ip", "10.255.255.1/24")
    dur       = data.get("duration", "87600h")

    def generate():
        def send(msg, cls=""):
            yield f"data: {json.dumps({'msg': msg, 'cls': cls})}\n\n"

        yield from send("▶ Iniciando setup de Nebula PKI...")

        # ── 1. Verificar / instalar binario ──────────────────────────────────
        if not os.path.exists(NEBULA_CERT_BIN):
            yield from send("⬇ nebula-cert no encontrado. Descargando Nebula v1.9.5...", "warn")
            ver = "v1.9.5"
            url = f"https://github.com/slackhq/nebula/releases/download/{ver}/nebula-linux-amd64.tar.gz"
            dl = subprocess.run(
                ["sudo","bash","-c",
                 f"mkdir -p /opt/nebula && curl -fsSL '{url}' | tar -xz -C /opt/nebula && "
                 f"chmod +x /opt/nebula/nebula /opt/nebula/nebula-cert"],
                capture_output=True, text=True)
            if dl.returncode != 0:
                yield from send(f"✗ Error descargando Nebula: {dl.stderr}", "error")
                yield "data: {\"done\":true,\"error\":true}\n\n"
                return
            yield from send("✓ Nebula instalado en /opt/nebula/", "ok")
        else:
            yield from send(f"✓ nebula-cert encontrado: {NEBULA_CERT_BIN}", "ok")

        # ── 2. Generar CA ─────────────────────────────────────────────────────
        ca_crt = os.path.join(NEBULA_CERTS_DIR, "ca.crt")
        ca_key = os.path.join(NEBULA_CERTS_DIR, "ca.key")
        if os.path.exists(ca_crt):
            yield from send(f"✓ CA ya existe en {ca_crt} — omitiendo generación", "ok")
        else:
            yield from send(f"🔑 Generando CA: '{ca_name}'...")
            r = subprocess.run(
                ["sudo", NEBULA_CERT_BIN, "ca",
                 "-name", ca_name, "-duration", dur,
                 "-out-crt", ca_crt, "-out-key", ca_key],
                capture_output=True, text=True)
            if r.returncode != 0:
                yield from send(f"✗ Error generando CA: {r.stderr}", "error")
                yield "data: {\"done\":true,\"error\":true}\n\n"
                return
            # ca.crt = legible por todos (se distribuye a clientes); ca.key = solo root
            subprocess.run(["sudo","chmod","644", ca_crt], capture_output=True)
            subprocess.run(["sudo","chmod","600", ca_key], capture_output=True)
            subprocess.run(["sudo","chown","root:kali", ca_crt], capture_output=True)
            yield from send(f"✓ CA generada: {ca_crt}", "ok")

        # ── 3. Generar cert del servidor (lighthouse) ─────────────────────────
        srv_crt = os.path.join(NEBULA_CERTS_DIR, "kali-server.crt")
        srv_key = os.path.join(NEBULA_CERTS_DIR, "kali-server.key")
        if os.path.exists(srv_crt):
            yield from send(f"✓ Cert servidor ya existe en {srv_crt} — omitiendo", "ok")
        else:
            yield from send(f"🔑 Generando certificado del servidor ({server_ip})...")
            r = subprocess.run(
                ["sudo", NEBULA_CERT_BIN, "sign",
                 "-ca-crt", ca_crt, "-ca-key", ca_key,
                 "-name", "kali-lighthouse",
                 "-ip", server_ip, "-groups", "lighthouse,servers",
                 "-duration", dur,
                 "-out-crt", srv_crt, "-out-key", srv_key],
                capture_output=True, text=True)
            if r.returncode != 0:
                yield from send(f"✗ Error generando cert servidor: {r.stderr}", "error")
                yield "data: {\"done\":true,\"error\":true}\n\n"
                return
            subprocess.run(["sudo","chmod","644", srv_crt], capture_output=True)
            subprocess.run(["sudo","chmod","640", srv_key], capture_output=True)
            subprocess.run(["sudo","chown","root:kali", srv_crt, srv_key], capture_output=True)
            yield from send(f"✓ Cert servidor: {srv_crt}", "ok")

        yield from send("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        yield from send("✅ PKI Nebula lista. Ya puedes emitir certificados de cliente.", "ok")
        yield "data: {\"done\":true,\"error\":false}\n\n"

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/nebula/status")
def api_nebula_status():
    """Estado del proceso nebula y la interfaz nebula0."""
    proc = subprocess.run(["pgrep","-f", NEBULA_BIN], capture_output=True, text=True)
    running = proc.returncode == 0
    iface_r = subprocess.run(["ip","a","show","nebula0"], capture_output=True, text=True)
    iface_up = "inet " in iface_r.stdout
    ip = next((l.strip() for l in iface_r.stdout.splitlines() if "inet " in l), "")
    ca_ok = os.path.exists(os.path.join(NEBULA_CERTS_DIR, "ca.crt"))
    return jsonify({"running": running, "iface_up": iface_up, "ip": ip, "ca_ok": ca_ok,
                    "nebula_bin": os.path.exists(NEBULA_BIN)})

@app.route("/api/nebula/certs")
def api_nebula_certs():
    """Lista todos los certificados emitidos (excluye CA)."""
    certs = []
    for f in sorted(os.listdir(NEBULA_CERTS_DIR)):
        if f.endswith(".crt") and f != "ca.crt":
            info = _nebula_cert_info(os.path.join(NEBULA_CERTS_DIR, f))
            if not info["is_ca"]:
                certs.append(info)
    return jsonify(certs)

def _nebula_ca_not_after():
    """Devuelve la fecha de expiración de la CA Nebula como datetime UTC, o None."""
    import datetime as _dt
    ca_crt = os.path.join(NEBULA_CERTS_DIR, "ca.crt")
    if not os.path.exists(ca_crt):
        return None
    r = subprocess.run(["sudo", NEBULA_CERT_BIN, "print", "-path", ca_crt],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if "not after" in line.lower():
            raw = line.split(":", 1)[1].strip()
            try:
                return _dt.datetime.strptime(raw[:19], "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=_dt.timezone.utc)
            except ValueError:
                return None
    return None

@app.route("/api/nebula/generate", methods=["POST"])
def api_nebula_generate():
    """Emite un nuevo certificado Nebula para un nodo cliente."""
    import datetime as _dt
    data   = request.json or {}
    name   = re.sub(r"[^a-zA-Z0-9_-]", "_", data.get("name","").strip())
    nip    = data.get("nebula_ip","").strip()
    groups = data.get("groups","clients").strip()
    dur    = data.get("duration","8760h").strip()

    if not name or not nip:
        return jsonify({"error": "Nombre e IP Nebula son obligatorios"}), 400

    # Auto-completar máscara CIDR si el usuario no la incluyó
    if "/" not in nip:
        nip = nip + "/24"

    # Validar formato IP básico antes de llamar nebula-cert
    ip_re = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
    if not ip_re.match(nip):
        return jsonify({"error": f"IP inválida: '{nip}'. Formato esperado: 10.255.255.10/24"}), 400

    ca_crt = os.path.join(NEBULA_CERTS_DIR, "ca.crt")
    ca_key = os.path.join(NEBULA_CERTS_DIR, "ca.key")
    if not os.path.exists(ca_crt) or not os.path.exists(ca_key):
        return jsonify({"error": "CA no encontrada. Ve a la pestaña Nebula VPN → Inicializar CA."}), 400
    if not os.path.exists(NEBULA_CERT_BIN):
        return jsonify({"error": f"nebula-cert no encontrado en {NEBULA_CERT_BIN}"}), 400

    # Calcular duración máxima permitida (el cert debe expirar antes que la CA)
    warn_msg = None
    ca_exp = _nebula_ca_not_after()
    if ca_exp:
        now = _dt.datetime.now(_dt.timezone.utc)
        unit_secs = {"h": 3600, "m": 60, "s": 1}
        unit = dur[-1] if dur[-1] in unit_secs else "h"
        try:
            req_secs = int(dur[:-1]) * unit_secs.get(unit, 3600)
        except ValueError:
            req_secs = 8760 * 3600
        max_secs = int((ca_exp - now).total_seconds()) - 3600  # 1h de margen seguro
        if max_secs <= 0:
            return jsonify({"error": "La CA ya ha expirado. Genera una nueva CA desde 'Inicializar CA'."}), 400
        if req_secs >= max_secs:
            safe_h = max(1, max_secs // 3600)
            dur = f"{safe_h}h"
            ca_days = int(max_secs / 86400)
            warn_msg = f"Duración ajustada a {safe_h}h ({ca_days}d) — límite de expiración de la CA."

    out_crt = os.path.join(NEBULA_CERTS_DIR, f"{name}.crt")
    out_key = os.path.join(NEBULA_CERTS_DIR, f"{name}.key")
    cmd = ["sudo", NEBULA_CERT_BIN, "sign",
           "-ca-crt", ca_crt, "-ca-key", ca_key,
           "-name", name, "-ip", nip,
           "-groups", groups,
           "-duration", dur,
           "-out-crt", out_crt, "-out-key", out_key]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        # Extraer sólo la primera línea del error (evitar el dump del usage completo)
        err_msg = (r.stderr or r.stdout or "Error generando certificado").strip()
        first_line = err_msg.splitlines()[0] if err_msg else "Error desconocido"
        return jsonify({"error": first_line}), 500
    # Dar permisos de lectura al usuario kali sobre el nuevo par
    subprocess.run(["sudo","chmod","644", out_crt], capture_output=True)
    subprocess.run(["sudo","chmod","640", out_key], capture_output=True)
    subprocess.run(["sudo","chown","kali:kali", out_crt, out_key], capture_output=True)
    return jsonify({"ok": True, "crt": out_crt, "key": out_key,
                    "warn": warn_msg, "cert": _nebula_cert_info(out_crt)})

@app.route("/api/nebula/certs/<name>", methods=["DELETE"])
def api_nebula_cert_delete(name):
    """Elimina el par crt/key de un nodo."""
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
    for ext in (".crt", ".key"):
        path = os.path.join(NEBULA_CERTS_DIR, safe + ext)
        if os.path.exists(path):
            try:
                os.remove(path)
            except PermissionError:
                subprocess.run(["sudo","rm","-f", path], capture_output=True)
    return jsonify({"ok": True})

def _sudo_read(path: str) -> bytes | None:
    """Lee un archivo que puede requerir permisos de root usando sudo."""
    r = subprocess.run(["sudo", "cat", path], capture_output=True)
    if r.returncode == 0:
        return r.stdout
    return None

@app.route("/api/nebula/certs/<name>/download")
def api_nebula_cert_download(name):
    """Descarga un bundle ZIP con crt + key + CA + config.yaml del nodo."""
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
    crt  = os.path.join(NEBULA_CERTS_DIR, safe + ".crt")
    key  = os.path.join(NEBULA_CERTS_DIR, safe + ".key")
    ca   = os.path.join(NEBULA_CERTS_DIR, "ca.crt")
    if not os.path.exists(crt):
        return jsonify({"error": "Certificado no encontrado"}), 404
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        crt_data = _sudo_read(crt)
        if crt_data:
            z.writestr(f"{safe}.crt", crt_data)
        key_data = _sudo_read(key)
        if key_data:
            z.writestr(f"{safe}.key", key_data)
        ca_data = _sudo_read(ca)
        if ca_data:
            z.writestr("ca.crt", ca_data)
        z.writestr(f"{safe}_config.yaml", _nebula_client_config_yaml(safe))
    buf.seek(0)
    return send_file(buf, mimetype="application/zip",
                     as_attachment=True, download_name=f"nebula_{safe}.zip")

# ── Chisel tunnel state ───────────────────────────────────────────────────────
CHISEL_BIN      = "/usr/local/bin/chisel"
CHISEL_PORT     = 8888
CHISEL_SOCKS_PORT = 1080
chisel_proc: dict = {"proc": None, "pid": None, "clients": []}
chisel_scan_jobs: dict[str, dict] = {}

@app.route("/api/chisel/status")
def api_chisel_status():
    proc = chisel_proc.get("proc")
    running = proc is not None and proc.poll() is None
    clients = chisel_proc.get("clients", [])
    return jsonify({
        "running": running,
        "pid":     proc.pid if running else None,
        "port":    CHISEL_PORT,
        "socks_port": CHISEL_SOCKS_PORT,
        "clients": clients,
    })

@app.route("/api/chisel/start", methods=["POST"])
def api_chisel_start():
    proc = chisel_proc.get("proc")
    if proc and proc.poll() is None:
        return jsonify({"ok": True, "pid": proc.pid, "already": True})
    try:
        cmd = [CHISEL_BIN, "server", "--port", str(CHISEL_PORT),
               "--reverse", "--socks5"]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             start_new_session=True)
        chisel_proc["proc"] = p
        chisel_proc["clients"] = []
        return jsonify({"ok": True, "pid": p.pid})
    except FileNotFoundError:
        return jsonify({"error": f"chisel no encontrado en {CHISEL_BIN}. Instálalo primero."}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/chisel/stop", methods=["POST"])
def api_chisel_stop():
    proc = chisel_proc.get("proc")
    if proc and proc.poll() is None:
        proc.terminate()
        chisel_proc["proc"] = None
        return jsonify({"ok": True})
    return jsonify({"ok": True, "already_stopped": True})

@app.route("/api/chisel/scan", methods=["POST"])
def api_chisel_scan():
    """Lanza nmap a través de proxychains por el túnel SOCKS5 de chisel."""
    data   = request.json or {}
    target = data.get("target", "").strip()
    ports  = data.get("ports", "22,80,443,445,3389,8080,8443").strip()
    if not target:
        return jsonify({"error": "target requerido"}), 400
    job_id = str(uuid.uuid4())
    chisel_scan_jobs[job_id] = {"running": True, "lines": [], "error": None}

    def _run(jid, tgt, prt):
        try:
            cmd = ["proxychains", "-q", "nmap", "-sT", "-Pn", "-T4",
                   "--open", "-p", prt, tgt]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            chisel_scan_jobs[jid]["proc"] = proc
            for line in proc.stdout:
                chisel_scan_jobs[jid]["lines"].append(line.rstrip())
            proc.wait()
            if proc.returncode not in (0, 1):
                chisel_scan_jobs[jid]["error"] = f"nmap retornó código {proc.returncode}"
        except FileNotFoundError:
            chisel_scan_jobs[jid]["error"] = "proxychains o nmap no encontrado"
        except Exception as e:
            chisel_scan_jobs[jid]["error"] = str(e)
        finally:
            chisel_scan_jobs[jid]["running"] = False

    threading.Thread(target=_run, args=(job_id, target, ports), daemon=True).start()
    return jsonify({"job_id": job_id})

@app.route("/api/chisel/scan_results/<job_id>")
def api_chisel_scan_results(job_id):
    job = chisel_scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job no encontrado"}), 404
    return jsonify({
        "running": job["running"],
        "lines":   job["lines"][-500:],
        "error":   job["error"],
    })

@app.route("/api/chisel/scan_stop/<job_id>", methods=["POST"])
def api_chisel_scan_stop(job_id):
    job = chisel_scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job no encontrado"}), 404
    proc = job.get("proc")
    if proc and job["running"]:
        proc.terminate()
    job["running"] = False
    return jsonify({"ok": True})

@app.route("/api/chisel/log")
def api_chisel_log():
    try:
        out = subprocess.check_output(
            ["sudo", "cat", "/tmp/chisel.log"],
            stderr=subprocess.STDOUT, text=True, timeout=5
        )
    except Exception as e:
        out = str(e)
    return jsonify({"log": out})

# ── ffuf jobs state ────────────────────────────────────────────────────────────
ffuf_jobs: dict[str, dict] = {}

@app.route("/api/ffuf/start", methods=["POST"])
def api_ffuf_start():
    data = request.json or {}
    url      = data.get("url", "").strip()
    wordlist = data.get("wordlist", "/usr/share/wordlists/dirb/common.txt").strip()
    method   = data.get("method", "GET").strip().upper()
    threads  = min(int(data.get("threads", 40)), 200)
    timeout  = min(int(data.get("timeout", 10)), 60)
    ext      = data.get("extensions", "").strip()
    headers  = data.get("headers", "").strip()
    cookies  = data.get("cookies", "").strip()
    postdata = data.get("postdata", "").strip()
    fc       = data.get("fc", "").strip()
    fs       = data.get("fs", "").strip()
    fw       = data.get("fw", "").strip()
    fl       = data.get("fl", "").strip()
    mc       = data.get("mc", "").strip()
    mr       = data.get("mr", "").strip()
    auto_fp  = bool(data.get("auto_fp", True))

    # Validación básica
    if not url or "FUZZ" not in url:
        return jsonify({"error": "URL debe contener FUZZ como marcador"}), 400
    if not re.match(r'^https?://', url):
        return jsonify({"error": "URL debe comenzar con http:// o https://"}), 400
    if not os.path.exists(wordlist):
        return jsonify({"error": f"Wordlist no encontrada: {wordlist}"}), 400

    # Construir comando ffuf
    cmd = ["ffuf", "-u", url, "-w", wordlist,
           "-t", str(threads), "-timeout", str(timeout),
           "-noninteractive", "-json"]

    if method != "GET":
        cmd += ["-X", method]
    if ext:
        cmd += ["-e", "." + ext.replace(",", ",.").lstrip(".")]
    if headers:
        for h in headers.split(";"):
            h = h.strip()
            if h:
                cmd += ["-H", h]
    if cookies:
        cmd += ["-b", cookies]
    if postdata:
        cmd += ["-d", postdata]
    if fc:
        cmd += ["-fc", fc]
    if fs:
        cmd += ["-fs", fs]
    if fw:
        cmd += ["-fw", fw]
    if fl:
        cmd += ["-fl", fl]
    if mc:
        cmd += ["-mc", mc]
    if mr:
        cmd += ["-mr", mr]
    if auto_fp:
        cmd += ["-ac"]   # auto-calibration: detecta y filtra respuestas baseline (falsos positivos)

    job_id = str(uuid.uuid4())
    ffuf_jobs[job_id] = {
        "cmd": cmd, "running": True, "results": [],
        "raw_lines": [], "error": None, "progress": "", "proc": None
    }

    def _run(jid, cmd):
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
            ffuf_jobs[jid]["proc"] = proc
            for line in proc.stdout:
                line = line.rstrip()
                ffuf_jobs[jid]["raw_lines"].append(line)
                # ffuf con -json emite un JSON final al terminar; parsear línea a línea
                if line.startswith("{"):
                    try:
                        obj = json.loads(line)
                        # JSON final con clave "results"
                        if "results" in obj:
                            for r in obj["results"]:
                                ffuf_jobs[jid]["results"].append({
                                    "status":   r.get("status", 0),
                                    "url":      r.get("url", ""),
                                    "length":   r.get("length", 0),
                                    "words":    r.get("words", 0),
                                    "lines":    r.get("lines", 0),
                                    "duration": r.get("duration", 0),
                                })
                    except (json.JSONDecodeError, KeyError):
                        pass
                # Progreso: línea de estado que ffuf imprime al stderr redirigido
                if "req/sec" in line or "Progress:" in line:
                    ffuf_jobs[jid]["progress"] = line.strip()
            proc.wait()
            if proc.returncode not in (0, -15):
                ffuf_jobs[jid]["error"] = f"ffuf salió con código {proc.returncode}"
        except FileNotFoundError:
            ffuf_jobs[jid]["error"] = "ffuf no encontrado. Instala: sudo apt install ffuf"
        except Exception as e:
            ffuf_jobs[jid]["error"] = str(e)
        finally:
            ffuf_jobs[jid]["running"] = False

    t = threading.Thread(target=_run, args=(job_id, cmd), daemon=True)
    t.start()
    return jsonify({"job_id": job_id})

@app.route("/api/ffuf/stop/<job_id>", methods=["POST"])
def api_ffuf_stop(job_id):
    job = ffuf_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job no encontrado"}), 404
    proc = job.get("proc")
    if proc and job["running"]:
        proc.terminate()
    job["running"] = False
    return jsonify({"ok": True})

@app.route("/api/ffuf/results/<job_id>")
def api_ffuf_results(job_id):
    job = ffuf_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job no encontrado"}), 404
    return jsonify({
        "running":   job["running"],
        "results":   job["results"],
        "raw_lines": job["raw_lines"][-300:],   # últimas 300 líneas
        "error":     job["error"],
        "progress":  job["progress"],
    })

@app.route("/api/probe/install")
def api_probe_install():
    """Sirve el script de instalación de la sonda."""
    try:
        with open("/opt/scanner/probe-gateway.sh", "r") as f:
            return Response(f.read(), mimetype="text/x-shellscript")
    except:
        # Fallback si no está en /opt/scanner
        try:
            with open("probe-gateway.sh", "r") as f:
                return Response(f.read(), mimetype="text/x-shellscript")
        except:
            return "Script no encontrado en el servidor.", 404

@app.route("/api/probe/agent")
def api_probe_agent():
    """Sirve el script del agente de escaneo local."""
    for path in ["/opt/scanner/probe-agent.sh", "probe-agent.sh"]:
        try:
            with open(path, "r") as f:
                return Response(f.read(), mimetype="text/x-shellscript")
        except FileNotFoundError:
            continue
    return "probe-agent.sh no encontrado.", 404

@app.route("/api/probe/install.ps1")
def api_probe_install_ps1():
    """Sirve el script de instalación de la sonda para Windows (PowerShell)."""
    try:
        with open("/opt/scanner/probe-gateway.ps1", "r") as f:
            return Response(f.read(), mimetype="text/plain")
    except:
        try:
            with open("probe-gateway.ps1", "r") as f:
                return Response(f.read(), mimetype="text/plain")
        except:
            return "Script PowerShell no encontrado.", 404

# ── Probe (Sonda) API ──────────────────────────────────────────────────────────

@app.route("/api/probe/register", methods=["POST"])
def api_probe_register():
    """Probe se registra con el servidor indicando nombre y subnets disponibles."""
    data = request.json or {}
    nebula_ip = data.get("nebula_ip", "").strip()
    name = data.get("name", "").strip() or nebula_ip
    subnets = data.get("subnets", [])
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', nebula_ip):
        return jsonify({"error": "nebula_ip inválida"}), 400
    registered_probes[nebula_ip] = {
        "name": name, "nebula_ip": nebula_ip, "subnets": subnets,
        "last_seen": now_str(), "status": "online",
    }
    return jsonify({"ok": True, "probe": registered_probes[nebula_ip]})

@app.route("/api/probe/list")
def api_probe_list():
    """Lista todas las sondas registradas."""
    return jsonify({"probes": list(registered_probes.values())})

@app.route("/api/probe/scan-results", methods=["POST"])
def api_probe_scan_results():
    """Probe envía sus resultados de escaneo local (arp-scan, nbtscan, nmap)."""
    data = request.json or {}
    nebula_ip = data.get("nebula_ip", "").strip()
    hosts = data.get("hosts", [])
    subnet = data.get("subnet", "").strip()
    if not nebula_ip:
        return jsonify({"error": "nebula_ip requerida"}), 400
    # Update probe last_seen
    if nebula_ip in registered_probes:
        registered_probes[nebula_ip]["last_seen"] = now_str()
    probe_scan_results[nebula_ip] = {
        "hosts": hosts, "subnet": subnet,
        "timestamp": now_str(), "status": "done",
        "probe_name": registered_probes.get(nebula_ip, {}).get("name", nebula_ip),
    }
    return jsonify({"ok": True, "received": len(hosts)})

@app.route("/api/probe/scan-results/<nebula_ip>")
def api_probe_get_results(nebula_ip):
    """Obtiene los resultados de escaneo de una sonda específica."""
    r = probe_scan_results.get(nebula_ip)
    if not r:
        return jsonify({"error": "Sin resultados para esta sonda"}), 404
    return jsonify(r)

@app.route("/api/probe/all-results")
def api_probe_all_results():
    """Combina resultados de todas las sondas en una tabla unificada."""
    all_hosts = []
    for pip, res in probe_scan_results.items():
        for h in res.get("hosts", []):
            h["probe"] = res.get("probe_name", pip)
            h["probe_ip"] = pip
            all_hosts.append(h)
    return jsonify({"hosts": all_hosts, "probe_count": len(probe_scan_results)})

@app.route("/api/network/probe-scan", methods=["POST"])
def api_network_probe_scan():
    """Inicia escaneo de red usando la sonda local en vez de escaneo remoto.
    Si hay una sonda registrada para el subnet solicitado, usa sus resultados.
    Si no hay sonda, hace fallback al escaneo nmap remoto normal."""
    data = request.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "target requerido"}), 400
    if not re.match(r'^[\w./:@\-]+$', target):
        return jsonify({"error": "target inválido"}), 400
    # Check if any probe covers this subnet
    probe_ip = None
    for pip, p in registered_probes.items():
        for s in p.get("subnets", []):
            if _subnet_contains(s, target) or s == target:
                probe_ip = pip
                break
        if probe_ip:
            break
    map_id = str(uuid.uuid4())[:8]
    network_maps[map_id] = {
        "done": False, "status": "Iniciando...",
        "nodes": [], "edges": [], "target": target,
        "mode": "probe" if probe_ip else "remote",
    }
    if probe_ip and probe_ip in probe_scan_results:
        # Use cached probe results directly
        threading.Thread(
            target=_build_map_from_probe, args=(map_id, probe_ip, target),
            daemon=True
        ).start()
    else:
        # Fallback: remote nmap scan
        threading.Thread(target=_run_network_map, args=(map_id, target), daemon=True).start()
    return jsonify({"map_id": map_id, "mode": "probe" if probe_ip else "remote"})

def _subnet_contains(subnet_cidr: str, target: str) -> bool:
    """Verifica si un target IP/CIDR está dentro de un subnet."""
    try:
        net = ipaddress.ip_network(subnet_cidr, strict=False)
        # target could be a single IP or CIDR
        if '/' in target:
            tgt = ipaddress.ip_network(target, strict=False)
            return tgt.subnet_of(net) or tgt == net
        else:
            return ipaddress.ip_address(target) in net
    except:
        return False

def _build_map_from_probe(map_id: str, probe_ip: str, target: str):
    """Construye el mapa de red a partir de resultados de la sonda."""
    state = network_maps[map_id]
    try:
        state["status"] = f"Usando datos de sonda {probe_ip}..."
        res = probe_scan_results.get(probe_ip, {})
        hosts = []
        for h in res.get("hosts", []):
            node = {
                "ip": h.get("ip", ""),
                "hostname": h.get("hostname", ""),
                "mac": h.get("mac", ""),
                "vendor": h.get("vendor", ""),
                "ports": h.get("ports", []),
                "status": h.get("status", "up"),
            }
            node["type"] = _classify_node(node)
            hosts.append(node)
        # Classify and build edges
        gateways = [h["ip"] for h in hosts if h["type"] == "gateway"]
        if not gateways and hosts:
            hosts[0]["type"] = "gateway"
            gateways = [hosts[0]["ip"]]
        edges = []
        if gateways:
            for h in hosts:
                if h["ip"] not in gateways:
                    edges.append({"source": gateways[0], "target": h["ip"]})
        for i in range(len(gateways) - 1):
            edges.append({"source": gateways[i], "target": gateways[i + 1]})
        state["nodes"] = hosts
        state["edges"] = edges
        state["status"] = "done"
        state["summary"] = f"{len(hosts)} hosts (vía sonda {probe_ip})"
    except Exception as e:
        state["status"] = f"error: {e}"
    finally:
        state["done"] = True


@app.route("/api/nebula/announce", methods=["POST"])
def api_nebula_announce():
    """Nodo cliente anuncia sus subnets locales; agrega unsafe_routes a Nebula y rutas Linux."""
    data      = request.json or {}
    nebula_ip = data.get("nebula_ip", "").strip()
    subnets   = data.get("subnets", [])
    name      = data.get("name", "").strip() or nebula_ip
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', nebula_ip):
        return jsonify({"error": "nebula_ip inválida"}), 400
    if not nebula_ip.startswith("10.255.255."):
        return jsonify({"error": "IP fuera del rango Nebula"}), 403
    # Also register as probe
    valid_subnets = []
    for subnet in subnets[:15]:
        subnet = subnet.strip()
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$', subnet):
            continue
        if subnet.startswith("10.255.255.") or subnet.startswith("127."):
            continue
        valid_subnets.append(subnet)
    registered_probes[nebula_ip] = {
        "name": name, "nebula_ip": nebula_ip, "subnets": valid_subnets,
        "last_seen": now_str(), "status": "online",
    }
    added, errors = [], []
    # 1. Add Linux kernel routes
    for subnet in valid_subnets:
        r = subprocess.run(
            ["sudo", "ip", "route", "replace", subnet, "via", nebula_ip, "dev", "nebula0"],
            capture_output=True, text=True)
        if r.returncode == 0:
            added.append(subnet)
        else:
            r2 = subprocess.run(
                ["sudo", "ip", "route", "replace", subnet, "dev", "nebula0"],
                capture_output=True, text=True)
            if r2.returncode == 0:
                added.append(subnet)
            else:
                errors.append(f"{subnet}: {r.stderr.strip()}")
    # 2. Update Nebula config with unsafe_routes for these subnets
    _update_nebula_unsafe_routes(nebula_ip, valid_subnets)
    return jsonify({"ok": True, "added": added, "errors": errors, "probe_registered": True})


def _update_nebula_unsafe_routes(via_ip: str, subnets: list):
    """Agrega unsafe_routes al config.yaml de Nebula del servidor y reinicia."""
    try:
        import yaml
    except ImportError:
        print("[!] PyYAML not installed, using fallback for unsafe_routes")
        _update_nebula_unsafe_routes_fallback(via_ip, subnets)
        return
    config_path = "/etc/nebula/config.yaml"
    try:
        raw = subprocess.run(["sudo", "cat", config_path],
                             capture_output=True, text=True).stdout
        if not raw:
            return
        cfg = yaml.safe_load(raw) or {}
        tun = cfg.setdefault("tun", {})
        existing = tun.get("unsafe_routes", [])
        # Merge new routes without duplicates
        existing_set = {(r.get("route"), r.get("via")) for r in existing}
        for subnet in subnets:
            if (subnet, via_ip) not in existing_set:
                existing.append({"route": subnet, "via": via_ip, "mtu": 1300})
        tun["unsafe_routes"] = existing
        # Write back
        new_yaml = yaml.dump(cfg, default_flow_style=False, sort_keys=False)
        tmp = f"/tmp/nebula_config_{uuid.uuid4().hex[:8]}.yaml"
        with open(tmp, "w") as f:
            f.write(new_yaml)
        subprocess.run(["sudo", "cp", tmp, config_path], check=True)
        subprocess.run(["sudo", "chmod", "600", config_path])
        os.unlink(tmp)
        # Restart Nebula to apply
        subprocess.run(["sudo", "systemctl", "restart", "nebula"], capture_output=True)
    except Exception as e:
        print(f"[!] Error updating Nebula unsafe_routes: {e}")


def _update_nebula_unsafe_routes_fallback(via_ip: str, subnets: list):
    """Fallback sin PyYAML: append unsafe_routes al final del config."""
    config_path = "/etc/nebula/config.yaml"
    try:
        raw = subprocess.run(["sudo", "cat", config_path],
                             capture_output=True, text=True).stdout
        if not raw:
            return
        lines_to_add = []
        for subnet in subnets:
            marker = f"route: {subnet}"
            if marker in raw:
                continue
            lines_to_add.append(f'    - route: {subnet}\n      via: {via_ip}\n      mtu: 1300')
        if not lines_to_add:
            return
        if "unsafe_routes:" not in raw:
            raw += "\ntun:\n  unsafe_routes:\n"
        insertion = "\n".join(lines_to_add) + "\n"
        # Append after unsafe_routes:
        raw = raw.replace("unsafe_routes:", "unsafe_routes:\n" + insertion, 1)
        tmp = f"/tmp/nebula_config_{uuid.uuid4().hex[:8]}.yaml"
        with open(tmp, "w") as f:
            f.write(raw)
        subprocess.run(["sudo", "cp", tmp, config_path], check=True)
        subprocess.run(["sudo", "chmod", "600", config_path])
        os.unlink(tmp)
        subprocess.run(["sudo", "systemctl", "restart", "nebula"], capture_output=True)
    except Exception as e:
        print(f"[!] Fallback unsafe_routes error: {e}")


@app.route("/api/nebula/config/<name>")
def api_nebula_config(name):
    """Devuelve la config YAML de cliente como texto plano."""
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
    return app.response_class(_nebula_client_config_yaml(safe),
                               mimetype="text/plain")

def _nebula_client_config_yaml(name: str) -> str:
    """Genera una config YAML Nebula mínima para un nodo cliente."""
    server_ip = "3.143.18.161"
    return f"""# Nebula config — nodo: {name}
# Generado por Kali VPN Vulnerability Scanner

pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/{name}.crt
  key: /etc/nebula/{name}.key

static_host_map:
  "10.255.255.1": ["{server_ip}:4242"]

lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "10.255.255.1"

listen:
  host: 0.0.0.0
  port: 0

punchy:
  punch: true
  respond: true
  delay: 1s

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
      host: any

# ── Exponer tu red local al servidor Kali ─────────────────────────────────────
# Ejecuta el script incluido en el bundle para registrar tus subnets automáticamente:
#   Linux/macOS : sudo bash announce.sh
#   Windows     : PowerShell (como Admin) > .\\announce.ps1
# Esto habilita el reenvío IP en tu máquina y notifica al servidor Kali
# para que pueda escanear tu red local sin configuración adicional.
"""

@app.route("/api/ping", methods=["POST"])
def api_ping():
    data   = request.json or {}
    host   = data.get("host", "").strip()
    count  = min(int(data.get("count", 4)), 10)
    if not host:
        return jsonify({"error": "Host requerido"}), 400
    # Basic validation — allow IPs and hostnames only
    if not re.match(r'^[a-zA-Z0-9._\-]+$', host):
        return jsonify({"error": "Host inválido"}), 400

    def generate():
        yield f"data: {json.dumps({'line': f'PING {host} — {count} paquetes', 'type': 'header'})}\n\n"
        try:
            proc = subprocess.Popen(
                ["stdbuf", "-oL", "ping", "-c", str(count), "-W", "2", host],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            for line in proc.stdout:
                line = strip_ansi(line).rstrip()
                if line:
                    t = "success" if ("bytes from" in line or "ttl=" in line.lower()) \
                        else "error" if ("unreachable" in line or "100%" in line) \
                        else "info"
                    yield f"data: {json.dumps({'line': line, 'type': t})}\n\n"
            proc.wait()
            status = "HOST ALCANZABLE ✓" if proc.returncode == 0 else "HOST NO RESPONDE ✗"
            t = "success" if proc.returncode == 0 else "error"
            yield f"data: {json.dumps({'line': f'--- {status} ---', 'type': t, 'done': True})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'line': f'Error: {e}', 'type': 'error', 'done': True})}\n\n"

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── API: Scan ──────────────────────────────────────────────────────────────────

@app.route("/api/scan/profiles")
def api_profiles():
    return jsonify(SCAN_PROFILES)

@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    data     = request.json
    target   = data.get("target",   "").strip()
    cmd_tpl  = data.get("command",  "").strip()
    client   = data.get("client",   "")
    profile  = data.get("profile",  "")
    engineer = data.get("engineer", "").strip() or "Sin especificar"

    if not target or not cmd_tpl:
        return jsonify({"error": "target y command son requeridos"}), 400

    cmd     = cmd_tpl.replace("{target}", target)
    # Force line-buffered output from nmap (avoids pipe buffering)
    # and inject --stats-every for periodic ETA updates
    if re.search(r'\bnmap\b', cmd):
        if "stdbuf" not in cmd:
            cmd = "stdbuf -oL " + cmd
        if "--stats-every" not in cmd:
            cmd = cmd.rstrip() + " --stats-every 8s"
    scan_id = str(uuid.uuid4())[:8]
    start   = now_str()

    header = (
        f"{'═'*68}\n"
        f"[{start}] ESCANEO INICIADO\n"
        f"  ID         : {scan_id}\n"
        f"  Ingeniero  : {engineer}\n"
        f"  Cliente    : {client or 'N/A'}\n"
        f"  Objetivo   : {target}\n"
        f"  Perfil     : {profile}\n"
        f"  Comando    : {cmd}\n"
        f"  VPN        : {'Activa ('+vpn_state['client']+')' if vpn_state['active'] else 'Inactiva'}\n"
        f"{'═'*68}\n"
    )

    active_scans[scan_id] = {
        "id":         scan_id,
        "proc":       None,
        "lines":      [header],
        "done":       False,
        "client":     client,
        "target":     target,
        "profile":    profile,
        "command":    cmd,
        "start":      start,
        "end":        None,
        "engineer":   engineer,
        "vpn_client": vpn_state["client"] if vpn_state["active"] else "No",
        # Live counters
        "devices":    [],   # list of discovered host strings
        "eta":        None, # "0:01:30" string from nmap stats
        "percent":    0.0,  # 0-100 float
    }

    threading.Thread(target=_run_scan_bg, args=(scan_id, cmd), daemon=True).start()
    return jsonify({"scan_id": scan_id})

def _run_scan_bg(scan_id, cmd):
    state = active_scans[scan_id]
    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        state["proc"] = proc
        _re_device = re.compile(
            r'Nmap scan report for (.+)|'       # nmap host header
            r'\+ Target IP:\s*(\S+)|'           # nikto
            r'Host:\s*(\S+)\s*\(\)'             # nmap -oG style
        )
        _re_nmap_done = re.compile(
            r'Nmap done.*?(\d+) hosts? up'
        )
        _re_stats = re.compile(
            r'About\s+([\d.]+)%\s+done.*?ETA:\s*([\d:]+)',
            re.IGNORECASE
        )
        for raw in proc.stdout:
            line = strip_ansi(raw)
            state["lines"].append(line)
            stripped = line.strip()
            # Device discovery
            m = _re_device.search(stripped)
            if m:
                host = next((g for g in m.groups() if g), None)
                if host and host not in state["devices"]:
                    state["devices"].append(host.strip())
            # nmap done line — final host count
            m2 = _re_nmap_done.search(stripped)
            if m2:
                # Ensure we at least have that many entries marked
                pass
            # nmap stats line — ETA + percent
            m3 = _re_stats.search(stripped)
            if m3:
                state["percent"] = float(m3.group(1))
                state["eta"]     = m3.group(2)
        proc.wait()
        state["end"] = now_str()
        state["lines"].append(
            f"\n{'═'*68}\n[{state['end']}] ESCANEO COMPLETADO\n{'═'*68}\n"
        )
        path = os.path.join(SCANS_DIR,
               f"scan_{re.sub(r'[^a-zA-Z0-9._-]','_',state['target'])}_{scan_id}.txt")
        with open(path, "w") as f:
            f.writelines(state["lines"])
        state["report_path"] = path
    except Exception as e:
        state["lines"].append(f"\n[ERROR] {e}\n")
        state["end"] = now_str()
    finally:
        state["done"] = True

@app.route("/api/scan/stop/<scan_id>", methods=["POST"])
def api_scan_stop(scan_id):
    s = active_scans.get(scan_id)
    if s and s["proc"]:
        s["proc"].terminate()
        s["done"] = True
        s["end"] = now_str()
    return jsonify({"ok": True})

@app.route("/api/scan/stream/<scan_id>")
def api_scan_stream(scan_id):
    def generate():
        idx = 0
        while True:
            s = active_scans.get(scan_id)
            if not s:
                yield f"data: [scan_id inválido]\n\n"
                break
            while idx < len(s["lines"]):
                line = s["lines"][idx].rstrip("\n")
                sev  = detect_severity(line)
                payload = {
                    "line":    line,
                    "sev":     sev,
                    "devices": len(s["devices"]),
                    "eta":     s["eta"],
                    "percent": s["percent"],
                }
                yield f"data: {json.dumps(payload)}\n\n"
                idx += 1
            if s["done"] and idx >= len(s["lines"]):
                yield f"data: {json.dumps({'done': True, 'devices': len(s['devices']), 'device_list': s['devices']})}\n\n"
                break
            time.sleep(0.08)
    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/scan/list")
def api_scan_list():
    out = [{"id": sid, "client": s["client"], "target": s["target"],
            "profile": s["profile"], "start": s["start"],
            "engineer": s.get("engineer",""), "done": s["done"]}
           for sid, s in active_scans.items()]
    return jsonify(out[::-1])

@app.route("/api/scan/export/<scan_id>")
def api_scan_export(scan_id):
    fmt = request.args.get("fmt", "pdf")
    s   = active_scans.get(scan_id)
    if not s:
        return "Not found", 404

    safe  = re.sub(r"[^a-zA-Z0-9._-]", "_", s["target"])
    fname = f"informe_{safe}_{scan_id}.{fmt}"

    if fmt == "pdf":
        pdf_bytes = generate_pdf_report(s)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=fname
        )
    elif fmt == "txt":
        content = "".join(s["lines"])
        return Response(content, mimetype="text/plain",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})
    elif fmt == "json":
        d = {k: s[k] for k in ("id","client","target","profile","command","start","end","engineer")}
        d["lines"] = s["lines"]
        return Response(json.dumps(d, indent=2, ensure_ascii=False),
                        mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})
    elif fmt == "html":
        rows = ""
        for line in s["lines"]:
            sev   = detect_severity(line)
            color = SEV_COLORS.get(sev, "#c9d1d9")
            esc   = line.replace("&","&amp;").replace("<","&lt;")
            rows += f'<tr style="color:{color}"><td class="sev">{sev}</td><td><code>{esc}</code></td></tr>\n'
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Informe — {s['target']}</title>
<style>body{{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:24px}}
h1{{color:#58a6ff}} .meta{{color:#8b949e;margin-bottom:16px;font-size:.9rem}}
table{{width:100%;border-collapse:collapse}}
td{{padding:3px 8px;border-bottom:1px solid #21262d;vertical-align:top}}
.sev{{width:80px;font-weight:bold}}</style></head><body>
<h1>Informe de Vulnerabilidades</h1>
<div class="meta">
  <b>Ingeniero:</b> {s.get('engineer','N/A')} &nbsp;|&nbsp;
  <b>Cliente:</b> {s['client']} &nbsp;|&nbsp;
  <b>Objetivo:</b> {s['target']}<br>
  <b>Perfil:</b> {s['profile']} &nbsp;|&nbsp; <b>Inicio:</b> {s['start']}
</div>
<table>{rows}</table></body></html>"""
        return Response(html, mimetype="text/html",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})
    elif fmt == "exec":
        html_content = generate_executive_html_report(s)
        safe_fname   = f"reporte_ejecutivo_{re.sub(r'[^a-zA-Z0-9._-]','_',s['client'] or 'cliente')}_{scan_id}.html"
        return Response(html_content, mimetype="text/html",
                        headers={"Content-Disposition": f"attachment; filename={safe_fname}"})
    return "fmt inválido", 400

# ── Main page ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

# ══════════════════════════════════════════════════════════════════════════════
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Kali VPN Vulnerability Scanner</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bg4:#30363d;
  --fg:#c9d1d9;--dim:#8b949e;
  --blue:#58a6ff;--green:#3fb950;--red:#f85149;
  --yellow:#e3b341;--orange:#f0883e;
  --c-crit:#ff4444;--c-high:#ff8800;--c-med:#ffcc00;--c-low:#44aaff;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font-family:'Segoe UI',system-ui,sans-serif;
     font-size:14px;height:100vh;display:flex;flex-direction:column;overflow:hidden}
header{background:var(--bg2);border-bottom:1px solid var(--bg4);
       padding:10px 20px;display:flex;align-items:center;gap:14px;flex-shrink:0}
header h1{font-size:1.2rem;color:var(--blue);font-weight:700}
header span{color:var(--dim);font-size:.82rem}
.badge-vpn{padding:3px 12px;border-radius:20px;font-size:.78rem;font-weight:700;
           background:var(--bg4);cursor:pointer;transition:.2s}
.badge-vpn.on{background:#1a3a1a;color:var(--green)}
.badge-vpn.off{background:#3a1a1a;color:var(--red)}
.layout{display:flex;flex:1;overflow:hidden}
.sidebar{width:270px;background:var(--bg2);border-right:1px solid var(--bg4);
         display:flex;flex-direction:column;flex-shrink:0;overflow:hidden}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.tabs{display:flex;border-bottom:1px solid var(--bg4);flex-shrink:0}
.tab{padding:10px 22px;cursor:pointer;color:var(--dim);border-bottom:2px solid transparent;
     transition:.15s;font-weight:600;font-size:.88rem}
.tab.active{color:var(--blue);border-bottom-color:var(--blue)}
.tab-content{display:none;flex:1;overflow:hidden}
.tab-content.active{display:flex;flex-direction:column;overflow:hidden}
.sidebar-header{padding:10px 12px;font-size:.78rem;color:var(--dim);font-weight:700;
                border-bottom:1px solid var(--bg4);display:flex;
                justify-content:space-between;align-items:center}
.client-list{flex:1;overflow-y:auto}
.client-item{padding:9px 14px;cursor:pointer;border-bottom:1px solid var(--bg4);
             transition:.15s;display:flex;justify-content:space-between;align-items:center}
.client-item:hover{background:var(--bg3)}
.client-item.active{background:var(--bg3);border-left:3px solid var(--blue)}
.client-name{font-weight:600;font-size:.88rem}
.client-net{font-size:.73rem;color:var(--dim)}
.client-del{color:var(--red);opacity:0;background:none;border:none;cursor:pointer;padding:2px 6px;font-size:.8rem}
.client-item:hover .client-del{opacity:1}
.form-group{display:flex;flex-direction:column;gap:4px;margin-bottom:10px}
label{font-size:.77rem;color:var(--dim);font-weight:600}
input,select,textarea{background:var(--bg3);border:1px solid var(--bg4);
       color:var(--fg);padding:7px 10px;border-radius:6px;font-size:.88rem;
       outline:none;width:100%;transition:.15s;font-family:inherit}
input:focus,select:focus{border-color:var(--blue)}
select option{background:var(--bg3)}
.row{display:flex;gap:8px}
.row .form-group{flex:1}
.btn{display:inline-flex;align-items:center;gap:6px;padding:7px 16px;
     border-radius:6px;border:none;cursor:pointer;font-size:.88rem;
     font-weight:600;transition:opacity .15s;font-family:inherit}
.btn:hover{opacity:.85}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn-blue{background:#1f6feb;color:#fff}
.btn-green{background:#238636;color:#fff}
.btn-red{background:#da3633;color:#fff}
.btn-orange{background:#9a5700;color:#fff}
.btn-gray{background:var(--bg4);color:var(--fg)}
.btn-pdf{background:#7c3aed;color:#fff}
.btn-sm{padding:4px 10px;font-size:.78rem}
.scan-config{padding:12px 16px;border-bottom:1px solid var(--bg4);flex-shrink:0}
.toolbar{display:flex;gap:8px;padding:8px 16px;border-bottom:1px solid var(--bg4);
         flex-shrink:0;align-items:center;flex-wrap:wrap}
.progress-bar{height:3px;background:var(--bg4);flex-shrink:0}
.progress-inner{height:100%;background:var(--blue);width:0}
.progress-inner.running{animation:prog 1.5s infinite linear}
@keyframes prog{0%{width:0%;margin-left:0}50%{width:40%}100%{width:0%;margin-left:100%}}
.output-area{display:flex;flex:1;overflow:hidden}
.terminal{flex:1;background:#090d13;font-family:'Courier New',monospace;font-size:12px;
          padding:12px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;line-height:1.5}
.findings-panel{width:300px;border-left:1px solid var(--bg4);display:flex;flex-direction:column;flex-shrink:0}
.findings-header{padding:8px 12px;font-size:.78rem;color:var(--dim);font-weight:700;
                 border-bottom:1px solid var(--bg4);display:flex;justify-content:space-between;align-items:center}
.findings-list{flex:1;overflow-y:auto;padding:6px}
.finding-item{padding:5px 8px;border-radius:5px;margin-bottom:4px;font-size:.77rem;
              font-family:'Courier New',monospace;background:var(--bg3);border-left:3px solid}
.sev-CRITICAL{color:var(--c-crit);border-color:var(--c-crit)!important}
.sev-HIGH{color:var(--c-high);border-color:var(--c-high)!important}
.sev-MEDIUM{color:var(--c-med);border-color:var(--c-med)!important}
.sev-LOW{color:var(--c-low);border-color:var(--c-low)!important}
.line-CRITICAL{color:var(--c-crit);font-weight:700}
.line-HIGH{color:var(--c-high);font-weight:700}
.line-MEDIUM{color:var(--c-med)}
.line-LOW{color:var(--c-low)}
.line-INFO{color:var(--fg)}
.line-HEADER{color:var(--green);font-weight:700}
.history-table{width:100%;border-collapse:collapse}
.history-table th{background:var(--bg3);padding:8px 12px;text-align:left;
                   font-size:.78rem;color:var(--dim);border-bottom:1px solid var(--bg4)}
.history-table td{padding:7px 12px;border-bottom:1px solid var(--bg4);font-size:.83rem}
.history-table tr:hover td{background:var(--bg3)}
.badge{padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:700}
.badge-done{background:#1a3a1a;color:var(--green)}
.badge-run{background:#1a2a3a;color:var(--blue)}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:100;
               display:none;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--bg4);border-radius:10px;
       padding:24px;width:440px;max-width:95vw}
.modal h2{color:var(--blue);margin-bottom:16px;font-size:1rem}
.client-form{border-top:1px solid var(--bg4);padding:12px;flex-shrink:0;
             max-height:52vh;overflow-y:auto;background:var(--bg)}
.client-form h3{font-size:.78rem;color:var(--dim);font-weight:700;margin-bottom:10px;text-transform:uppercase}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--bg4);border-radius:3px}
.stats-bar{display:flex;align-items:center;gap:0;flex-shrink:0;
           background:var(--bg2);border-bottom:1px solid var(--bg4);overflow:hidden}
.stat-block{display:flex;flex-direction:column;align-items:center;justify-content:center;
            padding:6px 20px;border-right:1px solid var(--bg4);min-width:130px}
.stat-block:last-child{border-right:none}
.stat-label{font-size:.68rem;color:var(--dim);font-weight:700;text-transform:uppercase;
            letter-spacing:.06em;margin-bottom:2px}
.stat-value{font-size:1.2rem;font-weight:800;font-family:'Courier New',monospace;
            line-height:1;transition:color .3s}
.stat-value.devices{color:var(--blue)}
.stat-value.elapsed{color:var(--fg)}
.stat-value.eta{color:var(--green)}
.stat-value.eta.unknown{color:var(--dim)}
.stat-value.percent{color:var(--yellow)}
.stat-progress{flex:1;padding:0 16px;display:flex;flex-direction:column;
               justify-content:center;gap:4px}
.stat-progress-label{display:flex;justify-content:space-between;
                      font-size:.72rem;color:var(--dim);font-weight:600}
.stat-progress-track{height:6px;background:var(--bg4);border-radius:3px;overflow:hidden}
.stat-progress-fill{height:100%;background:linear-gradient(90deg,var(--blue),var(--green));
                    border-radius:3px;width:0%;transition:width .8s ease}
.stat-devices-list{flex:1;padding:0 14px;overflow:hidden}
.stat-devices-scroll{display:flex;gap:6px;overflow-x:auto;padding-bottom:2px}
.stat-devices-scroll::-webkit-scrollbar{height:3px}
.stat-devices-scroll::-webkit-scrollbar-thumb{background:var(--bg4)}
.device-chip{background:var(--bg3);border:1px solid var(--blue);color:var(--blue);
             border-radius:4px;padding:2px 8px;font-size:.72rem;white-space:nowrap;
             font-family:'Courier New',monospace;animation:chipIn .3s ease}
@keyframes chipIn{from{opacity:0;transform:scale(.8)}to{opacity:1;transform:scale(1)}}
.ping-bar{display:flex;flex-direction:column;gap:0;
          border-bottom:1px solid var(--bg4);flex-shrink:0;background:var(--bg2)}
.ping-controls{display:flex;align-items:center;gap:8px;padding:7px 16px;flex-wrap:wrap}
.ping-label{font-size:.78rem;font-weight:700;color:var(--green);white-space:nowrap}
.ping-controls input{max-width:220px;padding:5px 10px;font-size:.85rem;
                background:var(--bg3);border:1px solid var(--bg4);
                color:var(--fg);border-radius:6px;outline:none}
.ping-controls input:focus{border-color:var(--green)}
.ping-controls select{width:120px;padding:5px 8px;font-size:.83rem;
                 background:var(--bg3);border:1px solid var(--bg4);
                 color:var(--fg);border-radius:6px;outline:none}
.btn-ping{background:#1a5c2a;color:var(--green);border:1px solid var(--green);padding:5px 14px;font-size:.83rem}
.btn-ping:hover{background:var(--green);color:#000}
.btn-ping.running{background:#0d3318;color:var(--dim);border-color:var(--dim);cursor:not-allowed}
.ping-status{font-size:.78rem;font-family:'Courier New',monospace;display:flex;
             align-items:center;gap:6px;margin-left:4px}
.ping-console{background:#090d13;font-family:'Courier New',monospace;font-size:.8rem;
              padding:6px 16px;max-height:90px;overflow-y:auto;
              border-top:1px solid var(--bg4);display:none;line-height:1.6}
.ping-console.visible{display:block}
.ping-console-line{white-space:pre-wrap;word-break:break-all}
.ping-line-success{color:var(--green);font-weight:600}
.ping-line-error{color:var(--red);font-weight:600}
.ping-line-header{color:var(--blue);font-weight:700}
.ping-line-info{color:var(--dim)}
.ping-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;display:inline-block}
.ping-dot.ok{background:var(--green)}
.ping-dot.fail{background:var(--red)}
.ping-dot.waiting{background:var(--dim)}
.statusbar{background:var(--bg2);border-top:1px solid var(--bg4);
           padding:4px 16px;font-size:.76rem;color:var(--dim);
           display:flex;justify-content:space-between;flex-shrink:0}
.engineer-bar{background:var(--bg2);border-bottom:1px solid var(--bg4);
              padding:7px 16px;display:flex;align-items:center;gap:12px;flex-shrink:0}
.engineer-bar label{font-size:.8rem;color:var(--dim);font-weight:700;white-space:nowrap}
.engineer-bar input{max-width:260px;background:var(--bg3);border:1px solid var(--bg4);
                    color:var(--fg);padding:5px 10px;border-radius:6px;font-size:.88rem}
.engineer-bar input:focus{border-color:var(--blue);outline:none}
.eng-hint{font-size:.75rem;color:var(--dim)}
/* ── Network Map ── */
.map-toolbar{display:flex;align-items:center;gap:8px;padding:8px 16px;
             border-bottom:1px solid var(--bg4);flex-shrink:0;flex-wrap:wrap;
             background:var(--bg2)}
.map-legend{display:flex;gap:12px;align-items:center;margin-left:auto;flex-wrap:wrap}
.leg-item{display:flex;align-items:center;gap:4px;font-size:.73rem;color:var(--dim);white-space:nowrap}
.leg-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;border:2px solid}
#mapContainer{flex:1;background:#090d13;position:relative;overflow:hidden;min-height:200px}
.node-tooltip{position:absolute;background:var(--bg2);border:1px solid var(--bg4);
              border-radius:8px;padding:10px 14px;min-width:220px;max-width:300px;
              z-index:50;pointer-events:none;box-shadow:0 4px 24px rgba(0,0,0,.7)}
.node-tooltip #ttTitle{font-size:.95rem;font-weight:700;margin-bottom:7px;
                        font-family:'Courier New',monospace}
.tt-row{font-size:.78rem;margin:3px 0;color:var(--fg);line-height:1.5}
.tt-row b{color:var(--dim);margin-right:4px}
.tt-port{display:inline-block;padding:1px 6px;border-radius:4px;font-size:.72rem;
         font-family:'Courier New',monospace;margin:2px 1px;border:1px solid currentColor}
#mapEmpty{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
          text-align:center;color:var(--dim);pointer-events:none;user-select:none}
#mapEmpty .em-icon{font-size:3rem;margin-bottom:10px}
#mapEmpty .em-text{font-size:1rem;color:var(--fg);margin-bottom:6px}
.inv-th{text-align:left;padding:10px 12px;color:var(--dim);font-weight:700;
        font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;
        border-bottom:2px solid var(--bg4);user-select:none}
#hostTableBody tr{border-bottom:1px solid var(--bg4);transition:background .1s}
#hostTableBody tr:hover{background:var(--bg3)}
#hostTableBody td{padding:8px 12px;color:var(--fg);font-size:.84rem;vertical-align:middle}
.host-status-up{color:var(--green);font-size:1.1rem}
.host-status-down{color:var(--red);font-size:1.1rem}
.host-mac{font-family:'Courier New',monospace;color:var(--yellow);font-size:.82rem}
.host-ports{display:flex;flex-wrap:wrap;gap:3px}
.host-port-badge{display:inline-block;padding:1px 6px;border-radius:4px;font-size:.72rem;
                 font-family:'Courier New',monospace;border:1px solid var(--blue);color:var(--blue)}
.host-type-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.72rem;font-weight:600}
#mapEmpty .em-sub{font-size:.82rem}
</style>
</head>
<body>

<header>
  <div>
    <h1>&#x26A1; Kali VPN Vulnerability Scanner</h1>
    <span>nmap &bull; vulners &bull; nikto &bull; OpenVPN &bull; WireGuard &bull; Nebula</span>
  </div>
  <div style="margin-left:auto;display:flex;gap:10px;align-items:center">
    <div id="vpnBadge" class="badge-vpn off" onclick="openVpnModal()">&#x25CF; VPN Inactiva</div>
    <button class="btn btn-gray btn-sm" onclick="showTab('history',this);loadHistory()">Historial</button>
  </div>
</header>

<!-- Engineer bar -->
<div class="engineer-bar">
  <label>&#x1F464; Ingeniero responsable:</label>
  <input id="engineerInput" type="text" placeholder="Nombre completo del ingeniero que realiza el test"
         autocomplete="name">
  <span class="eng-hint">Se incluirá en el informe PDF con firma y fecha/hora</span>
</div>

<div class="layout">
  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="sidebar-header">
      CLIENTES
      <button class="btn btn-green btn-sm" onclick="newClient()">+ Nuevo</button>
    </div>
    <div class="client-list" id="clientList"></div>
    <div class="client-form">
      <h3 id="clientFormTitle">Nuevo cliente</h3>
      <form id="clientFormEl" onsubmit="saveClient(event)">
        <div class="form-group">
          <label>Nombre / Empresa *</label>
          <input id="cf_name" name="name" required placeholder="Empresa ABC">
        </div>
        <div class="form-group">
          <label>Red interna (CIDR)</label>
          <input id="cf_network" name="network" placeholder="192.168.1.0/24">
        </div>
        <div class="form-group">
          <label>Descripción</label>
          <input id="cf_desc" name="desc" placeholder="Notas">
        </div>
        <div class="form-group">
          <label>Tipo VPN</label>
          <select id="cf_vpntype" name="vpn_type" onchange="onVpnTypeChange()">
            <option>Tailscale</option>
            <option>OpenVPN</option>
            <option>WireGuard</option>
            <option>Nebula</option>
          </select>
        </div>
        <!-- Campos Nebula (visibles sólo cuando vpn_type=Nebula) -->
        <div id="nebula_fields" style="display:none">
          <div class="row">
            <div class="form-group">
              <label>IP Nebula del nodo (CIDR)</label>
              <input id="cf_nebula_ip" name="nebula_ip" placeholder="10.255.255.10/24">
            </div>
            <div class="form-group">
              <label>Grupos Nebula</label>
              <input id="cf_nebula_groups" name="nebula_groups" placeholder="clients" value="clients">
            </div>
          </div>
        </div>
        <!-- Campos OpenVPN/WireGuard (ocultos para Nebula) -->
        <div id="classic_vpn_fields">
          <div class="form-group">
            <label>Config VPN (.ovpn / .conf / .yaml)</label>
            <input type="file" id="cf_vpnfile" name="vpn_config" accept=".ovpn,.conf,.yaml">
          </div>
          <div class="row">
            <div class="form-group">
              <label>Usuario VPN</label>
              <input id="cf_vpnuser" name="vpn_user" placeholder="(opcional)">
            </div>
            <div class="form-group">
              <label>Contraseña VPN</label>
              <input id="cf_vpnpass" name="vpn_pass" type="password">
            </div>
          </div>
        </div>
        <div style="display:flex;gap:8px;margin-top:4px">
          <button type="submit" class="btn btn-blue" style="flex:1">Guardar</button>
          <button type="button" class="btn btn-gray" onclick="newClient()">Limpiar</button>
        </div>
      </form>
    </div>
  </aside>

  <div class="main">
    <div class="tabs">
      <div class="tab active" id="tab-btn-scanner" onclick="showTab('scanner',this)">&#x1F50D; Escaneo</div>
      <div class="tab" id="tab-btn-history"  onclick="showTab('history',this);loadHistory()">&#x1F4CB; Historial</div>
      <div class="tab" id="tab-btn-map"      onclick="showTab('map',this);onMapTabOpen()">&#x1F5A7; Mapa de Red</div>
      <div class="tab" id="tab-btn-capture"  onclick="showTab('capture',this);loadCapIfaces()">&#x1F4E1; Captura de Tráfico</div>
      <div class="tab" id="tab-btn-ids"      onclick="showTab('ids',this)">&#x1F6E1; IDS Suricata</div>
      <div class="tab" id="tab-btn-nebula"   onclick="showTab('nebula',this);loadNebulaTab()">&#x1F300; Nebula VPN</div>
      <div class="tab" id="tab-btn-fuzz"     onclick="showTab('fuzz',this)">&#x1F4A5; Pentesting Externo</div>
      <div class="tab" id="tab-btn-chisel"   onclick="showTab('chisel',this);loadChiselStatus()">&#x1F50C; T&uacute;nel Chisel</div>
    </div>

    <!-- SCANNER TAB -->
    <div class="tab-content active" id="tab-scanner">
      <div class="scan-config">
        <!-- VPN row -->
        <div class="row" style="align-items:flex-end;margin-bottom:8px;flex-wrap:wrap;gap:10px">
          <div class="form-group" style="min-width:170px">
            <label>Cliente</label>
            <select id="selClient" onchange="onClientSelect()">
              <option value="">— Seleccionar —</option>
            </select>
          </div>
          <div class="form-group" style="min-width:180px">
            <label>Objetivo (IP / CIDR / hostname)</label>
            <input id="inTarget" placeholder="192.168.1.0/24">
          </div>
          <div class="form-group" style="min-width:220px">
            <label>Perfil de escaneo</label>
            <select id="selProfile" onchange="onProfileSelect()"></select>
          </div>
          <div style="display:flex;align-items:flex-end;gap:6px">
            <button class="btn btn-orange btn-sm" onclick="openVpnModal()">
              &#x1F512; VPN
            </button>
          </div>
        </div>
        <div class="form-group">
          <label>Comando (editable)</label>
          <input id="inCommand" style="font-family:'Courier New',monospace;color:var(--yellow)"
                 placeholder="sudo nmap ...">
        </div>
      </div>

      <!-- Ping Tool -->
      <div class="ping-bar">
        <div class="ping-controls">
          <span class="ping-label">&#x1F4E1; PING</span>
          <input id="pingHost" type="text" placeholder="IP o hostname (ej: 192.168.1.1)"
                 onkeydown="if(event.key==='Enter')doPing()" autocomplete="off">
          <select id="pingCount">
            <option value="4">4 paquetes</option>
            <option value="8">8 paquetes</option>
            <option value="10">10 paquetes</option>
          </select>
          <button class="btn btn-ping" id="btnPing" onclick="doPing()">&#x25B6; Ping</button>
          <button class="btn btn-gray btn-sm" onclick="clearPing()" title="Limpiar">&#x2715;</button>
          <div class="ping-status" id="pingStatus">
            <span id="pingDot" class="ping-dot waiting"></span>
            <span id="pingStatusText" style="color:var(--dim)">Introduce una IP y pulsa Ping</span>
          </div>
        </div>
        <div class="ping-console" id="pingOutput"></div>
      </div>

      <!-- Stats bar -->
      <div class="stats-bar" id="statsBar">
        <div class="stat-block">
          <div class="stat-label">Dispositivos</div>
          <div class="stat-value devices" id="statDevices">—</div>
        </div>
        <div class="stat-block">
          <div class="stat-label">Transcurrido</div>
          <div class="stat-value elapsed" id="statElapsed">00:00</div>
        </div>
        <div class="stat-block">
          <div class="stat-label">Tiempo restante</div>
          <div class="stat-value eta unknown" id="statEta">—</div>
        </div>
        <div class="stat-block">
          <div class="stat-label">Progreso</div>
          <div class="stat-value percent" id="statPercent">—</div>
        </div>
        <div class="stat-progress">
          <div class="stat-progress-label">
            <span id="progLabel">En espera</span>
            <span id="progPct">0%</span>
          </div>
          <div class="stat-progress-track">
            <div class="stat-progress-fill" id="progFill"></div>
          </div>
        </div>
        <div class="stat-devices-list">
          <div class="stat-devices-scroll" id="deviceChips"></div>
        </div>
      </div>

      <!-- Toolbar -->
      <div class="toolbar">
        <button class="btn btn-blue" id="btnScan" onclick="startScan()">&#x25B6; Iniciar Escaneo</button>
        <button class="btn btn-red"  id="btnStop" onclick="stopScan()" disabled>&#x25A0; Detener</button>
        <button class="btn btn-gray" onclick="clearOutput()">Limpiar</button>
        <div style="width:1px;height:24px;background:var(--bg4);margin:0 4px"></div>
        <button class="btn btn-pdf"  id="btnPdf"  onclick="exportScan('pdf')"  style="display:none">
          &#x1F4C4; Descargar PDF
        </button>
        <button class="btn btn-gray btn-sm" id="btnTxt"  onclick="exportScan('txt')"  style="display:none">&#x2B07; TXT</button>
        <button class="btn btn-gray btn-sm" id="btnJson" onclick="exportScan('json')" style="display:none">&#x2B07; JSON</button>
        <button class="btn btn-gray btn-sm" id="btnHtml" onclick="exportScan('html')" style="display:none">&#x2B07; HTML</button>
        <button class="btn btn-green btn-sm" id="btnExec" onclick="exportScan('exec')" style="display:none" title="Reporte ejecutivo para Gerencia General">&#x1F4CA; Informe Ejecutivo</button>
        <span id="scanStatus" style="color:var(--dim);font-size:.82rem;margin-left:auto"></span>
      </div>
      <div class="progress-bar"><div class="progress-inner" id="progressBar"></div></div>

      <div class="output-area">
        <div class="terminal" id="terminal">
          <span style="color:var(--dim)">Listo. Ingresa tu nombre, configura el cliente y objetivo para comenzar.
</span>
        </div>
        <div class="findings-panel">
          <div class="findings-header">
            HALLAZGOS
            <button class="btn btn-gray btn-sm" onclick="clearFindings()">Limpiar</button>
          </div>
          <div class="findings-list" id="findingsList"></div>
        </div>
      </div>
    </div>

    <!-- MAP TAB -->
    <div class="tab-content" id="tab-map">
      <div class="map-toolbar">
        <span style="font-weight:700;color:var(--blue);white-space:nowrap;font-size:.9rem">&#x1F5A7; Mapa de Red</span>
        <input id="mapTarget" placeholder="Subnet (ej: 192.168.10.0/24)"
               style="max-width:240px;padding:5px 10px;background:var(--bg3);
                      border:1px solid var(--bg4);color:var(--fg);border-radius:6px;
                      outline:none;font-size:.88rem;font-family:inherit"
               onkeydown="if(event.key==='Enter')startNetworkMap()"
               onfocus="this.style.borderColor='var(--blue)'"
               onblur="this.style.borderColor='var(--bg4)'">
        <button class="btn btn-blue btn-sm" id="btnMapScan" onclick="startNetworkMap()">&#x25B6; Escanear</button>
        <button class="btn btn-green btn-sm" id="btnProbeScan" onclick="startProbeScan()">&#x1F4E1; Sonda Local</button>
        <button class="btn btn-gray btn-sm" id="btnMapReset" onclick="resetMapView()">&#x21BA; Reset</button>
        <select id="mapViewMode" onchange="toggleMapView(this.value)"
                style="background:var(--bg3);color:var(--fg);border:1px solid var(--bg4);
                       border-radius:6px;padding:4px 8px;font-size:.82rem">
          <option value="graph">Vista Grafo</option>
          <option value="table">Vista Tabla</option>
          <option value="both">Ambas</option>
        </select>
        <span id="mapStatus" style="color:var(--dim);font-size:.8rem"></span>
        <div class="map-legend">
          <div class="leg-item"><div class="leg-dot" style="background:#8b1a1a;border-color:#f85149"></div>Gateway/FW</div>
          <div class="leg-item"><div class="leg-dot" style="background:#1a3a6b;border-color:#58a6ff"></div>Web Server</div>
          <div class="leg-item"><div class="leg-dot" style="background:#5a3200;border-color:#f0883e"></div>Windows</div>
          <div class="leg-item"><div class="leg-dot" style="background:#0e3a1a;border-color:#3fb950"></div>Linux/SSH</div>
          <div class="leg-item"><div class="leg-dot" style="background:#2e1a5a;border-color:#bc8cff"></div>Base de Datos</div>
          <div class="leg-item"><div class="leg-dot" style="background:#161b22;border-color:#6e7681"></div>Desconocido</div>
        </div>
      </div>
      <!-- Graph view -->
      <div id="mapContainer">
        <svg id="networkSvg" style="width:100%;height:100%"></svg>
        <div id="nodeTooltip" class="node-tooltip" style="display:none">
          <div id="ttTitle"></div>
          <div id="ttContent"></div>
        </div>
        <div id="mapEmpty">
          <div class="em-icon">&#x1F5A7;</div>
          <div class="em-text">Sin datos de red</div>
          <div class="em-sub">Introduce una subnet y pulsa Escanear<br>
            <span style="color:var(--blue);font-size:.78rem">Tip: arrastra nodos · scroll = zoom · doble-click = reset</span>
          </div>
        </div>
      </div>
      <!-- Host inventory table (Advanced IP Scanner style) -->
      <div id="hostTableContainer" style="display:none;overflow:auto;background:#090d13;border-top:1px solid var(--bg4)">
        <table id="hostInventoryTable" style="width:100%;border-collapse:collapse;font-size:.84rem">
          <thead>
            <tr style="background:var(--bg2);position:sticky;top:0;z-index:2">
              <th class="inv-th" style="width:50px">Estado</th>
              <th class="inv-th" onclick="sortHostTable('hostname')" style="cursor:pointer">Nombre &#x25B4;&#x25BE;</th>
              <th class="inv-th" onclick="sortHostTable('ip')" style="cursor:pointer">IP &#x25B4;&#x25BE;</th>
              <th class="inv-th" onclick="sortHostTable('vendor')" style="cursor:pointer">Fabricante &#x25B4;&#x25BE;</th>
              <th class="inv-th">Direcci&oacute;n MAC</th>
              <th class="inv-th">Puertos</th>
              <th class="inv-th">Tipo</th>
            </tr>
          </thead>
          <tbody id="hostTableBody"></tbody>
        </table>
      </div>
    </div>

    <!-- CAPTURE TAB -->
    <div class="tab-content" id="tab-capture">
      <div style="padding:16px;display:flex;flex-direction:column;gap:12px;height:100%;box-sizing:border-box">

        <!-- Toolbar: captura -->
        <div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
          <div style="display:flex;flex-direction:column;gap:4px;min-width:150px">
            <label style="font-size:.78rem;color:var(--dim);font-weight:700">Interfaz</label>
            <select id="capIface" style="background:var(--bg3);color:var(--fg);border:1px solid var(--bg4);
                    border-radius:6px;padding:5px 10px;font-size:.88rem;min-width:140px">
              <option value="eth0">eth0</option>
            </select>
          </div>
          <div style="display:flex;flex-direction:column;gap:4px;flex:1;min-width:220px">
            <label style="font-size:.78rem;color:var(--dim);font-weight:700">Filtro BPF (captura)</label>
            <input id="capBpf" placeholder="ej: net 192.168.1.0/24  |  port 445 or port 80"
                   style="padding:5px 10px;background:var(--bg3);color:var(--fg);
                          border:1px solid var(--bg4);border-radius:6px;font-size:.85rem;
                          font-family:'Courier New',monospace;width:100%;box-sizing:border-box">
          </div>
          <button class="btn btn-green btn-sm" id="btnCapStart" onclick="startCapture()">&#x25CF; Iniciar captura</button>
          <button class="btn btn-red   btn-sm" id="btnCapStop"  onclick="stopCapture()" disabled>&#x25A0; Detener</button>
          <button class="btn btn-gray  btn-sm" onclick="capClear()">&#x1F5D1; Limpiar</button>
        </div>

        <!-- Live console -->
        <div id="capConsole" style="background:#090d13;border:1px solid var(--bg4);
             border-radius:8px;overflow-y:auto;padding:10px 14px;height:160px;
             font-family:'Courier New',monospace;font-size:.8rem;line-height:1.55;color:#c9d1d9"></div>

        <!-- Charts grid (visible only during capture) -->
        <div id="capCharts" style="display:none;grid-template-columns:1fr 1fr;grid-template-rows:auto auto;gap:12px">
          <!-- Traffic over time -->
          <div style="background:var(--bg2);border:1px solid var(--bg4);border-radius:8px;padding:12px;grid-column:1/-1">
            <div style="font-size:.75rem;color:var(--dim);font-weight:700;margin-bottom:6px">
              PAQUETES / SEGUNDO — últimos 5 min
              <span id="capTotalPkts" style="float:right;color:var(--blue)"></span>
            </div>
            <canvas id="chartTime" height="70"></canvas>
          </div>
          <!-- Top src IPs -->
          <div style="background:var(--bg2);border:1px solid var(--bg4);border-radius:8px;padding:12px">
            <div style="font-size:.75rem;color:var(--dim);font-weight:700;margin-bottom:6px">TOP 10 IPs ORIGEN</div>
            <canvas id="chartSrc" height="140"></canvas>
          </div>
          <!-- Top dst ports -->
          <div style="background:var(--bg2);border:1px solid var(--bg4);border-radius:8px;padding:12px">
            <div style="font-size:.75rem;color:var(--dim);font-weight:700;margin-bottom:6px">TOP 10 PUERTOS DESTINO</div>
            <canvas id="chartPorts" height="140"></canvas>
          </div>
          <!-- TCP Flags -->
          <div style="background:var(--bg2);border:1px solid var(--bg4);border-radius:8px;padding:12px;
                      display:flex;flex-direction:column;align-items:center">
            <div style="font-size:.75rem;color:var(--dim);font-weight:700;margin-bottom:6px;width:100%">FLAGS TCP</div>
            <canvas id="chartFlags" style="max-height:160px;max-width:220px"></canvas>
          </div>
          <!-- In vs Out stacked -->
          <div style="background:var(--bg2);border:1px solid var(--bg4);border-radius:8px;padding:12px">
            <div style="font-size:.75rem;color:var(--dim);font-weight:700;margin-bottom:6px">IN vs OUT (acumulado 5 min)</div>
            <canvas id="chartInOut" height="140"></canvas>
          </div>
        </div>

        <hr style="border:none;border-top:1px solid var(--bg4);margin:4px 0">

        <!-- Sección leer/filtrar pcap -->
        <div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
          <span style="font-size:.82rem;color:var(--dim);font-weight:700;white-space:nowrap;
                       align-self:center">&#x1F4C2; Analizar .pcap:</span>
          <div style="display:flex;flex-direction:column;gap:4px;flex:2;min-width:220px">
            <label style="font-size:.78rem;color:var(--dim)">Archivo</label>
            <input id="capReadFile" placeholder="/opt/scanner/scans/capture_XXXXXXXX.pcap"
                   style="padding:5px 10px;background:var(--bg3);color:var(--fg);
                          border:1px solid var(--bg4);border-radius:6px;font-size:.82rem;
                          font-family:'Courier New',monospace;width:100%;box-sizing:border-box">
          </div>
          <div style="display:flex;flex-direction:column;gap:4px;flex:1;min-width:160px">
            <label style="font-size:.78rem;color:var(--dim)">Filtro (BPF)</label>
            <input id="capReadFilter" placeholder="port 445 or port 80"
                   style="padding:5px 10px;background:var(--bg3);color:var(--fg);
                          border:1px solid var(--bg4);border-radius:6px;font-size:.82rem;
                          font-family:'Courier New',monospace;width:100%;box-sizing:border-box">
          </div>
          <button class="btn btn-blue btn-sm" onclick="readCapture()">&#x1F50D; Leer / Filtrar</button>
        </div>

      </div>
    </div>

    <!-- IDS SURICATA TAB -->
    <div class="tab-content" id="tab-ids">
      <div style="padding:16px;display:flex;flex-direction:column;gap:12px;height:100%;box-sizing:border-box;overflow-y:auto">
        <!-- Toolbar -->
        <div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
          <div style="display:flex;flex-direction:column;gap:4px;min-width:150px">
            <label style="font-size:.78rem;color:var(--dim);font-weight:700">Interfaz</label>
            <select id="idsIface" style="background:var(--bg3);color:var(--fg);border:1px solid var(--bg4);
                    border-radius:6px;padding:5px 10px;font-size:.88rem;min-width:140px">
              <option value="eth0">eth0</option><option value="tailscale0">tailscale0</option>
            </select>
          </div>
          <button class="btn btn-green btn-sm" id="btnIdsStart" onclick="idsStart()">&#x25CF; Iniciar Suricata</button>
          <button class="btn btn-red   btn-sm" id="btnIdsStop"  onclick="idsStop()" disabled>&#x25A0; Detener</button>
          <span id="idsStatusText" style="font-size:.82rem;color:var(--dim)"></span>
          <span id="idsTotalAlerts" style="font-size:.82rem;color:var(--yellow);margin-left:auto"></span>
        </div>

        <!-- Stats grid -->
        <div id="idsCharts" style="display:none;grid-template-columns:1fr 1fr;gap:12px">
          <!-- Alerts timeline -->
          <div style="background:var(--bg2);border:1px solid var(--bg4);border-radius:8px;padding:12px;grid-column:1/-1">
            <div style="font-size:.75rem;color:var(--dim);font-weight:700;margin-bottom:6px">ALERTAS / SEGUNDO — últimos 5 min</div>
            <canvas id="idsChartTime" height="55"></canvas>
          </div>
          <!-- Top signatures -->
          <div style="background:var(--bg2);border:1px solid var(--bg4);border-radius:8px;padding:12px">
            <div style="font-size:.75rem;color:var(--dim);font-weight:700;margin-bottom:6px">TOP 10 FIRMAS</div>
            <canvas id="idsChartSig" height="150"></canvas>
          </div>
          <!-- Severity donut + top src -->
          <div style="display:flex;gap:12px;flex-direction:column">
            <div style="background:var(--bg2);border:1px solid var(--bg4);border-radius:8px;padding:12px;
                        display:flex;flex-direction:column;align-items:center;flex:1">
              <div style="font-size:.75rem;color:var(--dim);font-weight:700;margin-bottom:6px;width:100%">SEVERIDAD</div>
              <canvas id="idsChartSev" style="max-height:120px;max-width:200px"></canvas>
            </div>
            <div style="background:var(--bg2);border:1px solid var(--bg4);border-radius:8px;padding:12px;flex:1">
              <div style="font-size:.75rem;color:var(--dim);font-weight:700;margin-bottom:6px">TOP 10 IPs ORIGEN</div>
              <canvas id="idsChartSrc" height="120"></canvas>
            </div>
          </div>
        </div>

        <!-- Live alerts table -->
        <div style="font-size:.75rem;color:var(--dim);font-weight:700">ALERTAS EN TIEMPO REAL</div>
        <div id="idsAlertBox" style="flex:1;background:#090d13;border:1px solid var(--bg4);border-radius:8px;
             overflow-y:auto;min-height:150px;font-family:'Courier New',monospace;font-size:.76rem;line-height:1.5">
          <table style="width:100%;border-collapse:collapse">
            <thead style="position:sticky;top:0;background:#161b22;z-index:1">
              <tr>
                <th style="text-align:left;padding:6px 8px;color:var(--dim);border-bottom:1px solid var(--bg4);width:70px">Hora</th>
                <th style="text-align:left;padding:6px 8px;color:var(--dim);border-bottom:1px solid var(--bg4);width:30px">Sev</th>
                <th style="text-align:left;padding:6px 8px;color:var(--dim);border-bottom:1px solid var(--bg4);width:100px">Origen</th>
                <th style="text-align:left;padding:6px 8px;color:var(--dim);border-bottom:1px solid var(--bg4);width:100px">Destino</th>
                <th style="text-align:left;padding:6px 8px;color:var(--dim);border-bottom:1px solid var(--bg4);width:40px">Proto</th>
                <th style="text-align:left;padding:6px 8px;color:var(--dim);border-bottom:1px solid var(--bg4)">Firma / Alerta</th>
              </tr>
            </thead>
            <tbody id="idsAlertBody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- HISTORY TAB -->
    <div class="tab-content" id="tab-history" style="overflow:auto;padding:16px">
      <table class="history-table" id="historyTable">
        <thead><tr>
          <th>ID</th><th>Ingeniero</th><th>Cliente</th><th>Objetivo</th>
          <th>Perfil</th><th>Inicio</th><th>Estado</th><th>Descargar</th>
        </tr></thead>
        <tbody id="historyBody"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ── NEBULA TAB ─────────────────────────────────────────────────────────── -->
<div class="tab-content" id="tab-fuzz" style="flex-direction:column;overflow:auto;padding:20px;gap:18px">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
    <h2 style="margin:0;font-size:1rem;color:var(--blue)">&#x1F4A5; Pentesting Externo — Fuzzing Web (ffuf)</h2>
    <span id="fuzz-status-badge" style="font-size:.78rem;color:var(--dim)"></span>
  </div>

  <!-- URL objetivo destacada -->
  <div style="background:var(--bg2);border:1px solid var(--blue);border-radius:10px;padding:14px 16px;display:flex;gap:12px;align-items:flex-end">
    <div class="form-group" style="flex:1;margin:0">
      <label style="color:var(--blue);font-weight:700">URL objetivo <span style="color:var(--red)">*</span></label>
      <input id="fz-url" placeholder="https://ejemplo.com/FUZZ  — usa FUZZ como marcador de posición" style="width:100%;font-size:.9rem">
    </div>
    <button class="btn btn-red" onclick="startFuzz()" style="flex-shrink:0;height:36px">&#x25B6; Lanzar ffuf</button>
    <button class="btn btn-gray" id="fz-stop-btn" onclick="stopFuzz()" disabled style="flex-shrink:0;height:36px">&#x25A0; Detener</button>
    <button class="btn btn-gray" onclick="clearFuzz()" style="flex-shrink:0;height:36px">Limpiar</button>
    <button class="btn" id="fz-dl-btn" onclick="downloadFuzzReport()" disabled style="flex-shrink:0;height:36px;background:#1a3a1a;color:#4caf50;border:1px solid #4caf50">&#x2B07; Descargar reporte</button>
    <span id="fz-progress" style="font-size:.8rem;color:var(--dim);align-self:center"></span>
  </div>

  <!-- Config panel -->
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;background:var(--bg2);border-radius:10px;padding:16px">
    <div class="form-group">
      <label>Wordlist</label>
      <select id="fz-wl" style="width:100%">
        <option value="/usr/share/wordlists/dirb/common.txt">dirb/common (4k)</option>
        <option value="/usr/share/wordlists/dirb/big.txt">dirb/big (20k)</option>
        <option value="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt">raft-medium-dirs (30k)</option>
        <option value="/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt">raft-large-dirs (62k)</option>
        <option value="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt">dirbuster-medium (220k)</option>
        <option value="/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt">LFI – Jhaddix</option>
        <option value="/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt">SQLi – Generic</option>
        <option value="/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt">XSS – Jhaddix</option>
      </select>
    </div>
    <div class="form-group">
      <label>Extensiones (opcional)</label>
      <input id="fz-ext" placeholder="php,html,js,txt" style="width:100%">
    </div>
    <div class="form-group">
      <label>Método HTTP</label>
      <select id="fz-method" style="width:100%">
        <option>GET</option><option>POST</option><option>PUT</option><option>HEAD</option>
      </select>
    </div>
    <div class="form-group">
      <label>Threads</label>
      <input id="fz-threads" type="number" value="40" min="1" max="200" style="width:100%">
    </div>
    <div class="form-group">
      <label>Timeout por req (seg)</label>
      <input id="fz-timeout" type="number" value="10" min="1" max="60" style="width:100%">
    </div>
    <div class="form-group">
      <label>Cabeceras extra (opcional)</label>
      <input id="fz-headers" placeholder="Authorization: Bearer token123" style="width:100%">
    </div>
    <div class="form-group">
      <label>Cookies (opcional)</label>
      <input id="fz-cookies" placeholder="session=abc123" style="width:100%">
    </div>
    <div class="form-group">
      <label>POST body (solo POST)</label>
      <input id="fz-postdata" placeholder="user=FUZZ&pass=test" style="width:100%">
    </div>
  </div>

  <!-- Filtros anti-falsos positivos -->
  <div style="background:var(--bg2);border:1px solid #9a5700;border-radius:10px;padding:16px">
    <div style="font-size:.8rem;font-weight:700;color:#f0a500;margin-bottom:10px">&#x26A0; Filtros anti-falsos positivos</div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:12px">
      <div class="form-group">
        <label>Filtrar códigos HTTP</label>
        <input id="fz-fc" placeholder="404,400,403" style="width:100%">
        <span style="font-size:.72rem;color:var(--dim)">Ocultar respuestas con estos códigos</span>
      </div>
      <div class="form-group">
        <label>Filtrar por tamaño (bytes)</label>
        <input id="fz-fs" placeholder="ej: 1234" style="width:100%">
        <span style="font-size:.72rem;color:var(--dim)">Ocultar respuestas de este tamaño exacto</span>
      </div>
      <div class="form-group">
        <label>Filtrar por palabras</label>
        <input id="fz-fw" placeholder="ej: 23" style="width:100%">
        <span style="font-size:.72rem;color:var(--dim)">Ocultar respuestas con N palabras</span>
      </div>
      <div class="form-group">
        <label>Filtrar por líneas</label>
        <input id="fz-fl" placeholder="ej: 9" style="width:100%">
        <span style="font-size:.72rem;color:var(--dim)">Ocultar respuestas con N líneas</span>
      </div>
      <div class="form-group">
        <label>Matcher códigos (solo mostrar)</label>
        <input id="fz-mc" placeholder="200,201,301,302" style="width:100%">
        <span style="font-size:.72rem;color:var(--dim)">Solo mostrar estos códigos</span>
      </div>
      <div class="form-group">
        <label>Matcher regex en respuesta</label>
        <input id="fz-mr" placeholder="ej: admin|dashboard" style="width:100%">
      </div>
      <div class="form-group" style="grid-column:span 2">
        <label>Auto-detectar falsos positivos</label>
        <label style="display:flex;align-items:center;gap:6px;cursor:pointer;margin-top:6px">
          <input type="checkbox" id="fz-auto-fp" checked>
          <span style="font-size:.82rem">Enviar primero petición de calibración y filtrar automáticamente respuestas idénticas</span>
        </label>
      </div>
    </div>
  </div>

  <!-- Results table -->
  <div style="background:var(--bg2);border-radius:10px;overflow:hidden">
    <div style="padding:10px 14px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--bg4)">
      <span style="font-size:.85rem;font-weight:700;color:var(--blue)">Resultados</span>
      <span id="fz-count" style="font-size:.78rem;color:var(--dim)">0 hallazgos</span>
    </div>
    <div style="overflow-x:auto">
      <table style="width:100%;border-collapse:collapse;font-size:.82rem">
        <thead>
          <tr style="background:var(--bg3)">
            <th style="padding:7px 12px;text-align:left">Código</th>
            <th style="padding:7px 12px;text-align:left">URL</th>
            <th style="padding:7px 12px;text-align:right">Tamaño</th>
            <th style="padding:7px 12px;text-align:right">Palabras</th>
            <th style="padding:7px 12px;text-align:right">Líneas</th>
            <th style="padding:7px 12px;text-align:right">RT (ms)</th>
          </tr>
        </thead>
        <tbody id="fz-results-body"></tbody>
      </table>
    </div>
  </div>

  <!-- Raw output -->
  <div>
    <div style="font-size:.78rem;color:var(--dim);margin-bottom:4px">Salida raw (ffuf)</div>
    <pre id="fz-raw" style="background:var(--bg1);border:1px solid var(--bg4);border-radius:8px;padding:12px;font-size:.75rem;max-height:260px;overflow:auto;white-space:pre-wrap"></pre>
  </div>
</div>

<!-- ╔══════════════════════════════════════════════════════╗ -->
<!-- ║                 CHISEL TUNNEL TAB                   ║ -->
<!-- ╚══════════════════════════════════════════════════════╝ -->
<div class="tab-content" id="tab-chisel" style="flex-direction:column;overflow:auto;padding:20px;gap:18px">

  <!-- Estado del servidor Chisel -->
  <div style="background:var(--bg2);border:1px solid var(--bg4);border-radius:10px;padding:16px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <h3 style="color:var(--blue);font-size:.95rem;margin:0">&#x1F50C; Estado del Servidor Chisel (Kali)</h3>
      <button class="btn btn-gray btn-sm" onclick="loadChiselStatus()">&#x21BB; Refrescar</button>
    </div>
    <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:14px">
      <div class="stat-block"><div class="stat-label">Servidor</div><div id="cs-running" class="stat-value">—</div></div>
      <div class="stat-block"><div class="stat-label">PID</div><div id="cs-pid" class="stat-value">—</div></div>
      <div class="stat-block"><div class="stat-label">Puerto</div><div id="cs-port" class="stat-value">—</div></div>
      <div class="stat-block"><div class="stat-label">SOCKS5 local</div><div id="cs-socks" class="stat-value">—</div></div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button id="cs-start-btn" class="btn btn-green btn-sm" onclick="chiselStart()">&#x25B6; Iniciar Servidor</button>
      <button id="cs-stop-btn"  class="btn btn-red btn-sm"   onclick="chiselStop()">&#x25A0; Detener</button>
    </div>
  </div>

  <!-- Instrucciones para el cliente Windows (Sofia) -->
  <div style="background:var(--bg2);border:1px solid #1a4a1a;border-radius:10px;padding:16px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
      <span style="font-size:1rem">&#x1F5A5;</span>
      <h3 style="color:#3fb950;font-size:.9rem;margin:0">Instrucciones para el cliente Windows (Sofia-Soria)</h3>
    </div>
    <p style="font-size:.8rem;color:var(--dim);margin:0 0 10px 0">Ejecutar en <b>PowerShell como Administrador</b> en el equipo del cliente:</p>

    <!-- Paso 1 -->
    <div style="margin-bottom:12px">
      <div style="font-size:.78rem;font-weight:700;color:#f0a500;margin-bottom:4px">Paso 1 — Descargar chisel para Windows</div>
      <div style="position:relative">
        <pre id="cs-cmd1" style="background:var(--bg1);border:1px solid var(--bg4);border-radius:6px;padding:10px 12px;font-size:.78rem;overflow-x:auto;white-space:pre-wrap;margin:0">Invoke-WebRequest -Uri "https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_windows_amd64.zip" -OutFile "C:\Nebula\chisel.zip"; Expand-Archive -Path "C:\Nebula\chisel.zip" -DestinationPath "C:\Nebula\" -Force</pre>
        <button class="btn btn-gray btn-sm" style="position:absolute;top:6px;right:6px" onclick="copyCmd('cs-cmd1')">&#x1F4CB; Copiar</button>
      </div>
    </div>

    <!-- Paso 2 -->
    <div>
      <div style="font-size:.78rem;font-weight:700;color:#f0a500;margin-bottom:4px">Paso 2 — Conectar al servidor Kali y crear el túnel SOCKS5</div>
      <div style="position:relative">
        <pre id="cs-cmd2" style="background:var(--bg1);border:1px solid var(--bg4);border-radius:6px;padding:10px 12px;font-size:.78rem;overflow-x:auto;white-space:pre-wrap;margin:0">C:\Nebula\chisel.exe client 10.255.255.1:8888 R:socks</pre>
        <button class="btn btn-gray btn-sm" style="position:absolute;top:6px;right:6px" onclick="copyCmd('cs-cmd2')">&#x1F4CB; Copiar</button>
      </div>
      <div style="font-size:.75rem;color:var(--dim);margin-top:6px">
        Cuando conecte correctamente, verás en el log de Kali: <code>session#1: tun: proxy#R:127.0.0.1:1080=socks</code>
      </div>
    </div>
  </div>

  <!-- Escaneo a través del túnel -->
  <div style="background:var(--bg2);border:1px solid var(--bg4);border-radius:10px;padding:16px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
      <span style="font-size:1rem">&#x1F50D;</span>
      <h3 style="color:var(--blue);font-size:.9rem;margin:0">Escaneo a través del túnel SOCKS5</h3>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
      <div class="form-group">
        <label>Red / Host objetivo</label>
        <input id="cs-target" value="192.168.1.0/24" placeholder="192.168.1.0/24 o 192.168.1.157" style="width:100%">
        <span style="font-size:.72rem;color:var(--dim)">LAN interna del cliente (se escanea vía proxychains)</span>
      </div>
      <div class="form-group">
        <label>Puertos</label>
        <input id="cs-ports" value="22,80,443,445,3389,8080,8443,21,25,3306" placeholder="22,80,443,3389,8080" style="width:100%">
        <span style="font-size:.72rem;color:var(--dim)">Separados por coma</span>
      </div>
    </div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button id="cs-scan-btn" class="btn btn-blue btn-sm" onclick="chiselScan()">&#x1F50D; Escanear LAN</button>
      <button id="cs-scan-stop-btn" class="btn btn-red btn-sm" onclick="chiselScanStop()" disabled>&#x25A0; Detener escaneo</button>
      <span id="cs-scan-status" style="font-size:.82rem;color:var(--dim)"></span>
      <span id="cs-scan-badge" style="font-size:.75rem;padding:2px 8px;border-radius:4px;background:var(--bg3)"></span>
    </div>
  </div>

  <!-- Output del escaneo -->
  <div>
    <div style="font-size:.78rem;color:var(--dim);margin-bottom:4px">Salida del escaneo (nmap a través de proxychains)</div>
    <pre id="cs-output" style="background:var(--bg1);border:1px solid var(--bg4);border-radius:8px;padding:12px;font-size:.75rem;min-height:200px;max-height:500px;overflow:auto;white-space:pre-wrap"></pre>
  </div>

  <!-- Log chisel -->
  <div>
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">
      <div style="font-size:.78rem;color:var(--dim)">Log del servidor Chisel</div>
      <button class="btn btn-gray btn-sm" onclick="refreshChiselLog()">&#x21BB; Refrescar log</button>
    </div>
    <pre id="cs-log" style="background:var(--bg1);border:1px solid var(--bg4);border-radius:8px;padding:12px;font-size:.75rem;max-height:200px;overflow:auto;white-space:pre-wrap">— sin log aún —</pre>
  </div>

</div>

<div class="tab-content" id="tab-nebula" style="flex-direction:column;overflow:auto;padding:20px;gap:18px">

  <!-- Estado del servidor Nebula -->
  <div style="background:var(--bg2);border:1px solid var(--bg4);border-radius:10px;padding:16px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <h3 style="color:var(--blue);font-size:.95rem;margin:0">&#x1F300; Estado Nebula en el Servidor</h3>
      <button class="btn btn-gray btn-sm" onclick="loadNebulaStatus()">&#x21BB; Refrescar</button>
    </div>
    <div id="nebulaStatusGrid" style="display:flex;gap:16px;flex-wrap:wrap">
      <div class="stat-block"><div class="stat-label">Proceso</div><div id="ns_proc" class="stat-value">—</div></div>
      <div class="stat-block"><div class="stat-label">Interfaz nebula0</div><div id="ns_iface" class="stat-value">—</div></div>
      <div class="stat-block"><div class="stat-label">IP Overlay</div><div id="ns_ip" class="stat-value" style="font-size:.9rem">—</div></div>
      <div class="stat-block"><div class="stat-label">CA</div><div id="ns_ca" class="stat-value">—</div></div>
      <div class="stat-block"><div class="stat-label">Binario</div><div id="ns_bin" class="stat-value">—</div></div>
    </div>
  </div>

  <!-- Panel Inicializar CA (visible sólo si CA falta) -->
  <div id="nebula_init_panel" style="display:none;background:var(--bg2);border:1px solid #9a5700;border-radius:10px;padding:16px">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
      <span style="font-size:1.3rem">&#x26A0;</span>
      <h3 style="color:var(--orange);font-size:.95rem;margin:0">CA no encontrada — Inicializar PKI Nebula</h3>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:12px">
      <div class="form-group" style="min-width:220px">
        <label>Nombre de la CA</label>
        <input id="ni_ca_name" value="Datacom Security Nebula CA">
      </div>
      <div class="form-group" style="min-width:170px">
        <label>IP del servidor (lighthouse)</label>
        <input id="ni_server_ip" value="10.255.255.1/24">
      </div>
      <div class="form-group" style="min-width:110px">
        <label>Duración CA</label>
        <select id="ni_dur">
          <option value="87600h">10 años</option>
          <option value="43800h">5 años</option>
        </select>
      </div>
      <button class="btn btn-orange" onclick="nebulaInitCA()" id="btnNebulaInit">&#x1F527; Inicializar CA</button>
    </div>
    <div id="ni_log" style="background:#090d13;border-radius:6px;padding:10px;
         font-family:'Courier New',monospace;font-size:.8rem;min-height:60px;
         max-height:200px;overflow-y:auto;display:none;line-height:1.6"></div>
  </div>

  <!-- Generar Certificado -->
  <div style="background:var(--bg2);border:1px solid var(--bg4);border-radius:10px;padding:16px">
    <h3 style="color:var(--blue);font-size:.95rem;margin:0 0 12px">&#x1F4DC; Emitir Certificado de Cliente</h3>
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
      <div class="form-group" style="min-width:160px">
        <label>Nombre del nodo</label>
        <input id="ncg_name" placeholder="empresa-router01"
               oninput="this.value=this.value.replace(/[^a-zA-Z0-9_-]/g,'-')">
      </div>
      <div class="form-group" style="min-width:180px">
        <label>IP Nebula (CIDR) <span style="color:var(--dim);font-weight:400;font-size:.72rem">— se agrega /24 si se omite</span></label>
        <input id="ncg_ip" placeholder="10.255.255.10/24"
               onblur="fixCIDR(this)" oninput="this.style.borderColor=''">
      </div>
      <div class="form-group" style="min-width:140px">
        <label>Grupos</label>
        <input id="ncg_groups" placeholder="clients" value="clients">
      </div>
      <div class="form-group" style="min-width:110px">
        <label>Duración</label>
        <select id="ncg_dur">
          <option value="8760h">1 año</option>
          <option value="17520h">2 años</option>
          <option value="43800h">5 años</option>
          <option value="720h">30 días</option>
        </select>
      </div>
      <button class="btn btn-green" onclick="nebulaGenCert()">&#x2795; Generar</button>
    </div>
    <div id="ncg_msg" style="margin-top:8px;font-size:.83rem;color:var(--dim)"></div>
  </div>

  <!-- Tabla de certificados -->
  <div style="background:var(--bg2);border:1px solid var(--bg4);border-radius:10px;padding:16px;flex:1">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <h3 style="color:var(--blue);font-size:.95rem;margin:0">&#x1F4C1; Certificados Emitidos</h3>
      <button class="btn btn-gray btn-sm" onclick="loadNebulaCerts()">&#x21BB; Refrescar</button>
    </div>
    <div id="nebulaCertsWrap" style="overflow-x:auto">
      <table class="history-table" style="min-width:700px">
        <thead>
          <tr>
            <th>Nodo</th><th>IP Overlay</th><th>Grupos</th><th>Expira</th><th>Acciones</th>
          </tr>
        </thead>
        <tbody id="nebulaCertsBody">
          <tr><td colspan="5" style="color:var(--dim);text-align:center">Cargando...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

</div>
<!-- ── FIN NEBULA TAB ──────────────────────────────────────────────────────── -->

<div class="statusbar">
  <span id="statusText">Listo.</span>
  <span id="elapsedText"></span>
</div>

<!-- VPN Modal -->
<div class="modal-overlay" id="vpnModal">
  <div class="modal" style="width:500px">
    <h2>&#x1F512; Gestión VPN</h2>

    <!-- Detected interfaces -->
    <div id="vpnDetectedBlock" style="display:none;margin-bottom:14px;
         background:var(--bg3);border-radius:8px;padding:12px;border:1px solid var(--bg4)">
      <div style="font-size:.78rem;color:var(--dim);font-weight:700;margin-bottom:8px">
        INTERFACES VPN DETECTADAS EN EL SERVIDOR
      </div>
      <div id="vpnDetectedList"></div>
    </div>

    <div style="height:1px;background:var(--bg4);margin-bottom:14px"></div>

    <div class="form-group">
      <label>Conectar cliente via VPN</label>
      <select id="vpnSelClient"></select>
    </div>
    <div id="vpnInfo" style="color:var(--dim);font-size:.85rem;margin:8px 0;min-height:22px"></div>
    <div style="display:flex;gap:8px;margin-top:12px">
      <button class="btn btn-green btn-sm" onclick="vpnAutodetect()">&#x1F50D; Re-detectar</button>
      <button class="btn btn-orange" onclick="connectVpn()">Conectar VPN</button>
      <button class="btn btn-red"    onclick="disconnectVpn()">Desconectar</button>
      <button class="btn btn-gray"   onclick="closeVpnModal()">Cerrar</button>
    </div>
  </div>
</div>

<script>
let currentScanId = null, sseSource = null;
let scanRunning = false, startTime = null, timerInterval = null;
let profiles = {};
let knownDevices = new Set();

// ── Capture Tab ───────────────────────────────────────────────────────────────
let capId = null, capSse = null, capRunning = false;
let capStatsInterval = null;
let chartTime = null, chartSrc = null, chartPorts = null, chartFlags = null, chartInOut = null;

const CAP_COLORS = ['#4fc3f7','#81c784','#ffb74d','#e57373','#ba68c8','#4dd0e1','#fff176','#a1887f','#90a4ae','#f48fb1'];

function initCharts() {
  Chart.defaults.color = '#8b949e';
  Chart.defaults.borderColor = '#21262d';

  const ctTime = document.getElementById('chartTime').getContext('2d');
  chartTime = new Chart(ctTime, {
    type: 'line',
    data: { labels: [], datasets: [
      { label: 'Entrada', data: [], borderColor: '#4fc3f7', backgroundColor: 'rgba(79,195,247,.15)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 },
      { label: 'Salida',  data: [], borderColor: '#81c784', backgroundColor: 'rgba(129,199,132,.15)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 },
    ]},
    options: { animation: false, scales: {
      x: { ticks: { maxTicksLimit: 10, callback: (v, i, a) => { const d = new Date(parseInt(chartTime.data.labels[i])*1000); return d.toLocaleTimeString(); } } },
      y: { beginAtZero: true, ticks: { precision: 0 } }
    }, plugins: { legend: { position: 'top' } } }
  });

  const ctSrc = document.getElementById('chartSrc').getContext('2d');
  chartSrc = new Chart(ctSrc, {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Paquetes', data: [], backgroundColor: CAP_COLORS }] },
    options: { animation: false, indexAxis: 'y', plugins: { legend: { display: false } },
               scales: { x: { beginAtZero: true, ticks: { precision: 0 } } } }
  });

  const ctPorts = document.getElementById('chartPorts').getContext('2d');
  chartPorts = new Chart(ctPorts, {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Paquetes', data: [], backgroundColor: '#ffb74d' }] },
    options: { animation: false, plugins: { legend: { display: false } },
               scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
  });

  const ctFlags = document.getElementById('chartFlags').getContext('2d');
  chartFlags = new Chart(ctFlags, {
    type: 'doughnut',
    data: { labels: ['SYN','ACK','FIN','RST','PSH','UDP'],
            datasets: [{ data: [0,0,0,0,0,0], backgroundColor: ['#4fc3f7','#81c784','#e57373','#f48fb1','#ffb74d','#ce93d8'] }] },
    options: { animation: false, plugins: { legend: { position: 'right' } } }
  });

  const ctIO = document.getElementById('chartInOut').getContext('2d');
  chartInOut = new Chart(ctIO, {
    type: 'bar',
    data: { labels: [], datasets: [
      { label: 'Entrada', data: [], backgroundColor: 'rgba(79,195,247,.7)'  },
      { label: 'Salida',  data: [], backgroundColor: 'rgba(129,199,132,.7)' },
    ]},
    options: { animation: false, scales: {
      x: { stacked: true, ticks: { maxTicksLimit: 8, callback: (v, i) => { const d = new Date(parseInt(chartInOut.data.labels[i])*1000); return d.toLocaleTimeString(); } } },
      y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } }
    }, plugins: { legend: { position: 'top' } } }
  });
}

function destroyCharts() {
  [chartTime, chartSrc, chartPorts, chartFlags, chartInOut].forEach(c => { if(c) c.destroy(); });
  chartTime = chartSrc = chartPorts = chartFlags = chartInOut = null;
}

async function updateCapStats() {
  if (!capId) return;
  try {
    const r = await fetch('/api/capture/stats/' + capId);
    if (!r.ok) return;
    const d = await r.json();
    // Time series
    chartTime.data.labels       = d.labels;
    chartTime.data.datasets[0].data = d.series_in;
    chartTime.data.datasets[1].data = d.series_out;
    chartTime.update('none');
    // In/Out stacked
    chartInOut.data.labels = d.labels;
    chartInOut.data.datasets[0].data = d.series_in;
    chartInOut.data.datasets[1].data = d.series_out;
    chartInOut.update('none');
    // Top src IPs
    chartSrc.data.labels = d.top_src.map(x => x[0]);
    chartSrc.data.datasets[0].data = d.top_src.map(x => x[1]);
    chartSrc.update('none');
    // Top ports
    chartPorts.data.labels = d.top_ports.map(x => x[0]);
    chartPorts.data.datasets[0].data = d.top_ports.map(x => x[1]);
    chartPorts.update('none');
    // Flags
    const f = d.flags;
    chartFlags.data.datasets[0].data = [f.S||0, f.A||0, f.F||0, f.R||0, f.P||0, f.U||0];
    chartFlags.update('none');
    // Total
    document.getElementById('capTotalPkts').textContent = d.total.toLocaleString() + ' paquetes';
  } catch(e) {}
}

async function loadCapIfaces() {
  try {
    const r = await fetch('/api/capture/ifaces');
    const j = await r.json();
    const sel = document.getElementById('capIface');
    sel.innerHTML = '';
    for (const iface of j.ifaces) {
      const opt = document.createElement('option');
      opt.value = opt.textContent = iface;
      sel.appendChild(opt);
    }
    const anyOpt = document.createElement('option');
    anyOpt.value = 'any'; anyOpt.textContent = 'any (todas las interfaces)';
    sel.appendChild(anyOpt);
  } catch(e) {}
}

function capAppend(text, color) {
  const c = document.getElementById('capConsole');
  const d = document.createElement('div');
  d.style.color = color || '#c9d1d9';
  d.style.whiteSpace = 'pre';
  d.textContent = text;
  c.appendChild(d);
  c.scrollTop = c.scrollHeight;
}

function capClear() { document.getElementById('capConsole').innerHTML = ''; }

async function startCapture() {
  const iface = document.getElementById('capIface').value.trim();
  const bpf   = document.getElementById('capBpf').value.trim();
  if (!iface) return;
  capClear();
  capAppend('Iniciando captura...', '#4fc3f7');
  const r = await fetch('/api/capture/start', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({iface, bpf})
  });
  const j = await r.json();
  if (j.error) { capAppend('[ERROR] ' + j.error, '#ff4444'); return; }
  capId = j.cap_id;
  document.getElementById('capReadFile').value = j.file;
  capRunning = true;
  document.getElementById('btnCapStart').disabled = true;
  document.getElementById('btnCapStop').disabled  = false;
  // Show and init charts
  const chartsEl = document.getElementById('capCharts');
  chartsEl.style.display = 'grid';
  destroyCharts();
  initCharts();
  capStatsInterval = setInterval(updateCapStats, 2000);
  if (capSse) capSse.close();
  capSse = new EventSource('/api/capture/stream/' + capId);
  capSse.onmessage = e => {
    if (e.data === '__DONE__') {
      capSse.close(); capRunning = false;
      clearInterval(capStatsInterval);
      document.getElementById('btnCapStart').disabled = false;
      document.getElementById('btnCapStop').disabled  = true;
      updateCapStats();  // final update
      return;
    }
    const color = e.data.startsWith('[tcpdump]') ? '#4fc3f7'
                : e.data.startsWith('[ERROR]')   ? '#ff4444' : '#c9d1d9';
    capAppend(e.data, color);
  };
}

async function stopCapture() {
  if (!capId) return;
  await fetch('/api/capture/stop/' + capId, {method: 'POST'});
  if (capSse) capSse.close();
  clearInterval(capStatsInterval);
  capRunning = false;
  document.getElementById('btnCapStart').disabled = false;
  document.getElementById('btnCapStop').disabled  = true;
  capAppend('\n[Captura detenida por el usuario]', '#ffcc00');
  updateCapStats();  // final update
}

async function readCapture() {
  const file   = document.getElementById('capReadFile').value.trim();
  const filter = document.getElementById('capReadFilter').value.trim();
  if (!file) { capAppend('[ERROR] Especifica la ruta del archivo .pcap', '#ff4444'); return; }
  capClear();
  capAppend('Leyendo archivo...', '#4fc3f7');
  const r = await fetch('/api/capture/read', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({file, filter})
  });
  const j = await r.json();
  if (j.error) { capAppend('[ERROR] ' + j.error, '#ff4444'); return; }
  const sse = new EventSource('/api/capture/stream/' + j.cap_id);
  sse.onmessage = e => {
    if (e.data === '__DONE__') { sse.close(); return; }
    const color = e.data.startsWith('[tcpdump]') ? '#4fc3f7'
                : e.data.startsWith('[ERROR]')   ? '#ff4444' : '#a8ff78';
    capAppend(e.data, color);
  };
}

// ── IDS Suricata ─────────────────────────────────────────────────────────────
let idsRunning = false, idsPoll = null, idsStatsPoll = null, idsAlertIdx = 0;
let idsChartTime = null, idsChartSig = null, idsChartSev = null, idsChartSrc = null;
const SEV_COLORS_IDS = {1:'#e57373',2:'#ffb74d',3:'#4fc3f7',0:'#8b949e'};
const SEV_LABEL = {1:'HIGH',2:'MED',3:'LOW',0:'INFO'};

function idsInitCharts() {
  Chart.defaults.color = '#8b949e';
  Chart.defaults.borderColor = '#21262d';
  idsChartTime = new Chart(document.getElementById('idsChartTime').getContext('2d'), {
    type:'line', data:{labels:[],datasets:[{label:'Alertas/s',data:[],borderColor:'#e57373',backgroundColor:'rgba(229,115,115,.15)',fill:true,tension:.3,pointRadius:0,borderWidth:1.5}]},
    options:{animation:false,scales:{x:{ticks:{maxTicksLimit:10,callback:(v,i)=>{const d=new Date(parseInt(idsChartTime.data.labels[i])*1000);return d.toLocaleTimeString()}}},y:{beginAtZero:true,ticks:{precision:0}}},plugins:{legend:{display:false}}}
  });
  idsChartSig = new Chart(document.getElementById('idsChartSig').getContext('2d'), {
    type:'bar', data:{labels:[],datasets:[{label:'Alertas',data:[],backgroundColor:['#e57373','#ffb74d','#4fc3f7','#81c784','#ce93d8','#fff176','#4dd0e1','#a1887f','#90a4ae','#f48fb1']}]},
    options:{animation:false,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{beginAtZero:true,ticks:{precision:0}}}}
  });
  idsChartSev = new Chart(document.getElementById('idsChartSev').getContext('2d'), {
    type:'doughnut', data:{labels:['High (P1)','Medium (P2)','Low (P3)'],datasets:[{data:[0,0,0],backgroundColor:['#e57373','#ffb74d','#4fc3f7']}]},
    options:{animation:false,plugins:{legend:{position:'right'}}}
  });
  idsChartSrc = new Chart(document.getElementById('idsChartSrc').getContext('2d'), {
    type:'bar', data:{labels:[],datasets:[{label:'Alertas',data:[],backgroundColor:'#ce93d8'}]},
    options:{animation:false,plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,ticks:{precision:0}}}}
  });
}
function idsDestroyCharts(){[idsChartTime,idsChartSig,idsChartSev,idsChartSrc].forEach(c=>{if(c)c.destroy()});idsChartTime=idsChartSig=idsChartSev=idsChartSrc=null;}

async function idsStart() {
  const iface = document.getElementById('idsIface').value;
  document.getElementById('idsAlertBody').innerHTML = '';
  idsAlertIdx = 0;
  document.getElementById('idsStatusText').textContent = 'Iniciando Suricata...';
  const r = await fetch('/api/ids/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({iface})});
  const j = await r.json();
  if (j.error) { document.getElementById('idsStatusText').textContent = j.error; return; }
  idsRunning = true;
  document.getElementById('btnIdsStart').disabled = true;
  document.getElementById('btnIdsStop').disabled  = false;
  document.getElementById('idsCharts').style.display = 'grid';
  idsDestroyCharts(); idsInitCharts();
  document.getElementById('idsStatusText').textContent = 'Suricata activo';
  document.getElementById('idsStatusText').style.color = '#81c784';
  idsPoll      = setInterval(idsPollAlerts, 1500);
  idsStatsPoll = setInterval(idsPollStats, 2500);
}

async function idsStop() {
  await fetch('/api/ids/stop',{method:'POST'});
  idsRunning = false;
  clearInterval(idsPoll); clearInterval(idsStatsPoll);
  document.getElementById('btnIdsStart').disabled = false;
  document.getElementById('btnIdsStop').disabled  = true;
  document.getElementById('idsStatusText').textContent = 'Detenido';
  document.getElementById('idsStatusText').style.color = 'var(--dim)';
  idsPollStats();
}

async function idsPollAlerts() {
  try {
    const r = await fetch('/api/ids/alerts?since='+idsAlertIdx);
    const j = await r.json();
    const tbody = document.getElementById('idsAlertBody');
    const box = document.getElementById('idsAlertBox');
    for (const a of j.alerts) {
      const tr = document.createElement('tr');
      const sc = SEV_COLORS_IDS[a.sev] || '#8b949e';
      tr.innerHTML =
        '<td style="padding:4px 8px;color:var(--dim);white-space:nowrap">'+a.t+'</td>'+
        '<td style="padding:4px 8px;font-weight:bold;color:'+sc+'">'+(SEV_LABEL[a.sev]||'')+'</td>'+
        '<td style="padding:4px 8px;color:#4fc3f7">'+a.src+'</td>'+
        '<td style="padding:4px 8px;color:#81c784">'+a.dst+'</td>'+
        '<td style="padding:4px 8px;color:var(--dim)">'+a.proto+'</td>'+
        '<td style="padding:4px 8px;color:#c9d1d9;word-break:break-all">'+a.msg.replace(/</g,'&lt;')+'</td>';
      tbody.appendChild(tr);
    }
    idsAlertIdx = j.total;
    box.scrollTop = box.scrollHeight;
    document.getElementById('idsTotalAlerts').textContent = j.total + ' alertas';
    if (!j.running && idsRunning) {
      idsRunning = false;
      clearInterval(idsPoll); clearInterval(idsStatsPoll);
      document.getElementById('btnIdsStart').disabled = false;
      document.getElementById('btnIdsStop').disabled  = true;
    }
  } catch(e) {}
}

async function idsPollStats() {
  try {
    const r = await fetch('/api/ids/stats');
    const d = await r.json();
    idsChartTime.data.labels = d.labels;
    idsChartTime.data.datasets[0].data = d.counts;
    idsChartTime.update('none');
    idsChartSig.data.labels = d.top_sig.map(x=>x[0]);
    idsChartSig.data.datasets[0].data = d.top_sig.map(x=>x[1]);
    idsChartSig.update('none');
    idsChartSev.data.datasets[0].data = [d.severity.high, d.severity.medium, d.severity.low];
    idsChartSev.update('none');
    idsChartSrc.data.labels = d.top_src.map(x=>x[0]);
    idsChartSrc.data.datasets[0].data = d.top_src.map(x=>x[1]);
    idsChartSrc.update('none');
  } catch(e) {}
}

window.onload = async () => {
  await loadProfiles();
  await loadClients();
  // Auto-detect existing VPN on load (Tailscale, tun0, wg0, etc.)
  await vpnAutodetect(true);
  pollVpnStatus();
  // Restore engineer name from localStorage
  const saved = localStorage.getItem('engineer');
  if (saved) document.getElementById('engineerInput').value = saved;
  document.getElementById('engineerInput').addEventListener('input', e => {
    localStorage.setItem('engineer', e.target.value);
  });
};

function showTab(name, el) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  el.classList.add('active');
}

function onMapTabOpen() {
  // Auto-populate mapTarget from current scan target if empty
  const cur = document.getElementById('inTarget').value.trim();
  const mt  = document.getElementById('mapTarget');
  if (cur && !mt.value) mt.value = cur;
  // Resize SVG to container
  const c = document.getElementById('mapContainer');
  const s = document.getElementById('networkSvg');
  s.setAttribute('width',  c.clientWidth);
  s.setAttribute('height', c.clientHeight);
}

async function loadProfiles() {
  const r = await fetch('/api/scan/profiles');
  profiles = await r.json();
  const sel = document.getElementById('selProfile');
  sel.innerHTML = '';
  Object.entries(profiles).forEach(([name, cmd]) => {
    const o = document.createElement('option');
    o.value = cmd; o.textContent = name;
    sel.appendChild(o);
  });
  sel.selectedIndex = 5;
  onProfileSelect();
}

function onProfileSelect() {
  document.getElementById('inCommand').value =
    document.getElementById('selProfile').value;
}

async function loadClients() {
  const r = await fetch('/api/clients');
  const clients = await r.json();
  renderClientList(clients);
  renderClientCombo(clients);
  renderVpnCombo(clients);
}

function renderClientList(clients) {
  const el = document.getElementById('clientList');
  el.innerHTML = '';
  Object.entries(clients).forEach(([name, c]) => {
    const item = document.createElement('div');
    item.className = 'client-item';
    item.dataset.name = name;
    item.innerHTML = `<div>
      <div class="client-name">${esc(name)}</div>
      <div class="client-net">${esc(c.network||'Sin red')}</div>
    </div>
    <button class="client-del" onclick="deleteClient('${esc(name)}',event)">✕</button>`;
    item.addEventListener('click', () => selectClient(name, c, item));
    el.appendChild(item);
  });
}

function renderClientCombo(clients) {
  const sel = document.getElementById('selClient');
  const cur = sel.value;
  sel.innerHTML = '<option value="">— Seleccionar —</option>';
  Object.keys(clients).forEach(name => {
    const o = document.createElement('option');
    o.value = name; o.textContent = name;
    sel.appendChild(o);
  });
  if (cur) sel.value = cur;
}

function renderVpnCombo(clients) {
  const sel = document.getElementById('vpnSelClient');
  sel.innerHTML = '';
  Object.keys(clients).forEach(name => {
    const o = document.createElement('option');
    o.value = name; o.textContent = name;
    sel.appendChild(o);
  });
}

function selectClient(name, c, item) {
  document.querySelectorAll('.client-item').forEach(i => i.classList.remove('active'));
  item.classList.add('active');
  document.getElementById('cf_name').value          = name;
  document.getElementById('cf_network').value       = c.network       || '';
  document.getElementById('cf_desc').value          = c.desc          || '';
  document.getElementById('cf_vpntype').value       = c.vpn_type      || 'OpenVPN';
  document.getElementById('cf_vpnuser').value       = c.vpn_user      || '';
  document.getElementById('cf_vpnpass').value       = c.vpn_pass      || '';
  document.getElementById('cf_nebula_ip').value     = c.nebula_ip     || '';
  document.getElementById('cf_nebula_groups').value = c.nebula_groups || 'clients';
  document.getElementById('clientFormTitle').textContent = 'Editar: ' + name;
  document.getElementById('selClient').value  = name;
  document.getElementById('inTarget').value   = c.network  || '';
  onVpnTypeChange();
}

function onClientSelect() {
  const name = document.getElementById('selClient').value;
  fetch('/api/clients').then(r => r.json()).then(clients => {
    if (clients[name]) document.getElementById('inTarget').value = clients[name].network || '';
  });
}

function newClient() {
  document.getElementById('clientFormEl').reset();
  document.getElementById('clientFormTitle').textContent = 'Nuevo cliente';
  document.querySelectorAll('.client-item').forEach(i => i.classList.remove('active'));
}

async function saveClient(e) {
  e.preventDefault();
  const r = await fetch('/api/clients', {method:'POST', body: new FormData(document.getElementById('clientFormEl'))});
  const j = await r.json();
  if (j.error) { alert(j.error); return; }
  setStatus('Cliente guardado.');
  await loadClients();
}

async function deleteClient(name, e) {
  e.stopPropagation();
  if (!confirm(`¿Eliminar cliente "${name}"?`)) return;
  await fetch('/api/clients/' + encodeURIComponent(name), {method:'DELETE'});
  await loadClients();
}

// VPN
function openVpnModal()  {
  document.getElementById('vpnModal').classList.add('open');
  vpnAutodetect(false);
}
function closeVpnModal() { document.getElementById('vpnModal').classList.remove('open'); }

async function vpnAutodetect(silent) {
  try {
    const r = await fetch('/api/vpn/autodetect', {method:'POST'});
    const j = await r.json();
    updateVpnBadge(j);
    // Render detected interfaces in modal
    const block = document.getElementById('vpnDetectedBlock');
    const list  = document.getElementById('vpnDetectedList');
    if (j.interfaces && j.interfaces.length > 0) {
      block.style.display = 'block';
      list.innerHTML = j.interfaces.map(i => `
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <span style="background:#1a3a1a;color:var(--green);border-radius:4px;
                padding:2px 8px;font-family:'Courier New',monospace;font-size:.82rem;font-weight:700">
            ● ${i.iface}
          </span>
          <span style="color:var(--fg);font-family:'Courier New',monospace;font-size:.82rem">
            ${i.ip}
          </span>
        </div>`).join('');
      if (!silent)
        document.getElementById('vpnInfo').textContent =
          `${j.interfaces.length} interfaz(ces) VPN activa(s) detectada(s).`;
    } else {
      block.style.display = 'none';
      if (!silent)
        document.getElementById('vpnInfo').textContent = 'No se detectaron interfaces VPN activas.';
    }
    if (j.detected && silent) setStatus(`VPN detectada: ${j.iface} (${j.ip || ''})`);
  } catch(e) {
    if (!silent) console.error('autodetect error', e);
  }
}

async function connectVpn() {
  const client = document.getElementById('vpnSelClient').value;
  if (!client) { alert('Selecciona un cliente'); return; }
  document.getElementById('vpnInfo').textContent = 'Conectando VPN...';
  const r = await fetch('/api/vpn/connect', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({client})
  });
  const j = await r.json();
  document.getElementById('vpnInfo').textContent = j.msg || j.error || '';
  let tries = 0;
  const poll = setInterval(async () => {
    const s = await (await fetch('/api/vpn/status')).json();
    if (s.active) {
      clearInterval(poll);
      updateVpnBadge(s);
      document.getElementById('vpnInfo').textContent = 'VPN activa — ' + s.ip;
      setStatus('VPN activa: ' + s.client);
    } else if (++tries > 25) {
      clearInterval(poll);
      document.getElementById('vpnInfo').textContent = 'Tiempo agotado — verifica la config VPN.';
    }
  }, 2000);
}

async function disconnectVpn() {
  await fetch('/api/vpn/disconnect', {method:'POST'});
  updateVpnBadge({active:false});
  document.getElementById('vpnInfo').textContent = 'VPN desconectada.';
  setStatus('VPN desconectada.');
}

async function pollVpnStatus() {
  try { updateVpnBadge(await (await fetch('/api/vpn/status')).json()); } catch {}
  setTimeout(pollVpnStatus, 5000);
}

function updateVpnBadge(s) {
  const b = document.getElementById('vpnBadge');
  b.className = 'badge-vpn ' + (s.active ? 'on' : 'off');
  b.textContent = s.active ? '● VPN: ' + (s.client || 'Activa') : '● VPN Inactiva';
}

// Scanner
async function startScan() {
  const target   = document.getElementById('inTarget').value.trim();
  const command  = document.getElementById('inCommand').value.trim();
  const client   = document.getElementById('selClient').value;
  const profile  = document.getElementById('selProfile').selectedOptions[0]?.textContent || '';
  const engineer = document.getElementById('engineerInput').value.trim();

  if (!target)   { alert('Ingresa un objetivo.'); return; }
  if (!command)  { alert('Selecciona un perfil o escribe un comando.'); return; }
  if (!engineer) {
    if (!confirm('No has ingresado el nombre del ingeniero.\n¿Continuar de todas formas?')) return;
  }

  clearOutput();
  resetStats();
  const r = await fetch('/api/scan/start', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({target, command, client, profile, engineer})
  });
  const j = await r.json();
  if (j.error) { alert(j.error); return; }

  currentScanId = j.scan_id;
  scanRunning = true;
  startTime = Date.now();
  document.getElementById('btnScan').disabled = true;
  document.getElementById('btnStop').disabled = false;
  document.getElementById('progressBar').classList.add('running');
  // Hide export buttons during scan
  ['btnPdf','btnTxt','btnJson','btnHtml','btnExec'].forEach(id =>
    document.getElementById(id).style.display = 'none');
  startTimer();
  streamScan(currentScanId);
}

function streamScan(scanId) {
  if (sseSource) sseSource.close();
  sseSource = new EventSource('/api/scan/stream/' + scanId);
  sseSource.onmessage = e => {
    const data = JSON.parse(e.data);
    if (data.done) {
      if (data.device_list) renderDeviceChips(data.device_list);
      updateStats(data.devices ?? knownDevices.size, null, 100);
      scanDone();
      return;
    }
    appendLine(data.line, data.sev);
    if (['CRITICAL','HIGH','MEDIUM'].includes(data.sev)) appendFinding(data.line, data.sev);
    // Update live counters
    if (data.devices !== undefined) updateStats(data.devices, data.eta, data.percent);
    // Device chip — detect new host from line text too
    detectDeviceChip(data.line);
  };
  sseSource.onerror = () => { sseSource.close(); scanDone(); };
}

async function stopScan() {
  if (!currentScanId) return;
  await fetch('/api/scan/stop/' + currentScanId, {method:'POST'});
  if (sseSource) sseSource.close();
  scanDone();
  appendLine('\n[!] Escaneo detenido por el usuario.\n', 'HEADER');
}

function scanDone() {
  scanRunning = false;
  document.getElementById('btnScan').disabled = false;
  document.getElementById('btnStop').disabled = true;
  document.getElementById('progressBar').classList.remove('running');
  clearInterval(timerInterval);
  setStatus('Escaneo finalizado.');
  // Show export buttons
  document.getElementById('btnPdf').style.display  = 'inline-flex';
  document.getElementById('btnTxt').style.display  = 'inline-flex';
  document.getElementById('btnJson').style.display = 'inline-flex';
  document.getElementById('btnHtml').style.display = 'inline-flex';
  document.getElementById('btnExec').style.display = 'inline-flex';
}

function startTimer() {
  clearInterval(timerInterval);
  timerInterval = setInterval(() => {
    const s  = Math.floor((Date.now() - startTime) / 1000);
    const m  = String(Math.floor(s/60)).padStart(2,'0');
    const ss = String(s%60).padStart(2,'0');
    const fmt = `${m}:${ss}`;
    document.getElementById('elapsedText').textContent  = `Duración: ${fmt}`;
    document.getElementById('scanStatus').textContent   = `Escaneando... ${fmt}`;
    document.getElementById('statElapsed').textContent  = fmt;
  }, 1000);
}

// ── Stats counters ────────────────────────────────────────────────────────────
function resetStats() {
  knownDevices.clear();
  document.getElementById('statDevices').textContent = '0';
  document.getElementById('statEta').textContent     = '—';
  document.getElementById('statEta').className       = 'stat-value eta unknown';
  document.getElementById('statPercent').textContent = '—';
  document.getElementById('statElapsed').textContent = '00:00';
  document.getElementById('progFill').style.width    = '0%';
  document.getElementById('progPct').textContent     = '0%';
  document.getElementById('progLabel').textContent   = 'Escaneando...';
  document.getElementById('deviceChips').innerHTML   = '';
}

function updateStats(deviceCount, eta, percent) {
  // Devices
  const dEl = document.getElementById('statDevices');
  if (deviceCount !== undefined && deviceCount !== null) {
    const prev = parseInt(dEl.textContent) || 0;
    dEl.textContent = deviceCount;
    if (deviceCount > prev) {
      dEl.style.transform = 'scale(1.4)';
      setTimeout(() => dEl.style.transform = '', 300);
    }
  }
  // ETA
  if (eta) {
    const etaEl = document.getElementById('statEta');
    etaEl.textContent = eta;
    etaEl.className   = 'stat-value eta';
  }
  // Percent
  if (percent !== undefined && percent !== null && percent > 0) {
    const pct = Math.min(100, parseFloat(percent)).toFixed(1);
    document.getElementById('statPercent').textContent = pct + '%';
    document.getElementById('progFill').style.width    = pct + '%';
    document.getElementById('progPct').textContent     = pct + '%';
    document.getElementById('progLabel').textContent   =
      percent >= 100 ? 'Completado' : 'Progreso del escaneo';
  }
}

function detectDeviceChip(line) {
  // Parse host from nmap / nikto output lines
  const patterns = [
    /Nmap scan report for (.+)/,
    /\+ Target IP:\s*(\S+)/,
    /Host:\s*(\S+)\s*\(\)/,
  ];
  for (const re of patterns) {
    const m = line.match(re);
    if (m) {
      const host = m[1].trim();
      if (!knownDevices.has(host)) {
        knownDevices.add(host);
        addDeviceChip(host);
        // Pulse the counter
        document.getElementById('statDevices').textContent = knownDevices.size;
      }
      break;
    }
  }
}

function addDeviceChip(host) {
  const chips = document.getElementById('deviceChips');
  const chip  = document.createElement('span');
  chip.className   = 'device-chip';
  chip.textContent = host;
  chip.title       = 'Click para usar como objetivo';
  chip.onclick     = () => { document.getElementById('inTarget').value = host; };
  chips.appendChild(chip);
  chips.scrollLeft = chips.scrollWidth;
}

function renderDeviceChips(list) {
  const chips = document.getElementById('deviceChips');
  chips.innerHTML = '';
  knownDevices.clear();
  list.forEach(h => { knownDevices.add(h); addDeviceChip(h); });
  document.getElementById('statDevices').textContent = list.length;
}

function appendLine(line, sev) {
  const term = document.getElementById('terminal');
  const span = document.createElement('span');
  span.className = sev === 'HEADER' ? 'line-HEADER' : 'line-' + (sev||'INFO');
  span.textContent = line + '\n';
  term.appendChild(span);
  term.scrollTop = term.scrollHeight;
}

function appendFinding(line, sev) {
  const fl = document.getElementById('findingsList');
  const item = document.createElement('div');
  item.className = 'finding-item sev-' + sev;
  item.innerHTML = `<strong>${sev}</strong><br>${esc(line.trim())}`;
  fl.appendChild(item);
  fl.scrollTop = fl.scrollHeight;
}

function clearOutput() {
  document.getElementById('terminal').innerHTML =
    '<span style="color:var(--dim)">Listo.\n</span>';
  clearFindings();
  document.getElementById('elapsedText').textContent = '';
  document.getElementById('scanStatus').textContent  = '';
  ['btnPdf','btnTxt','btnJson','btnHtml','btnExec'].forEach(id =>
    document.getElementById(id).style.display = 'none');
  setStatus('Listo.');
}

function clearFindings() { document.getElementById('findingsList').innerHTML = ''; }

// History
async function loadHistory() {
  const scans = await (await fetch('/api/scan/list')).json();
  const tbody = document.getElementById('historyBody');
  tbody.innerHTML = '';
  scans.forEach(s => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${s.id}</code></td>
      <td>${esc(s.engineer||'—')}</td>
      <td>${esc(s.client||'—')}</td>
      <td>${esc(s.target)}</td>
      <td style="font-size:.78rem">${esc(s.profile)}</td>
      <td style="font-size:.78rem">${s.start}</td>
      <td><span class="badge ${s.done?'badge-done':'badge-run'}">${s.done?'Completado':'En curso'}</span></td>
      <td style="display:flex;gap:5px;flex-wrap:wrap">
        <button class="btn btn-pdf btn-sm" onclick="exportById('${s.id}','pdf')">&#x1F4C4; PDF</button>
        <button class="btn btn-green btn-sm" onclick="exportById('${s.id}','exec')" title="Reporte ejecutivo para Gerencia">&#x1F4CA; Ejecutivo</button>
        <button class="btn btn-gray btn-sm" onclick="exportById('${s.id}','txt')">TXT</button>
        <button class="btn btn-gray btn-sm" onclick="replayScan('${s.id}')">Ver</button>
      </td>`;
    tbody.appendChild(tr);
  });
}

function replayScan(id) {
  currentScanId = id;
  clearOutput();
  showTab('scanner', document.getElementById('tab-btn-scanner'));
  streamScan(id);
  document.getElementById('btnPdf').style.display  = 'inline-flex';
  document.getElementById('btnTxt').style.display  = 'inline-flex';
  document.getElementById('btnJson').style.display = 'inline-flex';
  document.getElementById('btnHtml').style.display = 'inline-flex';
  document.getElementById('btnExec').style.display = 'inline-flex';
}

function exportScan(fmt)      { exportById(currentScanId, fmt); }
function exportById(id, fmt)  {
  if (!id) { alert('No hay escaneo seleccionado.'); return; }
  window.open('/api/scan/export/' + id + '?fmt=' + fmt);
}

// ── Ping ──────────────────────────────────────────────────────────────────────
function _pingSetStatus(dot, text, color) {
  document.getElementById('pingDot').className = 'ping-dot ' + dot;
  const st = document.getElementById('pingStatusText');
  st.textContent = text;
  st.style.color = color || 'var(--dim)';
}

function _pingAppendLine(text, type) {
  const out = document.getElementById('pingOutput');
  const cls = {success:'ping-line-success', error:'ping-line-error',
               header:'ping-line-header', info:'ping-line-info'}[type] || 'ping-line-info';
  const div = document.createElement('div');
  div.className = 'ping-console-line ' + cls;
  div.textContent = text;
  out.appendChild(div);
  out.scrollTop = out.scrollHeight;
}

function doPing() {
  const host  = document.getElementById('pingHost').value.trim();
  const count = document.getElementById('pingCount').value;
  if (!host) { document.getElementById('pingHost').focus(); return; }

  const out = document.getElementById('pingOutput');
  const btn = document.getElementById('btnPing');

  // Reset console
  out.innerHTML = '';
  out.classList.add('visible');
  btn.classList.add('running');
  btn.disabled = true;
  _pingSetStatus('waiting', `Enviando ping a ${host}...`, 'var(--dim)');

  // Pre-fill scan target
  const tf = document.getElementById('inTarget');
  if (!tf.value) tf.value = host;

  fetch('/api/ping', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({host, count: parseInt(count)})
  }).then(res => {
    const reader  = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';

    function readChunk() {
      reader.read().then(({done, value}) => {
        if (done) { btn.classList.remove('running'); btn.disabled = false; return; }
        buf += decoder.decode(value, {stream: true});
        const parts = buf.split('\n\n');
        buf = parts.pop();
        parts.forEach(part => {
          const m = part.match(/^data: (.+)$/m);
          if (!m) return;
          try {
            const d = JSON.parse(m[1]);
            if (d.done) {
              const ok = d.type === 'success';
              _pingSetStatus(ok ? 'ok' : 'fail', d.line, ok ? 'var(--green)' : 'var(--red)');
              _pingAppendLine(d.line, d.type);
              btn.classList.remove('running');
              btn.disabled = false;
              setStatus(ok ? `✓ ${host} responde al ping` : `✗ ${host} no responde`);
            } else {
              _pingAppendLine(d.line, d.type);
              _pingSetStatus('waiting', d.line, 'var(--dim)');
            }
          } catch {}
        });
        readChunk();
      });
    }
    readChunk();
  }).catch(e => {
    _pingAppendLine('Error de conexión: ' + String(e), 'error');
    _pingSetStatus('fail', 'Error', 'var(--red)');
    btn.classList.remove('running');
    btn.disabled = false;
  });
}

function clearPing() {
  const out = document.getElementById('pingOutput');
  out.innerHTML = '';
  out.classList.remove('visible');
  document.getElementById('pingHost').value = '';
  _pingSetStatus('waiting', 'Introduce una IP y pulsa Ping', 'var(--dim)');
}

function setStatus(msg) { document.getElementById('statusText').textContent = msg; }
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Network Map (D3.js v7) ────────────────────────────────────────────────────
const NODE_CFG = {
  gateway:  {fill:'#8b1a1a', stroke:'#f85149', r:30, label:'Gateway / Firewall', icon:'⬡'},
  web:      {fill:'#1a3a6b', stroke:'#58a6ff', r:22, label:'Web Server',          icon:'⊛'},
  windows:  {fill:'#5a3200', stroke:'#f0883e', r:22, label:'Windows / SMB',       icon:'⊞'},
  linux:    {fill:'#0e3a1a', stroke:'#3fb950', r:22, label:'Linux / SSH',         icon:'$'},
  database: {fill:'#2e1a5a', stroke:'#bc8cff', r:22, label:'Base de Datos',       icon:'◈'},
  unknown:  {fill:'#161b22', stroke:'#6e7681', r:16, label:'Desconocido',         icon:'?'},
};
let _mapSim = null, _mapZoom = null;

async function startNetworkMap() {
  const target = document.getElementById('mapTarget').value.trim();
  if (!target) { document.getElementById('mapTarget').focus(); return; }
  const btn = document.getElementById('btnMapScan');
  btn.disabled = true;
  document.getElementById('mapEmpty').style.display = 'none';
  setMapStatus('Iniciando escaneo...', true);
  let r, j;
  try {
    r = await fetch('/api/network/scan', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({target})
    });
    j = await r.json();
  } catch(e) { setMapStatus('Error de red', false); btn.disabled=false; return; }
  if (j.error) { setMapStatus('Error: '+j.error, false); btn.disabled=false; return; }
  const sse = new EventSource('/api/network/stream/'+j.map_id);
  sse.onmessage = e => {
    const d = JSON.parse(e.data);
    if (d.type === 'status') {
      setMapStatus(d.msg, true);
    } else if (d.type === 'result') {
      sse.close(); btn.disabled = false;
      setMapStatus(d.summary || (d.nodes.length + ' hosts activos'), false);
      renderNetworkGraph(d.nodes, d.edges);
      renderHostTable(d.nodes);
    } else if (d.error) {
      sse.close(); btn.disabled = false;
      setMapStatus('Error: '+d.error, false);
    }
  };
  sse.onerror = () => { sse.close(); btn.disabled=false; setMapStatus('Error SSE', false); };
}

function renderNetworkGraph(nodes, edges) {
  if (_mapSim) { _mapSim.stop(); _mapSim = null; }
  const container = document.getElementById('mapContainer');
  const W = container.clientWidth  || 900;
  const H = container.clientHeight || 600;
  const svg = d3.select('#networkSvg').attr('width',W).attr('height',H);
  svg.selectAll('*').remove();
  svg.append('rect').attr('width',W).attr('height',H).attr('fill','#090d13');
  if (!nodes.length) {
    document.getElementById('mapEmpty').style.display = 'block';
    document.getElementById('mapEmpty').querySelector('.em-text').textContent = 'Sin hosts activos';
    return;
  }
  // ── Defs ──
  const defs = svg.append('defs');
  Object.entries(NODE_CFG).forEach(([t,c]) => {
    if (t==='unknown') return;
    const f = defs.append('filter').attr('id','glow-'+t).attr('x','-40%').attr('y','-40%').attr('width','180%').attr('height','180%');
    f.append('feGaussianBlur').attr('stdDeviation',5).attr('result','blur');
    const m = f.append('feMerge');
    m.append('feMergeNode').attr('in','blur');
    m.append('feMergeNode').attr('in','SourceGraphic');
  });
  // Gradient for gateway
  const gwg = defs.append('radialGradient').attr('id','gwGrad').attr('cx','35%').attr('cy','35%').attr('r','65%');
  gwg.append('stop').attr('offset','0%').attr('stop-color','#c03030');
  gwg.append('stop').attr('offset','100%').attr('stop-color','#5a0a0a');
  // ── Zoom ──
  const g = svg.append('g');
  _mapZoom = d3.zoom().scaleExtent([0.1, 6])
    .on('zoom', ev => g.attr('transform', ev.transform));
  svg.call(_mapZoom);
  svg.on('dblclick.zoom', () => fitGraph(svg, g, W, H));
  // ── Build node lookup ──
  const byIp = {};
  nodes.forEach(n => {
    byIp[n.ip] = n;
    n.x = W/2 + (Math.random()-.5)*280;
    n.y = H/2 + (Math.random()-.5)*280;
  });
  // ── Links ──
  const linkSel = g.append('g')
    .selectAll('line').data(edges).join('line')
    .attr('stroke','#2a3140').attr('stroke-width',2).attr('opacity',.9);
  // ── Node groups ──
  const nodeSel = g.append('g')
    .selectAll('g').data(nodes).join('g')
    .style('cursor','pointer')
    .call(d3.drag()
      .on('start',(ev,d)=>{ if(!ev.active)sim.alphaTarget(.3).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag', (ev,d)=>{ d.fx=ev.x; d.fy=ev.y; })
      .on('end',  (ev,d)=>{ if(!ev.active)sim.alphaTarget(0); d.fx=null; d.fy=null; })
    );
  // Outer pulse ring (gateway only)
  nodeSel.filter(d=>d.type==='gateway').append('circle')
    .attr('r', d=>NODE_CFG[d.type].r+10)
    .attr('fill','none').attr('stroke','#f85149').attr('stroke-width',1.5).attr('opacity',.25);
  // Main circle
  nodeSel.append('circle')
    .attr('r', d=>(NODE_CFG[d.type]||NODE_CFG.unknown).r)
    .attr('fill', d=>d.type==='gateway'?'url(#gwGrad)':(NODE_CFG[d.type]||NODE_CFG.unknown).fill)
    .attr('stroke', d=>(NODE_CFG[d.type]||NODE_CFG.unknown).stroke)
    .attr('stroke-width', 2.2)
    .attr('filter', d=>d.type!=='unknown'?'url(#glow-'+d.type+')':null);
  // Port indicator dots (satellite dots)
  nodeSel.each(function(d) {
    const cr = (NODE_CFG[d.type]||NODE_CFG.unknown).r;
    (d.ports||[]).slice(0,8).forEach((p,i,arr) => {
      const angle = (i/arr.length)*2*Math.PI - Math.PI/2;
      const or = cr + 13;
      d3.select(this).append('circle')
        .attr('cx', Math.cos(angle)*or).attr('cy', Math.sin(angle)*or)
        .attr('r',4).attr('fill',portColor(p.port))
        .attr('stroke','#090d13').attr('stroke-width',1.2)
        .append('title').text(p.port+'/'+p.service);
    });
  });
  // Type icon
  nodeSel.append('text')
    .attr('text-anchor','middle').attr('dominant-baseline','central')
    .attr('font-size', d=>d.type==='gateway'?'15px':'13px')
    .attr('fill','rgba(255,255,255,.85)').attr('pointer-events','none')
    .attr('font-weight','bold')
    .text(d=>(NODE_CFG[d.type]||NODE_CFG.unknown).icon);
  // IP label
  nodeSel.append('text')
    .attr('y', d=>(NODE_CFG[d.type]||NODE_CFG.unknown).r+16)
    .attr('text-anchor','middle').attr('font-size','11px')
    .attr('fill','#8b949e').attr('pointer-events','none')
    .attr('font-family',"'Courier New',monospace")
    .text(d=>d.ip);
  // Hostname label (if available)
  nodeSel.filter(d=>!!d.hostname).append('text')
    .attr('y', d=>(NODE_CFG[d.type]||NODE_CFG.unknown).r+28)
    .attr('text-anchor','middle').attr('font-size','10px')
    .attr('fill','#6e7681').attr('pointer-events','none')
    .text(d=>d.hostname.length>22?d.hostname.slice(0,22)+'…':d.hostname);
  // ── Tooltip ──
  nodeSel
    .on('mouseenter', (ev,d)=>{ showNodeTooltip(ev,d); })
    .on('mousemove',  ev  =>{ moveNodeTooltip(ev); })
    .on('mouseleave', ()  =>{ document.getElementById('nodeTooltip').style.display='none'; });
  // ── Simulation ──
  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(edges).id(d=>d.ip)
      .distance(d=>{
        const s = typeof d.source==='object'?d.source:byIp[d.source];
        const t = typeof d.target==='object'?d.target:byIp[d.target];
        return (s?.type==='gateway'||t?.type==='gateway') ? 170 : 110;
      }).strength(.55))
    .force('charge', d3.forceManyBody().strength(-700).distanceMax(400))
    .force('center', d3.forceCenter(W/2, H/2).strength(.05))
    .force('collide', d3.forceCollide().radius(d=>(NODE_CFG[d.type]||NODE_CFG.unknown).r+50).strength(.8))
    .on('tick', ()=>{
      linkSel.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
             .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
      nodeSel.attr('transform',d=>`translate(${d.x},${d.y})`);
    });
  _mapSim = sim;
  // Auto-fit after 2 s
  setTimeout(()=>fitGraph(svg, g, W, H), 2200);
}

function fitGraph(svg, g, W, H) {
  try {
    const bb = g.node().getBBox();
    if (bb.width<2 || bb.height<2) return;
    const pad = 80;
    const sc  = Math.min(.95, Math.min((W-pad)/(bb.width+pad), (H-pad)/(bb.height+pad)));
    const tx  = W/2 - sc*(bb.x+bb.width/2);
    const ty  = H/2 - sc*(bb.y+bb.height/2);
    svg.transition().duration(700)
      .call(_mapZoom.transform, d3.zoomIdentity.translate(tx,ty).scale(sc));
  } catch(e){}
}

function showNodeTooltip(ev, d) {
  const cfg = NODE_CFG[d.type] || NODE_CFG.unknown;
  document.getElementById('ttTitle').innerHTML =
    `<span style="color:${cfg.stroke}">${cfg.icon}&nbsp;${d.ip}</span>`;
  let html = `<div class="tt-row"><b>Tipo:</b>${cfg.label}</div>`;
  if (d.hostname) html += `<div class="tt-row"><b>Hostname:</b>${esc(d.hostname)}</div>`;
  if (d.mac)      html += `<div class="tt-row"><b>MAC:</b><span style="font-family:'Courier New',monospace;color:var(--yellow)">${esc(d.mac)}</span></div>`;
  if (d.vendor)   html += `<div class="tt-row"><b>Vendor:</b>${esc(d.vendor)}</div>`;
  if (d.ports && d.ports.length) {
    html += '<div class="tt-row"><b>Puertos:</b><br>';
    html += d.ports.map(p=>
      `<span class="tt-port" style="border-color:${portColor(p.port)};color:${portColor(p.port)}">${p.port}/${p.service}</span>`
    ).join('');
    html += '</div>';
  } else {
    html += '<div class="tt-row" style="color:var(--dim)"><i>Sin puertos abiertos detectados</i></div>';
  }
  document.getElementById('ttContent').innerHTML = html;
  document.getElementById('nodeTooltip').style.display = 'block';
  moveNodeTooltip(ev);
}

function moveNodeTooltip(ev) {
  const c  = document.getElementById('mapContainer').getBoundingClientRect();
  const tt = document.getElementById('nodeTooltip');
  let x = ev.clientX - c.left + 18;
  let y = ev.clientY - c.top  - 12;
  if (x + 300 > c.width)  x = ev.clientX - c.left - 306;
  if (y + 230 > c.height) y = ev.clientY - c.top  - 234;
  tt.style.left = Math.max(0,x) + 'px';
  tt.style.top  = Math.max(0,y) + 'px';
}

function portColor(port) {
  if ([80,8080,8000].includes(port))          return '#58a6ff';
  if ([443,8443].includes(port))              return '#3fb950';
  if (port===22)                              return '#e3b341';
  if ([445,3389].includes(port))             return '#f0883e';
  if ([3306,5432,27017,1521].includes(port)) return '#bc8cff';
  if (port===21)                             return '#f85149';
  if ([25,110,143].includes(port))           return '#ffa657';
  return '#6e7681';
}

function setMapStatus(msg, spin) {
  const el = document.getElementById('mapStatus');
  el.textContent = (spin ? '⟳ ' : '') + msg;
  el.style.color = spin ? 'var(--blue)' : 'var(--dim)';
}

function resetMapView() {
  const c   = document.getElementById('mapContainer');
  const svg = d3.select('#networkSvg');
  svg.transition().duration(500)
    .call(_mapZoom.transform, d3.zoomIdentity.translate(c.clientWidth/2, c.clientHeight/2).scale(1));
}

// ── Host Inventory Table (Advanced IP Scanner style) ─────────────────────────
let _lastMapNodes = [];
let _hostSortCol = 'ip', _hostSortAsc = true;

function toggleMapView(mode) {
  const graph = document.getElementById('mapContainer');
  const table = document.getElementById('hostTableContainer');
  if (mode === 'graph') {
    graph.style.display = ''; table.style.display = 'none';
    graph.style.flex = '1';
  } else if (mode === 'table') {
    graph.style.display = 'none'; table.style.display = '';
    table.style.flex = '1'; table.style.maxHeight = '100%';
  } else {
    graph.style.display = ''; graph.style.flex = '1';
    table.style.display = ''; table.style.maxHeight = '45%'; table.style.flex = 'none';
  }
}

function renderHostTable(nodes) {
  _lastMapNodes = nodes;
  const tbody = document.getElementById('hostTableBody');
  if (!nodes.length) { tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--dim);padding:20px">Sin hosts detectados</td></tr>'; return; }
  // Show table container
  const mode = document.getElementById('mapViewMode').value;
  if (mode !== 'graph') document.getElementById('hostTableContainer').style.display = '';
  // Sort
  const sorted = [...nodes].sort((a,b) => {
    let va = a[_hostSortCol] || '', vb = b[_hostSortCol] || '';
    if (_hostSortCol === 'ip') {
      const pa = va.split('.').map(Number), pb = vb.split('.').map(Number);
      for (let i=0;i<4;i++) { if (pa[i]!==pb[i]) return _hostSortAsc ? pa[i]-pb[i] : pb[i]-pa[i]; }
      return 0;
    }
    va = va.toString().toLowerCase(); vb = vb.toString().toLowerCase();
    return _hostSortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
  });
  const typeCfg = {
    gateway:{bg:'#3a1a1a',fg:'#f85149',label:'Gateway'},
    web:{bg:'#1a2a4a',fg:'#58a6ff',label:'Web'},
    windows:{bg:'#3a2800',fg:'#f0883e',label:'Windows'},
    linux:{bg:'#0e2a1a',fg:'#3fb950',label:'Linux'},
    database:{bg:'#2a1a4a',fg:'#bc8cff',label:'DB'},
    unknown:{bg:'var(--bg3)',fg:'var(--dim)',label:'?'},
  };
  tbody.innerHTML = sorted.map(h => {
    const tc = typeCfg[h.type] || typeCfg.unknown;
    const ports = (h.ports||[]).map(p => `<span class="host-port-badge">${p.port}/${p.service}</span>`).join('');
    const status = (h.status === 'up' || h.ports?.length > 0 || !h.status)
      ? '<span class="host-status-up">&#x25CF;</span>'
      : '<span class="host-status-down">&#x25CB;</span>';
    return `<tr>
      <td style="text-align:center">${status}</td>
      <td style="font-weight:600">${esc(h.hostname || '\u2014')}</td>
      <td style="font-family:'Courier New',monospace;font-weight:600">${esc(h.ip)}</td>
      <td>${esc(h.vendor || '\u2014')}</td>
      <td class="host-mac">${esc(h.mac || '\u2014')}</td>
      <td><div class="host-ports">${ports || '<span style="color:var(--dim)">\u2014</span>'}</div></td>
      <td><span class="host-type-badge" style="background:${tc.bg};color:${tc.fg}">${tc.label}</span></td>
    </tr>`;
  }).join('');
}

function sortHostTable(col) {
  if (_hostSortCol === col) _hostSortAsc = !_hostSortAsc;
  else { _hostSortCol = col; _hostSortAsc = true; }
  renderHostTable(_lastMapNodes);
}

async function startProbeScan() {
  const target = document.getElementById('mapTarget').value.trim();
  if (!target) { document.getElementById('mapTarget').focus(); return; }
  const btn = document.getElementById('btnProbeScan');
  btn.disabled = true;
  document.getElementById('mapEmpty').style.display = 'none';
  setMapStatus('Consultando sonda local...', true);
  try {
    const r = await fetch('/api/network/probe-scan', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({target})
    });
    const j = await r.json();
    if (j.error) { setMapStatus('Error: '+j.error, false); btn.disabled=false; return; }
    setMapStatus(`Modo: ${j.mode === 'probe' ? 'Sonda local' : 'Remoto'} — esperando...`, true);
    const sse = new EventSource('/api/network/stream/'+j.map_id);
    sse.onmessage = e => {
      const d = JSON.parse(e.data);
      if (d.type === 'status') {
        setMapStatus(d.msg, true);
      } else if (d.type === 'result') {
        sse.close(); btn.disabled = false;
        setMapStatus(d.summary || (d.nodes.length + ' hosts'), false);
        renderNetworkGraph(d.nodes, d.edges);
        renderHostTable(d.nodes);
        // Auto-switch to both view if table was hidden
        const sel = document.getElementById('mapViewMode');
        if (sel.value === 'graph') { sel.value = 'both'; toggleMapView('both'); }
      } else if (d.error) {
        sse.close(); btn.disabled = false;
        setMapStatus('Error: '+d.error, false);
      }
    };
    sse.onerror = () => { sse.close(); btn.disabled=false; setMapStatus('Error SSE', false); };
  } catch(e) { setMapStatus('Error de red', false); btn.disabled=false; }
}

// ── Nebula VPN Tab ────────────────────────────────────────────────────────────

function onVpnTypeChange() {
  const t = document.getElementById('cf_vpntype').value;
  const isNebula = (t === 'Nebula');
  document.getElementById('nebula_fields').style.display    = isNebula ? '' : 'none';
  document.getElementById('classic_vpn_fields').style.display = isNebula ? 'none' : '';
}

function fixCIDR(input) {
  let v = input.value.trim();
  if (!v) return;
  // Si no tiene máscara, agregar /24 por defecto
  if (v && !v.includes('/')) {
    v = v + '/24';
    input.value = v;
  }
  // Validación visual rápida
  const ok = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(v);
  input.style.borderColor = ok ? 'var(--green)' : 'var(--red)';
}

async function loadNebulaTab() {
  await loadNebulaStatus();
  await loadNebulaCerts();
}

async function loadNebulaStatus() {
  try {
    const r = await fetch('/api/nebula/status');
    const d = await r.json();
    const yn = (v) => `<span style="font-weight:700;color:${v ? 'var(--green)' : 'var(--red)'}">${v ? '✓' : '✗'}</span>`;
    document.getElementById('ns_proc').innerHTML  = yn(d.running);
    document.getElementById('ns_iface').innerHTML = yn(d.iface_up);
    document.getElementById('ns_ip').textContent  = d.ip || '—';
    document.getElementById('ns_ca').innerHTML    = yn(d.ca_ok);
    document.getElementById('ns_bin').innerHTML   = yn(d.nebula_bin);
    // Mostrar panel de inicialización sólo si la CA falta
    document.getElementById('nebula_init_panel').style.display = d.ca_ok ? 'none' : '';
  } catch(e) { console.error('nebula status', e); }
}

async function nebulaInitCA() {
  const btn  = document.getElementById('btnNebulaInit');
  const log  = document.getElementById('ni_log');
  const name = document.getElementById('ni_ca_name').value.trim();
  const ip   = document.getElementById('ni_server_ip').value.trim();
  const dur  = document.getElementById('ni_dur').value;

  btn.disabled = true;
  log.style.display = '';
  log.innerHTML = '';

  const addLine = (msg, cls) => {
    const line = document.createElement('div');
    line.textContent = msg;
    if (cls === 'ok')    line.style.color = 'var(--green)';
    if (cls === 'error') line.style.color = 'var(--red)';
    if (cls === 'warn')  line.style.color = 'var(--yellow)';
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
  };

  try {
    const res = await fetch('/api/nebula/setup', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ca_name: name, server_ip: ip, duration: dur})
    });
    const reader = res.body.getReader();
    const dec    = new TextDecoder();
    let buf = '';
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      buf += dec.decode(value, {stream: true});
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.startsWith('data:')) continue;
        try {
          const j = JSON.parse(line.slice(5).trim());
          if (j.msg) addLine(j.msg, j.cls);
          if (j.done) {
            btn.disabled = false;
            if (!j.error) {
              await loadNebulaStatus();
              await loadNebulaCerts();
            }
          }
        } catch {}
      }
    }
  } catch(e) {
    addLine('Error: ' + e, 'error');
    btn.disabled = false;
  }
}

async function loadNebulaCerts() {
  const tbody = document.getElementById('nebulaCertsBody');
  try {
    const r = await fetch('/api/nebula/certs');
    const certs = await r.json();
    if (!certs.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="color:var(--dim);text-align:center">Sin certificados emitidos.</td></tr>';
      return;
    }
    tbody.innerHTML = certs.map(c => `
      <tr>
        <td style="font-family:'Courier New',monospace;color:var(--blue)">${esc(c.name)}</td>
        <td style="font-family:'Courier New',monospace">${esc(c.ip||'—')}</td>
        <td>${(c.groups||[]).map(g=>`<span class="badge" style="background:var(--bg4);color:var(--fg)">${esc(g)}</span>`).join(' ')}</td>
        <td style="color:var(--dim);font-size:.8rem">${esc(c.not_after||'—')}</td>
        <td style="display:flex;gap:6px">
          <a href="/api/nebula/certs/${encodeURIComponent(c.name)}/download"
             class="btn btn-blue btn-sm" title="Descargar bundle">&#x2B07; ZIP</a>
          <a href="/api/nebula/config/${encodeURIComponent(c.name)}"
             class="btn btn-gray btn-sm" target="_blank" title="Ver config YAML">YAML</a>
          <button class="btn btn-red btn-sm"
             onclick="nebulaRevokeCert('${esc(c.name)}')">&#x1F5D1; Revocar</button>
        </td>
      </tr>`).join('');
  } catch(e) {
    tbody.innerHTML = `<tr><td colspan="5" style="color:var(--red)">${e}</td></tr>`;
  }
}

async function nebulaGenCert() {
  const name   = document.getElementById('ncg_name').value.trim();
  let   ip     = document.getElementById('ncg_ip').value.trim();
  const groups = document.getElementById('ncg_groups').value.trim();
  const dur    = document.getElementById('ncg_dur').value;
  const msg    = document.getElementById('ncg_msg');

  if (!name) { msg.style.color='var(--red)'; msg.textContent='⚠ Ingresa el nombre del nodo.'; return; }
  if (!ip)   { msg.style.color='var(--red)'; msg.textContent='⚠ Ingresa la IP Nebula.'; return; }

  // Auto-completar máscara si falta (igual que el backend)
  if (!ip.includes('/')) ip = ip + '/24';
  document.getElementById('ncg_ip').value = ip;

  msg.style.color='var(--dim)'; msg.textContent='⏳ Generando certificado...';
  try {
    const r = await fetch('/api/nebula/generate', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({name, nebula_ip: ip, groups, duration: dur})
    });
    const j = await r.json();
    if (j.error) {
      msg.style.color='var(--red)';
      msg.textContent='✗ ' + j.error;
      return;
    }
    msg.style.color='var(--green)';
    const certName = j.cert?.name || name;
    const certIp   = j.cert?.ip   || ip;
    msg.textContent = `✓ Certificado "${certName}" emitido (${certIp}) — descárgalo desde la tabla.`;
    if (j.warn) {
      const w = document.createElement('div');
      w.style.color = 'var(--yellow)';
      w.textContent = '⚠ ' + j.warn;
      msg.parentNode.insertBefore(w, msg.nextSibling);
      setTimeout(() => w.remove(), 8000);
    }
    document.getElementById('ncg_name').value='';
    document.getElementById('ncg_ip').value='';
    document.getElementById('ncg_ip').style.borderColor='';
    await loadNebulaCerts();
  } catch(e) { msg.style.color='var(--red)'; msg.textContent='✗ ' + String(e); }
}

async function nebulaRevokeCert(name) {
  if (!confirm(`¿Revocar y eliminar el certificado de "${name}"?`)) return;
  await fetch('/api/nebula/certs/'+encodeURIComponent(name), {method:'DELETE'});
  setStatus(`Certificado "${name}" eliminado.`);
  await loadNebulaCerts();
}

// ── Pentesting Externo — ffuf ─────────────────────────────────────────────────
let fuzzJobId = null;
let fuzzResults = [];

function codeColor(code) {
  const c = parseInt(code);
  if (c >= 200 && c < 300) return 'var(--green)';
  if (c >= 300 && c < 400) return 'var(--yellow)';
  if (c >= 400 && c < 500) return 'var(--red)';
  if (c >= 500) return '#ff8800';
  return 'var(--dim)';
}

async function startFuzz() {
  const url     = document.getElementById('fz-url').value.trim();
  if (!url) { alert('URL objetivo requerida (con FUZZ como marcador)'); return; }
  if (!url.includes('FUZZ')) { alert('La URL debe contener la palabra FUZZ como marcador de posición'); return; }

  const payload = {
    url,
    wordlist:  document.getElementById('fz-wl').value,
    extensions:document.getElementById('fz-ext').value.trim(),
    method:    document.getElementById('fz-method').value,
    threads:   parseInt(document.getElementById('fz-threads').value) || 40,
    timeout:   parseInt(document.getElementById('fz-timeout').value) || 10,
    headers:   document.getElementById('fz-headers').value.trim(),
    cookies:   document.getElementById('fz-cookies').value.trim(),
    postdata:  document.getElementById('fz-postdata').value.trim(),
    fc:        document.getElementById('fz-fc').value.trim(),
    fs:        document.getElementById('fz-fs').value.trim(),
    fw:        document.getElementById('fz-fw').value.trim(),
    fl:        document.getElementById('fz-fl').value.trim(),
    mc:        document.getElementById('fz-mc').value.trim(),
    mr:        document.getElementById('fz-mr').value.trim(),
    auto_fp:   document.getElementById('fz-auto-fp').checked
  };

  fuzzResults = [];
  document.getElementById('fz-results-body').innerHTML = '';
  document.getElementById('fz-raw').textContent = '';
  document.getElementById('fz-count').textContent = '0 hallazgos';
  document.getElementById('fz-progress').textContent = 'Iniciando…';
  document.getElementById('fz-stop-btn').disabled = false;

  try {
    const res = await fetch('/api/ffuf/start', {
      method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload)
    });
    const d = await res.json();
    if (!res.ok) { alert('Error: ' + (d.error||'desconocido')); return; }
    fuzzJobId = d.job_id;
    pollFuzz();
  } catch(e) { alert('Error iniciando ffuf: ' + e); }
}

async function stopFuzz() {
  if (!fuzzJobId) return;
  await fetch('/api/ffuf/stop/' + fuzzJobId, {method:'POST'});
  document.getElementById('fz-stop-btn').disabled = true;
  document.getElementById('fz-progress').textContent = 'Detenido.';
}

function clearFuzz() {
  fuzzResults = [];
  fuzzJobId = null;
  document.getElementById('fz-results-body').innerHTML = '';
  document.getElementById('fz-raw').textContent = '';
  document.getElementById('fz-count').textContent = '0 hallazgos';
  document.getElementById('fz-progress').textContent = '';
  document.getElementById('fz-stop-btn').disabled = true;
  document.getElementById('fz-dl-btn').disabled = true;
  document.getElementById('fuzz-status-badge').textContent = '';
}

function downloadFuzzReport() {
  if (!fuzzResults.length) return;
  const url    = document.getElementById('fz-url').value.trim();
  const wl     = document.getElementById('fz-wl').options[document.getElementById('fz-wl').selectedIndex].text;
  const now    = new Date().toLocaleString('es-EC');
  const codeColor = c => c>=200&&c<300?'#4caf50':c>=300&&c<400?'#f0a500':c>=400&&c<500?'#f44336':'#ff8800';
  const rows = fuzzResults.map(h => `
    <tr>
      <td style="font-weight:700;color:${codeColor(h.status)}">${h.status}</td>
      <td><a href="${h.url}" target="_blank" style="color:#58a6ff">${h.url}</a></td>
      <td style="text-align:right">${h.length}</td>
      <td style="text-align:right">${h.words}</td>
      <td style="text-align:right">${h.lines}</td>
      <td style="text-align:right">${h.duration}</td>
    </tr>`).join('');
  const html = `<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<title>Reporte ffuf — ${url}</title>
<style>
  body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:24px}
  h1{color:#58a6ff;font-size:1.1rem}h2{color:#8b949e;font-size:.85rem;font-weight:normal}
  table{width:100%;border-collapse:collapse;font-size:.82rem;margin-top:16px}
  th{background:#161b22;color:#8b949e;padding:8px 12px;text-align:left;border-bottom:1px solid #30363d}
  td{padding:6px 12px;border-bottom:1px solid #21262d}
  tr:hover td{background:#161b22}
  .meta{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;margin-bottom:16px;font-size:.82rem;line-height:1.8}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:700}
</style></head><body>
<h1>&#x1F4A5; Reporte Pentesting Externo — ffuf</h1>
<div class="meta">
  <b>URL objetivo:</b> ${url}<br>
  <b>Wordlist:</b> ${wl}<br>
  <b>Hallazgos:</b> ${fuzzResults.length}<br>
  <b>Fecha:</b> ${now}<br>
  <b>Generado por:</b> Kali VPN Vulnerability Scanner — Datacom Security
</div>
<table>
  <thead><tr><th>Código</th><th>URL</th><th>Tamaño (bytes)</th><th>Palabras</th><th>Líneas</th><th>RT (ms)</th></tr></thead>
  <tbody>${rows}</tbody>
</table>
</body></html>`;
  const blob = new Blob([html], {type:'text/html'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'ffuf_report_' + new Date().toISOString().slice(0,19).replace(/:/g,'-') + '.html';
  a.click();
  URL.revokeObjectURL(a.href);
}

async function pollFuzz() {
  if (!fuzzJobId) return;
  try {
    const res = await fetch('/api/ffuf/results/' + fuzzJobId);
    const d   = await res.json();

    // Actualizar raw
    const rawEl = document.getElementById('fz-raw');
    rawEl.textContent = (d.raw_lines || []).join('\n');
    rawEl.scrollTop = rawEl.scrollHeight;

    // Añadir filas nuevas a la tabla
    const tbody = document.getElementById('fz-results-body');
    const existing = tbody.querySelectorAll('tr').length;
    const hits = d.results || [];
    for (let i = existing; i < hits.length; i++) {
      const h = hits[i];
      const tr = document.createElement('tr');
      tr.style.borderBottom = '1px solid var(--bg4)';
      const color = codeColor(h.status);
      tr.innerHTML = `
        <td style="padding:6px 12px;font-weight:700;color:${color}">${h.status}</td>
        <td style="padding:6px 12px"><a href="${h.url}" target="_blank" style="color:var(--blue);word-break:break-all">${h.url}</a></td>
        <td style="padding:6px 12px;text-align:right;color:var(--dim)">${h.length}</td>
        <td style="padding:6px 12px;text-align:right;color:var(--dim)">${h.words}</td>
        <td style="padding:6px 12px;text-align:right;color:var(--dim)">${h.lines}</td>
        <td style="padding:6px 12px;text-align:right;color:var(--dim)">${h.duration}</td>`;
      tbody.appendChild(tr);
    }
    document.getElementById('fz-count').textContent = hits.length + ' hallazgos';

    if (d.running) {
      document.getElementById('fz-progress').textContent = `Procesando… ${d.progress||''}`;
      document.getElementById('fuzz-status-badge').textContent = '🔄 Corriendo';
      setTimeout(pollFuzz, 1500);
    } else {
      document.getElementById('fz-progress').textContent = d.error ? '✗ ' + d.error : '✓ Completado';
      document.getElementById('fuzz-status-badge').textContent = d.error ? '✗ Error' : '✓ Listo';
      document.getElementById('fz-stop-btn').disabled = true;
      if (hits.length > 0) document.getElementById('fz-dl-btn').disabled = false;
    }
  } catch(e) {
    document.getElementById('fz-progress').textContent = 'Error polling: ' + e;
    setTimeout(pollFuzz, 3000);
  }
}

// ══════════════════════════════════════════════════
//  CHISEL TUNNEL
// ══════════════════════════════════════════════════
let chiselScanJobId = null;

async function loadChiselStatus() {
  try {
    const r = await fetch('/api/chisel/status');
    const d = await r.json();
    document.getElementById('cs-running').textContent = d.running ? '✅ Activo' : '⛔ Detenido';
    document.getElementById('cs-running').style.color  = d.running ? '#3fb950' : '#f44336';
    document.getElementById('cs-pid').textContent     = d.pid ?? '—';
    document.getElementById('cs-port').textContent    = d.port + '/tcp';
    document.getElementById('cs-socks').textContent   = '127.0.0.1:' + d.socks_port;
    document.getElementById('cs-start-btn').disabled  = d.running;
    document.getElementById('cs-stop-btn').disabled   = !d.running;
  } catch(e) {
    document.getElementById('cs-running').textContent = '? Error: ' + e;
  }
}

async function chiselStart() {
  document.getElementById('cs-start-btn').disabled = true;
  try {
    const r = await fetch('/api/chisel/start', {method:'POST'});
    const d = await r.json();
    if (d.error) { alert('Error: ' + d.error); return; }
    await loadChiselStatus();
  } catch(e) { alert('Error: ' + e); document.getElementById('cs-start-btn').disabled = false; }
}

async function chiselStop() {
  document.getElementById('cs-stop-btn').disabled = true;
  try {
    await fetch('/api/chisel/stop', {method:'POST'});
    await loadChiselStatus();
  } catch(e) {}
}

async function chiselScan() {
  const target = document.getElementById('cs-target').value.trim();
  const ports  = document.getElementById('cs-ports').value.trim();
  if (!target) { alert('Ingresa un target'); return; }

  document.getElementById('cs-output').textContent = '';
  document.getElementById('cs-scan-status').textContent = 'Iniciando…';
  document.getElementById('cs-scan-badge').textContent  = '🔄 Corriendo';
  document.getElementById('cs-scan-btn').disabled      = true;
  document.getElementById('cs-scan-stop-btn').disabled = false;

  try {
    const r = await fetch('/api/chisel/scan', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({target, ports})
    });
    const d = await r.json();
    if (d.error) { alert('Error: ' + d.error); return; }
    chiselScanJobId = d.job_id;
    pollChiselScan();
  } catch(e) {
    document.getElementById('cs-scan-status').textContent = 'Error: ' + e;
    document.getElementById('cs-scan-btn').disabled = false;
  }
}

async function pollChiselScan() {
  if (!chiselScanJobId) return;
  try {
    const r = await fetch('/api/chisel/scan_results/' + chiselScanJobId);
    const d = await r.json();
    const out = document.getElementById('cs-output');
    out.textContent = (d.lines || []).join('\n');
    out.scrollTop = out.scrollHeight;
    if (d.running) {
      document.getElementById('cs-scan-status').textContent = 'Escaneando…';
      setTimeout(pollChiselScan, 2000);
    } else {
      document.getElementById('cs-scan-badge').textContent  = d.error ? '✗ Error' : '✓ Completado';
      document.getElementById('cs-scan-status').textContent = d.error ? '✗ ' + d.error : '✓ Escaneo completo';
      document.getElementById('cs-scan-btn').disabled      = false;
      document.getElementById('cs-scan-stop-btn').disabled = true;
      chiselScanJobId = null;
    }
  } catch(e) {
    setTimeout(pollChiselScan, 3000);
  }
}

async function chiselScanStop() {
  if (!chiselScanJobId) return;
  await fetch('/api/chisel/scan_stop/' + chiselScanJobId, {method:'POST'});
  document.getElementById('cs-scan-stop-btn').disabled = true;
  document.getElementById('cs-scan-btn').disabled = false;
  document.getElementById('cs-scan-badge').textContent = '⛔ Detenido';
  chiselScanJobId = null;
}

async function refreshChiselLog() {
  try {
    const r = await fetch('/api/chisel/log');
    const d = await r.json();
    document.getElementById('cs-log').textContent = d.log || '— sin log —';
  } catch(e) {}
}

function copyCmd(id) {
  const text = document.getElementById(id).textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btns = document.querySelectorAll('[onclick="copyCmd(\'' + id + '\')"]');
    btns.forEach(b => { const orig = b.textContent; b.textContent = '✓ Copiado'; setTimeout(()=>b.textContent=orig,1500); });
  });
}
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print("=" * 56)
    print("  Kali VPN Vulnerability Scanner")
    print("  URL: http://0.0.0.0:8040")
    print("=" * 56)
    app.run(host="0.0.0.0", port=8040, debug=False, threaded=True)
