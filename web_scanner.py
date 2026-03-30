#!/usr/bin/env python3
"""
Kali VPN Vulnerability Scanner — Web UI
Corre en el servidor Kali en el puerto 8040.
Acceder desde: http://<kali-ip>:8040
"""

import os, json, re, datetime, subprocess, threading, time, uuid, io
from flask import Flask, render_template_string, request, jsonify, Response, stream_with_context, send_file

app = Flask(__name__)
app.secret_key = os.urandom(32)

CLIENTS_FILE = "/opt/scanner/clients.json"
UPLOAD_DIR   = "/opt/scanner/vpn_configs"
SCANS_DIR    = "/opt/scanner/scans"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SCANS_DIR,  exist_ok=True)
if not os.path.exists(CLIENTS_FILE):
    with open(CLIENTS_FILE, "w") as f:
        json.dump({}, f)

# ── State ──────────────────────────────────────────────────────────────────────
active_scans: dict[str, dict] = {}
network_maps: dict[str, dict] = {}
vpn_state = {"active": False, "client": "", "iface": ""}

SCAN_PROFILES = {
    "Descubrimiento (hosts vivos)":      "nmap -sT -T4 --open -p 22,80,443,445,3306,3389,8080,8443,21,25,110,8000 {target}",
    "Puertos top-1000":                   "nmap -sT -Pn -T4 --open {target}",
    "Puertos completos (1-65535)":        "nmap -sT -Pn -T4 -p- --open {target}",
    "Info HTTP/SSH/FTP":                  "nmap -sT -Pn -T4 --script http-title,http-headers,ssh-hostkey,ftp-anon {target}",
    "Vulnerabilidades NSE":               "nmap -sT -Pn -T4 --script 'vuln and not ssl-heartbleed and not ssl-poodle and not sslv2-drown and not ssl-ccs-injection and not ssl-cert-intaddr and not ssl-known-key and not tls-ticketbleed' {target}",
    "Vuln + Info HTTP/SSH (completo)":    "nmap -sT -Pn -T4 --script 'vuln and not ssl-heartbleed and not ssl-poodle and not sslv2-drown and not ssl-ccs-injection and not ssl-cert-intaddr and not ssl-known-key and not tls-ticketbleed',http-title,http-headers,ssh-hostkey {target}",
    "CVEs con CVSS (vulners)":            "nmap -sT -Pn -T4 --script vulners --script-args mincvss=5.0 {target}",
    "Web / HTTP (nikto)":                 "nikto -h {target}",
    "SMB vulnerabilidades":               "nmap -sT -Pn -p445 --script 'smb-vuln*' -T4 {target}",
    "SSL/TLS — red/subred (nmap)":        "nmap -sT -Pn --script ssl-enum-ciphers,ssl-cert,ssl-dh-params -p 443,8443,8080,8888,8000 -T4 {target}",
    "SSL/TLS — host único (sslscan)":     "sslscan --no-colour {target}",
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
    C_BG    = colors.HexColor("#0d1117")
    C_BLUE  = colors.HexColor("#58a6ff")
    C_GREEN = colors.HexColor("#3fb950")
    C_GRAY  = colors.HexColor("#30363d")
    C_DIM   = colors.HexColor("#8b949e")
    C_FG    = colors.HexColor("#c9d1d9")
    C_ROW1  = colors.HexColor("#161b22")
    C_ROW2  = colors.HexColor("#0d1117")
    C_CRIT  = colors.HexColor("#ff4444")
    C_HIGH  = colors.HexColor("#ff8800")
    C_MED   = colors.HexColor("#ffcc00")
    C_LOW   = colors.HexColor("#44aaff")
    WHITE   = colors.white

    SEV_C = {"CRITICAL": C_CRIT, "HIGH": C_HIGH,
              "MEDIUM": C_MED, "LOW": C_LOW, "INFO": C_FG}

    engineer   = scan.get("engineer", "Sin especificar")
    client     = scan.get("client",   "N/A")
    target     = scan.get("target",   "N/A")
    profile    = scan.get("profile",  "N/A")
    command    = scan.get("command",  "N/A")
    start_time = scan.get("start",    now_str())
    end_time   = scan.get("end",      now_str())
    scan_id    = scan.get("id",       "N/A")
    lines      = scan.get("lines",    [])

    # Count findings
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for line in lines:
        sev = detect_severity(line if isinstance(line, str) else "")
        counts[sev] += 1

    buf = io.BytesIO()

    def on_page(canvas, doc):
        canvas.saveState()
        # Header
        canvas.setFillColor(C_BG)
        canvas.rect(0, H - 1.5*cm, W, 1.5*cm, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(C_BLUE)
        canvas.drawString(1.5*cm, H - 0.85*cm,
                          "INFORME DE ESCANEO DE VULNERABILIDADES — CONFIDENCIAL")
        canvas.setFillColor(C_DIM)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(W - 1.5*cm, H - 0.85*cm, f"ID: {scan_id}")
        # Top line
        canvas.setStrokeColor(C_BLUE)
        canvas.setLineWidth(1.5)
        canvas.line(0, H - 1.5*cm, W, H - 1.5*cm)
        # Footer
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, W, 1.1*cm, fill=1, stroke=0)
        canvas.setLineWidth(0.5)
        canvas.setStrokeColor(C_GRAY)
        canvas.line(0, 1.1*cm, W, 1.1*cm)
        canvas.setFillColor(C_DIM)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(1.5*cm, 0.45*cm,
                          f"Datacom Security  •  Generado: {now_display()}  •  Confidencial")
        canvas.drawRightString(W - 1.5*cm, 0.45*cm, f"Página {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm,
        topMargin=2.2*cm, bottomMargin=1.8*cm,
    )

    base = getSampleStyleSheet()
    def S(name, parent="Normal", **kw):
        return ParagraphStyle(name, parent=base[parent], **kw)

    st = {
        "title":  S("t", fontSize=20, leading=26, textColor=WHITE,
                    fontName="Helvetica-Bold", alignment=TA_CENTER),
        "sub":    S("s", fontSize=10, leading=14, textColor=C_BLUE,
                    fontName="Helvetica-Bold", alignment=TA_CENTER),
        "h1":     S("h1", fontSize=13, leading=18, textColor=C_BLUE,
                    fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=4),
        "h2":     S("h2", fontSize=10, leading=14, textColor=C_GREEN,
                    fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=3),
        "body":   S("b", fontSize=8.5, leading=13, textColor=C_FG,
                    fontName="Helvetica", alignment=TA_JUSTIFY,
                    spaceBefore=2, spaceAfter=3),
        "code":   S("c", fontSize=7.5, leading=11, textColor=colors.HexColor("#e3b341"),
                    fontName="Courier", backColor=C_ROW1,
                    leftIndent=8, rightIndent=8, spaceBefore=3, spaceAfter=3),
        "sign":   S("sg", fontSize=9, leading=14, textColor=C_FG,
                    fontName="Helvetica", alignment=TA_CENTER),
        "sign_name": S("sn", fontSize=13, leading=18, textColor=WHITE,
                       fontName="Helvetica-Bold", alignment=TA_CENTER),
        "label":  S("l", fontSize=8, leading=12, textColor=C_DIM,
                    fontName="Helvetica-Bold"),
    }

    def hr(c=C_BLUE, t=0.5):
        return HRFlowable(width="100%", thickness=t, color=c,
                          spaceAfter=5, spaceBefore=5)

    def meta_table(rows):
        t = Table(rows, colWidths=[4.5*cm, 10.7*cm])
        t.setStyle(TableStyle([
            ("FONTNAME",  (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTNAME",  (1,0), (1,-1), "Helvetica"),
            ("FONTSIZE",  (0,0), (-1,-1), 8.5),
            ("TEXTCOLOR", (0,0), (0,-1), C_DIM),
            ("TEXTCOLOR", (1,0), (1,-1), WHITE),
            ("VALIGN",    (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",(0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING",(0,0),(-1,-1), 6),
            ("ROWBACKGROUNDS",(0,0),(-1,-1), [C_ROW1, C_ROW2]),
            ("GRID", (0,0), (-1,-1), 0.3, C_GRAY),
        ]))
        return t

    story = []

    # ── COVER BLOCK ──────────────────────────────────────────────────────────
    cover_bg = Table(
        [[Paragraph("INFORME DE ESCANEO DE VULNERABILIDADES", st["title"]),],
         [Paragraph("Datacom Security — Ethical Hacking", st["sub"])]],
        colWidths=[W - 3.6*cm]
    )
    cover_bg.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_BG),
        ("TOPPADDING",  (0,0), (-1,-1), 16),
        ("BOTTOMPADDING",(0,0),(-1,-1), 16),
        ("LEFTPADDING", (0,0), (-1,-1), 16),
        ("RIGHTPADDING",(0,0), (-1,-1), 16),
        ("LINEABOVE",  (0,0), (-1,0), 2, C_BLUE),
        ("LINEBELOW",  (0,-1),(-1,-1), 2, C_BLUE),
    ]))
    story.append(cover_bg)
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
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Resumen de Hallazgos", st["h1"]))
    story.append(hr())

    sev_rows = [["Severidad", "Cantidad", "Descripción"]]
    sev_info = [
        ("CRITICAL", C_CRIT, "Vulnerabilidades críticas explotables remotamente"),
        ("HIGH",     C_HIGH, "Vulnerabilidades con CVE conocido o alto impacto"),
        ("MEDIUM",   C_MED,  "Configuraciones débiles o riesgo moderado"),
        ("LOW",      C_LOW,  "Información de baja criticidad"),
        ("INFO",     C_FG,   "Líneas informativas sin implicación de riesgo"),
    ]
    sev_rows += [[s, str(counts[s]), d] for s, c, d in sev_info]

    sev_style = [
        ("BACKGROUND", (0,0), (-1,0), C_GRAY),
        ("TEXTCOLOR",  (0,0), (-1,0), WHITE),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8.5),
        ("ALIGN",      (1,0), (1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ("LEFTPADDING",(0,0), (-1,-1), 8),
        ("GRID",       (0,0), (-1,-1), 0.3, C_GRAY),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_ROW1, C_ROW2]),
    ]
    for i, (sev, col, _) in enumerate(sev_info, 1):
        sev_style += [
            ("TEXTCOLOR", (0,i), (0,i), col),
            ("FONTNAME",  (0,i), (0,i), "Helvetica-Bold"),
        ]
        if counts[sev] > 0 and sev in ("CRITICAL","HIGH"):
            sev_style.append(("TEXTCOLOR", (1,i), (1,i), col))
            sev_style.append(("FONTNAME",  (1,i), (1,i), "Helvetica-Bold"))

    t = Table(sev_rows, colWidths=[2.8*cm, 2.2*cm, 10.2*cm])
    t.setStyle(TableStyle(sev_style))
    story.append(t)

    # ── COMMAND ───────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Comando ejecutado:", st["h2"]))
    story.append(Paragraph(command, st["code"]))

    # ── HOST TABLE ────────────────────────────────────────────────────────────
    discovered = _parse_hosts_from_lines(lines)
    if discovered:
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph("Hosts Activos Descubiertos", st["h1"]))
        story.append(hr())
        story.append(Paragraph(
            f"Se identificaron <b>{len(discovered)}</b> host(s) con servicios activos:",
            st["body"]))
        story.append(Spacer(1, 0.15*cm))

        host_rows = [[
            Paragraph("<b>Hostname</b>",    S("hh", fontSize=8, textColor=C_DIM, fontName="Helvetica-Bold")),
            Paragraph("<b>IP</b>",          S("hi", fontSize=8, textColor=C_DIM, fontName="Helvetica-Bold")),
            Paragraph("<b>MAC</b>",         S("hm", fontSize=8, textColor=C_DIM, fontName="Helvetica-Bold")),
            Paragraph("<b>Vendor</b>",      S("hv", fontSize=8, textColor=C_DIM, fontName="Helvetica-Bold")),
            Paragraph("<b>Puertos abiertos</b>", S("hp", fontSize=8, textColor=C_DIM, fontName="Helvetica-Bold")),
        ]]
        for h in discovered:
            ports_str = ", ".join(h["ports"]) if h["ports"] else "—"
            host_rows.append([
                Paragraph(h["hostname"] or "—",
                          S("hbody", fontSize=7.5, textColor=C_FG,    fontName="Helvetica")),
                Paragraph(h["ip"],
                          S("hip",   fontSize=7.5, textColor=C_BLUE,  fontName="Courier")),
                Paragraph(h["mac"],
                          S("hmac",  fontSize=7.5, textColor=colors.HexColor("#e3b341"), fontName="Courier")),
                Paragraph(h["vendor"],
                          S("hven",  fontSize=7.5, textColor=C_FG,    fontName="Helvetica")),
                Paragraph(ports_str,
                          S("hprt",  fontSize=7.5, textColor=C_GREEN,  fontName="Courier")),
            ])

        col_w = [3.8*cm, 3.2*cm, 4.0*cm, 3.2*cm, 1.0*cm]  # last col expands
        # Give remaining space to ports column
        total = sum(col_w)
        avail = W - 3.6*cm  # page margins
        col_w[-1] = avail - sum(col_w[:-1])

        ht = Table(host_rows, colWidths=col_w, repeatRows=1)
        ht.setStyle(TableStyle([
            # Header row
            ("BACKGROUND",    (0,0), (-1,0),  C_GRAY),
            ("TEXTCOLOR",     (0,0), (-1,0),  C_DIM),
            ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0),  8),
            ("TOPPADDING",    (0,0), (-1,0),  6),
            ("BOTTOMPADDING", (0,0), (-1,0),  6),
            # Data rows
            ("FONTSIZE",      (0,1), (-1,-1), 7.5),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_ROW1, C_ROW2]),
            ("TOPPADDING",    (0,1), (-1,-1), 5),
            ("BOTTOMPADDING", (0,1), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 7),
            ("RIGHTPADDING",  (0,0), (-1,-1), 7),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("GRID",          (0,0), (-1,-1), 0.3, C_GRAY),
        ]))
        story.append(ht)

    # ── RESULTS ───────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("Resultados del Escaneo", st["h1"]))
    story.append(hr())

    # Filter critical/high/medium findings separately
    findings = [(l, detect_severity(l)) for l in lines
                if detect_severity(l) in ("CRITICAL","HIGH","MEDIUM")]

    if findings:
        story.append(Paragraph(
            f"Se detectaron <b>{len(findings)}</b> hallazgos relevantes (CRITICAL/HIGH/MEDIUM):",
            st["body"]))
        story.append(Spacer(1, 0.15*cm))
        find_rows = [["SEV", "Hallazgo"]]
        for line, sev in findings[:80]:  # max 80 findings
            find_rows.append([sev, line.strip()])
        ft = Table(find_rows, colWidths=[2*cm, 13.2*cm])
        fs = [
            ("BACKGROUND", (0,0), (-1,0), C_GRAY),
            ("TEXTCOLOR",  (0,0), (-1,0), WHITE),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 7.5),
            ("FONTNAME",   (0,1), (-1,-1), "Courier"),
            ("VALIGN",     (0,0), (-1,-1), "TOP"),
            ("TOPPADDING", (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ("LEFTPADDING",(0,0), (-1,-1), 6),
            ("GRID",       (0,0), (-1,-1), 0.3, C_GRAY),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_ROW1, C_ROW2]),
            ("WORDWRAP",   (1,1), (1,-1),  True),
        ]
        sev_col = {"CRITICAL": C_CRIT, "HIGH": C_HIGH, "MEDIUM": C_MED}
        for i, (_, sev) in enumerate(findings[:80], 1):
            col = sev_col.get(sev, C_FG)
            fs += [("TEXTCOLOR", (0,i), (0,i), col),
                   ("FONTNAME",  (0,i), (0,i), "Helvetica-Bold")]
        ft.setStyle(TableStyle(fs))
        story.append(ft)
        story.append(Spacer(1, 0.3*cm))

    # Full output (truncated)
    story.append(Paragraph("Salida completa del escaneo:", st["h2"]))
    MAX_LINES = 300
    output_lines = [l for l in lines if isinstance(l, str)]
    truncated = len(output_lines) > MAX_LINES
    for line in output_lines[:MAX_LINES]:
        clean = line.rstrip()
        if clean:
            story.append(Paragraph(
                clean[:200].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"),
                st["code"]))
    if truncated:
        story.append(Paragraph(
            f"[... salida truncada — {len(output_lines) - MAX_LINES} líneas adicionales "
            f"disponibles en el servidor en /opt/scanner/scans/ ...]",
            S("trunc", fontSize=7.5, leading=11, textColor=C_DIM,
              fontName="Helvetica-Oblique")))

    # ── SIGNATURE BLOCK ───────────────────────────────────────────────────────
    story.append(Spacer(1, 0.8*cm))
    story.append(hr(C_BLUE, 1))
    story.append(Spacer(1, 0.5*cm))

    sig_date = end_time or start_time

    sig_data = [
        [
            Table([[Paragraph("Firma del Ingeniero Responsable", st["label"])]],
                  style=TableStyle([("ALIGN",(0,0),(-1,-1),"CENTER")])),
            Table([[Paragraph("Fecha y Hora del Test", st["label"])]],
                  style=TableStyle([("ALIGN",(0,0),(-1,-1),"CENTER")])),
        ],
        [
            # Signature line
            Table([
                [Paragraph("_" * 35, S("ul", fontSize=11, textColor=C_DIM,
                                       fontName="Helvetica", alignment=TA_CENTER))],
                [Paragraph(engineer, st["sign_name"])],
                [Paragraph("Ingeniero de Seguridad — Datacom Security",
                           S("role", fontSize=8, textColor=C_DIM,
                             fontName="Helvetica-Oblique", alignment=TA_CENTER))],
            ], style=TableStyle([
                ("ALIGN",   (0,0),(-1,-1),"CENTER"),
                ("TOPPADDING",(0,0),(-1,-1), 4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ])),
            # Date block
            Table([
                [Paragraph(sig_date, S("dt", fontSize=13, textColor=WHITE,
                                       fontName="Helvetica-Bold", alignment=TA_CENTER))],
                [Paragraph("Inicio del escaneo",
                           S("dt2", fontSize=8, textColor=C_DIM,
                             fontName="Helvetica", alignment=TA_CENTER))],
                [Paragraph(f"Generado: {now_display()}",
                           S("dt3", fontSize=8, textColor=C_GREEN,
                             fontName="Helvetica", alignment=TA_CENTER))],
            ], style=TableStyle([
                ("ALIGN",   (0,0),(-1,-1),"CENTER"),
                ("TOPPADDING",(0,0),(-1,-1), 4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ])),
        ],
    ]

    sig_table = Table(sig_data, colWidths=[8*cm, 7.2*cm])
    sig_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_ROW1),
        ("BOX",        (0,0), (-1,-1), 0.5, C_GRAY),
        ("LINEAFTER",  (0,0), (0,-1),  0.5, C_GRAY),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,0),  8),
        ("BOTTOMPADDING",(0,0),(-1,0), 6),
        ("TOPPADDING", (0,1), (-1,1),  14),
        ("BOTTOMPADDING",(0,1),(-1,1), 18),
        ("BACKGROUND", (0,0), (-1,0),  C_GRAY),
        ("TEXTCOLOR",  (0,0), (-1,0),  C_DIM),
        ("FONTNAME",   (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,0),  8),
    ]))
    story.append(sig_table)
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "Este informe ha sido generado automáticamente por el sistema Kali VPN Vulnerability Scanner "
        "de Datacom Security. Su contenido es confidencial y de uso exclusivo del cliente indicado. "
        "Queda prohibida su reproducción o distribución sin autorización escrita.",
        S("disc", fontSize=7, leading=10, textColor=C_DIM,
          fontName="Helvetica-Oblique", alignment=TA_CENTER)))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    buf.seek(0)
    return buf.read()


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
        "network":  data.get("network", "").strip(),
        "desc":     data.get("desc", "").strip(),
        "vpn_path": vpn_path,
        "vpn_type": data.get("vpn_type", "OpenVPN"),
        "vpn_user": data.get("vpn_user", "").strip(),
        "vpn_pass": data.get("vpn_pass", "").strip(),
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
        iface = "tun0"
    else:
        cmd = ["sudo","wg-quick","up",vpn_path]
        iface = "wg0"
    subprocess.run(cmd, capture_output=True)
    for _ in range(20):
        time.sleep(2)
        r = subprocess.run(["ip","a","show",iface], capture_output=True, text=True)
        if "inet " in r.stdout:
            vpn_state.update({"active": True, "client": name, "iface": iface})
            return
    vpn_state["active"] = False

@app.route("/api/vpn/disconnect", methods=["POST"])
def api_vpn_disconnect():
    if vpn_state["iface"] == "tun0":
        subprocess.run(["sudo","pkill","openvpn"], capture_output=True)
    else:
        c = load_clients().get(vpn_state["client"], {})
        subprocess.run(["sudo","wg-quick","down", c.get("vpn_path","")], capture_output=True)
    vpn_state.update({"active": False, "client": "", "iface": ""})
    return jsonify({"ok": True})

VPN_IFACES = ["tailscale0", "tun0", "tun1", "wg0", "wg1", "ppp0", "nordlynx"]

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

# ── API: Ping ─────────────────────────────────────────────────────────────────

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
.ping-bar{display:flex;align-items:center;gap:8px;padding:7px 16px;
          border-bottom:1px solid var(--bg4);flex-shrink:0;flex-wrap:wrap;
          background:var(--bg2)}
.ping-label{font-size:.78rem;font-weight:700;color:var(--green);white-space:nowrap}
.ping-bar input{max-width:220px;padding:5px 10px;font-size:.85rem;
                background:var(--bg3);border:1px solid var(--bg4);
                color:var(--fg);border-radius:6px;outline:none}
.ping-bar input:focus{border-color:var(--green)}
.ping-bar select{width:120px;padding:5px 8px;font-size:.83rem;
                 background:var(--bg3);border:1px solid var(--bg4);
                 color:var(--fg);border-radius:6px;outline:none}
.btn-ping{background:#1a5c2a;color:var(--green);border:1px solid var(--green);padding:5px 14px;font-size:.83rem}
.btn-ping:hover{background:var(--green);color:#000}
.btn-ping.running{background:#0d3318;color:var(--dim);border-color:var(--dim);cursor:not-allowed}
.ping-output{display:flex;align-items:center;gap:12px;font-family:'Courier New',monospace;
             font-size:.8rem;flex:1;min-width:0;overflow:hidden;white-space:nowrap;
             background:var(--bg3);border-radius:6px;padding:5px 10px;border:1px solid var(--bg4)}
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
#mapEmpty .em-sub{font-size:.82rem}
</style>
</head>
<body>

<header>
  <div>
    <h1>&#x26A1; Kali VPN Vulnerability Scanner</h1>
    <span>nmap &bull; vulners &bull; nikto &bull; OpenVPN &bull; WireGuard</span>
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
          <select id="cf_vpntype" name="vpn_type">
            <option>Tailscale</option>
            <option>OpenVPN</option>
            <option>WireGuard</option>
          </select>
        </div>
        <div class="form-group">
          <label>Config VPN (.ovpn / .conf)</label>
          <input type="file" id="cf_vpnfile" name="vpn_config" accept=".ovpn,.conf">
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
        <div class="ping-output" id="pingOutput"><span style="color:var(--dim)">Introduce una IP o hostname y pulsa Ping.</span></div>
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
        <input id="mapTarget" placeholder="Subnet (ej: 10.11.121.0/24)"
               style="max-width:240px;padding:5px 10px;background:var(--bg3);
                      border:1px solid var(--bg4);color:var(--fg);border-radius:6px;
                      outline:none;font-size:.88rem;font-family:inherit"
               onkeydown="if(event.key==='Enter')startNetworkMap()"
               onfocus="this.style.borderColor='var(--blue)'"
               onblur="this.style.borderColor='var(--bg4)'">
        <button class="btn btn-blue btn-sm" id="btnMapScan" onclick="startNetworkMap()">&#x25B6; Escanear</button>
        <button class="btn btn-gray btn-sm" id="btnMapReset" onclick="resetMapView()">&#x21BA; Reset</button>
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
  document.getElementById('cf_name').value    = name;
  document.getElementById('cf_network').value = c.network  || '';
  document.getElementById('cf_desc').value    = c.desc     || '';
  document.getElementById('cf_vpntype').value = c.vpn_type || 'OpenVPN';
  document.getElementById('cf_vpnuser').value = c.vpn_user || '';
  document.getElementById('cf_vpnpass').value = c.vpn_pass || '';
  document.getElementById('clientFormTitle').textContent = 'Editar: ' + name;
  document.getElementById('selClient').value  = name;
  document.getElementById('inTarget').value   = c.network  || '';
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
  ['btnPdf','btnTxt','btnJson','btnHtml'].forEach(id =>
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
  ['btnPdf','btnTxt','btnJson','btnHtml'].forEach(id =>
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
}

function exportScan(fmt)      { exportById(currentScanId, fmt); }
function exportById(id, fmt)  {
  if (!id) { alert('No hay escaneo seleccionado.'); return; }
  window.open('/api/scan/export/' + id + '?fmt=' + fmt);
}

// ── Ping ──────────────────────────────────────────────────────────────────────
let pingSse = null;

function doPing() {
  const host  = document.getElementById('pingHost').value.trim();
  const count = document.getElementById('pingCount').value;
  if (!host) { document.getElementById('pingHost').focus(); return; }

  if (pingSse) { pingSse.close(); pingSse = null; }

  const out = document.getElementById('pingOutput');
  const btn = document.getElementById('btnPing');
  out.innerHTML = `<span class="ping-dot waiting"></span><span style="color:var(--dim)">Enviando ping a ${esc(host)}...</span>`;
  btn.classList.add('running');
  btn.disabled = true;

  // Pre-fill target field with pinged host
  const targetField = document.getElementById('inTarget');
  if (!targetField.value) targetField.value = host;

  // Use fetch + SSE
  pingSse = new EventSource(`/api/ping?_=${Date.now()}`);

  // We trigger via fetch POST then open SSE — instead do both in one request via EventSource workaround
  // Actually send POST first, then read stream
  pingSse.close();

  fetch('/api/ping', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({host, count: parseInt(count)})
  }).then(res => {
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let lastLine = null;
    let success = null;

    out.innerHTML = '';

    function readChunk() {
      reader.read().then(({done, value}) => {
        if (done) {
          btn.classList.remove('running');
          btn.disabled = false;
          return;
        }
        buf += decoder.decode(value, {stream: true});
        const parts = buf.split('\n\n');
        buf = parts.pop();
        parts.forEach(part => {
          const m = part.match(/^data: (.+)$/m);
          if (!m) return;
          try {
            const d = JSON.parse(m[1]);
            lastLine = d;
            if (d.done) {
              success = d.type === 'success';
              // Show final status badge
              const dot = document.createElement('span');
              dot.className = 'ping-dot ' + (success ? 'ok' : 'fail');
              const msg = document.createElement('span');
              msg.className = success ? 'ping-line-success' : 'ping-line-error';
              msg.textContent = d.line;
              out.innerHTML = '';
              out.appendChild(dot);
              out.appendChild(msg);
              // Show full log in tooltip / title
              btn.classList.remove('running');
              btn.disabled = false;
              setStatus(success
                ? `✓ ${host} responde al ping`
                : `✗ ${host} no responde`);
            } else {
              // Accumulate last meaningful line
              const span = document.createElement('span');
              const cls = {success:'ping-line-success',error:'ping-line-error',
                           header:'ping-line-header',info:'ping-line-info'}[d.type] || 'ping-line-info';
              span.className = cls;
              span.textContent = d.line;
              // Only show last line in the bar (space limited)
              out.innerHTML = '';
              const dot = document.createElement('span');
              dot.className = 'ping-dot waiting';
              out.appendChild(dot);
              out.appendChild(span);
            }
          } catch {}
        });
        readChunk();
      });
    }
    readChunk();
  }).catch(e => {
    out.innerHTML = `<span class="ping-dot fail"></span><span class="ping-line-error">Error: ${esc(String(e))}</span>`;
    btn.classList.remove('running');
    btn.disabled = false;
  });
}

function clearPing() {
  document.getElementById('pingOutput').innerHTML =
    '<span style="color:var(--dim)">Introduce una IP o hostname y pulsa Ping.</span>';
  document.getElementById('pingHost').value = '';
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
