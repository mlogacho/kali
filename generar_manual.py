#!/usr/bin/env python3
"""Genera el manual PDF del Kali VPN Vulnerability Scanner."""

import os
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether, Image
)
from reportlab.platypus.flowables import Flowable
from reportlab.pdfgen import canvas as pdfcanvas

BASE   = "/Users/marcologacho/Documents/Kali"
OUTPUT = os.path.join(BASE, "Manual_Kali_VPN_Scanner.pdf")
LOGO   = os.path.join(BASE, "logo_datacom.png")

# ── Paleta ─────────────────────────────────────────────────────────────────
C_BG     = colors.HexColor("#0d1117")
C_BLUE   = colors.HexColor("#58a6ff")
C_GREEN  = colors.HexColor("#3fb950")
C_ORANGE = colors.HexColor("#f0883e")
C_RED    = colors.HexColor("#f85149")
C_YELLOW = colors.HexColor("#e3b341")
C_GRAY   = colors.HexColor("#30363d")
C_DIM    = colors.HexColor("#8b949e")
C_FG     = colors.HexColor("#c9d1d9")
C_ROW1   = colors.HexColor("#161b22")
C_ROW2   = colors.HexColor("#0d1117")
WHITE    = colors.white
BLACK    = colors.black

W, H = A4

# ── Header / Footer ────────────────────────────────────────────────────────
def on_page(canvas, doc):
    canvas.saveState()
    # Header bar
    canvas.setFillColor(C_BG)
    canvas.rect(0, H - 1.4*cm, W, 1.4*cm, fill=1, stroke=0)
    # Logo en header
    if os.path.exists(LOGO):
        try:
            canvas.drawImage(LOGO, 1.5*cm, H - 1.25*cm, height=0.95*cm,
                             preserveAspectRatio=True, mask="auto")
        except Exception:
            pass
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(C_BLUE)
    canvas.drawRightString(W - 1.5*cm, H - 0.75*cm,
                           "Kali VPN Vulnerability Scanner — Manual de Usuario")
    # Footer bar
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, W, 1.0*cm, fill=1, stroke=0)
    canvas.setFillColor(C_DIM)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(1.5*cm, 0.38*cm, "© 2026 Datacom Security — Uso exclusivo interno")
    canvas.drawRightString(W - 1.5*cm, 0.38*cm, f"Página {doc.page}")
    canvas.restoreState()

def on_page_cover(canvas, doc):
    canvas.saveState()
    # Full dark background
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    # Top accent bar
    canvas.setFillColor(C_BLUE)
    canvas.rect(0, H - 0.5*cm, W, 0.5*cm, fill=1, stroke=0)
    # Bottom accent bar
    canvas.setFillColor(C_BLUE)
    canvas.rect(0, 0, W, 0.5*cm, fill=1, stroke=0)
    canvas.restoreState()

# ── Estilos ────────────────────────────────────────────────────────────────
def make_styles():
    base = getSampleStyleSheet()
    def s(name, parent="Normal", **kw):
        return ParagraphStyle(name, parent=base[parent], **kw)

    return {
        "cover_title": s("cover_title",
            fontSize=32, leading=40, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER),
        "cover_sub": s("cover_sub",
            fontSize=14, leading=20, textColor=C_BLUE,
            fontName="Helvetica-Bold", alignment=TA_CENTER),
        "cover_meta": s("cover_meta",
            fontSize=10, leading=16, textColor=C_DIM,
            fontName="Helvetica", alignment=TA_CENTER),
        "h1": s("h1", fontSize=16, leading=22, textColor=C_BLUE,
                fontName="Helvetica-Bold", spaceBefore=18, spaceAfter=6),
        "h2": s("h2", fontSize=12, leading=17, textColor=C_GREEN,
                fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=4),
        "h3": s("h3", fontSize=10, leading=14, textColor=C_ORANGE,
                fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=3),
        "body": s("body", fontSize=9.5, leading=15, textColor=C_FG,
                  fontName="Helvetica", alignment=TA_JUSTIFY,
                  spaceBefore=3, spaceAfter=4),
        "bullet": s("bullet", fontSize=9.5, leading=14, textColor=C_FG,
                    fontName="Helvetica", leftIndent=14, spaceBefore=2),
        "code": s("code", fontSize=8.5, leading=13, textColor=C_YELLOW,
                  fontName="Courier", backColor=C_ROW1,
                  leftIndent=10, rightIndent=10,
                  spaceBefore=4, spaceAfter=4),
        "note": s("note", fontSize=9, leading=13, textColor=C_BLUE,
                  fontName="Helvetica-Oblique",
                  leftIndent=12, spaceBefore=4, spaceAfter=4),
        "warning": s("warning", fontSize=9, leading=13, textColor=C_ORANGE,
                     fontName="Helvetica-Bold",
                     leftIndent=12, spaceBefore=4, spaceAfter=4),
        "toc_h1": s("toc_h1", fontSize=10, leading=15, textColor=C_BLUE,
                    fontName="Helvetica-Bold", spaceBefore=4),
        "toc_h2": s("toc_h2", fontSize=9, leading=14, textColor=C_FG,
                    fontName="Helvetica", leftIndent=16, spaceBefore=1),
    }

# ── Table helper ───────────────────────────────────────────────────────────
def dark_table(data, col_widths, header_bg=C_GRAY, alt=True):
    style = [
        ("BACKGROUND",  (0,0), (-1,0),  header_bg),
        ("TEXTCOLOR",   (0,0), (-1,0),  WHITE),
        ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,0),  9),
        ("ALIGN",       (0,0), (-1,0),  "CENTER"),
        ("BOTTOMPADDING",(0,0),(-1,0),  7),
        ("TOPPADDING",  (0,0), (-1,0),  7),
        ("FONTNAME",    (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",    (0,1), (-1,-1), 8.5),
        ("TEXTCOLOR",   (0,1), (-1,-1), C_FG),
        ("ALIGN",       (0,1), (-1,-1), "LEFT"),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",  (0,1), (-1,-1), 5),
        ("BOTTOMPADDING",(0,1),(-1,-1), 5),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("GRID",        (0,0), (-1,-1), 0.3, C_GRAY),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_ROW1, C_ROW2] if alt else [C_ROW1]),
    ]
    return Table(data, colWidths=col_widths,
                 style=TableStyle(style), repeatRows=1)

def hr(color=C_BLUE, thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness,
                      color=color, spaceAfter=6, spaceBefore=6)

def sev_badge_table(data):
    """Tabla especial con colores de severidad."""
    sev_colors = {
        "CRITICAL": colors.HexColor("#ff4444"),
        "HIGH":     colors.HexColor("#ff8800"),
        "MEDIUM":   colors.HexColor("#ffcc00"),
        "LOW":      colors.HexColor("#44aaff"),
        "INFO":     C_DIM,
    }
    style = [
        ("BACKGROUND",  (0,0), (-1,0),  C_GRAY),
        ("TEXTCOLOR",   (0,0), (-1,0),  WHITE),
        ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 8.5),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",  (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("GRID",        (0,0), (-1,-1), 0.3, C_GRAY),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_ROW1, C_ROW2]),
    ]
    for i, row in enumerate(data[1:], 1):
        sev = row[0]
        col = sev_colors.get(sev, C_FG)
        style.append(("TEXTCOLOR", (0,i), (0,i), col))
        style.append(("FONTNAME",  (0,i), (0,i), "Helvetica-Bold"))
    t = Table(data, colWidths=[2.5*cm, 9*cm, 4*cm],
              style=TableStyle(style), repeatRows=1)
    return t


# ══════════════════════════════════════════════════════════════════════════════
def build_pdf():
    doc = SimpleDocTemplate(
        OUTPUT, pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm,
        topMargin=2.2*cm, bottomMargin=1.6*cm,
    )
    st = make_styles()
    story = []

    # ── PORTADA ──────────────────────────────────────────────────────────────
    story.append(Spacer(1, 3.5*cm))
    if os.path.exists(LOGO):
        try:
            story.append(Image(LOGO, width=5*cm, height=2*cm,
                               kind="proportional"))
            story.append(Spacer(1, 0.8*cm))
        except Exception:
            pass
    story.append(Paragraph("Kali VPN Vulnerability Scanner", st["cover_title"]))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph("Manual de Usuario", st["cover_sub"]))
    story.append(Spacer(1, 1.2*cm))
    story.append(hr(C_BLUE, 1))
    story.append(Spacer(1, 0.6*cm))
    story.append(Paragraph(
        "Plataforma web para gestión de clientes, conexión VPN y escaneo<br/>"
        "de vulnerabilidades en redes internas desde un servidor Kali Linux en AWS.",
        st["cover_meta"]))
    story.append(Spacer(1, 2*cm))

    meta = [
        ["Versión",   "1.0"],
        ["Fecha",     "Marzo 2026"],
        ["Autor",     "Datacom Security"],
        ["Servidor",  "18.117.130.45 (AWS us-east-2)"],
        ["Puerto",    "8040"],
    ]
    t = Table(meta, colWidths=[3.5*cm, 10*cm])
    t.setStyle(TableStyle([
        ("FONTNAME",  (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",  (1,0), (1,-1), "Helvetica"),
        ("FONTSIZE",  (0,0), (-1,-1), 9),
        ("TEXTCOLOR", (0,0), (0,-1), C_DIM),
        ("TEXTCOLOR", (1,0), (1,-1), WHITE),
        ("ALIGN",     (0,0), (-1,-1), "LEFT"),
        ("VALIGN",    (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",(0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ("LINEBELOW", (0,0), (-1,-2), 0.3, C_GRAY),
    ]))
    story.append(t)
    story.append(PageBreak())

    # ── ÍNDICE ───────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Contenido", st["h1"]))
    story.append(hr())

    toc = [
        ("1.", "Introducción y Arquitectura", "3"),
        ("2.", "Requisitos e Instalación", "3"),
        ("3.", "Acceso a la Interfaz Web", "4"),
        ("4.", "Gestión de Clientes", "4"),
        ("5.", "Conexión VPN", "5"),
        ("6.", "Escaneo de Vulnerabilidades", "6"),
        ("  6.1", "Configurar el escaneo", "6"),
        ("  6.2", "Perfiles disponibles", "7"),
        ("  6.3", "Lectura de resultados", "8"),
        ("7.", "Exportar Reportes", "9"),
        ("8.", "Historial de Escaneos", "9"),
        ("9.", "Gestión del Servicio", "10"),
        ("10.", "Seguridad y Buenas Prácticas", "10"),
    ]
    for num, title, page in toc:
        lvl = st["toc_h2"] if num.startswith("  ") else st["toc_h1"]
        line = Table(
            [[Paragraph(num, lvl), Paragraph(title, lvl),
              Paragraph(page, ParagraphStyle("p", parent=lvl, alignment=2))]],
            colWidths=[1.2*cm, 12.5*cm, 1.5*cm]
        )
        line.setStyle(TableStyle([
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING",  (0,0), (-1,-1), 0),
            ("RIGHTPADDING", (0,0), (-1,-1), 0),
            ("TOPPADDING",   (0,0), (-1,-1), 2),
            ("BOTTOMPADDING",(0,0), (-1,-1), 2),
        ]))
        story.append(line)

    story.append(PageBreak())

    # ── 1. INTRODUCCIÓN ──────────────────────────────────────────────────────
    story.append(Paragraph("1. Introducción y Arquitectura", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "El <b>Kali VPN Vulnerability Scanner</b> es una plataforma web desplegada sobre un servidor "
        "Kali Linux en Amazon AWS que permite realizar escaneos de vulnerabilidades en redes internas "
        "de clientes. La herramienta gestiona la conexión VPN al entorno del cliente y ejecuta "
        "herramientas como <b>nmap</b>, <b>vulners</b> y <b>nikto</b> directamente desde el servidor "
        "Kali, permitiendo operar como si se estuviera físicamente dentro de la red objetivo.",
        st["body"]))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Flujo de trabajo:", st["h3"]))

    arch = [
        ["Capa", "Componente", "Descripción"],
        ["1 — Acceso", "Navegador web", "El usuario accede a http://18.117.130.45:8040 desde cualquier dispositivo"],
        ["2 — Plataforma", "Flask (Kali AWS)", "Servidor web Python que gestiona clientes, VPN y escaneos"],
        ["3 — Túnel VPN", "OpenVPN / WireGuard", "El Kali se conecta a la red interna del cliente"],
        ["4 — Escaneo", "nmap · nikto · vulners", "Las herramientas analizan la red desde dentro del perímetro"],
    ]
    story.append(dark_table(arch, [2.8*cm, 4*cm, 8.4*cm]))
    story.append(Spacer(1, 0.3*cm))

    infra = [
        ["Parámetro", "Valor"],
        ["Instancia AWS", "i-0149996bf2a11dbdd"],
        ["Tipo de instancia", "t3.micro — us-east-2"],
        ["IP Pública", "18.117.130.45"],
        ["Sistema Operativo", "Kali Linux 2025.4 amd64"],
        ["Puerto de la aplicación", "8040 (TCP)"],
        ["Servicio systemd", "vuln-scanner"],
    ]
    story.append(Paragraph("Infraestructura AWS:", st["h3"]))
    story.append(dark_table(infra, [6*cm, 9.2*cm]))

    # ── 2. REQUISITOS ────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("2. Requisitos e Instalación", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "La aplicación ya está desplegada y configurada en el servidor Kali. "
        "No se requiere instalación adicional para usar la interfaz web.",
        st["body"]))

    story.append(Paragraph("Requisitos del usuario (cliente):", st["h2"]))
    for item in [
        "Navegador web moderno: Chrome, Firefox, Edge o Safari",
        "Acceso a internet o red con visibilidad a 18.117.130.45:8040",
        "Archivo de configuración VPN del cliente (.ovpn o .conf de WireGuard)",
        "Credenciales VPN del cliente (si aplica)",
    ]:
        story.append(Paragraph(f"• {item}", st["bullet"]))

    story.append(Paragraph("Herramientas disponibles en el servidor:", st["h2"]))
    tools = [
        ["Herramienta", "Versión", "Uso principal"],
        ["nmap", "7.x+", "Escaneo de puertos, detección de SO y versiones"],
        ["nmap NSE (vuln)", "Incluida", "Scripts de vulnerabilidades integrados"],
        ["vulners", "Incluida", "Correlación con base de datos de CVEs"],
        ["nikto", "2.x+", "Escaneo de vulnerabilidades en servidores web"],
        ["sslscan", "2.x+", "Análisis de configuración SSL/TLS"],
        ["OpenVPN", "2.x+", "Conexión VPN con archivos .ovpn"],
        ["WireGuard", "Incluido", "Conexión VPN con archivos .conf"],
    ]
    story.append(dark_table(tools, [3.5*cm, 2.5*cm, 9.2*cm]))

    story.append(Paragraph(
        "⚠ Si necesitas redesplegar la aplicación, ejecuta ./deploy.sh desde "
        "la carpeta local del proyecto con el archivo kali-aws.pem disponible.",
        st["warning"]))

    story.append(PageBreak())

    # ── 3. ACCESO ────────────────────────────────────────────────────────────
    story.append(Paragraph("3. Acceso a la Interfaz Web", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Abre tu navegador web e ingresa la siguiente URL:", st["body"]))
    story.append(Paragraph("http://18.117.130.45:8040", st["code"]))
    story.append(Paragraph(
        "La interfaz cargará automáticamente. No requiere login — asegúrate de que "
        "el acceso al puerto 8040 esté restringido a IPs autorizadas en el Security Group de AWS.",
        st["body"]))

    story.append(Paragraph("Secciones de la interfaz:", st["h2"]))
    sections = [
        ["Elemento", "Ubicación", "Función"],
        ["Sidebar — Clientes", "Panel izquierdo", "Lista de clientes registrados y formulario de alta"],
        ["Badge VPN", "Header superior derecho", "Indica el estado de la VPN y permite conectar/desconectar"],
        ["Pestaña Escaneo", "Área principal", "Configuración y ejecución de escaneos en tiempo real"],
        ["Pestaña Historial", "Área principal", "Lista de todos los escaneos realizados con opción de exportar"],
        ["Barra de estado", "Pie de página", "Estado actual del sistema y duración del escaneo activo"],
    ]
    story.append(dark_table(sections, [4*cm, 4*cm, 7.2*cm]))

    # ── 4. GESTIÓN DE CLIENTES ───────────────────────────────────────────────
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("4. Gestión de Clientes", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Antes de realizar cualquier escaneo, debes registrar el cliente. "
        "Cada cliente almacena su configuración VPN y la red interna objetivo.",
        st["body"]))

    story.append(Paragraph("Crear un nuevo cliente:", st["h2"]))
    steps = [
        ("1", "En el panel izquierdo, haz clic en el botón <b>+ Nuevo</b>."),
        ("2", "Completa el campo <b>Nombre / Empresa</b> (obligatorio)."),
        ("3", "Ingresa la <b>Red interna en formato CIDR</b> (ej: 192.168.10.0/24). "
               "Este valor se usará automáticamente como objetivo de escaneo."),
        ("4", "Agrega una descripción opcional para identificar el engagement."),
        ("5", "Selecciona el <b>Tipo VPN</b>: OpenVPN o WireGuard."),
        ("6", "Sube el archivo de configuración VPN (.ovpn para OpenVPN, .conf para WireGuard) "
               "usando el botón <b>Seleccionar</b>."),
        ("7", "Si la VPN requiere autenticación, ingresa <b>Usuario</b> y <b>Contraseña VPN</b>."),
        ("8", "Haz clic en <b>Guardar</b>. El cliente aparecerá en la lista izquierda."),
    ]
    for num, text in steps:
        story.append(Paragraph(f"&nbsp;&nbsp;<b>{num}.</b> {text}", st["bullet"]))
        story.append(Spacer(1, 2))

    story.append(Paragraph("Editar un cliente existente:", st["h2"]))
    story.append(Paragraph(
        "Haz clic en cualquier cliente de la lista izquierda para cargar sus datos "
        "en el formulario. Modifica los campos necesarios y haz clic en <b>Guardar</b>.",
        st["body"]))

    story.append(Paragraph("Eliminar un cliente:", st["h2"]))
    story.append(Paragraph(
        "Pasa el cursor sobre el cliente en la lista — aparecerá el botón <b>✕</b> "
        "a la derecha. Haz clic para eliminarlo (se pedirá confirmación).",
        st["body"]))

    story.append(Paragraph(
        "ℹ Los datos de clientes se almacenan en /opt/scanner/clients.json en el servidor Kali. "
        "Los archivos VPN se guardan en /opt/scanner/vpn_configs/.",
        st["note"]))

    story.append(PageBreak())

    # ── 5. CONEXIÓN VPN ──────────────────────────────────────────────────────
    story.append(Paragraph("5. Conexión VPN", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "La VPN conecta el servidor Kali a la red interna del cliente, permitiendo "
        "que los escaneos se realicen desde dentro del perímetro de red como si fuera "
        "un equipo interno. Es el paso más importante antes de escanear redes privadas.",
        st["body"]))

    story.append(Paragraph("Conectar a la VPN de un cliente:", st["h2"]))
    steps_vpn = [
        ("1", "Haz clic en el <b>badge VPN</b> en la esquina superior derecha "
               "(aparece como '● VPN Inactiva' en rojo)."),
        ("2", "En el modal que se abre, selecciona el <b>cliente</b> del dropdown."),
        ("3", "Haz clic en <b>Conectar VPN</b>."),
        ("4", "El sistema subirá la configuración al Kali y lanzará OpenVPN/WireGuard en segundo plano. "
               "El proceso puede tardar entre 10 y 40 segundos."),
        ("5", "Cuando la VPN esté activa, el badge cambiará a <b>verde</b> mostrando el nombre del cliente "
               "y la IP asignada en el túnel (ej: tun0: 10.8.0.2/24)."),
        ("6", "Cierra el modal — ya puedes escanear la red interna."),
    ]
    for num, text in steps_vpn:
        story.append(Paragraph(f"&nbsp;&nbsp;<b>{num}.</b> {text}", st["bullet"]))
        story.append(Spacer(1, 2))

    story.append(Paragraph("Desconectar la VPN:", st["h2"]))
    story.append(Paragraph(
        "Abre el modal VPN (badge superior) y haz clic en <b>Desconectar</b>. "
        "Siempre desconecta la VPN al finalizar el engagement para liberar recursos.",
        st["body"]))

    story.append(Paragraph("Estados del badge VPN:", st["h2"]))
    vpn_states = [
        ["Estado", "Color", "Significado"],
        ["● VPN Inactiva", "Rojo", "No hay túnel VPN activo. No se pueden escanear redes internas."],
        ["● VPN: [Cliente]", "Verde", "Túnel VPN activo. El Kali está conectado a la red del cliente."],
        ["Conectando VPN...", "Naranja", "El proceso de conexión está en curso (10-40 segundos)."],
    ]
    story.append(dark_table(vpn_states, [4*cm, 2.5*cm, 8.7*cm]))

    story.append(Paragraph(
        "⚠ Solo puede haber una VPN activa a la vez. Para cambiar de cliente, "
        "desconecta la VPN actual antes de conectar a otro cliente.",
        st["warning"]))

    # ── 6. ESCANEO ───────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.1*cm))
    story.append(Paragraph("6. Escaneo de Vulnerabilidades", st["h1"]))
    story.append(hr())

    story.append(Paragraph("6.1 Configurar el escaneo", st["h2"]))
    story.append(Paragraph(
        "En la pestaña <b>Escaneo</b>, configura los siguientes parámetros:", st["body"]))

    params = [
        ["Campo", "Descripción", "Ejemplo"],
        ["Cliente", "Dropdown para seleccionar el cliente activo. "
                    "Al seleccionarlo, rellena automáticamente el campo Objetivo.",
         "Empresa ABC"],
        ["Objetivo", "IP, rango CIDR o hostname a escanear. Puede ser un host "
                     "individual o toda una subred.",
         "192.168.10.0/24\n10.0.0.1\nserver.local"],
        ["Perfil de escaneo", "Tipo de análisis a realizar. Determina las "
                              "herramientas y flags utilizados.",
         "Vuln + SO + Versiones"],
        ["Comando (editable)", "El comando exacto que se ejecutará. Puedes "
                               "modificarlo manualmente para ajustar parámetros.",
         "sudo nmap -sS -sV -O --script vuln -T4 192.168.10.0/24"],
    ]
    story.append(dark_table(params, [3.5*cm, 8*cm, 3.7*cm]))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "Una vez configurado, haz clic en <b>▶ Iniciar Escaneo</b>. "
        "Los resultados aparecen en tiempo real en el terminal inferior.",
        st["body"]))

    story.append(PageBreak())

    story.append(Paragraph("6.2 Perfiles de escaneo disponibles", st["h2"]))
    story.append(Paragraph(
        "Selecciona el perfil según el objetivo del análisis. "
        "Los perfiles más completos toman más tiempo pero detectan más vulnerabilidades.",
        st["body"]))

    profiles = [
        ["Perfil", "Comando base", "Tiempo est.", "Uso recomendado"],
        ["Descubrimiento\n(hosts vivos)",
         "nmap -sn",
         "1-2 min",
         "Primera fase: identificar qué hosts están activos en la red."],
        ["Puertos top-1000",
         "nmap -sS -T4 --open",
         "2-5 min",
         "Escaneo rápido de los 1000 puertos más comunes."],
        ["Puertos completos\n(1-65535)",
         "nmap -sS -T4 -p-",
         "15-30 min",
         "Escaneo exhaustivo. Detecta servicios en puertos no estándar."],
        ["Versiones + SO",
         "nmap -sS -sV -O -T4",
         "5-10 min",
         "Identifica versiones de servicios y sistema operativo."],
        ["Vulnerabilidades NSE",
         "nmap --script vuln",
         "10-20 min",
         "Detecta CVEs conocidos usando los scripts integrados de nmap."],
        ["Vuln + SO + Versiones\n(Completo)",
         "nmap -sS -sV -O\n--script vuln",
         "20-40 min",
         "Análisis completo recomendado para auditorías formales."],
        ["CVEs con CVSS\n(vulners)",
         "nmap --script vulners\n--script-args mincvss=5.0",
         "15-25 min",
         "CVEs con puntuación CVSS ≥ 5.0 usando base de datos vulners."],
        ["Web / HTTP\n(nikto)",
         "nikto -h",
         "5-15 min",
         "Detecta vulnerabilidades en servidores web (XSS, SQLi, misc)."],
        ["SMB vulnerabilidades",
         "nmap -p445\n--script smb-vuln*",
         "2-5 min",
         "EternalBlue, MS17-010 y otros exploits sobre SMB (Windows)."],
        ["SSL/TLS\n(sslscan)",
         "sslscan",
         "1-3 min",
         "Analiza protocolos débiles, cifrados inseguros y expiración de certificados."],
    ]
    story.append(dark_table(profiles, [3.2*cm, 4*cm, 2*cm, 6*cm]))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("6.3 Lectura de resultados", st["h2"]))
    story.append(Paragraph(
        "El terminal muestra la salida en tiempo real coloreada por severidad. "
        "El panel derecho <b>Hallazgos</b> filtra automáticamente las líneas "
        "con severidad CRITICAL, HIGH y MEDIUM.",
        st["body"]))

    sev_data = [
        ["Severidad", "Descripción", "Ejemplos típicos"],
        ["CRITICAL", "Vulnerabilidad crítica explotable de forma remota sin autenticación.",
         "EternalBlue, Shellshock, RCE sin auth"],
        ["HIGH", "Vulnerabilidad con CVE conocido o vector de ataque documentado.",
         "CVE con CVSS alto, SQLi, LFI/RFI confirmado"],
        ["MEDIUM", "Configuración débil o servicio con riesgo moderado.",
         "SSL/TLS débil, cipher deprecated, warnings"],
        ["LOW", "Información de baja criticidad o fuga de datos mínima.",
         "Info leak, puertos abiertos conocidos"],
        ["INFO", "Información general del escaneo sin implicación de riesgo.",
         "Hosts activos, puertos, versiones detectadas"],
    ]
    story.append(sev_badge_table(sev_data))

    story.append(PageBreak())

    # ── 7. EXPORTAR ──────────────────────────────────────────────────────────
    story.append(Paragraph("7. Exportar Reportes", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Una vez finalizado el escaneo, puedes exportar los resultados en tres formatos "
        "usando los botones de la barra de herramientas:",
        st["body"]))

    export_data = [
        ["Formato", "Descripción", "Uso recomendado"],
        ["TXT", "Salida completa del escaneo en texto plano con cabecera de metadatos "
                "(cliente, objetivo, perfil, fecha).",
         "Evidencia técnica, adjuntar a informes internos."],
        ["JSON", "Resultados estructurados en JSON con todos los metadatos del escaneo. "
                 "Incluye scan_id, client, target, profile, command, start y array de líneas.",
         "Integración con otras herramientas o scripts de análisis."],
        ["HTML", "Reporte visual con tabla coloreada por severidad, listo para abrir "
                 "en el navegador o adjuntar a informes ejecutivos.",
         "Presentación a clientes o stakeholders no técnicos."],
    ]
    story.append(dark_table(export_data, [2*cm, 8.5*cm, 4.7*cm]))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "Los reportes también quedan guardados automáticamente en el servidor "
        "en <b>/opt/scanner/scans/</b> con el formato: "
        "<b>scan_[objetivo]_[id].txt</b>",
        st["note"]))

    story.append(Paragraph("Exportar desde el Historial:", st["h2"]))
    story.append(Paragraph(
        "En la pestaña <b>Historial</b>, cada fila tiene botones <b>TXT</b> y <b>HTML</b> "
        "para descargar el reporte de cualquier escaneo pasado, incluso de sesiones anteriores.",
        st["body"]))

    # ── 8. HISTORIAL ─────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.1*cm))
    story.append(Paragraph("8. Historial de Escaneos", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "La pestaña <b>Historial</b> muestra todos los escaneos realizados en la sesión actual. "
        "Para cada escaneo se muestra:",
        st["body"]))
    for col in ["ID único del escaneo", "Cliente asociado", "Objetivo escaneado",
                "Perfil utilizado", "Fecha y hora de inicio", "Estado (En curso / Completado)"]:
        story.append(Paragraph(f"• {col}", st["bullet"]))

    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("Acciones disponibles por escaneo:", st["h2"]))
    actions = [
        ["Botón", "Acción"],
        ["Ver", "Reproduce el output del escaneo en el terminal de la pestaña Escaneo."],
        ["TXT", "Descarga el reporte en formato texto plano."],
        ["HTML", "Descarga el reporte visual con colores de severidad."],
    ]
    story.append(dark_table(actions, [2.5*cm, 12.7*cm]))
    story.append(Paragraph(
        "ℹ El historial persiste durante la sesión del servidor. "
        "Si el servicio se reinicia, el historial en memoria se limpia "
        "(los reportes guardados en disco permanecen en /opt/scanner/scans/).",
        st["note"]))

    story.append(PageBreak())

    # ── 9. GESTIÓN DEL SERVICIO ──────────────────────────────────────────────
    story.append(Paragraph("9. Gestión del Servicio", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "La aplicación corre como servicio systemd (<b>vuln-scanner</b>) en el servidor Kali. "
        "Se inicia automáticamente con el sistema. Para gestionarlo via SSH:",
        st["body"]))

    cmds = [
        ["Acción", "Comando SSH"],
        ["Ver estado del servicio",
         "ssh -i kali-aws.pem kali@18.117.130.45 'sudo systemctl status vuln-scanner'"],
        ["Ver logs en tiempo real",
         "ssh -i kali-aws.pem kali@18.117.130.45 'sudo journalctl -u vuln-scanner -f'"],
        ["Reiniciar el servicio",
         "ssh -i kali-aws.pem kali@18.117.130.45 'sudo systemctl restart vuln-scanner'"],
        ["Detener el servicio",
         "ssh -i kali-aws.pem kali@18.117.130.45 'sudo systemctl stop vuln-scanner'"],
        ["Redesplegar la aplicación",
         "cd ~/Documents/Kali && ./deploy.sh"],
    ]
    t = Table(cmds, colWidths=[4*cm, 11.2*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0),  C_GRAY),
        ("TEXTCOLOR",   (0,0), (-1,0),  WHITE),
        ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 8),
        ("FONTNAME",    (0,1), (-1,-1), "Helvetica"),
        ("FONTNAME",    (1,1), (1,-1),  "Courier"),
        ("TEXTCOLOR",   (0,1), (0,-1),  C_FG),
        ("TEXTCOLOR",   (1,1), (1,-1),  C_YELLOW),
        ("BACKGROUND",  (0,1), (-1,-1), C_ROW1),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_ROW1, C_ROW2]),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",  (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("GRID",        (0,0), (-1,-1), 0.3, C_GRAY),
    ]))
    story.append(t)

    # ── 10. SEGURIDAD ────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("10. Seguridad y Buenas Prácticas", st["h1"]))
    story.append(hr())

    recs = [
        ("Restringir el puerto 8040",
         "En el Security Group de AWS, limita el acceso al puerto 8040 únicamente "
         "a las IPs de los consultores autorizados. Evita exponer la interfaz a 0.0.0.0/0."),
        ("Proteger el archivo .pem",
         "Nunca compartas ni subas el archivo kali-aws.pem a repositorios. "
         "Mantén permisos 600 (chmod 600 kali-aws.pem)."),
        ("Desconectar VPN al finalizar",
         "Siempre desconecta la VPN del cliente al terminar el engagement para "
         "evitar acceso no autorizado a redes privadas."),
        ("Documentar autorización",
         "Antes de escanear cualquier red, verifica que cuentas con autorización "
         "escrita del cliente. Guarda el contrato o carta de autorización."),
        ("Limitar el alcance",
         "Usa el campo Objetivo para especificar exactamente los hosts o rangos "
         "autorizados. Nunca escanees fuera del alcance definido."),
        ("Revisar logs regularmente",
         "Revisa los logs del servicio periódicamente para detectar usos no "
         "autorizados: journalctl -u vuln-scanner --since today."),
        ("Mantener el servidor actualizado",
         "Ejecuta sudo apt update && sudo apt upgrade regularmente en el servidor "
         "Kali para mantener las herramientas de escaneo actualizadas."),
    ]
    for title, desc in recs:
        story.append(KeepTogether([
            Paragraph(f"▸ {title}", st["h3"]),
            Paragraph(desc, st["body"]),
        ]))

    story.append(Spacer(1, 0.5*cm))
    story.append(hr(C_BLUE, 1))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "Kali VPN Vulnerability Scanner — Datacom Security © 2026<br/>"
        "Este manual es confidencial y de uso exclusivo del equipo de seguridad.",
        ParagraphStyle("footer_text", fontSize=8, textColor=C_DIM,
                       alignment=TA_CENTER, fontName="Helvetica-Oblique")))

    # ── BUILD ─────────────────────────────────────────────────────────────────
    def page_template(canvas, doc):
        if doc.page == 1:
            on_page_cover(canvas, doc)
        else:
            on_page(canvas, doc)

    doc.build(story, onFirstPage=page_template, onLaterPages=page_template)
    print(f"PDF generado: {OUTPUT}")

if __name__ == "__main__":
    build_pdf()
