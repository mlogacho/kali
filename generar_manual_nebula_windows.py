#!/usr/bin/env python3
"""Genera el manual PDF de instalación de Nebula VPN en Windows."""

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

BASE   = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(BASE, "Manual_Nebula_VPN_Windows.pdf")
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

W, H = A4

# ── Header / Footer ────────────────────────────────────────────────────────
def on_page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(C_BG)
    canvas.rect(0, H - 1.4*cm, W, 1.4*cm, fill=1, stroke=0)
    if os.path.exists(LOGO):
        try:
            canvas.drawImage(LOGO, 1.5*cm, H - 1.25*cm, height=0.95*cm,
                             preserveAspectRatio=True, mask="auto")
        except Exception:
            pass
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(C_BLUE)
    canvas.drawRightString(W - 1.5*cm, H - 0.75*cm,
                           "Nebula VPN — Manual de Instalación en Windows")
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, W, 1.0*cm, fill=1, stroke=0)
    canvas.setFillColor(C_DIM)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(1.5*cm, 0.38*cm, "© 2026 Datacom Security — Uso exclusivo interno")
    canvas.drawRightString(W - 1.5*cm, 0.38*cm, f"Página {doc.page}")
    canvas.restoreState()

def on_page_cover(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    canvas.setFillColor(C_BLUE)
    canvas.rect(0, H - 0.5*cm, W, 0.5*cm, fill=1, stroke=0)
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
            fontSize=30, leading=38, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER),
        "cover_sub": s("cover_sub",
            fontSize=14, leading=20, textColor=C_BLUE,
            fontName="Helvetica-Bold", alignment=TA_CENTER),
        "cover_meta": s("cover_meta",
            fontSize=10, leading=16, textColor=C_DIM,
            fontName="Helvetica", alignment=TA_CENTER),
        "h1": s("h1", fontSize=15, leading=21, textColor=C_BLUE,
                fontName="Helvetica-Bold", spaceBefore=18, spaceAfter=6),
        "h2": s("h2", fontSize=11, leading=16, textColor=C_GREEN,
                fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=4),
        "h3": s("h3", fontSize=10, leading=14, textColor=C_ORANGE,
                fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=3),
        "body": s("body", fontSize=9.5, leading=15, textColor=C_FG,
                  fontName="Helvetica", alignment=TA_JUSTIFY,
                  spaceBefore=3, spaceAfter=4),
        "bullet": s("bullet", fontSize=9.5, leading=14, textColor=C_FG,
                    fontName="Helvetica", leftIndent=14, spaceBefore=2),
        "bullet2": s("bullet2", fontSize=9, leading=13, textColor=C_DIM,
                     fontName="Helvetica", leftIndent=28, spaceBefore=1),
        "code": s("code", fontSize=8, leading=12, textColor=C_YELLOW,
                  fontName="Courier", backColor=C_ROW1,
                  leftIndent=10, rightIndent=10,
                  spaceBefore=4, spaceAfter=4),
        "note": s("note", fontSize=9, leading=13, textColor=C_BLUE,
                  fontName="Helvetica-Oblique",
                  leftIndent=12, spaceBefore=4, spaceAfter=4),
        "warning": s("warning", fontSize=9, leading=13, textColor=C_ORANGE,
                     fontName="Helvetica-Bold",
                     leftIndent=12, spaceBefore=4, spaceAfter=4),
        "danger": s("danger", fontSize=9, leading=13, textColor=C_RED,
                    fontName="Helvetica-Bold",
                    leftIndent=12, spaceBefore=4, spaceAfter=4),
        "toc_h1": s("toc_h1", fontSize=10, leading=15, textColor=C_BLUE,
                    fontName="Helvetica-Bold", spaceBefore=4),
        "toc_h2": s("toc_h2", fontSize=9, leading=14, textColor=C_FG,
                    fontName="Helvetica", leftIndent=16, spaceBefore=1),
    }

# ── Helpers ────────────────────────────────────────────────────────────────
def dark_table(data, col_widths, header_bg=C_GRAY, alt=True):
    style = [
        ("BACKGROUND",   (0,0), (-1,0),  header_bg),
        ("TEXTCOLOR",    (0,0), (-1,0),  WHITE),
        ("FONTNAME",     (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,0),  9),
        ("ALIGN",        (0,0), (-1,0),  "CENTER"),
        ("BOTTOMPADDING",(0,0), (-1,0),  7),
        ("TOPPADDING",   (0,0), (-1,0),  7),
        ("FONTNAME",     (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",     (0,1), (-1,-1), 8.5),
        ("TEXTCOLOR",    (0,1), (-1,-1), C_FG),
        ("ALIGN",        (0,1), (-1,-1), "LEFT"),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",   (0,1), (-1,-1), 5),
        ("BOTTOMPADDING",(0,1), (-1,-1), 5),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
        ("GRID",         (0,0), (-1,-1), 0.3, C_GRAY),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_ROW1, C_ROW2] if alt else [C_ROW1]),
    ]
    return Table(data, colWidths=col_widths,
                 style=TableStyle(style), repeatRows=1)

def hr(color=C_BLUE, thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness,
                      color=color, spaceAfter=6, spaceBefore=6)

def step_box(number, title, st):
    """Bloque visual de paso numerado."""
    data = [[
        Paragraph(f"<b>{number}</b>",
                  ParagraphStyle("sn", fontName="Helvetica-Bold",
                                 fontSize=13, textColor=C_BG, alignment=TA_CENTER)),
        Paragraph(f"<b>{title}</b>",
                  ParagraphStyle("st", fontName="Helvetica-Bold",
                                 fontSize=11, textColor=WHITE)),
    ]]
    t = Table(data, colWidths=[1.0*cm, 14.2*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (0,0),  C_BLUE),
        ("BACKGROUND",   (1,0), (1,0),  C_GRAY),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",   (0,0), (-1,-1), 7),
        ("BOTTOMPADDING",(0,0), (-1,-1), 7),
        ("LEFTPADDING",  (0,0), (0,0),  0),
        ("LEFTPADDING",  (1,0), (1,0),  10),
    ]))
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
    story.append(Spacer(1, 3.0*cm))
    if os.path.exists(LOGO):
        try:
            story.append(Image(LOGO, width=5*cm, height=2*cm, kind="proportional"))
            story.append(Spacer(1, 0.8*cm))
        except Exception:
            pass
    story.append(Paragraph("Nebula VPN", st["cover_title"]))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Manual de Instalación en Windows", st["cover_sub"]))
    story.append(Spacer(1, 1.0*cm))
    story.append(hr(C_BLUE, 1))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(
        "Guía paso a paso para conectar una máquina Windows a la red VPN Nebula<br/>"
        "gestionada por Datacom Security. Incluye instalación, configuración,<br/>"
        "arranque como servicio y solución de problemas.",
        st["cover_meta"]))
    story.append(Spacer(1, 2.0*cm))

    meta = [
        ["Versión",          "1.0"],
        ["Fecha",            "Abril 2026"],
        ["Autor",            "Datacom Security"],
        ["Infraestructura",  "Nebula v1.9.5 · Lighthouse 3.143.18.161"],
        ["Red VPN",          "192.168.100.0/24 · Puerto UDP 4242"],
    ]
    t = Table(meta, colWidths=[3.8*cm, 10*cm])
    t.setStyle(TableStyle([
        ("FONTNAME",        (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",        (1,0), (1,-1), "Helvetica"),
        ("FONTSIZE",        (0,0), (-1,-1), 9),
        ("TEXTCOLOR",       (0,0), (0,-1), C_DIM),
        ("TEXTCOLOR",       (1,0), (1,-1), WHITE),
        ("ALIGN",           (0,0), (-1,-1), "LEFT"),
        ("VALIGN",          (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",      (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",   (0,0), (-1,-1), 5),
        ("LINEBELOW",       (0,0), (-1,-2), 0.3, C_GRAY),
    ]))
    story.append(t)
    story.append(PageBreak())

    # ── ÍNDICE ───────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Contenido", st["h1"]))
    story.append(hr())

    toc = [
        ("1.", "Requisitos previos", "3"),
        ("2.", "Obtener el bundle de certificados", "3"),
        ("3.", "Descargar Nebula para Windows", "3"),
        ("4.", "Instalar el driver de red Wintun", "4"),
        ("5.", "Organizar los archivos en C:\\Nebula\\", "4"),
        ("6.", "Verificar y adaptar la configuración YAML", "5"),
        ("7.", "Primer arranque (prueba manual)", "5"),
        ("8.", "Instalar Nebula como servicio de Windows", "6"),
        ("  8.1", "Opción A — sc.exe (nativo)", "6"),
        ("  8.2", "Opción B — NSSM (recomendado)", "7"),
        ("9.", "Verificar la interfaz de red", "7"),
        ("10.", "Comandos de gestión", "8"),
        ("11.", "Reglas de Firewall de Windows", "8"),
        ("12.", "Referencia rápida de la red", "9"),
        ("13.", "Solución de problemas", "9"),
    ]
    for num, title, page in toc:
        lvl = st["toc_h2"] if num.startswith("  ") else st["toc_h1"]
        line = Table(
            [[Paragraph(num, lvl), Paragraph(title, lvl),
              Paragraph(page, ParagraphStyle("p", parent=lvl, alignment=2))]],
            colWidths=[1.4*cm, 12.3*cm, 1.5*cm]
        )
        line.setStyle(TableStyle([
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING",  (0,0), (-1,-1), 0),
            ("RIGHTPADDING", (0,0), (-1,-1), 0),
            ("TOPPADDING",   (0,0), (-1,-1), 2),
            ("BOTTOMPADDING",(0,0), (-1,-1), 2),
        ]))
        story.append(line)

    story.append(PageBreak())

    # ── 1. REQUISITOS ─────────────────────────────────────────────────────────
    story.append(Paragraph("1. Requisitos previos", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Antes de iniciar la instalación asegúrate de cumplir los siguientes requisitos:",
        st["body"]))
    story.append(Spacer(1, 0.2*cm))

    req = [
        ["Elemento", "Detalle"],
        ["Sistema Operativo", "Windows 10 / 11 (64-bit)  o  Windows Server 2016/2019/2022"],
        ["Permisos", "Cuenta de Administrador local"],
        ["Conectividad", "Puerto UDP 4242 de salida abierto hacia 3.143.18.161"],
        ["Archivos", "Bundle ZIP proporcionado por el administrador de Datacom Security"],
        ["Espacio en disco", "~20 MB libres en C:\\"],
    ]
    story.append(dark_table(req, [3.5*cm, 11.7*cm]))
    story.append(Spacer(1, 0.3*cm))

    # ── 2. OBTENER BUNDLE ────────────────────────────────────────────────────
    story.append(Paragraph("2. Obtener el bundle de certificados", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "El administrador de Datacom Security debe generar un bundle personalizado para tu equipo. "
        "Existen dos métodos equivalentes:", st["body"]))

    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("<b>Método A — Línea de comandos (servidor Kali)</b>", st["h3"]))
    story.append(Paragraph(
        "Reemplaza <b>nombre-cliente</b> por un identificador sin espacios y "
        "<b>192.168.100.XX</b> por la IP overlay asignada:", st["body"]))
    for line in [
        "# Emitir el certificado",
        "sudo ./nebula-cert-manager.sh issue nombre-cliente 192.168.100.10/24 clients 8760h",
        "",
        "# Generar el bundle ZIP descargable",
        "sudo ./nebula-cert-manager.sh bundle nombre-cliente",
    ]:
        story.append(Paragraph(line if line else "&nbsp;", st["code"]))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("<b>Método B — Interfaz Web</b>", st["h3"]))
    story.append(Paragraph(
        "Accede a <b>http://3.143.18.161:8040</b> → pestaña <b>Nebula VPN</b> → "
        "botón <b>Emitir certificado</b> → completa el formulario → "
        "botón <b>Descargar ZIP</b>.", st["body"]))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("El ZIP contiene los siguientes archivos:", st["body"]))
    files = [
        ["Archivo", "Descripción"],
        ["nombre-cliente.crt", "Tu certificado firmado por la CA de Datacom Security"],
        ["nombre-cliente.key", "Tu clave privada — NO compartir ni subir a la nube"],
        ["ca.crt",             "Certificado de la Autoridad Certificadora"],
        ["nombre-cliente_config.yaml", "Configuración lista para usar con Nebula"],
    ]
    story.append(dark_table(files, [5.5*cm, 9.7*cm]))

    story.append(PageBreak())

    # ── 3. DESCARGAR NEBULA ──────────────────────────────────────────────────
    story.append(Paragraph("3. Descargar Nebula para Windows", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Nebula es el binario que establece el túnel VPN. Debes descargar la versión "
        "correcta para Windows de 64 bits:", st["body"]))
    story.append(Spacer(1, 0.2*cm))

    steps = [
        "Abre tu navegador y ve a:",
        "    https://github.com/slackhq/nebula/releases/tag/v1.9.5",
        "Descarga el archivo: nebula-windows-amd64.zip",
        "Extrae el ZIP. Obtendrás dos ejecutables:",
        "    nebula.exe         ← motor VPN principal",
        "    nebula-cert.exe    ← herramienta de certificados (opcional en el cliente)",
    ]
    for i, s_text in enumerate(steps):
        if s_text.startswith("    "):
            story.append(Paragraph(s_text.strip(), st["code"]))
        else:
            story.append(Paragraph(f"  {i//2 + 1 if not s_text.startswith(' ') else ''}  {s_text}",
                                   st["bullet"] if not s_text.startswith("    ") else st["code"]))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "⚠  Si tu empresa tiene políticas de seguridad que bloquean ejecutables de Internet, "
        "el administrador puede proporcionar los binarios directamente.", st["warning"]))

    # ── 4. WINTUN ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("4. Instalar el driver de red Wintun", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Nebula en Windows requiere el driver <b>Wintun</b> para crear la interfaz "
        "de red virtual. <b>Sin este archivo Nebula no funcionará.</b>", st["body"]))

    story.append(Paragraph("🔴  Este paso es obligatorio en Windows.", st["danger"]))
    story.append(Spacer(1, 0.2*cm))

    wintun_steps = [
        ("1", "Accede a: https://www.wintun.net y descarga el ZIP"),
        ("2", "Extrae el ZIP"),
        ("3", "Copia el archivo correcto según tu arquitectura:"),
    ]
    for num, text in wintun_steps:
        story.append(Paragraph(f"  {num}.  {text}", st["bullet"]))

    story.append(Paragraph("wintun\\bin\\amd64\\wintun.dll   ← Windows 64-bit (más común)",
                            st["code"]))
    story.append(Paragraph(
        "Coloca <b>wintun.dll</b> en la misma carpeta que <b>nebula.exe</b> "
        "(en el paso siguiente usaremos C:\\Nebula\\).", st["body"]))

    story.append(PageBreak())

    # ── 5. ORGANIZAR ARCHIVOS ────────────────────────────────────────────────
    story.append(Paragraph("5. Organizar los archivos en C:\\Nebula\\", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Crea la carpeta <b>C:\\Nebula\\</b> y copia todos los archivos en ella. "
        "La estructura final debe ser:", st["body"]))

    tree_lines = [
        "C:\\Nebula\\",
        "├── nebula.exe",
        "├── nebula-cert.exe",
        "├── wintun.dll",
        "├── nombre-cliente.crt",
        "├── nombre-cliente.key",
        "├── ca.crt",
        "└── nombre-cliente_config.yaml",
    ]
    for line in tree_lines:
        story.append(Paragraph(line, st["code"]))

    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "Para crear la carpeta puedes abrir el Explorador de archivos o ejecutar "
        "en PowerShell:", st["body"]))
    story.append(Paragraph("New-Item -ItemType Directory -Path C:\\Nebula", st["code"]))

    # ── 6. CONFIGURACIÓN YAML ────────────────────────────────────────────────
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("6. Verificar y adaptar la configuración YAML", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Abre <b>C:\\Nebula\\nombre-cliente_config.yaml</b> con el Bloc de Notas "
        "o VS Code y verifica que las rutas apunten correctamente a tus archivos. "
        "Ejemplo de configuración correcta para Windows:", st["body"]))

    yaml_lines = [
        "pki:",
        "  ca:   C:/Nebula/ca.crt",
        "  cert: C:/Nebula/nombre-cliente.crt",
        "  key:  C:/Nebula/nombre-cliente.key",
        "",
        "static_host_map:",
        '  "192.168.100.1/24": ["3.143.18.161:4242"]',
        "",
        "lighthouse:",
        "  am_lighthouse: false",
        "  interval: 60",
        "  hosts:",
        '    - "192.168.100.1"',
        "",
        "listen:",
        "  host: 0.0.0.0",
        "  port: 0",
        "",
        "punchy:",
        "  punch: true",
        "",
        "tun:",
        "  disabled: false",
        "  dev: nebula0",
        "  mtu: 1300",
        "",
        "logging:",
        "  level: info",
        "  format: text",
        "",
        "firewall:",
        "  outbound:",
        "    - port: any",
        "      proto: any",
        "      host: any",
        "  inbound:",
        "    - port: any",
        "      proto: icmp",
        "      host: any",
        "    - port: any",
        "      proto: any",
        "      group: clients",
    ]
    for line in yaml_lines:
        story.append(Paragraph(line if line else "&nbsp;", st["code"]))

    story.append(Paragraph(
        "ℹ  En Windows puedes usar barras normales (/) o barras dobles (\\\\) "
        "en las rutas. Evita barras simples invertidas (\\).", st["note"]))

    story.append(PageBreak())

    # ── 7. PRIMER ARRANQUE ───────────────────────────────────────────────────
    story.append(Paragraph("7. Primer arranque (prueba manual)", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Antes de instalar Nebula como servicio, realiza una prueba manual para verificar "
        "que la configuración es correcta.", st["body"]))

    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "1.  Haz clic derecho en el menú Inicio → "
        "<b>Windows PowerShell (Administrador)</b>", st["bullet"]))
    story.append(Paragraph("2.  Navega a la carpeta Nebula:", st["bullet"]))
    story.append(Paragraph("cd C:\\Nebula", st["code"]))
    story.append(Paragraph("3.  Ejecuta Nebula:", st["bullet"]))
    story.append(Paragraph(
        ".\\nebula.exe -config .\\nombre-cliente_config.yaml", st["code"]))
    story.append(Paragraph("4.  Deberías ver mensajes similares a:", st["bullet"]))
    for log_line in [
        'INFO[0000] Nebula interface is up  addr=192.168.100.10/24 interface=nebula0',
        'INFO[0000] Handshake message sent  vpnAddr=192.168.100.1',
    ]:
        story.append(Paragraph(log_line, st["code"]))

    story.append(Paragraph(
        "5.  Abre <b>otra</b> ventana de PowerShell y verifica la conectividad:",
        st["bullet"]))
    story.append(Paragraph("ping 192.168.100.1", st["code"]))
    story.append(Paragraph(
        "Si recibes respuestas del ping, la VPN está funcionando correctamente. "
        "Puedes cerrar la ventana de prueba con Ctrl+C.", st["body"]))

    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "⚠  Es imprescindible ejecutar nebula.exe como Administrador. "
        "Sin permisos elevados no podrá crear la interfaz de red virtual.", st["warning"]))

    # ── 8. SERVICIO WINDOWS ──────────────────────────────────────────────────
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("8. Instalar Nebula como servicio de Windows", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Para que Nebula se inicie automáticamente con Windows y funcione en segundo "
        "plano, instálalo como servicio del sistema. Se presentan dos opciones:", st["body"]))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("8.1  Opción A — sc.exe (herramienta nativa de Windows)", st["h2"]))
    story.append(Paragraph(
        "Esta opción usa herramientas integradas en Windows. Abre PowerShell como "
        "Administrador y ejecuta:", st["body"]))

    sc_lines = [
        "sc.exe create NebulaVPN `",
        '  binPath= "C:\\Nebula\\nebula.exe -config C:\\Nebula\\nombre-cliente_config.yaml" `',
        "  start= auto `",
        '  DisplayName= "Nebula VPN - Datacom Security"',
        "",
        'sc.exe description NebulaVPN "Cliente VPN Nebula para la red Datacom Security"',
        "",
        "sc.exe start NebulaVPN",
    ]
    for line in sc_lines:
        story.append(Paragraph(line if line else "&nbsp;", st["code"]))

    story.append(Paragraph(
        "ℹ  Nota el espacio obligatorio después del signo = en los parámetros de sc.exe. "
        "Sin ese espacio el comando fallará.", st["note"]))

    story.append(PageBreak())

    story.append(Paragraph("8.2  Opción B — NSSM (recomendado, más robusto)", st["h2"]))
    story.append(Paragraph(
        "NSSM (Non-Sucking Service Manager) ofrece mejor manejo de reinicios automáticos "
        "y registro de logs. Es la opción recomendada para entornos de producción.", st["body"]))

    story.append(Paragraph(
        "1.  Descarga NSSM desde <b>https://nssm.cc/download</b>", st["bullet"]))
    story.append(Paragraph(
        "2.  Extrae y copia <b>nssm.exe</b> en <b>C:\\Nebula\\</b>", st["bullet"]))
    story.append(Paragraph(
        "3.  En PowerShell como Administrador ejecuta:", st["bullet"]))

    nssm_lines = [
        "C:\\Nebula\\nssm.exe install NebulaVPN C:\\Nebula\\nebula.exe",
        'C:\\Nebula\\nssm.exe set NebulaVPN AppParameters "-config C:\\Nebula\\nombre-cliente_config.yaml"',
        'C:\\Nebula\\nssm.exe set NebulaVPN DisplayName "Nebula VPN - Datacom Security"',
        "C:\\Nebula\\nssm.exe set NebulaVPN Start SERVICE_AUTO_START",
        "C:\\Nebula\\nssm.exe start NebulaVPN",
    ]
    for line in nssm_lines:
        story.append(Paragraph(line, st["code"]))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Verificar que el servicio está activo:", st["h3"]))
    story.append(Paragraph("sc.exe query NebulaVPN", st["code"]))
    story.append(Paragraph(
        "El campo <b>STATE</b> debe mostrar <b>RUNNING</b>. También puedes verificarlo "
        "en la GUI: <b>Win + R</b> → <b>services.msc</b> → busca "
        "<b>Nebula VPN - Datacom Security</b>.", st["body"]))

    # ── 9. VERIFICAR INTERFAZ ────────────────────────────────────────────────
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("9. Verificar la interfaz de red", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Una vez que el servicio está en ejecución, verifica que la interfaz Nebula "
        "aparece correctamente en Windows:", st["body"]))

    story.append(Paragraph("En PowerShell:", st["h3"]))
    story.append(Paragraph("ipconfig | findstr /A 5 nebula", st["code"]))
    story.append(Paragraph("Resultado esperado:", st["body"]))
    for out_line in [
        "Adaptador Ethernet nebula0:",
        "   Dirección IPv4. . . . . . . . : 192.168.100.10",
        "   Máscara de subred . . . . . . : 255.255.255.0",
    ]:
        story.append(Paragraph(out_line, st["code"]))

    story.append(Paragraph("Prueba de conectividad completa:", st["h3"]))
    for cmd in [
        "# Ping al lighthouse",
        "ping 192.168.100.1",
        "",
        "# Ping a otro nodo de la red VPN (si existe)",
        "ping 192.168.100.20",
    ]:
        story.append(Paragraph(cmd if cmd else "&nbsp;", st["code"]))

    story.append(PageBreak())

    # ── 10. COMANDOS DE GESTIÓN ──────────────────────────────────────────────
    story.append(Paragraph("10. Comandos de gestión", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Los siguientes comandos deben ejecutarse en PowerShell como Administrador:",
        st["body"]))
    story.append(Spacer(1, 0.2*cm))

    cmds = [
        ["Acción", "Comando PowerShell"],
        ["Iniciar servicio",    "sc.exe start NebulaVPN"],
        ["Detener servicio",    "sc.exe stop NebulaVPN"],
        ["Reiniciar servicio",  "sc.exe stop NebulaVPN; sc.exe start NebulaVPN"],
        ["Ver estado",          "sc.exe query NebulaVPN"],
        ["Desinstalar servicio","sc.exe stop NebulaVPN; sc.exe delete NebulaVPN"],
        ["Ver logs (NSSM)",     "notepad C:\\Nebula\\nebula_stdout.log"],
        ["Ver eventos Windows", "eventvwr  (Registros de Windows → Aplicación)"],
    ]
    story.append(dark_table(cmds, [4.5*cm, 10.7*cm]))

    # ── 11. FIREWALL WINDOWS ─────────────────────────────────────────────────
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("11. Reglas de Firewall de Windows", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Si Windows Defender Firewall bloquea las conexiones, añade las siguientes reglas "
        "en PowerShell como Administrador:", st["body"]))

    fw_lines = [
        "# Permitir tráfico UDP saliente hacia el lighthouse (puerto 4242)",
        "New-NetFirewallRule -DisplayName 'Nebula VPN Out' -Direction Outbound `",
        "  -Protocol UDP -RemotePort 4242 -Action Allow",
        "",
        "# Permitir tráfico entrante por la interfaz Nebula",
        "New-NetFirewallRule -DisplayName 'Nebula VPN Inbound' -Direction Inbound `",
        "  -InterfaceAlias 'nebula0' -Action Allow",
    ]
    for line in fw_lines:
        story.append(Paragraph(line if line else "&nbsp;", st["code"]))

    story.append(Paragraph(
        "ℹ  Si tu empresa gestiona el firewall mediante GPO (Group Policy), "
        "solicita a tu administrador de sistemas que añada estas reglas.", st["note"]))

    story.append(PageBreak())

    # ── 12. REFERENCIA RÁPIDA ────────────────────────────────────────────────
    story.append(Paragraph("12. Referencia rápida de la red", st["h1"]))
    story.append(hr())

    net = [
        ["Parámetro", "Valor"],
        ["Servidor Lighthouse",  "3.143.18.161 (AWS us-east-2)"],
        ["Puerto Lighthouse",    "UDP 4242"],
        ["IP Lighthouse (VPN)",  "192.168.100.1"],
        ["Rango de red VPN",     "192.168.100.0/24"],
        ["Tu IP VPN",            "Asignada por el administrador (ej: 192.168.100.10)"],
        ["Web UI (gestión)",     "http://3.143.18.161:8040  →  pestaña Nebula VPN"],
        ["Soporte",              "Datacom Security — Equipo de Infraestructura"],
    ]
    story.append(dark_table(net, [5*cm, 10.2*cm]))

    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        "🔒  Seguridad: Los archivos <b>.key</b> son tu clave privada. No los compartas, "
        "no los subas a servicios en la nube ni los incluyas en correos electrónicos. "
        "Si sospechas que fueron comprometidos, contacta de inmediato al administrador "
        "para revocar y regenerar tu certificado.", st["warning"]))

    # ── 13. SOLUCIÓN DE PROBLEMAS ────────────────────────────────────────────
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("13. Solución de problemas", st["h1"]))
    story.append(hr())

    problems = [
        (
            '❌  Error: "failed to open tun" / "WinTun not found"',
            [
                "Verifica que wintun.dll esté en C:\\Nebula\\ junto a nebula.exe",
                "Asegúrate de ejecutar nebula.exe (o el servicio) como Administrador",
            ]
        ),
        (
            '❌  Error: "failed to read ca" / "certificate signed by unknown authority"',
            [
                "Verifica que las rutas en el archivo .yaml sean correctas",
                "Usa barras normales (/) o barras dobles (\\\\) — nunca barras simples (\\)",
                "Confirma que ca.crt, .crt y .key existen en la ruta indicada",
            ]
        ),
        (
            "❌  No hay respuesta al hacer ping a 192.168.100.1",
            [
                "Verifica que el puerto UDP 4242 de salida no esté bloqueado por el firewall corporativo",
                "Ejecuta: Test-NetConnection 3.143.18.161 -Port 4242  (en PowerShell)",
                "Confirma con el administrador que el certificado esté activo (no revocado)",
                "Revisa los logs de Nebula: busca mensajes de error en la consola o en eventvwr",
            ]
        ),
        (
            "❌  El servicio se inicia pero se detiene solo",
            [
                "Abre el Visor de Eventos: Win + R → eventvwr → Registros de Windows → Aplicación",
                "Si usas NSSM, revisa C:\\Nebula\\nebula_stderr.log",
                "Prueba primero el arranque manual (Paso 7) para ver el error en tiempo real",
            ]
        ),
        (
            "❌  Windows Defender bloquea nebula.exe",
            [
                "Agrega una exclusión en Windows Security → Virus & threat protection → Exclusions",
                "O solicita al administrador que firme el binario con un certificado de código",
            ]
        ),
    ]

    for title_text, bullets in problems:
        story.append(KeepTogether([
            Paragraph(title_text, st["h3"]),
            *[Paragraph(f"  •  {b}", st["bullet"]) for b in bullets],
            Spacer(1, 0.2*cm),
        ]))

    # ── PIE FINAL ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.8*cm))
    story.append(hr(C_DIM))
    story.append(Paragraph(
        "Datacom Security — Soporte: http://3.143.18.161:8040 — Uso exclusivo interno",
        ParagraphStyle("footer_end", fontName="Helvetica", fontSize=8,
                       textColor=C_DIM, alignment=TA_CENTER)))

    # ── BUILD ──────────────────────────────────────────────────────────────────
    doc.build(story,
              onFirstPage=on_page_cover,
              onLaterPages=on_page)
    print(f"PDF generado: {OUTPUT}")


if __name__ == "__main__":
    build_pdf()
