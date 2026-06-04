#!/usr/bin/env python3
"""
Genera el manual PDF de instalación de Nebula VPN para Windows 10/11.
Guardado en: /opt/scanner/vpn_configs/Nebula-Windows-Manual-ES.pdf
"""

import os
import sys
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)

OUTPUT = "/opt/scanner/vpn_configs/Nebula-Windows-Manual-ES.pdf"
LOGO   = os.path.join(os.path.dirname(__file__), "logo_datacom.png")

# ── Paleta corporativa ──────────────────────────────────────────────────────
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
                           "Manual de Instalación — Nebula VPN para Windows")
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
                fontName="Helvetica-Bold", spaceBefore=16, spaceAfter=5),
        "h2": s("h2", fontSize=11, leading=16, textColor=C_GREEN,
                fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4),
        "h3": s("h3", fontSize=10, leading=14, textColor=C_ORANGE,
                fontName="Helvetica-Bold", spaceBefore=7, spaceAfter=3),
        "body": s("body", fontSize=9.5, leading=15, textColor=C_FG,
                  fontName="Helvetica", alignment=TA_JUSTIFY,
                  spaceBefore=3, spaceAfter=4),
        "bullet": s("bullet", fontSize=9.5, leading=14, textColor=C_FG,
                    fontName="Helvetica", leftIndent=14, spaceBefore=2),
        "code": s("code", fontSize=8.5, leading=13, textColor=C_YELLOW,
                  fontName="Courier", backColor=C_ROW1,
                  leftIndent=10, rightIndent=10,
                  spaceBefore=4, spaceAfter=4),
        "code_label": s("code_label", fontSize=7.5, leading=11, textColor=C_DIM,
                        fontName="Courier", leftIndent=10, spaceBefore=1, spaceAfter=0),
        "note": s("note", fontSize=9, leading=13, textColor=C_BLUE,
                  fontName="Helvetica-Oblique",
                  leftIndent=12, spaceBefore=4, spaceAfter=4),
        "warning": s("warning", fontSize=9, leading=13, textColor=C_ORANGE,
                     fontName="Helvetica-Bold",
                     leftIndent=12, spaceBefore=4, spaceAfter=4),
        "step_num": s("step_num", fontSize=22, leading=26, textColor=C_BLUE,
                      fontName="Helvetica-Bold", alignment=TA_CENTER),
        "toc_h1": s("toc_h1", fontSize=10, leading=15, textColor=C_BLUE,
                    fontName="Helvetica-Bold", spaceBefore=4),
        "toc_h2": s("toc_h2", fontSize=9, leading=14, textColor=C_FG,
                    fontName="Helvetica", leftIndent=16, spaceBefore=1),
    }


def hr(color=C_BLUE, thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness,
                      color=color, spaceAfter=6, spaceBefore=6)


def dark_table(data, col_widths, header_bg=C_GRAY, alt=True):
    style = [
        ("BACKGROUND",   (0, 0), (-1, 0),  header_bg),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  WHITE),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0),  9),
        ("ALIGN",        (0, 0), (-1, 0),  "CENTER"),
        ("BOTTOMPADDING",(0, 0), (-1, 0),  7),
        ("TOPPADDING",   (0, 0), (-1, 0),  7),
        ("FONTNAME",     (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",     (0, 1), (-1, -1), 8.5),
        ("TEXTCOLOR",    (0, 1), (-1, -1), C_FG),
        ("ALIGN",        (0, 1), (-1, -1), "LEFT"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",   (0, 1), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 1), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("GRID",         (0, 0), (-1, -1), 0.3, C_GRAY),
        ("ROWBACKGROUNDS",(0, 1),(-1, -1), [C_ROW1, C_ROW2] if alt else [C_ROW1]),
    ]
    return Table(data, colWidths=col_widths,
                 style=TableStyle(style), repeatRows=1)


def step_box(number, title, st):
    """Caja visual de paso numerado."""
    data = [[
        Paragraph(str(number), st["step_num"]),
        Paragraph(title, ParagraphStyle(
            "st", parent=st["h1"],
            textColor=WHITE, spaceBefore=0, spaceAfter=0,
            fontSize=13, leading=18)),
    ]]
    t = Table(data, colWidths=[1.8*cm, W - 1.8*cm - 3.6*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), C_GRAY),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",(0, 0), (-1, -1), 10),
        ("TOPPADDING",  (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",(0,0), (-1, -1), 8),
        ("LINEBELOW",   (0, 0), (-1, -1), 2, C_BLUE),
    ]))
    return t


# ══════════════════════════════════════════════════════════════════════════════
def build_pdf(output_path=OUTPUT):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm,
        topMargin=2.2*cm, bottomMargin=1.6*cm,
    )
    st = make_styles()
    story = []

    MESES_ES = [
        "", "enero", "febrero", "marzo", "abril", "mayo", "junio",
        "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre",
    ]
    now = datetime.now()
    fecha = f"{now.day} de {MESES_ES[now.month]} de {now.year}"

    # ── PORTADA ──────────────────────────────────────────────────────────────
    story.append(Spacer(1, 3.0*cm))
    if os.path.exists(LOGO):
        try:
            from reportlab.platypus import Image
            story.append(Image(LOGO, width=5*cm, height=2*cm, kind="proportional"))
            story.append(Spacer(1, 0.6*cm))
        except Exception:
            pass

    story.append(Paragraph("Manual de Instalación", st["cover_sub"]))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Nebula VPN", st["cover_title"]))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("para Windows 10 / 11", st["cover_sub"]))
    story.append(Spacer(1, 0.8*cm))
    story.append(hr(C_BLUE, 1))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        "Guía paso a paso para instalar y configurar el cliente Nebula VPN<br/>"
        "en equipos de escritorio con Windows 10 o Windows 11.<br/>"
        "Red corporativa: 10.0.0.0/24 — Servidor Kali: 3.143.18.161",
        st["cover_meta"]))
    story.append(Spacer(1, 1.6*cm))

    meta_data = [
        ["Versión",    "1.0"],
        ["Fecha",      fecha],
        ["Autor",      "Datacom Security"],
        ["Servidor",   "3.143.18.161 (AWS)"],
        ["Puerto VPN", "UDP 4242"],
        ["Red VPN",    "10.0.0.0/24"],
        ["Contacto",   "soporte@datacomsecurity.com"],
    ]
    t = Table(meta_data, colWidths=[3.5*cm, 10*cm])
    t.setStyle(TableStyle([
        ("FONTNAME",        (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",        (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",        (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",       (0, 0), (0, -1), C_DIM),
        ("TEXTCOLOR",       (1, 0), (1, -1), WHITE),
        ("ALIGN",           (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",          (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",      (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",   (0, 0), (-1, -1), 5),
        ("LINEBELOW",       (0, 0), (-1, -2), 0.3, C_GRAY),
    ]))
    story.append(t)
    story.append(PageBreak())

    # ── TABLA DE CONTENIDOS ──────────────────────────────────────────────────
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Tabla de Contenidos", st["h1"]))
    story.append(hr())

    toc = [
        ("1.", "Introducción a Nebula VPN"),
        ("2.", "Requisitos del Sistema"),
        ("3.", "Paso 1: Descargar Nebula"),
        ("4.", "Paso 2: Instalar y Extraer Archivos"),
        ("5.", "Paso 3: Obtener Certificados del Servidor"),
        ("6.", "Paso 4: Configurar Archivos"),
        ("7.", "Paso 5: Crear Acceso Directo"),
        ("8.", "Paso 6: Iniciar Nebula VPN"),
        ("9.", "Paso 7: Verificar Conexión"),
        ("10.", "Paso 8: Solucionar Problemas"),
        ("11.", "Apéndice: Comandos Útiles"),
        ("12.", "Contacto y Soporte"),
    ]
    for num, title in toc:
        line = Table(
            [[Paragraph(num, st["toc_h1"]), Paragraph(title, st["toc_h1"])]],
            colWidths=[1.2*cm, 13.8*cm],
        )
        line.setStyle(TableStyle([
            ("VALIGN",          (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING",     (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",    (0, 0), (-1, -1), 0),
            ("TOPPADDING",      (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",   (0, 0), (-1, -1), 3),
            ("LINEBELOW",       (0, 0), (-1, -1), 0.2, C_GRAY),
        ]))
        story.append(line)

    story.append(PageBreak())

    # ── 1. INTRODUCCIÓN ──────────────────────────────────────────────────────
    story.append(Paragraph("1. Introducción a Nebula VPN", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "<b>Nebula</b> es una herramienta de red superpuesta (overlay network) de código abierto "
        "desarrollada por Slack. A diferencia de soluciones tradicionales como OpenVPN o WireGuard, "
        "Nebula implementa su propia infraestructura PKI (Public Key Infrastructure) con certificados "
        "firmados internamente, lo que permite un control granular de qué nodos pueden comunicarse "
        "entre sí y bajo qué condiciones.",
        st["body"]))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("Ventajas de Nebula sobre otras soluciones VPN:", st["h2"]))

    ventajas = [
        ["Característica", "OpenVPN", "WireGuard", "Nebula"],
        ["Protocolo",      "TCP/UDP",  "UDP",       "UDP"],
        ["PKI propia",     "No",       "No",        "Sí"],
        ["Hole-punching",  "No",       "Limitado",  "Sí (nativo)"],
        ["Firewall integrado", "No",   "No",        "Sí"],
        ["Lighthouse (coordinador)", "No", "No",    "Sí"],
        ["Certs gestionados en UI",  "No", "No",    "Sí"],
    ]
    story.append(dark_table(ventajas, [5*cm, 2.5*cm, 2.5*cm, 2.5*cm]))
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("Arquitectura de la red:", st["h2"]))
    arch_txt = (
        "El servidor <b>Kali Linux</b> actúa como <b>Lighthouse</b> (nodo central de "
        "coordinación). Cada cliente Windows recibe un certificado único firmado por la CA "
        "del servidor y se conecta directamente usando UDP hole-punching, sin necesidad de "
        "configuración adicional de NAT o port-forwarding."
    )
    story.append(Paragraph(arch_txt, st["body"]))

    net_data = [
        ["Nodo",            "IP VPN",      "Rol"],
        ["Servidor Kali",   "10.0.0.1",    "Lighthouse (coordinador)"],
        ["Cliente Windows", "10.0.0.100",  "Cliente (office-scan)"],
        ["Otros clientes",  "10.0.0.x",    "Clientes adicionales"],
    ]
    story.append(dark_table(net_data, [5*cm, 3*cm, 6.2*cm]))
    story.append(PageBreak())

    # ── 2. REQUISITOS ────────────────────────────────────────────────────────
    story.append(Paragraph("2. Requisitos del Sistema", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Antes de comenzar la instalación, asegúrate de cumplir con los siguientes requisitos:",
        st["body"]))

    story.append(Paragraph("Requisitos de hardware y software:", st["h2"]))
    req_data = [
        ["Requisito",       "Mínimo",               "Recomendado"],
        ["Sistema Operativo","Windows 10 64-bit",   "Windows 11 64-bit"],
        ["RAM",             "2 GB",                  "4 GB o más"],
        ["Espacio en disco","50 MB libres",          "100 MB libres"],
        ["Permisos",        "Administrador local",   "Administrador local"],
        ["Conexión red",    "Acceso a internet/LAN", "Acceso a internet"],
        ["Puerto saliente", "UDP 4242 abierto",      "UDP 4242 abierto"],
    ]
    story.append(dark_table(req_data, [4.5*cm, 4*cm, 5.7*cm]))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "⚠ <b>Importante:</b> La instalación de Nebula requiere privilegios de <b>Administrador</b> "
        "en Windows para poder crear la interfaz de red virtual (TUN). Asegúrate de ejecutar "
        "los scripts con «Ejecutar como administrador».",
        st["warning"]))

    story.append(Paragraph("Información de la red VPN:", st["h2"]))
    vpn_data = [
        ["Parámetro",       "Valor"],
        ["Servidor Kali",   "3.143.18.161"],
        ["Puerto Nebula",   "UDP 4242"],
        ["Red VPN",         "10.0.0.0/24"],
        ["IP del lighthouse","10.0.0.1"],
        ["IP Windows cliente","10.0.0.100"],
        ["Nombre del nodo", "office-scan"],
    ]
    story.append(dark_table(vpn_data, [5*cm, 9.2*cm]))
    story.append(PageBreak())

    # ── PASO 1 ───────────────────────────────────────────────────────────────
    story.append(step_box(1, "Descargar Nebula", st))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        "Nebula se distribuye como un binario único sin instalador. "
        "Descarga la versión oficial desde GitHub:", st["body"]))

    story.append(Paragraph("URL de descarga directa:", st["h2"]))
    story.append(Paragraph(
        "https://github.com/slackhq/nebula/releases/latest",
        st["code"]))
    story.append(Paragraph(
        "Busca el archivo: <b>nebula-windows-amd64.zip</b> (para Windows 64-bit)",
        st["body"]))

    dl_data = [
        ["Archivo",                     "Sistema",    "Arquitectura"],
        ["nebula-windows-amd64.zip",    "Windows",    "64-bit (Intel/AMD)"],
        ["nebula-linux-amd64.tar.gz",   "Linux",      "64-bit (servidor)"],
        ["nebula-darwin-amd64.tar.gz",  "macOS",      "Intel"],
        ["nebula-darwin-arm64.tar.gz",  "macOS",      "Apple Silicon (M1/M2)"],
    ]
    story.append(dark_table(dl_data, [7*cm, 3*cm, 4.2*cm]))

    story.append(Paragraph("Pasos de descarga:", st["h2"]))
    for item in [
        "Abre tu navegador (Chrome, Edge o Firefox)",
        "Ve a: https://github.com/slackhq/nebula/releases/latest",
        "En la sección <b>Assets</b>, haz clic en <b>nebula-windows-amd64.zip</b>",
        "Guarda el archivo en tu carpeta de <b>Descargas</b>",
        "Verifica que el archivo descargado pese aproximadamente 15-20 MB",
    ]:
        story.append(Paragraph(f"• {item}", st["bullet"]))
    story.append(PageBreak())

    # ── PASO 2 ───────────────────────────────────────────────────────────────
    story.append(step_box(2, "Instalar y Extraer Archivos", st))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        "Nebula no requiere un instalador tradicional. Solo necesitas extraer el ZIP "
        "y colocar los archivos en una carpeta permanente.", st["body"]))

    story.append(Paragraph("Crear la carpeta de instalación:", st["h2"]))
    story.append(Paragraph(
        "Abre el <b>Explorador de Windows</b> (Win+E) y crea la siguiente carpeta:",
        st["body"]))
    story.append(Paragraph("C:\\nebula\\", st["code"]))

    story.append(Paragraph("Extraer el archivo ZIP:", st["h2"]))
    for step, text in [
        ("1", "Navega a tu carpeta de <b>Descargas</b>"),
        ("2", "Haz clic derecho en <b>nebula-windows-amd64.zip</b>"),
        ("3", "Selecciona «<b>Extraer todo...</b>»"),
        ("4", "En la ventana que aparece, escribe la ruta destino: <b>C:\\nebula</b>"),
        ("5", "Haz clic en <b>Extraer</b>"),
        ("6", "Verifica que aparezcan los archivos en <b>C:\\nebula\\</b>"),
    ]:
        story.append(Paragraph(f"  <b>{step}.</b> {text}", st["bullet"]))

    story.append(Paragraph("Estructura de carpetas esperada:", st["h2"]))
    story.append(Paragraph(
        "C:\\nebula\\nebula.exe        (binario principal)\n"
        "C:\\nebula\\nebula-cert.exe   (herramienta de certificados)",
        st["code"]))
    story.append(Paragraph(
        "ℹ Una vez instalados los certificados en el siguiente paso, la carpeta tendrá esta estructura completa:",
        st["note"]))
    story.append(Paragraph(
        "C:\\nebula\\\n"
        "  nebula.exe\n"
        "  nebula-cert.exe\n"
        "  ca.crt\n"
        "  office-scan.crt\n"
        "  office-scan.key\n"
        "  config.yml\n"
        "  iniciar_nebula.bat    (acceso directo, se crea en Paso 5)",
        st["code"]))
    story.append(PageBreak())

    # ── PASO 3 ───────────────────────────────────────────────────────────────
    story.append(step_box(3, "Obtener Certificados del Servidor", st))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        "Los certificados son generados y firmados por el servidor Kali. "
        "Descárgalos desde la interfaz web del servidor.", st["body"]))

    story.append(Paragraph("Acceder al servidor:", st["h2"]))
    story.append(Paragraph(
        "Abre tu navegador y navega a:",
        st["body"]))
    story.append(Paragraph("http://3.143.18.161:8040", st["code"]))

    story.append(Paragraph("Descargar los certificados:", st["h2"]))
    for step, text in [
        ("1", "En el menú superior, haz clic en la pestaña «<b>🌐 Nebula VPN</b>»"),
        ("2", "En la tabla de <b>Certificados Emitidos</b>, localiza el nodo <b>office-scan</b>"),
        ("3", "Haz clic en el botón «<b>⬇ ZIP</b>» de ese nodo"),
        ("4", "Se descargará un archivo <b>office-scan.zip</b> con todos los archivos necesarios"),
        ("5", "Guarda el ZIP en tu carpeta de Descargas"),
    ]:
        story.append(Paragraph(f"  <b>{step}.</b> {text}", st["bullet"]))

    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("Contenido del bundle ZIP:", st["h2"]))
    bundle_data = [
        ["Archivo",           "Descripción"],
        ["ca.crt",            "Certificado de la CA (autoridad certificadora del servidor)"],
        ["office-scan.crt",   "Certificado del cliente (identidad de este nodo)"],
        ["office-scan.key",   "Clave privada del cliente (¡mantener en secreto!)"],
        ["config.yml",        "Archivo de configuración pre-configurado para Windows"],
    ]
    story.append(dark_table(bundle_data, [4*cm, 10.2*cm]))

    story.append(Paragraph(
        "⚠ <b>Seguridad:</b> El archivo <b>.key</b> es la clave privada del nodo. "
        "Nunca lo compartas ni lo subas a servicios en la nube. Si se compromete, "
        "contacta con soporte para revocar y regenerar el certificado.",
        st["warning"]))
    story.append(PageBreak())

    # ── PASO 4 ───────────────────────────────────────────────────────────────
    story.append(step_box(4, "Configurar Archivos", st))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        "Copia los certificados descargados a la carpeta de Nebula y verifica "
        "el archivo de configuración.", st["body"]))

    story.append(Paragraph("Copiar los certificados:", st["h2"]))
    for step, text in [
        ("1", "Extrae el ZIP descargado en el paso anterior"),
        ("2", "Copia los 4 archivos a la carpeta <b>C:\\nebula\\</b>:"),
    ]:
        story.append(Paragraph(f"  <b>{step}.</b> {text}", st["bullet"]))

    story.append(Paragraph(
        "copy \"%USERPROFILE%\\Downloads\\ca.crt\" C:\\nebula\\\n"
        "copy \"%USERPROFILE%\\Downloads\\office-scan.crt\" C:\\nebula\\\n"
        "copy \"%USERPROFILE%\\Downloads\\office-scan.key\" C:\\nebula\\\n"
        "copy \"%USERPROFILE%\\Downloads\\config.yml\" C:\\nebula\\",
        st["code"]))
    story.append(Paragraph(
        "También puedes arrastrar y soltar los archivos directamente con el Explorador de Windows.",
        st["note"]))

    story.append(Paragraph("Verificar el archivo config.yml:", st["h2"]))
    story.append(Paragraph(
        "Abre el archivo <b>C:\\nebula\\config.yml</b> con el Bloc de notas. "
        "Debe tener el siguiente contenido (el bundle ya lo incluye pre-configurado):",
        st["body"]))
    story.append(Paragraph(
        "pki:\n"
        "  ca: ./ca.crt\n"
        "  cert: ./office-scan.crt\n"
        "  key: ./office-scan.key\n\n"
        "static_host_map:\n"
        "  \"10.0.0.1\": [\"3.143.18.161:4242\"]\n\n"
        "lighthouse:\n"
        "  am_lighthouse: false\n"
        "  interval: 60\n"
        "  hosts:\n"
        "    - \"10.0.0.1\"\n\n"
        "listen:\n"
        "  host: 0.0.0.0\n"
        "  port: 0\n\n"
        "punchy:\n"
        "  punch: true\n"
        "  respond: true\n\n"
        "firewall:\n"
        "  outbound:\n"
        "    - port: any\n"
        "      proto: any\n"
        "      host: any\n"
        "  inbound:\n"
        "    - port: any\n"
        "      proto: any\n"
        "      host: any",
        st["code"]))
    story.append(PageBreak())

    # ── PASO 5 ───────────────────────────────────────────────────────────────
    story.append(step_box(5, "Crear Acceso Directo (Script Batch)", st))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        "Crea un script <b>.bat</b> para iniciar Nebula fácilmente sin tener que "
        "escribir comandos manualmente cada vez.", st["body"]))

    story.append(Paragraph("Crear el archivo iniciar_nebula.bat:", st["h2"]))
    for step, text in [
        ("1", "Abre el <b>Bloc de notas</b> (busca «Notepad» en el menú Inicio)"),
        ("2", "Copia y pega el siguiente contenido:"),
    ]:
        story.append(Paragraph(f"  <b>{step}.</b> {text}", st["bullet"]))

    story.append(Paragraph(
        "@echo off\n"
        "title Nebula VPN - office-scan\n"
        "cd /d C:\\nebula\n\n"
        "echo ============================================\n"
        "echo  Iniciando Nebula VPN\n"
        "echo  Red: 10.0.0.0/24\n"
        "echo  Servidor: 3.143.18.161:4242\n"
        "echo ============================================\n"
        "echo.\n\n"
        "REM Verificar que nebula.exe existe\n"
        "if not exist nebula.exe (\n"
        "    echo ERROR: nebula.exe no encontrado en C:\\nebula\n"
        "    pause\n"
        "    exit /b 1\n"
        ")\n\n"
        "REM Verificar que config.yml existe\n"
        "if not exist config.yml (\n"
        "    echo ERROR: config.yml no encontrado en C:\\nebula\n"
        "    pause\n"
        "    exit /b 1\n"
        ")\n\n"
        "echo Iniciando Nebula VPN...\n"
        "nebula.exe -config config.yml\n\n"
        "echo.\n"
        "echo Nebula VPN detenida.\n"
        "pause",
        st["code"]))

    for step, text in [
        ("3", "Guarda el archivo: <b>Archivo → Guardar como...</b>"),
        ("4", "En «<b>Nombre de archivo</b>», escribe: <b>C:\\nebula\\iniciar_nebula.bat</b>"),
        ("5", "En «<b>Tipo</b>», selecciona: <b>Todos los archivos (*.*)</b>"),
        ("6", "Haz clic en <b>Guardar</b>"),
    ]:
        story.append(Paragraph(f"  <b>{step}.</b> {text}", st["bullet"]))

    story.append(Paragraph(
        "ℹ Para crear un acceso directo en el Escritorio: haz clic derecho en "
        "<b>iniciar_nebula.bat</b> → «<b>Crear acceso directo</b>» → arrastra el acceso al Escritorio.",
        st["note"]))
    story.append(PageBreak())

    # ── PASO 6 ───────────────────────────────────────────────────────────────
    story.append(step_box(6, "Iniciar Nebula VPN", st))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        "Una vez que los archivos estén en su lugar, sigue estos pasos para "
        "iniciar la conexión VPN.", st["body"]))

    story.append(Paragraph("⚠ Ejecutar siempre como Administrador:", st["h3"]))
    story.append(Paragraph(
        "Nebula necesita permisos de administrador para crear la interfaz de red virtual. "
        "Si no se ejecuta como administrador, fallará con un error de permisos.",
        st["body"]))

    story.append(Paragraph("Pasos para iniciar Nebula:", st["h2"]))
    for step, text in [
        ("1", "Haz clic derecho en el archivo <b>iniciar_nebula.bat</b> (o su acceso directo)"),
        ("2", "Selecciona «<b>Ejecutar como administrador</b>»"),
        ("3", "Si aparece el aviso de Control de Cuentas (UAC), haz clic en «<b>Sí</b>»"),
        ("4", "Aparecerá una ventana de terminal negra con los logs de Nebula"),
        ("5", "Espera unos segundos a que Nebula establezca la conexión"),
    ]:
        story.append(Paragraph(f"  <b>{step}.</b> {text}", st["bullet"]))

    story.append(Paragraph("Logs esperados al iniciar correctamente:", st["h2"]))
    story.append(Paragraph(
        "time=\"...\" level=info msg=\"Firewall rule added\" ...\n"
        "time=\"...\" level=info msg=\"Listening on\" addr=\"0.0.0.0:0\"\n"
        "time=\"...\" level=info msg=\"Nebula interface is active\" ...\n"
        "time=\"...\" level=info msg=\"Main HostMap created\" network=10.0.0.100/24",
        st["code"]))

    story.append(Paragraph("Estado de la ventana:", st["h2"]))
    status_data = [
        ["Lo que ves",                      "Significado"],
        ["\"Nebula interface is active\"",  "✓ Conexión establecida correctamente"],
        ["\"Listening on 0.0.0.0\"",        "✓ Nebula está escuchando"],
        ["\"Main HostMap created\"",         "✓ Red VPN lista"],
        ["Ventana vacía / sin errores",      "⏳ Conectando... espera unos segundos"],
        ["\"ERROR\" en rojo",               "✗ Ver sección Solución de Problemas"],
    ]
    story.append(dark_table(status_data, [7*cm, 7.2*cm]))
    story.append(PageBreak())

    # ── PASO 7 ───────────────────────────────────────────────────────────────
    story.append(step_box(7, "Verificar la Conexión", st))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        "Después de iniciar Nebula, verifica que la conexión VPN funciona correctamente "
        "desde el <b>Símbolo del sistema</b> (CMD) de Windows.", st["body"]))

    story.append(Paragraph("Abrir el Símbolo del sistema:", st["h2"]))
    story.append(Paragraph(
        "Presiona <b>Win+R</b>, escribe <b>cmd</b> y presiona <b>Enter</b>.",
        st["body"]))

    story.append(Paragraph("Comandos de verificación:", st["h2"]))
    checks = [
        ("Verificar interfaz de red Nebula:",
         "ipconfig /all | findstr /i \"nebula\"\n"
         "REM Debe mostrar la interfaz nebula con IP 10.0.0.100"),
        ("Verificar la IP asignada:",
         "ipconfig\n"
         "REM Busca: Ethernet adapter nebula:\n"
         "REM        IPv4 Address. . . . : 10.0.0.100"),
        ("Hacer ping al servidor (lighthouse):",
         "ping 10.0.0.1\n"
         "REM Respuesta esperada:\n"
         "REM Reply from 10.0.0.1: bytes=32 time=20ms TTL=64"),
        ("Verificar ruta a la red VPN:",
         "route print | findstr 10.0.0\n"
         "REM Debe mostrar la ruta 10.0.0.0/24"),
    ]
    for label, code in checks:
        story.append(Paragraph(label, st["h3"]))
        story.append(Paragraph(code, st["code"]))

    story.append(Paragraph("Prueba de conectividad completa:", st["h2"]))
    story.append(Paragraph(
        "REM Ping al servidor Kali por su IP VPN\n"
        "ping 10.0.0.1 -n 4\n\n"
        "REM Traceroute para ver el camino\n"
        "tracert 10.0.0.1",
        st["code"]))

    story.append(Paragraph(
        "ℹ Si el ping a 10.0.0.1 responde, la VPN está funcionando correctamente. "
        "Ahora puedes acceder a la red interna mediante las IPs 10.0.0.x.",
        st["note"]))
    story.append(PageBreak())

    # ── PASO 8 ───────────────────────────────────────────────────────────────
    story.append(step_box(8, "Solucionar Problemas", st))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        "Si Nebula no conecta correctamente, consulta la siguiente tabla de errores comunes:",
        st["body"]))

    story.append(Paragraph("Errores frecuentes y soluciones:", st["h2"]))
    errors = [
        ["Error / Síntoma",                        "Causa probable",               "Solución"],
        ["\"access denied\" o UAC bloqueado",
         "No se ejecutó como admin",
         "Clic derecho → Ejecutar como administrador"],
        ["\"config.yml: no such file\"",
         "config.yml no está en C:\\nebula",
         "Copia config.yml desde el bundle al directorio C:\\nebula"],
        ["\"failed to read ca\"",
         "ca.crt faltante o ruta incorrecta",
         "Verifica que ca.crt esté en C:\\nebula"],
        ["Ping a 10.0.0.1 falla",
         "Puerto UDP 4242 bloqueado",
         "Revisa el firewall de Windows y el router"],
        ["\"invalid certificate\"",
         "Certificado expirado o corrupto",
         "Descarga nuevos certificados desde el servidor"],
        ["Ventana se cierra inmediatamente",
         "Error de sintaxis en config.yml",
         "Abre CMD y ejecuta: nebula.exe -config config.yml"],
        ["No aparece interfaz nebula",
         "Driver TAP no instalado",
         "Instala el driver TAP-Windows desde el bundle"],
    ]
    story.append(dark_table(errors, [4.5*cm, 4*cm, 5.7*cm]))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Verificar el firewall de Windows:", st["h2"]))
    for item in [
        "Abre «<b>Configuración</b>» → «<b>Actualización y seguridad</b>» → «<b>Seguridad de Windows</b>»",
        "Haz clic en «<b>Firewall y protección de red</b>»",
        "Selecciona «<b>Permitir una aplicación a través del firewall</b>»",
        "Haz clic en «<b>Cambiar configuración</b>» y luego «<b>Permitir otra aplicación</b>»",
        "Navega a <b>C:\\nebula\\nebula.exe</b> y agrégalo",
        "Marca tanto «<b>Privada</b>» como «<b>Pública</b>»",
    ]:
        story.append(Paragraph(f"• {item}", st["bullet"]))

    story.append(Paragraph(
        "⚠ Si el problema persiste, ejecuta el siguiente comando en CMD (como admin) "
        "para ver logs detallados:",
        st["warning"]))
    story.append(Paragraph(
        "cd C:\\nebula\n"
        "nebula.exe -config config.yml 2>&1 | more",
        st["code"]))
    story.append(PageBreak())

    # ── APÉNDICE ─────────────────────────────────────────────────────────────
    story.append(Paragraph("11. Apéndice: Comandos Útiles", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Referencia rápida de comandos de Windows para gestionar la conexión Nebula VPN:",
        st["body"]))

    cmd_data = [
        ["Tarea",                       "Comando (ejecutar en CMD)"],
        ["Iniciar Nebula",
         "cd C:\\nebula && nebula.exe -config config.yml"],
        ["Ver interfaces de red",
         "ipconfig /all"],
        ["Verificar interfaz Nebula",
         "ipconfig | findstr /i \"nebula 10.0.0\""],
        ["Ping al servidor VPN",
         "ping 10.0.0.1"],
        ["Ver tabla de rutas",
         "route print"],
        ["Probar puerto UDP 4242",
         "nmap -sU -p 4242 3.143.18.161"],
        ["Ver conexiones activas",
         "netstat -an | findstr 4242"],
        ["Flush DNS",
         "ipconfig /flushdns"],
        ["Verificar certificado",
         "nebula-cert.exe print -path C:\\nebula\\office-scan.crt"],
    ]
    story.append(dark_table(cmd_data, [5*cm, 9.2*cm]))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Verificar versión de Nebula:", st["h2"]))
    story.append(Paragraph(
        "cd C:\\nebula\n"
        "nebula.exe -version",
        st["code"]))

    story.append(Paragraph("Detener Nebula:", st["h2"]))
    story.append(Paragraph(
        "Presiona <b>Ctrl+C</b> en la ventana de Nebula para detenerla, "
        "o cierra directamente la ventana de terminal.",
        st["body"]))
    story.append(PageBreak())

    # ── CONTACTO Y SOPORTE ───────────────────────────────────────────────────
    story.append(Paragraph("12. Contacto y Soporte", st["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Si tienes problemas con la instalación o conexión de Nebula VPN, "
        "contacta con el equipo de soporte de Datacom Security:",
        st["body"]))

    contact_data = [
        ["Canal",           "Detalle"],
        ["Email",           "soporte@datacomsecurity.com"],
        ["Web UI",          "http://3.143.18.161:8040"],
        ["Servidor VPN",    "3.143.18.161:4242 (UDP)"],
        ["Horario",         "Lunes–Viernes, 09:00–18:00 (UTC-5)"],
    ]
    story.append(dark_table(contact_data, [4*cm, 10.2*cm]))

    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("Al reportar un problema, incluye:", st["h2"]))
    for item in [
        "Sistema operativo Windows y versión (ej: Windows 11 Pro 23H2)",
        "Versión de Nebula instalada (resultado de <b>nebula.exe -version</b>)",
        "Contenido del log de error (captura de pantalla de la ventana CMD)",
        "Resultado de <b>ipconfig /all</b>",
        "Si el puerto UDP 4242 está abierto en tu router/firewall corporativo",
    ]:
        story.append(Paragraph(f"• {item}", st["bullet"]))

    story.append(Spacer(1, 0.5*cm))
    story.append(hr(C_BLUE, 1))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        f"Manual generado el {fecha} — Datacom Security<br/>"
        "Uso exclusivo interno. No distribuir.",
        ParagraphStyle("footer_note",
            parent=getSampleStyleSheet()["Normal"],
            fontSize=8, textColor=C_DIM, alignment=TA_CENTER)))

    # ── Build ────────────────────────────────────────────────────────────────
    doc.build(story,
              onFirstPage=on_page_cover,
              onLaterPages=on_page)
    return output_path


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else OUTPUT
    path = build_pdf(out)
    print(f"Manual generado: {path}")
