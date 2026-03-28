#!/usr/bin/env python3
"""
Kali VPN Vulnerability Scanner — Web UI
Corre en el servidor Kali en el puerto 8040.
Acceder desde: http://<kali-ip>:8040
"""

import os, json, re, datetime, subprocess, threading, time, uuid, shutil
from flask import Flask, render_template_string, request, jsonify, Response, stream_with_context

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

# ── State ─────────────────────────────────────────────────────────────────────
active_scans: dict[str, dict] = {}   # scan_id -> {proc, lines[], done, client, target}
vpn_state     = {"active": False, "client": "", "iface": ""}

SCAN_PROFILES = {
    "Descubrimiento (hosts vivos)":    "sudo nmap -sn {target}",
    "Puertos top-1000":                "sudo nmap -sS -T4 --open {target}",
    "Puertos completos (1-65535)":     "sudo nmap -sS -T4 -p- --open {target}",
    "Versiones + Sistema Operativo":   "sudo nmap -sS -sV -O -T4 {target}",
    "Vulnerabilidades NSE (vuln)":     "sudo nmap -sV --script vuln -T4 {target}",
    "Vuln + SO + Versiones (completo)":"sudo nmap -sS -sV -O --script vuln -T4 {target}",
    "CVEs con CVSS (vulners)":         "sudo nmap -sV --script vulners --script-args mincvss=5.0 -T4 {target}",
    "Web / HTTP (nikto)":              "nikto -h {target}",
    "SMB vulnerabilidades":            "sudo nmap -p445 --script smb-vuln* -T4 {target}",
    "SSL/TLS (sslscan)":               "sslscan {target}",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

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

# ── API: Clients ──────────────────────────────────────────────────────────────

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

# ── API: VPN ──────────────────────────────────────────────────────────────────

@app.route("/api/vpn/connect", methods=["POST"])
def api_vpn_connect():
    name = request.json.get("client", "")
    clients = load_clients()
    if name not in clients:
        return jsonify({"error": "Cliente no encontrado"}), 404
    c = clients[name]
    threading.Thread(target=_vpn_connect_bg, args=(name, c), daemon=True).start()
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
            cmd = ["sudo","openvpn","--config",vpn_path,"--auth-user-pass",cred,"--daemon","--log","/tmp/openvpn_scanner.log"]
        else:
            cmd = ["sudo","openvpn","--config",vpn_path,"--daemon","--log","/tmp/openvpn_scanner.log"]
        iface = "tun0"
    else:
        cmd = ["sudo","wg-quick","up",vpn_path]
        iface = "wg0"

    subprocess.run(cmd, capture_output=True)

    for _ in range(20):
        time.sleep(2)
        r = subprocess.run(["ip","a","show",iface], capture_output=True, text=True)
        if "inet " in r.stdout:
            vpn_state["active"] = True
            vpn_state["client"] = name
            vpn_state["iface"]  = iface
            return
    vpn_state["active"] = False

@app.route("/api/vpn/disconnect", methods=["POST"])
def api_vpn_disconnect():
    if vpn_state["iface"] == "tun0":
        subprocess.run(["sudo","pkill","openvpn"], capture_output=True)
    else:
        c = load_clients().get(vpn_state["client"], {})
        subprocess.run(["sudo","wg-quick","down", c.get("vpn_path","")], capture_output=True)
    vpn_state["active"] = False
    vpn_state["client"] = ""
    vpn_state["iface"]  = ""
    return jsonify({"ok": True})

@app.route("/api/vpn/status")
def api_vpn_status():
    if vpn_state["active"] and vpn_state["iface"]:
        r = subprocess.run(["ip","a","show", vpn_state["iface"]], capture_output=True, text=True)
        ip = ""
        for line in r.stdout.splitlines():
            if "inet " in line:
                ip = line.strip()
                break
        return jsonify({**vpn_state, "ip": ip})
    return jsonify(vpn_state)

# ── API: Scan ─────────────────────────────────────────────────────────────────

@app.route("/api/scan/profiles")
def api_profiles():
    return jsonify(SCAN_PROFILES)

@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    data = request.json
    target  = data.get("target", "").strip()
    cmd_tpl = data.get("command", "").strip()
    client  = data.get("client", "")
    profile = data.get("profile", "")

    if not target or not cmd_tpl:
        return jsonify({"error": "target y command son requeridos"}), 400

    cmd = cmd_tpl.replace("{target}", target)
    scan_id = str(uuid.uuid4())[:8]

    header = (
        f"{'═'*68}\n"
        f"[{now_str()}] ESCANEO INICIADO\n"
        f"  ID       : {scan_id}\n"
        f"  Cliente  : {client or 'N/A'}\n"
        f"  Objetivo : {target}\n"
        f"  Perfil   : {profile}\n"
        f"  Comando  : {cmd}\n"
        f"  VPN      : {'Activa ('+vpn_state['client']+')' if vpn_state['active'] else 'Inactiva'}\n"
        f"{'═'*68}\n"
    )

    active_scans[scan_id] = {
        "proc":    None,
        "lines":   [header],
        "done":    False,
        "client":  client,
        "target":  target,
        "profile": profile,
        "command": cmd,
        "start":   now_str(),
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
        for line in proc.stdout:
            state["lines"].append(line)
        proc.wait()
        elapsed = ""
        state["lines"].append(
            f"\n{'═'*68}\n[{now_str()}] ESCANEO COMPLETADO\n{'═'*68}\n"
        )
        # Save to disk
        safe = re.sub(r"[^a-zA-Z0-9._-]","_", state["target"])
        path = os.path.join(SCANS_DIR, f"scan_{safe}_{scan_id}.txt")
        with open(path, "w") as f:
            f.writelines(state["lines"])
        state["report_path"] = path
    except Exception as e:
        state["lines"].append(f"\n[ERROR] {e}\n")
    finally:
        state["done"] = True

@app.route("/api/scan/stop/<scan_id>", methods=["POST"])
def api_scan_stop(scan_id):
    s = active_scans.get(scan_id)
    if s and s["proc"]:
        s["proc"].terminate()
        s["done"] = True
    return jsonify({"ok": True})

@app.route("/api/scan/stream/<scan_id>")
def api_scan_stream(scan_id):
    """SSE stream — envía líneas del escaneo en tiempo real."""
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
                payload = json.dumps({"line": line, "sev": sev})
                yield f"data: {payload}\n\n"
                idx += 1
            if s["done"] and idx >= len(s["lines"]):
                yield f"data: {json.dumps({'done': True})}\n\n"
                break
            time.sleep(0.08)
    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})

@app.route("/api/scan/list")
def api_scan_list():
    out = []
    for sid, s in active_scans.items():
        out.append({
            "id":      sid,
            "client":  s["client"],
            "target":  s["target"],
            "profile": s["profile"],
            "start":   s["start"],
            "done":    s["done"],
        })
    return jsonify(out[::-1])

@app.route("/api/scan/export/<scan_id>")
def api_scan_export(scan_id):
    fmt = request.args.get("fmt", "txt")
    s = active_scans.get(scan_id)
    if not s:
        return "Not found", 404
    lines = s["lines"]
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", s["target"])
    fname = f"vuln_{safe}_{scan_id}.{fmt}"

    if fmt == "txt":
        content = "".join(lines)
        return Response(content, mimetype="text/plain",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})
    elif fmt == "json":
        data = {"scan_id": scan_id, **{k: s[k] for k in ("client","target","profile","command","start")},
                "lines": lines}
        return Response(json.dumps(data, indent=2, ensure_ascii=False),
                        mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})
    elif fmt == "html":
        rows = ""
        for line in lines:
            sev   = detect_severity(line)
            color = {"CRITICAL":"#ff4444","HIGH":"#ff8800","MEDIUM":"#ffcc00","LOW":"#44aaff","INFO":"#c9d1d9"}.get(sev,"#c9d1d9")
            esc   = line.replace("&","&amp;").replace("<","&lt;")
            rows += f'<tr style="color:{color}"><td class="sev">{sev}</td><td><code>{esc}</code></td></tr>\n'
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Vuln Report — {s['target']}</title>
<style>body{{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:24px}}
h1{{color:#58a6ff}} .meta{{color:#8b949e;margin-bottom:16px}}
table{{width:100%;border-collapse:collapse}}
td{{padding:3px 8px;border-bottom:1px solid #21262d;vertical-align:top}}
.sev{{width:80px;font-weight:bold}}</style></head><body>
<h1>Vulnerability Scan Report</h1>
<div class="meta">Cliente: <b>{s['client']}</b> &nbsp;|&nbsp; Objetivo: <b>{s['target']}</b><br>
Perfil: {s['profile']} &nbsp;|&nbsp; {s['start']}</div>
<table>{rows}</table></body></html>"""
        return Response(html, mimetype="text/html",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})
    return "fmt inválido", 400

# ── Main page ─────────────────────────────────────────────────────────────────

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
<style>
:root{
  --bg:#0d1117; --bg2:#161b22; --bg3:#21262d; --bg4:#30363d;
  --fg:#c9d1d9; --dim:#8b949e;
  --blue:#58a6ff; --green:#3fb950; --red:#f85149;
  --yellow:#e3b341; --orange:#f0883e;
  --c-crit:#ff4444; --c-high:#ff8800; --c-med:#ffcc00;
  --c-low:#44aaff;  --c-info:#c9d1d9;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font-family:'Segoe UI',system-ui,sans-serif;
     font-size:14px;height:100vh;display:flex;flex-direction:column;overflow:hidden}

/* ── Header ── */
header{background:var(--bg2);border-bottom:1px solid var(--bg4);
       padding:10px 20px;display:flex;align-items:center;gap:14px;flex-shrink:0}
header h1{font-size:1.25rem;color:var(--blue);font-weight:700}
header span{color:var(--dim);font-size:.85rem}
.badge-vpn{padding:3px 10px;border-radius:20px;font-size:.78rem;font-weight:700;
           background:var(--bg4);cursor:pointer;transition:background .2s}
.badge-vpn.on{background:#1a3a1a;color:var(--green)}
.badge-vpn.off{background:#3a1a1a;color:var(--red)}

/* ── Layout ── */
.layout{display:flex;flex:1;overflow:hidden}
.sidebar{width:270px;background:var(--bg2);border-right:1px solid var(--bg4);
         display:flex;flex-direction:column;flex-shrink:0;overflow:hidden}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}

/* ── Tabs ── */
.tabs{display:flex;border-bottom:1px solid var(--bg4);flex-shrink:0}
.tab{padding:10px 22px;cursor:pointer;color:var(--dim);border-bottom:2px solid transparent;
     transition:all .15s;font-weight:600;font-size:.88rem}
.tab.active{color:var(--blue);border-bottom-color:var(--blue)}
.tab-content{display:none;flex:1;overflow:hidden}
.tab-content.active{display:flex;flex-direction:column;overflow:hidden}

/* ── Sidebar: clients ── */
.sidebar-header{padding:10px 12px;font-size:.78rem;color:var(--dim);
                font-weight:700;border-bottom:1px solid var(--bg4);
                display:flex;justify-content:space-between;align-items:center}
.client-list{flex:1;overflow-y:auto}
.client-item{padding:9px 14px;cursor:pointer;border-bottom:1px solid var(--bg4);
             transition:background .15s;display:flex;justify-content:space-between;align-items:center}
.client-item:hover{background:var(--bg3)}
.client-item.active{background:var(--bg3);border-left:3px solid var(--blue)}
.client-name{font-weight:600}
.client-net{font-size:.75rem;color:var(--dim)}
.client-del{color:var(--red);font-size:.8rem;opacity:0;transition:opacity .2s;
            background:none;border:none;cursor:pointer;padding:2px 6px}
.client-item:hover .client-del{opacity:1}

/* ── Forms / inputs ── */
.form-group{display:flex;flex-direction:column;gap:4px;margin-bottom:10px}
label{font-size:.78rem;color:var(--dim);font-weight:600}
input,select,textarea{background:var(--bg3);border:1px solid var(--bg4);
       color:var(--fg);padding:7px 10px;border-radius:6px;font-size:.88rem;
       outline:none;width:100%;transition:border .15s;font-family:inherit}
input:focus,select:focus{border-color:var(--blue)}
select option{background:var(--bg3)}
.row{display:flex;gap:8px}
.row .form-group{flex:1}

/* ── Buttons ── */
btn,button,.btn{display:inline-flex;align-items:center;gap:6px;padding:7px 16px;
                border-radius:6px;border:none;cursor:pointer;font-size:.88rem;
                font-weight:600;transition:opacity .15s;font-family:inherit}
.btn-blue{background:#1f6feb;color:#fff} .btn-blue:hover{opacity:.85}
.btn-green{background:#238636;color:#fff} .btn-green:hover{opacity:.85}
.btn-red{background:#da3633;color:#fff} .btn-red:hover{opacity:.85}
.btn-orange{background:#9a5700;color:#fff} .btn-orange:hover{opacity:.85}
.btn-gray{background:var(--bg4);color:var(--fg)} .btn-gray:hover{opacity:.85}
.btn-sm{padding:4px 10px;font-size:.8rem}

/* ── Scanner tab ── */
.scan-config{padding:14px 16px;border-bottom:1px solid var(--bg4);flex-shrink:0}
.scan-config h3{font-size:.82rem;color:var(--dim);font-weight:700;
                margin-bottom:10px;text-transform:uppercase;letter-spacing:.05em}
.toolbar{display:flex;gap:8px;padding:10px 16px;border-bottom:1px solid var(--bg4);
         flex-shrink:0;align-items:center;flex-wrap:wrap}
.progress-bar{height:3px;background:var(--bg4);flex-shrink:0}
.progress-bar-inner{height:100%;background:var(--blue);width:0%;
                    transition:width .3s;animation:none}
.progress-bar-inner.running{animation:progress-anim 1.5s infinite linear}
@keyframes progress-anim{0%{width:0%;margin-left:0}50%{width:40%}100%{width:0%;margin-left:100%}}

/* ── Output ── */
.output-area{display:flex;flex:1;overflow:hidden}
.terminal{flex:1;background:#090d13;font-family:'Courier New',monospace;font-size:12.5px;
          padding:12px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;line-height:1.55}
.findings-panel{width:310px;border-left:1px solid var(--bg4);display:flex;
                flex-direction:column;flex-shrink:0}
.findings-header{padding:8px 12px;font-size:.78rem;color:var(--dim);font-weight:700;
                 border-bottom:1px solid var(--bg4);display:flex;
                 justify-content:space-between;align-items:center}
.findings-list{flex:1;overflow-y:auto;padding:6px}
.finding-item{padding:6px 8px;border-radius:6px;margin-bottom:5px;font-size:.8rem;
              font-family:'Courier New',monospace;background:var(--bg3);border-left:3px solid}
.sev-CRITICAL{color:var(--c-crit);border-color:var(--c-crit)!important}
.sev-HIGH{color:var(--c-high);border-color:var(--c-high)!important}
.sev-MEDIUM{color:var(--c-med);border-color:var(--c-med)!important}
.sev-LOW{color:var(--c-low);border-color:var(--c-low)!important}
.sev-INFO{color:var(--c-info)}
.line-CRITICAL{color:var(--c-crit);font-weight:700}
.line-HIGH{color:var(--c-high);font-weight:700}
.line-MEDIUM{color:var(--c-med)}
.line-LOW{color:var(--c-low)}
.line-INFO{color:var(--c-info)}
.line-HEADER{color:var(--green);font-weight:700}

/* ── History tab ── */
.history-table{width:100%;border-collapse:collapse}
.history-table th{background:var(--bg3);padding:8px 12px;text-align:left;
                   font-size:.8rem;color:var(--dim);border-bottom:1px solid var(--bg4)}
.history-table td{padding:8px 12px;border-bottom:1px solid var(--bg4);font-size:.85rem}
.history-table tr:hover td{background:var(--bg3)}
.badge{padding:2px 8px;border-radius:10px;font-size:.72rem;font-weight:700}
.badge-done{background:#1a3a1a;color:var(--green)}
.badge-run{background:#1a2a3a;color:var(--blue)}

/* ── VPN modal ── */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;
               display:none;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--bg4);border-radius:10px;
       padding:24px;width:440px;max-width:95vw}
.modal h2{color:var(--blue);margin-bottom:16px;font-size:1rem}

/* ── Client form (sidebar bottom) ── */
.client-form{border-top:1px solid var(--bg4);padding:12px;flex-shrink:0;
             max-height:52vh;overflow-y:auto;background:var(--bg)}
.client-form h3{font-size:.8rem;color:var(--dim);font-weight:700;
                margin-bottom:10px;text-transform:uppercase}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--bg4);border-radius:3px}

/* ── Status bar ── */
.statusbar{background:var(--bg2);border-top:1px solid var(--bg4);
           padding:4px 16px;font-size:.78rem;color:var(--dim);
           display:flex;justify-content:space-between;flex-shrink:0}
</style>
</head>
<body>

<!-- Header -->
<header>
  <div>
    <h1>&#x26A1; Kali VPN Vulnerability Scanner</h1>
    <span>nmap &bull; vulners &bull; nikto &bull; OpenVPN &bull; WireGuard</span>
  </div>
  <div style="margin-left:auto;display:flex;gap:10px;align-items:center">
    <div id="vpnBadge" class="badge-vpn off" onclick="openVpnModal()">
      &#x25CF; VPN Inactiva
    </div>
    <button class="btn btn-gray btn-sm" onclick="loadHistory()">Historial</button>
  </div>
</header>

<!-- Layout -->
<div class="layout">

  <!-- Sidebar: clients -->
  <aside class="sidebar">
    <div class="sidebar-header">
      CLIENTES
      <button class="btn btn-green btn-sm" onclick="newClient()">+ Nuevo</button>
    </div>
    <div class="client-list" id="clientList"></div>
    <!-- Client form -->
    <div class="client-form" id="clientForm">
      <h3 id="clientFormTitle">Nuevo cliente</h3>
      <form id="clientFormEl" onsubmit="saveClient(event)">
        <div class="form-group">
          <label>Nombre / Empresa *</label>
          <input id="cf_name" name="name" required placeholder="Ej: Empresa ABC">
        </div>
        <div class="form-group">
          <label>Red interna (CIDR)</label>
          <input id="cf_network" name="network" placeholder="192.168.1.0/24">
        </div>
        <div class="form-group">
          <label>Descripción</label>
          <input id="cf_desc" name="desc" placeholder="Notas del cliente">
        </div>
        <div class="form-group">
          <label>Tipo VPN</label>
          <select id="cf_vpntype" name="vpn_type">
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
            <input id="cf_vpnpass" name="vpn_pass" type="password" placeholder="(opcional)">
          </div>
        </div>
        <div style="display:flex;gap:8px;margin-top:4px">
          <button type="submit" class="btn btn-blue" style="flex:1">Guardar</button>
          <button type="button" class="btn btn-gray" onclick="newClient()">Limpiar</button>
        </div>
      </form>
    </div>
  </aside>

  <!-- Main content -->
  <div class="main">
    <div class="tabs">
      <div class="tab active" onclick="showTab('scanner',this)">&#x1F50D; Escaneo</div>
      <div class="tab" onclick="showTab('history',this);loadHistory()">&#x1F4CB; Historial</div>
    </div>

    <!-- ── SCANNER TAB ── -->
    <div class="tab-content active" id="tab-scanner">
      <!-- VPN + target config -->
      <div class="scan-config">
        <div class="row" style="align-items:flex-end;gap:12px;flex-wrap:wrap">
          <div class="form-group" style="min-width:180px">
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
        </div>
        <div class="form-group">
          <label>Comando (editable)</label>
          <input id="inCommand" style="font-family:'Courier New',monospace;color:var(--yellow)"
                 placeholder="sudo nmap -sV --script vuln -T4 192.168.1.0/24">
        </div>
      </div>

      <!-- Toolbar -->
      <div class="toolbar">
        <button class="btn btn-blue" id="btnScan" onclick="startScan()">&#x25B6; Iniciar Escaneo</button>
        <button class="btn btn-red"  id="btnStop" onclick="stopScan()" disabled>&#x25A0; Detener</button>
        <button class="btn btn-gray" onclick="clearOutput()">Limpiar</button>
        <div style="margin-left:auto;display:flex;gap:8px" id="exportBtns" style="display:none">
          <button class="btn btn-gray btn-sm" onclick="exportScan('txt')">&#x2B07; TXT</button>
          <button class="btn btn-gray btn-sm" onclick="exportScan('json')">&#x2B07; JSON</button>
          <button class="btn btn-gray btn-sm" onclick="exportScan('html')">&#x2B07; HTML</button>
        </div>
        <span id="scanStatus" style="color:var(--dim);font-size:.82rem"></span>
      </div>
      <div class="progress-bar"><div class="progress-bar-inner" id="progressBar"></div></div>

      <!-- Output + findings -->
      <div class="output-area">
        <div class="terminal" id="terminal">
          <span style="color:var(--dim)">Listo. Configura un cliente, objetivo y perfil para comenzar.
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

    <!-- ── HISTORY TAB ── -->
    <div class="tab-content" id="tab-history" style="overflow:auto;padding:16px">
      <table class="history-table" id="historyTable">
        <thead><tr>
          <th>ID</th><th>Cliente</th><th>Objetivo</th><th>Perfil</th>
          <th>Inicio</th><th>Estado</th><th>Acciones</th>
        </tr></thead>
        <tbody id="historyBody"></tbody>
      </table>
    </div>

  </div><!-- /main -->
</div><!-- /layout -->

<!-- Status bar -->
<div class="statusbar">
  <span id="statusText">Listo.</span>
  <span id="elapsedText"></span>
</div>

<!-- VPN Modal -->
<div class="modal-overlay" id="vpnModal">
  <div class="modal">
    <h2>&#x1F512; Gestión VPN</h2>
    <div id="vpnModalBody">
      <div class="form-group">
        <label>Cliente</label>
        <select id="vpnSelClient"></select>
      </div>
      <div id="vpnInfo" style="color:var(--dim);font-size:.85rem;margin:8px 0;min-height:24px"></div>
      <div style="display:flex;gap:8px;margin-top:12px">
        <button class="btn btn-orange" id="btnVpnConnect" onclick="connectVpn()">Conectar VPN</button>
        <button class="btn btn-red"    id="btnVpnDisconnect" onclick="disconnectVpn()">Desconectar</button>
        <button class="btn btn-gray"   onclick="closeVpnModal()">Cerrar</button>
      </div>
    </div>
  </div>
</div>

<script>
// ── State ────────────────────────────────────────────────────────────────────
let currentScanId = null;
let sseSource = null;
let scanRunning = false;
let startTime = null;
let timerInterval = null;
let profiles = {};

// ── Init ─────────────────────────────────────────────────────────────────────
window.onload = async () => {
  await loadProfiles();
  await loadClients();
  pollVpnStatus();
};

// ── Tabs ─────────────────────────────────────────────────────────────────────
function showTab(name, el) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  el.classList.add('active');
}

// ── Profiles ─────────────────────────────────────────────────────────────────
async function loadProfiles() {
  const r = await fetch('/api/scan/profiles');
  profiles = await r.json();
  const sel = document.getElementById('selProfile');
  sel.innerHTML = '';
  for (const [name, cmd] of Object.entries(profiles)) {
    const o = document.createElement('option');
    o.value = cmd; o.textContent = name;
    sel.appendChild(o);
  }
  // default to vuln+SO+versions
  sel.selectedIndex = 5;
  onProfileSelect();
}

function onProfileSelect() {
  const sel = document.getElementById('selProfile');
  document.getElementById('inCommand').value = sel.value;
}

// ── Clients ───────────────────────────────────────────────────────────────────
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
  for (const [name, c] of Object.entries(clients)) {
    const item = document.createElement('div');
    item.className = 'client-item';
    item.dataset.name = name;
    item.innerHTML = `
      <div>
        <div class="client-name">${escHtml(name)}</div>
        <div class="client-net">${escHtml(c.network || 'Sin red definida')}</div>
      </div>
      <button class="client-del" onclick="deleteClient('${escHtml(name)}',event)">✕</button>`;
    item.addEventListener('click', () => selectClient(name, c, item));
    el.appendChild(item);
  }
}

function renderClientCombo(clients) {
  const sel = document.getElementById('selClient');
  const cur = sel.value;
  sel.innerHTML = '<option value="">— Seleccionar —</option>';
  for (const name of Object.keys(clients)) {
    const o = document.createElement('option');
    o.value = name; o.textContent = name;
    sel.appendChild(o);
  }
  if (cur) sel.value = cur;
}

function renderVpnCombo(clients) {
  const sel = document.getElementById('vpnSelClient');
  sel.innerHTML = '';
  for (const name of Object.keys(clients)) {
    const o = document.createElement('option');
    o.value = name; o.textContent = name;
    sel.appendChild(o);
  }
}

function selectClient(name, c, item) {
  document.querySelectorAll('.client-item').forEach(i => i.classList.remove('active'));
  item.classList.add('active');
  document.getElementById('cf_name').value    = name;
  document.getElementById('cf_network').value = c.network || '';
  document.getElementById('cf_desc').value    = c.desc    || '';
  document.getElementById('cf_vpntype').value = c.vpn_type || 'OpenVPN';
  document.getElementById('cf_vpnuser').value = c.vpn_user || '';
  document.getElementById('cf_vpnpass').value = c.vpn_pass || '';
  document.getElementById('clientFormTitle').textContent = 'Editar: ' + name;
  // prefill scan target
  document.getElementById('selClient').value  = name;
  document.getElementById('inTarget').value   = c.network || '';
}

function onClientSelect() {
  const name = document.getElementById('selClient').value;
  fetch('/api/clients').then(r => r.json()).then(clients => {
    if (clients[name]) {
      document.getElementById('inTarget').value = clients[name].network || '';
    }
  });
}

function newClient() {
  document.getElementById('clientFormEl').reset();
  document.getElementById('clientFormTitle').textContent = 'Nuevo cliente';
  document.querySelectorAll('.client-item').forEach(i => i.classList.remove('active'));
}

async function saveClient(e) {
  e.preventDefault();
  const form = document.getElementById('clientFormEl');
  const fd = new FormData(form);
  const r = await fetch('/api/clients', {method:'POST', body: fd});
  const j = await r.json();
  if (j.error) { alert(j.error); return; }
  setStatus('Cliente guardado.');
  await loadClients();
}

async function deleteClient(name, e) {
  e.stopPropagation();
  if (!confirm(`¿Eliminar cliente "${name}"?`)) return;
  await fetch('/api/clients/'+encodeURIComponent(name), {method:'DELETE'});
  await loadClients();
}

// ── VPN ───────────────────────────────────────────────────────────────────────
function openVpnModal() {
  document.getElementById('vpnModal').classList.add('open');
}
function closeVpnModal() {
  document.getElementById('vpnModal').classList.remove('open');
}

async function connectVpn() {
  const client = document.getElementById('vpnSelClient').value;
  if (!client) { alert('Selecciona un cliente'); return; }
  document.getElementById('vpnInfo').textContent = 'Conectando VPN, espera...';
  const r = await fetch('/api/vpn/connect', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({client})
  });
  const j = await r.json();
  document.getElementById('vpnInfo').textContent = j.msg || j.error || '';
  setStatus('Conectando VPN...');
  // poll until active
  let tries = 0;
  const poll = setInterval(async () => {
    const s = await (await fetch('/api/vpn/status')).json();
    if (s.active) {
      clearInterval(poll);
      updateVpnBadge(s);
      document.getElementById('vpnInfo').textContent = 'VPN activa — ' + s.ip;
      setStatus('VPN activa.');
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
  try {
    const s = await (await fetch('/api/vpn/status')).json();
    updateVpnBadge(s);
  } catch {}
  setTimeout(pollVpnStatus, 5000);
}

function updateVpnBadge(s) {
  const b = document.getElementById('vpnBadge');
  if (s.active) {
    b.className = 'badge-vpn on';
    b.textContent = '● VPN: ' + (s.client || 'Activa');
  } else {
    b.className = 'badge-vpn off';
    b.textContent = '● VPN Inactiva';
  }
}

// ── Scanner ───────────────────────────────────────────────────────────────────
async function startScan() {
  const target  = document.getElementById('inTarget').value.trim();
  const command = document.getElementById('inCommand').value.trim();
  const client  = document.getElementById('selClient').value;
  const profile = document.getElementById('selProfile').selectedOptions[0]?.textContent || '';

  if (!target)  { alert('Ingresa un objetivo (IP, CIDR o hostname).'); return; }
  if (!command) { alert('Selecciona un perfil o escribe un comando.'); return; }

  clearOutput();
  const r = await fetch('/api/scan/start', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({target, command, client, profile})
  });
  const j = await r.json();
  if (j.error) { alert(j.error); return; }

  currentScanId = j.scan_id;
  scanRunning = true;
  startTime = Date.now();
  document.getElementById('btnScan').disabled = true;
  document.getElementById('btnStop').disabled = false;
  document.getElementById('progressBar').classList.add('running');
  document.getElementById('exportBtns').style.display = 'flex';
  startTimer();
  streamScan(currentScanId);
}

function streamScan(scanId) {
  if (sseSource) sseSource.close();
  sseSource = new EventSource('/api/scan/stream/' + scanId);
  sseSource.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.done) {
      scanDone();
      return;
    }
    appendLine(data.line, data.sev);
    if (['CRITICAL','HIGH','MEDIUM'].includes(data.sev)) {
      appendFinding(data.line, data.sev);
    }
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
}

function startTimer() {
  clearInterval(timerInterval);
  timerInterval = setInterval(() => {
    const s = Math.floor((Date.now() - startTime) / 1000);
    const m = Math.floor(s / 60).toString().padStart(2,'0');
    const ss = (s % 60).toString().padStart(2,'0');
    document.getElementById('elapsedText').textContent = `Duración: ${m}:${ss}`;
    document.getElementById('scanStatus').textContent  = `Escaneando... ${m}:${ss}`;
  }, 1000);
}

// ── Terminal output ───────────────────────────────────────────────────────────
function appendLine(line, sev) {
  const term = document.getElementById('terminal');
  const span = document.createElement('span');
  span.className = sev === 'HEADER' ? 'line-HEADER' : 'line-' + (sev || 'INFO');
  span.textContent = line + '\n';
  term.appendChild(span);
  term.scrollTop = term.scrollHeight;
}

function appendFinding(line, sev) {
  const fl = document.getElementById('findingsList');
  const item = document.createElement('div');
  item.className = 'finding-item sev-' + sev;
  item.innerHTML = `<strong>${sev}</strong><br>${escHtml(line.trim())}`;
  fl.appendChild(item);
  fl.scrollTop = fl.scrollHeight;
}

function clearOutput() {
  document.getElementById('terminal').innerHTML =
    '<span style="color:var(--dim)">Listo.\n</span>';
  clearFindings();
  document.getElementById('elapsedText').textContent = '';
  document.getElementById('scanStatus').textContent  = '';
  setStatus('Listo.');
}

function clearFindings() {
  document.getElementById('findingsList').innerHTML = '';
}

// ── History ───────────────────────────────────────────────────────────────────
async function loadHistory() {
  const r = await fetch('/api/scan/list');
  const scans = await r.json();
  const tbody = document.getElementById('historyBody');
  tbody.innerHTML = '';
  for (const s of scans) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${s.id}</code></td>
      <td>${escHtml(s.client||'—')}</td>
      <td>${escHtml(s.target)}</td>
      <td>${escHtml(s.profile)}</td>
      <td>${s.start}</td>
      <td><span class="badge ${s.done?'badge-done':'badge-run'}">${s.done?'Completado':'En curso'}</span></td>
      <td style="display:flex;gap:6px">
        <button class="btn btn-gray btn-sm" onclick="replayScan('${s.id}')">Ver</button>
        <button class="btn btn-gray btn-sm" onclick="exportScanById('${s.id}','txt')">TXT</button>
        <button class="btn btn-gray btn-sm" onclick="exportScanById('${s.id}','html')">HTML</button>
      </td>`;
    tbody.appendChild(tr);
  }
}

function replayScan(id) {
  currentScanId = id;
  clearOutput();
  showTab('scanner', document.querySelectorAll('.tab')[0]);
  streamScan(id);
}

// ── Export ────────────────────────────────────────────────────────────────────
function exportScan(fmt) { exportScanById(currentScanId, fmt); }
function exportScanById(id, fmt) {
  if (!id) { alert('No hay escaneo activo.'); return; }
  window.open('/api/scan/export/' + id + '?fmt=' + fmt);
}

// ── Utils ─────────────────────────────────────────────────────────────────────
function setStatus(msg) { document.getElementById('statusText').textContent = msg; }
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
</script>
</body>
</html>
"""

# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 56)
    print("  Kali VPN Vulnerability Scanner")
    print(f"  URL: http://0.0.0.0:8040")
    print("  Ctrl+C para detener")
    print("=" * 56)
    app.run(host="0.0.0.0", port=8040, debug=False, threaded=True)
