#!/usr/bin/env python3
"""
Kali VPN Vulnerability Scanner
Gestiona clientes, conecta el servidor Kali a la VPN del cliente
y realiza escaneos de vulnerabilidades en la red interna.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import paramiko
import os, datetime, json, re, queue, time

# ── Defaults ───────────────────────────────────────────────────────────────────
DEFAULT_HOST = "3.143.18.161"
DEFAULT_USER = "kali"
DEFAULT_KEY  = os.path.join(os.path.dirname(__file__), "kali-aws.pem")
CLIENTS_FILE = os.path.join(os.path.dirname(__file__), "clients.json")
DATACOM_LOGO = os.path.join(os.path.dirname(__file__), "logo_datacom.png")

SCAN_PROFILES = {
    "Descubrimiento (hosts vivos)":      "sudo nmap -sn {target}",
    "Puertos top-1000":                   "sudo nmap -sS -T4 --open {target}",
    "Puertos completos (1-65535)":        "sudo nmap -sS -T4 -p- --open {target}",
    "Versiones + SO":                     "sudo nmap -sS -sV -O -T4 {target}",
    "Vulnerabilidades NSE (vuln)":        "sudo nmap -sV --script vuln -T4 {target}",
    "Vuln + SO + Versiones (completo)":   "sudo nmap -sS -sV -O --script vuln -T4 {target}",
    "CVEs con puntuación (vulners)":      "sudo nmap -sV --script vulners --script-args mincvss=5.0 -T4 {target}",
    "Web / HTTP (nikto)":                 "nikto -h {target}",
    "SMB vulnerabilidades":               "sudo nmap -p445 --script smb-vuln* -T4 {target}",
    "SSL/TLS (sslscan)":                  "sslscan {target}",
    "Personalizado":                      "",
}

SEV_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#44aaff",
    "INFO":     "#c9d1d9",
}

BG      = "#0d1117"
BG2     = "#161b22"
BG3     = "#21262d"
BG4     = "#30363d"
FG      = "#c9d1d9"
FG_DIM  = "#8b949e"
BLUE    = "#58a6ff"
GREEN   = "#3fb950"
RED     = "#f85149"
YELLOW  = "#e3b341"
ORANGE  = "#ff8800"


# ── Helpers ────────────────────────────────────────────────────────────────────

def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def detect_severity(line):
    low = line.lower()
    if any(k in low for k in ["critical","rce","exploit","ms17-010","eternalblue","ms08-067","ms17","shellshock"]):
        return "CRITICAL"
    if any(k in low for k in ["high","vuln","cve-","sqli","rfi","lfi","backdoor","injection"]):
        return "HIGH"
    if any(k in low for k in ["medium","warning","deprecated","weak cipher","ssl","tls error"]):
        return "MEDIUM"
    if any(k in low for k in ["low","info leak","disclosure","open port"]):
        return "LOW"
    return "INFO"

def load_clients():
    if os.path.exists(CLIENTS_FILE):
        with open(CLIENTS_FILE) as f:
            return json.load(f)
    return {}

def save_clients(clients):
    with open(CLIENTS_FILE, "w") as f:
        json.dump(clients, f, indent=2, ensure_ascii=False)


# ── Main App ───────────────────────────────────────────────────────────────────

class VulnScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Kali VPN Vulnerability Scanner  •  Datacom Security")
        self.root.geometry("1200x820")
        self.root.configure(bg=BG)
        self.root.resizable(True, True)

        self.ssh: paramiko.SSHClient | None = None
        self.connected   = False
        self.vpn_active  = False
        self.scanning    = False
        self.stop_evt    = threading.Event()
        self.out_queue   = queue.Queue()
        self.scan_results = []
        self.clients     = load_clients()
        self._start_time = None

        self._build_ui()
        self._refresh_client_list()
        self._poll_queue()

    # ──────────────────────────────── UI BUILD ─────────────────────────────────

    def _build_ui(self):
        self._build_header()
        self._build_ssh_bar()

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=10, pady=4)
        self.nb = nb

        # Tab 1: Clientes
        tab_clients = tk.Frame(nb, bg=BG)
        nb.add(tab_clients, text="  Clientes  ")
        self._build_clients_tab(tab_clients)

        # Tab 2: Scanner
        tab_scan = tk.Frame(nb, bg=BG)
        nb.add(tab_scan, text="  Escaneo de Vulnerabilidades  ")
        self._build_scan_tab(tab_scan)

        # Tab 3: Resultados
        tab_results = tk.Frame(nb, bg=BG)
        nb.add(tab_results, text="  Resultados / Exportar  ")
        self._build_results_tab(tab_results)

        self._build_statusbar()

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TNotebook",         background=BG,  borderwidth=0)
        style.configure("TNotebook.Tab",     background=BG4, foreground=FG_DIM,
                        padding=[12,5], font=("Helvetica", 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", BG2)],
                  foreground=[("selected", BLUE)])
        style.configure("TCombobox",
                        fieldbackground=BG3, background=BG3,
                        foreground="white",
                        selectbackground=BG3, selectforeground="white")
        style.configure("Horizontal.TProgressbar",
                        background=BLUE, troughcolor=BG3,
                        bordercolor=BG4, lightcolor=BLUE, darkcolor=BLUE)

    # ── Header ──────────────────────────────────────────────────────────────────

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=BG2, pady=8)
        hdr.pack(fill="x")
        try:
            img = tk.PhotoImage(file=DATACOM_LOGO)
            w, h = img.width(), img.height()
            if h > 48:
                img = img.subsample(max(1, h // 48), max(1, h // 48))
            tk.Label(hdr, image=img, bg=BG2).pack(side="left", padx=12)
            self._logo = img
        except Exception:
            pass
        tk.Label(hdr, text="Kali VPN Vulnerability Scanner",
                 font=("Helvetica", 18, "bold"), fg=BLUE, bg=BG2
                 ).pack(side="left", padx=8)
        tk.Label(hdr, text="nmap · vulners · nikto · OpenVPN",
                 font=("Helvetica", 10), fg=FG_DIM, bg=BG2
                 ).pack(side="left", padx=4)

    # ── SSH bar ─────────────────────────────────────────────────────────────────

    def _build_ssh_bar(self):
        f = tk.LabelFrame(self.root, text=" Servidor Kali (AWS) — Conexión SSH ",
                          bg=BG, fg=BLUE, font=("Helvetica", 10, "bold"),
                          bd=1, relief="groove")
        f.pack(fill="x", padx=10, pady=(6,0))
        row = tk.Frame(f, bg=BG)
        row.pack(fill="x", padx=8, pady=4)

        for col, (lbl, var_def, width) in enumerate([
            ("Host:",    DEFAULT_HOST, 18),
            ("Usuario:", DEFAULT_USER, 10),
        ]):
            self._lbl(row, lbl).grid(row=0, column=col*2,   sticky="w", padx=(8 if col else 0, 0))
            var = tk.StringVar(value=var_def)
            setattr(self, f"_ssh_{'host' if col==0 else 'user'}", var)
            tk.Entry(row, textvariable=var, width=width,
                     bg=BG3, fg="white", insertbackground="white",
                     relief="flat", bd=4).grid(row=0, column=col*2+1, padx=4)

        self._lbl(row, "Clave SSH:").grid(row=0, column=4, sticky="w", padx=(8,0))
        self._key_var = tk.StringVar(value=DEFAULT_KEY)
        tk.Entry(row, textvariable=self._key_var, width=38,
                 bg=BG3, fg="white", insertbackground="white",
                 relief="flat", bd=4).grid(row=0, column=5, padx=4)
        self._btn(row, "...", self._browse_key, BG4).grid(row=0, column=6, padx=2)

        self.conn_btn = self._btn(row, "Conectar", self._toggle_conn, GREEN, bold=True)
        self.conn_btn.grid(row=0, column=7, padx=(12,4))
        self.conn_lbl = tk.Label(row, text="● Desconectado",
                                 fg=RED, bg=BG, font=("Helvetica", 10, "bold"))
        self.conn_lbl.grid(row=0, column=8, padx=4)

    # ── Tab: Clientes ───────────────────────────────────────────────────────────

    def _build_clients_tab(self, parent):
        left = tk.Frame(parent, bg=BG, width=340)
        left.pack(side="left", fill="y", padx=(8,0), pady=8)
        left.pack_propagate(False)

        tk.Label(left, text="Clientes registrados",
                 fg=FG_DIM, bg=BG, font=("Helvetica", 10, "bold")
                 ).pack(anchor="w")

        self.client_lb = tk.Listbox(left, bg=BG2, fg=FG, selectbackground=BLUE,
                                    font=("Helvetica", 10), relief="flat", bd=2)
        self.client_lb.pack(fill="both", expand=True, pady=(4,4))
        self.client_lb.bind("<<ListboxSelect>>", self._on_client_select)

        btnrow = tk.Frame(left, bg=BG)
        btnrow.pack(fill="x")
        self._btn(btnrow, "+ Nuevo", self._new_client, "#238636").pack(side="left", padx=(0,4))
        self._btn(btnrow, "Eliminar", self._delete_client, "#da3633").pack(side="left")

        # Right: edit form
        right = tk.LabelFrame(parent, text=" Datos del cliente ",
                               bg=BG, fg=BLUE, font=("Helvetica", 10, "bold"),
                               bd=1, relief="groove")
        right.pack(side="left", fill="both", expand=True, padx=8, pady=8)

        fields = [
            ("Nombre / empresa:",     "_cf_name",    40, ""),
            ("Red interna (CIDR):",   "_cf_network", 30, "192.168.1.0/24"),
            ("Descripción:",          "_cf_desc",    50, ""),
        ]
        for row_i, (lbl, attr, w, ph) in enumerate(fields):
            self._lbl(right, lbl).grid(row=row_i, column=0, sticky="w", padx=8, pady=4)
            var = tk.StringVar(value=ph)
            setattr(self, attr, var)
            tk.Entry(right, textvariable=var, width=w,
                     bg=BG3, fg="white", insertbackground="white",
                     relief="flat", bd=4).grid(row=row_i, column=1, padx=4, sticky="w")

        # VPN config file
        self._lbl(right, "Config VPN (.ovpn / WireGuard):").grid(
            row=3, column=0, sticky="w", padx=8, pady=4)
        vpn_row = tk.Frame(right, bg=BG)
        vpn_row.grid(row=3, column=1, sticky="w")
        self._cf_vpn = tk.StringVar()
        tk.Entry(vpn_row, textvariable=self._cf_vpn, width=36,
                 bg=BG3, fg="white", insertbackground="white",
                 relief="flat", bd=4).pack(side="left", padx=(0,4))
        self._btn(vpn_row, "Seleccionar", self._browse_vpn, BG4).pack(side="left")

        # VPN type
        self._lbl(right, "Tipo VPN:").grid(row=4, column=0, sticky="w", padx=8, pady=4)
        self._cf_vpntype = tk.StringVar(value="OpenVPN")
        ttk.Combobox(right, textvariable=self._cf_vpntype,
                     values=["OpenVPN", "WireGuard"],
                     state="readonly", width=16
                     ).grid(row=4, column=1, sticky="w", padx=4)

        # Credentials (optional)
        self._lbl(right, "VPN usuario (si aplica):").grid(
            row=5, column=0, sticky="w", padx=8, pady=4)
        self._cf_vpnuser = tk.StringVar()
        tk.Entry(right, textvariable=self._cf_vpnuser, width=20,
                 bg=BG3, fg="white", insertbackground="white",
                 relief="flat", bd=4).grid(row=5, column=1, sticky="w", padx=4)

        self._lbl(right, "VPN contraseña:").grid(
            row=6, column=0, sticky="w", padx=8, pady=4)
        self._cf_vpnpass = tk.StringVar()
        tk.Entry(right, textvariable=self._cf_vpnpass, width=20, show="*",
                 bg=BG3, fg="white", insertbackground="white",
                 relief="flat", bd=4).grid(row=6, column=1, sticky="w", padx=4)

        self._btn(right, "Guardar cliente", self._save_client, BLUE, bold=True
                  ).grid(row=7, column=0, columnspan=2, pady=10)

    # ── Tab: Scanner ────────────────────────────────────────────────────────────

    def _build_scan_tab(self, parent):
        top = tk.Frame(parent, bg=BG)
        top.pack(fill="x", padx=8, pady=(8,0))

        # VPN control
        vpn_frame = tk.LabelFrame(top, text=" Conexión VPN al cliente ",
                                  bg=BG, fg=ORANGE, font=("Helvetica", 10, "bold"),
                                  bd=1, relief="groove")
        vpn_frame.pack(fill="x", pady=(0,6))
        vrow = tk.Frame(vpn_frame, bg=BG)
        vrow.pack(fill="x", padx=8, pady=4)

        self._lbl(vrow, "Cliente:").grid(row=0, column=0, sticky="w")
        self._sel_client = tk.StringVar()
        self.client_combo = ttk.Combobox(vrow, textvariable=self._sel_client,
                                          values=[], state="readonly", width=28)
        self.client_combo.grid(row=0, column=1, padx=4)
        self.client_combo.bind("<<ComboboxSelected>>", self._on_combo_client)

        self._lbl(vrow, "Red interna:").grid(row=0, column=2, sticky="w", padx=(12,0))
        self._scan_network = tk.StringVar()
        tk.Entry(vrow, textvariable=self._scan_network, width=22,
                 bg=BG3, fg="white", insertbackground="white",
                 relief="flat", bd=4).grid(row=0, column=3, padx=4)

        self.vpn_btn = self._btn(vrow, "Conectar VPN", self._toggle_vpn, ORANGE, bold=True)
        self.vpn_btn.grid(row=0, column=4, padx=(12,4))
        self.vpn_lbl = tk.Label(vrow, text="● VPN inactiva",
                                 fg=RED, bg=BG, font=("Helvetica", 10, "bold"))
        self.vpn_lbl.grid(row=0, column=5, padx=4)

        # Scan config
        scan_frame = tk.LabelFrame(top, text=" Configuración del Escaneo ",
                                   bg=BG, fg=BLUE, font=("Helvetica", 10, "bold"),
                                   bd=1, relief="groove")
        scan_frame.pack(fill="x")
        srow = tk.Frame(scan_frame, bg=BG)
        srow.pack(fill="x", padx=8, pady=4)

        self._lbl(srow, "Objetivo:").grid(row=0, column=0, sticky="w")
        self._target = tk.StringVar()
        tk.Entry(srow, textvariable=self._target, width=24,
                 bg=BG3, fg="white", insertbackground="white",
                 relief="flat", bd=4).grid(row=0, column=1, padx=4)
        self._btn(srow, "Usar red cliente", self._use_client_network, BG4
                  ).grid(row=0, column=2, padx=4)

        self._lbl(srow, "Perfil:").grid(row=0, column=3, sticky="w", padx=(12,0))
        self._profile = tk.StringVar(value=list(SCAN_PROFILES.keys())[5])
        profile_cb = ttk.Combobox(srow, textvariable=self._profile,
                                   values=list(SCAN_PROFILES.keys()),
                                   state="readonly", width=32)
        profile_cb.grid(row=0, column=4, padx=4)
        profile_cb.bind("<<ComboboxSelected>>", self._on_profile)

        srow2 = tk.Frame(scan_frame, bg=BG)
        srow2.pack(fill="x", padx=8, pady=(0,6))
        self._lbl(srow2, "Comando:").grid(row=0, column=0, sticky="w")
        self._cmd = tk.StringVar(value=SCAN_PROFILES[self._profile.get()])
        tk.Entry(srow2, textvariable=self._cmd, width=76,
                 bg=BG3, fg=YELLOW, insertbackground="white",
                 relief="flat", bd=4, font=("Courier", 10)
                 ).grid(row=0, column=1, padx=4, sticky="ew")

        # Action buttons
        btn_row = tk.Frame(parent, bg=BG)
        btn_row.pack(fill="x", padx=8, pady=6)
        self.scan_btn  = self._btn(btn_row, "▶  Iniciar Escaneo", self._start_scan, BLUE, bold=True)
        self.scan_btn.pack(side="left", padx=(0,6))
        self.stop_btn  = self._btn(btn_row, "■  Detener", self._stop_scan, BG4, bold=True)
        self.stop_btn.pack(side="left", padx=4)
        self._btn(btn_row, "Limpiar", self._clear_output, BG4).pack(side="left", padx=4)

        # Progress
        self.progress = ttk.Progressbar(parent, mode="indeterminate")
        self.progress.pack(fill="x", padx=8, pady=(0,4))

        # Output pane
        paned = tk.PanedWindow(parent, orient="horizontal",
                               bg=BG, sashwidth=6, sashrelief="flat")
        paned.pack(fill="both", expand=True, padx=8, pady=(0,4))

        out_frame = tk.Frame(paned, bg=BG)
        paned.add(out_frame, stretch="always")
        tk.Label(out_frame, text="Salida del escaneo",
                 fg=FG_DIM, bg=BG, font=("Helvetica", 9, "bold")).pack(anchor="w")
        self.out_text = scrolledtext.ScrolledText(
            out_frame, bg="#090d13", fg=FG,
            font=("Courier", 10), relief="flat", bd=4,
            wrap="word", state="disabled")
        self.out_text.pack(fill="both", expand=True)
        for sev, color in SEV_COLORS.items():
            self.out_text.tag_configure(sev, foreground=color, font=("Courier", 10, "bold"))
        self.out_text.tag_configure("HEADER", foreground=GREEN,  font=("Courier", 10, "bold"))
        self.out_text.tag_configure("CMD",    foreground=BLUE,   font=("Courier", 10, "bold"))

        find_frame = tk.Frame(paned, bg=BG, width=290)
        paned.add(find_frame, stretch="never")
        tk.Label(find_frame, text="Hallazgos",
                 fg=FG_DIM, bg=BG, font=("Helvetica", 9, "bold")).pack(anchor="w")
        self.find_text = scrolledtext.ScrolledText(
            find_frame, bg=BG2, fg=FG,
            font=("Courier", 9), relief="flat", bd=4,
            wrap="word", state="disabled", width=38)
        self.find_text.pack(fill="both", expand=True)
        for sev, color in SEV_COLORS.items():
            self.find_text.tag_configure(sev, foreground=color, font=("Courier", 9, "bold"))

    # ── Tab: Results ────────────────────────────────────────────────────────────

    def _build_results_tab(self, parent):
        tk.Label(parent, text="Exportar resultados del último escaneo",
                 fg=FG_DIM, bg=BG, font=("Helvetica", 11, "bold")
                 ).pack(anchor="w", padx=12, pady=(10,4))

        btn_row = tk.Frame(parent, bg=BG)
        btn_row.pack(fill="x", padx=12, pady=4)
        self._btn(btn_row, "Exportar TXT",  lambda: self._export("txt"),  BG4).pack(side="left", padx=4)
        self._btn(btn_row, "Exportar JSON", lambda: self._export("json"), BG4).pack(side="left", padx=4)
        self._btn(btn_row, "Exportar HTML", lambda: self._export("html"), BG4).pack(side="left", padx=4)

        self.results_preview = scrolledtext.ScrolledText(
            parent, bg=BG2, fg=FG,
            font=("Courier", 10), relief="flat", bd=4,
            wrap="word", state="disabled")
        self.results_preview.pack(fill="both", expand=True, padx=12, pady=(4,8))

    # ── Status bar ──────────────────────────────────────────────────────────────

    def _build_statusbar(self):
        sb = tk.Frame(self.root, bg=BG2, pady=3)
        sb.pack(fill="x", side="bottom")
        self._status = tk.StringVar(value="Listo.")
        tk.Label(sb, textvariable=self._status,
                 fg=FG_DIM, bg=BG2, font=("Helvetica", 9), anchor="w"
                 ).pack(side="left", padx=8)
        self._elapsed = tk.StringVar()
        tk.Label(sb, textvariable=self._elapsed,
                 fg=FG_DIM, bg=BG2, font=("Helvetica", 9)
                 ).pack(side="right", padx=8)

    # ── Widget factory ──────────────────────────────────────────────────────────

    def _lbl(self, parent, text):
        return tk.Label(parent, text=text, fg=FG_DIM, bg=BG, font=("Helvetica", 10))

    def _btn(self, parent, text, cmd, color, bold=False):
        font = ("Helvetica", 10, "bold") if bold else ("Helvetica", 10)
        return tk.Button(parent, text=text, command=cmd,
                         bg=color, fg="white", font=font,
                         relief="flat", bd=0, padx=12, pady=5, cursor="hand2")

    # ── Clients ─────────────────────────────────────────────────────────────────

    def _refresh_client_list(self):
        self.client_lb.delete(0, "end")
        for name in self.clients:
            self.client_lb.insert("end", name)
        self.client_combo["values"] = list(self.clients.keys())

    def _on_client_select(self, _=None):
        sel = self.client_lb.curselection()
        if not sel:
            return
        name = self.client_lb.get(sel[0])
        c = self.clients[name]
        self._cf_name.set(name)
        self._cf_network.set(c.get("network", ""))
        self._cf_desc.set(c.get("desc", ""))
        self._cf_vpn.set(c.get("vpn_local", ""))
        self._cf_vpntype.set(c.get("vpn_type", "OpenVPN"))
        self._cf_vpnuser.set(c.get("vpn_user", ""))
        self._cf_vpnpass.set(c.get("vpn_pass", ""))

    def _on_combo_client(self, _=None):
        name = self._sel_client.get()
        if name in self.clients:
            self._scan_network.set(self.clients[name].get("network", ""))

    def _new_client(self):
        self._cf_name.set("")
        self._cf_network.set("192.168.1.0/24")
        self._cf_desc.set("")
        self._cf_vpn.set("")
        self._cf_vpnuser.set("")
        self._cf_vpnpass.set("")

    def _save_client(self):
        name = self._cf_name.get().strip()
        if not name:
            messagebox.showwarning("Nombre requerido", "Ingresa el nombre del cliente.")
            return
        self.clients[name] = {
            "network":   self._cf_network.get().strip(),
            "desc":      self._cf_desc.get().strip(),
            "vpn_local": self._cf_vpn.get().strip(),
            "vpn_type":  self._cf_vpntype.get(),
            "vpn_user":  self._cf_vpnuser.get().strip(),
            "vpn_pass":  self._cf_vpnpass.get().strip(),
        }
        save_clients(self.clients)
        self._refresh_client_list()
        self._set_status(f"Cliente '{name}' guardado.")

    def _delete_client(self):
        sel = self.client_lb.curselection()
        if not sel:
            return
        name = self.client_lb.get(sel[0])
        if messagebox.askyesno("Eliminar", f"¿Eliminar cliente '{name}'?"):
            del self.clients[name]
            save_clients(self.clients)
            self._refresh_client_list()

    def _browse_vpn(self):
        path = filedialog.askopenfilename(
            title="Seleccionar config VPN",
            filetypes=[("VPN configs", "*.ovpn *.conf"), ("All files", "*.*")]
        )
        if path:
            self._cf_vpn.set(path)

    def _browse_key(self):
        path = filedialog.askopenfilename(
            title="Clave SSH",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if path:
            self._key_var.set(path)

    def _use_client_network(self):
        self._target.set(self._scan_network.get())

    def _on_profile(self, _=None):
        self._cmd.set(SCAN_PROFILES.get(self._profile.get(), ""))

    # ── SSH ─────────────────────────────────────────────────────────────────────

    def _toggle_conn(self):
        if self.connected:
            self._disconnect()
        else:
            threading.Thread(target=self._connect, daemon=True).start()

    def _connect(self):
        self._set_status("Conectando al servidor Kali...")
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            key = paramiko.RSAKey.from_private_key_file(self._key_var.get())
            c.connect(self._ssh_host.get(), username=self._ssh_user.get(),
                      pkey=key, timeout=15, banner_timeout=15)
            self.ssh = c
            self.connected = True
            self.root.after(0, self._on_connected)
        except Exception as e:
            self.root.after(0, lambda: self._conn_error(str(e)))

    def _on_connected(self):
        self.conn_lbl.config(text="● Conectado", fg=GREEN)
        self.conn_btn.config(text="Desconectar", bg="#da3633")
        self._set_status(f"SSH conectado a {self._ssh_host.get()}")
        self._append("HEADER", f"[{now_str()}] Conexión SSH OK → {self._ssh_host.get()}\n")

    def _conn_error(self, msg):
        self.conn_lbl.config(text="● Error", fg=RED)
        self._set_status(f"Error SSH: {msg}")
        messagebox.showerror("Error de conexión", msg)

    def _disconnect(self):
        if self.ssh:
            self.ssh.close()
            self.ssh = None
        self.connected = False
        self.conn_lbl.config(text="● Desconectado", fg=RED)
        self.conn_btn.config(text="Conectar", bg=GREEN)
        self._set_status("Desconectado.")

    # ── VPN ─────────────────────────────────────────────────────────────────────

    def _toggle_vpn(self):
        if self.vpn_active:
            threading.Thread(target=self._vpn_disconnect, daemon=True).start()
        else:
            threading.Thread(target=self._vpn_connect, daemon=True).start()

    def _vpn_connect(self):
        if not self.connected:
            self.root.after(0, lambda: messagebox.showwarning(
                "Sin SSH", "Conecta al servidor Kali primero."))
            return
        name = self._sel_client.get()
        if not name or name not in self.clients:
            self.root.after(0, lambda: messagebox.showwarning(
                "Sin cliente", "Selecciona un cliente del combo."))
            return
        c = self.clients[name]
        vpn_local = c.get("vpn_local", "")
        vpn_type  = c.get("vpn_type", "OpenVPN")
        vpn_user  = c.get("vpn_user", "")
        vpn_pass  = c.get("vpn_pass", "")

        self.root.after(0, lambda: self._set_status(f"Conectando VPN ({vpn_type}) para {name}..."))
        self._append("HEADER", f"\n[{now_str()}] Iniciando VPN {vpn_type} → cliente: {name}\n")

        try:
            remote_cfg = f"/tmp/vpn_{name.replace(' ','_')}.{'ovpn' if vpn_type=='OpenVPN' else 'conf'}"

            if vpn_local:
                sftp = self.ssh.open_sftp()
                sftp.put(vpn_local, remote_cfg)
                sftp.close()
                self._append("INFO", f"  Config subida → {remote_cfg}\n")

            if vpn_type == "OpenVPN":
                if vpn_user and vpn_pass:
                    cred_file = "/tmp/vpn_creds.txt"
                    self._exec(f"echo -e '{vpn_user}\\n{vpn_pass}' > {cred_file}")
                    cmd = f"sudo openvpn --config {remote_cfg} --auth-user-pass {cred_file} --daemon --log /tmp/openvpn.log"
                else:
                    cmd = f"sudo openvpn --config {remote_cfg} --daemon --log /tmp/openvpn.log"
            else:  # WireGuard
                cmd = f"sudo wg-quick up {remote_cfg}"

            out, err = self._exec(cmd)
            self._append("INFO", f"  {out}{err}\n")

            # Wait for tun0 / wg0
            iface = "tun0" if vpn_type == "OpenVPN" else "wg0"
            for attempt in range(20):
                time.sleep(2)
                chk, _ = self._exec(f"ip a show {iface} 2>/dev/null | grep 'inet '")
                if chk.strip():
                    ip_line = chk.strip()
                    self._append("HEADER", f"  VPN activa — {iface}: {ip_line}\n")
                    self.vpn_active = True
                    self.root.after(0, self._vpn_on_ui)
                    return

            self._append("CRITICAL", "  [!] VPN no levantó interfaz en 40 s — verifica config.\n")
            self.root.after(0, lambda: self._set_status("VPN falló."))
        except Exception as e:
            self._append("CRITICAL", f"  [ERROR VPN] {e}\n")

    def _vpn_disconnect(self):
        name = self._sel_client.get()
        vpn_type = self.clients.get(name, {}).get("vpn_type", "OpenVPN")
        self._append("HEADER", f"\n[{now_str()}] Desconectando VPN...\n")
        if vpn_type == "OpenVPN":
            self._exec("sudo pkill openvpn")
        else:
            remote_cfg = f"/tmp/vpn_{name.replace(' ','_')}.conf"
            self._exec(f"sudo wg-quick down {remote_cfg}")
        self.vpn_active = False
        self.root.after(0, self._vpn_off_ui)

    def _vpn_on_ui(self):
        self.vpn_lbl.config(text="● VPN activa", fg=GREEN)
        self.vpn_btn.config(text="Desconectar VPN", bg="#da3633")
        self._set_status("VPN activa — listo para escanear.")

    def _vpn_off_ui(self):
        self.vpn_lbl.config(text="● VPN inactiva", fg=RED)
        self.vpn_btn.config(text="Conectar VPN", bg=ORANGE)
        self._set_status("VPN desconectada.")

    # ── Scan ─────────────────────────────────────────────────────────────────────

    def _start_scan(self):
        target = self._target.get().strip()
        if not target:
            messagebox.showwarning("Sin objetivo", "Ingresa IP, rango o hostname.")
            return
        if not self.connected:
            messagebox.showwarning("Sin SSH", "Conecta al servidor Kali primero.")
            return
        cmd_tpl = self._cmd.get().strip()
        if not cmd_tpl:
            messagebox.showwarning("Sin comando", "Selecciona un perfil o escribe el comando.")
            return

        cmd = cmd_tpl.replace("{target}", target)
        self.stop_evt.clear()
        self.scan_results.clear()
        self.scanning = True
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress.start(12)
        self._clear_findings()
        self._append("HEADER",
            f"\n{'═'*68}\n"
            f"[{now_str()}] ESCANEO INICIADO\n"
            f"  Cliente  : {self._sel_client.get() or 'N/A'}\n"
            f"  Objetivo : {target}\n"
            f"  Perfil   : {self._profile.get()}\n"
            f"  Comando  : {cmd}\n"
            f"  VPN      : {'Activa' if self.vpn_active else 'Inactiva'}\n"
            f"{'═'*68}\n"
        )
        self._set_status(f"Escaneando {target} ...")
        self._start_time = datetime.datetime.now()

        threading.Thread(target=self._run_scan, args=(cmd,), daemon=True).start()

    def _run_scan(self, cmd):
        try:
            transport = self.ssh.get_transport()
            chan = transport.open_session()
            chan.set_combine_stderr(True)
            chan.exec_command(cmd)
            buf = ""
            while not self.stop_evt.is_set():
                if chan.recv_ready():
                    chunk = chan.recv(4096).decode("utf-8", errors="replace")
                    buf += chunk
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        self.out_queue.put(("line", line + "\n"))
                        self.scan_results.append(line)
                elif chan.exit_status_ready():
                    if buf:
                        self.out_queue.put(("line", buf + "\n"))
                        self.scan_results.append(buf)
                    break
                else:
                    time.sleep(0.05)
            if self.stop_evt.is_set():
                chan.close()
                self.out_queue.put(("line", "\n[!] Escaneo detenido.\n"))
            else:
                elapsed = datetime.datetime.now() - self._start_time
                self.out_queue.put(("done",
                    f"\n{'═'*68}\n[{now_str()}] COMPLETADO — {elapsed}\n{'═'*68}\n"))
        except Exception as e:
            self.out_queue.put(("error", f"\n[ERROR] {e}\n"))

    def _stop_scan(self):
        self.stop_evt.set()
        self.stop_btn.config(state="disabled")
        self._set_status("Deteniendo...")

    # ── Queue poll ────────────────────────────────────────────────────────────

    def _poll_queue(self):
        try:
            while True:
                kind, data = self.out_queue.get_nowait()
                if kind == "line":
                    sev = detect_severity(data)
                    self._append(sev, data)
                    if sev in ("CRITICAL", "HIGH", "MEDIUM"):
                        self._append_finding(sev, data)
                    self._update_results_preview(data)
                elif kind == "done":
                    self._append("HEADER", data)
                    self._scan_done()
                elif kind == "error":
                    self._append("CRITICAL", data)
                    self._scan_done()
        except queue.Empty:
            pass
        self.root.after(50, self._poll_queue)

    def _scan_done(self):
        self.scanning = False
        self.progress.stop()
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if self._start_time:
            elapsed = datetime.datetime.now() - self._start_time
            self._set_status(f"Escaneo finalizado — {elapsed}")
            self._elapsed.set(f"Duración: {elapsed}")

    # ── Output ────────────────────────────────────────────────────────────────

    def _append(self, tag, text):
        self.out_text.config(state="normal")
        self.out_text.insert("end", text, tag)
        self.out_text.see("end")
        self.out_text.config(state="disabled")

    def _append_finding(self, tag, text):
        self.find_text.config(state="normal")
        self.find_text.insert("end", f"[{tag}] ", tag)
        self.find_text.insert("end", text.strip() + "\n")
        self.find_text.see("end")
        self.find_text.config(state="disabled")

    def _clear_findings(self):
        self.find_text.config(state="normal")
        self.find_text.delete("1.0", "end")
        self.find_text.config(state="disabled")

    def _clear_output(self):
        self.out_text.config(state="normal")
        self.out_text.delete("1.0", "end")
        self.out_text.config(state="disabled")
        self._clear_findings()
        self.scan_results.clear()
        self._elapsed.set("")
        self._update_results_preview("")

    def _update_results_preview(self, line):
        self.results_preview.config(state="normal")
        if line == "":
            self.results_preview.delete("1.0", "end")
        else:
            self.results_preview.insert("end", line)
            self.results_preview.see("end")
        self.results_preview.config(state="disabled")

    def _set_status(self, msg):
        self._status.set(msg)

    # ── SSH exec helper ───────────────────────────────────────────────────────

    def _exec(self, cmd):
        _, stdout, stderr = self.ssh.exec_command(cmd)
        return stdout.read().decode("utf-8", errors="replace"), \
               stderr.read().decode("utf-8", errors="replace")

    # ── Export ────────────────────────────────────────────────────────────────

    def _export(self, fmt):
        if not self.scan_results:
            messagebox.showinfo("Sin datos", "No hay resultados para exportar.")
            return
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = re.sub(r"[^a-zA-Z0-9._-]", "_", self._target.get())
        client_safe = re.sub(r"[^a-zA-Z0-9._-]", "_", self._sel_client.get() or "scan")
        default = f"vuln_{client_safe}_{target_safe}_{ts}.{fmt}"
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}", initialfile=default,
            filetypes=[(f"{fmt.upper()} files", f"*.{fmt}"), ("All files", "*.*")])
        if not path:
            return
        try:
            if fmt == "txt":
                with open(path, "w") as f:
                    f.write(f"Kali VPN Vulnerability Scanner — {now_str()}\n")
                    f.write(f"Cliente : {self._sel_client.get()}\n")
                    f.write(f"Objetivo: {self._target.get()}\n")
                    f.write(f"Perfil  : {self._profile.get()}\n")
                    f.write("=" * 68 + "\n")
                    f.write("\n".join(self.scan_results))

            elif fmt == "json":
                with open(path, "w") as f:
                    json.dump({
                        "timestamp": now_str(),
                        "client":    self._sel_client.get(),
                        "target":    self._target.get(),
                        "profile":   self._profile.get(),
                        "command":   self._cmd.get(),
                        "results":   self.scan_results,
                    }, f, indent=2, ensure_ascii=False)

            elif fmt == "html":
                rows = ""
                for line in self.scan_results:
                    sev   = detect_severity(line)
                    color = SEV_COLORS.get(sev, FG)
                    esc   = line.replace("&","&amp;").replace("<","&lt;")
                    rows += f'<tr style="color:{color}"><td>{sev}</td><td><code>{esc}</code></td></tr>\n'
                html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Vulnerability Report — {self._target.get()}</title>
<style>
  body{{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:20px}}
  h1{{color:#58a6ff}} table{{width:100%;border-collapse:collapse}}
  td{{padding:4px 8px;border-bottom:1px solid #21262d;vertical-align:top}}
  td:first-child{{width:90px;font-weight:bold}}
</style></head><body>
<h1>Vulnerability Scan Report</h1>
<p>Cliente: <b>{self._sel_client.get()}</b> | Objetivo: <b>{self._target.get()}</b> | {now_str()}</p>
<p>Perfil: {self._profile.get()}</p>
<table>{rows}</table></body></html>"""
                with open(path, "w") as f:
                    f.write(html)

            messagebox.showinfo("Exportado", f"Guardado en:\n{path}")
        except Exception as e:
            messagebox.showerror("Error al exportar", str(e))

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def on_close(self):
        self.stop_evt.set()
        if self.ssh:
            self.ssh.close()
        self.root.destroy()


# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    app  = VulnScannerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
