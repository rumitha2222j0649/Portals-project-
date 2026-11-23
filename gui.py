"""
gui.py - Modern Tkinter GUI Dashboard for Portal Scanner.
Features dedicated tabs for Port Scanning, Network Device Discovery,
Deep Service Inspection, and Documentation / Nmap setup guide.
"""

from datetime import datetime
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional

import config
from network_discovery import DeviceResult, NetworkDiscovery
from scanner_nmap import NmapScanner, is_nmap_available
from scanner_socket import PortScanResult, SocketPortScanner
import utils


class PortalScannerGUI:
    """
    Main GUI Controller and Dashboard for Portal Scanner.
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{config.APP_NAME} - v{config.APP_VERSION}")
        self.root.geometry("1120x760")
        self.root.minsize(980, 680)

        # Thread-safe communication queue
        self.ui_queue: queue.Queue = queue.Queue()

        # Scanner instances
        self.socket_scanner = SocketPortScanner()
        self.nmap_scanner = NmapScanner()
        self.network_discoverer = NetworkDiscovery()

        # State trackers
        self.port_scan_results: List[PortScanResult] = []
        self.device_scan_results: List[DeviceResult] = []
        self.active_scan_thread: Optional[threading.Thread] = None
        self.active_discovery_thread: Optional[threading.Thread] = None
        self.port_scan_start_time: float = 0.0
        self.discovery_start_time: float = 0.0

        # Stats counters
        self.count_open = 0
        self.count_closed = 0
        self.count_filtered = 0

        # Setup custom styles and layouts
        self._apply_styles()
        self._build_ui()

        # Start periodic UI queue processor
        self.root.after(40, self._process_ui_queue)

        # Intercept window close to gracefully terminate background threads
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _apply_styles(self):
        """Configures modern styling for ttk widgets."""
        self.root.configure(bg=config.COLORS["bg_dark"])

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Frame backgrounds
        style.configure("Dark.TFrame", background=config.COLORS["bg_dark"])
        style.configure("Card.TFrame", background=config.COLORS["bg_card"], relief="flat")
        style.configure("CardAlt.TFrame", background=config.COLORS["bg_card_alt"], relief="flat")

        # Labels
        style.configure(
            "Title.TLabel",
            background=config.COLORS["bg_dark"],
            foreground=config.COLORS["accent_primary"],
            font=("Segoe UI", 16, "bold"),
        )
        style.configure(
            "Subtitle.TLabel",
            background=config.COLORS["bg_dark"],
            foreground=config.COLORS["fg_muted"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "CardTitle.TLabel",
            background=config.COLORS["bg_card"],
            foreground=config.COLORS["accent_primary"],
            font=("Segoe UI", 11, "bold"),
        )
        style.configure(
            "CardText.TLabel",
            background=config.COLORS["bg_card"],
            foreground=config.COLORS["fg_text"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "Muted.TLabel",
            background=config.COLORS["bg_card"],
            foreground=config.COLORS["fg_muted"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "Status.TLabel",
            background=config.COLORS["bg_card"],
            foreground=config.COLORS["fg_text"],
            font=("Segoe UI", 9, "bold"),
        )

        # Badges / Stat values
        style.configure(
            "StatVal.TLabel",
            background=config.COLORS["bg_card_alt"],
            foreground=config.COLORS["fg_text"],
            font=("Segoe UI", 14, "bold"),
        )
        style.configure(
            "StatOpen.TLabel",
            background=config.COLORS["bg_card_alt"],
            foreground=config.COLORS["state_open"],
            font=("Segoe UI", 14, "bold"),
        )
        style.configure(
            "StatClosed.TLabel",
            background=config.COLORS["bg_card_alt"],
            foreground=config.COLORS["state_closed"],
            font=("Segoe UI", 14, "bold"),
        )
        style.configure(
            "StatFiltered.TLabel",
            background=config.COLORS["bg_card_alt"],
            foreground=config.COLORS["state_filtered"],
            font=("Segoe UI", 14, "bold"),
        )

        # Notebook tabs
        style.configure(
            "TNotebook",
            background=config.COLORS["bg_dark"],
            borderwidth=0,
        )
        style.configure(
            "TNotebook.Tab",
            background=config.COLORS["bg_card"],
            foreground=config.COLORS["fg_muted"],
            padding=[16, 8],
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", config.COLORS["bg_card_alt"])],
            foreground=[("selected", config.COLORS["accent_primary"])],
        )

        # Buttons
        style.configure(
            "Primary.TButton",
            font=("Segoe UI", 9, "bold"),
            background=config.COLORS["btn_green"],
            foreground="#ffffff",
            borderwidth=0,
            padding=[12, 6],
        )
        style.configure(
            "Danger.TButton",
            font=("Segoe UI", 9, "bold"),
            background=config.COLORS["btn_red"],
            foreground="#ffffff",
            borderwidth=0,
            padding=[12, 6],
        )
        style.configure(
            "Secondary.TButton",
            font=("Segoe UI", 9),
            background=config.COLORS["btn_gray"],
            foreground="#ffffff",
            borderwidth=0,
            padding=[10, 5],
        )

        # Progressbar
        style.configure(
            "Horizontal.TProgressbar",
            background=config.COLORS["accent_primary"],
            troughcolor=config.COLORS["bg_card"],
            borderwidth=0,
            thickness=8,
        )

        # Treeview (Results Tables)
        style.configure(
            "Treeview",
            background=config.COLORS["bg_card"],
            foreground=config.COLORS["fg_text"],
            fieldbackground=config.COLORS["bg_card"],
            rowheight=26,
            font=("Segoe UI", 9),
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background=config.COLORS["bg_card_alt"],
            foreground=config.COLORS["accent_primary"],
            font=("Segoe UI", 9, "bold"),
            padding=[6, 4],
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", config.COLORS["accent_hover"])],
            foreground=[("selected", "#ffffff")],
        )

    def _build_ui(self):
        """Constructs all GUI elements, header, and notebook tabs."""
        # Top Header Bar
        header_frame = ttk.Frame(self.root, style="Dark.TFrame", padding=(16, 12, 16, 8))
        header_frame.pack(fill="x")

        title_box = ttk.Frame(header_frame, style="Dark.TFrame")
        title_box.pack(side="left", fill="y")

        lbl_title = ttk.Label(title_box, text=config.APP_NAME.upper(), style="Title.TLabel")
        lbl_title.pack(anchor="w")

        lbl_sub = ttk.Label(title_box, text=config.APP_SUBTITLE, style="Subtitle.TLabel")
        lbl_sub.pack(anchor="w")

        # Nmap Availability Badge in Header
        badge_box = ttk.Frame(header_frame, style="Dark.TFrame")
        badge_box.pack(side="right", fill="y")

        nmap_ok, nmap_msg = is_nmap_available()
        self.nmap_available = nmap_ok

        badge_text = "Nmap Engine: READY" if nmap_ok else "Nmap Engine: NOT DETECTED (Socket Ready)"
        badge_color = config.COLORS["state_open"] if nmap_ok else config.COLORS["state_filtered"]

        lbl_badge = tk.Label(
            badge_box,
            text=badge_text,
            bg=config.COLORS["bg_card"],
            fg=badge_color,
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=4,
            relief="groove",
            bd=1,
        )
        lbl_badge.pack(anchor="e")

        # Main Tabbed Notebook Container
        self.notebook = ttk.Notebook(self.root, style="TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        # Create the separate sections / tabs
        self.tab_port_scanner = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.tab_network_discovery = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.tab_service_inspector = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.tab_help_docs = ttk.Frame(self.notebook, style="Dark.TFrame")

        self.notebook.add(self.tab_port_scanner, text="  Port Scanner  ")
        self.notebook.add(self.tab_network_discovery, text="  Network Device Discovery  ")
        self.notebook.add(self.tab_service_inspector, text="  Service Inspector  ")
        self.notebook.add(self.tab_help_docs, text="  Help & Nmap Setup  ")

        # Build individual tabs
        self._build_port_scanner_tab()
        self._build_network_discovery_tab()
        self._build_service_inspector_tab()
        self._build_help_tab()

    # =========================================================================
    # TAB 1: PORT SCANNER SECTION
    # =========================================================================
    def _build_port_scanner_tab(self):
        container = ttk.Frame(self.tab_port_scanner, style="Dark.TFrame", padding=10)
        container.pack(fill="both", expand=True)

        # Control Panel (Top Card)
        ctrl_card = ttk.Frame(container, style="Card.TFrame", padding=12)
        ctrl_card.pack(fill="x", pady=(0, 10))

        # --- Row 1: Target IP / Hostname Configuration ---
        row1 = ttk.Frame(ctrl_card, style="Card.TFrame")
        row1.pack(fill="x", pady=(0, 8))

        lbl_target = ttk.Label(row1, text="Target Address:", style="CardTitle.TLabel")
        lbl_target.pack(side="left", padx=(0, 8))

        self.var_target_ip = tk.StringVar(value="127.0.0.1")
        self.entry_target_ip = tk.Entry(
            row1,
            textvariable=self.var_target_ip,
            font=("Segoe UI", 10),
            bg=config.COLORS["bg_input"],
            fg=config.COLORS["fg_text"],
            insertbackground=config.COLORS["fg_text"],
            relief="solid",
            bd=1,
            width=24,
        )
        self.entry_target_ip.pack(side="left", padx=(0, 8))

        # Quick preset target buttons
        btn_local = tk.Button(
            row1,
            text="Localhost (127.0.0.1)",
            command=lambda: self.var_target_ip.set("127.0.0.1"),
            bg=config.COLORS["bg_card_alt"],
            fg=config.COLORS["fg_text"],
            font=("Segoe UI", 8),
            relief="flat",
            padx=6,
            pady=2,
            cursor="hand2",
        )
        btn_local.pack(side="left", padx=3)

        btn_scanme = tk.Button(
            row1,
            text="scanme.nmap.org",
            command=lambda: self.var_target_ip.set("scanme.nmap.org"),
            bg=config.COLORS["bg_card_alt"],
            fg=config.COLORS["fg_text"],
            font=("Segoe UI", 8),
            relief="flat",
            padx=6,
            pady=2,
            cursor="hand2",
        )
        btn_scanme.pack(side="left", padx=3)

        btn_my_ip = tk.Button(
            row1,
            text="My LAN IP",
            command=self._fill_local_ip,
            bg=config.COLORS["bg_card_alt"],
            fg=config.COLORS["fg_text"],
            font=("Segoe UI", 8),
            relief="flat",
            padx=6,
            pady=2,
            cursor="hand2",
        )
        btn_my_ip.pack(side="left", padx=3)

        # Engine selector on right
        engine_box = ttk.Frame(row1, style="Card.TFrame")
        engine_box.pack(side="right")

        ttk.Label(engine_box, text="Engine:", style="CardText.TLabel").pack(side="left", padx=(0, 4))
        self.var_port_engine = tk.StringVar(value="socket")
        rb_sock = tk.Radiobutton(
            engine_box,
            text="Socket (Native)",
            variable=self.var_port_engine,
            value="socket",
            bg=config.COLORS["bg_card"],
            fg=config.COLORS["fg_text"],
            selectcolor=config.COLORS["bg_dark"],
            activebackground=config.COLORS["bg_card"],
            activeforeground=config.COLORS["accent_primary"],
            font=("Segoe UI", 9),
        )
        rb_sock.pack(side="left", padx=4)

        rb_nmap = tk.Radiobutton(
            engine_box,
            text="Nmap (-sV)",
            variable=self.var_port_engine,
            value="nmap",
            bg=config.COLORS["bg_card"],
            fg=config.COLORS["fg_text"],
            selectcolor=config.COLORS["bg_dark"],
            activebackground=config.COLORS["bg_card"],
            activeforeground=config.COLORS["accent_primary"],
            font=("Segoe UI", 9),
        )
        rb_nmap.pack(side="left", padx=4)
        if not self.nmap_available:
            rb_nmap.configure(state="normal")  # let them click, will alert gracefully

        # --- Row 2: Port Selection ---
        row2 = ttk.Frame(ctrl_card, style="Card.TFrame")
        row2.pack(fill="x", pady=(0, 8))

        ttk.Label(row2, text="Select Ports:", style="CardTitle.TLabel").pack(side="left", padx=(0, 18))

        # Preset Dropdown
        self.preset_options = list(config.PORT_PRESETS.keys()) + ["Custom Range (e.g. 1-1024)", "Custom List (e.g. 22,80,443)"]
        self.var_port_preset = tk.StringVar(value="Common Core (10 ports)")
        self.combo_presets = ttk.Combobox(
            row2,
            textvariable=self.var_port_preset,
            values=self.preset_options,
            state="readonly",
            width=26,
            font=("Segoe UI", 9),
        )
        self.combo_presets.pack(side="left", padx=(0, 8))
        self.combo_presets.bind("<<ComboboxSelected>>", self._on_port_preset_selected)

        # Port Input Entry
        self.var_ports_entry = tk.StringVar(value="21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389")
        self.entry_ports = tk.Entry(
            row2,
            textvariable=self.var_ports_entry,
            font=("Segoe UI", 10),
            bg=config.COLORS["bg_input"],
            fg=config.COLORS["fg_text"],
            insertbackground=config.COLORS["fg_text"],
            relief="solid",
            bd=1,
        )
        self.entry_ports.pack(side="left", fill="x", expand=True, padx=(0, 8))

        # --- Row 3: Scan Tuning & Action Buttons ---
        row3 = ttk.Frame(ctrl_card, style="Card.TFrame")
        row3.pack(fill="x")

        # Concurrency & Timeout
        ttk.Label(row3, text="Threads:", style="Muted.TLabel").pack(side="left", padx=(0, 4))
        self.var_threads = tk.IntVar(value=40)
        sp_threads = tk.Spinbox(
            row3,
            from_=1,
            to=200,
            textvariable=self.var_threads,
            width=5,
            bg=config.COLORS["bg_input"],
            fg=config.COLORS["fg_text"],
            buttonbackground=config.COLORS["bg_card_alt"],
            relief="solid",
            bd=1,
        )
        sp_threads.pack(side="left", padx=(0, 12))

        ttk.Label(row3, text="Timeout (s):", style="Muted.TLabel").pack(side="left", padx=(0, 4))
        self.var_timeout = tk.DoubleVar(value=1.0)
        sp_timeout = tk.Spinbox(
            row3,
            from_=0.2,
            to=5.0,
            increment=0.2,
            textvariable=self.var_timeout,
            width=5,
            bg=config.COLORS["bg_input"],
            fg=config.COLORS["fg_text"],
            buttonbackground=config.COLORS["bg_card_alt"],
            relief="solid",
            bd=1,
        )
        sp_timeout.pack(side="left", padx=(0, 12))

        # Filter: Only Open Ports
        self.var_filter_open_only = tk.BooleanVar(value=False)
        chk_open = tk.Checkbutton(
            row3,
            text="Show Open Ports Only",
            variable=self.var_filter_open_only,
            command=self._apply_port_table_filter,
            bg=config.COLORS["bg_card"],
            fg=config.COLORS["accent_primary"],
            selectcolor=config.COLORS["bg_dark"],
            activebackground=config.COLORS["bg_card"],
            activeforeground=config.COLORS["accent_primary"],
            font=("Segoe UI", 9),
        )
        chk_open.pack(side="left", padx=(0, 12))

        # Action Buttons
        self.btn_start_port_scan = tk.Button(
            row3,
            text=" Start Port Scan ",
            command=self._start_port_scan,
            bg=config.COLORS["btn_green"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=4,
            cursor="hand2",
        )
        self.btn_start_port_scan.pack(side="right", padx=4)

        self.btn_stop_port_scan = tk.Button(
            row3,
            text=" Stop ",
            command=self._stop_port_scan,
            bg=config.COLORS["btn_red"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=10,
            pady=4,
            state="disabled",
            cursor="hand2",
        )
        self.btn_stop_port_scan.pack(side="right", padx=4)

        btn_clear = tk.Button(
            row3,
            text=" Clear ",
            command=self._clear_port_results,
            bg=config.COLORS["btn_gray"],
            fg="#ffffff",
            font=("Segoe UI", 9),
            relief="flat",
            padx=8,
            pady=4,
            cursor="hand2",
        )
        btn_clear.pack(side="right", padx=4)

        btn_export = tk.Button(
            row3,
            text=" Export CSV ",
            command=self._export_port_results_csv,
            bg=config.COLORS["bg_card_alt"],
            fg=config.COLORS["accent_primary"],
            font=("Segoe UI", 9, "bold"),
            relief="solid",
            bd=1,
            padx=8,
            pady=4,
            cursor="hand2",
        )
        btn_export.pack(side="right", padx=4)

        # Summary Metric Badges Card
        stats_frame = ttk.Frame(container, style="CardAlt.TFrame", padding=(10, 6))
        stats_frame.pack(fill="x", pady=(0, 8))

        self.lbl_stat_total = ttk.Label(stats_frame, text="Total Ports: 0", style="StatVal.TLabel")
        self.lbl_stat_total.pack(side="left", padx=16)

        self.lbl_stat_open = ttk.Label(stats_frame, text="OPEN: 0", style="StatOpen.TLabel")
        self.lbl_stat_open.pack(side="left", padx=16)

        self.lbl_stat_closed = ttk.Label(stats_frame, text="CLOSED: 0", style="StatClosed.TLabel")
        self.lbl_stat_closed.pack(side="left", padx=16)

        self.lbl_stat_filtered = ttk.Label(stats_frame, text="FILTERED: 0", style="StatFiltered.TLabel")
        self.lbl_stat_filtered.pack(side="left", padx=16)

        self.lbl_stat_time = ttk.Label(stats_frame, text="Duration: 0.0s", style="StatVal.TLabel")
        self.lbl_stat_time.pack(side="right", padx=16)

        # Progress bar & Status text
        progress_box = ttk.Frame(container, style="Dark.TFrame")
        progress_box.pack(fill="x", pady=(0, 6))

        self.progress_port = ttk.Progressbar(progress_box, style="Horizontal.TProgressbar", mode="determinate")
        self.progress_port.pack(fill="x", pady=(0, 4))

        self.lbl_port_status = ttk.Label(
            progress_box,
            text="Ready. Select target and ports, then click 'Start Port Scan'.",
            style="Subtitle.TLabel",
        )
        self.lbl_port_status.pack(anchor="w")

        # Results Table Frame
        table_frame = ttk.Frame(container, style="Card.TFrame")
        table_frame.pack(fill="both", expand=True)

        columns = ("port", "protocol", "state", "service", "banner", "latency")
        self.tree_ports = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.tree_ports.heading("port", text="Port")
        self.tree_ports.heading("protocol", text="Proto")
        self.tree_ports.heading("state", text="State")
        self.tree_ports.heading("service", text="Identified Service")
        self.tree_ports.heading("banner", text="Service Banner / Version Information")
        self.tree_ports.heading("latency", text="Latency")

        self.tree_ports.column("port", width=80, anchor="center")
        self.tree_ports.column("protocol", width=60, anchor="center")
        self.tree_ports.column("state", width=100, anchor="center")
        self.tree_ports.column("service", width=160, anchor="w")
        self.tree_ports.column("banner", width=480, anchor="w")
        self.tree_ports.column("latency", width=80, anchor="e")

        # Visual state color tags in Treeview
        self.tree_ports.tag_configure("open", foreground=config.COLORS["state_open"], background=config.COLORS["state_open_bg"])
        self.tree_ports.tag_configure("closed", foreground=config.COLORS["state_closed"])
        self.tree_ports.tag_configure("filtered", foreground=config.COLORS["state_filtered"])

        # Scrollbars
        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_ports.yview)
        scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree_ports.xview)
        self.tree_ports.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        self.tree_ports.pack(fill="both", expand=True)

        # Double-click handler to inspect service
        self.tree_ports.bind("<Double-1>", self._on_port_row_double_click)

    # =========================================================================
    # TAB 2: NETWORK DEVICE DISCOVERY SECTION
    # =========================================================================
    def _build_network_discovery_tab(self):
        container = ttk.Frame(self.tab_network_discovery, style="Dark.TFrame", padding=10)
        container.pack(fill="both", expand=True)

        # Control Card
        ctrl_card = ttk.Frame(container, style="Card.TFrame", padding=12)
        ctrl_card.pack(fill="x", pady=(0, 10))

        # Row 1: Subnet Input
        row1 = ttk.Frame(ctrl_card, style="Card.TFrame")
        row1.pack(fill="x", pady=(0, 8))

        lbl_subnet = ttk.Label(row1, text="Target Subnet / CIDR:", style="CardTitle.TLabel")
        lbl_subnet.pack(side="left", padx=(0, 8))

        _, default_subnet = utils.get_local_ip_and_subnet()
        self.var_subnet = tk.StringVar(value=default_subnet)
        self.entry_subnet = tk.Entry(
            row1,
            textvariable=self.var_subnet,
            font=("Segoe UI", 10),
            bg=config.COLORS["bg_input"],
            fg=config.COLORS["fg_text"],
            insertbackground=config.COLORS["fg_text"],
            relief="solid",
            bd=1,
            width=24,
        )
        self.entry_subnet.pack(side="left", padx=(0, 8))

        btn_detect = tk.Button(
            row1,
            text="Detect My Subnet",
            command=self._detect_local_subnet,
            bg=config.COLORS["bg_card_alt"],
            fg=config.COLORS["accent_primary"],
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=8,
            pady=2,
            cursor="hand2",
        )
        btn_detect.pack(side="left", padx=4)

        # Engine selector
        engine_box = ttk.Frame(row1, style="Card.TFrame")
        engine_box.pack(side="right")

        ttk.Label(engine_box, text="Method:", style="CardText.TLabel").pack(side="left", padx=(0, 4))
        self.var_discovery_engine = tk.StringVar(value="socket")
        rb_sock_disc = tk.Radiobutton(
            engine_box,
            text="TCP / Ping / ARP",
            variable=self.var_discovery_engine,
            value="socket",
            bg=config.COLORS["bg_card"],
            fg=config.COLORS["fg_text"],
            selectcolor=config.COLORS["bg_dark"],
            activebackground=config.COLORS["bg_card"],
            font=("Segoe UI", 9),
        )
        rb_sock_disc.pack(side="left", padx=4)

        rb_nmap_disc = tk.Radiobutton(
            engine_box,
            text="Nmap Ping (-sn)",
            variable=self.var_discovery_engine,
            value="nmap",
            bg=config.COLORS["bg_card"],
            fg=config.COLORS["fg_text"],
            selectcolor=config.COLORS["bg_dark"],
            activebackground=config.COLORS["bg_card"],
            font=("Segoe UI", 9),
        )
        rb_nmap_disc.pack(side="left", padx=4)

        # Row 2: Controls & Action Buttons
        row2 = ttk.Frame(ctrl_card, style="Card.TFrame")
        row2.pack(fill="x")

        ttk.Label(row2, text="Max Threads:", style="Muted.TLabel").pack(side="left", padx=(0, 4))
        self.var_disc_threads = tk.IntVar(value=60)
        sp_disc_threads = tk.Spinbox(
            row2,
            from_=10,
            to=150,
            textvariable=self.var_disc_threads,
            width=5,
            bg=config.COLORS["bg_input"],
            fg=config.COLORS["fg_text"],
            buttonbackground=config.COLORS["bg_card_alt"],
            relief="solid",
            bd=1,
        )
        sp_disc_threads.pack(side="left", padx=(0, 16))

        # Action Buttons
        self.btn_start_disc = tk.Button(
            row2,
            text=" Discover Active Devices ",
            command=self._start_network_discovery,
            bg=config.COLORS["btn_green"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=4,
            cursor="hand2",
        )
        self.btn_start_disc.pack(side="right", padx=4)

        self.btn_stop_disc = tk.Button(
            row2,
            text=" Stop ",
            command=self._stop_network_discovery,
            bg=config.COLORS["btn_red"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=10,
            pady=4,
            state="disabled",
            cursor="hand2",
        )
        self.btn_stop_disc.pack(side="right", padx=4)

        btn_send_port = tk.Button(
            row2,
            text=" Scan Selected Device Ports ",
            command=self._send_device_to_port_scanner,
            bg=config.COLORS["bg_card_alt"],
            fg=config.COLORS["accent_primary"],
            font=("Segoe UI", 9, "bold"),
            relief="solid",
            bd=1,
            padx=8,
            pady=4,
            cursor="hand2",
        )
        btn_send_port.pack(side="right", padx=4)

        btn_disc_export = tk.Button(
            row2,
            text=" Export CSV ",
            command=self._export_device_results_csv,
            bg=config.COLORS["bg_card_alt"],
            fg=config.COLORS["fg_text"],
            font=("Segoe UI", 9),
            relief="flat",
            padx=8,
            pady=4,
            cursor="hand2",
        )
        btn_disc_export.pack(side="right", padx=4)

        # Discovery Metric Card
        disc_stats = ttk.Frame(container, style="CardAlt.TFrame", padding=(10, 6))
        disc_stats.pack(fill="x", pady=(0, 8))

        self.lbl_disc_hosts = ttk.Label(disc_stats, text="Probed Hosts: 0", style="StatVal.TLabel")
        self.lbl_disc_hosts.pack(side="left", padx=16)

        self.lbl_disc_active = ttk.Label(disc_stats, text="ACTIVE DEVICES: 0", style="StatOpen.TLabel")
        self.lbl_disc_active.pack(side="left", padx=16)

        self.lbl_disc_time = ttk.Label(disc_stats, text="Duration: 0.0s", style="StatVal.TLabel")
        self.lbl_disc_time.pack(side="right", padx=16)

        # Progress bar
        disc_prog_box = ttk.Frame(container, style="Dark.TFrame")
        disc_prog_box.pack(fill="x", pady=(0, 6))

        self.progress_disc = ttk.Progressbar(disc_prog_box, style="Horizontal.TProgressbar", mode="determinate")
        self.progress_disc.pack(fill="x", pady=(0, 4))

        self.lbl_disc_status = ttk.Label(
            disc_prog_box,
            text="Ready. Enter subnet (e.g. 192.168.1.0/24) and click 'Discover Active Devices'.",
            style="Subtitle.TLabel",
        )
        self.lbl_disc_status.pack(anchor="w")

        # Devices Table
        table_frame = ttk.Frame(container, style="Card.TFrame")
        table_frame.pack(fill="both", expand=True)

        columns = ("ip", "hostname", "mac", "status", "latency", "time")
        self.tree_devices = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.tree_devices.heading("ip", text="IP Address")
        self.tree_devices.heading("hostname", text="Resolved Hostname")
        self.tree_devices.heading("mac", text="MAC Address")
        self.tree_devices.heading("status", text="Status")
        self.tree_devices.heading("latency", text="Latency")
        self.tree_devices.heading("time", text="Discovered At")

        self.tree_devices.column("ip", width=140, anchor="center")
        self.tree_devices.column("hostname", width=220, anchor="w")
        self.tree_devices.column("mac", width=160, anchor="center")
        self.tree_devices.column("status", width=90, anchor="center")
        self.tree_devices.column("latency", width=90, anchor="e")
        self.tree_devices.column("time", width=150, anchor="center")

        self.tree_devices.tag_configure("online", foreground=config.COLORS["state_open"])

        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_devices.yview)
        self.tree_devices.configure(yscrollcommand=scroll_y.set)

        scroll_y.pack(side="right", fill="y")
        self.tree_devices.pack(fill="both", expand=True)

        self.tree_devices.bind("<Double-1>", lambda event: self._send_device_to_port_scanner())

    # =========================================================================
    # TAB 3: DEEP SERVICE INSPECTOR
    # =========================================================================
    def _build_service_inspector_tab(self):
        container = ttk.Frame(self.tab_service_inspector, style="Dark.TFrame", padding=12)
        container.pack(fill="both", expand=True)

        ctrl_card = ttk.Frame(container, style="Card.TFrame", padding=12)
        ctrl_card.pack(fill="x", pady=(0, 10))

        ttk.Label(ctrl_card, text="Target IP:", style="CardTitle.TLabel").pack(side="left", padx=(0, 6))
        self.var_inspect_ip = tk.StringVar(value="127.0.0.1")
        tk.Entry(
            ctrl_card,
            textvariable=self.var_inspect_ip,
            font=("Segoe UI", 10),
            bg=config.COLORS["bg_input"],
            fg=config.COLORS["fg_text"],
            insertbackground=config.COLORS["fg_text"],
            width=20,
        ).pack(side="left", padx=(0, 16))

        ttk.Label(ctrl_card, text="Port:", style="CardTitle.TLabel").pack(side="left", padx=(0, 6))
        self.var_inspect_port = tk.IntVar(value=80)
        tk.Entry(
            ctrl_card,
            textvariable=self.var_inspect_port,
            font=("Segoe UI", 10),
            bg=config.COLORS["bg_input"],
            fg=config.COLORS["fg_text"],
            insertbackground=config.COLORS["fg_text"],
            width=8,
        ).pack(side="left", padx=(0, 16))

        # Quick port buttons
        for p, label in [(80, "HTTP"), (443, "HTTPS"), (22, "SSH"), (3306, "MySQL")]:
            btn = tk.Button(
                ctrl_card,
                text=label,
                command=lambda port_num=p: self.var_inspect_port.set(port_num),
                bg=config.COLORS["bg_card_alt"],
                fg=config.COLORS["fg_text"],
                font=("Segoe UI", 8),
                padx=6,
                pady=2,
                relief="flat",
                cursor="hand2",
            )
            btn.pack(side="left", padx=3)

        btn_inspect = tk.Button(
            ctrl_card,
            text=" Inspect Service ",
            command=self._run_deep_service_inspection,
            bg=config.COLORS["accent_primary"],
            fg=config.COLORS["bg_dark"],
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=4,
            cursor="hand2",
        )
        btn_inspect.pack(side="right")

        # Output Text View
        out_frame = ttk.Frame(container, style="Card.TFrame", padding=10)
        out_frame.pack(fill="both", expand=True)

        ttk.Label(out_frame, text="Service Diagnostic & Banner Analysis:", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 6))

        self.txt_inspect_output = tk.Text(
            out_frame,
            bg=config.COLORS["bg_input"],
            fg=config.COLORS["fg_text"],
            insertbackground=config.COLORS["fg_text"],
            font=("Consolas", 10),
            wrap="word",
            relief="solid",
            bd=1,
            padx=10,
            pady=10,
        )
        self.txt_inspect_output.pack(fill="both", expand=True)

        self.txt_inspect_output.insert(
            "1.0",
            "Select an IP and Port above (e.g. 80 for HTTP, 443 for HTTPS, 22 for SSH, 3306 for MySQL)\n"
            "and click 'Inspect Service' to perform deep protocol analysis and banner extraction.\n"
        )

    # =========================================================================
    # TAB 4: HELP & NMAP SETUP GUIDE
    # =========================================================================
    def _build_help_tab(self):
        container = ttk.Frame(self.tab_help_docs, style="Dark.TFrame", padding=12)
        container.pack(fill="both", expand=True)

        txt_help = tk.Text(
            container,
            bg=config.COLORS["bg_card"],
            fg=config.COLORS["fg_text"],
            font=("Segoe UI", 10),
            wrap="word",
            relief="flat",
            padx=16,
            pady=16,
        )
        txt_help.pack(fill="both", expand=True)

        guide_content = f"""
================================================================================
                      {config.APP_NAME.upper()} - USER & INSTALLATION GUIDE
================================================================================

1. OVERVIEW & FEATURES
--------------------------------------------------------------------------------
Portal Scanner is an all-in-one network discovery and security audit dashboard
built with Python, Tkinter, Socket, and Nmap.

* Port Scanning:
  - Scans TCP ports and accurately classifies states into:
    * OPEN: Connection accepted (target port is listening).
    * CLOSED: Target host actively replied with TCP RST (port is not listening).
    * FILTERED: Packets dropped by a firewall or router (no response/timeout).
  - Automatically identifies common services (HTTP, HTTPS, SSH, MySQL, FTP, DNS, etc.)
  - Performs banner grabbing & TLS certificate / HTTP header inspection.

* Network Device Discovery:
  - Sweeps local subnets (e.g. 192.168.1.0/24) to find active devices.
  - Resolves IP addresses, hostnames via reverse DNS, and MAC addresses via ARP.

* CSV Export:
  - Save all port scan results or discovered network devices into structured CSV files.

* Dual Engine Architecture:
  - Socket Engine: Pure Python native socket scanner. Requires NO external tools.
  - Nmap Engine: Integrates python-nmap for advanced service version scanning (-sV).


2. HOW TO INSTALL NMAP (OPTIONAL FOR ADVANCED SCANNING)
--------------------------------------------------------------------------------
The Socket Engine works immediately without Nmap. If you wish to use the Nmap Engine:

Windows:
  1. Open PowerShell as Administrator and run:
     winget install Insecure.Nmap
  2. OR download the official Windows installer (.exe) from:
     https://nmap.org/download.html
     (Make sure to check "Add Nmap to system PATH" during installation)

Debian / Ubuntu / Kali Linux:
  sudo apt update && sudo apt install nmap -y

macOS:
  brew install nmap


3. HOW TO USE THE DASHBOARD
--------------------------------------------------------------------------------
A. Scanning Ports:
  1. Go to the "Port Scanner" tab.
  2. Enter the target IP address or hostname (e.g. 127.0.0.1 or scanme.nmap.org).
  3. Select a port preset from the dropdown (e.g. "Common Core", "Web Servers")
     or type custom ports (e.g. "22,80,443,3306" or "1-1024").
  4. Select your engine (Socket or Nmap).
  5. Click "Start Port Scan". Results stream in real-time.
  6. Double-click any row to inspect that specific service in the Inspector tab!
  7. Click "Export CSV" to save results.

B. Discovering Network Devices:
  1. Go to the "Network Device Discovery" tab.
  2. Click "Detect My Subnet" to auto-populate your local network (e.g. 192.168.1.0/24).
  3. Click "Discover Active Devices".
  4. Once devices appear, select any row and click "Scan Selected Device Ports".


4. AUTHORIZATION & LEGAL DISCLAIMER
--------------------------------------------------------------------------------
Port scanning without authorization against systems you do not own or do not have
written permission to test may violate local laws and computer crime regulations.
Always ensure you are scanning:
  * Your own localhost (127.0.0.1)
  * Authorized lab machines or devices on your private local network
  * Permitted public test servers like scanme.nmap.org (maintained by the Nmap project)
"""
        txt_help.insert("1.0", guide_content)
        txt_help.configure(state="disabled")

    # =========================================================================
    # EVENT HANDLERS & BUSINESS LOGIC
    # =========================================================================
    def _fill_local_ip(self):
        local_ip, _ = utils.get_local_ip_and_subnet()
        self.var_target_ip.set(local_ip)

    def _detect_local_subnet(self):
        local_ip, default_subnet = utils.get_local_ip_and_subnet()
        self.var_subnet.set(default_subnet)
        self.lbl_disc_status.configure(text=f"Detected local IP: {local_ip} | Subnet: {default_subnet}")

    def _on_port_preset_selected(self, event=None):
        preset_name = self.var_port_preset.get()
        if preset_name in config.PORT_PRESETS:
            ports = config.PORT_PRESETS[preset_name]
            self.var_ports_entry.set(", ".join(str(p) for p in ports))
        elif "Range" in preset_name:
            self.var_ports_entry.set("1-1024")
        elif "List" in preset_name:
            self.var_ports_entry.set("21, 22, 25, 80, 443, 3306, 8080")

    def _apply_port_table_filter(self):
        """Filters the visible items in the port table based on checkboxes."""
        open_only = self.var_filter_open_only.get()
        # Clear treeview and re-insert according to filter
        for item in self.tree_ports.get_children():
            self.tree_ports.delete(item)

        for res in self.port_scan_results:
            if open_only and res.state != "open":
                continue
            self._insert_port_result_row(res)

    def _insert_port_result_row(self, res: PortScanResult):
        state_tag = res.state.lower()
        state_display = res.state.upper()
        self.tree_ports.insert(
            "",
            "end",
            values=(
                f"{res.port}/{res.protocol.lower()}",
                res.protocol,
                state_display,
                res.service,
                res.banner,
                f"{res.latency_ms} ms",
            ),
            tags=(state_tag,),
        )

    # -------------------------------------------------------------------------
    # Port Scanner Execution
    # -------------------------------------------------------------------------
    def _start_port_scan(self):
        target = self.var_target_ip.get().strip()
        port_input = self.var_ports_entry.get().strip()
        engine = self.var_port_engine.get()

        # Validate Target
        is_valid_tgt, resolved_ip, tgt_msg = utils.validate_ip_or_host(target)
        if not is_valid_tgt:
            messagebox.showerror("Invalid Target", tgt_msg)
            return

        # Validate Ports
        is_valid_ports, ports_list, port_msg = utils.parse_port_input(port_input)
        if not is_valid_ports:
            messagebox.showerror("Invalid Port Selection", port_msg)
            return

        # Check Nmap engine availability if requested
        if engine == "nmap":
            nmap_ok, nmap_err = is_nmap_available()
            if not nmap_ok:
                resp = messagebox.askyesno(
                    "Nmap Not Detected",
                    f"{nmap_err}\n\nWould you like to automatically switch to the native Socket Engine instead?",
                )
                if resp:
                    self.var_port_engine.set("socket")
                    engine = "socket"
                else:
                    return

        # Reset UI
        self._clear_port_results()
        self.btn_start_port_scan.configure(state="disabled")
        self.btn_stop_port_scan.configure(state="normal")
        self.progress_port.configure(maximum=len(ports_list), value=0)
        self.lbl_port_status.configure(
            text=f"Scanning {target} ({resolved_ip}) - {len(ports_list)} port(s) using {engine.upper()} engine..."
        )
        self.port_scan_start_time = time.perf_counter()

        timeout = self.var_timeout.get()
        threads = self.var_threads.get()
        only_open = self.var_filter_open_only.get()

        # Launch scanning in a dedicated background worker thread
        def worker():
            try:
                def progress_cb(res: PortScanResult, completed: int, total: int):
                    self.ui_queue.put(("port_result", res, completed, total))

                if engine == "nmap":
                    self.nmap_scanner.scan_ports(
                        target_ip=resolved_ip,
                        ports=ports_list,
                        callback=progress_cb,
                    )
                else:
                    self.socket_scanner.scan_ports(
                        target_ip=resolved_ip,
                        ports=ports_list,
                        timeout=timeout,
                        max_threads=threads,
                        callback=progress_cb,
                        only_open=only_open,
                    )

                self.ui_queue.put(("port_scan_done", None, len(ports_list), len(ports_list)))
            except Exception as e:
                self.ui_queue.put(("port_scan_error", str(e), 0, 0))

        self.active_scan_thread = threading.Thread(target=worker, daemon=True)
        self.active_scan_thread.start()

    def _stop_port_scan(self):
        self.socket_scanner.stop()
        self.nmap_scanner.stop()
        self.lbl_port_status.configure(text="Stopping scan... waiting for active threads to complete.")
        self.btn_stop_port_scan.configure(state="disabled")

    def _clear_port_results(self):
        for item in self.tree_ports.get_children():
            self.tree_ports.delete(item)
        self.port_scan_results.clear()
        self.count_open = 0
        self.count_closed = 0
        self.count_filtered = 0
        self._update_port_stat_labels(0.0)
        self.progress_port.configure(value=0)
        self.lbl_port_status.configure(text="Results cleared.")

    def _update_port_stat_labels(self, elapsed_sec: float):
        total = len(self.port_scan_results)
        self.lbl_stat_total.configure(text=f"Total Ports: {total}")
        self.lbl_stat_open.configure(text=f"OPEN: {self.count_open}")
        self.lbl_stat_closed.configure(text=f"CLOSED: {self.count_closed}")
        self.lbl_stat_filtered.configure(text=f"FILTERED: {self.count_filtered}")
        self.lbl_stat_time.configure(text=f"Duration: {elapsed_sec:.1f}s")

    def _export_port_results_csv(self):
        if not self.port_scan_results:
            messagebox.showinfo("Export CSV", "No scan results available to export.")
            return

        default_name = f"port_scan_{self.var_target_ip.get()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=default_name,
            title="Save Port Scan Results As CSV",
        )
        if not filepath:
            return

        headers = ["Target", "Port", "Protocol", "State", "Service", "Banner/Version", "Latency (ms)", "Timestamp"]
        rows = [
            [
                r.target,
                r.port,
                r.protocol,
                r.state.upper(),
                r.service,
                r.banner,
                r.latency_ms,
                r.timestamp,
            ]
            for r in self.port_scan_results
        ]

        ok, msg = utils.export_to_csv(filepath, headers, rows)
        if ok:
            messagebox.showinfo("Export Succeeded", msg)
        else:
            messagebox.showerror("Export Error", msg)

    # -------------------------------------------------------------------------
    # Network Device Discovery Execution
    # -------------------------------------------------------------------------
    def _start_network_discovery(self):
        subnet_str = self.var_subnet.get().strip()
        engine = self.var_discovery_engine.get()

        valid, ip_list, msg = utils.validate_subnet_or_cidr(subnet_str)
        if not valid:
            messagebox.showerror("Invalid Subnet", msg)
            return

        # Clear existing
        for item in self.tree_devices.get_children():
            self.tree_devices.delete(item)
        self.device_scan_results.clear()

        self.btn_start_disc.configure(state="disabled")
        self.btn_stop_disc.configure(state="normal")
        self.progress_disc.configure(maximum=len(ip_list), value=0)
        self.lbl_disc_hosts.configure(text="Probed Hosts: 0")
        self.lbl_disc_active.configure(text="ACTIVE DEVICES: 0")
        self.discovery_start_time = time.perf_counter()

        self.lbl_disc_status.configure(
            text=f"Discovering active hosts in {subnet_str} ({len(ip_list)} addresses)..."
        )

        max_threads = self.var_disc_threads.get()

        def worker():
            try:
                def progress_cb(dev: Optional[DeviceResult], completed: int, total: int):
                    self.ui_queue.put(("device_result", dev, completed, total))

                self.network_discoverer.discover(
                    subnet_input=subnet_str,
                    engine=engine,
                    timeout=0.45,
                    max_threads=max_threads,
                    callback=progress_cb,
                )
                self.ui_queue.put(("device_scan_done", None, len(ip_list), len(ip_list)))
            except Exception as e:
                self.ui_queue.put(("device_scan_error", str(e), 0, 0))

        self.active_discovery_thread = threading.Thread(target=worker, daemon=True)
        self.active_discovery_thread.start()

    def _stop_network_discovery(self):
        self.network_discoverer.stop()
        self.lbl_disc_status.configure(text="Stopping device discovery...")
        self.btn_stop_disc.configure(state="disabled")

    def _send_device_to_port_scanner(self):
        selected = self.tree_devices.selection()
        if not selected:
            messagebox.showinfo("Select Device", "Please click on a discovered device in the table first.")
            return

        item = self.tree_devices.item(selected[0])
        device_ip = item["values"][0]
        self.var_target_ip.set(device_ip)
        # Switch notebook to Port Scanner tab
        self.notebook.select(self.tab_port_scanner)
        self.lbl_port_status.configure(
            text=f"Selected {device_ip} from discovery. Choose ports and click 'Start Port Scan'."
        )

    def _export_device_results_csv(self):
        if not self.device_scan_results:
            messagebox.showinfo("Export CSV", "No discovered devices to export.")
            return

        default_name = f"network_devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=default_name,
            title="Save Discovered Network Devices As CSV",
        )
        if not filepath:
            return

        headers = ["IP Address", "Hostname", "MAC Address", "Status", "Latency (ms)", "Discovered At"]
        rows = [
            [d.ip, d.hostname, d.mac, d.status, d.latency_ms, d.timestamp]
            for d in self.device_scan_results
        ]

        ok, msg = utils.export_to_csv(filepath, headers, rows)
        if ok:
            messagebox.showinfo("Export Succeeded", msg)
        else:
            messagebox.showerror("Export Error", msg)

    # -------------------------------------------------------------------------
    # Deep Service Inspector Execution
    # -------------------------------------------------------------------------
    def _run_deep_service_inspection(self):
        target = self.var_inspect_ip.get().strip()
        try:
            port = int(self.var_inspect_port.get())
        except ValueError:
            messagebox.showerror("Invalid Port", "Port must be a valid integer between 1 and 65535.")
            return

        is_valid, resolved_ip, msg = utils.validate_ip_or_host(target)
        if not is_valid:
            messagebox.showerror("Invalid Target", msg)
            return

        self.txt_inspect_output.delete("1.0", "end")
        self.txt_inspect_output.insert("1.0", f"[*] Probing {target} ({resolved_ip}) on TCP port {port}...\n")
        self.root.update_idletasks()

        def worker():
            lines = []
            lines.append(f"Inspection Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"Target: {target} (Resolved: {resolved_ip})")
            lines.append(f"Port: {port}/tcp")

            svc_name, svc_desc = utils.resolve_service_name(port)
            lines.append(f"Standard Service Name: {svc_name}")
            lines.append(f"Standard Description: {svc_desc}")
            lines.append("-" * 70)

            # Test connectivity
            scan_res = self.socket_scanner.scan_port(resolved_ip, port, timeout=2.0, grab_banners=True)
            lines.append(f"Port State: {scan_res.state.upper()}")
            lines.append(f"Connection Latency: {scan_res.latency_ms:.2f} ms")
            lines.append(f"Initial Banner: {scan_res.banner}")
            lines.append("-" * 70)

            if scan_res.state == "open":
                lines.append("[+] Port is OPEN! Inspecting service payload and protocol handshake...\n")

                if port in (80, 8080, 8000, 3000, 5000, 8888):
                    lines.append("--- HTTP Protocol Inspection ---")
                    try:
                        import socket
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(2.0)
                        s.connect((resolved_ip, port))
                        req = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: PortalScanner/1.0\r\nConnection: close\r\n\r\n"
                        s.sendall(req.encode("ascii"))
                        resp = s.recv(2048).decode("utf-8", errors="replace")
                        s.close()
                        lines.append(resp.strip())
                    except Exception as e:
                        lines.append(f"HTTP Probe Error: {e}")

                elif port in (443, 8443):
                    lines.append("--- TLS / SSL Certificate Inspection ---")
                    try:
                        import socket, ssl
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        with socket.create_connection((resolved_ip, port), timeout=2.5) as sock:
                            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                                cert = ssock.getpeercert(binary_form=False)
                                cipher = ssock.cipher()
                                lines.append(f"TLS Protocol Version: {ssock.version()}")
                                lines.append(f"Cipher Suite: {cipher[0]} ({cipher[1]}, {cipher[2]} bits)")
                                if cert:
                                    lines.append(f"Subject: {cert.get('subject')}")
                                    lines.append(f"Issuer: {cert.get('issuer')}")
                                    lines.append(f"Not Before: {cert.get('notBefore')}")
                                    lines.append(f"Not After: {cert.get('notAfter')}")
                                else:
                                    lines.append("Self-signed or unverified certificate returned.")
                    except Exception as e:
                        lines.append(f"TLS Inspection Error: {e}")

                elif port == 3306:
                    lines.append("--- MySQL / MariaDB Handshake Packet Analysis ---")
                    try:
                        import socket
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(2.0)
                        s.connect((resolved_ip, port))
                        raw = s.recv(1024)
                        s.close()
                        lines.append(f"Packet Length: {len(raw)} bytes")
                        lines.append(f"Raw Hex: {raw[:32].hex()}")
                        parsed = utils.parse_mysql_handshake(raw)
                        lines.append(f"Parsed Version: {parsed}")
                    except Exception as e:
                        lines.append(f"MySQL Analysis Error: {e}")

                elif port == 22:
                    lines.append("--- SSH Version Exchange ---")
                    try:
                        import socket
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(2.0)
                        s.connect((resolved_ip, port))
                        banner = s.recv(512).decode("utf-8", errors="replace").strip()
                        s.close()
                        lines.append(f"SSH Identification String: {banner}")
                    except Exception as e:
                        lines.append(f"SSH Banner Error: {e}")

            elif scan_res.state == "closed":
                lines.append("[!] Target sent TCP RST (Connection Refused). The host is online, but no service is bound to this port.")
            elif scan_res.state == "filtered":
                lines.append("[!] Probe timed out with no response. Packets are likely being dropped by a stateful firewall or network filter.")

            self.ui_queue.put(("inspect_result", "\n".join(lines), 0, 0))

        threading.Thread(target=worker, daemon=True).start()

    def _on_port_row_double_click(self, event):
        selected = self.tree_ports.selection()
        if not selected:
            return
        item = self.tree_ports.item(selected[0])
        val = item["values"]
        port_raw = str(val[0]).split("/")[0]
        try:
            p = int(port_raw)
            self.var_inspect_ip.set(self.var_target_ip.get())
            self.var_inspect_port.set(p)
            self.notebook.select(self.tab_service_inspector)
            self._run_deep_service_inspection()
        except ValueError:
            pass

    # -------------------------------------------------------------------------
    # Thread-Safe UI Queue Processor
    # -------------------------------------------------------------------------
    def _process_ui_queue(self):
        """Processes pending updates from background threads safely on the main Tkinter thread."""
        try:
            while not self.ui_queue.empty():
                msg_type, data, completed, total = self.ui_queue.get_nowait()

                if msg_type == "port_result":
                    res: PortScanResult = data
                    self.port_scan_results.append(res)
                    if res.state == "open":
                        self.count_open += 1
                    elif res.state == "closed":
                        self.count_closed += 1
                    elif res.state == "filtered":
                        self.count_filtered += 1

                    # Only insert into table if filter condition allows
                    if not self.var_filter_open_only.get() or res.state == "open":
                        self._insert_port_result_row(res)

                    self.progress_port.configure(value=completed)
                    elapsed = time.perf_counter() - self.port_scan_start_time
                    self._update_port_stat_labels(elapsed)
                    self.lbl_port_status.configure(
                        text=f"Scanning port {res.port} ({completed}/{total}) - Found: {self.count_open} Open, {self.count_closed} Closed, {self.count_filtered} Filtered"
                    )

                elif msg_type == "port_scan_done":
                    elapsed = time.perf_counter() - self.port_scan_start_time
                    self.btn_start_port_scan.configure(state="normal")
                    self.btn_stop_port_scan.configure(state="disabled")
                    self.progress_port.configure(value=total)
                    self._update_port_stat_labels(elapsed)
                    self.lbl_port_status.configure(
                        text=f"Scan completed in {elapsed:.2f}s. Total: {len(self.port_scan_results)} ports | Open: {self.count_open} | Closed: {self.count_closed} | Filtered: {self.count_filtered}"
                    )

                elif msg_type == "port_scan_error":
                    self.btn_start_port_scan.configure(state="normal")
                    self.btn_stop_port_scan.configure(state="disabled")
                    self.lbl_port_status.configure(text=f"Scan error: {data}")
                    messagebox.showerror("Scan Error", f"An error occurred during port scanning:\n{data}")

                elif msg_type == "device_result":
                    dev: Optional[DeviceResult] = data
                    if dev:
                        self.device_scan_results.append(dev)
                        self.tree_devices.insert(
                            "",
                            "end",
                            values=(
                                dev.ip,
                                dev.hostname,
                                dev.mac,
                                dev.status,
                                f"{dev.latency_ms} ms",
                                dev.timestamp,
                            ),
                            tags=("online",),
                        )
                        self.lbl_disc_active.configure(text=f"ACTIVE DEVICES: {len(self.device_scan_results)}")

                    self.progress_disc.configure(value=completed)
                    elapsed = time.perf_counter() - self.discovery_start_time
                    self.lbl_disc_hosts.configure(text=f"Probed Hosts: {completed}/{total}")
                    self.lbl_disc_time.configure(text=f"Duration: {elapsed:.1f}s")
                    self.lbl_disc_status.configure(
                        text=f"Sweeping subnet... Probed {completed}/{total} hosts. Active found: {len(self.device_scan_results)}"
                    )

                elif msg_type == "device_scan_done":
                    elapsed = time.perf_counter() - self.discovery_start_time
                    self.btn_start_disc.configure(state="normal")
                    self.btn_stop_disc.configure(state="disabled")
                    self.progress_disc.configure(value=total)
                    self.lbl_disc_time.configure(text=f"Duration: {elapsed:.1f}s")
                    self.lbl_disc_status.configure(
                        text=f"Discovery completed in {elapsed:.2f}s. Discovered {len(self.device_scan_results)} active device(s)."
                    )

                elif msg_type == "device_scan_error":
                    self.btn_start_disc.configure(state="normal")
                    self.btn_stop_disc.configure(state="disabled")
                    self.lbl_disc_status.configure(text=f"Discovery error: {data}")
                    messagebox.showerror("Discovery Error", f"An error occurred during network discovery:\n{data}")

                elif msg_type == "inspect_result":
                    self.txt_inspect_output.delete("1.0", "end")
                    self.txt_inspect_output.insert("1.0", data)

        except Exception:
            pass
        finally:
            self.root.after(40, self._process_ui_queue)

    def _on_close(self):
        """Clean shutdown handler."""
        try:
            self.socket_scanner.stop()
            self.nmap_scanner.stop()
            self.network_discoverer.stop()
        except Exception:
            pass
        self.root.destroy()

