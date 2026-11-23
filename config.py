"""
config.py - Configuration constants, service mappings, UI themes, and presets.
"""

# Application Metadata
APP_NAME = "Portal Scanner"
APP_SUBTITLE = "Network Device Discovery & Port Security Audit Dashboard"
APP_VERSION = "1.0.0"

# Common Well-Known Service Ports Dictionary
# Maps port number (int) -> Service dictionary
COMMON_SERVICES = {
    20: {"name": "FTP-DATA", "protocol": "TCP", "description": "File Transfer Protocol (Data Transfer)"},
    21: {"name": "FTP", "protocol": "TCP", "description": "File Transfer Protocol (Control/Authentication)"},
    22: {"name": "SSH", "protocol": "TCP", "description": "Secure Shell - Encrypted remote login & commands"},
    23: {"name": "Telnet", "protocol": "TCP", "description": "Telnet - Unencrypted text communications"},
    25: {"name": "SMTP", "protocol": "TCP", "description": "Simple Mail Transfer Protocol (Email routing)"},
    53: {"name": "DNS", "protocol": "TCP/UDP", "description": "Domain Name System (Name resolution)"},
    67: {"name": "DHCP", "protocol": "UDP", "description": "Dynamic Host Configuration Protocol (Server)"},
    68: {"name": "DHCP", "protocol": "UDP", "description": "Dynamic Host Configuration Protocol (Client)"},
    69: {"name": "TFTP", "protocol": "UDP", "description": "Trivial File Transfer Protocol"},
    80: {"name": "HTTP", "protocol": "TCP", "description": "Hypertext Transfer Protocol (Cleartext Web Server)"},
    88: {"name": "Kerberos", "protocol": "TCP/UDP", "description": "Kerberos Authentication System"},
    110: {"name": "POP3", "protocol": "TCP", "description": "Post Office Protocol v3 (Email retrieval)"},
    123: {"name": "NTP", "protocol": "UDP", "description": "Network Time Protocol (Clock synchronization)"},
    135: {"name": "MS-RPC", "protocol": "TCP", "description": "Microsoft RPC Endpoint Mapper"},
    139: {"name": "NetBIOS-SSN", "protocol": "TCP", "description": "NetBIOS Session Service (Windows file sharing)"},
    143: {"name": "IMAP", "protocol": "TCP", "description": "Internet Message Access Protocol (Email)"},
    161: {"name": "SNMP", "protocol": "UDP", "description": "Simple Network Management Protocol"},
    389: {"name": "LDAP", "protocol": "TCP", "description": "Lightweight Directory Access Protocol (Active Directory)"},
    443: {"name": "HTTPS", "protocol": "TCP", "description": "HTTP Secure (TLS/SSL Encrypted Web Traffic)"},
    445: {"name": "SMB", "protocol": "TCP", "description": "Server Message Block (Windows SMB / Samba File Sharing)"},
    465: {"name": "SMTPS", "protocol": "TCP", "description": "Secure SMTP over SSL"},
    514: {"name": "Syslog", "protocol": "UDP", "description": "System Logging Protocol"},
    587: {"name": "SMTP-Submission", "protocol": "TCP", "description": "Email Message Submission"},
    636: {"name": "LDAPS", "protocol": "TCP", "description": "LDAP over SSL/TLS"},
    993: {"name": "IMAPS", "protocol": "TCP", "description": "IMAP over SSL/TLS"},
    995: {"name": "POP3S", "protocol": "TCP", "description": "POP3 over SSL/TLS"},
    1433: {"name": "MS-SQL", "protocol": "TCP", "description": "Microsoft SQL Server Database Engine"},
    1521: {"name": "Oracle-DB", "protocol": "TCP", "description": "Oracle Database Listener"},
    1723: {"name": "PPTP", "protocol": "TCP", "description": "Point-to-Point Tunneling Protocol (VPN)"},
    2049: {"name": "NFS", "protocol": "TCP", "description": "Network File System"},
    3000: {"name": "Node/React/Grafana", "protocol": "TCP", "description": "Common Dev Web Server & Grafana"},
    3306: {"name": "MySQL", "protocol": "TCP", "description": "MySQL / MariaDB Relational Database Management System"},
    3389: {"name": "RDP", "protocol": "TCP", "description": "Remote Desktop Protocol (Windows Remote Desktop)"},
    5000: {"name": "Flask/Dev", "protocol": "TCP", "description": "Python Flask Development Web Server / Docker Registry"},
    5432: {"name": "PostgreSQL", "protocol": "TCP", "description": "PostgreSQL Object-Relational Database System"},
    5900: {"name": "VNC", "protocol": "TCP", "description": "Virtual Network Computing (Remote Screen Sharing)"},
    6379: {"name": "Redis", "protocol": "TCP", "description": "Redis In-Memory Key-Value Data Store"},
    8000: {"name": "HTTP-Alt/Django", "protocol": "TCP", "description": "Alternative HTTP / Django Dev Server"},
    8080: {"name": "HTTP-Proxy/Tomcat", "protocol": "TCP", "description": "HTTP Alternative / Apache Tomcat / Jenkins"},
    8443: {"name": "HTTPS-Alt", "protocol": "TCP", "description": "Alternative HTTPS / Tomcat SSL"},
    8888: {"name": "Jupyter/HTTP-Alt", "protocol": "TCP", "description": "Jupyter Notebook / Alternative HTTP Server"},
    9090: {"name": "Prometheus/Cockpit", "protocol": "TCP", "description": "Prometheus Metrics / Linux Cockpit"},
    9200: {"name": "Elasticsearch", "protocol": "TCP", "description": "Elasticsearch REST API Search Engine"},
    27017: {"name": "MongoDB", "protocol": "TCP", "description": "MongoDB NoSQL Document Database"},
}

# Port Presets for Easy Selection in GUI
PORT_PRESETS = {
    "Common Core (10 ports)": [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389],
    "Web Servers (HTTP/HTTPS)": [80, 443, 3000, 5000, 8000, 8080, 8443, 8888],
    "Databases (SQL & NoSQL)": [1433, 1521, 3306, 5432, 6379, 27017],
    "Remote Access & Admin": [22, 23, 135, 139, 445, 3389, 5900],
    "Email Protocols": [25, 110, 143, 465, 587, 993, 995],
    "Top 20 Most Frequent": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
    "Top 50 Common Ports": [
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123, 135, 137, 138, 139, 143,
        161, 389, 443, 445, 465, 514, 587, 636, 993, 995, 1080, 1433, 1521, 1723,
        2049, 3000, 3128, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8080, 8443, 8888,
        9090, 9200, 9418, 27017, 50000
    ],
}

# Scan Configuration Defaults
DEFAULT_TIMEOUT = 1.0        # Seconds per socket attempt
DEFAULT_THREADS = 40         # Concurrent threads for port scanning
DEFAULT_DISCOVERY_THREADS = 60 # Concurrent threads for subnet sweep
MIN_PORT = 1
MAX_PORT = 65535

# Color Palette (Modern Dark Theme)
COLORS = {
    "bg_dark": "#0f172a",        # Slate 900
    "bg_card": "#1e293b",        # Slate 800
    "bg_card_alt": "#334155",    # Slate 700
    "bg_input": "#0b1220",       # Slate 950
    "fg_text": "#f8fafc",        # Slate 50
    "fg_muted": "#94a3b8",       # Slate 400
    "accent_primary": "#38bdf8", # Sky 400
    "accent_hover": "#0ea5e9",   # Sky 500
    "accent_active": "#0284c7",  # Sky 600
    "state_open": "#22c55e",     # Green 500 (Open port)
    "state_closed": "#ef4444",   # Red 500 (Closed port)
    "state_filtered": "#f59e0b", # Amber 500 (Filtered port)
    "state_open_bg": "#052e16",  # Very dark green
    "state_closed_bg": "#450a0a",# Very dark red
    "state_filtered_bg": "#451a03", # Very dark amber
    "border": "#475569",         # Slate 600
    "btn_green": "#16a34a",
    "btn_red": "#dc2626",
    "btn_gray": "#4b5563"
}

# Sample / Safe Scan Targets for Quick Testing
SAMPLE_TARGETS = [
    {"label": "127.0.0.1 (Localhost)", "target": "127.0.0.1"},
    {"label": "scanme.nmap.org (Authorized Nmap Test Host)", "target": "scanme.nmap.org"},
]

# Nmap Installation Guide Links and Commands
NMAP_INSTALL_INFO = {
    "windows": [
        "1. Using Windows Package Manager (winget):",
        "   Run in PowerShell/Terminal: winget install Insecure.Nmap",
        "2. Using Chocolatey:",
        "   Run: choco install nmap",
        "3. Official Installer Download:",
        "   Visit https://nmap.org/download.html and run the Windows installer (.exe).",
        "   Ensure 'Add to PATH' option is checked during installation."
    ],
    "linux": [
        "Debian / Ubuntu / Kali / Mint:",
        "   sudo apt update && sudo apt install nmap -y",
        "Fedora / RHEL / CentOS:",
        "   sudo dnf install nmap -y",
        "Arch Linux:",
        "   sudo pacman -S nmap"
    ],
    "macos": [
        "Using Homebrew:",
        "   brew install nmap"
    ]
}

