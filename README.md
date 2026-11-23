# Portal Scanner - Network Device Discovery & Port Security Audit Tool

A modern, multi-threaded GUI network scanner built with **Python**, **Socket**, **Nmap**, and **Tkinter**. Portal Scanner allows cybersecurity students, system administrators, and network engineers to discover active devices on local subnets, scan open/closed/filtered TCP ports on authorized targets, identify common services (such as HTTP, HTTPS, SSH, MySQL), and export structured audit reports to CSV files.

---

## 🚀 Key Features

- **Port State Classification**:
  - **OPEN**: Target accepted TCP 3-way handshake; service is listening.
  - **CLOSED**: Target actively responded with a TCP RST (connection refused); host is online but no service is listening on that port.
  - **FILTERED**: Target did not respond or connection timed out; packets are being dropped by a stateful firewall or network filter.
- **Local Network Device Discovery**:
  - Sweeps local subnets (e.g., `192.168.1.0/24` or user-defined IP ranges).
  - Automatically identifies active IP addresses, hostnames (reverse DNS), MAC hardware addresses (ARP), and connection latency.
  - Single-click action to transfer any discovered IP directly into the Port Scanner.
- **Service Identification & Banner Grabbing**:
  - Identifies standard services including **HTTP** (80, 8080), **HTTPS** (443, 8443), **SSH** (22), **MySQL** (3306), **FTP** (21), **Telnet** (23), **SMTP** (25, 587), **DNS** (53), **RDP** (3389), **PostgreSQL** (5432), and **Redis** (6379).
  - Performs banner grabbing, HTTP server header extraction, SSL/TLS certificate inspection, and MySQL handshake packet version decoding.
- **Dual Engine Architecture**:
  - **Socket Engine (Native Python)**: 100% self-contained multi-threaded scanner requiring **no external software installation**. Works out of the box on Windows, macOS, and Linux.
  - **Nmap Engine**: Seamlessly integrates with Nmap (`python-nmap`) for advanced service version scanning (`-sV`) and ping sweep (`-sn`) when Nmap is installed.
- **Intuitive GUI Dashboard**:
  - Modern dark slate aesthetic built with `tkinter` and `ttk`.
  - Color-coded results (Emerald Green for Open, Crimson Red for Closed, Amber Yellow for Filtered).
  - Real-time statistics counters, smooth progress bars, and responsive background threads (GUI never freezes).
  - Separate sections/tabs for Port Scanning, Network Device Discovery, Service Inspector, and Help & Setup.
- **CSV Export**:
  - One-click export for both Port Scan results and Discovered Network Devices to timestamped CSV files.
- **Input Validation & Error Handling**:
  - Comprehensive regex and `ipaddress` validation for IPv4 addresses, domain names, CIDR subnets, and port ranges (`1-1024`, `22, 80, 443`).

---

## 📁 Project Structure

```
c:\Portals\
│
├── main.py                  # Main entry point; initializes Tkinter dashboard
├── config.py                # Configuration constants, common port map, UI colors, presets
├── utils.py                 # Network validation, ARP cache lookup, banner grabbers, CSV export
├── scanner_socket.py        # Native Python multi-threaded socket scanner (Open/Closed/Filtered)
├── scanner_nmap.py          # Nmap wrapper using python-nmap with fallback and error handling
├── network_discovery.py     # Subnet device discovery engine (TCP probe, Ping, ARP)
├── gui.py                   # Complete Tkinter GUI layout, tabs, widgets, and thread-safe queue
├── test_scanner.py          # Unit test suite verifying scanner and utility functions
├── requirements.txt         # Project dependencies (python-nmap)
└── README.md                # Project documentation and user guide
```

---

## 🛠️ Prerequisites & Installation

### 1. Requirements
- **Python 3.8 or higher** (Python 3.10+ recommended)
- **Tkinter** (included by default with standard Python installations on Windows and macOS)
- Standard operating systems: Windows 10/11, Ubuntu/Debian/Kali Linux, or macOS

### 2. Install Python Dependencies
Open your terminal or PowerShell in the project directory (`c:\Portals`) and run:

```bash
pip install -r requirements.txt
```

*(Note: The only external dependency is `python-nmap`)*

### 3. (Optional) Install Nmap for Advanced Scanning
The **Socket Engine** works completely out of the box with zero external dependencies. If you wish to use the **Nmap Engine** for deep service version fingerprinting (`-sV`):

- **Windows**:
  - Using Windows Package Manager (PowerShell):
    ```powershell
    winget install Insecure.Nmap
    ```
  - Or download and run the official Windows installer from:
    [https://nmap.org/download.html](https://nmap.org/download.html)  
    *(Ensure the "Add Nmap to system PATH" checkbox is selected)*
- **Ubuntu / Debian / Kali Linux**:
  ```bash
  sudo apt update && sudo apt install nmap -y
  ```
- **macOS (Homebrew)**:
  ```bash
  brew install nmap
  ```

---

## 🖥️ Running the Application

Launch the application by running:

```bash
python main.py
```

The GUI window will open with the modern dashboard.

---

## 📖 Feature Walkthrough & Usage Guide

### Section 1: Port Scanner
1. **Target Address**: Enter an authorized target IP (e.g. `127.0.0.1`) or hostname (e.g. `scanme.nmap.org`). You can also click the quick buttons (`Localhost`, `scanme.nmap.org`, or `My LAN IP`).
2. **Engine Selection**:
   - Choose **Socket (Native)** for instant, multi-threaded scanning without external dependencies.
   - Choose **Nmap (-sV)** for deep Nmap service version detection.
3. **Port Selection**:
   - Pick a preset from the dropdown (e.g. *Common Core (10 ports)*, *Web Servers*, *Databases*, *Top 20*, or *Top 50*).
   - Or type custom ports directly in the entry box:
     - Single port: `80`
     - Comma-separated: `22, 80, 443, 3306, 8080`
     - Range: `1-1024`
     - Combined: `21-25, 80, 443, 3306, 8000-8080`
4. **Scan Tuning**:
   - Set thread concurrency (default: 40 threads).
   - Set connection timeout in seconds (default: 1.0s).
   - Toggle **Show Open Ports Only** if you wish to hide closed and filtered ports.
5. **Start Scan**: Click **Start Port Scan**. Results will stream into the table in real-time.
6. **Inspect Service**: Double-click any row in the results table to automatically open that port in the **Service Inspector** tab.
7. **Export CSV**: Click **Export CSV** to save the results to a file.

### Section 2: Network Device Discovery
1. **Target Subnet**: Click **Detect My Subnet** to automatically discover your local network interface (e.g. `192.168.1.0/24` or `10.0.0.0/24`), or type a custom CIDR / IP range (e.g. `192.168.1.1-192.168.1.50`).
2. **Method**: Choose between native TCP/Ping/ARP sweep or Nmap Ping Scan (`-sn`).
3. **Discover Active Devices**: Click **Discover Active Devices**. The dashboard sweeps the network and displays:
   - IP Address
   - Hostname (via Reverse DNS)
   - MAC Address (via system ARP table)
   - Online Status and Response Latency
4. **Scan Selected Device**: Click any discovered device in the table and press **Scan Selected Device Ports** to instantly transfer its IP to the Port Scanner tab.
5. **Export CSV**: Click **Export CSV** to save discovered active devices.

### Section 3: Deep Service Inspector
- Enter a Target IP and Port (e.g. 80, 443, 22, 3306).
- Click **Inspect Service** to perform detailed protocol interrogation:
  - **HTTP (80/8080)**: Performs `HEAD` request and displays HTTP status and Server headers.
  - **HTTPS (443/8443)**: Performs TLS handshake and inspects SSL certificate (Issuer, Subject, Expiry, Cipher Suite, TLS protocol version).
  - **SSH (22)**: Reads raw SSH server identification banner.
  - **MySQL (3306)**: Analyzes initial handshake packet and extracts exact MySQL/MariaDB server version and protocol version.

### Section 4: Help & Nmap Setup
- Embedded documentation containing installation commands for Nmap, port definitions, and security guidelines.

---

## 🧪 Running Unit Tests

The project includes unit and integration tests covering IP validation, port parsing, subnet validation, MySQL handshake parsing, service resolution, socket scanning, and CSV export.

To run the test suite:

```bash
python test_scanner.py
```

Expected output:
```
Ran 9 tests in 0.14s
OK
```

---

## 🔒 Legal & Ethical Notice

> [!IMPORTANT]
> **Port scanning and network probing should only be performed on networks and systems that you own or where you have received explicit, written authorization from the owner.**
>
> Unauthorized port scanning may violate local, national, or international computer crime legislation (such as the CFAA in the United States, the Computer Misuse Act in the UK, or equivalent laws in other jurisdictions).
>
> For testing and educational practice, use:
> - Your local loopback interface: `127.0.0.1` (`localhost`)
> - Local virtual machines (e.g., VirtualBox / VMware / Docker containers)
> - Authorized testing targets such as `scanme.nmap.org` (maintained by the Nmap Project for authorized test scans).

