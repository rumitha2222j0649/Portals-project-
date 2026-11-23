"""
utils.py - Networking helper functions, IP/Port validation, banner grabbing, and CSV export.
"""

import csv
import ipaddress
import re
import socket
import ssl
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

import config


def validate_ip_or_host(target: str) -> Tuple[bool, str, str]:
    """
    Validates an IPv4 address or hostname. Resolves hostnames to IPv4.
    Returns: (is_valid, resolved_ip, message)
    """
    target = target.strip()
    if not target:
        return False, "", "Target address cannot be empty."

    # Check if target is a valid IPv4 address directly
    try:
        ip_obj = ipaddress.IPv4Address(target)
        return True, str(ip_obj), f"Valid IPv4 address: {ip_obj}"
    except ipaddress.AddressValueError:
        pass

    # Validate hostname syntax
    hostname_regex = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
    )
    if not hostname_regex.match(target):
        return False, "", f"'{target}' is neither a valid IPv4 address nor a valid hostname."

    # Try resolving hostname to IPv4
    try:
        resolved_ip = socket.gethostbyname(target)
        return True, resolved_ip, f"Resolved '{target}' to {resolved_ip}"
    except socket.gaierror as e:
        return False, "", f"Could not resolve hostname '{target}': {e}"
    except Exception as e:
        return False, "", f"Error resolving '{target}': {e}"


def parse_port_input(port_input: str) -> Tuple[bool, List[int], str]:
    """
    Parses a string containing ports, port ranges, and comma-separated lists.
    Examples:
      - "80"
      - "80, 443, 3306"
      - "1-1024"
      - "22, 80-90, 443, 8000-8080"
    Returns: (is_valid, sorted_unique_ports, error_message)
    """
    cleaned = port_input.strip()
    if not cleaned:
        return False, [], "Port input cannot be empty."

    ports_set = set()
    tokens = [t.strip() for t in cleaned.split(",") if t.strip()]

    if not tokens:
        return False, [], "No valid ports specified."

    for token in tokens:
        if "-" in token:
            # Handle range (e.g. "80-100")
            parts = token.split("-")
            if len(parts) != 2:
                return False, [], f"Invalid range format in '{token}'. Use 'start-end'."
            try:
                start_p = int(parts[0].strip())
                end_p = int(parts[1].strip())
            except ValueError:
                return False, [], f"Range values must be integers in '{token}'."

            if start_p > end_p:
                start_p, end_p = end_p, start_p

            if start_p < config.MIN_PORT or end_p > config.MAX_PORT:
                return (
                    False,
                    [],
                    f"Port range {start_p}-{end_p} out of bounds ({config.MIN_PORT}-{config.MAX_PORT}).",
                )

            # Limit single range expansion to avoid accidental memory exhaustion
            if (end_p - start_p) > 10000:
                return False, [], f"Range '{token}' spans more than 10,000 ports. Please narrow the range."

            for p in range(start_p, end_p + 1):
                ports_set.add(p)
        else:
            # Single port
            try:
                p = int(token)
            except ValueError:
                return False, [], f"Invalid port value: '{token}' is not an integer."

            if p < config.MIN_PORT or p > config.MAX_PORT:
                return (
                    False,
                    [],
                    f"Port {p} is out of valid range ({config.MIN_PORT}-{config.MAX_PORT}).",
                )
            ports_set.add(p)

    sorted_ports = sorted(list(ports_set))
    return True, sorted_ports, f"Parsed {len(sorted_ports)} unique port(s)."


def validate_subnet_or_cidr(subnet_str: str) -> Tuple[bool, List[str], str]:
    """
    Validates a CIDR network (e.g. '192.168.1.0/24') or IP range ('192.168.1.1-192.168.1.50').
    Returns: (is_valid, list_of_ip_strings, message)
    """
    cleaned = subnet_str.strip()
    if not cleaned:
        return False, [], "Subnet cannot be empty."

    # Check IP range format e.g. "192.168.1.1-192.168.1.50"
    if "-" in cleaned and "/" not in cleaned:
        parts = cleaned.split("-")
        if len(parts) == 2:
            try:
                start_ip = ipaddress.IPv4Address(parts[0].strip())
                end_ip = ipaddress.IPv4Address(parts[1].strip())
                if int(start_ip) > int(end_ip):
                    start_ip, end_ip = end_ip, start_ip

                count = int(end_ip) - int(start_ip) + 1
                if count > 512:
                    return False, [], f"Range includes {count} hosts. Maximum allowed is 512 for subnet scan."

                ip_list = [str(ipaddress.IPv4Address(ip_int)) for ip_int in range(int(start_ip), int(end_ip) + 1)]
                return True, ip_list, f"Range with {len(ip_list)} host addresses."
            except ipaddress.AddressValueError:
                pass

    # Check CIDR format e.g. "192.168.1.0/24"
    try:
        network = ipaddress.ip_network(cleaned, strict=False)
        # Limit to /24 (256 addresses) or smaller to keep discovery fast and responsive
        if network.num_addresses > 512:
            return (
                False,
                [],
                f"Subnet {cleaned} contains {network.num_addresses} addresses. "
                "Please specify a /24 (e.g. 192.168.1.0/24) or smaller network.",
            )

        # Skip network address and broadcast address for standard host lists if > 2 addresses
        if network.num_addresses > 2:
            ip_list = [str(host) for host in network.hosts()]
        else:
            ip_list = [str(host) for host in network]

        return True, ip_list, f"Subnet {network} ({len(ip_list)} usable host IPs)."
    except ValueError as e:
        return False, [], f"Invalid CIDR notation '{cleaned}': {e}"


def get_local_ip_and_subnet() -> Tuple[str, str]:
    """
    Detects the machine's primary active local IP and default /24 subnet.
    Returns: (local_ip, default_subnet_cidr)
    """
    local_ip = "127.0.0.1"
    try:
        # Establish a dummy UDP socket to find the outbound routing interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        # Connect to a public DNS IP (doesn't send actual packets on UDP connect)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = "127.0.0.1"

    # Compute default /24 subnet
    if local_ip != "127.0.0.1":
        parts = local_ip.split(".")
        if len(parts) == 4:
            default_subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            return local_ip, default_subnet

    return local_ip, "192.168.1.0/24"


def resolve_service_name(port: int, protocol: str = "tcp") -> Tuple[str, str]:
    """
    Returns (service_name, description) for a given port.
    """
    if port in config.COMMON_SERVICES:
        entry = config.COMMON_SERVICES[port]
        return entry["name"], entry["description"]

    # Fall back to system's /etc/services or Windows services file
    try:
        service_name = socket.getservbyport(port, protocol.lower())
        return service_name.upper(), f"Standard {service_name.upper()} service"
    except (OSError, socket.error):
        return "Unknown", "Custom or unassigned service port"


def parse_mysql_handshake(data: bytes) -> str:
    """
    Parses MySQL Initial Handshake Packet (Protocol 10).
    Packet structure:
      - 3 bytes packet length
      - 1 byte packet number (usually 0)
      - 1 byte protocol version (usually 10)
      - null-terminated server version string
    """
    if len(data) < 5:
        return "MySQL (Handshake response received)"
    try:
        proto_ver = data[4]
        # Null-terminated string begins at byte 5
        null_pos = data.find(b"\x00", 5)
        if null_pos != -1:
            ver_str = data[5:null_pos].decode("utf-8", errors="replace")
            return f"MySQL / MariaDB (v{ver_str}, Proto {proto_ver})"
        return f"MySQL Server (Proto {proto_ver})"
    except Exception:
        return "MySQL Server"


def grab_banner(target_ip: str, port: int, timeout: float = 1.2) -> str:
    """
    Attempts to identify the service version and grab banner details.
    Specialized handlers for HTTP, HTTPS, SSH, MySQL, and FTP.
    """
    # 1. SSH (Port 22 or common SSH ports)
    if port == 22:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target_ip, port))
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            s.close()
            if banner:
                return banner
        except Exception:
            pass

    # 2. HTTPS (Port 443, 8443) - SSL/TLS Handshake & Certificate Inspection
    if port in (443, 8443):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            with ctx.wrap_socket(s, server_hostname=target_ip) as ssock:
                ssock.connect((target_ip, port))
                cert = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                tls_version = ssock.version() or "TLS"

                # Send HTTP HEAD request over TLS
                req = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: PortalScanner/1.0\r\nConnection: close\r\n\r\n"
                ssock.sendall(req.encode("ascii"))
                resp = ssock.recv(1024).decode("utf-8", errors="replace")

                server_header = ""
                for line in resp.splitlines():
                    if line.lower().startswith("server:"):
                        server_header = line.split(":", 1)[1].strip()
                        break

                details = [f"{tls_version}"]
                if cipher:
                    details.append(f"{cipher[0]}")
                if server_header:
                    details.append(f"Server: {server_header}")

                return " | ".join(details)
        except Exception as e:
            # TLS failed or timed out, report service exists
            return f"HTTPS (TLS active - {type(e).__name__})"

    # 3. HTTP (Port 80, 8080, 8000, 3000, 5000, 8888)
    if port in (80, 8080, 8000, 3000, 5000, 8888):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target_ip, port))
            req = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: PortalScanner/1.0\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode("ascii"))
            resp = s.recv(1024).decode("utf-8", errors="replace")
            s.close()

            server_header = ""
            status_line = ""
            lines = resp.splitlines()
            if lines:
                status_line = lines[0].strip()
            for line in lines:
                if line.lower().startswith("server:"):
                    server_header = line.split(":", 1)[1].strip()
                    break

            parts = []
            if status_line and status_line.startswith("HTTP"):
                parts.append(status_line)
            if server_header:
                parts.append(f"Server: {server_header}")

            if parts:
                return " | ".join(parts)
            return "HTTP Web Service"
        except Exception:
            return "HTTP Web Service"

    # 4. MySQL (Port 3306)
    if port == 3306:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target_ip, port))
            # MySQL server sends greeting immediately upon connect
            data = s.recv(1024)
            s.close()
            if data:
                return parse_mysql_handshake(data)
        except Exception:
            return "MySQL Database"

    # 5. FTP (Port 21)
    if port == 21:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target_ip, port))
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            s.close()
            if banner:
                return banner
        except Exception:
            return "FTP Service"

    # 6. Generic Banner Grab (Connect, send newline probe, read response)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, port))
        # Wait briefly for server to speak first
        s.settimeout(0.5)
        try:
            data = s.recv(512)
        except (socket.timeout, socket.error):
            # If nothing sent, send a probe
            s.sendall(b"\r\n\r\n")
            try:
                data = s.recv(512)
            except Exception:
                data = b""
        s.close()

        if data:
            # Clean non-printable characters
            text = "".join(chr(b) if 32 <= b <= 126 else " " for b in data).strip()
            # Collapse multiple spaces
            text = re.sub(r"\s+", " ", text)
            if len(text) > 80:
                text = text[:77] + "..."
            if text:
                return text
    except Exception:
        pass

    svc_name, _ = resolve_service_name(port)
    return f"{svc_name} service active"


def get_arp_table() -> Dict[str, str]:
    """
    Parses local system ARP cache to map IP addresses to MAC hardware addresses.
    Returns: {ip_str: mac_str}
    """
    arp_map = {}
    try:
        cmd = ["arp", "-a"]
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.0
        )
        output = proc.stdout
        # Regular expression for matching IP and MAC address pairs
        # Format on Windows: 192.168.1.1  00-11-22-33-44-55  dynamic
        # Format on Linux: (192.168.1.1) at 00:11:22:33:44:55
        ip_mac_pattern = re.compile(
            r"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)\s+([0-9a-fA-F[:-]{11,17})"
        )
        for line in output.splitlines():
            match = ip_mac_pattern.search(line)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                if mac != "FF:FF:FF:FF:FF:FF":
                    arp_map[ip] = mac
    except Exception:
        pass
    return arp_map


def export_to_csv(filepath: str, headers: List[str], rows: List[List[str]]) -> Tuple[bool, str]:
    """
    Exports structured data rows with headers to a CSV file.
    Returns: (success_bool, message)
    """
    try:
        with open(filepath, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        return True, f"Successfully saved {len(rows)} records to:\n{filepath}"
    except Exception as e:
        return False, f"Failed to export CSV: {e}"

