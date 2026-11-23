"""
scanner_nmap.py - Nmap Scanner wrapper using python-nmap.
Integrates Nmap scanning capabilities, service version detection (-sV), and graceful fallbacks.
"""

import os
import shutil
import sys
import threading
import time
from typing import Callable, List, Optional, Tuple

import config
from scanner_socket import PortScanResult
import utils

# Attempt importing python-nmap
try:
    import nmap
    PYTHON_NMAP_INSTALLED = True
except ImportError:
    nmap = None
    PYTHON_NMAP_INSTALLED = False


def find_nmap_executable() -> Optional[str]:
    """
    Searches for the nmap executable in system PATH and common installation directories.
    """
    # 1. Check system PATH
    found = shutil.which("nmap")
    if found:
        return found

    # 2. Check common Windows installation paths
    if sys.platform == "win32":
        common_win_paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap\nmap.exe"),
            os.path.expandvars(r"%PROGRAMFILES%\Nmap\nmap.exe"),
            os.path.expandvars(r"%PROGRAMFILES(X86)%\Nmap\nmap.exe"),
        ]
        for path in common_win_paths:
            if os.path.isfile(path):
                return path

    return None


def is_nmap_available() -> Tuple[bool, str]:
    """
    Checks if Nmap binary and python-nmap wrapper are ready to use.
    Returns: (is_available, status_message_or_path)
    """
    if not PYTHON_NMAP_INSTALLED:
        return False, "python-nmap library is not installed (run: pip install python-nmap)"

    nmap_path = find_nmap_executable()
    if not nmap_path:
        return (
            False,
            "Nmap binary was not found in system PATH or standard folders. "
            "Please install Nmap from https://nmap.org/download.html",
        )

    # Test initialization
    try:
        # Add found path to environment PATH if not already present
        nmap_dir = os.path.dirname(nmap_path)
        if nmap_dir and nmap_dir not in os.environ.get("PATH", ""):
            os.environ["PATH"] = nmap_dir + os.pathsep + os.environ.get("PATH", "")

        scanner = nmap.PortScanner()
        version = scanner.nmap_version()
        return True, f"Nmap v{version[0]}.{version[1]} ready ({nmap_path})"
    except Exception as e:
        return False, f"Nmap initialization failed: {e}"


class NmapScanner:
    """
    Nmap port scanner wrapper providing deep service version detection,
    OS fingerprinting, and standardized PortScanResult outputs.
    """

    def __init__(self):
        self._stop_event = threading.Event()
        self.is_scanning = False
        self._scanner = None

    def stop(self):
        """Signals stop request."""
        self._stop_event.set()

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def _ensure_scanner(self):
        if not PYTHON_NMAP_INSTALLED:
            raise RuntimeError("python-nmap module is not installed. Please run 'pip install python-nmap'.")
        
        nmap_path = find_nmap_executable()
        if nmap_path:
            nmap_dir = os.path.dirname(nmap_path)
            if nmap_dir not in os.environ.get("PATH", ""):
                os.environ["PATH"] = nmap_dir + os.pathsep + os.environ.get("PATH", "")

        try:
            self._scanner = nmap.PortScanner()
        except nmap.PortScannerError as e:
            raise RuntimeError(
                f"Nmap executable not found: {e}\n"
                "Please download and install Nmap from https://nmap.org or use the native Socket Engine."
            )

    def scan_ports(
        self,
        target_ip: str,
        ports: List[int],
        scan_arguments: str = "-sV -T4",
        callback: Optional[Callable[[PortScanResult, int, int], None]] = None,
    ) -> List[PortScanResult]:
        """
        Runs an Nmap scan against the specified target and port list.
        Parses results into PortScanResult objects.
        """
        self._stop_event.clear()
        self.is_scanning = True
        self._ensure_scanner()

        # Format ports argument e.g. "22,80,443"
        ports_str = ",".join(str(p) for p in ports)
        total_ports = len(ports)
        results: List[PortScanResult] = []

        try:
            # Execute Nmap scan
            # Note: -Pn is added to skip host discovery if target blocks ICMP ping
            full_args = f"-Pn {scan_arguments}"
            scan_data = self._scanner.scan(hosts=target_ip, ports=ports_str, arguments=full_args)
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")

            scan_host_info = scan_data.get("scan", {}).get(target_ip, {})
            tcp_scan = scan_host_info.get("tcp", {})

            # Process each requested port
            completed_count = 0
            for port in ports:
                if self._stop_event.is_set():
                    break

                completed_count += 1
                if port in tcp_scan:
                    p_info = tcp_scan[port]
                    state = p_info.get("state", "filtered").lower()
                    service_name = p_info.get("name", "unknown")
                    product = p_info.get("product", "")
                    version = p_info.get("version", "")
                    extrainfo = p_info.get("extrainfo", "")

                    banner_parts = []
                    if product:
                        banner_parts.append(product)
                    if version:
                        banner_parts.append(f"v{version}")
                    if extrainfo:
                        banner_parts.append(f"({extrainfo})")

                    banner = " ".join(banner_parts) if banner_parts else f"{service_name.upper()} service"
                else:
                    # Port was not explicitly in tcp list, default to filtered
                    state = "filtered"
                    svc_name, _ = utils.resolve_service_name(port)
                    service_name = svc_name
                    banner = "Filtered / No response"

                # Normalize service name if unknown
                if not service_name or service_name == "unknown":
                    svc_name, _ = utils.resolve_service_name(port)
                    service_name = svc_name

                res = PortScanResult(
                    target=target_ip,
                    port=port,
                    protocol="TCP",
                    state=state,
                    service=service_name.upper(),
                    banner=banner,
                    latency_ms=0.0,
                    timestamp=now_str,
                )
                results.append(res)

                if callback:
                    callback(res, completed_count, total_ports)

        except Exception as e:
            self.is_scanning = False
            raise RuntimeError(f"Nmap scan failed: {e}")

        self.is_scanning = False
        results.sort(key=lambda r: r.port)
        return results

    def discover_hosts(
        self,
        subnet_cidr: str,
        callback: Optional[Callable[[str, str, str, str], None]] = None,
    ) -> List[dict]:
        """
        Runs an Nmap host discovery scan (-sn / ping scan) across a subnet.
        Returns list of active devices.
        """
        self._stop_event.clear()
        self.is_scanning = True
        self._ensure_scanner()

        devices = []
        try:
            scan_data = self._scanner.scan(hosts=subnet_cidr, arguments="-sn -T4")
            scan_hosts = scan_data.get("scan", {})

            for host_ip, host_info in scan_hosts.items():
                if self._stop_event.is_set():
                    break

                status = host_info.get("status", {}).get("state", "down")
                if status == "up":
                    hostname = host_info.get("hostnames", [{}])[0].get("name", "")
                    mac = host_info.get("addresses", {}).get("mac", "")
                    vendor = host_info.get("vendor", {}).get(mac, "")

                    dev = {
                        "ip": host_ip,
                        "hostname": hostname or "N/A",
                        "mac": mac or "Unknown",
                        "vendor": vendor or "Generic Device",
                        "status": "Online",
                        "latency_ms": 1.0,
                    }
                    devices.append(dev)
                    if callback:
                        callback(dev["ip"], dev["hostname"], dev["mac"], dev["status"])
        except Exception as e:
            self.is_scanning = False
            raise RuntimeError(f"Nmap discovery failed: {e}")

        self.is_scanning = False
        return devices

