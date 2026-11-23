"""
network_discovery.py - Local Network Active Device Discovery.
Scans subnets using multi-threaded TCP/ICMP/ARP probes to discover active devices.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import os
import socket
import subprocess
import sys
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

import config
from scanner_nmap import NmapScanner, is_nmap_available
import utils


@dataclass
class DeviceResult:
    ip: str
    hostname: str
    mac: str
    status: str
    latency_ms: float
    timestamp: str


class NetworkDiscovery:
    """
    Scans a local subnet or IP range to discover live, active devices.
    Displays IP address, Hostname, MAC Address, Status, and Latency.
    """

    # Common LAN ports that are typically open or return TCP RST on active devices
    PROBE_PORTS = [80, 443, 445, 135, 139, 22, 8080, 53, 3389, 21, 8000]

    def __init__(self):
        self._stop_event = threading.Event()
        self.is_scanning = False
        self._arp_cache: Dict[str, str] = {}

    def stop(self):
        """Stops the discovery scan."""
        self._stop_event.set()

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def _ping_host(self, ip_str: str, timeout_ms: int = 500) -> bool:
        """
        Sends a single ICMP echo ping to determine if host is responsive.
        """
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip_str]
        else:
            timeout_sec = max(1, int(timeout_ms / 1000))
            cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip_str]

        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout_ms / 1000.0 + 0.5,
            )
            return res.returncode == 0
        except Exception:
            return False

    def _tcp_probe(self, ip_str: str, timeout: float = 0.4) -> Tuple[bool, float]:
        """
        Attempts fast TCP connect on common ports. If any port responds with open
        or connection refused (closed, but host responded), returns (True, latency).
        """
        for port in self.PROBE_PORTS:
            if self._stop_event.is_set():
                break
            start_t = time.perf_counter()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect((ip_str, port))
                latency = (time.perf_counter() - start_t) * 1000.0
                return True, round(latency, 2)
            except ConnectionRefusedError:
                # Connection refused means host is definitely alive and replied with TCP RST
                latency = (time.perf_counter() - start_t) * 1000.0
                return True, round(latency, 2)
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        return False, 0.0

    def probe_device(self, ip_str: str, arp_cache: Dict[str, str], timeout: float = 0.5) -> Optional[DeviceResult]:
        """
        Probes an individual IP address to test if it is active.
        """
        if self._stop_event.is_set():
            return None

        is_alive = False
        latency = 0.0

        # Method 1: Fast TCP probe on common LAN ports
        alive_tcp, lat = self._tcp_probe(ip_str, timeout=0.35)
        if alive_tcp:
            is_alive = True
            latency = lat

        # Method 2: ICMP ping if TCP probe was inconclusive
        if not is_alive:
            t0 = time.perf_counter()
            if self._ping_host(ip_str, timeout_ms=int(timeout * 1000)):
                is_alive = True
                latency = round((time.perf_counter() - t0) * 1000.0, 2)

        # Method 3: Check if IP is in system ARP cache (often populated during network communication)
        if not is_alive and ip_str in arp_cache:
            mac_val = arp_cache[ip_str]
            if mac_val and mac_val != "FF:FF:FF:FF:FF:FF":
                is_alive = True
                latency = 1.0

        if not is_alive:
            return None

        # Reverse DNS lookup for hostname
        hostname = "N/A"
        try:
            host_info = socket.gethostbyaddr(ip_str)
            hostname = host_info[0] if host_info else "N/A"
        except (socket.herror, socket.gaierror, Exception):
            hostname = "N/A"

        mac = arp_cache.get(ip_str, "Dynamic / Local")
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")

        return DeviceResult(
            ip=ip_str,
            hostname=hostname,
            mac=mac,
            status="Online",
            latency_ms=latency,
            timestamp=now_str,
        )

    def discover(
        self,
        subnet_input: str,
        engine: str = "socket",
        timeout: float = 0.5,
        max_threads: int = config.DEFAULT_DISCOVERY_THREADS,
        callback: Optional[Callable[[Optional[DeviceResult], int, int], None]] = None,
    ) -> List[DeviceResult]:
        """
        Discovers active devices across the specified subnet or range.
        Calls callback(device_or_none, completed_hosts, total_hosts).
        """
        self._stop_event.clear()
        self.is_scanning = True

        # Validate subnet or range
        valid, ip_list, msg = utils.validate_subnet_or_cidr(subnet_input)
        if not valid:
            self.is_scanning = False
            raise ValueError(msg)

        # If Nmap engine selected and Nmap is available, use Nmap host discovery
        if engine.lower() == "nmap":
            nmap_ok, _ = is_nmap_available()
            if nmap_ok:
                try:
                    nmap_scanner = NmapScanner()
                    raw_devs = nmap_scanner.discover_hosts(subnet_input)
                    results = []
                    total = len(ip_list)
                    for idx, d in enumerate(raw_devs, 1):
                        dev_res = DeviceResult(
                            ip=d["ip"],
                            hostname=d["hostname"],
                            mac=d["mac"],
                            status=d["status"],
                            latency_ms=d["latency_ms"],
                            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                        )
                        results.append(dev_res)
                        if callback:
                            callback(dev_res, idx, total)
                    self.is_scanning = False
                    return results
                except Exception:
                    # Fallback to socket scan on error
                    pass

        # Socket / Ping / ARP Discovery
        total_hosts = len(ip_list)
        completed = 0
        discovered_devices: List[DeviceResult] = []

        # Refresh system ARP cache once before scan
        self._arp_cache = utils.get_arp_table()

        num_workers = min(max_threads, max(1, total_hosts))
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            future_to_ip = {
                executor.submit(self.probe_device, ip, self._arp_cache, timeout): ip
                for ip in ip_list
            }

            for future in as_completed(future_to_ip):
                if self._stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                completed += 1
                try:
                    dev = future.result()
                    if dev:
                        discovered_devices.append(dev)
                    if callback:
                        callback(dev, completed, total_hosts)
                except Exception:
                    if callback:
                        callback(None, completed, total_hosts)

        # Refresh ARP cache once after scan to catch newly resolved MACs
        updated_arp = utils.get_arp_table()
        for dev in discovered_devices:
            if dev.mac in ("Dynamic / Local", "Unknown") and dev.ip in updated_arp:
                dev.mac = updated_arp[dev.ip]

        self.is_scanning = False
        # Sort devices by IP address
        discovered_devices.sort(
            key=lambda d: [int(x) if x.isdigit() else 0 for x in d.ip.split(".")]
        )
        return discovered_devices
