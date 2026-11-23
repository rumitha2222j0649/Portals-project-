"""
scanner_socket.py - Multi-threaded Socket-based Port Scanner.
Detects OPEN, CLOSED, and FILTERED states and identifies common services and banners.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import errno
import socket
import threading
import time
from typing import Callable, List, Optional

import config
import utils


@dataclass
class PortScanResult:
    target: str
    port: int
    protocol: str
    state: str  # "open", "closed", "filtered"
    service: str
    banner: str
    latency_ms: float
    timestamp: str


class SocketPortScanner:
    """
    High-performance multi-threaded port scanner using Python's native socket library.
    Identifies Open, Closed, and Filtered states, resolves services, and grabs banners.
    """

    def __init__(self):
        self._stop_event = threading.Event()
        self.is_scanning = False

    def stop(self):
        """Signals the scanner to stop immediately."""
        self._stop_event.set()

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def scan_port(
        self,
        target_ip: str,
        port: int,
        timeout: float = config.DEFAULT_TIMEOUT,
        grab_banners: bool = True,
    ) -> PortScanResult:
        """
        Scans an individual TCP port on the target IP.
        Determines if port is OPEN, CLOSED, or FILTERED.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        start_time = time.perf_counter()
        state = "filtered"
        latency = 0.0

        try:
            # Attempt TCP connect using timeout-managed connect()
            s.connect((target_ip, port))
            latency = (time.perf_counter() - start_time) * 1000.0
            state = "open"
        except ConnectionRefusedError:
            latency = (time.perf_counter() - start_time) * 1000.0
            state = "closed"
        except (socket.timeout, TimeoutError):
            latency = timeout * 1000.0
            state = "filtered"
        except OSError as e:
            latency = (time.perf_counter() - start_time) * 1000.0
            err_code = getattr(e, "errno", None) or getattr(e, "winerror", None)
            if err_code in (errno.ECONNREFUSED, 10061, 111, 61):
                state = "closed"
            elif err_code in (errno.ETIMEDOUT, 10060, 110, 60, errno.EHOSTUNREACH, 10065, 113):
                state = "filtered"
            else:
                state = "filtered"
        except Exception:
            state = "filtered"
        finally:
            try:
                s.close()
            except Exception:
                pass

        # Service name resolution
        svc_name, _ = utils.resolve_service_name(port, "tcp")
        banner = ""

        # For open ports, perform banner grabbing and version identification
        if state == "open" and grab_banners:
            try:
                banner = utils.grab_banner(target_ip, port, timeout=min(timeout, 1.5))
            except Exception:
                banner = f"{svc_name} service active"
        elif state == "open":
            banner = f"{svc_name} detected"
        elif state == "closed":
            banner = "Port closed (Host responded with TCP RST)"
        elif state == "filtered":
            banner = "Packet dropped or blocked (No response / Firewall)"

        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        return PortScanResult(
            target=target_ip,
            port=port,
            protocol="TCP",
            state=state,
            service=svc_name,
            banner=banner,
            latency_ms=round(latency, 2),
            timestamp=now_str,
        )

    def scan_ports(
        self,
        target_ip: str,
        ports: List[int],
        timeout: float = config.DEFAULT_TIMEOUT,
        max_threads: int = config.DEFAULT_THREADS,
        callback: Optional[Callable[[PortScanResult, int, int], None]] = None,
        only_open: bool = False,
    ) -> List[PortScanResult]:
        """
        Scans a list of ports using a thread pool.
        Calls callback(result, completed_count, total_count) on each scanned port.
        """
        self._stop_event.clear()
        self.is_scanning = True
        results: List[PortScanResult] = []
        total_ports = len(ports)
        completed_ports = 0

        # Adjust worker count so we don't spawn more threads than ports
        num_workers = min(max_threads, max(1, total_ports))

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            # Map future to port
            future_to_port = {
                executor.submit(self.scan_port, target_ip, p, timeout, True): p
                for p in ports
            }

            for future in as_completed(future_to_port):
                if self._stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                try:
                    res = future.result()
                    completed_ports += 1
                    results.append(res)

                    if callback:
                        # If user requested only open ports, notify callback only when open or for progress
                        callback(res, completed_ports, total_ports)
                except Exception:
                    completed_ports += 1

        self.is_scanning = False
        # Return sorted by port number
        results.sort(key=lambda r: r.port)
        return results
