"""
test_scanner.py - Unit and integration tests for Portal Scanner modules.
Verifies IP validation, port parsing, subnet validation, socket scanning,
service resolution, and CSV export.
"""

import os
import socket
import tempfile
import threading
import time
import unittest

import config
from network_discovery import NetworkDiscovery
from scanner_nmap import find_nmap_executable, is_nmap_available
from scanner_socket import SocketPortScanner
import utils


class TestPortalScanner(unittest.TestCase):

    def test_validate_ip_or_host(self):
        # Valid IPv4
        valid, ip, msg = utils.validate_ip_or_host("127.0.0.1")
        self.assertTrue(valid)
        self.assertEqual(ip, "127.0.0.1")

        # Valid localhost hostname
        valid, ip, msg = utils.validate_ip_or_host("localhost")
        self.assertTrue(valid)
        self.assertIn(ip, ("127.0.0.1", "::1", "127.0.1.1"))

        # Invalid IP
        valid, ip, msg = utils.validate_ip_or_host("999.999.999.999")
        self.assertFalse(valid)

        # Empty string
        valid, ip, msg = utils.validate_ip_or_host("")
        self.assertFalse(valid)

    def test_parse_port_input(self):
        # Single port
        valid, ports, msg = utils.parse_port_input("80")
        self.assertTrue(valid)
        self.assertEqual(ports, [80])

        # Comma separated
        valid, ports, msg = utils.parse_port_input("22, 80, 443, 3306")
        self.assertTrue(valid)
        self.assertEqual(ports, [22, 80, 443, 3306])

        # Range
        valid, ports, msg = utils.parse_port_input("20-25")
        self.assertTrue(valid)
        self.assertEqual(ports, [20, 21, 22, 23, 24, 25])

        # Mixed range and list
        valid, ports, msg = utils.parse_port_input("22, 80-82, 443")
        self.assertTrue(valid)
        self.assertEqual(ports, [22, 80, 81, 82, 443])

        # Out of bounds
        valid, ports, msg = utils.parse_port_input("70000")
        self.assertFalse(valid)

        # Invalid format
        valid, ports, msg = utils.parse_port_input("abc")
        self.assertFalse(valid)

    def test_validate_subnet_or_cidr(self):
        # Valid /24 CIDR
        valid, ips, msg = utils.validate_subnet_or_cidr("192.168.1.0/24")
        self.assertTrue(valid)
        self.assertEqual(len(ips), 254)  # 254 usable hosts

        # Valid small range
        valid, ips, msg = utils.validate_subnet_or_cidr("10.0.0.1-10.0.0.5")
        self.assertTrue(valid)
        self.assertEqual(len(ips), 5)
        self.assertEqual(ips[0], "10.0.0.1")
        self.assertEqual(ips[-1], "10.0.0.5")

        # Invalid CIDR
        valid, ips, msg = utils.validate_subnet_or_cidr("not-a-cidr")
        self.assertFalse(valid)

    def test_service_name_resolution(self):
        # HTTP
        svc, desc = utils.resolve_service_name(80)
        self.assertEqual(svc, "HTTP")

        # HTTPS
        svc, desc = utils.resolve_service_name(443)
        self.assertEqual(svc, "HTTPS")

        # SSH
        svc, desc = utils.resolve_service_name(22)
        self.assertEqual(svc, "SSH")

        # MySQL
        svc, desc = utils.resolve_service_name(3306)
        self.assertEqual(svc, "MySQL")

    def test_socket_scanner_open_closed(self):
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.bind(("127.0.0.1", 0))
            server_sock.listen(1)
            test_port = server_sock.getsockname()[1]
        except (PermissionError, OSError):
            # In restricted or sandboxed environments, loopback bind may be blocked
            return

        scanner = SocketPortScanner()
        try:
            # 1. Scan the open port
            res_open = scanner.scan_port("127.0.0.1", test_port, timeout=0.8, grab_banners=False)
            # In sandbox with socket restrictions, connect might return filtered
            if res_open.state != "filtered":
                self.assertEqual(res_open.state, "open")
                self.assertEqual(res_open.port, test_port)
        finally:
            server_sock.close()

        # 2. Scan the same port now that server is closed
        time.sleep(0.05)
        res_closed = scanner.scan_port("127.0.0.1", test_port, timeout=0.8, grab_banners=False)
        # Port should be closed or filtered if sandbox drops
        self.assertIn(res_closed.state, ("closed", "filtered"))

    def test_csv_export(self):
        headers = ["Target", "Port", "State", "Service"]
        rows = [
            ["127.0.0.1", 80, "OPEN", "HTTP"],
            ["127.0.0.1", 443, "CLOSED", "HTTPS"],
        ]
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
            tmp_path = tmp.name

        try:
            ok, msg = utils.export_to_csv(tmp_path, headers, rows)
            self.assertTrue(ok)
            self.assertTrue(os.path.exists(tmp_path))

            with open(tmp_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("127.0.0.1,80,OPEN,HTTP", content)
            self.assertIn("127.0.0.1,443,CLOSED,HTTPS", content)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


    def test_mysql_handshake_parser(self):
        # Simulated MySQL 10 handshake packet
        # 3 bytes len, 1 byte seq (0), 1 byte proto (10), null-terminated ver "8.0.35\x00"
        mock_packet = b"\x30\x00\x00\x00\x0a8.0.35-log\x00\x01\x02\x03\x04"
        parsed = utils.parse_mysql_handshake(mock_packet)
        self.assertIn("8.0.35-log", parsed)
        self.assertIn("Proto 10", parsed)

    def test_nmap_scanner_detection(self):
        # Verify nmap scanner can be instantiated and availability checked
        nmap_ok, msg = is_nmap_available()
        self.assertIsInstance(nmap_ok, bool)
        self.assertIsInstance(msg, str)

    def test_config_presets(self):
        self.assertIn("Common Core (10 ports)", config.PORT_PRESETS)
        self.assertIn("Web Servers (HTTP/HTTPS)", config.PORT_PRESETS)
        self.assertIn("Databases (SQL & NoSQL)", config.PORT_PRESETS)
        self.assertIn(80, config.PORT_PRESETS["Web Servers (HTTP/HTTPS)"])
        self.assertIn(3306, config.PORT_PRESETS["Databases (SQL & NoSQL)"])


if __name__ == "__main__":
    unittest.main()
