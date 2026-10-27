"""TCP connect probes against a listener on 127.0.0.1. No real network."""

import socket
import threading
import unittest

from lantern.scanner import clean_banner, probe_port, scan_host


class _Listener:
    """One-shot TCP server that greets with `banner` (or stays silent)."""

    def __init__(self, banner=b""):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.banner = banner
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                if self.banner:
                    conn.sendall(self.banner)
                else:
                    try:
                        conn.settimeout(1)
                        conn.recv(64)
                    except OSError:
                        pass

    def close(self):
        self.sock.close()


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class CleanBannerTests(unittest.TestCase):
    def test_first_printable_line_trimmed(self):
        self.assertEqual(clean_banner(b"\r\n  SSH-2.0-OpenSSH_9.6\r\nmore"), "SSH-2.0-OpenSSH_9.6")
        self.assertEqual(clean_banner(b"\x00\x01\x02"), "")
        self.assertEqual(clean_banner(b""), "")
        self.assertEqual(len(clean_banner(b"A" * 500)), 120)
        self.assertEqual(clean_banner(b"\xff\xfeok"), "\ufffd\ufffdok")


class ProbeTests(unittest.TestCase):
    def test_open_port_with_banner(self):
        listener = _Listener(b"220 lantern test\r\n")
        try:
            result = probe_port("127.0.0.1", listener.port, timeout=1)
        finally:
            listener.close()
        self.assertEqual(result, {"port": listener.port, "open": True, "banner": "220 lantern test"})

    def test_open_silent_port(self):
        listener = _Listener()
        try:
            result = probe_port("127.0.0.1", listener.port, timeout=0.3)
        finally:
            listener.close()
        self.assertTrue(result["open"])
        self.assertEqual(result["banner"], "")

    def test_closed_port(self):
        result = probe_port("127.0.0.1", _free_port(), timeout=0.5)
        self.assertEqual(result["open"], False)

    def test_scan_host_returns_sorted_open_ports_only(self):
        a, b = _Listener(b"a\n"), _Listener(b"b\n")
        try:
            ports = [b.port, _free_port(), a.port, a.port]
            results = scan_host("127.0.0.1", ports, timeout=1)
        finally:
            a.close()
            b.close()
        self.assertEqual([r["port"] for r in results], sorted({a.port, b.port}))
        self.assertEqual(scan_host("127.0.0.1", []), [])


if __name__ == "__main__":
    unittest.main()
