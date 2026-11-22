"""TCP connect probes against a listener on 127.0.0.1. No real network."""

import socket
import threading
import time
import unittest
from unittest import mock

from lantern.scanner import (
    BANNER_PORTS,
    HTTP_HEADER_BYTES,
    HTTP_HEADER_SECONDS,
    clean_banner,
    probe_port,
    scan_host,
)


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
        # shutdown wakes accept. Closing alone can leave this thread blocked
        # in the kernel, and a later server may reuse the fd and receive the
        # banner this thread still sends.
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        self.thread.join(timeout=2)


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

    def test_no_fingerprint_is_the_single_read_and_skips_the_parser(self):
        listener = _Listener(b"SSH-2.0-OpenSSH_9.6\n")
        try:
            with mock.patch("lantern.fingerprint.parse", side_effect=AssertionError("parsed")):
                plain = probe_port("127.0.0.1", listener.port, timeout=1, fingerprint=False)
        finally:
            listener.close()
        self.assertEqual(plain, {
            "port": listener.port, "open": True, "banner": "SSH-2.0-OpenSSH_9.6",
        })
        listener = _Listener(b"SSH-2.0-OpenSSH_9.6\n")
        try:
            parsed = probe_port("127.0.0.1", listener.port, timeout=1, fingerprint=True)
        finally:
            listener.close()
        self.assertEqual(parsed["banner"], "SSH-2.0-OpenSSH_9.6")
        self.assertEqual(parsed["fingerprint"]["product"], "OpenSSH")
        self.assertEqual(parsed["fingerprint"]["version"], "9.6")
        self.assertEqual(parsed["fingerprint"]["parse_status"], "ok")


class _SpeakFirst:
    """Sends `chunks` with a pause between them, or drips until the peer goes away."""

    def __init__(self, chunks, pause=0.0, drip=False):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.chunks = chunks
        self.pause = pause
        self.drip = drip
        self.received = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            if self.drip:
                while True:
                    try:
                        conn.sendall(b"X")
                    except OSError:
                        return
                    time.sleep(0.05)
            # The peer spoke first. Send before reading, or both sides wait.
            for chunk in self.chunks:
                try:
                    conn.sendall(chunk)
                except OSError:
                    # The client already has what it needs and hung up (macOS
                    # reports that at once). Still record what it sent: nothing.
                    break
                if self.pause:
                    time.sleep(self.pause)
            got = b""
            try:
                conn.settimeout(0.2)
                while len(got) < 128:
                    piece = conn.recv(64)
                    if not piece:
                        break
                    got += piece
            except OSError:
                pass
            self.received.append(got)

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        self.thread.join(timeout=2)


class BannerReadTests(unittest.TestCase):
    def test_a_trickled_ssh_greeting_is_parsed_and_sends_nothing(self):
        greeting = b"SSH-2.0-OpenSSH_9.6\n"
        # Five-byte pieces: still several separate reads, but four short sleeps
        # instead of twenty, which macOS runners stretch past the probe timeout.
        listener = _SpeakFirst([greeting[i:i + 5] for i in range(0, len(greeting), 5)], pause=0.02)
        try:
            started = time.monotonic()
            result = probe_port("127.0.0.1", listener.port, timeout=1)
            elapsed = time.monotonic() - started
        finally:
            listener.close()
        self.assertLess(elapsed, 1.2)
        self.assertEqual(listener.received, [b""])
        self.assertEqual(result["fingerprint"]["service"], "ssh")
        self.assertEqual(result["fingerprint"]["product"], "OpenSSH")
        self.assertEqual(result["fingerprint"]["version"], "9.6")

    def test_a_drip_stops_at_the_connect_deadline(self):
        listener = _SpeakFirst([], drip=True)
        try:
            started = time.monotonic()
            result = probe_port("127.0.0.1", listener.port, timeout=0.25)
            elapsed = time.monotonic() - started
        finally:
            listener.close()
        self.assertTrue(result["open"])
        self.assertLess(elapsed, 0.25 + 0.2)
        self.assertNotIn("fingerprint", result)

    def test_http_head_is_the_only_send_and_lf_headers_parse(self):
        bound = None
        for candidate in sorted(BANNER_PORTS):
            if candidate < 1024:
                continue
            try:
                bound = _HttpListener(candidate, b"HTTP/1.0 200 OK\nServer: nginx/1.24.0\n\n")
                break
            except OSError:
                continue
        if bound is None:
            self.skipTest("HTTP banner ports are in use")
        try:
            started = time.monotonic()
            result = probe_port("127.0.0.1", bound.port, timeout=0.6)
            elapsed = time.monotonic() - started
        finally:
            bound.close()
        self.assertLess(elapsed, HTTP_HEADER_SECONDS + 0.2)
        self.assertEqual(bound.received, [b"HEAD / HTTP/1.0\r\n\r\n"])
        self.assertEqual(result["fingerprint"]["product"], "nginx")
        self.assertEqual(result["fingerprint"]["version"], "1.24.0")

    def test_a_long_http_response_stops_at_2kib_and_a_non_http_port_sends_nothing(self):
        header = b"HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\n" + (b"X-Pad: " + b"A" * 100 + b"\r\n") * 400 + b"\r\n"
        self.assertGreater(len(header), HTTP_HEADER_BYTES)
        bound = None
        for candidate in sorted(BANNER_PORTS):
            if candidate < 1024:
                continue
            try:
                bound = _HttpListener(candidate, header)
                break
            except OSError:
                continue
        if bound is None:
            self.skipTest("HTTP banner ports are in use")
        try:
            result = probe_port("127.0.0.1", bound.port, timeout=0.6)
        finally:
            bound.close()
        self.assertEqual(bound.received, [b"HEAD / HTTP/1.0\r\n\r\n"])
        self.assertEqual(result["fingerprint"]["product"], "nginx")
        self.assertLessEqual(len(result["fingerprint"]["raw"]), 120)

        quiet = _SpeakFirst([b"220 (vsFTPd 3.0.5)\r\n"])
        try:
            ftp = probe_port("127.0.0.1", quiet.port, timeout=1)
        finally:
            quiet.close()
        self.assertEqual(quiet.received, [b""])
        self.assertEqual(ftp["fingerprint"]["service"], "ftp")
        self.assertEqual(ftp["fingerprint"]["product"], "vsFTPd")
        self.assertEqual(ftp["fingerprint"]["version"], "3.0.5")


class _HttpListener:
    """Accepts one connection, records the request, then writes `response`."""

    def __init__(self, port, response):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(1)
        self.port = port
        self.response = response
        self.received = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            got = b""
            conn.settimeout(2)
            try:
                while b"\r\n\r\n" not in got and len(got) < 256:
                    piece = conn.recv(64)
                    if not piece:
                        break
                    got += piece
            except OSError:
                pass
            self.received.append(got)
            try:
                conn.sendall(self.response)
            except OSError:
                return

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        self.thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
