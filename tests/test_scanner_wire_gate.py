"""GATE-M6c: a scan must not send more than main's probe.

The reference is the 7e74c05 ``probe_port`` send decision, copied here.
It is not the scanner under test. Fake sockets only. Nothing is on the network.
"""

import random
import socket
import unittest
from collections import Counter
from unittest import mock

from lantern.scanner import BANNER_BYTES, HTTP_HEADER_BYTES, probe_port

# Frozen from scanner.clean_banner and BANNER_PORTS at 7e74c05.
_FROZEN_BANNER_PORTS = {80, 8080, 8888, 9000, 9090, 32400, 8096, 8123}
_HEAD = b"HEAD / HTTP/1.0\r\n\r\n"


def _frozen_clean(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = "".join(ch for ch in line if ch.isprintable()).strip()
        if line:
            return line[:120]
    return ""


class _ScriptSocket:
    """One scripted connection. ``timeout`` and ``close`` are the only signals."""

    def __init__(self, script):
        self.script = list(script)
        self.pending = b""
        self.sent = []
        self.delivered = 0

    def recv(self, size):
        while not self.pending:
            if not self.script:
                return b""
            item = self.script.pop(0)
            if item == "timeout":
                raise socket.timeout("timed out")
            if item == "close":
                return b""
            self.pending = item
        chunk = self.pending[:size]
        self.pending = self.pending[size:]
        self.delivered += len(chunk)
        return chunk

    def sendall(self, data):
        self.sent.append(bytes(data))

    def settimeout(self, _value):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def _reference_sends(port: int, script) -> list[bytes]:
    """What 7e74c05 sent: one recv, then HEAD and one more recv when that cleaned to empty."""
    sock = _ScriptSocket(script)
    try:
        try:
            data = sock.recv(256)
        except Exception:
            banner = ""
        else:
            banner = _frozen_clean(data)
        if not banner and port in _FROZEN_BANNER_PORTS:
            try:
                sock.sendall(_HEAD)
                sock.recv(256)
            except Exception:
                pass
    except Exception:
        pass
    return list(sock.sent)


def _probe_sends(port: int, script, fingerprint: bool) -> list[bytes]:
    sock = _ScriptSocket(script)
    with mock.patch("lantern.scanner.socket.create_connection", return_value=sock):
        probe_port("127.0.0.1", port, timeout=0.6, fingerprint=fingerprint)
    return list(sock.sent)


def _named_scripts():
    scripts = [
        [],
        ["timeout"],
        ["close"],
        [b"\x00\x01\x02"],
        [b"S", b"S", b"H", b"-", b"2.0-OpenSSH_9.6\n"],
        [bytes(range(256))],
        [b"HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"],
        [b""],
        ["timeout", b"HTTP/1.0 200 OK\r\n\r\n"],
        [b"\n"],
    ]
    ports = (80, 22, 12345)
    for port in ports:
        for script in scripts:
            yield port, script


def _generated_scripts(count: int):
    rng = random.Random(20261118)
    ports = (80, 22, 8080, 21, 25, 12345)
    for _ in range(count):
        events = []
        for _step in range(rng.randint(0, 6)):
            kind = rng.randrange(4)
            if kind == 0:
                events.append(bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 40))))
            elif kind == 1:
                events.append(bytes([rng.randrange(256)]))
            elif kind == 2:
                events.append("timeout")
            else:
                events.append("close")
        yield rng.choice(ports), events


class WireGateTests(unittest.TestCase):
    def test_sent_bytes_are_a_subset_of_main(self):
        cases = list(_named_scripts()) + list(_generated_scripts(200))
        self.assertGreaterEqual(len(cases), 200)
        for port, script in cases:
            reference = _reference_sends(port, script)
            for enabled in (True, False):
                sent = _probe_sends(port, script, enabled)
                self.assertLessEqual(
                    Counter(sent), Counter(reference),
                    (port, script, enabled, sent, reference),
                )
                for payload in sent:
                    self.assertEqual(payload, _HEAD)

    def test_a_flood_stops_at_the_byte_cap(self):
        class _Flood(_ScriptSocket):
            def __init__(self):
                super().__init__([])
                self.reads = 0

            def recv(self, size):
                self.reads += 1
                if self.reads == 1:
                    raise socket.timeout("timed out")
                self.delivered += size
                return b"A" * size

        for port, cap in ((80, HTTP_HEADER_BYTES), (12345, BANNER_BYTES)):
            sock = _Flood()
            with mock.patch("lantern.scanner.socket.create_connection", return_value=sock):
                probe_port("127.0.0.1", port, timeout=0.6, fingerprint=True)
            self.assertLessEqual(sock.delivered, cap, port)
            if port == 80:
                self.assertEqual(sock.sent, [_HEAD])
            else:
                self.assertEqual(sock.sent, [])


if __name__ == "__main__":
    unittest.main()
