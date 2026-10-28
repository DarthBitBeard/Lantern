"""End-to-end tests for the stdlib web dashboard. Run: python3 tests/test_web.py"""

import contextlib
import io
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lantern import webapp  # noqa: E402
from lantern.webapp import MAX_BODY_BYTES, make_server  # noqa: E402

_TOKEN_RE = re.compile(r'<meta name="lantern-token" content="([^"]+)"')


class WebTests(unittest.TestCase):
    def setUp(self):
        # Fresh database and server per test, so ids are predictable.
        self.tmp = tempfile.TemporaryDirectory()
        self.server = make_server(Path(self.tmp.name) / "test.db", port=0)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.token = ""
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        try:
            self.token = self._fetch_token()
        except Exception:
            self.tearDown()
            raise

    def tearDown(self):
        server = getattr(self, "server", None)
        if server is not None:
            self.server = None
            server.shutdown()
            server.server_close()
        tmp = getattr(self, "tmp", None)
        if tmp is not None:
            self.tmp = None
            tmp.cleanup()

    def request(self, path, method="GET", body=None, headers=None, raw=None, token=None, base=None):
        hdrs = {"Content-Type": "application/json"}
        if method == "POST" and token is not False:
            hdrs[webapp.TOKEN_HEADER] = self.token if token is None else token
        hdrs.update(headers or {})
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request((base or self.base) + path, method=method, data=data, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode(), resp.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(), exc.headers

    def _token_in(self, page: str) -> str:
        match = _TOKEN_RE.search(page)
        self.assertIsNotNone(match, page)
        token = match.group(1)
        self.assertNotIn(webapp.TOKEN_PLACEHOLDER, token)
        self.assertGreaterEqual(len(token), 32)
        return token

    def _fetch_token(self) -> str:
        status, body, _ = self.request("/")
        self.assertEqual(status, 200, body)
        return self._token_in(body)

    def assert_forbidden(self, status, body):
        self.assertEqual(status, 403, body)
        self.assertEqual(json.loads(body), {"error": webapp.FORBIDDEN_MESSAGE})
        self.assertNotIn(self.token, body)
        self.assertNotIn("evil.example", body)

    def get_json(self, path):
        status, body, _ = self.request(path)
        return status, json.loads(body)

    def test_latest_diff_stays_inside_one_scope(self):
        from lantern.store import connect, save_scan

        def device(ip):
            return {
                "ip": ip, "mac": None, "hostname": None, "label": None,
                "open_ports": [], "findings": [],
            }

        conn = connect(Path(self.tmp.name) / "test.db")
        try:
            save_scan(conn, "192.168.50.0/24", [device("192.168.50.10")], scope_name="home")
            save_scan(conn, "10.50.0.0/24", [device("10.50.0.10")], scope_name="lab")
            home_b = save_scan(
                conn, "192.168.50.0/24",
                [device("192.168.50.10"), device("192.168.50.11")],
                scope_name="home",
            )
            save_scan(conn, "10.50.0.0/24", [device("10.50.0.10")], scope_name="lab")
        finally:
            conn.close()
        status, data = self.get_json("/api/diff")
        self.assertEqual(status, 200, data)
        self.assertEqual(data["scan"]["scope_name"], "lab")
        self.assertEqual(data["diff"]["added"], [])
        self.assertEqual(data["diff"]["removed"], [])
        status, data = self.get_json(f"/api/scans/{home_b}")
        self.assertEqual(status, 200, data)
        self.assertEqual([d["ip"] for d in data["diff"]["added"]], ["192.168.50.11"])
        self.assertEqual(data["diff"]["removed"], [])

    def test_flow(self):
        status, body, headers = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn("Lantern", body)
        self.assertIn(self.token, body)
        self.assertNotIn(webapp.TOKEN_PLACEHOLDER, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

        for asset in ("/styles.css", "/app.js"):
            status, _, headers = self.request(asset)
            self.assertEqual(status, 200, asset)
        self.assertTrue(headers["Content-Type"].startswith("text/javascript"))

        status, data = self.get_json("/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(data["scan_count"], 0)
        self.assertIsNone(data["latest_scan_id"])
        self.assertFalse(data["scan_running"])
        self.assertIn("version", data)

        status, data = self.get_json("/api/scans/latest")
        self.assertEqual((status, data), (200, {"scan": None, "diff": None}))

        status, body, _ = self.request("/api/report?format=html")
        self.assertEqual(status, 404)

        status, body, headers = self.request("/api/demo", method="POST", body={})
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        data = json.loads(body)
        self.assertEqual(data["scan_id"], 2)
        self.assertEqual(len(data["scan"]["devices"]), 6)
        self.assertEqual(len(data["diff"]["added"]), 1)

        # Trust by MAC; label is trimmed and survives reloads of any scan.
        mac = "DE-AD-BE-EF-00-99"
        status, body, _ = self.request(
            "/api/trust", method="POST", body={"mac": mac, "label": "  Mystery box ", "trusted": True},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body), {"mac": "de:ad:be:ef:00:99", "label": "Mystery box", "trusted": True})

        status, data = self.get_json("/api/scans/latest")
        devices = {d["ip"]: d for d in data["scan"]["devices"]}
        self.assertTrue(devices["192.168.1.99"]["trusted"])
        self.assertEqual(devices["192.168.1.99"]["label"], "Mystery box")
        self.assertFalse(devices["192.168.1.1"]["trusted"])

        # A specific scan carries its own diff against the scan before it.
        status, data = self.get_json("/api/scans/1")
        self.assertEqual(status, 200)
        self.assertEqual(data["scan"]["id"], 1)
        self.assertIsNone(data["diff"])
        status, data = self.get_json("/api/scans/2")
        self.assertEqual(data["diff"]["added"][0]["ip"], "192.168.1.99")
        self.assertEqual(data["diff"]["added"][0]["label"], "Mystery box")

        status, data = self.get_json("/api/scans/999")
        self.assertEqual(status, 404)
        status, data = self.get_json("/api/scans/abc")
        self.assertEqual(status, 400)
        status, data = self.get_json("/api/scans/0")
        self.assertEqual(status, 400)

        status, body, _ = self.request("/api/report?format=html")
        self.assertEqual(status, 200)
        self.assertIn("Telnet", body)
        self.assertIn("Mystery box", body)
        status, body, _ = self.request("/api/report?format=json&scan_id=1")
        self.assertEqual(json.loads(body)["device_count"], 5)
        status, _, _ = self.request("/api/report?format=xml")
        self.assertEqual(status, 400)
        status, _, _ = self.request("/api/report?scan_id=77")
        self.assertEqual(status, 404)

        status, data = self.get_json("/api/scans")
        self.assertEqual(data["scans"][0]["device_count"], 6)
        self.assertEqual([s["id"] for s in data["scans"]], [2, 1])

        status, data = self.get_json("/api/diff")
        self.assertEqual(len(data["diff"]["added"]), 1)

    def test_scan_validation_and_no_network_for_bad_input(self):
        with mock.patch("lantern.cli.ping_host", side_effect=AssertionError("network touched")):
            status, body, _ = self.request("/api/scan", method="POST", body={"subnet": "8.8.8.0/24"})
            self.assertEqual(status, 400, body)
            self.assertIn("private", json.loads(body)["error"])
            status, body, _ = self.request("/api/scan", method="POST", body={"subnet": 42})
            self.assertEqual(status, 400, body)
            with mock.patch.object(webapp, "guess_subnet", return_value=None):
                status, body, _ = self.request("/api/scan", method="POST", body={})
                self.assertEqual(status, 400, body)
                self.assertIn("auto-detect", json.loads(body)["error"])

    def test_scan_is_serialized(self):
        self.assertTrue(webapp._scan_lock.acquire(blocking=False))
        try:
            status, body, _ = self.request("/api/scan", method="POST", body={"subnet": "10.0.0.0/24"})
        finally:
            webapp._scan_lock.release()
        self.assertEqual(status, 409, body)
        status, data = self.get_json("/api/status")
        self.assertFalse(data["scan_running"])

    def test_trust_validation(self):
        bad_bodies = [
            {"mac": "nope"},
            {"mac": "aa:bb:cc:dd:ee:ff", "trusted": "yes"},
            {"mac": "aa:bb:cc:dd:ee:ff", "label": ["x"]},
            {},
        ]
        for body in bad_bodies:
            status, text, _ = self.request("/api/trust", method="POST", body=body)
            self.assertEqual(status, 400, (body, text))
        status, text, _ = self.request("/api/trust", method="POST", body={"mac": "aa:bb:cc:dd:ee:ff", "label": "x" * 200})
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(text)["label"]), 80)

    def test_request_hygiene(self):
        status, body, _ = self.request("/api/demo", method="POST", raw=b"not json")
        self.assertEqual(status, 400)
        status, body, _ = self.request("/api/demo", method="POST", raw=b"[1, 2]")
        self.assertEqual(status, 400)
        status, body, _ = self.request(
            "/api/demo", method="POST", raw=b"{}", headers={"Content-Type": "text/plain"},
        )
        self.assertEqual(status, 415, body)
        status, body, _ = self.request(
            "/api/demo", method="POST", raw=b"{}", headers={"Content-Length": str(MAX_BODY_BYTES + 1)},
        )
        self.assertEqual(status, 413, body)
        status, body, _ = self.request(
            "/api/demo", method="POST", body={}, headers={"Origin": "http://evil.example"},
        )
        self.assertEqual(status, 403, body)
        # No Origin, with the token, is a command-line client and is allowed.
        # Sec-Fetch-Site is not the control; the token and the Host are.
        status, body, _ = self.request(
            "/api/status", method="POST", body={}, headers={"Sec-Fetch-Site": "cross-site"},
        )
        self.assertEqual(status, 404, body)
        # Same-origin browser requests carry a matching Origin and the token.
        status, body, _ = self.request(
            "/api/status", method="POST", body={}, headers={"Origin": self.base},
        )
        self.assertEqual(status, 404, body)  # route unknown, but not blocked
        status, body, _ = self.request("/nope", method="POST", body={})
        self.assertEqual(status, 404)
        status, _, _ = self.request("/api/nope")
        self.assertEqual(status, 404)

    def test_static_paths(self):
        for path in ("/../pyproject.toml", "/..%2fpyproject.toml", "/web/../cli.py", "/missing.css", "/", "/index.html"):
            status, body, headers = self.request(path)
            if path in ("/", "/index.html"):
                self.assertEqual(status, 200, path)
            else:
                self.assertEqual(status, 404, path)
                self.assertNotIn("[project]", body)
        status, _, _ = self.request("/favicon.ico")
        self.assertEqual(status, 204)
        status, body, headers = self.request("/", method="HEAD")
        self.assertEqual((status, body), (200, ""))
        self.assertGreater(int(headers["Content-Length"]), 0)


class HostAllowlistTests(unittest.TestCase):
    """F-01: DNS rebinding. Localhost listeners and in-memory data only.

    Helpers live on WebTests. This class does not subclass it, so
    the original dashboard tests are not collected twice.
    """

    setUp = WebTests.setUp
    tearDown = WebTests.tearDown
    request = WebTests.request
    _token_in = WebTests._token_in
    _fetch_token = WebTests._fetch_token
    assert_forbidden = WebTests.assert_forbidden
    get_json = WebTests.get_json

    def test_index_embeds_the_process_token(self):
        disk = (webapp.WEB_DIR / "index.html").read_text(encoding="utf-8")
        self.assertEqual(disk.count(webapp.TOKEN_PLACEHOLDER), 1)
        self.assertNotIn(self.token, disk)
        status, page, headers = self.request("/index.html")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self._token_in(page), self.token)
        self.assertEqual(self.token, self.server.RequestHandlerClass.api_token)
        status, script, _ = self.request("/app.js")
        self.assertEqual(status, 200)
        self.assertIn("X-Lantern-Token", script)
        self.assertNotIn(self.token, script)
        other = make_server(Path(self.tmp.name) / "other.db", port=0)
        try:
            self.assertNotEqual(other.RequestHandlerClass.api_token, self.token)
        finally:
            other.server_close()

    def test_f01_rebinding_repro_is_forbidden(self):
        """Matching evil Host and Origin must not read inventory or start a demo."""
        port = self.port
        evil_host = f"evil.example:{port}"
        with mock.patch("lantern.cli.run_scan", side_effect=AssertionError("scan started")):
            status, body, _ = self.request(
                "/api/demo",
                method="POST",
                body={},
                headers={"Host": evil_host, "Origin": f"http://{evil_host}"},
            )
            self.assert_forbidden(status, body)
            status, body, _ = self.request(
                "/api/scan",
                method="POST",
                body={"subnet": "192.168.1.0/24"},
                headers={"Host": evil_host, "Origin": f"http://{evil_host}"},
            )
            self.assert_forbidden(status, body)
            status, body, _ = self.request(
                "/api/trust",
                method="POST",
                body={"mac": "aa:bb:cc:dd:ee:ff", "trusted": True},
                headers={"Host": evil_host},
            )
            self.assert_forbidden(status, body)
        # The review's GET: Host evil.example, with and without the port.
        for host in ("evil.example", evil_host):
            status, body, _ = self.request("/api/scans", headers={"Host": host})
            self.assert_forbidden(status, body)
            status, body, _ = self.request("/api/report?format=html", headers={"Host": host})
            self.assert_forbidden(status, body)
        status, body, _ = self.request("/", headers={"Host": evil_host})
        self.assert_forbidden(status, body)
        self.assertNotIn(webapp.TOKEN_PLACEHOLDER, body)
        status, body, _ = self.request("/app.js", headers={"Host": evil_host})
        self.assert_forbidden(status, body)
        # Control from the review: loopback Host, foreign Origin.
        status, body, _ = self.request(
            "/api/demo",
            method="POST",
            body={},
            headers={"Host": f"127.0.0.1:{port}", "Origin": "http://evil.example"},
        )
        self.assert_forbidden(status, body)
        status, data = self.get_json("/api/status")
        self.assertEqual(data["scan_count"], 0)
        # Not a suffix or prefix match.
        for host in (f"localhost.localdomain:{port}", f"127.0.0.1.evil.example:{port}", "127.0.0.1"):
            status, body, _ = self.request("/api/status", headers={"Host": host})
            self.assert_forbidden(status, body)

    def test_valid_host_and_token_post(self):
        status, body, _ = self.request(
            "/api/demo",
            method="POST",
            body={},
            headers={"Host": f"localhost:{self.port}", "Origin": f"http://localhost:{self.port}"},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["scan_id"], 2)

    def test_missing_or_wrong_token_is_forbidden(self):
        status, data = self.get_json("/api/status")
        self.assertEqual(data["scan_count"], 0)
        for bad in (False, "wrong-token", "x" * 80, "ñ"):
            status, body, _ = self.request(
                "/api/demo",
                method="POST",
                body={},
                token=bad,
                headers={"Origin": self.base},
            )
            self.assert_forbidden(status, body)
        status, data = self.get_json("/api/status")
        self.assertEqual(data["scan_count"], 0)
        # GET does not require the token. A later valid POST still works.
        status, data = self.get_json("/api/scans")
        self.assertEqual(status, 200)
        self.assertEqual(data["scans"], [])
        status, body, _ = self.request("/api/demo", method="POST", body={})
        self.assertEqual(status, 200, body)

    def test_token_is_compared_with_compare_digest_and_not_logged(self):
        self.assertEqual(self.token, self.server.RequestHandlerClass.api_token)
        with mock.patch("lantern.webapp.hmac.compare_digest", return_value=True) as compare:
            status, body, _ = self.request("/api/status", method="POST", body={})
        self.assertEqual(status, 404, body)
        compare.assert_called_once_with(self.token, self.server.RequestHandlerClass.api_token)

        self.server.RequestHandlerClass.debug = True
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                status, body, _ = self.request("/api/demo", method="POST", body={})
                self.assertEqual(status, 200, body)
                status, page, _ = self.request("/")
                self.assertIn(self.token, page)
        finally:
            self.server.RequestHandlerClass.debug = False
        logged = err.getvalue()
        self.assertIn("POST /api/demo", logged)
        self.assertNotIn(self.token, logged)
        self.assertNotIn(webapp.TOKEN_HEADER, logged)

    def test_ipv6_loopback_host_is_allowed(self):
        host = f"[::1]:{self.port}"
        status, body, _ = self.request("/api/scans", headers={"Host": host})
        self.assertEqual(status, 200, body)
        status, page, _ = self.request("/", headers={"Host": host})
        self.assertEqual(status, 200)
        self.assertIn(self.token, page)
        status, body, _ = self.request(
            "/api/demo",
            method="POST",
            body={},
            headers={"Host": host, "Origin": f"http://[::1]:{self.port}"},
        )
        self.assertEqual(status, 200, body)
        expanded = f"[0:0:0:0:0:0:0:1]:{self.port}"
        status, body, _ = self.request("/api/status", headers={"Host": expanded})
        self.assertEqual(status, 200, body)
        wrong = 1 if self.port != 1 else 2
        status, body, _ = self.request("/api/status", headers={"Host": f"[::1]:{wrong}"})
        self.assert_forbidden(status, body)

    def test_extra_allow_host(self):
        server = make_server(Path(self.tmp.name) / "extra.db", port=0, allow_hosts=["dash.example"])
        port = server.server_address[1]
        self.assertIn(f"dash.example:{port}", server.RequestHandlerClass.allowed_hosts)
        self.assertNotIn(f"evil.example:{port}", server.RequestHandlerClass.allowed_hosts)
        explicit = 65530 if port != 65530 else 65529
        server.RequestHandlerClass.allowed_hosts = webapp.build_allowed_hosts(
            port, ["dash.example", f"other.example:{explicit}"],
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        # LIFO: shutdown runs before server_close.
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{port}"
        status, page, _ = self.request("/", base=base)
        self.assertEqual(status, 200, page)
        token = self._token_in(page)
        self.assertNotEqual(token, self.token)

        status, body, _ = self.request("/api/status", base=base, headers={"Host": f"dash.example:{port}"})
        self.assertEqual(status, 200, body)
        status, body, _ = self.request(
            "/api/demo",
            method="POST",
            body={},
            base=base,
            token=token,
            headers={
                "Host": f"other.example:{explicit}",
                "Origin": f"http://other.example:{explicit}",
            },
        )
        self.assertEqual(status, 200, body)
        status, body, _ = self.request(
            "/api/status", base=base, headers={"Host": f"other.example:{port}"},
        )
        self.assertEqual(status, 403, body)
        status, body, _ = self.request("/api/status", headers={"Host": f"dash.example:{self.port}"})
        self.assert_forbidden(status, body)

    def test_duplicate_host_or_token_headers_are_forbidden(self):
        port = self.port
        host_dup = (
            f"GET /api/status HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Host: evil.example:{port}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        token_dup = (
            f"POST /api/demo HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: 2\r\n"
            f"X-Lantern-Token: {self.token}\r\n"
            f"X-Lantern-Token: not-the-token\r\n"
            f"Connection: close\r\n\r\n"
            "{}"
        ).encode()
        for payload in (host_dup, token_dup):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.sendall(payload)
                data = b""
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    data += chunk
            self.assertTrue(data.startswith(b"HTTP/1.1 403"), data)
            self.assertNotIn(self.token.encode(), data)
            self.assertNotIn(b"evil.example", data)
        status, data = self.get_json("/api/status")
        self.assertEqual(data["scan_count"], 0)


class AllowlistUnitTests(unittest.TestCase):
    def test_defaults_and_extras(self):
        allowed = webapp.build_allowed_hosts(
            8068, ["dash.example", "Other.Example:65530", "[2001:db8::5]"],
        )
        self.assertEqual(
            allowed,
            frozenset({
                "127.0.0.1:8068",
                "localhost:8068",
                "[::1]:8068",
                "dash.example:8068",
                "other.example:65530",
                "[2001:db8::5]:8068",
            }),
        )
        self.assertNotIn("0.0.0.0:8068", allowed)
        self.assertNotIn("evil.example:8068", allowed)

    def test_unicode_host_is_punycode(self):
        allowed = webapp.build_allowed_hosts(8068, ["bücher.example"])
        self.assertIn("xn--bcher-kva.example:8068", allowed)
        self.assertEqual(
            webapp.request_host_key("xn--bcher-kva.example:8068", 8068),
            "xn--bcher-kva.example:8068",
        )

    def test_rejects_bad_hosts(self):
        bad_values = (
            "",
            "*",
            "*.home",
            "192.168.1.0/24",
            "0.0.0.0",
            "0.0.0.0:8068",
            "0",
            "00",
            "0:8068",
            "2130706433",
            "127.1",
            "127.0.1",
            "0x7f000001",
            "0177.0.0.1",
            "0x7f.1",
            "127.000.000.001",
            "[::]",
            "[fe80::1%eth0]",
            "http://dash.example",
            "bad host",
            "::1",
            "dash.example:99999",
            "user@dash.example",
            "[::1]:0",
            "dash.example/path",
            12,
        )
        for bad in bad_values:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    webapp.build_allowed_hosts(8068, [bad])
        for shorthand in ("127.1", "0x7f.1", "0177.0.0.1", "127.000.000.001", "0x7f000001"):
            with self.assertRaises(ValueError) as ctx:
                webapp.parse_allow_host(shorthand)
            message = str(ctx.exception)
            self.assertIn("full dotted form", message)
            self.assertNotIn("unspecified", message)

    def test_host_and_origin_keys(self):
        self.assertEqual(webapp.request_host_key("[0:0:0:0:0:0:0:1]:8068", 8068), "[::1]:8068")
        self.assertEqual(webapp.request_host_key("LocalHost:8068", 8068), "localhost:8068")
        self.assertEqual(webapp.request_host_key("127.0.0.1:08068", 8068), "127.0.0.1:8068")
        self.assertIsNone(webapp.request_host_key("evil.example", 8068))
        self.assertEqual(webapp.request_host_key("localhost", 80), "localhost:80")
        self.assertEqual(webapp.origin_allowlist_key("http://127.0.0.1:8068"), "127.0.0.1:8068")
        self.assertEqual(webapp.origin_allowlist_key("http://[::1]:8068"), "[::1]:8068")
        self.assertEqual(
            webapp.origin_allowlist_key("http://[0:0:0:0:0:0:0:1]:8068"),
            "[::1]:8068",
        )
        self.assertEqual(webapp.origin_allowlist_key("https://LocalHost:8068"), "localhost:8068")
        self.assertEqual(webapp.origin_allowlist_key("http://127.0.0.1"), "127.0.0.1:80")
        self.assertIsNone(webapp.origin_allowlist_key("null"))
        self.assertIsNone(webapp.origin_allowlist_key("http://evil.example:8068/steal"))
        self.assertIsNone(webapp.origin_allowlist_key("javascript:alert(1)"))
        self.assertIsNone(webapp.origin_allowlist_key("http://user:pass@127.0.0.1:8068"))

    def test_lan_allowlist_is_only_the_configured_address(self):
        allowed = webapp.build_lan_allowlist("192.168.1.50", 8068)
        self.assertEqual(allowed, frozenset({"192.168.1.50:8068"}))
        self.assertNotIn("127.0.0.1:8068", allowed)
        self.assertNotIn("localhost:8068", allowed)
        self.assertNotIn("[::1]:8068", allowed)
        self.assertNotIn("0.0.0.0:8068", allowed)

        with_name = webapp.build_lan_allowlist(
            "192.168.1.50", 8068, ["dashboard.home", "10.1.1.9:8443"],
        )
        self.assertEqual(
            with_name,
            frozenset({
                "192.168.1.50:8068",
                "dashboard.home:8068",
                "10.1.1.9:8443",
            }),
        )

        unspecified = webapp.build_lan_allowlist("0.0.0.0", 8068, ["192.168.1.50"])
        self.assertEqual(unspecified, frozenset({"192.168.1.50:8068"}))
        for host in ("0.0.0.0", "::", "0.0.0.0"):
            with self.assertRaises(ValueError):
                webapp.build_lan_allowlist(host, 8068)
            with self.assertRaises(ValueError):
                webapp.build_lan_allowlist(host, 8068, ["dashboard.home"])

    def test_banner_names_the_mode_and_omits_the_token(self):
        token = "banner-token-must-not-appear-here"
        loopback = "\n".join(webapp.startup_lines(
            "127.0.0.1", 8068, lan_bound=False,
            allowed_hosts=frozenset({"127.0.0.1:8068", "localhost:8068", "[::1]:8068"}),
        ))
        self.assertIn("http://127.0.0.1:8068/", loopback)
        self.assertIn("loopback only", loopback)
        self.assertNotIn("no login", loopback)
        self.assertNotIn("local only", loopback)
        self.assertNotIn(token, loopback)

        lan = "\n".join(webapp.startup_lines(
            "0.0.0.0", 8068, lan_bound=True,
            allowed_hosts=frozenset({"192.168.1.50:8068"}),
        ))
        self.assertIn("every API call requires the startup token", lan)
        self.assertIn("192.168.1.50:8068", lan)
        self.assertNotIn("no login", lan)
        self.assertNotIn(token, lan)

        v6 = "\n".join(webapp.startup_lines(
            "::1", 8068, lan_bound=False, allowed_hosts=frozenset({"[::1]:8068"}),
        ))
        self.assertIn("http://[::1]:8068/", v6)


class LanModeTests(unittest.TestCase):
    """LAN rules on a 127.0.0.1 listener. The allowlist host is not the socket."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.token = "LanternTokenValue0123456789abcdEF"
        self.lan_host = "192.168.1.50"
        with mock.patch("lantern.webapp.secrets.token_urlsafe", side_effect=AssertionError("second token")):
            self.server = make_server(
                Path(self.tmp.name) / "lan.db",
                host=self.lan_host,
                listen_host="127.0.0.1",
                port=0,
                lan_bound=True,
                api_token=self.token,
            )
        self.port = self.server.server_address[1]
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.base = f"http://127.0.0.1:{self.port}"
        self.host = f"{self.lan_host}:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        server = getattr(self, "server", None)
        if server is not None:
            self.server = None
            server.shutdown()
            server.server_close()
        tmp = getattr(self, "tmp", None)
        if tmp is not None:
            self.tmp = None
            tmp.cleanup()

    def request(self, path, method="GET", body=None, headers=None, token=False, raw=None):
        hdrs = {"Host": self.host, "Content-Type": "application/json"}
        if token is not False:
            hdrs[webapp.TOKEN_HEADER] = self.token if token is None else token
        hdrs.update(headers or {})
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, method=method, data=data, headers=hdrs)
        # POST /api/demo writes two scans. A 5s urlopen timeout expired on a
        # slow Windows runner while that response status line was still
        # unread. Other calls in this helper stay at 5s.
        timeout = 20 if method == "POST" and path.startswith("/api/demo") else 5
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode(), resp.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(), exc.headers

    def test_get_requires_the_one_token_and_the_page_does_not_hold_it(self):
        self.assertEqual(self.server.RequestHandlerClass.api_token, self.token)
        self.assertEqual(
            self.server.RequestHandlerClass.allowed_hosts,
            frozenset({self.host}),
        )
        for path in ("/api/scans", "/api/status", "/api/report?format=json", "/api/report?format=html"):
            status, body, _ = self.request(path)
            self.assertEqual(status, 403, (path, body))
            self.assertNotIn(self.token, body)

        status, body, _ = self.request("/api/scans", token=self.token)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["scans"], [])

        status, body, _ = self.request("/api/scans", token="not-the-lan-token-value-at-all")
        self.assertEqual(status, 403, body)
        status, body, _ = self.request("/api/scans", token=self.token[:-1])
        self.assertEqual(status, 403, body)

        status, page, _ = self.request("/")
        self.assertEqual(status, 200, page)
        self.assertNotIn(self.token, page)
        self.assertNotIn(webapp.TOKEN_PLACEHOLDER, page)
        self.assertIn('name="lantern-auth" content="token"', page)
        self.assertIn('id="token-entry"', page)
        status, page, _ = self.request("/index.html")
        self.assertNotIn(self.token, page)
        status, script, _ = self.request("/app.js")
        self.assertEqual(status, 200)
        self.assertIn("sessionStorage", script)
        self.assertIn("X-Lantern-Token", script)
        self.assertNotIn(self.token, script)

        status, body, _ = self.request(
            "/api/scans",
            headers={"Host": f"127.0.0.1:{self.port}"},
        )
        self.assertEqual(status, 403, body)
        status, body, _ = self.request(
            "/api/scans",
            token=self.token,
            headers={"Host": f"127.0.0.1:{self.port}"},
        )
        self.assertEqual(status, 403, body)
        status, body, _ = self.request(
            "/api/report?format=html",
            headers={"Host": f"127.0.0.1:{self.port}"},
        )
        self.assertEqual(status, 403, body)

    def test_post_and_report_with_the_token_and_a_foreign_origin_still_fails(self):
        evil = f"evil.example:{self.port}"
        status, body, _ = self.request(
            "/api/demo",
            method="POST",
            body={},
            token=self.token,
            headers={"Host": evil, "Origin": f"http://{evil}"},
        )
        self.assertEqual(status, 403, body)
        status, body, _ = self.request(
            "/api/demo",
            method="POST",
            body={},
            token=self.token,
            headers={"Origin": "http://evil.example"},
        )
        self.assertEqual(status, 403, body)
        status, body, _ = self.request("/api/demo", method="POST", body={})
        self.assertEqual(status, 403, body)

        status, body, _ = self.request("/api/demo", method="POST", body={}, token=self.token)
        self.assertEqual(status, 200, body)
        status, report, _ = self.request("/api/report?format=html", token=self.token)
        self.assertEqual(status, 200, report)
        self.assertIn("Telnet", report)
        status, report, _ = self.request("/api/report?format=json", token=self.token)
        self.assertEqual(status, 200, report)
        status, blocked, _ = self.request("/api/report?format=html")
        self.assertEqual(status, 403, blocked)
        self.assertNotIn("Telnet", blocked)

        blob = (Path(self.tmp.name) / "lan.db").read_bytes()
        self.assertNotIn(self.token.encode(), blob)

    def test_token_compare_is_constant_time_and_not_logged(self):
        with mock.patch("lantern.webapp.hmac.compare_digest", return_value=True) as compare:
            status, body, _ = self.request("/api/scans", token=self.token)
        self.assertEqual(status, 200, body)
        compare.assert_called_with(self.token, self.token)

        self.server.RequestHandlerClass.debug = True
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                status, body, _ = self.request("/api/scans", token=self.token)
                self.assertEqual(status, 200, body)
                status, page, _ = self.request("/")
                self.assertNotIn(self.token, page)
        finally:
            self.server.RequestHandlerClass.debug = False
        logged = err.getvalue()
        self.assertIn("GET /api/scans", logged)
        self.assertNotIn(self.token, logged)
        self.assertNotIn(webapp.TOKEN_HEADER, logged)


class HardeningTests(unittest.TestCase):
    """F-05, F-06, F-13, and N-3. Listeners are loopback only."""

    setUp = WebTests.setUp
    tearDown = WebTests.tearDown
    request = WebTests.request
    _token_in = WebTests._token_in
    _fetch_token = WebTests._fetch_token

    def test_errors_do_not_return_exception_text(self):
        secret = "secret-path-/tmp/lantern-should-not-leak"
        err = io.StringIO()
        with mock.patch("lantern.webapp.list_scans", side_effect=RuntimeError(secret)), \
                contextlib.redirect_stderr(err):
            status, body, _ = self.request("/api/scans")
        self.assertEqual(status, 500, body)
        self.assertEqual(json.loads(body), {"error": webapp.SERVER_ERROR_MESSAGE})
        self.assertNotIn(secret, body)
        self.assertNotIn("Traceback", body)
        self.assertNotIn("RuntimeError", body)
        self.assertNotIn(secret, err.getvalue())

        self.server.RequestHandlerClass.debug = True
        err = io.StringIO()
        try:
            with mock.patch("lantern.webapp.list_scans", side_effect=RuntimeError(secret)), \
                    contextlib.redirect_stderr(err):
                status, body, _ = self.request("/api/scans")
        finally:
            self.server.RequestHandlerClass.debug = False
        self.assertEqual(status, 500, body)
        self.assertNotIn(secret, body)
        self.assertIn(secret, err.getvalue())

        status, body, _ = self.request("/api/scans/" + "9" * 40)
        self.assertEqual(status, 400, body)
        self.assertNotIn("SQLite", body)
        self.assertNotIn("Python int", body)
        self.assertNotIn("Traceback", body)

    def test_absolute_form_targets_are_rejected(self):
        port = self.port

        def send(payload: bytes) -> bytes:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.sendall(payload)
                data = b""
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    data += chunk
            return data

        absolute_evil = (
            f"GET http://evil.example:{port}/api/scans HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        data = send(absolute_evil)
        self.assertTrue(data.startswith(b"HTTP/1.1 400"), data)
        self.assertNotIn(b"evil.example", data)
        self.assertNotIn(self.token.encode(), data)

        absolute_loopback = (
            f"GET http://127.0.0.1:{port}/api/scans HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        data = send(absolute_loopback)
        self.assertTrue(data.startswith(b"HTTP/1.1 400"), data)

        evil_host = (
            f"GET http://127.0.0.1:{port}/api/scans HTTP/1.1\r\n"
            f"Host: evil.example:{port}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        data = send(evil_host)
        self.assertTrue(data.startswith(b"HTTP/1.1 403"), data)

        origin = (
            f"GET /api/scans HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        data = send(origin)
        self.assertTrue(data.startswith(b"HTTP/1.1 200"), data)

    def test_connection_cap_and_timeout(self):
        self.assertEqual(webapp.MAX_BODY_BYTES, 64 * 1024)
        self.assertEqual(webapp.REQUEST_TIMEOUT_SECONDS, 10)
        self.assertEqual(self.server.RequestHandlerClass.timeout, 10)

        server = make_server(
            Path(self.tmp.name) / "cap.db",
            host="127.0.0.1",
            port=0,
            max_connections=1,
            request_timeout=2,
        )
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        self.assertEqual(server.server_address[0], "127.0.0.1")
        threading.Thread(target=server.serve_forever, daemon=True).start()

        held = socket.create_connection(("127.0.0.1", port), timeout=2)
        self.addCleanup(held.close)
        import time
        time.sleep(0.2)
        with socket.create_connection(("127.0.0.1", port), timeout=2) as extra:
            extra.settimeout(2)
            data = b""
            while True:
                try:
                    chunk = extra.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
        self.assertIn(b"503", data)
        self.assertNotIn(b"Traceback", data)

    def test_ipv6_loopback_accepts_connections(self):
        try:
            server = make_server(Path(self.tmp.name) / "v6.db", host="::1", port=0)
        except OSError as exc:
            self.skipTest(f"IPv6 loopback is not available: {exc}")
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.assertEqual(server.address_family, socket.AF_INET6)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://[::1]:{port}"
        try:
            status, page, _ = self.request("/", base=base)
        except urllib.error.URLError as exc:
            self.skipTest(f"IPv6 loopback is not reachable: {exc}")
        self.assertEqual(status, 200, page)
        self.assertNotIn(self.token, page)
        match = re.search(r'<meta name="lantern-token" content="([^"]+)"', page)
        self.assertIsNotNone(match, page)
        self.assertGreaterEqual(len(match.group(1)), 32)
        self.assertNotEqual(match.group(1), self.token)
        self.assertEqual(server.RequestHandlerClass.api_token, match.group(1))

    def test_slow_drip_cannot_hold_a_connection_past_the_header_deadline(self):
        import time

        server = make_server(
            Path(self.tmp.name) / "drip.db",
            host="127.0.0.1",
            port=0,
            request_timeout=2,
            header_timeout=0.5,
            max_connections=4,
        )
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        self.assertEqual(server.server_address[0], "127.0.0.1")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started = time.monotonic()
        sock = socket.create_connection(("127.0.0.1", port), timeout=2)
        self.addCleanup(sock.close)
        sock.sendall(b"GET / HTTP/1.1\r\n")
        closed = False
        while time.monotonic() - started < 3:
            time.sleep(0.15)
            try:
                sock.sendall(b"Y")
            except OSError:
                closed = True
                break
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.5, "slow drip held the connection past the header deadline")
        self.assertTrue(closed or elapsed < 1.2)

    def test_per_ip_cap_returns_503_before_the_global_cap(self):
        import time

        server = make_server(
            Path(self.tmp.name) / "perip.db",
            host="127.0.0.1",
            port=0,
            max_connections=4,
            max_connections_per_ip=1,
            request_timeout=2,
            header_timeout=2,
        )
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        held = socket.create_connection(("127.0.0.1", port), timeout=2)
        self.addCleanup(held.close)
        time.sleep(0.2)
        with socket.create_connection(("127.0.0.1", port), timeout=2) as extra:
            extra.settimeout(2)
            data = b""
            while True:
                try:
                    chunk = extra.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
        self.assertIn(b"503", data)
        self.assertIn(b"busy", data)

    def test_unknown_methods_are_405_after_host_and_token_checks(self):
        port = self.port
        for method in ("OPTIONS", "PUT", "DELETE", "PATCH"):
            status, body, headers = self.request("/api/scans", method=method, token=False)
            self.assertEqual(status, 405, (method, body))
            self.assertNotIn("<html", body.lower())
            self.assertEqual(json.loads(body)["error"], "Method not allowed.")
            self.assertEqual(headers["Allow"], "GET, HEAD, POST")
        status, body, _ = self.request(
            "/api/scans", method="OPTIONS", token=False,
            headers={"Host": f"evil.example:{port}"},
        )
        self.assertEqual(status, 403, body)

    def test_chunked_body_is_rejected_and_not_parsed_as_another_request(self):
        port = self.port
        payload = (
            f"POST /api/demo HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"{webapp.TOKEN_HEADER}: {self.token}\r\n"
            f"\r\n"
            f"2\r\n{{}}\r\n0\r\n\r\n"
            f"GET /api/scans HTTP/1.1\r\n"
            f"Host: evil.example:{port}\r\n"
            f"\r\n"
        ).encode()
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(payload)
            sock.settimeout(2)
            data = b""
            while True:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
        self.assertTrue(data.startswith(b"HTTP/1.1 400"), data)
        self.assertEqual(data.count(b"HTTP/1.1"), 1)
        self.assertNotIn(b"evil.example", data)
        self.assertNotIn(self.token.encode(), data)
        self.assertIn(b"Connection: close", data)

    def test_get_with_a_body_is_not_parsed_as_a_second_request(self):
        port = self.port
        smuggled = (
            f"GET /api/scans HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"\r\n"
        ).encode()
        payload = (
            f"GET / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Content-Length: {len(smuggled)}\r\n"
            f"\r\n"
        ).encode() + smuggled
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(payload)
            sock.settimeout(2)
            data = b""
            while True:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
        self.assertTrue(data.startswith(b"HTTP/1.1 200"), data)
        self.assertEqual(data.count(b"HTTP/1.1"), 1)
        self.assertIn(b"Connection: close", data)
        self.assertNotIn(b'"scans"', data)

        head = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Content-Length: {len(smuggled)}\r\n"
            f"\r\n"
        ).encode() + smuggled
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(head)
            sock.settimeout(2)
            data = b""
            while True:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
        self.assertTrue(data.startswith(b"HTTP/1.1 200"), data)
        self.assertEqual(data.count(b"HTTP/1.1"), 1)
        self.assertIn(b"Connection: close", data)

    def test_empty_transfer_encoding_is_rejected(self):
        port = self.port
        payload = (
            f"GET / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Transfer-Encoding:\r\n"
            f"\r\n"
            f"GET /api/scans HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"\r\n"
        ).encode()
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(payload)
            sock.settimeout(2)
            data = b""
            while True:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
        self.assertTrue(data.startswith(b"HTTP/1.1 400"), data)
        self.assertEqual(data.count(b"HTTP/1.1"), 1)
        self.assertIn(b"Connection: close", data)
        self.assertNotIn(b'"scans"', data)

    def test_socket_timeout_is_restored_for_the_response_write(self):
        seen = {}
        server = make_server(
            Path(self.tmp.name) / "timeout.db",
            host="127.0.0.1",
            port=0,
            request_timeout=5,
            header_timeout=2,
        )
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        original = server.RequestHandlerClass.end_headers

        def wrapped(handler):
            original(handler)
            seen["timeout"] = handler.connection.gettimeout()

        server.RequestHandlerClass.end_headers = wrapped
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        status, _body, _headers = self.request("/", base=f"http://127.0.0.1:{port}")
        self.assertEqual(status, 200)
        self.assertEqual(seen["timeout"], 5)

    def test_slow_body_drip_is_closed_by_the_request_deadline(self):
        import time

        server = make_server(
            Path(self.tmp.name) / "body-drip.db",
            host="127.0.0.1",
            port=0,
            request_timeout=2,
            header_timeout=3.2,
            api_token=self.token,
        )
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        headers = (
            f"POST /api/demo HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: 40\r\n"
            f"{webapp.TOKEN_HEADER}: {self.token}\r\n"
            f"\r\n"
        ).encode()
        started = time.monotonic()
        sock = socket.create_connection(("127.0.0.1", port), timeout=2)
        self.addCleanup(sock.close)
        sock.sendall(headers)
        closed = False
        while time.monotonic() - started < 12:
            time.sleep(1.5)
            try:
                sock.sendall(b"{")
            except OSError:
                closed = True
                break
        elapsed = time.monotonic() - started
        # An immediate 403 (token never checked against a real body read)
        # closes in about 1.5 s. The 3.2 s deadline is noticed on the next
        # drip, before 7.5 s. Without a body deadline the loop runs to 8 s.
        self.assertGreater(elapsed, 2.5, elapsed)
        self.assertLess(elapsed, 7.5, "slow body drip held the connection past the request deadline")
        self.assertTrue(closed)
        self.assertEqual(server.RequestHandlerClass.api_token, self.token)

    def test_large_response_reaches_a_slow_reader(self):
        import time

        from urllib.parse import urlparse

        # Bigger than a 16 KiB send buffer, and slow enough that delivery
        # takes longer than write_timeout. A single timeout for the whole
        # send would stop early. Chunks plus a longer overall cap finish.
        payload = b"L" * (256 * 1024)
        write_timeout = 0.35
        server = make_server(
            Path(self.tmp.name) / "big.db",
            host="127.0.0.1",
            port=0,
            request_timeout=30,
            write_timeout=write_timeout,
            write_deadline=8,
        )
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        original_setup = server.RequestHandlerClass.setup
        original_get = server.RequestHandlerClass.do_GET

        def setup(handler):
            original_setup(handler)
            handler.connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 * 1024)

        def do_GET(handler):
            if urlparse(handler.path).path == "/big":
                handler._send_bytes(200, payload, "application/octet-stream")
                return
            return original_get(handler)

        server.RequestHandlerClass.setup = setup
        server.RequestHandlerClass.do_GET = do_GET
        port = server.server_address[1]
        self.assertEqual(server.server_address[0], "127.0.0.1")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.addCleanup(sock.close)
        sock.sendall(
            f"GET /big HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
        )
        sock.settimeout(8)
        started = time.monotonic()
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        match = re.search(br"Content-Length: (\d+)", head)
        self.assertIsNotNone(match, head)
        needed = int(match.group(1))
        self.assertEqual(needed, len(payload))
        while len(rest) < needed:
            time.sleep(0.02)
            chunk = sock.recv(4096)
            if not chunk:
                break
            rest += chunk
        elapsed = time.monotonic() - started
        self.assertGreater(elapsed, write_timeout, elapsed)
        self.assertEqual(rest, payload)

    def test_write_chunk_timeout_is_capped_by_the_deadline(self):
        """A stalled chunk cannot wait the full write timeout past the deadline.

        The overall cap used to be checked only between chunks, and each
        chunk then waited the full write_timeout. One chunk could hold a
        slot for about write_deadline plus write_timeout. The chunk's
        socket timeout is now the time remaining.
        """
        import time

        write_timeout = 1.5
        write_deadline = 0.3
        server = make_server(
            Path(self.tmp.name) / "write-cap.db",
            host="127.0.0.1",
            port=0,
            write_timeout=write_timeout,
            write_deadline=write_deadline,
        )
        self.addCleanup(server.server_close)
        handler = server.RequestHandlerClass.__new__(server.RequestHandlerClass)
        self.assertEqual(handler.write_deadline, write_deadline)
        self.assertEqual(handler.write_timeout, write_timeout)
        handler.close_connection = False
        seen = []

        class Stalled:
            def settimeout(self, value):
                seen.append(float(value))

            def send(self, data):
                # A reader that takes nothing blocks until this chunk's timeout.
                time.sleep(seen[-1])
                raise TimeoutError("chunk stalled")

        handler.connection = Stalled()
        started = time.monotonic()
        handler._write_all(b"W" * 64)
        elapsed = time.monotonic() - started
        self.assertTrue(handler.close_connection)
        self.assertTrue(seen, "no chunk timeout was set")
        self.assertLessEqual(seen[0], write_deadline + 0.05, seen)
        self.assertLess(seen[0], write_timeout)
        self.assertLess(
            elapsed,
            write_timeout * 0.6,
            f"chunk blocked for {elapsed:.2f}s after a {write_deadline}s deadline",
        )

    def test_trace_and_connect_close_once(self):
        port = self.port
        for method in ("TRACE", "CONNECT"):
            target = "/" if method == "TRACE" else "127.0.0.1:1"
            payload = (
                f"{method} {target} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                f"\r\n"
            ).encode()
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.sendall(payload)
                sock.settimeout(2)
                data = b""
                while True:
                    try:
                        chunk = sock.recv(8192)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    data += chunk
            self.assertTrue(data.startswith(b"HTTP/1.1 501"), (method, data[:40]))
            self.assertEqual(data.lower().count(b"connection: close"), 1, (method, data.split(b"\r\n\r\n", 1)[0]))

    def test_bad_content_length_does_not_serve_a_smuggled_request(self):
        port = self.port
        smuggled = (
            f"GET /api/scans HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"\r\n"
        ).encode()
        for value in ("abc", "-1", "1e3", "5, 5", "+2"):
            payload = (
                f"GET / HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                f"Content-Length: {value}\r\n"
                f"\r\n"
            ).encode() + smuggled
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.sendall(payload)
                sock.settimeout(2)
                data = b""
                while True:
                    try:
                        chunk = sock.recv(8192)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    data += chunk
            self.assertTrue(data.startswith(b"HTTP/1.1 400"), (value, data[:80]))
            self.assertEqual(data.count(b"HTTP/1.1"), 1, (value, data[:120]))
            self.assertEqual(data.lower().count(b"connection: close"), 1, value)
            self.assertNotIn(b'"scans"', data, value)
        duplicate = (
            f"POST /nope HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Content-Length: 5\r\n"
            f"Content-Length: 5\r\n"
            f"\r\n"
        ).encode() + smuggled
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(duplicate)
            sock.settimeout(2)
            data = b""
            while True:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
        self.assertTrue(data.startswith(b"HTTP/1.1 400"), data[:80])
        self.assertNotIn(b"404", data)
        self.assertEqual(data.count(b"HTTP/1.1"), 1)
        self.assertNotIn(b'"scans"', data)


class LanMethodTests(unittest.TestCase):
    """PUT and OPTIONS in LAN mode. The listener is 127.0.0.1."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.token = "LanternTokenValue0123456789abcdEF"
        self.server = make_server(
            Path(self.tmp.name) / "lan.db",
            host="192.168.1.50",
            listen_host="127.0.0.1",
            port=0,
            lan_bound=True,
            api_token=self.token,
        )
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.host = f"192.168.1.50:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def request(self, method, token=False, host=None):
        hdrs = {"Host": host or self.host, "Content-Type": "application/json"}
        if token is not False:
            hdrs[webapp.TOKEN_HEADER] = self.token if token is None else token
        req = urllib.request.Request(self.base + "/api/scans", method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode(), resp.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(), exc.headers

    def test_put_and_options_need_the_token_then_return_405(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        for method in ("PUT", "OPTIONS", "DELETE", "PATCH"):
            status, body, _headers = self.request(method)
            self.assertEqual(status, 403, (method, body))
            self.assertNotIn(self.token, body)
            status, body, headers = self.request(method, token=self.token)
            self.assertEqual(status, 405, (method, body))
            self.assertEqual(json.loads(body), {"error": "Method not allowed."})
            self.assertEqual(headers["Allow"], "GET, HEAD, POST")
            self.assertNotIn("<html", body.lower())
        status, body, _headers = self.request(
            "OPTIONS", token=self.token, host=f"evil.example:{self.port}",
        )
        self.assertEqual(status, 403, body)
        status, body, _headers = self.request("OPTIONS", token="not-the-token-but-long-enoughxx")
        self.assertEqual(status, 403, body)


class StrictAuthTests(unittest.TestCase):
    """Strict auth on loopback. This is the default. The server is built with strict_auth=True."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.token = "s" * 32
        self.server = make_server(
            Path(self.tmp.name) / "strict.db",
            host="127.0.0.1",
            port=0,
            api_token=self.token,
            strict_auth=True,
        )
        self.addCleanup(self._close)
        self.port = self.server.server_address[1]
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def _close(self):
        server = getattr(self, "server", None)
        if server is not None:
            self.server = None
            server.shutdown()
            server.server_close()
        tmp = getattr(self, "tmp", None)
        if tmp is not None:
            self.tmp = None
            tmp.cleanup()

    def request(self, path, method="GET", body=None, token=False):
        hdrs = {"Host": f"127.0.0.1:{self.port}", "Content-Type": "application/json"}
        if token is not False:
            hdrs[webapp.TOKEN_HEADER] = self.token if token is None else token
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, method=method, data=data, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode(), resp.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(), exc.headers

    def test_page_and_headers_do_not_contain_the_token(self):
        status, page, headers = self.request("/")
        self.assertEqual(status, 200, page)
        self.assertNotIn(self.token, page)
        self.assertNotIn(webapp.TOKEN_PLACEHOLDER, page)
        self.assertIn('name="lantern-auth" content="strict"', page)
        self.assertIn('name="lantern-token" content=""', page)
        for key, value in headers.items():
            self.assertNotIn(self.token, str(key))
            self.assertNotIn(self.token, str(value))
        self.assertIsNone(headers.get("Set-Cookie"))
        status, page, headers = self.request("/index.html")
        self.assertEqual(status, 200)
        self.assertNotIn(self.token, page)
        for _key, value in headers.items():
            self.assertNotIn(self.token, str(value))
        status, script, _ = self.request("/app.js")
        self.assertEqual(status, 200)
        self.assertNotIn(self.token, script)

    def test_every_get_api_route_requires_the_token(self):
        paths = (
            "/api/status",
            "/api/scans",
            "/api/scans/latest",
            "/api/diff",
            "/api/report?format=json",
            "/api/report?format=html",
        )
        for path in paths:
            with mock.patch("lantern.webapp.time.sleep") as slept:
                status, body, _headers = self.request(path)
            self.assertEqual(status, 403, (path, body))
            self.assertEqual(json.loads(body), {"error": webapp.FORBIDDEN_MESSAGE})
            self.assertNotIn(self.token, body)
            slept.assert_not_called()
        for path in ("/api/status", "/api/scans", "/api/scans/latest", "/api/diff"):
            status, body, _headers = self.request(path, token=self.token)
            self.assertEqual(status, 200, (path, body))
            self.assertNotIn(self.token, body)
        for path in ("/api/report?format=json", "/api/report?format=html"):
            status, body, _headers = self.request(path, token=self.token)
            self.assertEqual(status, 404, (path, body))
            self.assertIn("No scans yet", body)
            self.assertNotIn(self.token, body)

    def test_presented_mismatch_uses_the_same_delay(self):
        with mock.patch("lantern.webapp.time.sleep") as slept, \
                mock.patch("lantern.webapp.hmac.compare_digest", return_value=False) as compare:
            status, body, _headers = self.request("/api/status", token="w" * 32)
        self.assertEqual(status, 403, body)
        compare.assert_called()
        slept.assert_called_with(webapp.TOKEN_FAILURE_DELAY_SECONDS)

    def test_post_scan_requires_the_token_and_then_runs(self):
        with mock.patch("lantern.cli.run_scan", side_effect=AssertionError("scan started")):
            status, body, _headers = self.request(
                "/api/scan", method="POST", body={"subnet": "192.168.1.0/24"},
            )
        self.assertEqual(status, 403, body)
        with mock.patch("lantern.cli.run_scan", return_value=[]) as run_scan:
            status, body, _headers = self.request(
                "/api/scan", method="POST", body={"subnet": "192.168.1.0/24"}, token=self.token,
            )
        self.assertEqual(status, 200, body)
        run_scan.assert_called_once()

    def test_opt_out_loopback_embeds_the_token_and_allows_get(self):
        """``strict_auth=False`` is the ``--no-strict-auth`` server."""
        server = make_server(
            Path(self.tmp.name) / "legacy.db", host="127.0.0.1", port=0, strict_auth=False,
        )
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        self.assertFalse(server.RequestHandlerClass.strict_auth)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        req = urllib.request.Request(f"http://127.0.0.1:{port}/", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            page = resp.read().decode()
        match = _TOKEN_RE.search(page)
        self.assertIsNotNone(match)
        token = match.group(1)
        self.assertEqual(token, server.RequestHandlerClass.api_token)
        status_req = urllib.request.Request(f"http://127.0.0.1:{port}/api/status", method="GET")
        with urllib.request.urlopen(status_req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)

    def test_fragment_handler_keeps_the_token_out_of_the_request(self):
        script = (webapp.WEB_DIR / "app.js").read_text(encoding="utf-8")
        start = script.index("function takeFragmentToken()")
        body = script[start:script.index("function showTokenPrompt")]
        self.assertIn("#token=", body)
        self.assertIn("decodeURIComponent", body)
        self.assertIn("sessionStorage.setItem(TOKEN_STORAGE, value)", body)
        self.assertIn("history.replaceState", body)
        self.assertNotIn("fetch(", body)
        self.assertNotIn("XMLHttpRequest", body)
        call = script.index("takeFragmentToken();")
        guard = script.rfind("if (needsStoredToken())", 0, call)
        self.assertGreater(guard, start)
        self.assertNotIn("else", script[guard:call])
        self.assertEqual(script.count("takeFragmentToken();"), 1)
        self.assertIn('headers["X-Lantern-Token"] = token', script)

    def test_stale_token_is_cleared_for_strict_auth_and_not_for_default_mode(self):
        """Run app.js under node with a fake page. Skip when node is absent.

        Default mode must ignore a #token= fragment and prefer the page token.
        Strict mode must store the fragment, then clear it and show the prompt
        after a 403 from the API and from the report link.
        """
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed; app.js was not executed")
        script = r"""
const fs = require("fs");
const vm = require("vm");
const app = fs.readFileSync(process.argv[1], "utf8");

function load(auth, pageToken, hash) {
  const store = {};
  const meta = { "lantern-token": pageToken, "lantern-auth": auth };
  const listeners = {};
  const elements = {};
  function el(id) {
    if (!elements[id]) {
      elements[id] = {
        id, hidden: true, textContent: "", value: "", className: "",
        href: "/api/report?format=html", disabled: false,
        addEventListener(type, fn) { listeners[id + ":" + type] = fn; },
        getAttribute(name) { return name === "href" ? this.href : ""; },
      };
    }
    return elements[id];
  }
  let fetchMode = "ok";
  const context = {
    sessionStorage: {
      getItem: (k) => (Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null),
      setItem: (k, v) => { store[k] = String(v); },
      removeItem: (k) => { delete store[k]; },
    },
    document: {
      getElementById: el,
      querySelector(sel) {
        const match = /meta\[name="([^"]+)"\]/.exec(sel);
        if (!match) return null;
        const name = match[1];
        return { getAttribute: (attr) => (attr === "content" ? meta[name] || "" : "") };
      },
      body: { setAttribute() {} },
    },
    window: { open() {} },
    history: { replaceState() {} },
    URL: { createObjectURL: () => "blob:test" },
    fetch: async () => {
      if (fetchMode === "403") {
        return { ok: false, status: 403, json: async () => ({ error: "Forbidden." }), text: async () => "" };
      }
      return {
        ok: true, status: 200,
        json: async () => ({
          scan_count: 0, latest_scan_id: null, scan_running: false, version: "t",
          scans: [], scan: null, diff: null,
        }),
        text: async () => "<p>ok</p>",
      };
    },
    console,
  };
  context.window.location = { hash, pathname: "/", search: "" };
  vm.createContext(context);
  vm.runInContext(app, context);
  return { context, store, elements, listeners, setFetch: (mode) => { fetchMode = mode; } };
}

const fallback = load("page", "page-token", "#token=junk");
if (fallback.store["lantern-token"]) process.exit(2);
fallback.store["lantern-token"] = "junk";
if (fallback.context.lanternToken() !== "page-token") process.exit(3);
fallback.setFetch("403");
fallback.context.api("/api/status").catch(() => {}).then(() => {
  if (fallback.store["lantern-token"] !== "junk") process.exit(4);
  const strict = load("strict", "", "#token=from-fragment");
  if (strict.store["lantern-token"] !== "from-fragment") process.exit(5);
  strict.setFetch("403");
  return strict.context.api("/api/status").catch((err) => {
    if (!String(err).includes("Forbidden")) throw err;
  }).then(() => {
    if (Object.prototype.hasOwnProperty.call(strict.store, "lantern-token")) process.exit(6);
    if (strict.elements["token-entry"].hidden !== false) process.exit(7);
    strict.store["lantern-token"] = "stale";
    return strict.listeners["report-link:click"]({ preventDefault() {} });
  }).then(() => {
    if (Object.prototype.hasOwnProperty.call(strict.store, "lantern-token")) process.exit(8);
  });
}).catch((err) => { console.error(err); process.exit(9); });
"""
        proc = subprocess.run(
            [node, "-e", script, str(webapp.WEB_DIR / "app.js")],
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)

    def test_dashboard_escapes_scope_and_device_fields(self):
        """app.js must escape scope, banner, hostname, label, owner, tag, and notes."""
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed; app.js was not executed")
        script = r"""
const fs = require("fs");
const vm = require("vm");
const app = fs.readFileSync(process.argv[1], "utf8");
const elements = {};
function el(id) {
  if (!elements[id]) {
    elements[id] = {
      id, hidden: true, textContent: "", value: "", className: "",
      innerHTML: "", href: "", disabled: false,
      addEventListener() {},
      getAttribute() { return ""; },
      querySelectorAll() { return []; },
    };
  }
  return elements[id];
}
const context = {
  sessionStorage: { getItem() { return null; }, setItem() {}, removeItem() {} },
  document: {
    getElementById: el,
    querySelector() { return { getAttribute() { return ""; } }; },
    body: { setAttribute() {} },
  },
  window: { open() {} },
  history: { replaceState() {} },
  URL: { createObjectURL: () => "blob:test" },
  fetch: async () => ({
    ok: true, status: 200,
    json: async () => ({
      scan_count: 0, latest_scan_id: null, scan_running: false, version: "t",
      scans: [], scan: null, diff: null,
    }),
    text: async () => "",
  }),
  console,
};
context.window.location = { hash: "", pathname: "/", search: "" };
vm.createContext(context);
vm.runInContext(app, context);
const payload = "<script>alert(1)</script>";
const html = context.renderDevice({
  ip: "192.168.50.10",
  mac: "aa:bb:cc:dd:ee:10",
  hostname: payload + "hostname",
  label: payload + "label",
  owner: payload + "owner",
  tags: [payload + "tag"],
  notes: payload + "notes",
  trusted: false,
  open_ports: [{ port: 80, banner: payload + "banner" }],
  findings: [],
});
if (html.includes("<script>")) process.exit(2);
for (const field of ["hostname", "label", "owner", "tag", "notes", "banner"]) {
  if (!html.includes("&lt;script&gt;alert(1)&lt;/script&gt;" + field)) {
    console.error("missing " + field);
    process.exit(3);
  }
}
context.renderSummary({
  id: 1, devices: [], subnet: "192.168.50.0/24",
  scope_name: payload + "scope", started_at: "2026-10-28T00:00:00Z", demo: false,
}, null);
const summary = elements.summary.innerHTML;
if (summary.includes("<script>") || !summary.includes("&lt;script&gt;alert(1)&lt;/script&gt;scope")) {
  console.error(summary);
  process.exit(4);
}
const option = context.historyOption({
  id: 3, started_at: "2026-10-28T00:00:00Z", device_count: 1, demo: false,
  scope_name: payload + "scope",
});
if (option.includes("<script>") || !option.includes("&lt;script&gt;alert(1)&lt;/script&gt;scope")) {
  console.error(option);
  process.exit(5);
}
"""
        proc = subprocess.run(
            [node, "-e", script, str(webapp.WEB_DIR / "app.js")],
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)

    def test_strict_auth_without_a_token_is_refused(self):
        with self.assertRaises(ValueError):
            make_server(
                Path(self.tmp.name) / "missing.db",
                host="127.0.0.1",
                port=0,
                strict_auth=True,
            )


if __name__ == "__main__":
    unittest.main()
