"""End-to-end tests for the stdlib web dashboard. Run: python3 tests/test_web.py"""

import json
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


class WebTests(unittest.TestCase):
    def setUp(self):
        # Fresh database and server per test, so ids are predictable.
        self.tmp = tempfile.TemporaryDirectory()
        self.server = make_server(Path(self.tmp.name) / "test.db", port=0)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def request(self, path, method="GET", body=None, headers=None, raw=None):
        hdrs = {"Content-Type": "application/json"}
        hdrs.update(headers or {})
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, method=method, data=data, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode(), resp.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(), exc.headers

    def get_json(self, path):
        status, body, _ = self.request(path)
        return status, json.loads(body)

    def test_flow(self):
        status, body, headers = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn("Lantern", body)
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
        status, body, _ = self.request(
            "/api/demo", method="POST", body={}, headers={"Sec-Fetch-Site": "cross-site"},
        )
        self.assertEqual(status, 403, body)
        # Same-origin browser requests carry a matching Origin and are fine.
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


if __name__ == "__main__":
    unittest.main()
