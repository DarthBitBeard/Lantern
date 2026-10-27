"""End-to-end tests for the stdlib web dashboard. Run: python3 tests/test_web.py"""

import json
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lantern.webapp import LanternHandler  # noqa: E402


def _request(base, path, method="GET", body=None):
    req = urllib.request.Request(
        base + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def main():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        handler = type("TestHandler", (LanternHandler,), {"db_path": str(db_path)})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{port}"
        try:
            status, body = _request(base, "/")
            assert status == 200 and "Lantern" in body, f"index failed: {status}"
            status, body = _request(base, "/api/status")
            assert status == 200, body
            assert json.loads(body)["scan_count"] == 0, body

            status, body = _request(base, "/api/demo", method="POST", body={})
            assert status == 200, body
            data = json.loads(body)
            assert len(data["scan"]["devices"]) == 6, body
            assert len(data["diff"]["added"]) == 1, body

            mac = "de:ad:be:ef:00:99"
            status, body = _request(
                base, "/api/trust", method="POST",
                body={"mac": mac, "label": "Mystery box", "trusted": True},
            )
            assert status == 200, body

            status, body = _request(base, "/api/scans/latest")
            devices = {d["ip"]: d for d in json.loads(body)["scan"]["devices"]}
            assert devices["192.168.1.99"]["trusted"] is True, body
            assert devices["192.168.1.99"]["label"] == "Mystery box", body

            status, body = _request(base, "/api/scan", method="POST", body={"subnet": "8.8.8.0/24"})
            assert status == 400, f"public scan not refused: {status} {body}"

            status, body = _request(base, "/api/report?format=html")
            assert status == 200 and "Telnet" in body, body

            status, body = _request(base, "/api/scans")
            assert json.loads(body)["scans"][0]["device_count"] == 6, body
            print("web tests passed: index, status, demo, trust, public-scan refusal, report, history")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
