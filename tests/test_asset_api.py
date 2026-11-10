"""POST /api/v1/assets/{key}. Localhost and rows inserted in the test only."""

import json
import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

from lantern.assets import get_asset
from lantern.store import connect, get_trusted, save_scan
from lantern.webapp import make_server


def _device(ip, mac=None, hostname=None):
    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "label": None,
        "open_ports": [],
        "findings": [],
    }


class AssetWriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.db"
        self.server = make_server(self.db, port=0)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        status, body, _ = self._request("GET", "/")
        match = re.search(r'<meta name="lantern-token" content="([^"]+)"', body)
        self.assertIsNotNone(match, body)
        self.token = match.group(1)
        self._seed()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def _seed(self):
        conn = connect(self.db)
        try:
            save_scan(
                conn,
                "192.168.50.0/24",
                [
                    _device("192.168.50.10", "aa:bb:cc:dd:ee:10", hostname="named"),
                    _device("192.168.50.2", None, hostname="bare"),
                ],
            )
        finally:
            conn.close()

    def _request(self, method, path, body=None, token=None, origin=None, host=None, cookie=None):
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["X-Lantern-Token"] = token
        if origin is not None:
            headers["Origin"] = origin
        if host is not None:
            headers["Host"] = host
        if cookie is not None:
            headers["Cookie"] = cookie
        request = urllib.request.Request(
            self.base + path, data=data, method=method, headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, response.read().decode(), response.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(), exc.headers

    def _post(self, key, body, **kwargs):
        return self._request("POST", "/api/v1/assets/" + quote(key, safe=""), body, **kwargs)

    def _no_cors(self, headers):
        self.assertFalse(any(name.lower().startswith("access-control-") for name in headers))

    def _asset(self, key):
        conn = connect(self.db)
        try:
            return get_asset(conn, key)
        finally:
            conn.close()

    def test_auth_host_and_origin(self):
        payload = {"updated_at": None, "owner": "Sam"}
        status, body, headers = self._post("aa:bb:cc:dd:ee:10", payload)
        self.assertEqual(status, 403, body)
        self.assertEqual(json.loads(body)["error"]["code"], "forbidden")
        self._no_cors(headers)

        status, body, headers = self._post("aa:bb:cc:dd:ee:10", payload, token="not-the-token")
        self.assertEqual(status, 403, body)
        self._no_cors(headers)

        status, body, _ = self._request(
            "POST",
            "/api/v1/assets/" + quote("aa:bb:cc:dd:ee:10", safe="") + "?token=" + self.token,
            payload,
        )
        self.assertEqual(status, 403, body)

        status, body, _ = self._post(
            "aa:bb:cc:dd:ee:10",
            {"token": self.token, "updated_at": None, "owner": "Sam"},
        )
        self.assertEqual(status, 403, body)
        self.assertIsNone(self._asset("mac:aa:bb:cc:dd:ee:10"))

        status, body, _ = self._post(
            "aa:bb:cc:dd:ee:10", payload, cookie=f"token={self.token}",
        )
        self.assertEqual(status, 403, body)

        status, body, headers = self._post(
            "aa:bb:cc:dd:ee:10", payload, token=self.token,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["api_version"], 1)
        self._no_cors(headers)
        self.assertEqual(json.loads(body)["owner"], "Sam")

        status, body, headers = self._post(
            "aa:bb:cc:dd:ee:10",
            {"updated_at": json.loads(body)["updated_at"], "location": "Rack"},
            token=self.token,
            origin=f"http://127.0.0.1:{self.port}",
        )
        self.assertEqual(status, 200, body)
        self._no_cors(headers)

        status, body, headers = self._post(
            "aa:bb:cc:dd:ee:10",
            {"updated_at": json.loads(body)["updated_at"], "notes": "no"},
            token=self.token,
            origin="http://evil.example",
        )
        self.assertEqual(status, 403, body)
        self._no_cors(headers)
        self.assertIsNone(self._asset("mac:aa:bb:cc:dd:ee:10")["notes"])

        status, _, _ = self._post(
            "aa:bb:cc:dd:ee:10",
            payload,
            token=self.token,
            host="evil.example:9",
        )
        self.assertNotEqual(status, 200)

    def test_keys(self):
        status, body, _ = self._post(
            "192.168.50.2", {"updated_at": None, "owner": "Bare"}, token=self.token,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["key_type"], "ip")
        self.assertEqual(self._asset("ip:192.168.50.2")["owner"], "Bare")

        status, body, _ = self._post(
            "mac:aa:bb:cc:dd:ee:10", {"updated_at": None, "owner": "No"}, token=self.token,
        )
        self.assertEqual(status, 400, body)
        self.assertEqual(json.loads(body)["error"]["code"], "bad_request")
        self.assertEqual(json.loads(body)["api_version"], 1)

        status, body, _ = self._post(
            "ip:192.168.50.2", {"updated_at": None, "owner": "No"}, token=self.token,
        )
        self.assertEqual(status, 400, body)

        status, body, _ = self._post(
            "aa:bb:cc:dd:ee:99", {"updated_at": None, "owner": "No"}, token=self.token,
        )
        self.assertEqual(status, 404, body)
        self.assertEqual(json.loads(body)["error"]["code"], "not_found")
        self.assertNotIn("aa:bb:cc:dd:ee:99", json.loads(body)["error"]["message"])

        encoded = quote("aa:bb:cc:dd:ee:10", safe="")
        status, body, _ = self._request(
            "GET", "/api/v1/assets/" + encoded, token=self.token,
        )
        self.assertEqual(status, 405, body)
        self.assertEqual(json.loads(body)["error"]["code"], "method_not_allowed")

    def test_validation_matches_the_cli_limits(self):
        mac = "aa:bb:cc:dd:ee:10"
        status, body, _ = self._post(
            mac, {"updated_at": None, "owner": "A" * 81}, token=self.token,
        )
        self.assertEqual(status, 422, body)
        payload = json.loads(body)
        self.assertEqual(payload["api_version"], 1)
        self.assertEqual(payload["error"]["code"], "validation")
        self.assertEqual(payload["error"]["fields"]["owner"], "too_long")
        self.assertIsNone(self._asset("mac:" + mac))

        status, body, _ = self._post(
            mac, {"updated_at": None, "owner": "   "}, token=self.token,
        )
        self.assertEqual(json.loads(body)["error"]["fields"]["owner"], "blank")

        status, body, _ = self._post(
            mac, {"updated_at": None, "notes": "line\u2028break"}, token=self.token,
        )
        self.assertEqual(json.loads(body)["error"]["fields"]["notes"], "invalid")

        status, body, _ = self._post(
            mac, {"updated_at": None, "notes": "bell\x07"}, token=self.token,
        )
        self.assertEqual(json.loads(body)["error"]["fields"]["notes"], "invalid")

        status, body, _ = self._post(
            mac, {"updated_at": None, "tags": None}, token=self.token,
        )
        self.assertEqual(json.loads(body)["error"]["fields"]["tags"], "null_forbidden")

        status, body, _ = self._post(
            mac, {"updated_at": None, "tags": [f"t{index}" for index in range(11)]}, token=self.token,
        )
        self.assertEqual(json.loads(body)["error"]["fields"]["tags"], "too_many")

        status, body, _ = self._post(
            mac, {"updated_at": None, "tags": ["Bad Tag"]}, token=self.token,
        )
        self.assertEqual(json.loads(body)["error"]["fields"]["tags"], "invalid")

        status, body, _ = self._post(
            mac, {"updated_at": None, "criticality": "nope"}, token=self.token,
        )
        self.assertEqual(json.loads(body)["error"]["fields"]["criticality"], "invalid")

        status, body, _ = self._post(
            mac, {"updated_at": None, "owner": "Sam", "sneaky_field": "x"}, token=self.token,
        )
        self.assertEqual(status, 400, body)
        self.assertNotIn("sneaky_field", body)
        self.assertIsNone(self._asset("mac:" + mac))

        status, body, _ = self._post(mac, {"owner": "Sam"}, token=self.token)
        self.assertEqual(json.loads(body)["error"]["fields"]["updated_at"], "required")

        status, body, _ = self._post(
            mac, {"updated_at": 1, "owner": "Sam"}, token=self.token,
        )
        self.assertEqual(json.loads(body)["error"]["fields"]["updated_at"], "invalid")

        status, body, _ = self._post(
            mac, {"updated_at": None, "owner": "invalid"}, token=self.token,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["owner"], "invalid")
        status, body, _ = self._post(
            mac,
            {"updated_at": json.loads(body)["updated_at"], "owner": None},
            token=self.token,
        )
        self.assertEqual(status, 200, body)

        xss = '<img src=x onerror="alert(1)">'
        status, body, _ = self._post(
            mac, {"updated_at": None, "owner": xss}, token=self.token,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["owner"], xss)
        self.assertEqual(self._asset("mac:" + mac)["owner"], xss)

    def test_concurrency_and_partial_updates(self):
        mac = "aa:bb:cc:dd:ee:10"
        status, body, _ = self._post(
            mac,
            {"updated_at": None, "owner": "Sam", "location": "Rack", "tags": ["Web", "web"], "notes": "n"},
            token=self.token,
        )
        self.assertEqual(status, 200, body)
        saved = json.loads(body)
        self.assertTrue(saved["updated_at"].endswith("Z"))
        self.assertEqual(saved["tags"], ["web"])

        plus = saved["updated_at"].replace("Z", "+00:00")
        status, body, _ = self._post(
            mac, {"updated_at": plus, "owner": "Ada"}, token=self.token,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["owner"], "Ada")
        self.assertEqual(json.loads(body)["location"], "Rack")
        self.assertEqual(json.loads(body)["tags"], ["web"])

        status, body, _ = self._post(
            mac, {"updated_at": saved["updated_at"], "notes": "stale"}, token=self.token,
        )
        self.assertEqual(status, 409, body)
        self.assertEqual(json.loads(body)["error"]["code"], "conflict")
        self.assertNotIn("fields", json.loads(body)["error"])
        self.assertEqual(self._asset("mac:" + mac)["notes"], "n")

        status, body, _ = self._post(
            "192.168.50.2", {"updated_at": "2020-01-01T00:00:00Z", "owner": "No"}, token=self.token,
        )
        self.assertEqual(status, 409, body)
        self.assertIsNone(self._asset("ip:192.168.50.2"))

        status, fresh, _ = self._request(
            "GET", "/api/v1/devices?limit=10", token=self.token,
        )
        ada = [item for item in json.loads(fresh)["items"] if item["key"] == mac][0]
        status, body, _ = self._post(
            mac, {"updated_at": ada["updated_at"], "tags": []}, token=self.token,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["tags"], [])
        self.assertEqual(json.loads(body)["owner"], "Ada")

        status, body, _ = self._post(
            mac, {"updated_at": json.loads(body)["updated_at"], "owner": "", "location": None, "notes": None, "criticality": None},
            token=self.token,
        )
        self.assertEqual(status, 200, body)
        cleared = json.loads(body)
        self.assertIsNone(cleared["owner"])
        self.assertIsNone(cleared["updated_at"])
        self.assertIsNone(self._asset("mac:" + mac))

        status, body, _ = self._post(mac, {"updated_at": None}, token=self.token)
        self.assertEqual(status, 422, body)
        self.assertEqual(json.loads(body)["error"]["fields"]["request"], "required")

    def test_label_and_trusted_follow_the_mac(self):
        mac = "aa:bb:cc:dd:ee:10"
        status, body, _ = self._post(
            mac, {"updated_at": None, "label": "L" * 81}, token=self.token,
        )
        self.assertEqual(json.loads(body)["error"]["fields"]["label"], "too_long")

        status, body, _ = self._post(
            mac, {"updated_at": None, "label": "lab\x1bel"}, token=self.token,
        )
        self.assertEqual(json.loads(body)["error"]["fields"]["label"], "invalid")

        status, body, _ = self._post(
            mac, {"updated_at": None, "trusted": "yes"}, token=self.token,
        )
        self.assertEqual(json.loads(body)["error"]["fields"]["trusted"], "invalid")

        status, body, _ = self._post(
            "192.168.50.2", {"updated_at": None, "owner": "Keep", "label": "nope"}, token=self.token,
        )
        self.assertEqual(status, 422, body)
        self.assertEqual(json.loads(body)["error"]["fields"]["label"], "unsupported")
        self.assertIsNone(self._asset("ip:192.168.50.2"))

        status, body, _ = self._post(
            mac,
            {"updated_at": None, "label": "Living room", "trusted": True, "owner": "Sam"},
            token=self.token,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["label"], "Living room")
        self.assertTrue(json.loads(body)["trusted"])
        conn = connect(self.db)
        try:
            info = get_trusted(conn)[mac]
        finally:
            conn.close()
        self.assertEqual(info["label"], "Living room")
        self.assertTrue(info["trusted"])

        status, body, _ = self._request("POST", "/api/v1/devices", {"updated_at": None}, token=self.token)
        self.assertEqual(status, 405, body)
        self.assertNotIn("access-control", body.lower())
