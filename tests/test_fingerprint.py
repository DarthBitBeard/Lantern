"""Banner parsers. Fixtures are inert bytes. Nothing is opened on the network."""

import ast
import json
import random
import time
import unittest
from pathlib import Path

from lantern.fingerprint import (
    PRODUCT_CAP,
    RAW_CAP,
    VERSION_CAP,
    Fingerprint,
    parse,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "banner-fixtures.json"
_PRINTABLE = set(chr(code) for code in range(32, 127))


def _build(raw, encoding: str) -> bytes:
    if isinstance(raw, str):
        return raw.encode(encoding)
    if "repeat" in raw:
        return _build(raw["repeat"]["unit"], encoding) * raw["repeat"]["count"]
    return b"".join(_build(part, encoding) for part in raw["concat"])


class FixtureTests(unittest.TestCase):
    def test_fixtures_match_the_parser(self):
        document = json.loads(_FIXTURES.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(document["fixtures"]), 20)
        for fixture in document["fixtures"]:
            raw = _build(fixture["raw"], fixture.get("encoding", "latin-1"))
            got = parse(fixture["protocol"], raw)
            expect = fixture["expect"]
            if not expect["accepted"]:
                if expect["reason"] == "empty":
                    self.assertIsNone(got, fixture["id"])
                else:
                    self.assertIsInstance(got, Fingerprint, fixture["id"])
                    self.assertEqual(got.parse_status, "rejected", fixture["id"])
                    self.assertIsNone(got.product, fixture["id"])
                    self.assertIsNone(got.version, fixture["id"])
                continue
            self.assertEqual(got.service, expect["service"], fixture["id"])
            self.assertEqual(got.product, expect["product"], fixture["id"])
            self.assertEqual(got.version, expect["version"], fixture["id"])
            self.assertEqual(got.parse_status, expect["parse_status"], fixture["id"])
            if fixture["id"] == "fx15-ftp-format-string":
                self.assertIn("%s%n%x", got.raw)
                self.assertIsNone(got.version)

    def test_junk_product_is_unknown_not_stored(self):
        openssh = parse("ssh", b"SSH-2.0-\xff\xfe\xc0\xafOpenSSH_9.6\r\n")
        self.assertIsNone(openssh.product)
        self.assertIsNone(openssh.version)
        self.assertEqual(openssh.parse_status, "unknown")
        self.assertNotIn("OpenSSH", openssh.product or "")

        formula = parse("http", b"HTTP/1.0 200 OK\r\nServer: @SUM(1)/2\r\n\r\n")
        self.assertIsNone(formula.product)
        self.assertIsNone(formula.version)
        self.assertEqual(formula.parse_status, "unknown")

    def test_named_products_and_caps(self):
        ftp = parse("ftp", b"220 (Pure-FTPd 1.0.49)\r\n")
        self.assertEqual((ftp.product, ftp.version, ftp.parse_status), ("Pure-FTPd", "1.0.49", "ok"))
        smtp = parse("smtp", b"220 mail ESMTP Sendmail 8.17.1\r\n")
        self.assertEqual((smtp.product, smtp.version, smtp.parse_status), ("Sendmail", "8.17.1", "ok"))
        self.assertIsNone(parse("ssh", b""))
        self.assertIsNone(parse("telnet", b"hello"))
        huge = parse("ssh", b"SSH-2.0-" + b"A" * 100_000)
        self.assertIsNone(huge.product)
        self.assertIsNone(huge.version)
        self.assertEqual(huge.parse_status, "unknown")
        self.assertLessEqual(len(huge.raw), RAW_CAP)


class HostileInputTests(unittest.TestCase):
    def test_listed_payloads_stay_inside_the_caps(self):
        samples = [
            b"A" * 100_000,
            b"9." * 5000,
            b"SSH-2.0-OpenSSH_9\x00\x1b\r\n",
            "SSH-2.0-OpenSSH_\u202e9".encode(),
            "Server: caf\u00e9/1".encode(),
            b"220 %s%n ready\r\n",
            b"HTTP/1.0 200 OK\r\nServer: <img onerror>\r\n\r\n",
            b"HTTP/1.0 200 OK\r\n" + b"X: y\r\n" * 5000,
            b"HTTP/1.0 200 OK\r\nServer: " + b" " * 50_000 + b"a/1\r\n",
            b"",
            b"HTTP/1.0 200 OK\r\nServer: one/1\r\nServer: two/2\r\n",
        ]
        started = time.perf_counter()
        for protocol in ("ssh", "ftp", "smtp", "http"):
            for sample in samples:
                got = parse(protocol, sample)
                self._holds(got)
        self.assertLess(time.perf_counter() - started, 0.05)

    def test_random_bytes_do_not_escape_the_caps(self):
        chooser = random.Random(0)
        for _ in range(2000):
            size = chooser.randrange(0, 4097)
            sample = bytes(chooser.randrange(256) for _ in range(size))
            for protocol in ("ssh", "ftp", "smtp", "http"):
                self._holds(parse(protocol, sample))

    def _holds(self, got):
        if got is None:
            return
        self.assertIn(got.parse_status, ("ok", "unknown", "rejected"))
        self.assertLessEqual(len(got.raw), RAW_CAP)
        self.assertTrue(set(got.raw) <= _PRINTABLE)
        if got.product is not None:
            self.assertLessEqual(len(got.product), PRODUCT_CAP)
            self.assertTrue(got.product[0].isalnum())
            self.assertTrue(set(got.product) <= set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-"))
        if got.version is not None:
            self.assertLessEqual(len(got.version), VERSION_CAP)
            self.assertTrue(got.version[0].isdigit())


class ParserGapTests(unittest.TestCase):
    def test_http_server_controls_do_not_survive(self):
        raw = "HTTP/1.0 200 OK\r\nServer: nginx\x1b\x00\u202e/1.25.1\r\n\r\n".encode("utf-8")
        got = parse("http", raw)
        self.assertNotIn("\x1b", got.raw)
        self.assertNotIn("\x00", got.raw)
        self.assertNotIn("\u202e", got.raw)
        self.assertNotIn("\x1b", got.product or "")
        self.assertIsNone(got.product)

    def test_version_and_product_charsets_reject_markup(self):
        marked = parse("http", b"HTTP/1.1 200 OK\r\nServer: nginx/1.2<script>=\r\n\r\n")
        self.assertEqual(marked.product, "nginx")
        self.assertIsNone(marked.version)
        junk = parse("http", b"HTTP/1.1 200 OK\r\nServer: -2+3/1.0\r\n\r\n")
        self.assertIsNone(junk.product)
        self.assertIsNone(junk.version)

    def test_caps_drop_what_falls_past_them(self):
        cut = b"220 " + b"A" * 250 + b" vsFTPd 2.3.4\r\n"
        self.assertIsNone(parse("ftp", cut).product)
        self.assertEqual(parse("ftp", b"220 vsFTPd 2.3.4\r\n").product, "vsFTPd")
        short = parse("ssh", b"SSH-2.0-OpenSSH_" + b"1" * VERSION_CAP + b"\r\n")
        self.assertEqual(short.version, "1" * VERSION_CAP)
        long = parse("ssh", b"SSH-2.0-OpenSSH_" + b"1" * (VERSION_CAP + 1) + b"\r\n")
        self.assertEqual(long.product, "OpenSSH")
        self.assertIsNone(long.version)
        headers = b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 63 + b"Server: nginx/1.25.1\r\n\r\n"
        self.assertIsNone(parse("http", headers).product)
        early = b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 10 + b"Server: nginx/1.25.1\r\n\r\n"
        self.assertEqual(parse("http", early).product, "nginx")
        tokens = b"220 " + b"A " * 20 + b"vsFTPd 1.0\r\n"
        self.assertIsNone(parse("ftp", tokens).product)

    def test_ssh_prefix_and_protocol_version(self):
        self.assertEqual(parse("ssh", b"XYZ-2.0-OpenSSH_9.6\r\n").parse_status, "rejected")
        self.assertIsNone(parse("ssh", b"XYZ-2.0-OpenSSH_9.6\r\n").product)
        self.assertEqual(parse("ssh", b"SSH-1.5-OpenSSH_9.6\r\n").parse_status, "rejected")
        self.assertEqual(parse("ssh", b"SSH-1.99-OpenSSH_9.6\r\n").product, "OpenSSH")
        self.assertEqual(parse("ssh", b"SSH-2.0-OpenSSH_9.6\r\n").version, "9.6")

    def test_server_after_the_blank_line_is_ignored(self):
        body = b"HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\n\r\nServer: Apache/2.4.58\r\n"
        self.assertIsNone(parse("http", body).product)
        apache = b"HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\nServer: Apache/2.4.58\r\n\r\n"
        got = parse("http", apache)
        self.assertEqual((got.product, got.version), ("Apache", "2.4.58"))
        lower = parse("http", b"HTTP/1.0 200 OK\r\nserver: nginx/1.25.1\r\n\r\n")
        self.assertEqual((lower.product, lower.version), ("nginx", "1.25.1"))

    def test_2201_is_not_a_greeting_and_sendmail_keeps_its_version(self):
        self.assertEqual(parse("ftp", b"2201 vsFTPd 3.0.5\r\n").parse_status, "rejected")
        self.assertIsNone(parse("ftp", b"2201 vsFTPd 3.0.5\r\n").product)
        mail = parse("smtp", b"220 mail.example ESMTP Sendmail 8.15.2/8.15.2; Mon, 1 Jan 2024\r\n")
        self.assertEqual((mail.product, mail.version), ("Sendmail", "8.15.2"))
        marked = parse("ssh", b"SSH-2.0-OpenSSH_9.6?1\r\n")
        self.assertIsNone(marked.version)

    def test_a_str_banner_is_refused(self):
        with self.assertRaises(TypeError):
            parse("ssh", "SSH-2.0-OpenSSH_9.6\r\n")


class ParserSourceTests(unittest.TestCase):
    def test_the_parser_does_not_evaluate_banner_text(self):
        source = (Path(__file__).parent.parent / "lantern" / "fingerprint.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertFalse(any(alias.name == "re" for alias in node.names))
            if isinstance(node, ast.ImportFrom):
                self.assertNotEqual(node.module, "re")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ("eval", "exec"))
            if isinstance(node, ast.BinOp):
                self.assertNotIsInstance(node.op, ast.Mod)
            if isinstance(node, ast.Attribute):
                self.assertNotEqual(node.attr, "format")
