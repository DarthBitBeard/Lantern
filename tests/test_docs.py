"""README links, schema wording, search length, favicon, and Docker health."""

import io
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from lantern import cli
from lantern.store import SCHEMA_VERSION, connect

ROOT = Path(__file__).resolve().parent.parent


def _slug(title: str) -> str:
    text = title.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"\s+", "-", text)


def _headings(path: Path) -> set[str]:
    found = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            found.add(_slug(line.lstrip("#")))
    return found


class DocLinkTests(unittest.TestCase):
    def test_relative_links_and_anchors_resolve(self):
        missing = []
        for path in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]:
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r"\[[^\]]+\]\(([^)]+)\)", text):
                target = match.group(1)
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                file_part, _, anchor = target.partition("#")
                dest = (path.parent / file_part).resolve() if file_part else path
                if not dest.is_file():
                    missing.append(f"{path.name}: {target}")
                    continue
                if anchor and _slug(anchor) not in _headings(dest) and anchor not in _headings(dest):
                    # The link anchor is already a slug.
                    if anchor not in _headings(dest):
                        missing.append(f"{path.name}: {target}")
        self.assertEqual(missing, [])

    def test_readme_names_the_current_schema(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"schema {SCHEMA_VERSION}", text)
        self.assertIn("schema 6", text)

    def test_search_box_has_a_maxlength(self):
        html = (ROOT / "lantern" / "web" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="search"', html)
        self.assertRegex(html, r'id="search"[^>]*maxlength="200"')

    def test_favicon_has_no_script_and_a_dark_outline(self):
        svg = (ROOT / "lantern" / "web" / "favicon.svg").read_text(encoding="utf-8")
        self.assertNotIn("<script", svg.lower())
        self.assertNotIn("href=", svg.lower())
        self.assertIn("#F5F1E8", svg)
        self.assertIn("prefers-color-scheme: dark", svg)

        def channel(value):
            value = value / 255
            return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4

        def luminance(hex_color):
            red, green, blue = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
            return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue)

        def ratio(left, right):
            lighter, darker = sorted((luminance(left), luminance(right)), reverse=True)
            return (lighter + 0.05) / (darker + 0.05)

        self.assertAlmostEqual(ratio("#0B1F3A", "#FFFFFF"), 16.52, places=2)
        self.assertGreaterEqual(ratio("#F5F1E8", "#202124"), 3)
        self.assertIn(".hex { stroke: #F5F1E8; }", svg)

    def test_docker_healthcheck_does_not_carry_a_token(self):
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("HEALTHCHECK", docker)
        health = [line for line in docker.splitlines() if "HEALTHCHECK" in line or line.strip().startswith("CMD python")]
        blob = "\n".join(health)
        self.assertNotIn("LANTERN_API_TOKEN", blob)
        self.assertIn("127.0.0.1", blob)
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("init: true", compose)
        self.assertIn("LANTERN_HEALTH_PORT", docker)
        self.assertIn("127.0.0.1:8068", (ROOT / "README.md").read_text(encoding="utf-8"))

    def test_healthcheck_fails_with_no_server_and_passes_when_one_listens(self):
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        match = re.search(r'CMD python -c "([^"]+)"', docker)
        self.assertIsNotNone(match)
        command = match.group(1)
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = str(probe.getsockname()[1])
        probe.close()
        env = {**os.environ, "LANTERN_HEALTH_PORT": port}
        missing = subprocess.run(
            [sys.executable, "-c", command], env=env, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(missing.returncode, 1, missing.stderr)
        server = socket.socket()
        server.bind(("127.0.0.1", int(port)))
        server.listen(1)
        threading.Thread(target=lambda: server.accept()[0].close(), daemon=True).start()
        self.addCleanup(server.close)
        ready = subprocess.run(
            [sys.executable, "-c", command], env=env, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(ready.returncode, 0, ready.stderr)


class PolishCliTests(unittest.TestCase):
    def test_vacuum_without_yes_warns_and_does_not_change_the_exit(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = str(Path(tmp.name) / "t.db")
        connect(db).close()
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            code = cli.main(["--db", db, "prune", "--keep", "1", "--vacuum"])
        self.assertEqual(code, 0)
        self.assertIn("nothing was vacuumed", err.getvalue())
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            code = cli.main(["--db", db, "prune", "--keep", "1", "--vacuum", "--yes"])
        self.assertEqual(code, 0)
        self.assertNotIn("nothing was vacuumed", err.getvalue())

    def test_a_missing_token_file_does_not_print_its_path(self):
        missing = "/tmp/lantern-missing-token-9f3a"
        with self.assertRaises(ValueError) as caught:
            cli.read_private_file(missing, "LANTERN_API_TOKEN_FILE")
        text = str(caught.exception)
        self.assertIn("Cannot read LANTERN_API_TOKEN_FILE", text)
        self.assertNotIn("lantern-missing-token-9f3a", text)
        self.assertNotIn("/tmp/", text)
        with mock.patch("lantern.cli.Path.is_symlink", side_effect=OSError(13, "denied")):
            with self.assertRaises(ValueError) as caught:
                cli.read_private_file("/var/lantern-token-path", "LANTERN_API_TOKEN_FILE")
        text = str(caught.exception)
        self.assertEqual(text, "Cannot read LANTERN_API_TOKEN_FILE. Refusing to start.")
        self.assertNotIn("lantern-token-path", text)
        self.assertNotIn("/var/", text)

    def test_search_trims_to_200_characters_before_matching(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed")
        script = r"""
const fs = require("fs");
const vm = require("vm");
const lines = fs.readFileSync(process.argv[1], "utf8").split("\n");
const cut = lines.findIndex((line) => line.startsWith('$("scan-form")'));
if (cut < 0) process.exit(2);
const elements = {};
function el(id) {
  if (!elements[id]) elements[id] = { value: "" };
  return elements[id];
}
const context = {
  document: {
    getElementById: el,
    createElement() { return { style: {} }; },
    createTextNode(text) { return { textContent: String(text) }; },
    querySelector() { return { getAttribute() { return ""; } }; },
    body: { setAttribute() {} },
  },
  sessionStorage: { getItem() { return ""; }, setItem() {}, removeItem() {} },
  console,
};
vm.createContext(context);
vm.runInContext(lines.slice(0, cut).join("\n"), context);
const device = {
  ip: "10.0.0.8", trusted: false, tags: [], notes: "needle",
  open_ports: [], findings: [],
};
el("search").value = "x".repeat(200) + "needle";
el("filter").value = "all";
if (context.deviceMatches(device)) process.exit(3);
el("search").value = "  needle  ";
if (!context.deviceMatches(device)) process.exit(4);
"""
        proc = subprocess.run(
            [node, "-e", script, str(ROOT / "lantern" / "web" / "app.js")],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
