"""Workflow and image-build pins. No network, no install."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

# Tags peeled to these commits on 2026-11-05.
# actions/checkout v7.0.1, actions/setup-python v7.1.0.
CHECKOUT = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON = "6d4fd22b20465ccc0f7354476588e8df7c9ca0e0"
BASE_DIGEST = "sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"


class SupplyChainTests(unittest.TestCase):
    def test_checkout_and_setup_python_pins_match(self):
        workflows = sorted(WORKFLOWS.glob("*.yml"))
        self.assertGreaterEqual(len(workflows), 4)
        saw_checkout = saw_python = False
        for path in workflows:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("actions/checkout@v", text, path.name)
            self.assertNotIn("actions/setup-python@v", text, path.name)
            chunks = text.split("- uses:")
            for chunk in chunks[1:]:
                first = chunk.splitlines()[0]
                if "actions/checkout@" in first:
                    saw_checkout = True
                    self.assertIn(CHECKOUT, first, path.name)
                    self.assertIn("v7.0.1", first, path.name)
                    self.assertIn("persist-credentials: false", chunk, path.name)
                if "actions/setup-python@" in first:
                    saw_python = True
                    self.assertIn(SETUP_PYTHON, first, path.name)
                    self.assertIn("v7.1.0", first, path.name)
        self.assertTrue(saw_checkout)
        self.assertTrue(saw_python)

    def test_oui_refresh_does_not_force_push_a_shared_branch(self):
        text = (WORKFLOWS / "oui-refresh.yml").read_text(encoding="utf-8")
        self.assertNotIn("--force", text)
        self.assertNotIn("gh pr merge", text)
        self.assertIn('branch="oui-refresh/${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"', text)
        self.assertNotIn("oui-refresh/$(date", text)

    def test_dockerfile_does_not_fetch_an_unpinned_build_backend(self):
        text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn(BASE_DIGEST, text)
        self.assertIn("--require-hashes", text)
        self.assertIn("--no-deps", text)
        self.assertIn("--no-build-isolation", text)
        self.assertNotIn("pip install --no-cache-dir .\n", text)
        for line in text.splitlines():
            if line.strip().endswith(". \\") or line.strip().endswith(" . \\"):
                self.assertIn("--no-deps", line)
                self.assertIn("--no-build-isolation", line)
