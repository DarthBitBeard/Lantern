"""The static check registry. No network, no dataset, no schema change."""

import ast
import json
import socket
import unittest
from pathlib import Path
from unittest import mock

from lantern.checks import (
    REGISTRY,
    Observation,
    describe_checks,
    locked_check_message,
    run_checks,
    unknown_check_message,
    validate_disabled,
)
from lantern.ports import PORT_RULES, findings_for_ports
from lantern.webapp import make_server

ROOT = Path(__file__).resolve().parents[1]
_BANNED_MODULES = frozenset({
    "socket", "ssl", "urllib", "http", "subprocess", "importlib",
    "ctypes", "asyncio", "multiprocessing",
})
_BANNED_CALLS = frozenset({"__import__", "eval", "exec", "compile", "open"})


def _check_sources() -> list[Path]:
    """Every module the purity rule covers. A new file is included on its own."""
    found = sorted((ROOT / "lantern" / "checks").rglob("*.py"))
    for name in ("vulndata.py", "vulndata_import.py"):
        path = ROOT / "lantern" / name
        if path.is_file():
            found.append(path)
    return found


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


class _PurityVisitor(ast.NodeVisitor):
    def __init__(self, path: Path):
        self.path = path
        self.errors: list[str] = []
        self._function: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function.append(node.name)
        self.generic_visit(node)
        self._function.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".", 1)[0]
            if root in _BANNED_MODULES:
                self.errors.append(f"{self.path.name}: imports {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        root = module.split(".", 1)[0]
        if root in _BANNED_MODULES:
            self.errors.append(f"{self.path.name}: imports {module}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        # getattr(builtins, "ev" + "al") never names eval, so matching the
        # called function's name would miss it. Any getattr here is refused.
        if name == "getattr":
            self.errors.append(f"{self.path.name}: calls getattr")
        elif name in _BANNED_CALLS:
            allowed = (
                name == "open"
                and self.path.name == "vulndata.py"
                and self._function
                and self._function[-1] == "_read_packaged"
            )
            if not allowed:
                self.errors.append(f"{self.path.name}: calls {name}")
        self.generic_visit(node)


class RegistryTests(unittest.TestCase):
    def test_registry_is_a_fixed_literal(self):
        source = (ROOT / "lantern" / "checks" / "__init__.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        found = None
        for node in tree.body:
            target = None
            value = None
            if isinstance(node, ast.AnnAssign):
                target, value = node.target, node.value
            elif isinstance(node, ast.Assign):
                target, value = node.targets[0], node.value
            if isinstance(target, ast.Name) and target.id == "REGISTRY":
                found = value
                break
        self.assertIsInstance(found, ast.Dict)
        keys = []
        for key in found.keys:
            self.assertIsInstance(key, ast.Constant)
            self.assertIsInstance(key.value, str)
            keys.append(key.value)
        self.assertEqual(keys, ["port-rules"])
        self.assertEqual(tuple(REGISTRY), ("port-rules",))

    def test_port_rules_match_the_frozen_fixture(self):
        """Stored findings match a fixed fixture, not the live findings function."""
        fixture = json.loads(
            (ROOT / "tests" / "fixtures" / "port_rules_golden.json").read_text(encoding="utf-8")
        )
        via = run_checks(
            Observation(open_ports=tuple(fixture["together_ports"])), None, frozenset(),
        )
        self.assertEqual(via, fixture["together"])
        self.assertEqual(json.dumps(via), json.dumps(fixture["together"]))
        self.assertGreaterEqual(len(fixture["one"]), len(PORT_RULES))
        for port_text, expected in fixture["one"].items():
            one = run_checks(Observation(open_ports=(int(port_text),)), None, frozenset())
            self.assertEqual(json.dumps(one), json.dumps(expected), port_text)

    def test_disabled_check_is_skipped_and_unknown_id_is_refused(self):
        obs = Observation(open_ports=(23, 80))
        with self.assertRaises(ValueError) as ctx:
            run_checks(obs, None, frozenset({"port-rules"}))
        self.assertEqual(
            str(ctx.exception),
            locked_check_message(["port-rules"]),
        )
        with self.assertRaises(ValueError) as ctx:
            validate_disabled(frozenset({"nope"}))
        self.assertIn("port-rules", str(ctx.exception))
        self.assertIn("'nope'", str(ctx.exception))
        self.assertEqual(
            unknown_check_message(["nope"]),
            "Unknown check 'nope'. Valid checks: port-rules.",
        )
        for bad in ("Port-Rules", "PORT-RULES", " port-rules", "port-rules ", "port-rules\t"):
            with self.assertRaises(ValueError, msg=bad) as ctx:
                validate_disabled(frozenset({bad}))
            self.assertIn(repr(bad), str(ctx.exception))
            self.assertNotIn("cannot be disabled", str(ctx.exception))

    def test_a_check_other_than_port_rules_can_be_disabled(self):
        called = []

        def extra(obs, dataset):
            called.append(obs)
            return []

        obs = Observation(open_ports=(23,))
        with mock.patch.dict(REGISTRY, {"sample-check": extra}):
            found = run_checks(obs, None, frozenset({"sample-check"}))
            self.assertEqual(called, [])
            self.assertTrue(any(item["port"] == 23 for item in found))
            text = describe_checks(frozenset({"sample-check"}))
            self.assertIn("sample-check  disabled", text)
            self.assertIn("port-rules", text)
            self.assertIn("enabled", text)
            validate_disabled(frozenset({"sample-check"}))
            with self.assertRaises(ValueError) as ctx:
                validate_disabled(frozenset({"port-rules", "sample-check"}))
            self.assertIn("'port-rules'", str(ctx.exception))
            self.assertIn("cannot be disabled", str(ctx.exception))

    def test_findings_sort_by_severity_and_keep_port_rule_order(self):
        ports = [443, 22, 3389, 6379, 23]
        via = run_checks(Observation(open_ports=tuple(ports)), None, frozenset())
        self.assertEqual([item["port"] for item in via], [item["port"] for item in findings_for_ports(ports)])
        self.assertEqual([item["severity"] for item in via], ["critical", "critical", "high", "low", "info"])

    def test_describe_lists_enabled_state_and_a_missing_dataset(self):
        text = describe_checks(frozenset())
        self.assertIn("port-rules  enabled", text)
        self.assertIn("dataset status: missing", text)
        with self.assertRaises(ValueError) as ctx:
            describe_checks(frozenset({"port-rules"}))
        self.assertIn("cannot be disabled", str(ctx.exception))

    def test_purity_ast_has_no_network_or_dynamic_code(self):
        errors = []
        sources = _check_sources()
        self.assertTrue(sources)
        for path in sources:
            visitor = _PurityVisitor(path)
            visitor.visit(ast.parse(path.read_text(encoding="utf-8")))
            errors.extend(visitor.errors)
        self.assertEqual(errors, [])

    def test_purity_ast_rejects_getattr_access(self):
        source = "\n".join((
            "import builtins",
            "getattr(builtins, 'ev' + 'al')",
            "builtins.getattr(builtins, 'exec')",
        ))
        visitor = _PurityVisitor(Path("snippet.py"))
        visitor.visit(ast.parse(source))
        self.assertGreaterEqual(len(visitor.errors), 2)
        self.assertTrue(all("getattr" in error for error in visitor.errors))
        self.assertFalse(any("imports" in error for error in visitor.errors))

    def test_run_checks_does_not_open_a_socket(self):
        def boom(*_args, **_kwargs):
            raise AssertionError("network")

        obs = Observation(open_ports=tuple(PORT_RULES) + (1,))
        with mock.patch.object(socket.socket, "connect", boom), \
                mock.patch.object(socket, "create_connection", boom):
            found = run_checks(obs, None, frozenset())
        self.assertEqual(len(found), len(findings_for_ports(list(PORT_RULES) + [1])))


class DashboardChecksTests(unittest.TestCase):
    def test_server_stores_the_disabled_set_and_has_no_check_route(self):
        import tempfile

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        server = make_server(
            Path(tmp.name) / "checks.db",
            port=0,
            disabled_checks=frozenset({"port-rules"}),
        )
        self.addCleanup(server.server_close)
        self.assertEqual(
            server.RequestHandlerClass.disabled_checks,
            frozenset({"port-rules"}),
        )
        bare = make_server(Path(tmp.name) / "plain.db", port=0)
        self.addCleanup(bare.server_close)
        self.assertEqual(bare.RequestHandlerClass.disabled_checks, frozenset())
        source = (ROOT / "lantern" / "webapp.py").read_text(encoding="utf-8")
        dashboard = (ROOT / "lantern" / "web" / "app.js").read_text(encoding="utf-8")
        for text in (source, dashboard):
            self.assertNotIn("/api/checks", text)
            self.assertNotIn("disable-check", text)
            self.assertNotIn("disableCheck", text)


if __name__ == "__main__":
    unittest.main()
