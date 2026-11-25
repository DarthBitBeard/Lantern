"""TOML scope files. Parsing only: nothing is scanned."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lantern import checks
from lantern.scopes import load_disabled_checks, load_scopes, select_scope

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "lantern.toml"


class LoadScopesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "lantern.toml"

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, text: str) -> None:
        self.path.write_text(text, encoding="utf-8")

    def test_example_config_is_three_private_scopes(self):
        scopes = load_scopes(EXAMPLE)
        self.assertEqual(
            [(s.name, s.subnet, s.description) for s in scopes.values()],
            [
                ("home", "192.168.1.0/24", "Home LAN"),
                ("lab", "10.10.10.0/24", "Lab bench"),
                ("guest", "172.16.8.0/24", "Guest Wi-Fi"),
            ],
        )

    def test_host_bits_are_normalized_and_description_is_optional(self):
        self.write('[scopes.bench]\nsubnet = " 10.9.9.8/24 "\n')
        scope = select_scope(load_scopes(self.path), None)
        self.assertEqual(scope.name, "bench")
        self.assertEqual(scope.subnet, "10.9.9.0/24")
        self.assertIsNone(scope.description)

    def test_largest_prefix_accepted_and_larger_rejected(self):
        self.write('[scopes.wide]\nsubnet = "10.1.0.0/22"\n')
        self.assertEqual(load_scopes(self.path)["wide"].subnet, "10.1.0.0/22")
        self.write('[scopes.wide]\nsubnet = "10.0.0.0/8"\n')
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        self.assertIn("1024", str(ctx.exception))
        self.assertIn("wide", str(ctx.exception))

    def test_rejects_public_loopback_link_local_cgnat_and_ipv6(self):
        for subnet in ("8.8.8.0/24", "127.0.0.1/32", "169.254.1.0/24", "100.64.0.0/24", "fd00::/64"):
            self.write(f'[scopes.bad]\nsubnet = "{subnet}"\n')
            with self.assertRaises(ValueError) as ctx:
                load_scopes(self.path)
            self.assertIn("bad", str(ctx.exception))

    def test_rejects_unknown_keys_and_extra_root_settings(self):
        self.write('[scopes.home]\nsubnet = "10.0.0.0/24"\nexclude = ["10.0.0.1"]\nports = [22]\n')
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        self.assertIn("exclude", str(ctx.exception))
        self.assertIn("ports", str(ctx.exception))

        self.write('note = "hi"\n[scopes.home]\nsubnet = "10.0.0.0/24"\n')
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        self.assertIn("note", str(ctx.exception))

    def test_checks_table_accepts_only_known_ids(self):
        self.write(
            '[scopes.home]\nsubnet = "10.0.0.0/24"\n\n'
            '[checks]\ndisabled = ["port-rules"]\n'
        )
        with self.assertRaises(ValueError) as ctx:
            load_disabled_checks(self.path)
        self.assertIn("cannot be disabled", str(ctx.exception))
        self.assertIn("'port-rules'", str(ctx.exception))
        self.assertEqual(load_scopes(self.path)["home"].subnet, "10.0.0.0/24")

        self.write('[scopes.home]\nsubnet = "10.0.0.0/24"\n\n[checks]\nplugins = true\n')
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        self.assertIn("plugins", str(ctx.exception))
        self.assertIn("disabled", str(ctx.exception))

        self.write('[scopes.home]\nsubnet = "10.0.0.0/24"\n\n[checks]\ndisabled = ["nope"]\n')
        with self.assertRaises(ValueError) as ctx:
            load_disabled_checks(self.path)
        self.assertIn("port-rules", str(ctx.exception))
        self.assertIn("nope", str(ctx.exception))

        self.write('[scopes.home]\nsubnet = "10.0.0.0/24"\n\n[checks]\ndisabled = "port-rules"\n')
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        self.assertIn("list of check ids", str(ctx.exception))

        self.write("[checks]\ndisabled = []\n")
        self.assertEqual(load_disabled_checks(self.path), frozenset())
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        self.assertIn("no [scopes]", str(ctx.exception))

        def extra(*_args):
            return []

        with mock.patch.dict(checks.REGISTRY, {"sample-check": extra}):
            self.write('[checks]\ndisabled = ["sample-check"]\n')
            self.assertEqual(load_disabled_checks(self.path), frozenset({"sample-check"}))
            for bad in ("Sample-Check", " sample-check", "sample-check "):
                self.write("[checks]\ndisabled = " + json.dumps([bad]) + "\n")
                with self.assertRaises(ValueError, msg=bad) as ctx:
                    load_disabled_checks(self.path)
                self.assertIn(repr(bad), str(ctx.exception))
                self.assertNotIn("cannot be disabled", str(ctx.exception))

    def test_rejects_subnets_array_and_bad_types(self):
        self.write('[scopes.home]\nsubnets = ["10.0.0.0/24", "10.0.1.0/24"]\n')
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        self.assertIn("subnets", str(ctx.exception))

        self.write("[[scopes]]\nsubnet = \"10.0.0.0/24\"\n")
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        self.assertIn("named scopes", str(ctx.exception))

        self.write("[scopes.home]\nsubnet = 24\n")
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        self.assertIn("string", str(ctx.exception))

        self.write('[scopes.home]\nsubnet = "10.0.0.0/24"\ndescription = 1\n')
        with self.assertRaises(ValueError):
            load_scopes(self.path)

    def test_rejects_bad_names_empty_file_and_invalid_toml(self):
        self.write('[scopes."my home"]\nsubnet = "10.0.0.0/24"\n')
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        self.assertIn("not allowed", str(ctx.exception))

        self.write("[scopes]\n")
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        self.assertIn("does not define", str(ctx.exception))

        self.write("this is not toml\n")
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        self.assertIn("Invalid TOML", str(ctx.exception))

        missing = self.path.with_name("missing.toml")
        with self.assertRaises(ValueError) as ctx:
            load_scopes(missing)
        self.assertIn("Cannot read", str(ctx.exception))

    def test_description_blank_is_none_and_too_long_is_rejected(self):
        self.write('[scopes.home]\nsubnet = "10.0.0.0/24"\ndescription = "  "\n')
        self.assertIsNone(load_scopes(self.path)["home"].description)
        self.write('[scopes.home]\nsubnet = "10.0.0.0/24"\ndescription = "' + ("x" * 201) + '"\n')
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        self.assertIn("200", str(ctx.exception))

    def test_select_scope_requires_a_name_when_several_exist(self):
        self.write(
            '[scopes.home]\nsubnet = "192.168.1.0/24"\n'
            '[scopes.lab]\nsubnet = "10.1.0.0/24"\n'
        )
        scopes = load_scopes(self.path)
        self.assertEqual(select_scope(scopes, "lab").subnet, "10.1.0.0/24")
        with self.assertRaises(ValueError) as ctx:
            select_scope(scopes, None)
        self.assertIn("home", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            select_scope(scopes, "office")
        self.assertIn("Unknown scope", str(ctx.exception))
        self.assertEqual(select_scope(scopes, "LAB").subnet, "10.1.0.0/24")

    def test_select_scope_rejects_non_ascii_before_casefold(self):
        self.write('[scopes.k]\nsubnet = "10.1.0.0/24"\n[scopes.ss]\nsubnet = "10.2.0.0/24"\n')
        scopes = load_scopes(self.path)
        for typed in ("\u212a", "\u00df"):
            with self.assertRaises(ValueError, msg=typed) as ctx:
                select_scope(scopes, typed)
            self.assertIn("not allowed", str(ctx.exception), typed)
            self.assertNotIn("10.1.0.0/24", str(ctx.exception))
            self.assertNotIn("10.2.0.0/24", str(ctx.exception))

    def test_case_variant_scope_names_are_rejected(self):
        self.write(
            '[scopes.home]\nsubnet = "192.168.1.0/24"\n'
            '[scopes.Home]\nsubnet = "10.1.0.0/24"\n'
        )
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        self.assertIn("except for case", str(ctx.exception))

    def test_rejects_scope_config_larger_than_64_kib(self):
        marker = "NOT-A-PARSE-ERROR-MARKER"
        prefix = '[scopes.home]\nsubnet = "10.0.0.0/24"\n# '
        exact = prefix.encode() + b"x" * (64 * 1024 - len(prefix.encode()))
        self.assertEqual(len(exact), 64 * 1024)
        self.path.write_bytes(exact)
        scope = load_scopes(self.path)["home"]
        self.assertEqual(scope.subnet, "10.0.0.0/24")

        oversized = f'{prefix}{marker}\n'.encode() + b"y" * (64 * 1024)
        self.assertGreater(len(oversized), 64 * 1024)
        self.path.write_bytes(oversized)
        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.path)
        message = str(ctx.exception)
        self.assertIn("too large", message)
        self.assertIn("64 KiB", message)
        self.assertNotIn(marker, message)
        self.assertNotIn("10.0.0.0/24", message)
        self.assertNotIn("Invalid TOML", message)

        with self.assertRaises(ValueError) as ctx:
            load_scopes(self.tmp.name)
        self.assertIn("not a regular file", str(ctx.exception))

    def test_error_messages_strip_control_bidi_and_zero_width_from_the_path(self):
        nasty = "x\x1b]0;pwned\x07\u202a\u202e\u2066\u200b\u200c\u200d\ufeff.toml"
        path = Path(self.tmp.name) / nasty
        unsafe = ("\x1b", "\x07", "\u202a", "\u202e", "\u2066", "\u200b", "\u200c", "\u200d", "\ufeff")

        def assert_safe(message, label):
            for char in unsafe:
                self.assertNotIn(char, message, label)
            self.assertIn("x", message)
            self.assertIn(".toml", message)

        with self.assertRaises(ValueError) as ctx:
            load_scopes(path)
        self.assertIn("Cannot read", str(ctx.exception))
        assert_safe(str(ctx.exception), "missing")

        path.write_text("this is not toml\n", encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            load_scopes(path)
        self.assertIn("Invalid TOML", str(ctx.exception))
        assert_safe(str(ctx.exception), "toml")

        path.write_text("\n", encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            load_scopes(path)
        self.assertIn("no [scopes]", str(ctx.exception))
        assert_safe(str(ctx.exception), "empty")

        path.write_bytes(b"y" * (64 * 1024 + 1))
        with self.assertRaises(ValueError) as ctx:
            load_scopes(path)
        self.assertIn("too large", str(ctx.exception))
        assert_safe(str(ctx.exception), "size")

    def test_deeply_nested_toml_raises_without_a_recursion_message(self):
        text = "a = " + ("[" * 2000) + ("]" * 2000) + "\n"
        self.assertLess(len(text.encode()), 64 * 1024)
        path = Path(self.tmp.name) / "deep\u202e\u200b.toml"
        path.write_text(text, encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            load_scopes(path)
        message = str(ctx.exception)
        self.assertIn("nested too deeply", message)
        self.assertNotIn("Traceback", message)
        self.assertNotIn("maximum recursion", message)
        self.assertNotIn("\u202e", message)
        self.assertNotIn("\u200b", message)


if __name__ == "__main__":
    unittest.main()
