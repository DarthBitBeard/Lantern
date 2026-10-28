"""TOML scope files. Parsing only: nothing is scanned."""

import tempfile
import unittest
from pathlib import Path

from lantern.scopes import load_scopes, select_scope

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


if __name__ == "__main__":
    unittest.main()
