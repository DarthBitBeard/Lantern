"""Dataset loader and version comparator. Fake products only. No network."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from lantern.checks import Observation, run_checks
from lantern.checks.vuln_match import BANNER_SENTENCE
from lantern.ports import findings_for_ports
from lantern.vulndata import (
    MAX_BYTES,
    compare_versions,
    data_version_newer,
    dataset_from_bytes,
    load_for_scan,
    load_packaged,
    packaged_path,
    parse_data_version,
    validate,
    version_in_range,
)


def _entry(**overrides):
    entry = {
        "id": "LV-1",
        "text_origin": "lantern",
        "product": "lanterntestd",
        "aliases": ["lt-test"],
        "service": "ssh",
        "severity": "high",
        "summary": "Test daemon can be reached by a banner match.",
        "fix": "Upgrade the test daemon.",
        "ranges": [{"introduced": "1.0", "fixed": "1.2"}],
        "refs": [{
            "id": "CVE-2024-1000",
            "url": "https://www.cve.org/CVERecord?id=CVE-2024-1000",
        }],
    }
    entry.update(overrides)
    return entry


def _blob(entries=None, **overrides):
    from lantern.vulndata import canonical_sha256

    body = {
        "license": "CC0-1.0",
        "data_version": "2026.1.0",
        "entries": [_entry()] if entries is None else entries,
    }
    body["sha256"] = canonical_sha256(body["entries"])
    body.update(overrides)
    if "sha256" not in overrides and "entries" in body:
        body["sha256"] = canonical_sha256(body["entries"])
    return json.dumps(body).encode("utf-8")


class ComparatorTests(unittest.TestCase):
    def test_digit_and_letter_runs(self):
        self.assertEqual(compare_versions("9.6p1", "9.6p2"), -1)
        self.assertEqual(compare_versions("9.6p2", "9.6p1"), 1)
        self.assertEqual(compare_versions("9.6p1", "9.6.p1"), 0)
        self.assertEqual(compare_versions("2.4.58", "2.4.9"), 1)
        self.assertEqual(compare_versions("2.4.9", "2.4.58"), -1)
        self.assertEqual(compare_versions("1.0", "1.0.0"), 0)
        self.assertEqual(compare_versions("1", "1.0.0"), 0)
        self.assertEqual(compare_versions("1.0", "1.0.1"), -1)

    def test_a_non_ascii_digit_does_not_compare(self):
        self.assertTrue("\u0661".isdigit())
        self.assertIsNone(compare_versions("1.\u0661", "1.2"))
        self.assertIsNone(compare_versions("\uff11.0", "1.0"))

    def test_unparseable_too_many_parts_and_too_long(self):
        self.assertIsNone(compare_versions("1.0", "not a version"))
        self.assertIsNone(compare_versions("", "1.0"))
        self.assertIsNone(compare_versions("1.0$", "1.0"))
        self.assertEqual(compare_versions("v1.0", "v1.0"), 0)
        many = ".".join(["1"] * 17)
        self.assertIsNone(compare_versions(many, "1.0"))
        self.assertIsNone(compare_versions("1" * 65, "1"))
        self.assertFalse(version_in_range("not a version", "1.0", fixed="2.0"))
        self.assertFalse(version_in_range("1.2", "1.0$", fixed="2.0"))

    def test_range_bounds(self):
        self.assertTrue(version_in_range("1.0", "1.0", fixed="2.0"))
        self.assertTrue(version_in_range("1.9", "1.0", fixed="2.0"))
        self.assertFalse(version_in_range("2.0", "1.0", fixed="2.0"))
        self.assertFalse(version_in_range("0.9", "1.0", fixed="2.0"))
        self.assertTrue(version_in_range("1.5", "1.0", last_affected="1.5"))
        self.assertFalse(version_in_range("1.6", "1.0", last_affected="1.5"))

    def test_data_version_is_integer_tuples_not_string_order(self):
        self.assertLess(parse_data_version("2026.9.0"), parse_data_version("2026.10.0"))
        self.assertGreater("2026.9.0", "2026.10.0")
        self.assertTrue(data_version_newer("2026.10.0", "2026.9.0"))
        self.assertFalse(data_version_newer("2026.1.0", "2026.1.0"))
        for bad in ("2026.01.0", "2026", "v2026.1.0", "2026.1.0a", ""):
            with self.assertRaises(ValueError, msg=bad):
                parse_data_version(bad)


class LoaderTests(unittest.TestCase):
    def test_packaged_file_is_not_shipped(self):
        self.assertFalse(packaged_path().is_file())
        dataset = load_packaged()
        self.assertEqual(dataset.status, "missing")
        self.assertEqual(dataset.entries, ())
        self.assertIsNone(dataset.message)
        data_dir = packaged_path().parent
        names = [path.name for path in data_dir.iterdir()] if data_dir.is_dir() else []
        self.assertNotIn("vulns.json", names)
        self.assertFalse(any(name.startswith("fixture") for name in names))

    def test_valid_blob_round_trips(self):
        parsed = validate(_blob())
        self.assertEqual(parsed["license"], "CC0-1.0")
        self.assertEqual(parsed["entries"][0]["text_origin"], "lantern")
        dataset = dataset_from_bytes(_blob())
        self.assertEqual(dataset.status, "ok")
        self.assertEqual(dataset.entry_count, 1)
        self.assertEqual(len(dataset.sha256_prefix()), 16)

    def test_each_refusal_is_one_fixed_line(self):
        huge_int = b'{"n": 1' + b"0" * 40 + b"}"
        deep = ("[" * 10000 + "]").encode() * 1
        cases = {
            "size": b"x" * (MAX_BYTES + 1),
            "json": b"{",
            "encoding": b"\xff\xfe" + b"{}",
            "bom": b"\xef\xbb\xbf{}",
            "depth": deep,
            "number": b'{"n": NaN}',
            "integer": huge_int,
            "duplicate": b'{"license": "CC0-1.0", "license": "CC0-1.0"}',
            "license": _blob(license="MIT"),
            "origin": _blob(entries=[_entry(text_origin="nvd")]),
            "origin-missing": _without("text_origin"),
            "checksum": _blob(sha256="0" * 64),
            "placeholder": _blob(entries=[_entry(summary="This is a PLACEHOLDER summary for tests.")]),
            "example-id": _blob(entries=[_entry(id="LV-1", summary="EXAMPLE text is not allowed here.")]),
            "http": _blob(entries=[_entry(refs=[{"id": "CVE-2024-1000", "url": "http://www.cve.org/a"}])]),
            "javascript": _blob(entries=[_entry(refs=[{"id": "CVE-2024-1000", "url": "javascript:alert(1)"}])]),
            "invalid-host": _blob(entries=[_entry(refs=[{
                "id": "CVE-2024-1000", "url": "https://updates.invalid/advisory",
            }])]),
            "example-host": _blob(entries=[_entry(refs=[{
                "id": "CVE-2024-1000", "url": "https://example.com/advisory",
            }])]),
            "limits": _blob(entries=[_entry(summary="x" * 301)]),
            "schema": _blob(entries=[_entry(severity="urgent")]),
        }
        # A missing text_origin is a schema failure before the origin check,
        # because the key set is fixed. Build that blob without the key.
        self.assertIn("origin-missing", cases)
        seen = set()
        with tempfile.TemporaryDirectory() as folder:
            for name, blob in cases.items():
                path = Path(folder) / f"{name}.json"
                path.write_bytes(blob)
                raw = path.read_bytes()
                with self.assertRaises(ValueError, msg=name) as ctx:
                    validate(raw)
                message = str(ctx.exception)
                self.assertTrue(message.startswith("lantern: vulnerability data was refused:"), name)
                self.assertNotIn("Traceback", message)
                self.assertNotIn(str(path), message)
                seen.add(message)
        self.assertGreaterEqual(len(seen), 8)
        self.assertIn("text origin", str(_refusal(_blob(entries=[_entry(text_origin="copied")]))))
        self.assertIn("license", str(_refusal(_blob(license="MIT"))))
        self.assertIn("checksum", str(_refusal(_blob(sha256="ab" * 32))))
        self.assertIn("placeholder", str(_refusal(cases["placeholder"])))
        self.assertIn("reference", str(_refusal(cases["invalid-host"])))
        self.assertIn("larger than 5 MB", str(_refusal(cases["size"])))
        self.assertIn("nesting is too deep", str(_refusal(cases["depth"])))
        self.assertIn("non-finite number", str(_refusal(cases["number"])))
        self.assertIn("integer is too large", str(_refusal(cases["integer"])))
        self.assertIn("duplicate key", str(_refusal(cases["duplicate"])))

    def test_duplicate_ids_and_too_many_ranges_are_refused(self):
        self.assertIn("schema", str(_refusal(_blob(entries=[_entry(), _entry()]))))
        ranges = [{"introduced": "1.0", "fixed": "1.1"} for _ in range(17)]
        self.assertIn("limits", str(_refusal(_blob(entries=[_entry(ranges=ranges)]))))

    def test_invalid_dataset_does_not_stop_port_rules(self):
        dataset = dataset_from_bytes(b"{")
        self.assertEqual(dataset.status, "invalid")
        err = io.StringIO()
        with redirect_stderr(err):
            chosen = load_for_scan()
        self.assertEqual(chosen.status, "missing")
        self.assertEqual(err.getvalue(), "")
        err = io.StringIO()
        with redirect_stderr(err):
            load_for_scan(dataset)
        # An already-chosen snapshot is not announced again.
        self.assertEqual(err.getvalue(), "")
        obs = Observation(open_ports=(22,))
        found = run_checks(obs, dataset, frozenset())
        self.assertEqual(found, findings_for_ports([22]))


def _without(key):
    entry = _entry()
    entry.pop(key)
    return _blob(entries=[entry])


def _refusal(blob: bytes) -> ValueError:
    try:
        validate(blob)
    except ValueError as exc:
        return exc
    raise AssertionError("validate accepted a blob that should be refused")


class MatcherTests(unittest.TestCase):
    def _dataset(self, **overrides):
        return dataset_from_bytes(_blob(entries=[_entry(**overrides)]))

    def _obs(self, product="lanterntestd", version="1.1", service="ssh", status="ok", port=22):
        return Observation(
            open_ports=(port,),
            fingerprints=({
                "port": port,
                "service": service,
                "product": product,
                "version": version,
                "parse_status": status,
            },),
        )

    def test_match_is_banner_only_and_has_the_fixed_sentence(self):
        found = run_checks(self._obs(), self._dataset(), frozenset())
        vuln = [item for item in found if item.get("check_id") == "vuln-match"]
        self.assertEqual(len(vuln), 1)
        self.assertEqual(vuln[0]["confidence"], "banner")
        self.assertEqual(vuln[0]["id"], "LV-1")
        self.assertEqual(vuln[0]["refs"], ["CVE-2024-1000"])
        self.assertEqual(vuln[0]["note"], BANNER_SENTENCE)
        self.assertEqual(vuln[0]["evidence"], "lanterntestd 1.1 on port 22")
        self.assertTrue(any(item["port"] == 22 and "check_id" not in item for item in found))

    def test_alias_and_case_match_and_bounds_do_not(self):
        dataset = self._dataset()
        self.assertTrue(any(
            item.get("id") == "LV-1"
            for item in run_checks(self._obs(product="LT-Test"), dataset, frozenset())
        ))
        self.assertFalse(any(
            item.get("check_id") == "vuln-match"
            for item in run_checks(self._obs(version="1.2"), dataset, frozenset())
        ))
        self.assertFalse(any(
            item.get("check_id") == "vuln-match"
            for item in run_checks(self._obs(service="http"), dataset, frozenset())
        ))
        self.assertFalse(any(
            item.get("check_id") == "vuln-match"
            for item in run_checks(self._obs(status="unknown"), dataset, frozenset())
        ))

    def test_vuln_match_cannot_be_disabled(self):
        with self.assertRaises(ValueError) as ctx:
            run_checks(self._obs(), self._dataset(), frozenset({"vuln-match"}))
        self.assertIn("'vuln-match'", str(ctx.exception))
        self.assertIn("cannot be disabled", str(ctx.exception))

    def test_missing_dataset_matches_nothing(self):
        found = run_checks(self._obs(), load_packaged(), frozenset())
        self.assertFalse(any(item.get("check_id") == "vuln-match" for item in found))

    def test_last_affected_is_inclusive(self):
        dataset = self._dataset(ranges=[{"introduced": "1.0", "last_affected": "1.1"}])
        self.assertTrue(any(
            item.get("id") == "LV-1"
            for item in run_checks(self._obs(version="1.1"), dataset, frozenset())
        ))
        self.assertFalse(any(
            item.get("check_id") == "vuln-match"
            for item in run_checks(self._obs(version="1.1.1"), dataset, frozenset())
        ))

    def test_unicode_digit_in_a_range_refuses_the_file_and_the_scan_continues(self):
        from lantern import vulndata
        from lantern.engine import scan_subnet

        for digit in ("\u0661", "\uff11", "\u0967"):
            self.assertTrue(digit.isdigit(), digit)
            blob = _blob(entries=[_entry(ranges=[{"introduced": "1." + digit, "fixed": "9.0"}])])
            dataset = dataset_from_bytes(blob)
            self.assertEqual(dataset.status, "invalid", digit)
            self.assertIn("refused", dataset.message or "")
            self.assertNotIn("Traceback", dataset.message or "")
            self.assertNotIn(digit, dataset.message or "")
            found = run_checks(Observation(open_ports=(22,)), dataset, frozenset())
            self.assertEqual(found, findings_for_ports([22]), digit)

        blob = _blob(entries=[_entry(ranges=[{"introduced": "1.\u0661", "fixed": "9.0"}])])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vulns.json"
            path.write_bytes(blob)
            stderr = io.StringIO()
            with mock.patch.object(vulndata, "packaged_path", return_value=path), \
                    redirect_stderr(stderr):
                devices, _info = scan_subnet("192.168.1.0/24", demo_mode=True)
        text = stderr.getvalue()
        self.assertIn("refused", text)
        self.assertNotIn("Traceback", text)
        self.assertNotIn("\u0661", text)
        self.assertTrue(devices)
        for device in devices:
            self.assertTrue(device["findings"])
            self.assertFalse(any(item.get("check_id") == "vuln-match" for item in device["findings"]))


if __name__ == "__main__":
    unittest.main()
