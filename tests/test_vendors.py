"""MAC vendor lookup, the vendor hints in the classifier, and the table builder. Offline."""

import csv
import gzip
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

from lantern import classify, store, v1, vendors

ROOT = Path(__file__).resolve().parent.parent

SYNOLOGY = "00:11:32:aa:bb:cc"
APPLE = "f0:18:98:01:02:03"
ESPRESSIF = "24:0a:c4:11:22:33"
RASPBERRY = "b8:27:eb:12:34:56"
UBIQUITI = "fc:ec:da:00:00:01"
INTEL = "00:12:f0:00:00:01"
BROTHER = "00:80:77:00:00:01"
MA_S = "00:1b:c5:00:12:34"     # first 9 hex digits 001BC5001: an MA-S block inside an IEEE RA MA-L block
IEEE_RA_GAP = "00:1b:c5:ff:ff:ff"


def _device(mac, ports=(), **extra):
    return {"ip": "192.168.1.50", "mac": mac,
            "open_ports": [{"port": p} for p in ports], **extra}


class LookupTests(unittest.TestCase):
    def test_table_loads_every_registry(self):
        table = vendors._load()
        self.assertGreater(len(table), 50_000)
        lengths = {len(prefix) for prefix in table}
        self.assertEqual(lengths, {6, 7, 9})
        self.assertFalse(any(prefix.startswith("#") for prefix in table))

    def test_known_vendors_and_formats(self):
        self.assertEqual(vendors.lookup(SYNOLOGY)["vendor"], "Synology")
        self.assertEqual(vendors.lookup("F0-18-98-01-02-03")["vendor"], "Apple")
        self.assertEqual(vendors.lookup("f01898010203")["vendor_name"], "Apple, Inc.")
        self.assertEqual(vendors.lookup(BROTHER)["vendor"], "Brother")

    def test_longest_prefix_wins_and_ieee_placeholders_are_none(self):
        found = vendors.lookup(MA_S)
        self.assertEqual(found["vendor_name"], vendors._load()["001BC5001"])
        self.assertNotIn("IEEE", found["vendor"])
        self.assertIsNone(vendors.lookup(IEEE_RA_GAP))

    def test_private_malformed_and_missing(self):
        for mac in ("3a:11:22:33:44:01", "02:00:00:00:00:01", None, "", "zz:zz", "00:11:32", "00:11:32:aa:bb:cc:dd"):
            self.assertIsNone(vendors.lookup(mac), mac)
        self.assertTrue(vendors.is_private_mac("3a:11:22:33:44:01"))
        self.assertFalse(vendors.is_private_mac(SYNOLOGY))
        self.assertFalse(vendors.is_private_mac(None))

    def test_short_names(self):
        cases = {
            "Synology Incorporated": "Synology",
            "XEROX CORPORATION": "Xerox",
            "HUAWEI TECHNOLOGIES CO.,LTD": "Huawei",
            "Intel Corporate": "Intel",
            "Brother industries, LTD.": "Brother",
            "Zebra Technologies Inc": "Zebra",
            "Raspberry Pi Foundation": "Raspberry Pi Foundation",
        }
        for name, short in cases.items():
            self.assertEqual(vendors.short_name(name), short, name)
        self.assertLessEqual(len(vendors.short_name("A" * 200)), 40)

    def test_annotate(self):
        devices = [{"mac": SYNOLOGY}, {"mac": "3a:00:00:00:00:01"}, {"mac": None}]
        vendors.annotate_vendors(devices)
        self.assertEqual([d["vendor"] for d in devices], ["Synology", None, None])
        self.assertEqual([d["private_mac"] for d in devices], [False, True, False])


class ClassifyVendorTests(unittest.TestCase):
    def kind(self, device):
        return classify.classify(device)

    def test_strong_vendor_beats_port_guesses(self):
        # File sharing alone would say "computer".
        self.assertEqual(self.kind(_device(SYNOLOGY, [22, 80, 445, 5000]))[0], "nas")
        self.assertIn("Synology", self.kind(_device(SYNOLOGY, [445]))[1])
        self.assertEqual(self.kind(_device(UBIQUITI, [22, 80, 443]))[0], "network")
        self.assertEqual(self.kind(_device(ESPRESSIF, [80]))[0], "smart_home")
        self.assertEqual(self.kind(_device(BROTHER, [80, 443]))[0], "printer")

    def test_announced_services_beat_the_vendor(self):
        identity = {"services": ["_ipp._tcp"]}
        self.assertEqual(self.kind(_device(UBIQUITI, [631], identity=identity))[0], "printer")

    def test_weak_vendor_only_fills_in(self):
        self.assertEqual(self.kind(_device(APPLE)), (
            "phone", "An Apple device with no open services, often an iPhone, iPad, or Watch."))
        # An Apple with file sharing is a computer, not a phone.
        self.assertEqual(self.kind(_device(APPLE, [445]))[0], "computer")
        # A phone-maker hint never applies when the device offers services.
        self.assertNotEqual(self.kind(_device(APPLE, [8080]))[0], "phone")
        self.assertEqual(self.kind(_device(INTEL))[0], "computer")
        self.assertEqual(self.kind(_device(RASPBERRY))[0], "server")
        # SSH already says server, before any weak hint.
        self.assertEqual(self.kind(_device(INTEL, [22]))[0], "server")

    def test_private_and_unknown_vendors_change_nothing(self):
        self.assertEqual(self.kind(_device("3a:11:22:33:44:01"))[0], "phone")
        self.assertEqual(self.kind(_device("00:11:22:33:44:55"))[0], "unknown")


class ApiVendorTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.conn = store.connect(str(Path(tmp.name) / "v.db"))
        self.addCleanup(self.conn.close)
        store.save_scan(self.conn, "192.168.1.0/24", [
            {"ip": "192.168.1.5", "mac": SYNOLOGY, "open_ports": [{"port": 445}], "findings": []},
            {"ip": "192.168.1.6", "mac": "3a:11:22:33:44:01", "open_ports": [], "findings": []},
        ])

    def test_devices_json_and_csv_carry_the_vendor(self):
        listed = {d["ip"]: d for d in v1.devices_document(self.conn, {}, private=False)["items"]}
        self.assertEqual((listed["192.168.1.5"]["vendor"], listed["192.168.1.5"]["kind"]), ("Synology", "nas"))
        self.assertEqual((listed["192.168.1.6"]["vendor"], listed["192.168.1.6"]["private_mac"]), (None, True))
        body, *_ = v1.render_export(self.conn, {"what": ["devices"], "format": ["json"]}, private=False)
        exported = {d["ip"]: d for d in json.loads(body)["items"]}
        self.assertEqual(exported, listed)
        body, *_ = v1.render_export(self.conn, {"what": ["devices"], "format": ["csv"]}, private=False)
        rows = list(csv.reader(io.StringIO(body.decode())))
        self.assertEqual(rows[0][-2:], ["vendor", "private_mac"])
        by_ip = {row[rows[0].index("ip")]: dict(zip(rows[0], row)) for row in rows[1:]}
        self.assertEqual(by_ip["192.168.1.5"]["vendor"], "Synology")
        self.assertEqual(by_ip["192.168.1.6"]["private_mac"], "true")


def _load_tool():
    spec = importlib.util.spec_from_file_location("update_oui", ROOT / "tools" / "update_oui.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _csv(rows):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Registry", "Assignment", "Organization Name", "Organization Address"])
    writer.writerows(rows)
    return out.getvalue().encode("utf-8-sig")


class UpdateToolTests(unittest.TestCase):
    def sources(self, extra=()):
        mal = [["MA-L", f"{i:06X}", f"Maker {i}", "addr"] for i in range(150)] + list(extra)
        mam = [["MA-M", f"ABCDEF{i:X}", f"Mid {i}", "addr"] for i in range(16)] * 1
        mam += [["MA-M", f"ABCDE{i:02X}", f"Mid2 {i}", "addr"] for i in range(100)]
        mas = [["MA-S", f"123456{i:03X}", f"Small {i}", "addr"] for i in range(150)]
        return {"oui.csv": _csv(mal), "mam.csv": _csv(mam), "oui36.csv": _csv(mas)}

    def test_build_is_clean_and_reproducible(self):
        tool = _load_tool()
        extra = [["MA-L", "ZZZZZZ", "Bad hex", ""], ["MA-L", "AABBCCDD", "Too long", ""],
                 ["MA-L", "AABBCC", "Tab\tand\x07bell  name", ""], ["MA-L", "AABBCD", "", ""]]
        first = tool.build(self.sources(extra))
        self.assertEqual(first[4:8], b"\x00\x00\x00\x00")  # gzip mtime 0
        lines = gzip.decompress(first).decode().splitlines()
        self.assertTrue(lines[0].startswith("# IEEE"))
        table = dict(line.split("\t") for line in lines[1:])
        self.assertEqual(table["AABBCC"], "Tab and bell name")
        self.assertNotIn("ZZZZZZ", table)
        self.assertNotIn("AABBCD", table)
        self.assertTrue(all(len(k) in (6, 7, 9) for k in table))
        self.assertEqual(lines[1:], sorted(lines[1:]))

    def test_a_registry_with_too_few_rows_is_refused(self):
        tool = _load_tool()
        sources = self.sources()
        sources["oui36.csv"] = _csv([["MA-S", "123456789", "Only one", ""]])
        with self.assertRaises(SystemExit):
            tool.build(sources)

    def test_package_data_ships_the_table(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('"data/*"', text)
        self.assertTrue((ROOT / "lantern" / "data" / "oui.tsv.gz").is_file())


class VendorBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        vendors._table = None
        vendors._bundle_path = None

    def tearDown(self):
        vendors._table = None
        vendors._bundle_path = None
        self.tmp.cleanup()

    def _write(self, payload: bytes) -> None:
        path = Path(self.tmp.name) / "oui.tsv.gz"
        path.write_bytes(payload)
        vendors._bundle_path = path
        vendors._table = None

    def test_a_gzip_bomb_is_refused_and_lookup_is_unknown(self):
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as handle:
            handle.write(b"A" * 800)
        self._write(buf.getvalue())
        original = vendors.MAX_VENDOR_BYTES
        vendors.MAX_VENDOR_BYTES = 100
        try:
            with self.assertRaises(ValueError) as caught:
                vendors._load()
            self.assertIn("larger than Lantern", str(caught.exception))
            self.assertIsNone(vendors.lookup("00:11:22:33:44:55"))
        finally:
            vendors.MAX_VENDOR_BYTES = original

    def test_a_vendor_name_with_esc_is_cleaned(self):
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as handle:
            handle.write(b"001122\tAcme\x1bCorp\n")
        self._write(buf.getvalue())
        found = vendors.lookup("00:11:22:33:44:55")
        self.assertIsNotNone(found)
        self.assertNotIn("\x1b", found["vendor"])
        self.assertNotIn("\x1b", found["vendor_name"])
        self.assertIn("Acme", found["vendor"])


if __name__ == "__main__":
    unittest.main()
