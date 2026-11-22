"""Classification, banner parsing, UPnP XML and port-table regressions."""

import unittest
from unittest import mock

from lantern import classify, fingerprint, identify, ports


def _dev(**kw):
    device = {"ip": "192.168.1.50", "mac": None, "open_ports": [], "findings": []}
    device.update(kw)
    return device


def _ports(*numbers):
    return [{"port": n} for n in numbers]


class ClassifyNameTests(unittest.TestCase):
    def kind(self, **kw):
        with mock.patch("lantern.classify.vendors.lookup", return_value=None):
            return classify.classify(_dev(**kw))[0]

    def test_person_names_are_not_devices(self):
        self.assertNotEqual(self.kind(hostname="Nastya-laptop"), "nas")
        self.assertNotEqual(self.kind(hostname="Cameron-PC"), "camera")

    def test_real_device_names_still_match(self):
        self.assertEqual(self.kind(hostname="home-nas"), "nas")
        self.assertEqual(self.kind(hostname="nas01"), "nas")
        self.assertEqual(self.kind(hostname="porch-cam"), "camera")
        self.assertEqual(self.kind(hostname="cam2"), "camera")
        self.assertEqual(self.kind(hostname="DiskStation"), "nas")

    def test_gateway_named_pc_is_not_a_router(self):
        self.assertNotEqual(self.kind(hostname="Gateway-PC", open_ports=_ports(445)), "network")

    def test_nas_with_rtsp_is_not_a_camera(self):
        self.assertEqual(self.kind(hostname="synology", open_ports=_ports(554, 445)), "nas")

    def test_nas_vendor_with_rtsp_is_not_a_camera(self):
        vendor = {"vendor_name": "Synology Incorporated", "vendor": "Synology"}
        with mock.patch("lantern.classify.vendors.lookup", return_value=vendor):
            kind = classify.classify(_dev(mac="00:11:32:aa:bb:cc", open_ports=_ports(554)))[0]
        self.assertEqual(kind, "nas")


class RandomizedMacTests(unittest.TestCase):
    def test_formats(self):
        for mac in ("da:a1:19:00:00:01", "DA-A1-19-00-00-01", "daa1.1900.0001", "daa119000001", "a:b:c:d:e:f"):
            self.assertTrue(classify.is_randomized_mac(mac), mac)
        for mac in ("00:11:32:aa:bb:cc", "0011.32aa.bbcc", "001132aabbcc", None, "", "zz:zz"):
            self.assertFalse(classify.is_randomized_mac(mac), mac)


class FingerprintTests(unittest.TestCase):
    def test_tab_separated_ftp_greeting(self):
        result = fingerprint.parse("ftp", b"220\tProFTPD 1.3.5 Server ready\r\n")
        self.assertEqual((result.product, result.version), ("ProFTPD", "1.3.5"))

    def test_server_word_before_version(self):
        result = fingerprint.parse("ftp", b"220 ProFTPD Server 1.3.5 ready\r\n")
        self.assertEqual((result.product, result.version), ("ProFTPD", "1.3.5"))

    def test_truncated_http_server_header_gives_no_version(self):
        raw =b"HTTP/1.1 200 OK\r\n" + b"X-A: " + b"a" * 2020 + b"\r\nServer: Apache/2.4.41 (Ubuntu)"
        result = fingerprint.parse("http", raw)
        self.assertIsNone(result.version)

    def test_complete_http_header_keeps_version(self):
        result = fingerprint.parse("http", b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n")
        self.assertEqual((result.product, result.version), ("nginx", "1.24.0"))


class UpnpXmlTests(unittest.TestCase):
    XML = "<root><device><friendlyName>TV</friendlyName></device></root>"

    def test_plain_document_parses(self):
        self.assertEqual(identify.parse_description(self.XML.encode())["name"], "TV")

    def test_utf16_document_is_refused(self):
        self.assertEqual(identify.parse_description(self.XML.encode("utf-16")), {})
        doc = "<!DOCTYPE x [<!ENTITY a 'b'>]>" + self.XML
        self.assertEqual(identify.parse_description(doc.encode("utf-16-le")), {})

    def test_doctype_is_refused(self):
        self.assertEqual(identify.parse_description(b"<!DOCTYPE x>" + self.XML.encode()), {})


class DescriptionUrlTests(unittest.TestCase):
    def test_public_sender_is_refused(self):
        self.assertFalse(identify.description_url_allowed("http://8.8.8.8/d.xml", "8.8.8.8", None))

    def test_private_sender_is_allowed(self):
        self.assertTrue(identify.description_url_allowed("http://192.168.1.9:80/d.xml", "192.168.1.9", None))


class PortTableTests(unittest.TestCase):
    def test_new_risky_ports_have_rules(self):
        for port in (111, 389, 873, 2049, 5984, 5985, 5986, 6443, 10250):
            self.assertIn(port, ports.PORT_RULES)
            self.assertIn(port, ports.DEFAULT_PORTS)

    def test_every_rule_is_complete(self):
        for port, rule in ports.PORT_RULES.items():
            self.assertEqual(len(rule), 4, port)
            self.assertIn(rule[1], ports.SEVERITY_RANK, port)


if __name__ == "__main__":
    unittest.main()
