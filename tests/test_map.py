"""Network map pieces: gateway parsing, SSDP/mDNS parsing, classification. Offline.

Nothing here opens a socket to the network. Discovery replies are built by
hand, including malformed and hostile ones.
"""

import ipaddress
import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lantern import classify, demo, engine, identify, store
from lantern.discovery import parse_default_gateways

NET = ipaddress.ip_network("192.168.1.0/24")


def _name(text):
    return identify._encode_name(text)


def _rr(name, rtype, data):
    return _name(name) + struct.pack("!HHIH", rtype, 1, 120, len(data)) + data


def _txt(*items):
    return b"".join(bytes([len(item)]) + item for item in items)


def _response(*records, flags=0x8400):
    return struct.pack("!HHHHHH", 0x4C41, flags, 0, len(records), 0, 0) + b"".join(records)


class GatewayParsingTests(unittest.TestCase):
    def test_windows_route_print_any_language(self):
        text = (
            "IPv4-Routentabelle\n"
            "Aktive Routen:\n"
            "     Netzwerkziel    Netzwerkmaske          Gateway    Schnittstelle Metrik\n"
            "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25\n"
            "        127.0.0.0        255.0.0.0   Auf Verbindung         127.0.0.1    331\n"
            "      192.168.1.0    255.255.255.0         On-link     192.168.1.50    281\n"
        )
        self.assertEqual(parse_default_gateways(text), ["192.168.1.1"])

    def test_linux_ip_route_and_proc_route(self):
        self.assertEqual(
            parse_default_gateways("default via 10.0.0.1 dev eth0 proto dhcp metric 100\n"),
            ["10.0.0.1"],
        )
        proc = (
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
            "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n"
        )
        self.assertEqual(parse_default_gateways(proc), ["192.168.1.1"])

    def test_macos_netstat_skips_link_entries(self):
        text = (
            "Routing tables\n\nInternet:\n"
            "Destination        Gateway            Flags           Netif Expire\n"
            "default            192.168.0.1        UGScg             en0\n"
            "default            link#17            UCSIg       bridge100\n"
        )
        self.assertEqual(parse_default_gateways(text), ["192.168.0.1"])

    def test_garbage_gives_nothing(self):
        self.assertEqual(parse_default_gateways("0.0.0.0 0.0.0.0 On-link x\ndefault via nope\n"), [])


class CleanTextTests(unittest.TestCase):
    def test_control_and_bidi_characters_are_removed_and_length_capped(self):
        self.assertEqual(identify.clean_text("Living\x00Room‮TV\x1b[31m"), "Living Room TV [31m")
        self.assertEqual(len(identify.clean_text("x" * 500)), identify.MAX_TEXT)
        self.assertIsNone(identify.clean_text(" \x00 ​ "))
        self.assertIsNone(identify.clean_text(None))


class MdnsTests(unittest.TestCase):
    def cast_reply(self):
        return _response(
            _rr("_googlecast._tcp.local", 12, _name("Living-Room._googlecast._tcp.local")),
            _rr("Living-Room._googlecast._tcp.local", 16,
                _txt(b"md=Chromecast Ultra", b"fn=Living Room TV", b"id=SECRET-SERIAL-123")),
            _rr("Living-Room._googlecast._tcp.local", 33, struct.pack("!HHH", 0, 0, 8009) + _name("cc.local")),
            _rr("cc.local", 1, socket.inet_aton("192.168.1.40")),
        )

    def test_names_model_and_services_and_nothing_else_from_txt(self):
        identity = identify.identity_from_mdns(identify.parse_mdns_packet(self.cast_reply()))
        self.assertEqual(identity["name"], "Living Room TV")
        self.assertEqual(identity["model"], "Chromecast Ultra")
        self.assertEqual(identity["services"], ["_googlecast._tcp"])
        self.assertNotIn("SECRET", json.dumps(identity))

    def test_printer_model_parentheses_are_dropped(self):
        packet = _response(
            _rr("Office._ipp._tcp.local", 16, _txt(b"ty=(Lexmark B2338dw)")),
        )
        identity = identify.identity_from_mdns(identify.parse_mdns_packet(packet))
        self.assertEqual(identity["model"], "Lexmark B2338dw")

    def test_service_enumeration_lists_types(self):
        packet = _response(
            _rr("_services._dns-sd._udp.local", 12, _name("_ipp._tcp.local")),
            _rr("_services._dns-sd._udp.local", 12, _name("_airplay._tcp.local")),
        )
        identity = identify.identity_from_mdns(identify.parse_mdns_packet(packet))
        self.assertEqual(sorted(identity["services"]), ["_airplay._tcp", "_ipp._tcp"])

    def test_compression_pointers_are_followed(self):
        header = struct.pack("!HHHHHH", 1, 0x8400, 0, 2, 0, 0)
        first = _name("_http._tcp.local") + struct.pack("!HHIH", 12, 1, 120, 2) + b"\xc0\x0c"
        records = identify.parse_mdns_packet(header + first + _rr("x.local", 1, socket.inet_aton("1.2.3.4")))
        self.assertEqual(records[0]["data"], "_http._tcp.local")
        self.assertEqual(records[1]["data"], "1.2.3.4")

    def test_hostile_packets_give_nothing(self):
        loop = struct.pack("!HHHHHH", 1, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 1, 0)
        self.assertEqual(identify.parse_mdns_packet(loop), [])
        self.assertEqual(identify.parse_mdns_packet(self.cast_reply()[:40]), [])
        self.assertEqual(identify.parse_mdns_packet(b"\x00" * 5), [])
        self.assertEqual(identify.parse_mdns_packet(b"\x00" * (identify.MAX_PACKET + 1)), [])
        # A query, not a response.
        self.assertEqual(identify.parse_mdns_packet(identify.build_mdns_query(["_http._tcp.local"])), [])
        # A label longer than the packet.
        bad = struct.pack("!HHHHHH", 1, 0x8400, 0, 1, 0, 0) + b"\x3f" + b"a" * 10
        self.assertEqual(identify.parse_mdns_packet(bad), [])

    def test_query_packet_asks_ptr_for_each_type(self):
        packet = identify.build_mdns_query(identify.MDNS_SERVICE_TYPES)
        self.assertLess(len(packet), 1400)  # one unfragmented datagram
        _id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
        self.assertNotEqual(_id, 0)  # legacy unicast: answers come back to our port
        self.assertEqual((flags, qd, an, ns, ar), (0, len(identify.MDNS_SERVICE_TYPES), 0, 0, 0))


class SsdpTests(unittest.TestCase):
    def test_reply_headers(self):
        headers = identify.parse_ssdp_response(
            b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.50:49152/d.xml\r\n"
            b"ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\nX-Other: ignored\r\n\r\n"
        )
        self.assertEqual(headers["location"], "http://192.168.1.50:49152/d.xml")
        self.assertNotIn("x-other", headers)
        self.assertEqual(identify.parse_ssdp_response(b"NOTIFY * HTTP/1.1\r\n\r\n"), {})

    def test_description_is_fetched_only_from_the_replying_device_over_http(self):
        allowed = identify.description_url_allowed
        self.assertTrue(allowed("http://192.168.1.50:49152/d.xml", "192.168.1.50", NET))
        self.assertFalse(allowed("http://192.168.1.51/d.xml", "192.168.1.50", NET))
        self.assertFalse(allowed("http://8.8.8.8/d.xml", "8.8.8.8", NET))
        self.assertFalse(allowed("https://192.168.1.50/d.xml", "192.168.1.50", NET))
        self.assertFalse(allowed("http://router.local/d.xml", "192.168.1.50", NET))
        self.assertFalse(allowed("http://192.168.1.50:99999/d.xml", "192.168.1.50", NET))
        self.assertFalse(allowed("file:///etc/passwd", "192.168.1.50", NET))

    def test_description_fields_and_dtd_refusal(self):
        xml = (
            b'<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>'
            b"<deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>"
            b"<friendlyName>Kitchen</friendlyName><manufacturer>Sonos, Inc.</manufacturer>"
            b"<modelName>One</modelName><serialNumber>ABC</serialNumber></device></root>"
        )
        self.assertEqual(identify.parse_description(xml), {
            "name": "Kitchen", "manufacturer": "Sonos, Inc.", "model": "One", "device_type": "MediaRenderer",
        })
        bomb = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaaaaaaaa">]><root><x>&a;</x></root>'
        self.assertEqual(identify.parse_description(bomb), {})
        self.assertEqual(identify.parse_description(b"<root>" + b"x" * identify.DESCRIPTION_MAX_BYTES + b"</root>"), {})
        self.assertEqual(identify.parse_description(b"not xml"), {})


class DiscoverIdentitiesTests(unittest.TestCase):
    def test_merges_sources_and_drops_addresses_outside_the_subnet(self):
        mdns = {"192.168.1.40": {**identify.empty_identity(), "name": "TV", "services": ["_googlecast._tcp"], "sources": ["mdns"]}}
        ssdp = {"192.168.1.40": {**identify.empty_identity(), "manufacturer": "Google", "services": ["upnp:MediaRenderer"], "sources": ["ssdp"]},
                "192.168.1.41": identify.empty_identity()}
        with mock.patch.object(identify, "mdns_identities", return_value=mdns), \
                mock.patch.object(identify, "ssdp_identities", return_value=ssdp):
            found = identify.discover_identities(NET, "192.168.1.10")
        self.assertEqual(list(found), ["192.168.1.40"])  # the empty one is dropped
        self.assertEqual(found["192.168.1.40"]["manufacturer"], "Google")
        self.assertEqual(found["192.168.1.40"]["sources"], ["mdns", "ssdp"])

    def test_a_failure_gives_an_empty_result(self):
        with mock.patch.object(identify, "mdns_identities", side_effect=OSError("no multicast")):
            self.assertEqual(identify.discover_identities(NET), {})


def _dev(ip, ports=(), mac="00:11:22:00:00:10", hostname=None, identity=None):
    return {"ip": ip, "mac": mac, "hostname": hostname, "label": None,
            "open_ports": [{"port": p, "open": True, "banner": ""} for p in ports],
            "findings": [], "identity": identity}


class ClassifyTests(unittest.TestCase):
    def kind(self, device, gateway=None):
        return classify.classify(device, gateway)[0]

    def test_kinds(self):
        self.assertEqual(self.kind(_dev("192.168.1.1", [53, 80]), "192.168.1.1"), "router")
        self.assertEqual(self.kind(_dev("192.168.1.5", [80, 9100])), "printer")
        self.assertEqual(self.kind(_dev("192.168.1.6", [554, 80])), "camera")
        self.assertEqual(self.kind(_dev("192.168.1.7", [8123])), "smart_home")
        self.assertEqual(self.kind(_dev("192.168.1.8", [135, 445, 3389])), "computer")
        self.assertEqual(self.kind(_dev("192.168.1.9", [3389], hostname="LAB-HV02")), "server")
        self.assertEqual(self.kind(_dev("192.168.1.10", [5432])), "server")
        self.assertEqual(self.kind(_dev("192.168.1.11", [22])), "server")
        self.assertEqual(self.kind(_dev("192.168.1.12", [], mac="da:00:11:22:33:44")), "phone")
        self.assertEqual(self.kind(_dev("192.168.1.13", [80])), "other")
        self.assertEqual(self.kind(_dev("192.168.1.14", [])), "unknown")
        cast = {**identify.empty_identity(), "services": ["_googlecast._tcp"]}
        self.assertEqual(self.kind(_dev("192.168.1.15", [8009], identity=cast)), "media")
        nas = {**identify.empty_identity(), "model": "DS920+", "name": "Synology DiskStation"}
        self.assertEqual(self.kind(_dev("192.168.1.16", [445], identity=nas)), "nas")

    def test_every_result_has_a_reason(self):
        for ports in ([], [80], [22], [53, 80], [9100], [445]):
            kind, reason = classify.classify(_dev("192.168.1.20", ports))
            self.assertIn(kind, classify.KINDS)
            self.assertTrue(reason.endswith("."))

    def test_likely_gateway_prefers_dns_web_and_router_addresses(self):
        devices = [_dev("192.168.1.20", [80]), _dev("192.168.1.1", [53, 80]), _dev("192.168.1.254", [80])]
        self.assertEqual(classify.likely_gateway(devices), "192.168.1.1")
        self.assertIsNone(classify.likely_gateway([_dev("192.168.1.20", [22])]))

    def test_annotate_scan_guesses_a_gateway_for_old_scans(self):
        scan = {"devices": [_dev("192.168.1.1", [53, 80]), _dev("192.168.1.30", [9100])]}
        classify.annotate_scan(scan)
        self.assertEqual(scan["network"]["gateway_ip"], "192.168.1.1")
        self.assertTrue(scan["network"]["gateway_guessed"])
        self.assertEqual([d["kind"] for d in scan["devices"]], ["router", "printer"])


class SchemaFiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "lantern.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_network_and_identity_round_trip(self):
        conn = store.connect(self.db)
        try:
            scan_id = store.save_scan(conn, demo.DEMO_SUBNET, demo.demo_scan_1(), demo=True, network=demo.DEMO_NETWORK)
            scan = store.load_scan(conn, scan_id)
        finally:
            conn.close()
        self.assertEqual(scan["network"], demo.DEMO_NETWORK)
        tv = next(d for d in scan["devices"] if d["ip"] == "192.168.1.40")
        self.assertEqual(tv["identity"]["name"], "Living Room TV")
        pc = next(d for d in scan["devices"] if d["ip"] == "192.168.1.10")
        self.assertIsNone(pc["identity"])

    def test_bad_identity_json_loads_as_none(self):
        conn = store.connect(self.db)
        try:
            scan_id = store.save_scan(conn, "192.168.1.0/24", [_dev("192.168.1.2")])
            conn.execute("UPDATE devices SET identity = 'not json' WHERE scan_id = ?", (scan_id,))
            conn.commit()
            self.assertIsNone(store.load_scan(conn, scan_id)["devices"][0]["identity"])
        finally:
            conn.close()


class EngineNetworkTests(unittest.TestCase):
    def test_default_route_inside_the_subnet_is_the_gateway(self):
        devices = [_dev("192.168.1.1", [53, 80], mac="aa:bb:cc:00:00:01"), _dev("192.168.1.254", [53, 80])]
        with mock.patch.object(engine, "default_gateways", return_value=["10.0.0.1", "192.168.1.254"]):
            info = engine.describe_network(NET, devices, {}, "192.168.1.10")
        self.assertEqual(info, {"gateway_ip": "192.168.1.254", "gateway_mac": "00:11:22:00:00:10", "local_ip": "192.168.1.10"})

    def test_falls_back_to_the_likely_router_and_attaches_identities(self):
        devices = [_dev("192.168.1.1", [53, 80], mac="aa:bb:cc:00:00:01"), _dev("192.168.1.40", [8009])]
        identities = {"192.168.1.40": {**identify.empty_identity(), "name": "TV"}}
        with mock.patch.object(engine, "default_gateways", return_value=["10.0.0.1"]):
            info = engine.describe_network(NET, devices, identities, None)
        self.assertEqual(info["gateway_ip"], "192.168.1.1")
        self.assertEqual(info["gateway_mac"], "aa:bb:cc:00:00:01")
        self.assertEqual(devices[1]["identity"]["name"], "TV")

    def test_scan_subnet_runs_identification_beside_the_sweep(self):
        with mock.patch.object(engine, "scan_hosts", return_value=[_dev("10.9.9.1", [53, 80])]) as sweep, \
                mock.patch.object(engine, "discover_identities", return_value={}) as ids, \
                mock.patch.object(engine, "local_ipv4_in", return_value="10.9.9.5"), \
                mock.patch.object(engine, "default_gateways", return_value=["10.9.9.1"]):
            devices, info = engine.scan_subnet("10.9.9.0/30")
        sweep.assert_called_once()
        ids.assert_called_once()
        self.assertEqual(info["gateway_ip"], "10.9.9.1")
        self.assertEqual(info["local_ip"], "10.9.9.5")
        self.assertEqual(len(devices), 1)

    def test_demo_mode_touches_nothing(self):
        with mock.patch.object(engine, "discover_identities", side_effect=AssertionError("network")), \
                mock.patch.object(engine, "scan_hosts", side_effect=AssertionError("network")):
            devices, info = engine.scan_subnet("192.168.1.0/24", demo_mode=True)
        self.assertEqual(info, demo.DEMO_NETWORK)
        self.assertTrue(devices)


if __name__ == "__main__":
    unittest.main()


class V1KindTests(unittest.TestCase):
    """/api/v1 devices, diffs, and exports carry kind and identity (1.2.0)."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.conn = store.connect(str(Path(tmp.name) / "v1.db"))
        self.addCleanup(self.conn.close)

    def _save(self, devices, network=None):
        return store.save_scan(self.conn, demo.DEMO_SUBNET, devices, demo=True, network=network)

    def _export(self, fmt):
        from lantern import v1
        body, *_ = v1.render_export(self.conn, {"what": ["devices"], "format": [fmt]}, private=False)
        return body.decode("utf-8")

    def _by_ip(self, items):
        return {item["ip"]: item for item in items}

    def test_devices_and_export_agree_on_kind_and_identity(self):
        from lantern import v1
        self._save(demo.demo_scan_1(), demo.DEMO_NETWORK)
        self._save(demo.demo_scan_2(), demo.DEMO_NETWORK)
        listed = self._by_ip(v1.devices_document(self.conn, {}, private=False)["items"])
        exported = self._by_ip(json.loads(self._export("json"))["items"])
        self.assertEqual(listed, exported)

        self.assertEqual(listed["192.168.1.1"]["kind"], "router")
        self.assertEqual(listed["192.168.1.30"]["kind"], "printer")
        self.assertTrue(listed["192.168.1.30"]["kind_reason"])
        printer = listed["192.168.1.30"]["identity"]
        self.assertEqual(printer["model"], "LaserJet M110")
        self.assertEqual(set(printer), set(identify.empty_identity()))
        self.assertIsNone(listed["192.168.1.99"]["identity"])

        diff = v1.diff_document(self.conn, {})
        self.assertEqual([d["ip"] for d in diff["added"]], ["192.168.1.99"])
        self.assertEqual(diff["added"][0]["kind"], listed["192.168.1.99"]["kind"])

    def test_guessed_router_matches_between_list_and_streamed_export(self):
        from lantern import v1
        # No stored network (as for a scan saved before schema 5).
        self._save(demo.demo_scan_1())
        listed = self._by_ip(v1.devices_document(self.conn, {}, private=False)["items"])
        exported = self._by_ip(json.loads(self._export("json"))["items"])
        self.assertEqual(
            {ip: (d["kind"], d["kind_reason"]) for ip, d in listed.items()},
            {ip: (d["kind"], d["kind_reason"]) for ip, d in exported.items()},
        )
        self.assertEqual(listed["192.168.1.1"]["kind"], "router")
        self.assertIn("router address", listed["192.168.1.1"]["kind_reason"])

    def test_csv_appends_the_new_columns_after_the_1_0_columns(self):
        import csv
        import io
        self._save(demo.demo_scan_1(), demo.DEMO_NETWORK)
        rows = list(csv.reader(io.StringIO(self._export("csv"))))
        header = rows[0]
        self.assertEqual(
            header[-5:],
            ["kind", "kind_reason", "announced_name", "announced_model", "announced_manufacturer"],
        )
        self.assertEqual(header[header.index("finding_count") + 1], "kind")
        printer = next(dict(zip(header, row)) for row in rows[1:] if row[header.index("ip")] == "192.168.1.30")
        self.assertEqual(printer["kind"], "printer")
        self.assertEqual(printer["announced_name"], "Office Printer")
        self.assertEqual(printer["announced_model"], "LaserJet M110")
        self.assertEqual(printer["announced_manufacturer"], "")
