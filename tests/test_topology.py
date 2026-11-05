"""Switch map: the SNMP client, switch reading, the tree, storage, and the CLI. Offline.

A fake SNMPv2c agent answers from a dict of OIDs, either in-process or on a
UDP socket bound to 127.0.0.1. Nothing here sends SNMP to a real network.
"""

import contextlib
import io
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from lantern import cli, demo, snmp, store, topology
from lantern.snmp import SnmpError

T = topology


def _value(value):
    if isinstance(value, bool):
        raise TypeError
    if isinstance(value, int):
        return snmp._integer(value)
    if isinstance(value, tuple):
        return snmp._encode_oid(value)
    if isinstance(value, str):
        value = value.encode()
    if isinstance(value, bytes):
        return snmp._tlv(snmp.OCTET_STRING, value)
    if value is None:
        return snmp._tlv(snmp.END_OF_MIB_VIEW, b"")
    raise TypeError(value)


def response(request_id, varbinds, community=b"public", status=0):
    body = b"".join(
        snmp._tlv(snmp.SEQUENCE, snmp._encode_oid(oid) + _value(value)) for oid, value in varbinds
    )
    pdu = snmp._integer(request_id) + snmp._integer(status) + snmp._integer(0) + snmp._tlv(snmp.SEQUENCE, body)
    return snmp._tlv(
        snmp.SEQUENCE,
        snmp._integer(1) + snmp._tlv(snmp.OCTET_STRING, community) + snmp._tlv(snmp.RESPONSE, pdu),
    )


def parse_request(packet):
    """(community, pdu tag, request id, max repetitions, oids) of a request."""
    start, stop = snmp._expect(packet, 0, len(packet), snmp.SEQUENCE)
    _, a, b = snmp._read(packet, start, stop)
    a, b = snmp._expect(packet, b, stop, snmp.OCTET_STRING)
    community = packet[a:b]
    tag, ps, pe = snmp._read(packet, b, stop)
    nums = []
    pos = ps
    for _ in range(3):
        a, b = snmp._expect(packet, pos, pe, snmp.INTEGER)
        nums.append(snmp._decode_int(packet[a:b]))
        pos = b
    ls, le = snmp._expect(packet, pos, pe, snmp.SEQUENCE)
    oids = []
    pos = ls
    while pos < le:
        vs, ve = snmp._expect(packet, pos, le, snmp.SEQUENCE)
        a, b = snmp._expect(packet, vs, ve, snmp.OBJECT_ID)
        oids.append(snmp.decode_oid(packet[a:b]))
        pos = ve
    return community, tag, nums[0], nums[2], oids


class FakeAgent:
    """Answers Get/GetNext/GetBulk from a dict. Silent on a wrong community."""

    def __init__(self, table, community=b"public"):
        self.table = dict(table)
        self.order = sorted(self.table)
        self.community = community
        self.requests = []

    def answer(self, packet):
        community, tag, request_id, max_rep, oids = parse_request(packet)
        self.requests.append((tag, oids))
        if community != self.community:
            return None
        if tag == snmp.GET:
            out = [(oid, self.table.get(oid, _Missing())) for oid in oids]
        else:
            count = max_rep if tag == snmp.GET_BULK else 1
            out = []
            current = oids[0]
            for _ in range(count):
                after = [oid for oid in self.order if oid > current]
                if not after:
                    out.append((current, None))
                    break
                current = after[0]
                out.append((current, self.table[current]))
        return response(request_id, out, community)

    def transport(self, packet, accept):
        reply = self.answer(packet)
        if reply is None or not accept(reply):
            raise SnmpError("timed out")
        return reply


class _Missing:
    pass


def _encode_missing(original):
    def patched(value):
        if isinstance(value, _Missing):
            return snmp._tlv(snmp.NO_SUCH_INSTANCE, b"")
        return original(value)
    return patched


_value = _encode_missing(_value)


def mac_index(mac):
    return tuple(int(part, 16) for part in mac.split(":"))


def switch_table(name, bridge_mac, ports, neighbors=(), self_macs=()):
    """A switch's MIB: `ports` is {bridge port: (ifName, [macs])}."""
    table = {
        T.SYS_NAME: name,
        T.SYS_DESCR: "Example switch\x07 firmware 1.0",
        T.BRIDGE_ADDRESS: bytes(mac_index(bridge_mac)),
    }
    for bridge_port, (if_name, macs) in ports.items():
        ifindex = 1000 + bridge_port
        table[T.IF_NAME + (ifindex,)] = if_name
        table[T.BRIDGE_PORT_IFINDEX + (bridge_port,)] = ifindex
        for mac in macs:
            table[T.DOT1Q_FDB_PORT + (1,) + mac_index(mac)] = bridge_port
            table[T.DOT1Q_FDB_STATUS + (1,) + mac_index(mac)] = T.FDB_LEARNED
    for mac in self_macs:
        table[T.DOT1Q_FDB_PORT + (1,) + mac_index(mac)] = 0
        table[T.DOT1Q_FDB_STATUS + (1,) + mac_index(mac)] = 4
    for remote_index, (bridge_port, sys_name, chassis_mac, remote_port) in enumerate(neighbors, 1):
        key = (0, bridge_port, remote_index)
        table[T.LLDP_REM + (T.LLDP_REM_CHASSIS_SUBTYPE,) + key] = T.CHASSIS_SUBTYPE_MAC
        table[T.LLDP_REM + (T.LLDP_REM_CHASSIS_ID,) + key] = bytes(mac_index(chassis_mac))
        table[T.LLDP_REM + (T.LLDP_REM_PORT_ID,) + key] = remote_port
        table[T.LLDP_REM + (T.LLDP_REM_SYS_NAME,) + key] = sys_name
    return table


def factory(agents):
    def make(ip, community):
        agent = agents[ip]
        return snmp.Client(ip, community, retries=0, transport=agent.transport)
    return make


class EncodingTests(unittest.TestCase):
    def test_get_request_matches_the_well_known_bytes(self):
        # snmpget -v2c -c public <host> 1.3.6.1.2.1.1.1.0 with request id 1.
        expected = bytes.fromhex(
            "3026020101040670756 26c6963a019020101020100020100300e300c06082b060102010101000500".replace(" ", "")
        )
        self.assertEqual(snmp.encode_request(snmp.GET, 1, b"public", ["1.3.6.1.2.1.1.1.0"]), expected)

    def test_only_read_requests_can_be_encoded(self):
        with self.assertRaises(ValueError):
            snmp.encode_request(0xA3, 1, b"public", ["1.3.6.1.2.1.1.5.0"])  # SetRequest

    def test_oid_round_trip_with_large_parts(self):
        oid = (1, 3, 6, 1, 4, 1, 2 ** 32 - 1, 0, 128, 16384)
        tag, start, stop = snmp._read(snmp._encode_oid(oid), 0, 64)
        self.assertEqual(snmp.decode_oid(snmp._encode_oid(oid)[start:stop]), oid)
        self.assertEqual(snmp.parse_oid("1.0.8802.1.1.2"), (1, 0, 8802, 1, 1, 2))


class HostileReplyTests(unittest.TestCase):
    def good(self):
        return response(7, [((1, 3, 6, 1, 2, 1, 1, 5, 0), "sw1")])

    def test_a_good_reply_decodes(self):
        rid, status, _index, varbinds = snmp.decode_response(self.good())
        self.assertEqual((rid, status), (7, 0))
        self.assertEqual(varbinds, [((1, 3, 6, 1, 2, 1, 1, 5, 0), b"sw1")])

    def test_truncations_and_bad_lengths_are_refused(self):
        packet = self.good()
        for cut in range(1, len(packet)):
            with self.assertRaises(SnmpError, msg=cut):
                snmp.decode_response(packet[:cut])
        with self.assertRaises(SnmpError):
            snmp.decode_response(packet + b"\x00")
        # Five-byte long-form length.
        with self.assertRaises(SnmpError):
            snmp.decode_response(b"\x30\x85\x00\x00\x00\x00\x10" + b"\x00" * 16)
        # Indefinite length.
        with self.assertRaises(SnmpError):
            snmp.decode_response(b"\x30\x80\x00\x00")
        # A length that runs past the packet.
        with self.assertRaises(SnmpError):
            snmp.decode_response(b"\x30\x84\x7f\xff\xff\xff")

    def test_oid_limits(self):
        with self.assertRaises(SnmpError):
            snmp.decode_oid(b"\x2b" + b"\x01" * 200)
        with self.assertRaises(SnmpError):
            snmp.decode_oid(b"\x2b\xff\xff\xff\xff\x7f")
        with self.assertRaises(SnmpError):
            snmp.decode_oid(b"\x2b\x86")

    def test_wrong_request_id_and_wrong_pdu_are_ignored_until_timeout(self):
        def transport(packet, accept):
            for reply in (
                response(999999, [((1, 3, 6, 1, 2, 1, 1, 5, 0), "x")]),
                b"\x30\x03\x02\x01\x01",
                b"garbage",
            ):
                self.assertFalse(accept(reply))
            raise SnmpError("timed out")

        client = snmp.Client("192.168.1.2", "public", retries=1, transport=transport)
        with self.assertRaises(SnmpError):
            client.get([T.SYS_NAME])

    def test_error_status_raises(self):
        def transport(packet, accept):
            _c, _t, rid, _m, _o = parse_request(packet)
            reply = response(rid, [(T.SYS_NAME, None)], status=5)
            self.assertTrue(accept(reply))
            return reply

        with self.assertRaises(SnmpError):
            snmp.Client("192.168.1.2", "public", transport=transport).get([T.SYS_NAME])

    def test_walk_refuses_oids_that_go_backwards(self):
        base = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)

        def transport(packet, accept):
            _c, _t, rid, _m, _o = parse_request(packet)
            reply = response(rid, [(base + (5,), "a"), (base + (3,), "b")])
            accept(reply)
            return reply

        with self.assertRaises(SnmpError):
            snmp.Client("192.168.1.2", "public", transport=transport).walk(base)

    def test_walk_stops_at_the_row_cap_and_subtree_end(self):
        base = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)
        table = {base + (i,): f"if{i}" for i in range(1, 60)}
        table[(1, 3, 6, 1, 2, 1, 2, 2, 1, 3, 1)] = 6
        agent = FakeAgent(table)
        client = snmp.Client("192.168.1.2", "public", transport=agent.transport)
        self.assertEqual(len(client.walk(base)), 59)
        self.assertEqual(len(client.walk(base, max_rows=10)), 10)


class UdpAgentTests(unittest.TestCase):
    """The real socket path, against an agent on 127.0.0.1."""

    def setUp(self):
        self.agent = FakeAgent({T.SYS_NAME: "udp-switch", T.SYS_DESCR: "desc"})
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.stop = False
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.stop = True
        self.sock.close()

    def serve(self):
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                packet, peer = self.sock.recvfrom(65535)
            except (socket.timeout, OSError):
                continue
            reply = self.agent.answer(packet)
            if reply is not None:
                self.sock.sendto(reply, peer)

    def test_get_over_udp(self):
        client = snmp.Client("127.0.0.1", "public", port=self.port, timeout=3)
        self.assertEqual(client.get([T.SYS_NAME]), {T.SYS_NAME: b"udp-switch"})

    def test_wrong_community_times_out(self):
        client = snmp.Client("127.0.0.1", "nope", port=self.port, timeout=0.3, retries=0)
        with self.assertRaises(SnmpError):
            client.get([T.SYS_NAME])


CORE_MAC = "aa:bb:cc:00:00:20"
EDGE_MAC = "aa:bb:cc:00:00:30"
ROUTER = "aa:bb:cc:00:00:01"
PC = "00:11:22:00:00:10"
NAS = "00:11:22:00:00:20"
PHONE1 = "3a:00:00:00:00:01"
PHONE2 = "3a:00:00:00:00:02"


def two_switches(lldp=True):
    core = switch_table(
        "core", CORE_MAC,
        {1: ("Gi1/0/1", [ROUTER]), 2: ("Gi1/0/2", [NAS]),
         24: ("Gi1/0/24", [PC, EDGE_MAC, PHONE1, PHONE2])},
        neighbors=[(24, "edge", EDGE_MAC, "Gi0/1")] if lldp else [],
        self_macs=[CORE_MAC],
    )
    edge = switch_table(
        "edge", EDGE_MAC,
        {1: ("Gi0/1", [ROUTER, NAS, CORE_MAC]), 3: ("Gi0/3", [PC]),
         7: ("Gi0/7", [PHONE1, PHONE2])},
        neighbors=[(1, "core", CORE_MAC, "Gi1/0/24")] if lldp else [],
    )
    return {"192.168.1.2": FakeAgent(core), "192.168.1.3": FakeAgent(edge)}


DEVICES = [
    {"ip": "192.168.1.1", "mac": ROUTER},
    {"ip": "192.168.1.2", "mac": "aa:bb:cc:00:00:21"},
    {"ip": "192.168.1.10", "mac": PC},
    {"ip": "192.168.1.20", "mac": NAS},
    {"ip": "192.168.1.50", "mac": PHONE1},
    {"ip": "192.168.1.51", "mac": PHONE2},
    {"ip": "192.168.1.99", "mac": "00:99:99:99:99:99"},
]


class QuerySwitchTests(unittest.TestCase):
    def test_reads_names_ports_fdb_and_lldp(self):
        agents = two_switches()
        result = T.query_switch("192.168.1.2", "public", client_factory=factory(agents))
        self.assertIsNone(result["error"])
        self.assertEqual(result["name"], "core")
        self.assertNotIn("\x07", result["description"])
        self.assertEqual(result["macs"], [CORE_MAC])
        self.assertEqual(result["ports"][24]["name"], "Gi1/0/24")
        self.assertIn(PC, result["ports"][24]["macs"])
        # The switch's own MAC (status self) is not a learned entry.
        self.assertTrue(all(CORE_MAC not in p["macs"] for p in result["ports"].values()))
        self.assertEqual(result["neighbors"], [{
            "port": 24, "port_name": "Gi1/0/24", "name": "edge", "mac": EDGE_MAC, "remote_port": "Gi0/1",
        }])

    def test_falls_back_to_the_dot1d_table(self):
        table = {T.SYS_NAME: "old", T.BRIDGE_PORT_IFINDEX + (2,): 2, T.IF_DESCR + (2,): "port2",
                 T.DOT1D_FDB_PORT + mac_index(PC): 2, T.DOT1D_FDB_STATUS + mac_index(PC): 3}
        result = T.query_switch("192.168.1.4", "public",
                                client_factory=factory({"192.168.1.4": FakeAgent(table)}))
        self.assertEqual(result["ports"], {2: {"name": "port2", "macs": [PC]}})

    def test_wrong_community_is_a_friendly_error_without_the_community(self):
        agents = {"192.168.1.2": FakeAgent({T.SYS_NAME: "x"}, community=b"right")}
        result = T.query_switch("192.168.1.2", "wrong-secret", client_factory=factory(agents))
        self.assertIn("No SNMP reply", result["error"])
        self.assertNotIn("wrong-secret", json.dumps(result))

    def test_query_switches_keeps_order_and_never_raises(self):
        agents = two_switches()

        def make(ip, community):
            if ip == "192.168.1.9":
                raise RuntimeError("boom")
            return factory(agents)(ip, community)

        results = T.query_switches(["192.168.1.3", "192.168.1.9", "192.168.1.2"], "public", client_factory=make)
        self.assertEqual([r["ip"] for r in results], ["192.168.1.3", "192.168.1.9", "192.168.1.2"])
        self.assertIsNotNone(results[1]["error"])


class BuildTopologyTests(unittest.TestCase):
    def tree(self, lldp=True, devices=DEVICES):
        agents = two_switches(lldp)
        results = T.query_switches(["192.168.1.2", "192.168.1.3"], "public", client_factory=factory(agents))
        return T.build_topology(results, devices, ROUTER)

    def check(self, tree):
        switches = {s["ip"]: s for s in tree["switches"]}
        self.assertEqual(tree["router"]["switch"], "192.168.1.2")
        self.assertEqual(tree["router"]["port"], "Gi1/0/1")
        self.assertIsNone(switches["192.168.1.2"]["parent"])
        self.assertEqual(switches["192.168.1.2"]["port_to_parent"], "Gi1/0/1")
        self.assertEqual(switches["192.168.1.3"]["parent"], "192.168.1.2")
        self.assertEqual(switches["192.168.1.3"]["parent_port"], "Gi1/0/24")
        self.assertEqual(switches["192.168.1.3"]["port_to_parent"], "Gi0/1")
        self.assertEqual(switches["192.168.1.3"]["depth"], 1)
        where = tree["locations"]
        self.assertEqual((where[PC]["switch"], where[PC]["port"], where[PC]["shared"]),
                         ("192.168.1.3", "Gi0/3", False))
        self.assertEqual((where[NAS]["switch"], where[NAS]["port"]), ("192.168.1.2", "Gi1/0/2"))
        self.assertEqual((where[PHONE1]["port"], where[PHONE1]["shared"], where[PHONE1]["mac_count"]),
                         ("Gi0/7", True, 2))
        # Not on any switch, the router itself, and the switch's own address are not placed.
        self.assertNotIn("00:99:99:99:99:99", where)
        self.assertNotIn(ROUTER, where)
        self.assertNotIn("aa:bb:cc:00:00:21", where)

    def test_tree_with_lldp(self):
        self.check(self.tree(lldp=True))

    def test_tree_from_forwarding_tables_alone(self):
        self.check(self.tree(lldp=False))

    def test_a_failed_switch_is_listed_with_its_error(self):
        agents = two_switches()
        results = T.query_switches(["192.168.1.2"], "public", client_factory=factory(agents))
        results.append({"ip": "192.168.1.3", "name": None, "description": None, "macs": [],
                        "ports": {}, "neighbors": [], "error": "No SNMP reply."})
        tree = T.build_topology(results, DEVICES, ROUTER)
        failed = [s for s in tree["switches"] if s["error"]]
        self.assertEqual([s["ip"] for s in failed], ["192.168.1.3"])
        # The PC is only seen on core's uplink toward the switch that did not answer,
        # which is not an uplink any more, so it lands on that shared port.
        self.assertEqual(tree["locations"][PC]["port"], "Gi1/0/24")
        self.assertTrue(tree["locations"][PC]["shared"])

    def test_tree_is_json_safe_and_annotates_a_scan(self):
        tree = json.loads(json.dumps(self.tree()))
        scan = {"devices": [dict(d) for d in DEVICES], "topology": tree}
        T.annotate_topology(scan)
        by_ip = {d["ip"]: d for d in scan["devices"]}
        self.assertTrue(by_ip["192.168.1.2"]["is_switch"])
        self.assertEqual(by_ip["192.168.1.10"]["switch_port"]["switch_name"], "edge")
        self.assertNotIn("switch_port", by_ip["192.168.1.99"])

    def test_demo_topology(self):
        tree = demo.demo_topology(demo.demo_scan_2())
        self.assertEqual([s["name"] for s in tree["switches"]], ["Living room switch", "Office switch"])
        self.assertEqual(tree["router"]["port"], "Port 1")
        self.assertTrue(tree["locations"]["de:ad:be:ef:00:99"]["shared"])


class ValidationTests(unittest.TestCase):
    def test_switch_addresses_must_be_private_ipv4(self):
        self.assertEqual(T.validate_switch(" 10.0.0.2 "), "10.0.0.2")
        for bad in ("8.8.8.8", "127.0.0.1", "169.254.1.1", "switch.local", "10.0.0.0/24", "::1"):
            with self.assertRaises(ValueError, msg=bad):
                T.validate_switch(bad)

    def test_community_rules(self):
        self.assertEqual(T.validate_community(" public\n"), "public")
        for bad in ("", "has space", "x" * 65, "café"):
            with self.assertRaises(ValueError):
                T.validate_community(bad)


def args(**kw):
    base = {"switch": [], "snmp_community_file": None}
    base.update(kw)
    return SimpleNamespace(**base)


class ResolveSwitchesTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def resolve(self, environ=None, **kw):
        return cli.resolve_switches(args(**kw), environ or {}, suffix="Nothing was scanned.")

    def test_no_switch_means_none(self):
        self.assertIsNone(self.resolve())
        with self.assertRaises(ValueError):
            self.resolve(snmp_community_file="x")

    def test_sources_in_order(self):
        path = self.dir / "community"
        path.write_text("from-file\n")
        if os.name != "nt":
            os.chmod(path, 0o600)
        env = {cli.SNMP_COMMUNITY_FILE_ENV: str(path), cli.SNMP_COMMUNITY_ENV: "from-env"}
        self.assertEqual(self.resolve(env, switch=["192.168.1.2", "192.168.1.2"]),
                         (["192.168.1.2"], "from-file"))
        self.assertEqual(self.resolve({cli.SNMP_COMMUNITY_ENV: "from-env"}, switch=["10.1.1.1"])[1], "from-env")
        with self.assertRaises(ValueError) as caught:
            self.resolve(switch=["10.1.1.1"])
        self.assertIn("--snmp-community-file", str(caught.exception))

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_group_readable_file_is_refused_without_its_contents(self):
        path = self.dir / "community"
        path.write_text("sekrit")
        os.chmod(path, 0o644)
        with self.assertRaises(ValueError) as caught:
            self.resolve(switch=["10.1.1.1"], snmp_community_file=str(path))
        self.assertNotIn("sekrit", str(caught.exception))
        self.assertIn("Nothing was scanned.", str(caught.exception))

    def test_limits(self):
        env = {cli.SNMP_COMMUNITY_ENV: "public"}
        with self.assertRaises(ValueError):
            self.resolve(env, switch=[f"10.0.0.{i}" for i in range(1, 18)])
        with self.assertRaises(ValueError):
            self.resolve(env, switch=["1.1.1.1"])
        with self.assertRaises(ValueError) as caught:
            self.resolve({cli.SNMP_COMMUNITY_ENV: "two words"}, switch=["10.0.0.1"])
        self.assertNotIn("two words", str(caught.exception))


class StoreAndCliTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = str(Path(tmp.name) / "t.db")

    def run_cli(self, *argv, env=None):
        out, err = io.StringIO(), io.StringIO()
        saved = {k: os.environ.get(k) for k in (cli.SNMP_COMMUNITY_ENV, cli.SNMP_COMMUNITY_FILE_ENV)}
        try:
            for key in saved:
                os.environ.pop(key, None)
            os.environ.update(env or {})
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(["--db", self.db, *argv])
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        return code, out.getvalue(), err.getvalue()

    def test_schema_6_round_trip(self):
        conn = store.connect(self.db)
        try:
            self.assertEqual(store.schema_version(conn), 6)
            scan_id = store.save_scan(conn, "192.168.1.0/24", [dict(d) for d in DEVICES])
            self.assertIsNone(store.load_scan(conn, scan_id)["topology"])
            self.assertTrue(store.set_topology(conn, scan_id, {"switches": [], "router": None, "locations": {}}))
            self.assertEqual(store.load_scan(conn, scan_id)["topology"]["switches"], [])
            self.assertFalse(store.set_topology(conn, 999, {"switches": []}))
        finally:
            conn.close()

    def test_demo_scan_prints_and_stores_the_switch_map(self):
        code, out, err = self.run_cli("scan", "--demo")
        self.assertEqual(code, 0, err)
        self.assertIn("Living room switch (192.168.1.2), router on Port 1", out)
        self.assertIn("Port 8 -> Office switch (192.168.1.3), uplink Port 1", out)
        code, out, err = self.run_cli("report", "--format", "json")
        report = json.loads(out)
        self.assertEqual(report["switch_map"]["router"]["port"], "Port 1")
        printer = next(d for d in report["devices"] if d["ip"] == "192.168.1.30")
        self.assertEqual(printer["switch_port"]["switch_name"], "Office switch")

    def test_switch_with_demo_and_topology_on_demo_data_are_refused(self):
        env = {cli.SNMP_COMMUNITY_ENV: "public"}
        code, _out, err = self.run_cli("scan", "--demo", "--switch", "192.168.1.2", env=env)
        self.assertEqual(code, 2, err)
        code, _out, err = self.run_cli("topology", "--switch", "192.168.1.2", env=env)
        self.assertEqual(code, 1, err)  # no scan yet
        self.run_cli("demo")
        code, _out, err = self.run_cli("topology", "--switch", "192.168.1.2", env=env)
        self.assertEqual(code, 2)
        self.assertIn("demo data", err)

    def test_topology_command_attaches_the_map(self):
        conn = store.connect(self.db)
        try:
            scan_id = store.save_scan(conn, "192.168.1.0/24", [dict(d) for d in DEVICES],
                                      network={"gateway_ip": "192.168.1.1", "gateway_mac": ROUTER})
        finally:
            conn.close()
        agents = two_switches()
        original = T.Client
        T.Client = lambda ip, community: snmp.Client(ip, community, retries=0, transport=agents[ip].transport)
        try:
            code, out, err = self.run_cli("topology", "--switch", "192.168.1.2", "--switch", "192.168.1.3",
                                          env={cli.SNMP_COMMUNITY_ENV: "public"})
        finally:
            T.Client = original
        self.assertEqual(code, 0, err)
        self.assertIn("Gi0/3: 192.168.1.10", out)
        self.assertIn("Not seen on a switch port: 1 device(s)", out)
        self.assertNotIn("public", out + err)
        conn = store.connect(self.db)
        try:
            self.assertEqual(store.load_scan(conn, scan_id)["topology"]["router"]["port"], "Gi1/0/1")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()


class DashboardSwitchTests(unittest.TestCase):
    """The dashboard serves the switch map and never the community."""

    def setUp(self):
        import urllib.request

        from lantern import webapp

        self.webapp = webapp
        self.urllib = urllib.request
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.server = webapp.make_server(Path(tmp.name) / "w.db", port=0,
                                         switches=(["192.168.1.2"], "sekrit-community"))
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def get(self, path, headers=None, method="GET", data=None):
        req = self.urllib.Request(self.base + path, method=method, data=data, headers=headers or {})
        with self.urllib.urlopen(req, timeout=30) as resp:
            return resp.read().decode()

    def test_demo_map_is_served_and_the_community_is_not(self):
        import re

        page = self.get("/")
        token = re.search(r'<meta name="lantern-token" content="([^"]+)"', page).group(1)
        headers = {"Content-Type": "application/json", self.webapp.TOKEN_HEADER: token}
        self.get("/api/demo", headers=headers, method="POST", data=b"{}")
        bodies = [page, self.get("/api/status", headers), self.get("/api/scans/latest", headers)]
        latest = json.loads(bodies[-1])
        scan = latest.get("scan", latest)
        self.assertEqual(scan["topology"]["router"]["port"], "Port 1")
        printer = next(d for d in scan["devices"] if d["ip"] == "192.168.1.30")
        self.assertEqual(printer["switch_port"]["switch_name"], "Office switch")
        for body in bodies:
            self.assertNotIn("sekrit-community", body)
        self.assertEqual(self.server.RequestHandlerClass.switch_config,
                         (["192.168.1.2"], "sekrit-community"))


class CorruptScanCliTests(unittest.TestCase):
    """A stored row that is not valid JSON is a clean error in every command."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = str(Path(tmp.name) / "c.db")
        conn = store.connect(self.db)
        try:
            store.save_scan(conn, "192.168.1.0/24", [dict(DEVICES[2])])
            conn.execute("UPDATE devices SET open_ports = '{broken'")
            conn.commit()
        finally:
            conn.close()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        saved = os.environ.get(cli.SNMP_COMMUNITY_ENV)
        os.environ[cli.SNMP_COMMUNITY_ENV] = "public"
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(["--db", self.db, *argv])
        finally:
            if saved is None:
                os.environ.pop(cli.SNMP_COMMUNITY_ENV, None)
            else:
                os.environ[cli.SNMP_COMMUNITY_ENV] = saved
        return code, err.getvalue()

    def test_commands_report_an_unreadable_scan(self):
        for argv in (["report"], ["diff"], ["topology", "--switch", "192.168.1.2"],
                     ["export", "--what", "devices"]):
            code, err = self.run_cli(*argv)
            self.assertEqual(code, 2, argv)
            self.assertIn("The saved scan could not be read.", err, argv)
            self.assertNotIn("Traceback", err, argv)
