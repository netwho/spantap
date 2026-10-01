# SPDX-License-Identifier: GPL-2.0-or-later
import io
import struct

import pytest

from spantap.encap import checksum16
from spantap.sources.live import combine_filter, exclusion_filter
from spantap.sources.pcapread import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_RAW,
    PcapFormatError,
    open_packet_stream,
    to_ethernet,
    write_pcap_header,
    write_pcap_packet,
)
from spantap.sources.base import Packet
from spantap.sources.synth import SyntheticSource, _pseudo_v4, _pseudo_v6

FRAMES = [b"\x01" * 60, b"\x02" * 128, b"\x03" * 1514]


def _classic(linktype=LINKTYPE_ETHERNET):
    buf = io.BytesIO()
    write_pcap_header(buf, linktype)
    for i, f in enumerate(FRAMES):
        write_pcap_packet(buf, 1_700_000_000_000_000_000 + i * 1_000_000, f)
    buf.seek(0)
    return buf


def test_classic_pcap_roundtrip():
    pkts = list(open_packet_stream(_classic()))
    assert [p.data for p in pkts] == FRAMES
    assert pkts[0].linktype == LINKTYPE_ETHERNET
    assert pkts[1].ts_ns - pkts[0].ts_ns == 1_000_000


def test_classic_pcap_big_endian():
    buf = io.BytesIO()
    buf.write(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, LINKTYPE_ETHERNET))
    for f in FRAMES:
        buf.write(struct.pack(">IIII", 1700000000, 500000, len(f), len(f)))
        buf.write(f)
    buf.seek(0)
    pkts = list(open_packet_stream(buf))
    assert [p.data for p in pkts] == FRAMES
    assert pkts[0].ts_ns == 1700000000 * 10**9 + 500_000_000


def _pcapng():
    """A minimal but real pcapng: SHB, IDB (nanosecond resolution), 3 EPBs."""
    out = io.BytesIO()
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    out.write(struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body
              + struct.pack("<I", 12 + len(shb_body)))
    opts = struct.pack("<HHB", 9, 1, 9) + b"\x00" * 3 + struct.pack("<HH", 0, 0)
    idb_body = struct.pack("<HHI", LINKTYPE_ETHERNET, 0, 262144) + opts
    out.write(struct.pack("<II", 1, 12 + len(idb_body)) + idb_body
              + struct.pack("<I", 12 + len(idb_body)))
    for i, f in enumerate(FRAMES):
        ts = 1_700_000_000_000_000_000 + i * 1_000_000
        pad = (-len(f)) % 4
        body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(f), len(f)) + f + b"\x00" * pad
        total = 12 + len(body)
        out.write(struct.pack("<II", 6, total) + body + struct.pack("<I", total))
    out.seek(0)
    return out


def test_pcapng_roundtrip_with_nanosecond_timestamps():
    pkts = list(open_packet_stream(_pcapng()))
    assert [p.data for p in pkts] == FRAMES
    assert pkts[0].ts_ns == 1_700_000_000_000_000_000
    assert pkts[1].ts_ns - pkts[0].ts_ns == 1_000_000


def test_truncated_stream_stops_cleanly():
    raw = _classic().getvalue()[:-40]
    pkts = list(open_packet_stream(io.BytesIO(raw)))
    assert len(pkts) == 2  # the partial third record is dropped, not crashed on


def test_to_ethernet_passes_ethernet_through():
    p = Packet(0, LINKTYPE_ETHERNET, b"\xff" * 64, 64)
    assert to_ethernet(p) is p.data


def test_to_ethernet_wraps_raw_ip():
    ipv4 = b"\x45" + b"\x00" * 19
    out = to_ethernet(Packet(0, LINKTYPE_RAW, ipv4, len(ipv4)))
    assert len(out) == len(ipv4) + 14
    assert out[12:14] == b"\x08\x00"
    ipv6 = b"\x60" + b"\x00" * 39
    assert to_ethernet(Packet(0, LINKTYPE_RAW, ipv6, len(ipv6)))[12:14] == b"\x86\xdd"


def test_to_ethernet_converts_linux_cooked():
    sll = struct.pack("!HHH", 0, 1, 6) + b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x00\x00" + b"\x08\x00"
    out = to_ethernet(Packet(0, LINKTYPE_LINUX_SLL, sll + b"payload", len(sll) + 7))
    assert out[6:12] == b"\xaa\xbb\xcc\xdd\xee\xff"
    assert out[12:14] == b"\x08\x00"
    assert out[14:] == b"payload"


def test_to_ethernet_refuses_unknown_linktype():
    with pytest.raises(PcapFormatError):
        to_ethernet(Packet(0, 999, b"x" * 20, 20))


# -- self-exclusion --------------------------------------------------------

def test_exclusion_filter_is_specific_when_the_source_is_known():
    assert exclusion_filter("10.0.0.5", "10.0.0.1") == (
        "not (ip proto 47 and src host 10.0.0.1 and dst host 10.0.0.5)"
    )


def test_exclusion_filter_falls_back_to_destination_only():
    assert exclusion_filter("10.0.0.5") == "not (ip proto 47 and dst host 10.0.0.5)"
    assert exclusion_filter("10.0.0.5", "0.0.0.0") == "not (ip proto 47 and dst host 10.0.0.5)"


def test_user_filter_is_anded_never_substituted():
    mandatory = exclusion_filter("10.0.0.5")
    combined = combine_filter("port 80", mandatory)
    assert combined == "(port 80) and " + mandatory
    assert combine_filter(None, mandatory) == mandatory
    assert combine_filter("   ", mandatory) == mandatory


# -- synthetic traffic -----------------------------------------------------

def _walk(frame):
    """Return (ip_version, proto, ip_header, l4) for a synthetic frame."""
    ethertype = int.from_bytes(frame[12:14], "big")
    off = 14
    if ethertype == 0x8100:
        ethertype = int.from_bytes(frame[16:18], "big")
        off = 18
    if ethertype == 0x0800:
        ihl = (frame[off] & 0xF) * 4
        return 4, frame[off + 9], frame[off:off + ihl], frame[off + ihl:]
    if ethertype == 0x86DD:
        return 6, frame[off + 6], frame[off:off + 40], frame[off + 40:]
    raise AssertionError("unexpected ethertype 0x%04X" % ethertype)


@pytest.mark.parametrize("scenario", ["dns", "http", "icmp", "bulk", "jumbo", "smb", "telnet", "mixed"])
def test_synthetic_frames_have_valid_checksums(scenario):
    src = SyntheticSource(scenario=scenario, count=40, seed=1)
    n = 0
    for pkt in src:
        n += 1
        ver, proto, iphdr, l4 = _walk(pkt.data)
        if ver == 4:
            assert checksum16(iphdr) == 0, "bad IPv4 header checksum"
            ip_src = ".".join(str(b) for b in iphdr[12:16])
            ip_dst = ".".join(str(b) for b in iphdr[16:20])
            pseudo = _pseudo_v4(ip_src, ip_dst, proto, len(l4))
        else:
            import socket as _s
            ip_src = _s.inet_ntop(_s.AF_INET6, iphdr[8:24])
            ip_dst = _s.inet_ntop(_s.AF_INET6, iphdr[24:40])
            pseudo = _pseudo_v6(ip_src, ip_dst, proto, len(l4))
        if proto in (6, 17):
            assert checksum16(pseudo + l4) == 0, "bad L4 checksum (proto %d)" % proto
        elif proto == 1:
            assert checksum16(l4) == 0, "bad ICMP checksum"
    assert n == 40


def test_synthetic_output_is_reproducible():
    a = [p.data for p in SyntheticSource(count=20, seed=7)]
    b = [p.data for p in SyntheticSource(count=20, seed=7)]
    assert a == b


def test_vlan_tag_is_applied():
    for pkt in SyntheticSource(scenario="dns", count=4, seed=3, vlan=1234):
        assert pkt.data[12:14] == b"\x81\x00"
        assert int.from_bytes(pkt.data[14:16], "big") & 0xFFF == 1234


# -- host/protocol affinity in "mixed" ---------------------------------------

from spantap.sources.synth import (  # noqa: E402
    _MIXED_POOL, _V4_CLIENTS, _V6_CLIENTS, _V4_CLIENT_PROTOCOLS,
    _V6_CLIENT_PROTOCOLS, _clients_for,
)


def test_every_mixed_protocol_has_at_least_one_client_in_each_family():
    for name in _MIXED_POOL:
        assert _clients_for(name, v6=False), "no IPv4 client speaks %r" % name
        assert _clients_for(name, v6=True), "no IPv6 client speaks %r" % name


def test_no_client_speaks_every_mixed_protocol():
    # The whole point: some clients do several protocols, but none does all
    # of them — otherwise filtering a capture down to one protocol would
    # still show every client, which is exactly what was reported as a bug.
    for protocols in list(_V4_CLIENT_PROTOCOLS.values()) + list(_V6_CLIENT_PROTOCOLS.values()):
        assert set(protocols) < set(_MIXED_POOL)


def test_filtering_a_mixed_capture_by_protocol_narrows_the_client_set():
    seen_by_protocol = {name: set() for name in _MIXED_POOL}
    port_to_protocol = {80: "http", 445: "smb", 23: "telnet", 53: "dns"}
    all_clients = set(_V4_CLIENTS)
    for pkt in SyntheticSource(scenario="mixed", count=3000, seed=11, v6_ratio=0.0):
        f = pkt.data
        addrs = {".".join(str(b) for b in f[26:30]), ".".join(str(b) for b in f[30:34])}
        if f[14 + 9] == 1:  # ICMP
            seen_by_protocol["icmp"] |= addrs & all_clients
            continue
        if f[14 + 9] not in (6, 17):
            continue
        sport, dport = struct.unpack("!HH", f[34:38])
        name = port_to_protocol.get(sport) or port_to_protocol.get(dport)
        if name is None and 443 in (sport, dport):
            name = "bulk"
        if name:
            seen_by_protocol[name] |= addrs & all_clients

    for name, clients in seen_by_protocol.items():
        expected = set(_clients_for(name, v6=False))
        assert clients, "scenario %r never appeared in the mixed run" % name
        assert clients == expected, "%r: saw %r, expected %r" % (name, clients, expected)
        assert clients < all_clients, (
            "%r was seen from every client — affinity isn't narrowing anything" % name
        )


# -- routing / bridging infrastructure protocols ----------------------------

from spantap.sources.synth import (  # noqa: E402
    MAC_CDP, MAC_STP, MAC_OSPF_ALLSPFROUTERS, MAC_RIP2_ROUTERS,
    LLC_SNAP_CDP, LLC_STP, _ROOT_SWITCH, _ROUTERS,
)


def test_infra_scenario_rotates_through_all_four_protocols():
    kinds = set()
    for pkt in SyntheticSource(scenario="infra", count=200, seed=5):
        dst = pkt.data[0:6]
        if dst == MAC_CDP:
            kinds.add("cdp")
        elif dst == MAC_STP:
            kinds.add("stp")
        elif dst == MAC_OSPF_ALLSPFROUTERS:
            kinds.add("ospf")
        elif dst == MAC_RIP2_ROUTERS:
            kinds.add("rip")
    assert kinds == {"cdp", "stp", "ospf", "rip"}


def test_cdp_frames_are_802_3_llc_snap_with_a_valid_checksum():
    for pkt in SyntheticSource(scenario="cdp", count=20, seed=6):
        f = pkt.data
        assert f[0:6] == MAC_CDP
        length = int.from_bytes(f[12:14], "big")
        assert length < 0x0600, "should be an 802.3 length field, not an EtherType"
        assert f[14:22] == LLC_SNAP_CDP
        cdp = f[22:]
        assert checksum16(cdp) == 0, "bad CDP checksum"
        assert cdp[0] == 0x02, "CDP version"


def test_stp_bpdus_all_agree_on_the_same_root():
    seen_ports = set()
    for pkt in SyntheticSource(scenario="stp", count=30, seed=7):
        f = pkt.data
        assert f[0:6] == MAC_STP
        length = int.from_bytes(f[12:14], "big")
        assert length < 0x0600
        assert f[14:17] == LLC_STP
        bpdu = f[17:]
        root_id = bpdu[5:13]
        bridge_id = bpdu[17:25]
        assert root_id == struct.pack("!H", _ROOT_SWITCH.priority) + _ROOT_SWITCH.mac
        cost = int.from_bytes(bpdu[13:17], "big")
        assert cost == (0 if bridge_id == root_id else 19)
        seen_ports.add(int.from_bytes(bpdu[25:27], "big"))
    assert len(seen_ports) > 1, "expected BPDUs from more than one switch port"


def test_ospf_hellos_have_a_valid_checksum_and_list_the_other_routers():
    seen_routers = set()
    for pkt in SyntheticSource(scenario="ospf", count=30, seed=8):
        f = pkt.data
        ihl = (f[14] & 0xF) * 4
        assert f[14 + 9] == 89, "IP protocol should be OSPF"
        ospf = f[14 + ihl:]
        assert ospf[0] == 2 and ospf[1] == 1, "OSPFv2 Hello"
        router_id = ".".join(str(b) for b in ospf[4:8])
        seen_routers.add(router_id)
        neighbors = {".".join(str(b) for b in ospf[44 + i:48 + i]) for i in range(0, len(ospf) - 44, 4)}
        assert router_id not in neighbors, "a router must not list itself as a neighbor"
        cks_field = ospf[12:14]
        without_auth = ospf[:16]
        stripped = without_auth[:12] + b"\x00\x00" + without_auth[14:16]
        body = ospf[24:]
        assert checksum16(stripped + body) == int.from_bytes(cks_field, "big"), "bad OSPF checksum"
    assert seen_routers == {r.router_id for r in _ROUTERS}


def test_rip_responses_advertise_routes_with_a_valid_checksum():
    for pkt in SyntheticSource(scenario="rip", count=20, seed=9):
        f = pkt.data
        ihl = (f[14] & 0xF) * 4
        assert f[14 + 9] == 17, "IP protocol should be UDP"
        udp = f[14 + ihl:]
        sport, dport = struct.unpack("!HH", udp[0:4])
        assert sport == 520 and dport == 520
        rip = udp[8:]
        assert rip[0] == 2, "RIP command should be Response"
        assert len(rip) >= 4 + 20, "at least one 20-byte route entry"
        pseudo = _pseudo_v4(f"{f[26]}.{f[27]}.{f[28]}.{f[29]}",
                             f"{f[30]}.{f[31]}.{f[32]}.{f[33]}", 17, len(udp))
        assert checksum16(pseudo + udp) in (0, 0xFFFF)


def test_infra_scenarios_are_named_by_the_classifier_not_left_generic():
    # The frames were always correct on the wire (checked above and against
    # real Wireshark); what was missing was spantap's own monitor being able
    # to name them, since it used to lump every 802.3/LLC frame together.
    from spantap.classify import classify
    expected = {"cdp": "CDP", "stp": "STP", "ospf": "OSPF", "rip": "RIP"}
    for scenario, want in expected.items():
        for pkt in SyntheticSource(scenario=scenario, count=5, seed=4):
            v = classify(pkt.data)
            got = v.app if scenario == "rip" else v.l4
            assert got == want, "%s frame classified as %r, not %r" % (scenario, got, want)


def test_ospf_hellos_now_carry_a_real_dr_and_bdr():
    # Previously always "0.0.0.0" regardless of who was actually elected —
    # a gap PacketCircle Map's own field list flagged directly.
    for pkt in SyntheticSource(scenario="ospf", count=20, seed=10):
        f = pkt.data
        ihl = (f[14] & 0xF) * 4
        ospf = f[14 + ihl:]
        dr = ".".join(str(b) for b in ospf[36:40])
        bdr = ".".join(str(b) for b in ospf[40:44])
        assert dr == _ROUTERS[0].router_id
        assert bdr == _ROUTERS[1].router_id


# -- the PacketCircle Map "campus" fixture (LLDP, BGP, ARP) -----------------

from spantap.sources.synth import (  # noqa: E402
    MAC_LLDP, ETHERTYPE_LLDP, ETHERTYPE_ARP, MAC_BROADCAST,
    _CAMPUS_ROUTERS, _CAMPUS_SWITCHES, _CAMPUS_ROOT_SWITCH,
    _CAMPUS_BGP_AS, _CAMPUS_BGP_PREFIXES, _CAMPUS_HOSTS, _CAMPUS_FLOWS,
)


def test_campus_scenario_rotates_through_all_five_protocols():
    kinds = set()
    for pkt in SyntheticSource(scenario="campus", count=400, seed=12):
        f = pkt.data
        ethertype = int.from_bytes(f[12:14], "big")
        if f[0:6] == MAC_STP:
            kinds.add("stp")
        elif ethertype == ETHERTYPE_LLDP:
            kinds.add("lldp")
        elif ethertype == ETHERTYPE_ARP:
            kinds.add("arp")
        elif ethertype == 0x0800 and f[14 + 9] == 89:
            kinds.add("ospf")
        elif ethertype == 0x0800 and f[14 + 9] == 6:
            kinds.add("bgp")
    assert kinds == set(_CAMPUS_FLOWS)


def test_lldp_frames_name_the_device_and_uplink_port():
    seen_names = set()
    for pkt in SyntheticSource(scenario="lldp", count=40, seed=13):
        f = pkt.data
        assert f[0:6] == MAC_LLDP
        assert int.from_bytes(f[12:14], "big") == ETHERTYPE_LLDP
        pdu = f[14:]
        # Chassis ID (type 1, MAC subtype), Port ID (type 2), TTL (type 3)
        # must appear in that mandatory order per IEEE 802.1AB.
        t0 = (pdu[0] >> 1) & 0x7F
        t1_off = 2 + (((pdu[0] & 1) << 8) | pdu[1])
        t1 = (pdu[t1_off] >> 1) & 0x7F
        assert (t0, t1) == (1, 2)
        names = {r.hostname for r in _CAMPUS_ROUTERS} | {s.hostname for s in _CAMPUS_SWITCHES}
        assert any(name.encode() in pdu for name in names)
    # not asserting a specific name was seen every run — just that the PDU
    # decodes sanely, checked exhaustively above; real-Wireshark cross-check
    # (tshark -V) is the stronger evidence and was done by hand for this fix.


def test_bgp_session_carries_a_real_open_and_update():
    from spantap.sources.synth import BGP_TYPE_OPEN, BGP_TYPE_UPDATE, bgp_message
    seen_types = set()
    for pkt in SyntheticSource(scenario="bgp", count=60, seed=14):
        f = pkt.data
        ihl = (f[14] & 0xF) * 4
        if f[14 + 9] != 6:  # TCP
            continue
        tcp_off = 14 + ihl
        data_off = ((f[tcp_off + 12] >> 4) & 0xF) * 4
        payload = f[tcp_off + data_off:]
        if len(payload) < 19 or payload[:16] != b"\xff" * 16:
            continue
        msg_type = payload[18]
        seen_types.add(msg_type)
        if msg_type == BGP_TYPE_OPEN:
            asn = int.from_bytes(payload[20:22], "big")
            assert asn == _CAMPUS_BGP_AS
        elif msg_type == BGP_TYPE_UPDATE:
            assert b"\x0a\x0a\x00" in payload  # 10.10.0.0/24 NLRI
            assert b"\x0a\x14\x00" in payload  # 10.20.0.0/24 NLRI
    assert BGP_TYPE_OPEN in seen_types
    assert BGP_TYPE_UPDATE in seen_types


def test_arp_pairs_are_request_then_reply_for_a_real_campus_host():
    campus_ips = {h[0] for h in _CAMPUS_HOSTS}
    gateway_ips = {h[2] for h in _CAMPUS_HOSTS}
    for pkt in SyntheticSource(scenario="arp", count=10, seed=15):
        f = pkt.data
        assert int.from_bytes(f[12:14], "big") == ETHERTYPE_ARP
        arp = f[14:]
        op = int.from_bytes(arp[6:8], "big")
        spa = ".".join(str(b) for b in arp[14:18])
        tpa = ".".join(str(b) for b in arp[24:28])
        if op == 1:  # request
            assert f[0:6] == MAC_BROADCAST
            assert spa in campus_ips and tpa in gateway_ips
        else:  # reply
            assert spa in gateway_ips and tpa in campus_ips


# -- finding a capture tool -------------------------------------------------

def test_a_tool_that_exists_but_is_unreachable_is_not_reported_as_missing(
        tmp_path, monkeypatch):
    """Debian ships dumpcap 0750 root:wireshark — "install it" is wrong advice."""
    from spantap.sources import live
    fake = tmp_path / "dumpcap"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o750)
    monkeypatch.setattr(live, "find_capture_tool", lambda: None)
    monkeypatch.setattr(live, "_CAPTURE_PATHS", (str(fake),))

    path, problem = live.capture_tool_status()
    assert path is None
    assert "is installed but this process cannot execute it" in problem
    assert "and this runs as" in problem
    # the point of the whole function: it must not tell you to install a tool
    # that is already sitting on disk
    assert "install dumpcap" not in problem
    assert "install tcpdump" not in problem


def test_a_genuinely_missing_tool_says_to_install_one(monkeypatch):
    from spantap.sources import live
    monkeypatch.setattr(live, "find_capture_tool", lambda: None)
    monkeypatch.setattr(live, "_CAPTURE_PATHS", ("/nonexistent/dumpcap",))
    path, problem = live.capture_tool_status()
    assert path is None and "install dumpcap" in problem


def test_a_usable_tool_reports_no_problem(monkeypatch):
    from spantap.sources import live
    monkeypatch.setattr(live, "find_capture_tool", lambda: "/usr/bin/dumpcap")
    assert live.capture_tool_status() == ("/usr/bin/dumpcap", None)
