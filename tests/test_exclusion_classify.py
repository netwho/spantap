# SPDX-License-Identifier: GPL-2.0-or-later
import os
import random
import struct
import subprocess

import pytest

from spantap.classify import classify
from spantap.exclusion import DEFAULT_PCAPOVERIP_PORT, build_plan

DUMPCAP = "/usr/bin/dumpcap"


# -- exclusions ------------------------------------------------------------

def test_both_feedback_loops_are_excluded_by_default():
    plan = build_plan("10.0.0.5", "10.0.0.1")
    exprs = [c.expr for c in plan.clauses]
    assert exprs == [
        "not (ip proto 47 and src host 10.0.0.1 and dst host 10.0.0.5)",
        "not (tcp port %d)" % DEFAULT_PCAPOVERIP_PORT,
    ]
    assert all(c.mandatory for c in plan.clauses)


def test_mandatory_clauses_come_before_the_user_filter():
    # BPF keywords like `vlan` shift offsets for everything that follows them,
    # so the user's filter must never precede the exclusions.
    plan = build_plan("10.0.0.5", "10.0.0.1", user_filter="vlan and port 80")
    assert plan.clauses[-1].expr == "(vlan and port 80)"
    assert plan.clauses[-1].mandatory is False
    assert plan.clauses[0].expr.startswith("not (ip proto 47")


def test_erspan_self_exclusion_can_never_be_removed():
    for kwargs in (
        {},
        {"pcapoverip_port": 0},
        {"exclude_ssh": True},
        {"user_filter": "port 80"},
        {"pcapoverip_host": "10.0.0.9"},
    ):
        plan = build_plan("10.0.0.5", "10.0.0.1", **kwargs)
        assert any("ip proto 47" in c.expr for c in plan.clauses), kwargs


def test_port_zero_drops_only_the_gateway_clause():
    plan = build_plan("10.0.0.5", pcapoverip_port=0)
    assert len(plan.clauses) == 1
    assert "tcp port" not in plan.expression()


def test_gateway_clause_can_be_narrowed_to_one_host():
    plan = build_plan("10.0.0.5", pcapoverip_host="192.168.1.9")
    assert "not (tcp port 57012 and host 192.168.1.9)" in plan.expression()


def test_explain_carries_a_reason_for_every_clause():
    plan = build_plan("10.0.0.5", "10.0.0.1", exclude_ssh=True, user_filter="port 80")
    for item in plan.explain():
        assert item["reason"] and item["expr"]
    assert sum(1 for i in plan.explain() if i["mandatory"]) == 2


@pytest.mark.skipif(not os.path.exists(DUMPCAP), reason="dumpcap not installed")
@pytest.mark.parametrize("kwargs", [
    {},
    {"erspan_src": "10.0.0.1"},
    {"erspan_src": "0.0.0.0"},
    {"pcapoverip_port": 0},
    {"pcapoverip_port": 65535},
    {"pcapoverip_host": "10.0.0.9"},
    {"exclude_ssh": True},
    {"user_filter": "port 80 or port 443"},
    {"user_filter": "not (host 10.1.1.1 and port 22)"},
    {"user_filter": "vlan and ip"},
])
def test_every_filter_we_emit_compiles(kwargs):
    """The filter is useless if libpcap rejects it, so let libpcap judge."""
    src = kwargs.pop("erspan_src", None)
    expr = build_plan("10.0.0.5", src, **kwargs).expression()
    proc = subprocess.run(
        [DUMPCAP, "-d", "-f", expr, "-i", "lo"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, "dumpcap rejected %r:\n%s" % (expr, proc.stderr)


# -- classification --------------------------------------------------------

def eth(ethertype, payload=b"", vlan=None, qinq=False):
    out = b"\x02" * 6 + b"\x03" * 6
    if qinq:
        out += struct.pack("!HHHH", 0x88A8, 100, 0x8100, vlan or 200)
    elif vlan is not None:
        out += struct.pack("!HH", 0x8100, vlan)
    return out + struct.pack("!H", ethertype) + payload


def ipv4(proto, rest=b"", frag_off=0, ihl=5):
    hdr = bytearray(ihl * 4)
    hdr[0] = 0x40 | ihl
    hdr[6:8] = struct.pack("!H", frag_off & 0x1FFF)
    hdr[9] = proto
    return bytes(hdr) + rest


def ipv6(nxt, rest=b""):
    return struct.pack("!IHBB", 0x60000000, len(rest), nxt, 64) + b"\x00" * 32 + rest


def ports(sport, dport):
    return struct.pack("!HH", sport, dport) + b"\x00" * 16


def test_plain_ipv4_tcp():
    v = classify(eth(0x0800, ipv4(6, ports(51234, 443))))
    assert (v.l2, v.l3, v.l4, v.app) == ("Ethernet", "IPv4", "TCP", "HTTPS")


def test_vlan_and_qinq_tags():
    v = classify(eth(0x0800, ipv4(17, ports(53, 33333)), vlan=42))
    assert (v.l2, v.vlan_id, v.app) == ("VLAN", 42, "DNS")
    v = classify(eth(0x0800, ipv4(6, ports(80, 40000)), vlan=200, qinq=True))
    assert (v.l2, v.vlan_id, v.app) == ("VLAN", 100, "HTTP")


def test_ipv4_options_are_stepped_over():
    v = classify(eth(0x0800, ipv4(6, ports(22, 40000), ihl=8)))
    assert v.app == "SSH"


def test_later_ipv4_fragments_have_no_ports():
    v = classify(eth(0x0800, ipv4(6, ports(80, 40000), frag_off=185)))
    assert v.l4 == "TCP" and v.app is None


def test_ipv6_authentication_header_length_is_in_32_bit_words():
    # AH payload-len is (words - 2), unlike every other extension header.
    ah = bytes([6, 1, 0, 0]) + b"\x00" * 8          # 12 bytes, next=TCP
    v = classify(eth(0x86DD, ipv6(51, ah + ports(40000, 443))))
    assert (v.l3, v.l4, v.app) == ("IPv6", "TCP", "HTTPS")

    ah16 = bytes([6, 2, 0, 0]) + b"\x00" * 12       # 16 bytes
    v = classify(eth(0x86DD, ipv6(51, ah16 + ports(40000, 80))))
    assert v.app == "HTTP"


def test_later_ipv6_fragments_have_no_ports():
    frag = bytes([6, 0]) + struct.pack("!H", 185 << 3) + b"\x00" * 4
    v = classify(eth(0x86DD, ipv6(44, frag + ports(40000, 443))))
    assert v.l4 == "TCP" and v.app is None
    first = bytes([6, 0]) + struct.pack("!H", 0) + b"\x00" * 4
    v = classify(eth(0x86DD, ipv6(44, first + ports(40000, 443))))
    assert v.app == "HTTPS"


def test_non_ip_ethertypes():
    assert classify(eth(0x0806, b"\x00" * 28)).l3 == "ARP"
    assert classify(eth(0x88CC, b"\x00" * 20)).l3 == "LLDP"
    assert classify(eth(0x9999, b"\x00" * 20)).l3 == "0x9999"


def test_llc_stp_frames_are_named_not_left_as_generic_llc():
    payload = bytes([0x42, 0x42, 0x03]) + b"\x00" * 32  # DSAP/SSAP/Control + a fake BPDU
    v = classify(eth(len(payload), payload))
    assert (v.l3, v.l4) == ("802.3/LLC", "STP")


def test_llc_snap_cdp_frames_are_named_not_left_as_generic_llc():
    payload = (bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C]) + struct.pack("!H", 0x2000)
               + b"\x00" * 10)
    v = classify(eth(len(payload), payload))
    assert (v.l3, v.l4) == ("802.3/LLC", "CDP")


def test_llc_frames_that_are_neither_stp_nor_cdp_stay_generic():
    # SNAP, but a different OUI/PID than Cisco CDP — must not be misnamed.
    payload = (bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]) + struct.pack("!H", 0x0001)
               + b"\x00" * 10)
    v = classify(eth(len(payload), payload))
    assert (v.l3, v.l4) == ("802.3/LLC", None)


def test_rip_is_named_by_port():
    v = classify(eth(0x0800, ipv4(17, ports(520, 520))))
    assert v.app == "RIP"


def test_snapped_ip_frames_are_still_called_ip():
    """A snaplen-truncated IPv4 frame must not show up as ethertype 0x0800."""
    assert classify(eth(0x0800, b"\x45" + b"\x00" * 8)).l3 == "IPv4"
    assert classify(eth(0x86DD, b"\x60" + b"\x00" * 8)).l3 == "IPv6"


def test_classify_survives_anything():
    rng = random.Random(4)
    for _ in range(20000):
        n = rng.randrange(0, 80)
        classify(bytes(rng.randrange(256) for _ in range(n)))
    base = eth(0x86DD, ipv6(0, b"\x2c" + b"\xff" * 7 + b"\x00" * 64))
    for cut in range(len(base)):
        classify(base[:cut])
