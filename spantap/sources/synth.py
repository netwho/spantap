# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic traffic generator.

Builds real, checksum-correct frames from scratch so the simulator can produce
traffic that no capture file happens to contain: VLAN tags, IPv6, jumbo frames
that force ERSPAN truncation, a steady known packet rate, and a small fake
network's worth of routing/bridging control-plane chatter (CDP, STP, OSPF,
RIP, LLDP, BGP, ARP) — so a tool built to read infrastructure information out
of a capture (device names, platform/capabilities, STP root/bridge roles,
OSPF neighbor adjacencies and DR election, BGP prefixes, ARP endpoints) has
something to show against synthetic traffic instead of only end-host
conversations. "campus" in particular is a literal reproduction of the
minimal fixture PacketCircle Map's own dev docs describe as enough to draw a
full infrastructure map.

All addresses come from the documentation ranges (RFC 5737 / RFC 3849) and all
MAC addresses are locally administered, so nothing here can be mistaken for
real traffic in a capture.
"""

from __future__ import annotations

import random
import socket
import struct
import time
from typing import Iterator, List, Optional

from ..encap import checksum16, ipv4_header
from .base import Packet, PacketSource
from .pcapread import LINKTYPE_ETHERNET

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_OSPF = 89
IPPROTO_ICMPV6 = 58

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_ARP = 0x0806
ETHERTYPE_LLDP = 0x88CC

# "infra" rotates through the four control-plane scenarios below; each is
# also individually selectable. "campus" rotates through the five
# PacketCircle-Map-focused scenarios (see the campus section below); each of
# those is also individually selectable. "mixed" rotates through the
# end-host protocols (everything here except jumbo and the infra/campus
# ones) — each client only speaks a subset of them; see
# _V4_CLIENT_PROTOCOLS below.
SCENARIOS = ("mixed", "dns", "http", "icmp", "bulk", "jumbo", "smb", "telnet",
             "cdp", "stp", "ospf", "rip", "infra",
             "lldp", "bgp", "arp", "campus")


# --------------------------------------------------------------------------
# frame builders
# --------------------------------------------------------------------------

def mac(n: int) -> bytes:
    """A locally-administered MAC derived from a small integer."""
    return bytes([0x02, 0x00, 0x00, 0x00, (n >> 8) & 0xFF, n & 0xFF])


def ethernet(dst: bytes, src: bytes, ethertype: int, vlan: Optional[int] = None,
             pcp: int = 0) -> bytes:
    if vlan is None:
        return dst + src + struct.pack("!H", ethertype)
    tci = ((pcp & 0x7) << 13) | (vlan & 0xFFF)
    return dst + src + struct.pack("!HHH", ETHERTYPE_VLAN, tci, ethertype)


def dot3(dst: bytes, src: bytes, payload: bytes, vlan: Optional[int] = None,
         pcp: int = 0) -> bytes:
    """802.3 frame: dst+src+[802.1Q tag]+length+payload.

    CDP and STP are LLC frames, not Ethernet II — what follows src (or the
    VLAN tag) is the payload *length*, not an EtherType, which is what tells
    a receiver to parse an LLC header next instead of an IPv4/IPv6/ARP one.
    """
    if vlan is None:
        return dst + src + struct.pack("!H", len(payload)) + payload
    tci = ((pcp & 0x7) << 13) | (vlan & 0xFFF)
    return dst + src + struct.pack("!HH", ETHERTYPE_VLAN, tci) + struct.pack("!H", len(payload)) + payload


def ipv6_header(src: str, dst: str, nxt: int, payload: bytes, hlim: int = 64) -> bytes:
    return (
        struct.pack("!IHBB", 0x60000000, len(payload), nxt, hlim)
        + socket.inet_pton(socket.AF_INET6, src)
        + socket.inet_pton(socket.AF_INET6, dst)
    )


def _pseudo_v4(src: str, dst: str, proto: int, length: int) -> bytes:
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, length)


def _pseudo_v6(src: str, dst: str, nxt: int, length: int) -> bytes:
    return (
        socket.inet_pton(socket.AF_INET6, src)
        + socket.inet_pton(socket.AF_INET6, dst)
        + struct.pack("!IBBBB", length, 0, 0, 0, nxt)
    )


def udp_segment(sport: int, dport: int, payload: bytes, src: str, dst: str,
                v6: bool = False) -> bytes:
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    proto = IPPROTO_UDP
    pseudo = _pseudo_v6(src, dst, proto, length) if v6 else _pseudo_v4(src, dst, proto, length)
    cks = checksum16(pseudo + hdr + payload) or 0xFFFF
    return hdr[:6] + struct.pack("!H", cks) + payload


def tcp_segment(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes,
                src: str, dst: str, v6: bool = False, window: int = 64240) -> bytes:
    offset_flags = (5 << 12) | (flags & 0x1FF)
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags, window, 0, 0)
    length = len(hdr) + len(payload)
    pseudo = (_pseudo_v6(src, dst, IPPROTO_TCP, length) if v6
              else _pseudo_v4(src, dst, IPPROTO_TCP, length))
    cks = checksum16(pseudo + hdr + payload)
    return hdr[:16] + struct.pack("!H", cks) + hdr[18:] + payload


def icmp_echo(ident: int, seq: int, payload: bytes, request: bool = True) -> bytes:
    hdr = struct.pack("!BBHHH", 8 if request else 0, 0, 0, ident, seq)
    cks = checksum16(hdr + payload)
    return hdr[:2] + struct.pack("!H", cks) + hdr[4:] + payload


MAC_BROADCAST = b"\xff" * 6
ARP_REQUEST = 1
ARP_REPLY = 2


def arp_packet(op: int, sha: bytes, spa: str, tha: bytes, tpa: str) -> bytes:
    """An Ethernet/IPv4 ARP request or reply (RFC 826)."""
    return (
        struct.pack("!HHBBH", 1, ETHERTYPE_IPV4, 6, 4, op)
        + sha + socket.inet_aton(spa) + tha + socket.inet_aton(tpa)
    )


def arp_frame(src_mac: bytes, dst_mac: bytes, arp_msg: bytes, vlan: Optional[int] = None) -> bytes:
    return ethernet(dst_mac, src_mac, ETHERTYPE_ARP, vlan) + arp_msg


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def dns_query(txid: int, name: str) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)


def dns_response(txid: int, name: str, addr: str) -> bytes:
    question = dns_name(name) + struct.pack("!HH", 1, 1)
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + socket.inet_aton(addr)
    return struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer


# SMB2 is little-endian on the wire, unlike everything else built in this
# file — every struct format below is "<", deliberately, not "!".
SMB2_MAGIC = b"\xfeSMB"
SMB2_CMD_NEGOTIATE = 0x0000
SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001


def smb2_header(command: int, message_id: int, response: bool = False,
                 process_id: int = 0xFEFF) -> bytes:
    flags = SMB2_FLAGS_SERVER_TO_REDIR if response else 0
    return struct.pack(
        "<4sHHIHHIIQIIQ16s",
        SMB2_MAGIC, 64, 1, 0, command, 1, flags, 0, message_id,
        process_id, 0, 0, b"\x00" * 16,
    )


def smb2_negotiate_request(client_guid: bytes, dialect: int = 0x0202) -> bytes:
    return (
        struct.pack("<HHHHI", 36, 1, 1, 0, 0)  # size, dialect count, security mode, reserved, caps
        + client_guid + b"\x00" * 8            # ClientGuid, ClientStartTime (must be zero pre-3.x)
        + struct.pack("<H", dialect)
    )


def smb2_negotiate_response(server_guid: bytes, dialect: int = 0x0202) -> bytes:
    return struct.pack(
        "<HHHH16sIIIIQQHHI",
        65, 1, dialect, 0, server_guid, 0,
        0x00800000, 0x00800000, 0x00800000,  # MaxTransact/Read/WriteSize
        0, 0,                                # SystemTime, ServerStartTime
        128, 0, 0,                           # SecurityBufferOffset/Length, NegotiateContextOffset
    )


def nbss(payload: bytes) -> bytes:
    """NetBIOS Session Service framing: a 1-byte type plus a 3-byte
    big-endian length, ahead of every SMB message on TCP/445."""
    return bytes([0x00]) + len(payload).to_bytes(3, "big") + payload


def telnet_negotiate(*opts: int) -> bytes:
    """IAC WILL <opt> for each option offered."""
    return b"".join(bytes([0xFF, 0xFB, o]) for o in opts)


# --------------------------------------------------------------------------
# routing / bridging control-plane protocols
#
# Unlike the host flows above, these are not a client talking to a server:
# CDP and STP are link-local multicast, and OSPF Hello/RIP are subnet-local
# multicast. Nothing here "replies" to anything; each is one fake device on
# a shared segment announcing itself, exactly the pattern a tool that reads
# infrastructure information out of a capture (device names, platform and
# capabilities, STP root/designated roles, OSPF neighbor adjacencies,
# advertised routes) is looking for.
# --------------------------------------------------------------------------

MAC_CDP = bytes.fromhex("0100cccccccc")   # CDP/VTP/DTP well-known multicast
MAC_STP = bytes.fromhex("0180c2000000")   # IEEE 802.1D STP BPDU multicast

IP_OSPF_ALLSPFROUTERS = "224.0.0.5"
IP_RIP2_ROUTERS = "224.0.0.9"
MAC_OSPF_ALLSPFROUTERS = bytes.fromhex("01005e000005")  # RFC 1112 IPv4->MAC mapping
MAC_RIP2_ROUTERS = bytes.fromhex("01005e000009")

LLC_SNAP_CDP = bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C]) + struct.pack("!H", 0x2000)
LLC_STP = bytes([0x42, 0x42, 0x03])

CDP_TYPE_DEVICE_ID = 0x0001
CDP_TYPE_ADDRESS = 0x0002
CDP_TYPE_PORT_ID = 0x0003
CDP_TYPE_CAPABILITIES = 0x0004
CDP_TYPE_SOFTWARE_VERSION = 0x0005
CDP_TYPE_PLATFORM = 0x0006

CDP_CAP_ROUTER = 0x01
CDP_CAP_SWITCH = 0x08


def cdp_tlv(kind: int, value: bytes) -> bytes:
    return struct.pack("!HH", kind, 4 + len(value)) + value


def cdp_address(ip: str) -> bytes:
    # One NLPID-addressed protocol entry: protocol type 1 (NLPID), protocol
    # length 1, protocol 0xCC (IP), address length, address.
    entry = struct.pack("!BBB", 1, 1, 0xCC) + struct.pack("!H", 4) + socket.inet_aton(ip)
    return struct.pack("!I", 1) + entry


def cdp_packet(device_id: str, port_id: str, capabilities: int, software_version: str,
               platform: str, address: Optional[str] = None, ttl: int = 180) -> bytes:
    tlvs = (
        cdp_tlv(CDP_TYPE_DEVICE_ID, device_id.encode())
        + cdp_tlv(CDP_TYPE_PORT_ID, port_id.encode())
        + cdp_tlv(CDP_TYPE_CAPABILITIES, struct.pack("!I", capabilities))
        + cdp_tlv(CDP_TYPE_SOFTWARE_VERSION, software_version.encode())
        + cdp_tlv(CDP_TYPE_PLATFORM, platform.encode())
    )
    if address:
        tlvs += cdp_tlv(CDP_TYPE_ADDRESS, cdp_address(address))
    msg = struct.pack("!BBH", 0x02, ttl, 0) + tlvs  # version, ttl, checksum placeholder
    cks = checksum16(msg)
    return msg[:2] + struct.pack("!H", cks) + msg[4:]


def cdp_frame(src_mac: bytes, cdp_msg: bytes, vlan: Optional[int] = None) -> bytes:
    return dot3(MAC_CDP, src_mac, LLC_SNAP_CDP + cdp_msg, vlan)


def stp_bpdu(root_priority: int, root_mac: bytes, root_path_cost: int,
             bridge_priority: int, bridge_mac: bytes, port_id: int,
             message_age: float = 0, max_age: float = 20, hello_time: float = 2,
             forward_delay: float = 15, topology_change: bool = False) -> bytes:
    """A classic (802.1D) Configuration BPDU. Times are seconds; on the wire
    they're 1/256ths, per spec."""
    flags = 0x01 if topology_change else 0x00
    root_id = struct.pack("!H", root_priority) + root_mac
    bridge_id = struct.pack("!H", bridge_priority) + bridge_mac
    return (
        struct.pack("!HBBB", 0x0000, 0x00, 0x00, flags)  # protocol id, version, type, flags
        + root_id
        + struct.pack("!I", root_path_cost)
        + bridge_id
        + struct.pack("!H", port_id)
        + struct.pack("!HHHH", int(message_age * 256), int(max_age * 256),
                      int(hello_time * 256), int(forward_delay * 256))
    )


def stp_frame(bpdu: bytes, src_mac: bytes, vlan: Optional[int] = None) -> bytes:
    return dot3(MAC_STP, src_mac, LLC_STP + bpdu, vlan)


def ospf_hello(router_id: str, area_id: str, netmask: str, neighbors: List[str],
               hello_interval: int = 10, dead_interval: int = 40, priority: int = 1,
               options: int = 0x02, dr: str = "0.0.0.0", bdr: str = "0.0.0.0") -> bytes:
    """An OSPFv2 Hello. Rides directly on IP protocol 89 — no UDP/TCP."""
    body = (
        socket.inet_aton(netmask)
        + struct.pack("!HBB", hello_interval, options, priority)
        + struct.pack("!I", dead_interval)
        + socket.inet_aton(dr) + socket.inet_aton(bdr)
        + b"".join(socket.inet_aton(n) for n in neighbors)
    )
    # The 16-byte common header up to and including AuType; checksum is
    # computed with it zeroed and, per RFC 2328 D.4.3, excludes the 64-bit
    # Authentication field that follows it.
    hdr16 = (struct.pack("!BBH", 2, 1, 24 + len(body))
             + socket.inet_aton(router_id) + socket.inet_aton(area_id)
             + struct.pack("!HH", 0, 0))
    cks = checksum16(hdr16 + body)
    hdr16 = hdr16[:12] + struct.pack("!H", cks) + hdr16[14:16]
    return hdr16 + b"\x00" * 8 + body


def ospf_frame(src_mac: bytes, router_id: str, neighbors: List[str],
               vlan: Optional[int] = None, dr: str = "0.0.0.0", bdr: str = "0.0.0.0") -> bytes:
    hello = ospf_hello(router_id, "0.0.0.0", "255.255.255.0", neighbors, dr=dr, bdr=bdr)
    ip_hdr = ipv4_header(router_id, IP_OSPF_ALLSPFROUTERS, len(hello),
                          ttl=1, df=False, proto=IPPROTO_OSPF)
    return ethernet(MAC_OSPF_ALLSPFROUTERS, src_mac, ETHERTYPE_IPV4, vlan) + ip_hdr + hello


def rip_entry(network: str, mask: str, metric: int, next_hop: str = "0.0.0.0",
              tag: int = 0) -> bytes:
    return (struct.pack("!HH", 2, tag) + socket.inet_aton(network)
            + socket.inet_aton(mask) + socket.inet_aton(next_hop) + struct.pack("!I", metric))


def rip_frame(src_mac: bytes, router_ip: str, routes: List[tuple],
              vlan: Optional[int] = None) -> bytes:
    """A RIPv2 Response advertising ``routes`` (network, mask, metric)."""
    entries = b"".join(rip_entry(net, mask, metric) for net, mask, metric in routes)
    msg = struct.pack("!BBH", 2, 2, 0) + entries  # command=response, version=2
    udp = udp_segment(520, 520, msg, router_ip, IP_RIP2_ROUTERS, v6=False)
    ip_hdr = ipv4_header(router_ip, IP_RIP2_ROUTERS, len(udp), ttl=1, df=False, proto=IPPROTO_UDP)
    return ethernet(MAC_RIP2_ROUTERS, src_mac, ETHERTYPE_IPV4, vlan) + ip_hdr + udp


# -- LLDP (IEEE 802.1AB) -----------------------------------------------------
#
# The vendor-neutral alternative to CDP. Type/length are packed into the same
# two leading bytes (7 bits type, 9 bits length) ahead of every TLV; a bare
# zero-length "type 0" TLV terminates the LLDPDU.

MAC_LLDP = bytes.fromhex("0180c200000e")  # LLDP Nearest Bridge multicast

LLDP_TYPE_END = 0
LLDP_TYPE_CHASSIS_ID = 1
LLDP_TYPE_PORT_ID = 2
LLDP_TYPE_TTL = 3
LLDP_TYPE_SYSTEM_NAME = 5
LLDP_TYPE_CAPABILITIES = 7
LLDP_TYPE_MGMT_ADDR = 8

LLDP_CHASSIS_SUBTYPE_MAC = 4
LLDP_PORT_SUBTYPE_IFNAME = 5
LLDP_MGMT_SUBTYPE_IPV4 = 1

LLDP_CAP_BRIDGE = 0x0004
LLDP_CAP_ROUTER = 0x0010


def lldp_tlv(kind: int, value: bytes) -> bytes:
    return struct.pack("!H", ((kind & 0x7F) << 9) | (len(value) & 0x1FF)) + value


def lldp_pdu(chassis_mac: bytes, port_name: str, system_name: str,
             capabilities: int, mgmt_ip: Optional[str] = None, ttl: int = 120) -> bytes:
    out = (
        lldp_tlv(LLDP_TYPE_CHASSIS_ID, bytes([LLDP_CHASSIS_SUBTYPE_MAC]) + chassis_mac)
        + lldp_tlv(LLDP_TYPE_PORT_ID, bytes([LLDP_PORT_SUBTYPE_IFNAME]) + port_name.encode())
        + lldp_tlv(LLDP_TYPE_TTL, struct.pack("!H", ttl))
        + lldp_tlv(LLDP_TYPE_SYSTEM_NAME, system_name.encode())
        + lldp_tlv(LLDP_TYPE_CAPABILITIES, struct.pack("!HH", capabilities, capabilities))
    )
    if mgmt_ip:
        # addr string len (1 + 4 bytes: subtype + IPv4), subtype, address,
        # interface-numbering subtype (2=ifindex), interface number, OID len=0.
        addr = bytes([LLDP_MGMT_SUBTYPE_IPV4]) + socket.inet_aton(mgmt_ip)
        out += lldp_tlv(LLDP_TYPE_MGMT_ADDR,
                         bytes([len(addr)]) + addr + struct.pack("!BIB", 2, 1, 0))
    out += lldp_tlv(LLDP_TYPE_END, b"")
    return out


def lldp_frame(src_mac: bytes, pdu: bytes, vlan: Optional[int] = None) -> bytes:
    return ethernet(MAC_LLDP, src_mac, ETHERTYPE_LLDP, vlan) + pdu


# -- BGP-4 (RFC 4271) ---------------------------------------------------------
#
# Rides on TCP/179 like any other application, so — unlike CDP/STP/OSPF/RIP
# above — a BGP session is a real TCP flow between two specific routers, not
# link-local or subnet-local multicast. Built with the same tcp_segment()
# every host flow below uses.

BGP_TYPE_OPEN = 1
BGP_TYPE_UPDATE = 2
BGP_TYPE_KEEPALIVE = 4
_BGP_MARKER = b"\xff" * 16


def bgp_message(msg_type: int, body: bytes = b"") -> bytes:
    return _BGP_MARKER + struct.pack("!HB", 19 + len(body), msg_type) + body


def bgp_open(asn: int, bgp_id: str, hold_time: int = 180) -> bytes:
    body = struct.pack("!BHH", 4, asn, hold_time) + socket.inet_aton(bgp_id) + b"\x00"
    return bgp_message(BGP_TYPE_OPEN, body)


def bgp_path_attr(flags: int, type_code: int, value: bytes) -> bytes:
    return struct.pack("!BBB", flags, type_code, len(value)) + value


def bgp_nlri(prefix: str, prefix_len: int) -> bytes:
    n = (prefix_len + 7) // 8
    return bytes([prefix_len]) + socket.inet_aton(prefix)[:n]


def bgp_update(next_hop: str, prefixes: List[tuple]) -> bytes:
    """An UPDATE with no withdrawals, ORIGIN/AS_PATH/NEXT_HOP attributes, and
    NLRI for each (network, prefix_len) in ``prefixes``. An empty AS_PATH is
    correct here — these are iBGP peers in the same AS, so nothing is
    prepended."""
    attrs = (
        bgp_path_attr(0x40, 1, b"\x00")               # ORIGIN = IGP
        + bgp_path_attr(0x40, 2, b"")                  # AS_PATH, empty (iBGP)
        + bgp_path_attr(0x40, 3, socket.inet_aton(next_hop))  # NEXT_HOP
    )
    nlri = b"".join(bgp_nlri(net, plen) for net, plen in prefixes)
    body = struct.pack("!H", 0) + struct.pack("!H", len(attrs)) + attrs + nlri
    return bgp_message(BGP_TYPE_UPDATE, body)


class _InfraRouter:
    def __init__(self, n: int, ip: str, hostname: str):
        self.n = n
        self.mac = mac(0x100 + n)
        self.ip = ip
        self.router_id = ip
        self.hostname = hostname


class _InfraSwitch:
    def __init__(self, n: int, priority: int, hostname: str):
        self.n = n
        self.mac = mac(0x200 + n)
        self.priority = priority
        self.hostname = hostname


# A small fake three-router, three-switch network — enough for OSPF full
# adjacency, a non-trivial RIP routing table, and an unambiguous STP root —
# so a topology built from this traffic has more than one node in it.
_ROUTERS = [
    _InfraRouter(1, "192.0.2.1", "spantap-core1"),
    _InfraRouter(2, "192.0.2.2", "spantap-dist1"),
    _InfraRouter(3, "192.0.2.3", "spantap-edge1"),
]
_ROUTER_ROUTES = {
    _ROUTERS[0].n: [("198.51.100.0", "255.255.255.0", 1)],
    _ROUTERS[1].n: [("203.0.113.0", "255.255.255.0", 1), ("198.51.100.0", "255.255.255.0", 2)],
    _ROUTERS[2].n: [("203.0.113.0", "255.255.255.0", 1)],
}
_SWITCHES = [
    _InfraSwitch(1, 4096, "spantap-sw1"),   # lowest priority -> elected root
    _InfraSwitch(2, 32768, "spantap-sw2"),
    _InfraSwitch(3, 32768, "spantap-sw3"),
]
_ROOT_SWITCH = _SWITCHES[0]


def _flow_cdp(rng: random.Random, vlan: Optional[int]) -> List[bytes]:
    if rng.random() < 0.5:
        r = rng.choice(_ROUTERS)
        msg = cdp_packet(r.hostname, "GigabitEthernet0/%d" % rng.randrange(0, 4),
                          CDP_CAP_ROUTER, "spantap-sim synthetic router",
                          "spantap virtual router", address=r.ip)
        return [cdp_frame(r.mac, msg, vlan)]
    s = rng.choice(_SWITCHES)
    msg = cdp_packet(s.hostname, "FastEthernet0/%d" % rng.randrange(0, 24),
                      CDP_CAP_SWITCH, "spantap-sim synthetic switch",
                      "spantap virtual switch")
    return [cdp_frame(s.mac, msg, vlan)]


def _flow_stp(rng: random.Random, vlan: Optional[int]) -> List[bytes]:
    s = rng.choice(_SWITCHES)
    cost = 0 if s is _ROOT_SWITCH else 19
    bpdu = stp_bpdu(_ROOT_SWITCH.priority, _ROOT_SWITCH.mac, cost,
                     s.priority, s.mac, port_id=0x8000 | s.n)
    return [stp_frame(bpdu, s.mac, vlan)]


def _flow_ospf(rng: random.Random, vlan: Optional[int]) -> List[bytes]:
    r = rng.choice(_ROUTERS)
    neighbors = [x.router_id for x in _ROUTERS if x is not r]
    # Every router on a segment agrees on the same elected DR/BDR — fixed
    # here (first/second router) rather than actually run the election, but
    # every Hello, from whichever router, reports the same pair, exactly as
    # real OSPF would once the election has settled.
    return [ospf_frame(r.mac, r.router_id, neighbors, vlan,
                        dr=_ROUTERS[0].router_id, bdr=_ROUTERS[1].router_id)]


def _flow_rip(rng: random.Random, vlan: Optional[int]) -> List[bytes]:
    r = rng.choice(_ROUTERS)
    return [rip_frame(r.mac, r.ip, _ROUTER_ROUTES[r.n], vlan)]


_INFRA_FLOWS = {
    "cdp": _flow_cdp,
    "stp": _flow_stp,
    "ospf": _flow_ospf,
    "rip": _flow_rip,
}


# --------------------------------------------------------------------------
# "campus": a fixed small network matching, field for field, the minimal
# fixture PacketCircle Map's own dev docs describe as enough to draw a full
# L2+L3 picture — root/distribution/access switches naming their uplink
# ports, an OSPF DR election, an iBGP session carrying real prefixes, and a
# few ARP speakers so Access isn't empty. Deliberately a separate, dedicated
# cast (its own routers/switches/hosts, its own 10.0.0.0/8 addressing) rather
# than reusing _ROUTERS/_SWITCHES above, so this scenario reproduces that
# recipe exactly rather than approximately.
# --------------------------------------------------------------------------

_CAMPUS_ROUTERS = [
    _InfraRouter(11, "10.0.0.1", "campus-core-rtr"),   # elected OSPF DR
    _InfraRouter(12, "10.0.0.2", "campus-dist-rtr"),   # also this router's iBGP peer
    _InfraRouter(13, "10.0.0.3", "campus-edge-rtr"),
]
_CAMPUS_BGP_AS = 65001
_CAMPUS_BGP_PREFIXES = [("10.10.0.0", 24), ("10.20.0.0", 24)]

_CAMPUS_SWITCHES = [
    _InfraSwitch(21, 4096, "core-sw"),      # lowest priority -> elected STP root
    _InfraSwitch(22, 32768, "dist-sw"),
    _InfraSwitch(23, 32768, "access-sw"),
]
_CAMPUS_ROOT_SWITCH = _CAMPUS_SWITCHES[0]

# A few endpoints on the two subnets BGP advertises, ARPing for their
# gateway — the campus core router's interface on each subnet — so Access
# has something in it besides silent infrastructure.
_CAMPUS_GATEWAY_MAC = _CAMPUS_ROUTERS[0].mac
_CAMPUS_HOSTS = [
    ("10.10.0.101", mac(0x300 + 1), "10.10.0.1"),
    ("10.10.0.102", mac(0x300 + 2), "10.10.0.1"),
    ("10.20.0.101", mac(0x300 + 3), "10.20.0.1"),
    ("10.20.0.102", mac(0x300 + 4), "10.20.0.1"),
    ("10.20.0.103", mac(0x300 + 5), "10.20.0.1"),
]


def _flow_campus_stp(rng: random.Random, vlan: Optional[int]) -> List[bytes]:
    s = rng.choice(_CAMPUS_SWITCHES)
    cost = 0 if s is _CAMPUS_ROOT_SWITCH else 19
    bpdu = stp_bpdu(_CAMPUS_ROOT_SWITCH.priority, _CAMPUS_ROOT_SWITCH.mac, cost,
                     s.priority, s.mac, port_id=0x8000 | s.n)
    return [stp_frame(bpdu, s.mac, vlan)]


def _flow_lldp(rng: random.Random, vlan: Optional[int]) -> List[bytes]:
    if rng.random() < 0.4:
        r = rng.choice(_CAMPUS_ROUTERS)
        pdu = lldp_pdu(r.mac, "GigabitEthernet0/%d" % rng.randrange(0, 4), r.hostname,
                        LLDP_CAP_ROUTER, mgmt_ip=r.ip)
        return [lldp_frame(r.mac, pdu, vlan)]
    s = rng.choice(_CAMPUS_SWITCHES)
    pdu = lldp_pdu(s.mac, "GigabitEthernet1/0/%d" % s.n, s.hostname, LLDP_CAP_BRIDGE)
    return [lldp_frame(s.mac, pdu, vlan)]


def _flow_campus_ospf(rng: random.Random, vlan: Optional[int]) -> List[bytes]:
    r = rng.choice(_CAMPUS_ROUTERS)
    neighbors = [x.router_id for x in _CAMPUS_ROUTERS if x is not r]
    return [ospf_frame(r.mac, r.router_id, neighbors, vlan,
                        dr=_CAMPUS_ROUTERS[0].router_id, bdr=_CAMPUS_ROUTERS[1].router_id)]


def _flow_bgp(rng: random.Random, vlan: Optional[int]) -> List[bytes]:
    """A full iBGP session between the campus core and distribution routers:
    TCP handshake, OPEN both ways, KEEPALIVE both ways, then an UPDATE
    advertising the two campus subnets."""
    a, b = _CAMPUS_ROUTERS[0], _CAMPUS_ROUTERS[1]
    sport = rng.randrange(20000, 60000)
    cseq, sseq = rng.randrange(1 << 30), rng.randrange(1 << 30)

    def seg(src, dst, sp, dp, seq, ack, flags, payload):
        t = tcp_segment(sp, dp, seq, ack, flags, payload, src.ip, dst.ip, v6=False)
        ip_hdr = ipv4_header(src.ip, dst.ip, len(t), ttl=64,
                              ident=rng.randrange(0x10000), df=False, proto=IPPROTO_TCP)
        return ethernet(dst.mac, src.mac, ETHERTYPE_IPV4, vlan) + ip_hdr + t

    frames = [
        seg(a, b, sport, 179, cseq, 0, 0x002, b""),               # SYN
        seg(b, a, 179, sport, sseq, cseq + 1, 0x012, b""),        # SYN,ACK
        seg(a, b, sport, 179, cseq + 1, sseq + 1, 0x010, b""),    # ACK
    ]
    c_seq, s_seq = cseq + 1, sseq + 1
    for payload, sender, other, sp, dp in (
        (bgp_open(_CAMPUS_BGP_AS, a.router_id), a, b, sport, 179),
        (bgp_open(_CAMPUS_BGP_AS, b.router_id), b, a, 179, sport),
        (bgp_message(BGP_TYPE_KEEPALIVE), a, b, sport, 179),
        (bgp_message(BGP_TYPE_KEEPALIVE), b, a, 179, sport),
        (bgp_update(a.router_id, _CAMPUS_BGP_PREFIXES), a, b, sport, 179),
    ):
        if sender is a:
            frames.append(seg(a, b, sp, dp, c_seq, s_seq, 0x018, payload))
            c_seq += len(payload)
        else:
            frames.append(seg(b, a, sp, dp, s_seq, c_seq, 0x018, payload))
            s_seq += len(payload)
    frames.append(seg(b, a, 179, sport, s_seq, c_seq, 0x010, b""))  # final ACK
    return frames


def _flow_arp(rng: random.Random, vlan: Optional[int]) -> List[bytes]:
    host_ip, host_mac, gw_ip = rng.choice(_CAMPUS_HOSTS)
    req = arp_packet(ARP_REQUEST, host_mac, host_ip, b"\x00" * 6, gw_ip)
    reply = arp_packet(ARP_REPLY, _CAMPUS_GATEWAY_MAC, gw_ip, host_mac, host_ip)
    return [
        arp_frame(host_mac, MAC_BROADCAST, req, vlan),
        arp_frame(_CAMPUS_GATEWAY_MAC, host_mac, reply, vlan),
    ]


_CAMPUS_FLOWS = {
    "stp": _flow_campus_stp,
    "lldp": _flow_lldp,
    "ospf": _flow_campus_ospf,
    "bgp": _flow_bgp,
    "arp": _flow_arp,
}


# --------------------------------------------------------------------------
# flow scenarios
# --------------------------------------------------------------------------

# A single hard-coded client/server pair meant every conversation in a
# capture looked identical apart from ports — Wireshark's "Conversations"
# view showed just one IPv4 pair and one IPv6 pair. Instead, draw from a
# pool of documentation-range hosts (still RFC 5737 / RFC 3849, still
# unmistakably fake) big enough to give at least 20 distinct pairs of each
# address family.
_V4_CLIENTS = ["192.0.2.%d" % i for i in range(10, 15)]  # 5 hosts
_V4_SERVERS = ["198.51.100.53", "198.51.100.80", "198.51.100.88",
               "203.0.113.10", "203.0.113.53"]  # 5 hosts
_V4_PAIRS = [(c, s) for c in _V4_CLIENTS for s in _V4_SERVERS]  # 25 pairs

_V6_CLIENTS = ["2001:db8:1::%x" % i for i in range(0x10, 0x15)]  # 5 hosts
_V6_SERVERS = ["2001:db8:2::53", "2001:db8:2::80", "2001:db8:2::88",
               "2001:db8:3::10", "2001:db8:3::53"]  # 5 hosts
_V6_PAIRS = [(c, s) for c in _V6_CLIENTS for s in _V6_SERVERS]  # 25 pairs

# Every client used to be eligible for every protocol, picked independently
# per flow — so filtering a capture down to one protocol showed the same set
# of IPs as the unfiltered capture. Real hosts specialise: some browse, some
# serve files, some are old enough to still run telnet. Each client below
# gets a fixed, small subset of _MIXED_POOL's protocols — never all of them,
# and every protocol still has at least one client that speaks it (checked
# by test_every_mixed_protocol_has_at_least_one_client). Servers stay
# unrestricted: this is about what a *client* initiates, not who answers.
_V4_CLIENT_PROTOCOLS = {
    _V4_CLIENTS[0]: ("dns", "http"),
    _V4_CLIENTS[1]: ("http", "smb"),
    _V4_CLIENTS[2]: ("icmp", "telnet"),
    _V4_CLIENTS[3]: ("bulk", "dns"),
    _V4_CLIENTS[4]: ("smb", "telnet", "icmp"),
}
_V6_CLIENT_PROTOCOLS = {
    _V6_CLIENTS[0]: ("dns", "http"),
    _V6_CLIENTS[1]: ("http", "bulk"),
    _V6_CLIENTS[2]: ("icmp", "smb"),
    _V6_CLIENTS[3]: ("telnet", "dns"),
    _V6_CLIENTS[4]: ("bulk", "telnet", "icmp"),
}


def _clients_for(name: str, v6: bool) -> List[str]:
    pool = _V6_CLIENT_PROTOCOLS if v6 else _V4_CLIENT_PROTOCOLS
    return [c for c, protocols in pool.items() if name in protocols]


# One locally-administered MAC per unique address, shared across pools so
# each host keeps the same MAC whichever role (client/server) it plays.
_ALL_HOSTS = list(dict.fromkeys(_V4_CLIENTS + _V4_SERVERS + _V6_CLIENTS + _V6_SERVERS))
_HOST_MAC = {addr: mac(i + 1) for i, addr in enumerate(_ALL_HOSTS)}


class _Builder:
    """Knows a pair of fake hosts and hands back finished Ethernet frames."""

    def __init__(self, rng: random.Random, client: str, server: str,
                 vlan: Optional[int] = None, v6: bool = False):
        self.rng = rng
        self.vlan = vlan
        self.v6 = v6
        self.client = client
        self.server = server
        self.client_mac = _HOST_MAC[client]
        self.server_mac = _HOST_MAC[server]

    def _wrap(self, l4: bytes, proto: int, to_server: bool) -> bytes:
        src, dst = (self.client, self.server) if to_server else (self.server, self.client)
        smac, dmac = ((self.client_mac, self.server_mac) if to_server
                      else (self.server_mac, self.client_mac))
        if self.v6:
            ethertype = ETHERTYPE_IPV6
            ip_hdr = ipv6_header(src, dst, proto, l4)
        else:
            ethertype = ETHERTYPE_IPV4
            ip_hdr = ipv4_header(src, dst, len(l4), ttl=64,
                                 ident=self.rng.randrange(0x10000), df=False, proto=proto)
        return ethernet(dmac, smac, ethertype, self.vlan) + ip_hdr + l4


def _flow_dns(b: _Builder) -> List[bytes]:
    txid = b.rng.randrange(0x10000)
    sport = b.rng.randrange(20000, 60000)
    name = b.rng.choice(["www.example.com", "packetfactor.example", "swisspunk.example"])
    q = udp_segment(sport, 53, dns_query(txid, name), b.client, b.server, b.v6)
    a = udp_segment(53, sport, dns_response(txid, name, "198.51.100.80"), b.server, b.client, b.v6)
    return [b._wrap(q, IPPROTO_UDP, True), b._wrap(a, IPPROTO_UDP, False)]


def _flow_http(b: _Builder) -> List[bytes]:
    sport = b.rng.randrange(20000, 60000)
    cseq, sseq = b.rng.randrange(1 << 30), b.rng.randrange(1 << 30)
    req = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: spantap-sim\r\n\r\n"
    body = b"<html><body>spantap-sim synthetic response</body></html>"
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body)
    f = []
    f.append(b._wrap(tcp_segment(sport, 80, cseq, 0, 0x002, b"", b.client, b.server, b.v6),
                     IPPROTO_TCP, True))
    f.append(b._wrap(tcp_segment(80, sport, sseq, cseq + 1, 0x012, b"", b.server, b.client, b.v6),
                     IPPROTO_TCP, False))
    f.append(b._wrap(tcp_segment(sport, 80, cseq + 1, sseq + 1, 0x010, b"", b.client, b.server, b.v6),
                     IPPROTO_TCP, True))
    f.append(b._wrap(tcp_segment(sport, 80, cseq + 1, sseq + 1, 0x018, req, b.client, b.server, b.v6),
                     IPPROTO_TCP, True))
    f.append(b._wrap(tcp_segment(80, sport, sseq + 1, cseq + 1 + len(req), 0x018, resp,
                                 b.server, b.client, b.v6), IPPROTO_TCP, False))
    f.append(b._wrap(tcp_segment(sport, 80, cseq + 1 + len(req), sseq + 1 + len(resp), 0x011,
                                 b"", b.client, b.server, b.v6), IPPROTO_TCP, True))
    return f


def _flow_icmp(b: _Builder) -> List[bytes]:
    if b.v6:  # keep it simple: ICMPv6 needs a pseudo-header checksum
        return _flow_dns(b)
    ident = b.rng.randrange(0x10000)
    payload = bytes(range(0x08, 0x08 + 56))
    return [
        b._wrap(icmp_echo(ident, 1, payload, True), IPPROTO_ICMP, True),
        b._wrap(icmp_echo(ident, 1, payload, False), IPPROTO_ICMP, False),
    ]


def _flow_bulk(b: _Builder, segments: int = 8) -> List[bytes]:
    sport = b.rng.randrange(20000, 60000)
    seq = b.rng.randrange(1 << 30)
    chunk = bytes((i * 7) & 0xFF for i in range(1460))
    out = []
    for i in range(segments):
        out.append(b._wrap(
            tcp_segment(sport, 443, seq + i * len(chunk), 1, 0x010, chunk,
                        b.client, b.server, b.v6),
            IPPROTO_TCP, True))
    return out


def _flow_jumbo(b: _Builder, size: int = 8000) -> List[bytes]:
    """Oversized frames, to exercise ERSPAN truncation and the T bit."""
    sport = b.rng.randrange(20000, 60000)
    chunk = bytes((i * 11) & 0xFF for i in range(size))
    return [b._wrap(tcp_segment(sport, 9000, 1, 1, 0x010, chunk, b.client, b.server, b.v6),
                    IPPROTO_TCP, True)]


def _flow_smb(b: _Builder) -> List[bytes]:
    """A minimal SMB2 Negotiate Protocol Request/Response over NBSS/TCP 445."""
    sport = b.rng.randrange(20000, 60000)
    cseq, sseq = b.rng.randrange(1 << 30), b.rng.randrange(1 << 30)
    mid = b.rng.randrange(1 << 20)
    client_guid = b.rng.getrandbits(128).to_bytes(16, "little")
    server_guid = b.rng.getrandbits(128).to_bytes(16, "little")
    req = nbss(smb2_header(SMB2_CMD_NEGOTIATE, mid) + smb2_negotiate_request(client_guid))
    resp = nbss(smb2_header(SMB2_CMD_NEGOTIATE, mid, response=True)
                + smb2_negotiate_response(server_guid))
    f = []
    f.append(b._wrap(tcp_segment(sport, 445, cseq, 0, 0x002, b"", b.client, b.server, b.v6),
                     IPPROTO_TCP, True))
    f.append(b._wrap(tcp_segment(445, sport, sseq, cseq + 1, 0x012, b"", b.server, b.client, b.v6),
                     IPPROTO_TCP, False))
    f.append(b._wrap(tcp_segment(sport, 445, cseq + 1, sseq + 1, 0x010, b"", b.client, b.server, b.v6),
                     IPPROTO_TCP, True))
    f.append(b._wrap(tcp_segment(sport, 445, cseq + 1, sseq + 1, 0x018, req, b.client, b.server, b.v6),
                     IPPROTO_TCP, True))
    f.append(b._wrap(tcp_segment(445, sport, sseq + 1, cseq + 1 + len(req), 0x018, resp,
                                 b.server, b.client, b.v6), IPPROTO_TCP, False))
    f.append(b._wrap(tcp_segment(sport, 445, cseq + 1 + len(req), sseq + 1 + len(resp), 0x011,
                                 b"", b.client, b.server, b.v6), IPPROTO_TCP, True))
    return f


def _flow_telnet(b: _Builder) -> List[bytes]:
    """A TCP/23 session: option negotiation, a login banner, a typed username."""
    sport = b.rng.randrange(20000, 60000)
    cseq, sseq = b.rng.randrange(1 << 30), b.rng.randrange(1 << 30)
    greeting = (telnet_negotiate(0x01, 0x03)  # IAC WILL ECHO, IAC WILL SUPPRESS-GO-AHEAD
                + b"\r\nspantap-sim synthetic host\r\nlogin: ")
    username = b"demo\r\n"
    f = []
    f.append(b._wrap(tcp_segment(sport, 23, cseq, 0, 0x002, b"", b.client, b.server, b.v6),
                     IPPROTO_TCP, True))
    f.append(b._wrap(tcp_segment(23, sport, sseq, cseq + 1, 0x012, b"", b.server, b.client, b.v6),
                     IPPROTO_TCP, False))
    f.append(b._wrap(tcp_segment(sport, 23, cseq + 1, sseq + 1, 0x010, b"", b.client, b.server, b.v6),
                     IPPROTO_TCP, True))
    f.append(b._wrap(tcp_segment(23, sport, sseq + 1, cseq + 1, 0x018, greeting,
                                 b.server, b.client, b.v6), IPPROTO_TCP, False))
    f.append(b._wrap(tcp_segment(sport, 23, cseq + 1, sseq + 1 + len(greeting), 0x018, username,
                                 b.client, b.server, b.v6), IPPROTO_TCP, True))
    f.append(b._wrap(tcp_segment(23, sport, sseq + 1 + len(greeting), cseq + 1 + len(username),
                                 0x011, b"", b.server, b.client, b.v6), IPPROTO_TCP, False))
    return f


_HOST_FLOWS = {
    "dns": _flow_dns,
    "http": _flow_http,
    "icmp": _flow_icmp,
    "bulk": _flow_bulk,
    "jumbo": _flow_jumbo,
    "smb": _flow_smb,
    "telnet": _flow_telnet,
}
# jumbo stays opt-in only, as before — the others are what a client is
# assigned a subset of via _V4_CLIENT_PROTOCOLS / _V6_CLIENT_PROTOCOLS.
_MIXED_POOL = ("dns", "http", "icmp", "bulk", "smb", "telnet")


class SyntheticSource(PacketSource):
    def __init__(
        self,
        scenario: str = "mixed",
        count: int = 0,
        seed: int = 0,
        vlan: Optional[int] = None,
        v6_ratio: float = 0.25,
    ):
        if scenario not in SCENARIOS:
            raise ValueError("unknown scenario %r; pick one of %s" % (scenario, ", ".join(SCENARIOS)))
        self.scenario = scenario
        self.count = count
        self.rng = random.Random(seed or 0xC0FFEE)
        self.vlan = vlan
        self.v6_ratio = v6_ratio
        self.description = "synthetic %s traffic%s%s" % (
            scenario,
            " (%d packets)" % count if count else " (unlimited)",
            ", VLAN %d" % vlan if vlan else "",
        )

    def _next_flow(self) -> List[bytes]:
        if self.scenario == "mixed":
            name = self.rng.choice(_MIXED_POOL)
        elif self.scenario == "infra":
            name = self.rng.choice(list(_INFRA_FLOWS))
        elif self.scenario == "campus":
            name = self.rng.choice(list(_CAMPUS_FLOWS))
            return _CAMPUS_FLOWS[name](self.rng, self.vlan)
        else:
            name = self.scenario

        if name in _INFRA_FLOWS:
            return _INFRA_FLOWS[name](self.rng, self.vlan)
        if name in _CAMPUS_FLOWS and name not in _INFRA_FLOWS:
            # Individually-selectable "lldp"/"bgp"/"arp" — the campus-only
            # protocols. "stp"/"ospf" are ambiguous by name alone (both infra
            # and campus have one); the _INFRA_FLOWS check above already
            # claims those for the original spantap-core/spantap-sw cast, so
            # only the campus scenario itself (handled above) reaches them.
            return _CAMPUS_FLOWS[name](self.rng, self.vlan)

        v6 = self.rng.random() < self.v6_ratio
        if name in _MIXED_POOL:
            # Only a client assigned this protocol gets to use it — this is
            # what makes filtering a mixed capture down to one protocol show
            # fewer IPs than the unfiltered capture. Servers are shared.
            client = self.rng.choice(_clients_for(name, v6))
            server = self.rng.choice(_V6_SERVERS if v6 else _V4_SERVERS)
        else:
            # jumbo: a stress scenario, not a "device speaks this app" one —
            # any client/server pair is eligible, same as always.
            client, server = self.rng.choice(_V6_PAIRS if v6 else _V4_PAIRS)
        builder = _Builder(self.rng, client, server, vlan=self.vlan, v6=v6)
        return _HOST_FLOWS[name](builder)

    def __iter__(self) -> Iterator[Packet]:
        sent = 0
        while not self.count or sent < self.count:
            for frame in self._next_flow():
                yield Packet(
                    ts_ns=time.time_ns(),
                    linktype=LINKTYPE_ETHERNET,
                    data=frame,
                    orig_len=len(frame),
                )
                sent += 1
                if self.count and sent >= self.count:
                    return
