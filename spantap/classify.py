# SPDX-License-Identifier: GPL-2.0-or-later
"""Cheap protocol classification of the frames we mirror.

Deliberately shallow: enough to answer "what am I actually sending?" in the
monitor, not a dissector. It touches only the headers — normally the first
few dozen bytes, further into the frame when IPv6 extension headers are
present — and does a bounded amount of work per packet, so it can run on every
packet without changing the shape of the throughput graph.
"""

from __future__ import annotations

import struct
from typing import NamedTuple, Optional

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_LLDP = 0x88CC
ETHERTYPE_MPLS = 0x8847
ETHERTYPE_ERSPAN = 0x88BE

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_FRAGMENT = 44
IPPROTO_AH = 51
IPPROTO_GRE = 47
IPPROTO_ICMPV6 = 58

# IPv6 extension headers we step over to find the real transport header.
# 0 hop-by-hop, 43 routing, 44 fragment, 51 AH, 60 destination, 135 mobility.
_V6_EXT = {0, 43, 44, 51, 60, 135}

_TRANSPORT = {
    IPPROTO_TCP: "TCP",
    IPPROTO_UDP: "UDP",
    IPPROTO_ICMP: "ICMP",
    IPPROTO_ICMPV6: "ICMPv6",
    IPPROTO_GRE: "GRE",
    2: "IGMP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
    112: "VRRP",
    132: "SCTP",
}

_PORTS = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
    135: "MSRPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 162: "SNMP", 179: "BGP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD", 520: "RIP",
    546: "DHCPv6", 547: "DHCPv6", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    1812: "RADIUS", 3306: "MySQL", 3389: "RDP", 4500: "IPsec NAT-T",
    5060: "SIP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch",
    57012: "PCAP-over-IP",
}

# 802.3/LLC frames (length field, not an EtherType — see the ``<= 0x05DC``
# branch below) all used to be lumped into one generic "802.3/LLC" bucket
# with no further label, so CDP and STP frames were genuinely on the wire
# (confirmed against real Wireshark) but invisible by name in spantap's own
# monitor — indistinguishable from each other and from anything else that
# happens to use LLC. DSAP/SSAP (and, for SNAP, the OUI+PID that follows)
# are enough to tell them apart without a real dissector.
_LLC_STP_DSAP = 0x42
_LLC_SNAP_DSAP = 0xAA
_SNAP_OUI_CISCO = b"\x00\x00\x0c"
_SNAP_PID_CDP = 0x2000


class Verdict(NamedTuple):
    l2: str                    # "Ethernet" or "VLAN"
    l3: str                    # IPv4 / IPv6 / ARP / LLDP / ...
    l4: Optional[str]          # TCP / UDP / ICMP / OSPF / ... — also CDP / STP,
                               # which have no real L4 but are identified this way
    app: Optional[str]         # best-effort, from the well-known port
    vlan_id: Optional[int]


def _app_from_ports(sport: int, dport: int) -> Optional[str]:
    """Pick the more meaningful of the two ports: the well-known one."""
    a, b = _PORTS.get(dport), _PORTS.get(sport)
    if a and b:
        return a if dport <= sport else b
    return a or b


def classify(frame: bytes) -> Verdict:
    """Classify one Ethernet frame. Never raises on short or odd input."""
    n = len(frame)
    if n < 14:
        return Verdict("Ethernet", "short", None, None, None)

    ethertype = (frame[12] << 8) | frame[13]
    off = 14
    l2 = "Ethernet"
    vlan_id = None

    # Walk up to two tags: Q-in-Q shows up on plenty of real mirror ports.
    for _ in range(2):
        if ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ) and n >= off + 4:
            if vlan_id is None:
                vlan_id = ((frame[off] << 8) | frame[off + 1]) & 0x0FFF
            l2 = "VLAN"
            ethertype = (frame[off + 2] << 8) | frame[off + 3]
            off += 4
        else:
            break

    if ethertype == ETHERTYPE_ARP:
        return Verdict(l2, "ARP", None, None, vlan_id)
    if ethertype == ETHERTYPE_LLDP:
        return Verdict(l2, "LLDP", None, None, vlan_id)
    if ethertype == ETHERTYPE_MPLS:
        return Verdict(l2, "MPLS", None, None, vlan_id)

    if ethertype == ETHERTYPE_IPV4:
        if n < off + 20:
            return Verdict(l2, "IPv4", None, None, vlan_id)
        ihl = (frame[off] & 0x0F) * 4
        if ihl < 20:
            return Verdict(l2, "IPv4", None, None, vlan_id)
        proto = frame[off + 9]
        frag_off = ((frame[off + 6] << 8) | frame[off + 7]) & 0x1FFF
        l4 = _TRANSPORT.get(proto, "IP proto %d" % proto)
        app = None
        # Only the first fragment carries the transport header.
        if frag_off == 0 and proto in (IPPROTO_TCP, IPPROTO_UDP) and n >= off + ihl + 4:
            sport, dport = struct.unpack("!HH", frame[off + ihl:off + ihl + 4])
            app = _app_from_ports(sport, dport)
        return Verdict(l2, "IPv4", l4, app, vlan_id)

    if ethertype == ETHERTYPE_IPV6:
        if n < off + 40:
            return Verdict(l2, "IPv6", None, None, vlan_id)
        nxt = frame[off + 6]
        p = off + 40
        first_fragment = True
        for _ in range(4):  # bounded walk; malformed chains must not loop
            if nxt not in _V6_EXT or n < p + 8:
                break
            if nxt == IPPROTO_FRAGMENT:
                # Only fragment offset 0 carries the transport header, exactly
                # as for IPv4; the rest is payload that would decode as ports.
                if ((frame[p + 2] << 8) | frame[p + 3]) >> 3:
                    first_fragment = False
                ext_len = 8
            elif nxt == IPPROTO_AH:
                # AH is the odd one out: Payload Len counts 32-bit words minus
                # two, not 8-octet units minus one.
                ext_len = (frame[p + 1] + 2) * 4
            else:
                ext_len = (frame[p + 1] + 1) * 8
            nxt = frame[p]
            p += ext_len
        l4 = _TRANSPORT.get(nxt, "IP proto %d" % nxt)
        app = None
        if first_fragment and nxt in (IPPROTO_TCP, IPPROTO_UDP) and n >= p + 4:
            sport, dport = struct.unpack("!HH", frame[p:p + 4])
            app = _app_from_ports(sport, dport)
        return Verdict(l2, "IPv6", l4, app, vlan_id)

    if ethertype <= 0x05DC:
        if n >= off + 3:
            dsap, ssap = frame[off], frame[off + 1]
            if dsap == _LLC_STP_DSAP and ssap == _LLC_STP_DSAP:
                return Verdict(l2, "802.3/LLC", "STP", None, vlan_id)
            if dsap == _LLC_SNAP_DSAP and ssap == _LLC_SNAP_DSAP and n >= off + 8:
                oui = frame[off + 3:off + 6]
                pid = (frame[off + 6] << 8) | frame[off + 7]
                if oui == _SNAP_OUI_CISCO and pid == _SNAP_PID_CDP:
                    return Verdict(l2, "802.3/LLC", "CDP", None, vlan_id)
        return Verdict(l2, "802.3/LLC", None, None, vlan_id)

    return Verdict(l2, "0x%04X" % ethertype, None, None, vlan_id)
