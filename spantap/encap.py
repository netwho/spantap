# SPDX-License-Identifier: GPL-2.0-or-later
"""ERSPAN Type II encapsulation.

Wire layout produced here (IPv4 transport)::

    +---------------------------+  20 bytes  IPv4, protocol 47 (GRE)
    +---------------------------+   8 bytes  GRE: flags 0x1000 (S), proto 0x88BE, seq
    +---------------------------+   8 bytes  ERSPAN Type II header
    +---------------------------+   n bytes  mirrored Ethernet frame (possibly truncated)

ERSPAN Type II header, per Cisco / draft-foschiano-erspan::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Ver  |          VLAN         | COS |En |T|   Session ID      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Reserved          |                  Index                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Ver is 1 for Type II.  The GRE sequence number is mandatory for Type II, which
is why the GRE flags word is 0x1000 and the header is 8 rather than 4 bytes.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

IPPROTO_GRE = 47
ETH_P_ERSPAN_TYPE2 = 0x88BE
ETH_P_ERSPAN_TYPE3 = 0x22EB

GRE_FLAGS_SEQ = 0x1000

IPV4_HDR_LEN = 20
GRE_HDR_LEN = 8
ERSPAN2_HDR_LEN = 8
ENCAP_OVERHEAD = IPV4_HDR_LEN + GRE_HDR_LEN + ERSPAN2_HDR_LEN  # 36

# ERSPAN "En" field — what was done with the original 802.1Q tag.
EN_NONE = 0  # original frame had no tag, or tag left in frame; VLAN field invalid
EN_ISL = 1
EN_DOT1Q = 2  # tag was stripped by the source; VLAN field carries it
EN_PRESERVED = 3  # frame is mirrored with its tag intact; VLAN field also set

MAX_SESSION_ID = 0x3FF
MAX_VLAN = 0xFFF
MAX_INDEX = 0xFFFFF


def checksum16(data: bytes) -> int:
    """Standard Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_header(
    src: str,
    dst: str,
    payload_len: int,
    *,
    ttl: int = 64,
    dscp: int = 0,
    ecn: int = 0,
    ident: int = 0,
    df: bool = True,
    proto: int = IPPROTO_GRE,
) -> bytes:
    """Build a 20-byte IPv4 header with a correct checksum."""
    ver_ihl = 0x45
    tos = ((dscp & 0x3F) << 2) | (ecn & 0x03)
    total_len = IPV4_HDR_LEN + payload_len
    if total_len > 0xFFFF:
        raise ValueError("IPv4 total length overflow: %d" % total_len)
    frag = 0x4000 if df else 0x0000
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ident & 0xFFFF, frag, ttl & 0xFF, proto, 0, src_b, dst_b,
    )
    cks = checksum16(hdr)
    return hdr[:10] + struct.pack("!H", cks) + hdr[12:]


def gre_header(seq: int, proto: int = ETH_P_ERSPAN_TYPE2) -> bytes:
    """GRE header with the sequence-number flag set (mandatory for ERSPAN II)."""
    return struct.pack("!HHI", GRE_FLAGS_SEQ, proto, seq & 0xFFFFFFFF)


def erspan2_header(
    *,
    session_id: int = 0,
    vlan: int = 0,
    cos: int = 0,
    en: int = EN_NONE,
    truncated: bool = False,
    index: int = 0,
) -> bytes:
    """Build the 8-byte ERSPAN Type II header."""
    if not 0 <= session_id <= MAX_SESSION_ID:
        raise ValueError("session_id must be 0..1023")
    if not 0 <= vlan <= MAX_VLAN:
        raise ValueError("vlan must be 0..4095")
    if not 0 <= index <= MAX_INDEX:
        raise ValueError("index must be 0..1048575")
    word0 = (
        (1 << 28)                      # Ver = 1 (Type II)
        | ((vlan & MAX_VLAN) << 16)
        | ((cos & 0x7) << 13)
        | ((en & 0x3) << 11)
        | ((1 if truncated else 0) << 10)
        | (session_id & MAX_SESSION_ID)
    )
    word1 = index & MAX_INDEX          # top 12 bits reserved, must be zero
    return struct.pack("!II", word0, word1)


@dataclass
class ErspanConfig:
    """Everything that shapes the ERSPAN packets we emit."""

    dst: str
    src: str = "0.0.0.0"
    session_id: int = 1
    vlan: int = 0
    cos: int = 0
    en: int = EN_NONE
    index: int = 0
    ttl: int = 64
    dscp: int = 0
    df: bool = True
    mtu: int = 1500

    def max_frame_len(self) -> int:
        """Largest mirrored frame that still fits in one ERSPAN packet."""
        room = self.mtu - ENCAP_OVERHEAD
        if room < 64:
            raise ValueError(
                "mtu %d is too small for ERSPAN (needs > %d)" % (self.mtu, ENCAP_OVERHEAD + 64)
            )
        return room


class ErspanEncapsulator:
    """Turns mirrored Ethernet frames into complete ERSPAN Type II IP packets.

    Stateful: it owns the GRE sequence number and the IP identification field,
    both of which a receiver may use to detect loss and reordering.
    """

    def __init__(self, config: ErspanConfig, start_seq: int = 0, start_ident: int = 1):
        self.config = config
        self.seq = start_seq & 0xFFFFFFFF
        self.ident = start_ident & 0xFFFF
        self.truncated_count = 0
        self._max_frame = config.max_frame_len()

    def encapsulate(self, frame: bytes) -> bytes:
        """Return one full IPv4/GRE/ERSPAN packet carrying ``frame``.

        Frames larger than the configured MTU allows are cut short and the
        ERSPAN ``T`` bit is set, which is what real hardware does.
        """
        cfg = self.config
        truncated = len(frame) > self._max_frame
        if truncated:
            frame = frame[: self._max_frame]
            self.truncated_count += 1

        payload = (
            gre_header(self.seq)
            + erspan2_header(
                session_id=cfg.session_id,
                vlan=cfg.vlan,
                cos=cfg.cos,
                en=cfg.en,
                truncated=truncated,
                index=cfg.index,
            )
            + frame
        )
        packet = ipv4_header(
            cfg.src, cfg.dst, len(payload),
            ttl=cfg.ttl, dscp=cfg.dscp, ident=self.ident, df=cfg.df,
        ) + payload

        self.seq = (self.seq + 1) & 0xFFFFFFFF
        self.ident = (self.ident + 1) & 0xFFFF
        return packet
