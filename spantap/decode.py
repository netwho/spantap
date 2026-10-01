# SPDX-License-Identifier: GPL-2.0-or-later
"""Decoder for the packets :mod:`spantap.encap` produces.

This exists so the simulator can check its own output without a second tool in
the loop, and so ``spantap-sim decode`` can explain a capture of ERSPAN traffic.
It is deliberately strict: anything that does not look like ERSPAN Type II
raises, rather than being quietly guessed at.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Optional

from .encap import (
    ERSPAN2_HDR_LEN,
    ETH_P_ERSPAN_TYPE2,
    ETH_P_ERSPAN_TYPE3,
    GRE_HDR_LEN,
    IPPROTO_GRE,
    checksum16,
)


class DecodeError(ValueError):
    """Raised when a buffer is not a well-formed ERSPAN Type II packet."""


@dataclass
class DecodedErspan:
    src: str
    dst: str
    ttl: int
    dscp: int
    ident: int
    df: bool
    ip_checksum_ok: bool
    gre_proto: int
    seq: int
    version: int
    vlan: int
    cos: int
    en: int
    truncated: bool
    session_id: int
    index: int
    frame: bytes

    def summary(self) -> str:
        return (
            "{s} -> {d}  ttl={t} id={i}  seq={q}  ver={v} session={ses} "
            "vlan={vl} cos={c} en={e} T={tr} index={x}  frame={n}B".format(
                s=self.src, d=self.dst, t=self.ttl, i=self.ident, q=self.seq,
                v=self.version, ses=self.session_id, vl=self.vlan, c=self.cos,
                e=self.en, tr=int(self.truncated), x=self.index, n=len(self.frame),
            )
        )


def decode_erspan2(packet: bytes) -> DecodedErspan:
    """Decode a raw IPv4 packet carrying GRE/ERSPAN Type II."""
    if len(packet) < 20:
        raise DecodeError("short packet: %d bytes" % len(packet))
    ver_ihl = packet[0]
    if ver_ihl >> 4 != 4:
        raise DecodeError("not IPv4 (first nibble %d)" % (ver_ihl >> 4))
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl:
        raise DecodeError("bad IHL %d" % ihl)

    tos, total_len, ident, frag, ttl, proto = struct.unpack("!BHHHBB", packet[1:10])
    src = socket.inet_ntoa(packet[12:16])
    dst = socket.inet_ntoa(packet[16:20])
    if proto != IPPROTO_GRE:
        raise DecodeError("IP protocol %d, expected %d (GRE)" % (proto, IPPROTO_GRE))
    ip_ck_ok = checksum16(packet[:ihl]) == 0

    body = packet[ihl:total_len] if total_len and total_len <= len(packet) else packet[ihl:]
    if len(body) < GRE_HDR_LEN + ERSPAN2_HDR_LEN:
        raise DecodeError("truncated GRE/ERSPAN header")

    flags, gre_proto, seq = struct.unpack("!HHI", body[:GRE_HDR_LEN])
    if gre_proto == ETH_P_ERSPAN_TYPE3:
        raise DecodeError("ERSPAN Type III (0x22EB) is not supported yet")
    if gre_proto != ETH_P_ERSPAN_TYPE2:
        raise DecodeError("GRE protocol 0x%04X, expected 0x88BE" % gre_proto)
    if not flags & 0x1000:
        raise DecodeError("GRE sequence flag not set; mandatory for ERSPAN Type II")
    if flags & 0x8000 or flags & 0x2000:
        raise DecodeError("GRE checksum/key flags set; not expected for ERSPAN Type II")

    word0, word1 = struct.unpack("!II", body[GRE_HDR_LEN:GRE_HDR_LEN + ERSPAN2_HDR_LEN])
    version = (word0 >> 28) & 0xF
    if version != 1:
        raise DecodeError("ERSPAN header version %d, expected 1" % version)

    return DecodedErspan(
        src=src,
        dst=dst,
        ttl=ttl,
        dscp=(tos >> 2) & 0x3F,
        ident=ident,
        df=bool(frag & 0x4000),
        ip_checksum_ok=ip_ck_ok,
        gre_proto=gre_proto,
        seq=seq,
        version=version,
        vlan=(word0 >> 16) & 0xFFF,
        cos=(word0 >> 13) & 0x7,
        en=(word0 >> 11) & 0x3,
        truncated=bool((word0 >> 10) & 0x1),
        session_id=word0 & 0x3FF,
        index=word1 & 0xFFFFF,
        frame=body[GRE_HDR_LEN + ERSPAN2_HDR_LEN:],
    )


def try_decode(packet: bytes) -> Optional[DecodedErspan]:
    """Like :func:`decode_erspan2` but returns ``None`` instead of raising."""
    try:
        return decode_erspan2(packet)
    except DecodeError:
        return None
