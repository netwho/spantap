# SPDX-License-Identifier: GPL-2.0-or-later
"""Minimal, dependency-free readers for classic pcap and pcapng.

Both readers are *streaming*: they work on a pipe just as well as on a file,
which is what lets the live source consume ``dumpcap -w -`` directly.  Only the
blocks a capture tool actually emits are understood; everything else is skipped
by length, which is the whole point of pcapng's block framing.
"""

from __future__ import annotations

import struct
from typing import BinaryIO, Iterator

from .base import Packet

# libpcap link types we know how to normalise to Ethernet.
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_RAW_BSD = 12
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

PCAP_MAGIC_US_BE = 0xA1B2C3D4
PCAP_MAGIC_NS_BE = 0xA1B23C4D
PCAPNG_SHB = 0x0A0D0D0A

_FAKE_DST = b"\x02\x00\x00\x00\x00\x02"
_FAKE_SRC = b"\x02\x00\x00\x00\x00\x01"


class PcapFormatError(ValueError):
    pass


def _read_exact(fh: BinaryIO, n: int) -> bytes:
    """Read up to ``n`` bytes, blocking until they arrive or the stream ends.

    A short return means end of stream.  Callers check the length and stop,
    rather than raising: a capture pipe that is killed mid-record is a normal
    way for ``spantap-sim live`` to finish, not a corrupt file.
    """
    chunks = []
    remaining = n
    while remaining:
        chunk = fh.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def iter_classic_pcap(fh: BinaryIO, header: bytes = b"") -> Iterator[Packet]:
    """Yield packets from a classic (tcpdump/libpcap) stream."""
    head = header + _read_exact(fh, 24 - len(header))
    if len(head) < 24:
        raise PcapFormatError("file too short for a pcap header")
    magic = struct.unpack("<I", head[:4])[0]
    if magic in (PCAP_MAGIC_US_BE, PCAP_MAGIC_NS_BE):
        endian = "<"
        ts_mult = 1000 if magic == PCAP_MAGIC_US_BE else 1
    else:
        magic = struct.unpack(">I", head[:4])[0]
        if magic not in (PCAP_MAGIC_US_BE, PCAP_MAGIC_NS_BE):
            raise PcapFormatError("not a pcap file (magic 0x%08X)" % magic)
        endian = ">"
        ts_mult = 1000 if magic == PCAP_MAGIC_US_BE else 1

    linktype = struct.unpack(endian + "I", head[20:24])[0]
    rec_fmt = endian + "IIII"

    while True:
        rec = _read_exact(fh, 16)
        if len(rec) < 16:
            return
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(rec_fmt, rec)
        if incl_len > 0x00FFFFFF:
            raise PcapFormatError("implausible record length %d" % incl_len)
        data = _read_exact(fh, incl_len) if incl_len else b""
        if len(data) != incl_len:
            return
        yield Packet(
            ts_ns=ts_sec * 1_000_000_000 + ts_frac * ts_mult,
            linktype=linktype,
            data=data,
            orig_len=orig_len or incl_len,
        )


def iter_pcapng(fh: BinaryIO, header: bytes = b"") -> Iterator[Packet]:
    """Yield packets from a pcapng stream."""
    pending = header
    endian = "<"
    # interface id -> (linktype, timestamp units per second)
    interfaces: list = []

    while True:
        block_head = pending + _read_exact(fh, 8 - len(pending))
        pending = b""
        if not block_head or len(block_head) < 8:
            return
        btype = struct.unpack(endian + "I", block_head[:4])[0]

        if btype == PCAPNG_SHB:
            # The byte-order magic lives in the block body and may flip `endian`.
            rest = _read_exact(fh, 4)
            if len(rest) < 4:
                return
            bom = struct.unpack("<I", rest)[0]
            if bom == 0x1A2B3C4D:
                endian = "<"
            elif bom == 0x4D3C2B1A:
                endian = ">"
            else:
                raise PcapFormatError("bad pcapng byte-order magic 0x%08X" % bom)
            total_len = struct.unpack(endian + "I", block_head[4:8])[0]
            _read_exact(fh, max(0, total_len - 12))
            interfaces = []
            continue

        total_len = struct.unpack(endian + "I", block_head[4:8])[0]
        if total_len < 12 or total_len % 4:
            raise PcapFormatError("bad pcapng block length %d" % total_len)
        body = _read_exact(fh, total_len - 8)
        if len(body) < total_len - 8:
            return
        body = body[:-4]  # drop the trailing total-length copy

        if btype == 0x00000001:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            interfaces.append((linktype, _tsres_from_options(body[8:], endian)))
        elif btype == 0x00000006:  # Enhanced Packet Block
            iface_id, ts_hi, ts_lo, caplen, origlen = struct.unpack(endian + "IIIII", body[:20])
            linktype, units = _interface(interfaces, iface_id)
            ts = (ts_hi << 32) | ts_lo
            yield Packet(
                ts_ns=ts * (1_000_000_000 // units) if units <= 1_000_000_000 else ts // (units // 1_000_000_000),
                linktype=linktype,
                data=body[20:20 + caplen],
                orig_len=origlen or caplen,
            )
        elif btype == 0x00000003:  # Simple Packet Block
            origlen = struct.unpack(endian + "I", body[:4])[0]
            linktype, _ = _interface(interfaces, 0)
            yield Packet(ts_ns=0, linktype=linktype, data=body[4:4 + origlen], orig_len=origlen)
        # every other block type is skipped by length, as pcapng intends


def _interface(interfaces: list, idx: int):
    if idx < len(interfaces):
        return interfaces[idx]
    return (LINKTYPE_ETHERNET, 1_000_000)


def _tsres_from_options(opts: bytes, endian: str) -> int:
    """Read if_tsresol (option code 9); default is microseconds."""
    off = 0
    while off + 4 <= len(opts):
        code, length = struct.unpack(endian + "HH", opts[off:off + 4])
        off += 4
        if code == 0:  # opt_endofopt
            break
        value = opts[off:off + length]
        off += (length + 3) & ~3
        if code == 9 and value:
            raw = value[0]
            if raw & 0x80:
                return 1 << (raw & 0x7F)
            return 10 ** raw
    return 1_000_000


def open_packet_stream(fh: BinaryIO) -> Iterator[Packet]:
    """Detect the container format and return an iterator of packets."""
    magic = _read_exact(fh, 4)
    if len(magic) < 4:
        raise PcapFormatError("empty capture stream")
    as_le = struct.unpack("<I", magic)[0]
    if as_le == PCAPNG_SHB:
        return iter_pcapng(fh, magic)
    return iter_classic_pcap(fh, magic)


def to_ethernet(pkt: Packet) -> bytes:
    """Normalise a captured frame to Ethernet, which is what ERSPAN carries.

    Raw-IP and Linux cooked captures get a synthetic Ethernet header with
    locally-administered MAC addresses, so a receiver still sees a valid frame.
    """
    lt = pkt.linktype
    data = pkt.data
    if lt == LINKTYPE_ETHERNET:
        return data
    if lt in (LINKTYPE_RAW, LINKTYPE_RAW_BSD, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if lt == LINKTYPE_IPV6:
            ethertype = 0x86DD
        elif lt == LINKTYPE_IPV4:
            ethertype = 0x0800
        else:
            ethertype = 0x86DD if data and (data[0] >> 4) == 6 else 0x0800
        return _FAKE_DST + _FAKE_SRC + struct.pack("!H", ethertype) + data
    if lt == LINKTYPE_LINUX_SLL and len(data) >= 16:
        # pkttype(2) arphrd(2) addrlen(2) addr(8) protocol(2)
        addr_len = struct.unpack("!H", data[4:6])[0]
        src = data[6:12] if addr_len == 6 else _FAKE_SRC
        ethertype = data[14:16]
        return _FAKE_DST + src + ethertype + data[16:]
    if lt == LINKTYPE_LINUX_SLL2 and len(data) >= 20:
        # protocol(2) reserved(2) ifindex(4) arphrd(2) pkttype(1) addrlen(1) addr(8)
        ethertype = data[0:2]
        addr_len = data[11]
        src = data[12:18] if addr_len == 6 else _FAKE_SRC
        return _FAKE_DST + src + ethertype + data[20:]
    raise PcapFormatError(
        "link type %d is not supported; ERSPAN needs Ethernet frames" % lt
    )


def write_pcap_header(fh: BinaryIO, linktype: int, snaplen: int = 262144) -> None:
    fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))


def write_pcap_packet(fh: BinaryIO, ts_ns: int, data: bytes, orig_len: int = 0) -> None:
    fh.write(
        struct.pack(
            "<IIII",
            ts_ns // 1_000_000_000,
            (ts_ns % 1_000_000_000) // 1000,
            len(data),
            orig_len or len(data),
        )
    )
    fh.write(data)
