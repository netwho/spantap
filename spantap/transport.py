# SPDX-License-Identifier: GPL-2.0-or-later
"""Where finished ERSPAN packets go: the wire, a pcap file, or nowhere."""

from __future__ import annotations

import os
import socket
from typing import BinaryIO, Optional

from .sources.pcapread import LINKTYPE_RAW, write_pcap_header, write_pcap_packet


class Sender:
    description = "sender"

    def send(self, packet: bytes, ts_ns: int = 0) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def __enter__(self) -> "Sender":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class RawSocketSender(Sender):
    """Sends complete IPv4 packets on a raw socket.

    We build the IPv4 header ourselves (IP_HDRINCL) rather than letting the
    kernel do it, because ERSPAN cares about TTL, DSCP and the DF bit, and
    because the same bytes then go to the wire and to ``--write-pcap``.

    Needs CAP_NET_RAW.  ``spantap-sim doctor`` explains how to get it without
    running the whole thing as root.
    """

    def __init__(self, dst: str, bind_iface: Optional[str] = None,
                 sndbuf: int = 1 << 20):
        self.dst = dst
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuf)
        except OSError:
            pass
        if bind_iface:
            if not hasattr(socket, "SO_BINDTODEVICE"):
                raise RuntimeError("--bind-iface needs SO_BINDTODEVICE (Linux)")
            self.sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bind_iface.encode() + b"\x00"
            )
        self.description = "raw socket to %s%s" % (
            dst, " via %s" % bind_iface if bind_iface else ""
        )

    def send(self, packet: bytes, ts_ns: int = 0) -> None:
        self.sock.sendto(packet, (self.dst, 0))

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class PcapFileSender(Sender):
    """Writes the ERSPAN packets to a pcap file instead of the wire.

    Link type 101 (raw IP), so Wireshark decodes IP -> GRE -> ERSPAN -> the
    mirrored frame with no further hints.  Needs no privileges at all, which
    makes it the fastest way to check an encapsulation change.
    """

    def __init__(self, path: str):
        self.path = path
        self._fh: BinaryIO = open(path, "wb")
        write_pcap_header(self._fh, LINKTYPE_RAW)
        self.description = "pcap file %s (link type RAW)" % path

    def send(self, packet: bytes, ts_ns: int = 0) -> None:
        write_pcap_packet(self._fh, ts_ns, packet)

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()


class NullSender(Sender):
    """Encapsulates everything and throws it away — for --dry-run."""

    description = "dry run (nothing is transmitted)"

    def send(self, packet: bytes, ts_ns: int = 0) -> None:
        pass


def guess_source_address(dst: str) -> str:
    """Ask the routing table which local address would reach ``dst``.

    No packet is sent: connecting a UDP socket only picks a route.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst, 9))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


def interface_mtu(iface: str) -> Optional[int]:
    try:
        with open("/sys/class/net/%s/mtu" % iface) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None
