# SPDX-License-Identifier: GPL-2.0-or-later
"""PCAP-over-IP: hand the de-encapsulated frames to Wireshark over TCP.

    wireshark -k -i TCP@<host>:57012
    tshark       -i TCP@<host>:57012

The protocol is not a protocol: on connect we write a classic libpcap file
header and then append records for as long as the client stays. Classic pcap,
not pcapng — same choice as the PCAP-over-IP tool, and the one every client
understands.

One client at a time. A second connection is accepted and closed immediately
rather than left hanging, so the person on the other end gets a connection
reset now instead of a silent stall, and the count shows up in the monitor.
"""

from __future__ import annotations

import select
import socket
import struct
import threading
import time
from typing import Optional

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
DEFAULT_PORT = 57012
DEFAULT_SNAPLEN = 262144


def pcap_file_header(linktype: int = LINKTYPE_ETHERNET,
                     snaplen: int = DEFAULT_SNAPLEN) -> bytes:
    return struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, snaplen, linktype)


def pcap_record(ts_ns: int, frame: bytes, orig_len: int = 0) -> bytes:
    return struct.pack(
        "<IIII",
        ts_ns // 1_000_000_000,
        (ts_ns % 1_000_000_000) // 1000,
        len(frame),
        orig_len or len(frame),
    ) + frame


class PcapOverIpServer:
    def __init__(
        self,
        ring,
        bind: str = "127.0.0.1",
        port: int = DEFAULT_PORT,
        snaplen: int = DEFAULT_SNAPLEN,
        linktype: int = LINKTYPE_ETHERNET,
    ):
        self.ring = ring
        self.bind = bind
        self.port = port
        self.snaplen = snaplen or DEFAULT_SNAPLEN
        self.linktype = linktype

        self._listener: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._writer_thread: Optional[threading.Thread] = None
        self._client: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._stop = threading.Event()

        self.peer: Optional[str] = None
        self.connected_since: Optional[float] = None
        self.frames_sent = 0
        self.bytes_sent = 0
        self.clients_served = 0
        self.refused = 0
        self.last_error: Optional[str] = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self.bind, self.port))
        except OSError as exc:
            listener.close()
            raise OSError(
                "cannot listen on %s:%d — %s%s"
                % (self.bind, self.port, exc,
                   "  (something else is already serving PCAP-over-IP?)"
                   if getattr(exc, "errno", None) == 98 else "")
            )
        listener.listen(4)
        listener.settimeout(0.3)
        self._listener = listener
        self._stop.clear()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="pcapoverip-accept", daemon=True
        )
        self._accept_thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        with self._lock:
            client = self._client
            self._client = None
        for sock in (client, self._listener):
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
        self._listener = None
        for thread in (self._writer_thread, self._accept_thread):
            if thread is not None and thread.is_alive():
                thread.join(timeout=timeout)
        self.ring.stop_accepting()
        self.peer = None
        self.connected_since = None

    @property
    def port_in_use(self) -> int:
        if self._listener is not None:
            return self._listener.getsockname()[1]
        return self.port

    # -- accepting ---------------------------------------------------------

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            listener = self._listener
            if listener is None:
                return
            try:
                sock, addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return

            with self._lock:
                busy = self._client is not None
            if busy:
                self.refused += 1
                try:
                    sock.close()
                except OSError:
                    pass
                continue

            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except OSError:
                pass
            with self._lock:
                self._client = sock
                self.peer = "%s:%d" % addr
                self.connected_since = time.time()
                self.clients_served += 1
            self._writer_thread = threading.Thread(
                target=self._serve, args=(sock,), name="pcapoverip-writer", daemon=True
            )
            self._writer_thread.start()

    # -- serving -----------------------------------------------------------

    def _serve(self, sock: socket.socket) -> None:
        # Frames only start being queued once somebody is listening, so a
        # client gets live traffic rather than whatever was buffered earlier.
        self.ring.stop_accepting(clear=True)
        self.ring.start_accepting()
        try:
            sock.sendall(pcap_file_header(self.linktype, self.snaplen))
            while not self._stop.is_set():
                # Wireshark never sends anything, so the only thing that can
                # arrive is end-of-file. Checking for it explicitly matters:
                # without it a client that connects and leaves without ever
                # being sent a frame — a port scan, a health check, somebody's
                # stray `nc` — holds the single client slot forever, because a
                # dead peer is otherwise only noticed by a failing send.
                if self._peer_gone(sock):
                    break
                batch = self.ring.get_batch(max_items=512, timeout=0.25)
                if not batch:
                    continue
                buf = bytearray()
                for ts_ns, frame, orig_len in batch:
                    if len(frame) > self.snaplen:
                        frame = frame[: self.snaplen]
                    buf += pcap_record(ts_ns, frame, orig_len)
                sock.sendall(buf)
                self.frames_sent += len(batch)
                self.bytes_sent += len(buf)
        except (BrokenPipeError, ConnectionResetError, OSError) as exc:
            if not self._stop.is_set():
                self.last_error = "client gone: %s" % exc
        finally:
            self.ring.stop_accepting(clear=True)
            with self._lock:
                if self._client is sock:
                    self._client = None
                    self.peer = None
                    self.connected_since = None
            try:
                sock.close()
            except OSError:
                pass

    @staticmethod
    def _peer_gone(sock: socket.socket) -> bool:
        """True once the client has closed its end."""
        try:
            readable, _, errored = select.select([sock], [], [sock], 0)
        except (OSError, ValueError):
            return True
        if errored:
            return True
        if not readable:
            return False
        try:
            return sock.recv(4096, socket.MSG_DONTWAIT) == b""
        except BlockingIOError:
            return False
        except OSError:
            return True

    # -- observation -------------------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            connected = self._client is not None
        return {
            "listening": self._listener is not None,
            "bind": self.bind,
            "port": self.port_in_use,
            "connected": connected,
            "peer": self.peer,
            "connected_since": self.connected_since,
            "frames_sent": self.frames_sent,
            "bytes_sent": self.bytes_sent,
            "clients_served": self.clients_served,
            "refused": self.refused,
            "snaplen": self.snaplen,
            "last_error": self.last_error,
            "hint": "wireshark -k -i TCP@%s:%d" % (
                "127.0.0.1" if self.bind in ("0.0.0.0", "") else self.bind,
                self.port_in_use,
            ),
        }
