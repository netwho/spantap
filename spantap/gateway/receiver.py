# SPDX-License-Identifier: GPL-2.0-or-later
"""The receiving half: ERSPAN Type II off a raw GRE socket.

A raw ``AF_INET/SOCK_RAW`` socket on IP protocol 47 sees every GRE packet
delivered to this host, loopback included, without any tunnel interface having
to exist. That is deliberately the simplest thing that works: an ``erspan``
netdev would need root, ``ip link`` state and a per-session interface, and it
would not help on the same-host case at all.

Everything that is not well-formed ERSPAN Type II — other people's GRE tunnels,
Type I, Type III — is counted and ignored rather than guessed at.

Loss detection comes free from the GRE sequence number, which ERSPAN Type II
mandates. It is tracked per (source, session), because two sources mirroring
into the same collector each have their own counter.
"""

from __future__ import annotations

import collections
import socket
import struct
import time
from dataclasses import dataclass
from typing import Dict, Iterator, Optional, Tuple

from ..decode import DecodeError, decode_erspan2

IPPROTO_GRE = 47
DEFAULT_RCVBUF = 8 * 1024 * 1024


class ReceiverError(RuntimeError):
    pass


@dataclass
class ReceivedFrame:
    ts_ns: int
    frame: bytes
    session_id: int
    seq: int
    truncated: bool
    source: str
    lost_before: int = 0     # frames the sequence number says went missing


class ErspanReceiver:
    """Iterate the mirrored frames arriving on this host.

    ``session_id`` of None accepts every session; an integer accepts only that
    one. ``from_host`` narrows to a single mirroring source.
    """

    def __init__(
        self,
        bind: str = "0.0.0.0",
        session_id: Optional[int] = None,
        from_host: Optional[str] = None,
        rcvbuf: int = DEFAULT_RCVBUF,
        poll_interval: float = 0.25,
    ):
        if session_id is not None and not 0 <= session_id <= 1023:
            raise ValueError("session_id must be 0..1023 or None for all sessions")
        self.bind = bind
        self.session_id = session_id
        self.from_host = from_host
        self.rcvbuf = rcvbuf
        self.poll_interval = poll_interval

        self._sock: Optional[socket.socket] = None
        self._stop = False
        self._expected: Dict[Tuple[str, int], int] = {}

        self.received = 0
        self.bytes = 0
        self.ignored = 0          # GRE that is not ERSPAN Type II
        self.filtered = 0         # ERSPAN, but not the session/source we want
        self.lost = 0
        self.reordered = 0
        self.truncated = 0
        self.sessions: collections.Counter = collections.Counter()
        self.sources: collections.Counter = collections.Counter()
        self.last_error: Optional[str] = None

        self.description = "raw GRE socket on %s%s" % (
            bind,
            "" if session_id is None else ", session %d" % session_id,
        )

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_GRE)
        except PermissionError:
            raise ReceiverError(
                "receiving ERSPAN needs CAP_NET_RAW — run 'spantap-gw doctor' for how "
                "to grant it without running as root"
            )
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
        except OSError:
            pass
        try:
            sock.bind((self.bind, 0))
        except OSError as exc:
            sock.close()
            raise ReceiverError("cannot bind %s: %s" % (self.bind, exc))
        sock.settimeout(self.poll_interval)
        self._sock = sock
        self._stop = False

    def close(self) -> None:
        self._stop = True
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def request_stop(self) -> None:
        self._stop = True

    # -- the loop ----------------------------------------------------------

    def frames(self) -> Iterator[ReceivedFrame]:
        if self._sock is None:
            self.open()
        sock = self._sock
        assert sock is not None
        while not self._stop:
            try:
                data = sock.recv(65565)
            except socket.timeout:
                continue            # gives request_stop() a chance to be seen
            except OSError as exc:
                if self._stop:
                    return
                self.last_error = str(exc)
                return
            ts_ns = time.time_ns()

            try:
                decoded = decode_erspan2(data)
            except DecodeError:
                self.ignored += 1
                continue

            if self.session_id is not None and decoded.session_id != self.session_id:
                self.filtered += 1
                continue
            if self.from_host and decoded.src != self.from_host:
                self.filtered += 1
                continue

            lost = self._track_sequence(decoded.src, decoded.session_id, decoded.seq)

            self.received += 1
            self.bytes += len(data)
            self.sessions[decoded.session_id] += 1
            self.sources[decoded.src] += 1
            if decoded.truncated:
                self.truncated += 1

            yield ReceivedFrame(
                ts_ns=ts_ns,
                frame=decoded.frame,
                session_id=decoded.session_id,
                seq=decoded.seq,
                truncated=decoded.truncated,
                source=decoded.src,
                lost_before=lost,
            )

    def _track_sequence(self, src: str, session: int, seq: int) -> int:
        """Return how many frames the sequence number says we missed."""
        key = (src, session)
        expected = self._expected.get(key)
        self._expected[key] = (seq + 1) & 0xFFFFFFFF
        if expected is None:
            return 0
        if seq == expected:
            return 0
        gap = (seq - expected) & 0xFFFFFFFF
        # A "gap" of nearly 2^32 is a late or duplicated packet, not a loss of
        # four billion frames.
        if gap > 0x7FFFFFFF:
            self.reordered += 1
            self._expected[key] = expected      # keep the forward expectation
            return 0
        self.lost += gap
        return gap

    # -- observation -------------------------------------------------------

    def snapshot(self) -> dict:
        return {
            # Which source the gateway is running, so the UI does not have to
            # infer it from which keys happen to be present.
            "kind": "erspan",
            "description": self.description,
            "received": self.received,
            "bytes": self.bytes,
            "ignored": self.ignored,
            "filtered": self.filtered,
            "lost": self.lost,
            "reordered": self.reordered,
            "truncated": self.truncated,
            "sessions": {str(k): v for k, v in self.sessions.items()},
            "sources": dict(self.sources),
            "last_error": self.last_error,
        }
