# SPDX-License-Identifier: GPL-2.0-or-later
"""A third receiving half: a stored pcap/pcapng file, played back.

Neither a switch nor a live interface — a capture already sitting on disk,
delivered to Wireshark over PCAP-over-IP exactly as the other two sources
would deliver it. The point is not to reproduce the file's original timing
with any precision: it is to exercise or demonstrate the ERSPAN-in,
PCAP-over-IP-out pipeline (or troubleshoot the delivery side of it) without
a switch mirror or a NIC worth capturing from at hand.

This class presents the same surface as
:class:`~spantap.gateway.receiver.ErspanReceiver` and
:class:`~spantap.gateway.livecapture.LiveCapture` — ``open``, ``frames``,
``request_stop``, ``close``, ``snapshot``, ``description``, ``last_error`` —
so :class:`~spantap.gateway.service.GatewayController` holds any of the
three and does not care which. It reads with the same
:func:`~spantap.sources.pcapread.open_packet_stream` the local-interface
source already uses, and loops the same way the simulator's own ``replay``
source does (:class:`~spantap.sources.filesrc.PcapFileSource`): ``loop=0``
forever, a positive integer for that many passes.

**No exclusion filter is needed here, unlike the other two sources.** A live
interface or an ERSPAN receiver can see the gateway's own PCAP-over-IP
output on the wire it is watching, which is what the mandatory tcp/57012
exclusion in :mod:`spantap.exclusion` guards against. A stored file is
static content, not a live tap on anything — there is nothing for the
gateway's own traffic to feed back into.

**Timestamps are stamped at delivery, not read from the file.** Every other
source stamps ``ts_ns`` with when the gateway actually saw the frame
(:func:`time.time_ns` for ERSPAN and, in effect, for a live capture too);
this does the same, so a replayed frame looks like what it is — something
the gateway is delivering right now — rather than carrying a capture
timestamp from whenever the file was originally recorded. The file's own
timestamps are used only to *pace* delivery, not to label it.

**Pacing is deliberately approximate, not exact.** The gap between two
frames is read from the file and slept before the second is delivered, but
that is best-effort scheduling on a busy interpreter, not a claim about
matching the original capture's timing precisely — this exists to demo the
pipeline and to make replayed traffic look roughly like it is arriving live,
not to reproduce recorded timing exactly. Any single gap is capped at
``max_gap`` seconds, so one long idle period recorded in the file (a demo
capture that waited an hour for something to happen) cannot stall a replay
for real time. Pass ``pace=False`` to skip all of this and deliver frames as
fast as the ring will take them.

Loss is reported as ``None``, not ``0``, for the same reason a local
interface capture reports it that way: a pcap file carries no GRE sequence
number, so "none lost" and "cannot know" would otherwise be conflated.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Iterator, Optional

from ..sources.pcapread import PcapFormatError, open_packet_stream, to_ethernet
from .receiver import ReceivedFrame


class ReplayError(RuntimeError):
    pass


class PcapReplay:
    """Play a stored capture into the gateway's ring."""

    def __init__(
        self,
        path: str,
        *,
        loop: int = 0,
        pace: bool = True,
        max_gap: float = 2.0,
    ):
        """``loop`` of 0 means forever, matching the simulator's own replay
        source and its default. ``pace`` toggles timestamp-based pacing
        between frames; ``max_gap`` bounds any single paced sleep.
        """
        if not path:
            raise ReplayError("a capture file is required")
        if not os.path.isfile(path):
            raise ReplayError("no such capture: %s" % path)
        self.path = path
        self.loop = loop
        self.pace = pace
        self.max_gap = max_gap

        self.received = 0
        self.bytes = 0
        self.truncated = 0
        self.passes = 0
        self.last_error: Optional[str] = None

        self._closed = False
        self._stop_event = threading.Event()

        self.description = "pcap replay of %s%s%s" % (
            path,
            (" (looping forever)" if loop == 0
             else "" if loop == 1 else " (%d passes)" % loop),
            "" if pace else ", unpaced",
        )

    # -- lifecycle -----------------------------------------------------------

    def open(self) -> None:
        """Fail fast on a file that is not really a capture.

        Separate from :meth:`frames` so the controller can tell a bad file
        apart from a clean start, the same courtesy the other two sources
        give it before the server is declared bound and running.
        """
        if self._closed:
            return
        try:
            with open(self.path, "rb") as fh:
                # Forces the header (and, in a non-empty capture, the first
                # record) to actually parse, without consuming anything
                # frames() will read again from its own fresh handle.
                next(iter(open_packet_stream(fh)), None)
        except PcapFormatError as exc:
            raise ReplayError(
                "%s does not look like a capture: %s" % (self.path, exc))
        except OSError as exc:
            raise ReplayError("could not read %s: %s" % (self.path, exc))

    def frames(self) -> Iterator[ReceivedFrame]:
        """Yield frames until the requested number of passes is done, or a
        stop is requested."""
        if self._closed:
            return
        pass_no = 0
        last_ts: Optional[int] = None
        try:
            while not self._closed and (self.loop == 0 or pass_no < self.loop):
                pass_no += 1
                self.passes = pass_no
                with open(self.path, "rb") as fh:
                    for pkt in open_packet_stream(fh):
                        if self._closed:
                            return
                        if self.pace and last_ts is not None:
                            gap = (pkt.ts_ns - last_ts) / 1_000_000_000
                            if gap > 0 and self._stop_event.wait(min(gap, self.max_gap)):
                                return
                        last_ts = pkt.ts_ns

                        # Whatever the link type, the ring and the
                        # PCAP-over-IP server deal in Ethernet frames — the
                        # same shape the other two sources deliver, so a
                        # client cannot tell which one it is reading.
                        frame = to_ethernet(pkt)
                        self.received += 1
                        self.bytes += len(frame)
                        truncated = bool(pkt.orig_len and pkt.orig_len > len(frame))
                        if truncated:
                            self.truncated += 1
                        yield ReceivedFrame(
                            ts_ns=time.time_ns(),
                            frame=frame,
                            session_id=-1,      # no session: this is not ERSPAN
                            seq=-1,              # and no sequence number either
                            truncated=truncated,
                            source=os.path.basename(self.path),
                        )
        except (OSError, PcapFormatError) as exc:
            self.last_error = "%s: %s" % (self.path, exc)
            raise ReplayError(self.last_error)

    def request_stop(self) -> None:
        self._closed = True
        self._stop_event.set()

    def close(self) -> None:
        self._closed = True
        self._stop_event.set()

    # -- observation -----------------------------------------------------------

    def snapshot(self) -> dict:
        return {
            "kind": "replay",
            "description": self.description,
            "path": self.path,
            "received": self.received,
            "bytes": self.bytes,
            "ignored": 0,
            "filtered": 0,
            # None, not 0: a stored capture carries no GRE sequence number,
            # so loss is not something this source can claim to know either.
            "lost": None,
            "reordered": None,
            "truncated": self.truncated,
            "sessions": {},
            "sources": {os.path.basename(self.path): self.received},
            "passes": self.passes,
            "loop": self.loop,
            "pace": self.pace,
            "last_error": self.last_error,
        }


__all__ = ["PcapReplay", "ReplayError"]
