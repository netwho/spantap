# SPDX-License-Identifier: GPL-2.0-or-later
"""The loop that ties a source, the encapsulator and a sender together."""

from __future__ import annotations

import signal
import sys
from typing import Optional

from .encap import ErspanEncapsulator
from .pacer import Pacer
from .sources.base import PacketSource
from .sources.pcapread import PcapFormatError, to_ethernet
from .stats import Stats
from .transport import Sender


class Runner:
    def __init__(
        self,
        source: PacketSource,
        encapsulator: ErspanEncapsulator,
        sender: Sender,
        pacer: Optional[Pacer] = None,
        stats: Optional[Stats] = None,
        skip_unsupported: bool = True,
    ):
        self.source = source
        self.encapsulator = encapsulator
        self.sender = sender
        self.pacer = pacer or Pacer()
        self.stats = stats or Stats()
        self.skip_unsupported = skip_unsupported
        self._stop = False

    def request_stop(self, *_args) -> None:
        self._stop = True

    def install_signal_handlers(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self.request_stop)
            except (ValueError, OSError):
                pass  # not on the main thread

    def run(self) -> Stats:
        enc = self.encapsulator
        warned_linktypes = set()
        if self._stop:      # stopped before the first packet ever arrived
            return self.stats
        for pkt in self.source:
            if self._stop:
                break
            try:
                frame = to_ethernet(pkt)
            except PcapFormatError as exc:
                if not self.skip_unsupported:
                    raise
                if pkt.linktype not in warned_linktypes:
                    warned_linktypes.add(pkt.linktype)
                    sys.stderr.write("  skipping packets: %s\n" % exc)
                self.stats.note_error()
                continue

            before = enc.truncated_count
            packet = enc.encapsulate(frame)
            self.pacer.wait(pkt.ts_ns)
            try:
                self.sender.send(packet, pkt.ts_ns)
            except OSError as exc:
                self.stats.note_error()
                if exc.errno in (105, 55):  # ENOBUFS / no buffer space
                    continue
                raise
            self.stats.record(frame, len(packet), enc.truncated_count > before)
            self.stats.maybe_report()
        return self.stats
