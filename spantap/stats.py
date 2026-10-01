# SPDX-License-Identifier: GPL-2.0-or-later
"""Counters, protocol breakdown, throughput history, and the CLI progress line.

The same object serves the CLI's periodic one-liner and the web monitor, so
what you read in a terminal and what the browser shows can never disagree.
"""

from __future__ import annotations

import collections
import sys
import threading
import time
from typing import Dict, List, Optional

from .classify import classify


class Stats:
    def __init__(
        self,
        interval: float = 2.0,
        stream=sys.stderr,
        classify_traffic: bool = False,
        history: int = 300,
    ):
        self.packets = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.truncated = 0
        self.errors = 0
        self.interval = interval
        self.stream = stream
        self.classify_traffic = classify_traffic

        self.by_l2: collections.Counter = collections.Counter()
        self.by_l3: collections.Counter = collections.Counter()
        self.by_l4: collections.Counter = collections.Counter()
        self.by_app: collections.Counter = collections.Counter()
        self.vlans: collections.Counter = collections.Counter()

        self._lock = threading.Lock()
        self.started = time.monotonic()
        self.started_wall = time.time()
        self._last_report = self.started
        self._last_packets = 0
        self._last_bytes = 0

        # One entry per sample() call: (seconds since start, pkt/s, bit/s).
        self.history: collections.deque = collections.deque(maxlen=history)
        self._last_sample = self.started
        self._sample_packets = 0
        self._sample_bytes = 0

    # -- recording ---------------------------------------------------------

    def record(self, frame: bytes, packet_len: int, truncated: bool = False) -> None:
        with self._lock:
            self.packets += 1
            self.bytes_in += len(frame)
            self.bytes_out += packet_len
            if truncated:
                self.truncated += 1
            if self.classify_traffic:
                v = classify(frame)
                self.by_l2[v.l2] += 1
                self.by_l3[v.l3] += 1
                if v.l4:
                    self.by_l4[v.l4] += 1
                if v.app:
                    self.by_app[v.app] += 1
                if v.vlan_id is not None:
                    self.vlans[v.vlan_id] += 1

    def note_error(self) -> None:
        with self._lock:
            self.errors += 1

    # -- sampling ----------------------------------------------------------

    def sample(self, min_gap: float = 0.5) -> None:
        """Append one throughput sample, if enough time has passed.

        Called by whoever is watching (the monitor poll loop). Nothing samples
        on its own, so an unobserved run costs nothing.
        """
        now = time.monotonic()
        # The whole read-modify-write must be atomic: several browser tabs (or
        # a tab plus a curl) poll from different handler threads, and an
        # interleaved update yields negative or wildly inflated rates.
        with self._lock:
            gap = now - self._last_sample
            if gap < min_gap:
                return
            packets, out = self.packets, self.bytes_out
            self._last_sample = now
            prev_packets, prev_bytes = self._sample_packets, self._sample_bytes
            self._sample_packets = packets
            self._sample_bytes = out
            self.history.append(
                (
                    round(now - self.started, 2),
                    max(0.0, (packets - prev_packets) / gap),
                    max(0.0, (out - prev_bytes) * 8 / gap),
                )
            )

    # -- reporting ---------------------------------------------------------

    def maybe_report(self) -> None:
        if not self.interval:
            return
        now = time.monotonic()
        elapsed = now - self._last_report
        if elapsed < self.interval:
            return
        pps = (self.packets - self._last_packets) / elapsed
        mbps = (self.bytes_out - self._last_bytes) * 8 / elapsed / 1e6
        self._last_report = now
        self._last_packets = self.packets
        self._last_bytes = self.bytes_out
        self.stream.write(
            "  %10d packets   %8.0f pkt/s   %7.2f Mbit/s out\n" % (self.packets, pps, mbps)
        )
        self.stream.flush()

    def elapsed(self) -> float:
        return max(time.monotonic() - self.started, 1e-9)

    def summary(self) -> str:
        elapsed = self.elapsed()
        return (
            "%d packets in %.2fs (%.0f pkt/s), %.1f KiB mirrored, %.1f KiB on the wire"
            "%s%s"
            % (
                self.packets,
                elapsed,
                self.packets / elapsed,
                self.bytes_in / 1024,
                self.bytes_out / 1024,
                ", %d truncated" % self.truncated if self.truncated else "",
                ", %d errors" % self.errors if self.errors else "",
            )
        )

    def protocol_lines(self, top: int = 8) -> List[str]:
        """Human-readable protocol breakdown for the CLI summary."""
        if not self.classify_traffic or not self.packets:
            return []
        out = []
        for title, counter in (
            ("link", self.by_l2), ("network", self.by_l3),
            ("transport", self.by_l4), ("application", self.by_app),
        ):
            if not counter:
                continue
            parts = [
                "%s %d (%.0f%%)" % (k, v, 100.0 * v / self.packets)
                for k, v in counter.most_common(top)
            ]
            out.append("  %-12s %s" % (title + ":", ", ".join(parts)))
        return out

    def snapshot(self) -> Dict:
        """Everything the monitor needs, in one consistent read."""
        with self._lock:
            packets, bin_, bout = self.packets, self.bytes_in, self.bytes_out
            truncated, errors = self.truncated, self.errors
            by_l2 = dict(self.by_l2)
            by_l3 = dict(self.by_l3)
            by_l4 = dict(self.by_l4)
            by_app = dict(self.by_app)
            vlans = dict(self.vlans)
        elapsed = self.elapsed()
        return {
            "packets": packets,
            "bytes_in": bin_,
            "bytes_out": bout,
            "truncated": truncated,
            "errors": errors,
            "elapsed": elapsed,
            "started_wall": self.started_wall,
            "avg_pps": packets / elapsed,
            "avg_bps": bout * 8 / elapsed,
            "protocols": {
                "link": by_l2,
                "network": by_l3,
                "transport": by_l4,
                "application": by_app,
                "vlans": {str(k): v for k, v in vlans.items()},
            },
            "history": list(self.history),
        }
