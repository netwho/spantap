# SPDX-License-Identifier: GPL-2.0-or-later
"""The buffer between the receiver and the Wireshark client.

A tap must never be slowed down by whoever is reading it. If Wireshark (or the
TCP connection to it) cannot keep up, the right failure is to drop the oldest
frames and say so loudly — not to block the receiver, which would push the loss
into the kernel's socket buffer where nobody can see or count it.

So: bounded by both frame count and total bytes, drop-oldest, every drop
counted. The counters are the point; a gateway that silently loses frames is
worse than one that loses them visibly.
"""

from __future__ import annotations

import collections
import threading
from typing import List, Optional, Tuple

# (capture timestamp ns, frame bytes, length on the wire before any snapping)
Item = Tuple[int, bytes, int]


class FrameRing:
    def __init__(self, max_frames: int = 8192, max_bytes: int = 64 * 1024 * 1024):
        if max_frames < 1:
            raise ValueError("max_frames must be at least 1")
        if max_bytes < 1024:
            raise ValueError("max_bytes must be at least 1 KiB")
        self.max_frames = max_frames
        self.max_bytes = max_bytes

        self._dq: collections.deque = collections.deque()
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._closed = False

        self.bytes = 0
        self.dropped = 0            # evicted because the consumer was too slow
        self.dropped_bytes = 0
        self.skipped_idle = 0       # arrived while nobody was listening
        self.high_water = 0
        self.accepted = 0

        #: While false, frames are discarded on arrival rather than queued, so
        #: a client that connects gets live traffic instead of a stale backlog.
        self.accepting = False

    # -- producer ----------------------------------------------------------

    def put(self, item: Item) -> bool:
        """Queue a frame. Returns False if it was discarded."""
        with self._not_empty:
            if self._closed:
                return False
            if not self.accepting:
                self.skipped_idle += 1
                return False
            size = len(item[1])
            self._dq.append(item)
            self.bytes += size
            self.accepted += 1
            # Evict oldest-first, but never the frame that just arrived: a
            # single frame larger than the whole ring is pathological, and
            # throwing away the newest thing we have is not an improvement.
            while len(self._dq) > 1 and (
                len(self._dq) > self.max_frames or self.bytes > self.max_bytes
            ):
                old = self._dq.popleft()
                self.bytes -= len(old[1])
                self.dropped += 1
                self.dropped_bytes += len(old[1])
            depth = len(self._dq)
            if depth > self.high_water:
                self.high_water = depth
            self._not_empty.notify()
            return True

    # -- consumer ----------------------------------------------------------

    def get_batch(self, max_items: int = 256, timeout: float = 0.25) -> List[Item]:
        """Take up to ``max_items`` frames, waiting briefly if the ring is empty.

        Batching matters: one `sendall` of many pcap records costs far less
        than one syscall per frame, and at tap rates that difference is what
        decides whether the ring overflows at all.
        """
        with self._not_empty:
            if not self._dq and not self._closed:
                self._not_empty.wait(timeout)
            out: List[Item] = []
            while self._dq and len(out) < max_items:
                item = self._dq.popleft()
                self.bytes -= len(item[1])
                out.append(item)
            return out

    # -- lifecycle ---------------------------------------------------------

    def start_accepting(self) -> None:
        with self._not_empty:
            self.accepting = True

    def stop_accepting(self, clear: bool = True) -> None:
        with self._not_empty:
            self.accepting = False
            if clear:
                self._dq.clear()
                self.bytes = 0

    def close(self) -> None:
        with self._not_empty:
            self._closed = True
            self.accepting = False
            self._dq.clear()
            self.bytes = 0
            self._not_empty.notify_all()

    def depth(self) -> int:
        with self._lock:
            return len(self._dq)

    def snapshot(self) -> dict:
        with self._lock:
            depth = len(self._dq)
            return {
                "depth": depth,
                "bytes": self.bytes,
                "max_frames": self.max_frames,
                "max_bytes": self.max_bytes,
                "fill": depth / self.max_frames if self.max_frames else 0.0,
                "accepted": self.accepted,
                "dropped": self.dropped,
                "dropped_bytes": self.dropped_bytes,
                "skipped_idle": self.skipped_idle,
                "high_water": self.high_water,
                "accepting": self.accepting,
            }
