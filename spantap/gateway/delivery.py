# SPDX-License-Identifier: GPL-2.0-or-later
"""What actually reached Wireshark, as opposed to what arrived.

The gateway already counts what comes in. That is only half the question, and
usually the less interesting half: a tap is doing its job when frames come out
the other end, and the two numbers are not the same. Between them sit three
places a frame can go:

``skipped_idle``
    It arrived while nobody was connected. Deliberate — a client that attaches
    should see live traffic, not a stale backlog — but it is still a frame you
    did not get, and it explains most "I started it and saw nothing".
``dropped``
    The ring evicted it because the reader could not keep up. This is the one
    that matters: it means the capture has holes.
``depth``
    It is still in the ring, on its way out. Not lost, just not yet counted.

So the identity a healthy gateway satisfies is::

    received == delivered + dropped + skipped_idle + depth   (± in flight)

:meth:`DeliveryTracker.reconcile` computes both sides and reports the
difference. If it does not balance, something is losing frames that nothing is
counting, which is exactly the failure a tap must never have silently.

The rate history here is separate from :class:`spantap.stats.Stats`, which
measures arrival. Sampling the same series twice would not answer the question
"is the reader keeping up", and that question is the whole point of this tab.
"""

from __future__ import annotations

import collections
import threading
import time
from typing import Dict, List, Optional

#: Roughly ten minutes at the UI's slowest poll, which is as far back as a
#: live rate chart is worth reading.
HISTORY = 240


class DeliveryTracker:
    """Rates and client history for the PCAP-over-IP side."""

    def __init__(self, history: int = HISTORY):
        self._lock = threading.Lock()
        self.started = time.monotonic()
        self.history: collections.deque = collections.deque(maxlen=history)
        self.clients: List[Dict] = []

        self._last_sample = self.started
        self._last_frames = 0
        self._last_bytes = 0
        self.peak_fps = 0.0
        self.peak_bps = 0.0
        #: The client currently attached, so a reconnect is recorded once
        #: rather than on every poll.
        self._current_peer: Optional[str] = None

    def sample(self, frames_sent: int, bytes_sent: int, min_gap: float = 0.5) -> None:
        """Append one delivered-rate sample, if enough time has passed."""
        now = time.monotonic()
        # The whole read-modify-write under the lock: several browser tabs poll
        # from different handler threads, and interleaving them yields negative
        # or wildly inflated rates.
        with self._lock:
            gap = now - self._last_sample
            if gap < min_gap:
                return
            prev_frames, prev_bytes = self._last_frames, self._last_bytes
            self._last_sample = now
            self._last_frames, self._last_bytes = frames_sent, bytes_sent
            fps = max(0.0, (frames_sent - prev_frames) / gap)
            bps = max(0.0, (bytes_sent - prev_bytes) * 8 / gap)
            self.peak_fps = max(self.peak_fps, fps)
            self.peak_bps = max(self.peak_bps, bps)
            self.history.append((round(now - self.started, 2), fps, bps))

    def note_client(self, peer: Optional[str], connected: bool,
                    since: Optional[float], frames_sent: int) -> None:
        """Record attach and detach, so the tab can show who read what."""
        with self._lock:
            key = peer if connected else None
            if key == self._current_peer:
                return
            if self._current_peer is not None and self.clients:
                last = self.clients[-1]
                if last.get("until") is None:
                    last["until"] = time.time()
                    last["frames_at_end"] = frames_sent
            if key is not None:
                self.clients.append({
                    "peer": key,
                    "since": since or time.time(),
                    "until": None,
                    "frames_at_start": frames_sent,
                    "frames_at_end": None,
                })
                del self.clients[:-20]       # the last twenty is plenty
            self._current_peer = key

    @staticmethod
    def reconcile(receiver: Optional[Dict], ring: Optional[Dict],
                  server: Optional[Dict]) -> Dict:
        """Account for every frame that came in. See the module docstring."""
        if not (receiver and ring and server):
            return {"balanced": True, "difference": 0, "received": 0,
                    "delivered": 0, "dropped": 0, "skipped_idle": 0, "buffered": 0}
        received = receiver.get("received", 0) or 0
        delivered = server.get("frames_sent", 0) or 0
        dropped = ring.get("dropped", 0) or 0
        idle = ring.get("skipped_idle", 0) or 0
        buffered = ring.get("depth", 0) or 0
        accounted = delivered + dropped + idle + buffered
        difference = received - accounted
        return {
            "received": received,
            "delivered": delivered,
            "dropped": dropped,
            "skipped_idle": idle,
            "buffered": buffered,
            "difference": difference,
            # A frame or two in flight between the ring and the socket is
            # normal; a persistent gap is not, and means something is losing
            # frames that nothing is counting.
            "balanced": abs(difference) <= max(4, received // 1000),
        }

    def snapshot(self, server: Optional[Dict] = None) -> Dict:
        with self._lock:
            history = list(self.history)
            clients = [dict(c) for c in self.clients]
            peak_fps, peak_bps = self.peak_fps, self.peak_bps
        elapsed = max(1e-9, time.monotonic() - self.started)
        frames = (server or {}).get("frames_sent", 0) or 0
        octets = (server or {}).get("bytes_sent", 0) or 0
        return {
            "history": history,
            "clients": clients,
            "peak_fps": peak_fps,
            "peak_bps": peak_bps,
            "avg_fps": frames / elapsed,
            "avg_bps": octets * 8 / elapsed,
            "elapsed": elapsed,
        }


__all__ = ["DeliveryTracker"]
