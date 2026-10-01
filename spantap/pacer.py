# SPDX-License-Identifier: GPL-2.0-or-later
"""Rate control shared by every source."""

from __future__ import annotations

import time


class Pacer:
    """Decides when the next packet may go out.

    Three modes, in order of precedence:

    * ``pps`` set        — fixed rate, capture timestamps ignored.
    * ``speed`` > 0      — replay original inter-packet gaps, scaled by ``speed``
                           (1.0 = real time, 10.0 = ten times faster).
    * neither            — no pacing at all, send as fast as the socket allows.
    """

    def __init__(self, speed: float = 0.0, pps: float = 0.0):
        if speed < 0:
            raise ValueError("speed must not be negative")
        if pps < 0:
            raise ValueError("pps must not be negative")
        self.speed = speed
        self.pps = pps
        self._interval = 1.0 / pps if pps else 0.0
        self._base_wall = 0.0
        self._base_ts = 0
        self._next = 0.0
        self._started = False

    def reset(self) -> None:
        """Start a fresh timeline, e.g. at the beginning of a replay loop."""
        self._started = False

    def wait(self, ts_ns: int) -> None:
        if not self.pps and not self.speed:
            return
        now = time.monotonic()
        if not self._started:
            self._started = True
            self._base_wall = now
            self._base_ts = ts_ns
            self._next = now
            return
        if self.pps:
            self._next += self._interval
            target = self._next
        else:
            delta = (ts_ns - self._base_ts) / 1_000_000_000.0 / self.speed
            if delta < 0:  # non-monotonic capture timestamps: don't go backwards
                delta = 0.0
            target = self._base_wall + delta
        sleep_for = target - now
        if sleep_for > 0:
            time.sleep(sleep_for)
        elif self.pps and sleep_for < -1.0:
            # We have fallen more than a second behind; re-anchor rather than
            # accumulating an ever-growing debt we will never pay off.
            self._next = now
