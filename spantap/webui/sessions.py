# SPDX-License-Identifier: GPL-2.0-or-later
"""Login sessions, and the backoff that a password needs and a token does not.

A token cannot be guessed: 32 random bytes has no dictionary.  A password can,
so adding login adds an attack the UI did not previously have, and this module
is the answer to it.

**Sessions live in memory only.**  Restarting the server logs everyone out,
which is the right trade for a tool that is restarted deliberately: nothing to
persist, nothing to steal from disk, and no stale session surviving a config
change.  The cookie holds a random id and nothing else — no user name, no
expiry, no signature to get wrong — so a forged cookie is simply a value that
is not in the table.

**The id is always ours.**  :meth:`Sessions.create` mints a fresh random id
and never adopts one the client presented, so session fixation is structurally
impossible rather than defended against — there is no path by which a value
someone else chose becomes a valid session.  Separately, logging in discards
the session the same browser was already holding, so signing in again does not
leave the previous one alive behind it.

**Failures are counted per user and per source address**, and the slower of
the two decides.  Per-user alone lets a botnet spread guesses across
addresses; per-address alone lets one address spray many user names.
"""

from __future__ import annotations

import secrets
import threading
import time
from typing import Dict, Optional, Tuple

#: Rolled forward on every authenticated request; a browser left open stays
#: logged in, one walked away from does not.
IDLE_TIMEOUT = 30 * 60
#: Never mind how active: after this the password is asked for again.
ABSOLUTE_TIMEOUT = 12 * 60 * 60

SESSION_COOKIE = "erspan_sid"

#: Free guesses before the door starts closing. Generous enough for a typo.
FREE_ATTEMPTS = 5
#: Then a lockout that doubles per failure, to a ceiling. Fifteen minutes
#: turns an offline-speed dictionary into roughly four guesses an hour.
BASE_LOCKOUT = 15.0
MAX_LOCKOUT = 15 * 60.0
#: Failures are forgotten this long after the last one, so an honest user who
#: fumbles a password in the morning is not penalised in the afternoon.
FAILURE_TTL = 60 * 60


class Sessions:
    """The live session table. One per server; safe to share across threads."""

    def __init__(self, idle: float = IDLE_TIMEOUT, absolute: float = ABSOLUTE_TIMEOUT):
        self.idle = idle
        self.absolute = absolute
        self._lock = threading.Lock()
        self._sessions: Dict[str, Dict] = {}

    # -- lifecycle ---------------------------------------------------------

    def create(self, user: str, peer: str = "", old_sid: str = "") -> str:
        """Start a session under a fresh id of our own.

        ``old_sid`` is the session this browser was already holding, if any.
        It is dropped rather than left running: signing in again should not
        quietly accumulate live sessions, and it means a second sign-in is a
        way to cut off the first.
        """
        sid = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            if old_sid:
                self._sessions.pop(old_sid, None)
            self._sessions[sid] = {
                "user": user, "created": now, "last_seen": now, "peer": peer,
            }
            self._reap(now)
        return sid

    def lookup(self, sid: str) -> Optional[str]:
        """The user this session belongs to, touching it. None if not valid."""
        if not sid:
            return None
        now = time.time()
        with self._lock:
            rec = self._sessions.get(sid)
            if rec is None:
                return None
            if now - rec["last_seen"] > self.idle or now - rec["created"] > self.absolute:
                del self._sessions[sid]
                return None
            rec["last_seen"] = now
            return rec["user"]

    def destroy(self, sid: str) -> None:
        with self._lock:
            self._sessions.pop(sid, None)

    def destroy_user(self, user: str) -> int:
        """Log a user out everywhere — what revoking an account has to mean."""
        with self._lock:
            gone = [s for s, r in self._sessions.items() if r["user"] == user]
            for s in gone:
                del self._sessions[s]
        return len(gone)

    def active(self) -> int:
        now = time.time()
        with self._lock:
            self._reap(now)
            return len(self._sessions)

    def _reap(self, now: float) -> None:
        """Called with the lock held."""
        dead = [
            s for s, r in self._sessions.items()
            if now - r["last_seen"] > self.idle or now - r["created"] > self.absolute
        ]
        for s in dead:
            del self._sessions[s]


class Throttle:
    """Per-key failure counting with doubling lockouts."""

    def __init__(self, free: int = FREE_ATTEMPTS, base: float = BASE_LOCKOUT,
                 ceiling: float = MAX_LOCKOUT, ttl: float = FAILURE_TTL):
        self.free = free
        self.base = base
        self.ceiling = ceiling
        self.ttl = ttl
        self._lock = threading.Lock()
        self._state: Dict[str, Tuple[int, float]] = {}

    def retry_after(self, *keys: str) -> float:
        """Seconds still to wait, worst key wins. 0.0 means go ahead."""
        now = time.time()
        worst = 0.0
        with self._lock:
            for key in keys:
                if not key:
                    continue
                entry = self._state.get(key)
                if entry is None:
                    continue
                failures, last = entry
                if now - last > self.ttl:
                    del self._state[key]
                    continue
                if failures <= self.free:
                    continue
                wait = min(self.base * (2 ** (failures - self.free - 1)), self.ceiling)
                worst = max(worst, (last + wait) - now)
        return max(0.0, worst)

    def record_failure(self, *keys: str) -> None:
        now = time.time()
        with self._lock:
            for key in keys:
                if not key:
                    continue
                failures, last = self._state.get(key, (0, now))
                if now - last > self.ttl:
                    failures = 0
                self._state[key] = (failures + 1, now)

    def clear(self, *keys: str) -> None:
        """A correct password forgives that account's history, not the address's.

        Clearing the address key too would let an attacker who happens to own
        one valid account reset the counter between guesses at the others.
        """
        with self._lock:
            for key in keys:
                self._state.pop(key, None)


def describe_wait(seconds: float) -> str:
    if seconds >= 60:
        return "%d minutes" % round(seconds / 60.0)
    return "%d seconds" % max(1, round(seconds))
