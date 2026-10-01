# SPDX-License-Identifier: GPL-2.0-or-later
"""The run loop: source -> ring -> PCAP-over-IP server, with an optional tee
to a size-capped local pcap file.

Deliberately not :class:`spantap.gateway.service.GatewayController`: that
class is shaped around a web UI polling ``snapshot()`` on a stateful,
restartable controller, and has no file-tee hook. spantap-lite's needs are
narrower -- one process, one run, started once from the CLI -- so this is its
own small class that wires the same building blocks
(:class:`~spantap.gateway.livecapture.LiveCapture`,
:class:`~spantap.gateway.replay.PcapReplay`,
:class:`~spantap.gateway.ring.FrameRing`,
:class:`~spantap.gateway.pcapoverip.PcapOverIpServer`) the same way
``GatewayController`` does, including the one ordering rule that actually
matters: **the PCAP-over-IP server binds before the source opens**, so the
mandatory self-exclusion filter is always built around the port actually in
use, not the one merely requested.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Dict, Optional

from ..gateway.livecapture import LiveCapture
from ..gateway.pcapoverip import (
    DEFAULT_SNAPLEN,
    LINKTYPE_ETHERNET,
    PcapOverIpServer,
    pcap_file_header,
    pcap_record,
)
from ..gateway.replay import PcapReplay
from ..gateway.ring import FrameRing
from ..sources.live import CaptureError

STATE_IDLE = "idle"
STATE_RUNNING = "running"
STATE_STOPPING = "stopping"
STATE_STOPPED = "stopped"
STATE_ERROR = "error"


class CappedPcapWriter:
    """Tee frames to a local classic-pcap file, up to a fixed size.

    Not rotation -- Walter's spec asks for one capped file, not a ring of
    them -- so once the cap is reached, writing simply stops; the
    PCAP-over-IP side keeps running unaffected, and the current fill level
    stays visible in :meth:`snapshot` so it is obvious why it stopped
    growing.
    """

    def __init__(self, path: str, max_bytes: int, *,
                snaplen: int = DEFAULT_SNAPLEN, linktype: int = LINKTYPE_ETHERNET):
        self.path = path
        self.max_bytes = max_bytes
        self.snaplen = snaplen or DEFAULT_SNAPLEN
        self.frames_written = 0
        self.capped = False
        self.last_error: Optional[str] = None
        self._lock = threading.Lock()

        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        self._fh = open(path, "wb")
        header = pcap_file_header(linktype, self.snaplen)
        self._fh.write(header)
        self._fh.flush()
        self._written = len(header)

    def write(self, ts_ns: int, frame: bytes, orig_len: int) -> None:
        if self.capped:
            return
        if len(frame) > self.snaplen:
            frame = frame[: self.snaplen]
        record = pcap_record(ts_ns, frame, orig_len)
        with self._lock:
            if self.capped:
                return
            if self._written + len(record) > self.max_bytes:
                self.capped = True
                return
            try:
                self._fh.write(record)
                self._written += len(record)
                self.frames_written += 1
            except OSError as exc:
                self.last_error = str(exc)
                self.capped = True

    def close(self) -> None:
        try:
            self._fh.flush()
            self._fh.close()
        except OSError:
            pass

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "path": self.path,
                "bytes": self._written,
                "max_bytes": self.max_bytes,
                "frames_written": self.frames_written,
                "capped": self.capped,
                "last_error": self.last_error,
            }


class LiteService:
    """One capture -> PCAP-over-IP run. Not restartable -- make a new one."""

    def __init__(self) -> None:
        self.state = STATE_IDLE
        self.error: Optional[str] = None
        self.config: Optional[Dict] = None
        self.started_at: Optional[float] = None
        self.stopped_at: Optional[float] = None

        self._receiver = None       # LiveCapture or PcapReplay
        self._server: Optional[PcapOverIpServer] = None
        self._ring: Optional[FrameRing] = None
        self._writer: Optional[CappedPcapWriter] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, config: Dict) -> None:
        if self.state != STATE_IDLE:
            raise RuntimeError("this service has already been started once")

        buf = config["buffer"]
        srv = config["serve"]
        save = config["save"]

        ring = FrameRing(max_frames=buf["max_frames"], max_bytes=buf["max_mib"] * 1024 * 1024)
        server = PcapOverIpServer(ring, bind=srv["bind"], port=srv["port"])

        # As in the full gateway: bind the server first. With serve.port set
        # to 0 the kernel picks it, and the mandatory self-exclusion clause
        # must be built around whichever port that actually is.
        server.start()
        writer = None
        try:
            if save["enabled"]:
                writer = CappedPcapWriter(
                    save["path"], save["max_mib"] * 1024 * 1024, snaplen=server.snaplen
                )
            if config["source"] == "replay":
                receiver = PcapReplay(config["replay"]["file"])
            else:
                receiver = LiveCapture(
                    config["live"]["iface"],
                    pcapoverip_port=server.port_in_use,
                    exclude_ssh=config["exclude_self"],
                    user_filter=config["filter"]["custom"] or None,
                )
            # Open before declaring success, same reasoning as the gateway: a
            # bound port with a source that never actually started is worse
            # than a clean failure right here.
            receiver.open()
        except BaseException:
            if writer is not None:
                writer.close()
            server.stop(timeout=1.0)
            raise

        self._ring, self._receiver, self._server, self._writer = ring, receiver, server, writer
        self.config = config
        self.state = STATE_RUNNING
        self.error = None
        self.started_at = time.time()
        self.stopped_at = None
        self._thread = threading.Thread(target=self._run, name="spantap-lite-rx", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        receiver, ring, writer = self._receiver, self._ring, self._writer
        final, error = STATE_STOPPED, None
        try:
            for rf in receiver.frames():
                ring.put((rf.ts_ns, rf.frame, len(rf.frame)))
                if writer is not None:
                    writer.write(rf.ts_ns, rf.frame, len(rf.frame))
            if receiver.last_error:
                final, error = STATE_ERROR, receiver.last_error
        except CaptureError as exc:
            final, error = STATE_ERROR, str(exc)
        except Exception as exc:  # noqa: BLE001 -- surfaced to the CLI, never silent
            final, error = STATE_ERROR, "%s: %s" % (type(exc).__name__, exc)
        if self.state != STATE_STOPPING or final == STATE_ERROR:
            self.state = final
            self.error = error
            self.stopped_at = time.time()

    def stop(self, timeout: float = 5.0) -> None:
        if self.state == STATE_RUNNING:
            self.state = STATE_STOPPING
        if self._receiver is not None:
            self._receiver.request_stop()
        if self._server is not None:
            self._server.stop(timeout=timeout)
        if self._receiver is not None:
            self._receiver.close()
        if self._ring is not None:
            self._ring.close()
        if self._writer is not None:
            self._writer.close()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        if self._thread is not None and self._thread.is_alive():
            self.state = STATE_ERROR
            self.error = "the receiver did not stop within %.0fs" % timeout
        elif self.state == STATE_STOPPING:
            self.state = STATE_STOPPED
        self.stopped_at = self.stopped_at or time.time()

    def snapshot(self) -> Dict:
        return {
            "state": self.state,
            "error": self.error,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "receiver": self._receiver.snapshot() if self._receiver is not None else None,
            "ring": self._ring.snapshot() if self._ring is not None else None,
            "server": self._server.snapshot() if self._server is not None else None,
            "save": self._writer.snapshot() if self._writer is not None else None,
        }


__all__ = [
    "LiteService", "CappedPcapWriter",
    "STATE_IDLE", "STATE_RUNNING", "STATE_STOPPING", "STATE_STOPPED", "STATE_ERROR",
]
