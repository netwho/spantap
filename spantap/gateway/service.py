# SPDX-License-Identifier: GPL-2.0-or-later
"""The gateway proper: source → ring → PCAP-over-IP server.

Three threads, each with one job: the source pulls frames in and never waits
for anyone; the ring absorbs the difference in pace and counts what it had to
throw away; the server writes whatever the ring has to whichever Wireshark is
connected. Nothing downstream can stall the source, which is the only property
that really matters in a tap.

The source is one of three, chosen by ``source`` in the configuration:

``erspan``
    :class:`~spantap.gateway.receiver.ErspanReceiver` — a raw GRE socket
    taking mirrored frames from a switch.
``live``
    :class:`~spantap.gateway.livecapture.LiveCapture` — a local interface,
    for a host worth watching that no switch is mirroring.
``replay``
    :class:`~spantap.gateway.replay.PcapReplay` — a stored capture, played
    back, for demoing or troubleshooting the delivery side without either
    of the above at hand.

One at a time, deliberately. All three deliver Ethernet frames and could be
merged, but ERSPAN carries a GRE sequence number and neither a local capture
nor a replayed file does, so a merged stream would report a loss figure that
was meaningful for part of it and meaningless for the rest.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, Optional

from ..config import ConfigError, validate_gateway
from ..sources.live import CaptureError
from ..stats import Stats
from .delivery import DeliveryTracker
from .livecapture import LiveCapture
from .pcapoverip import PcapOverIpServer
from .receiver import ErspanReceiver, ReceiverError
from .replay import PcapReplay, ReplayError
from .ring import FrameRing

STATE_IDLE = "idle"
STATE_RUNNING = "running"
STATE_STOPPING = "stopping"
STATE_STOPPED = "stopped"
STATE_ERROR = "error"


class GatewayController:
    """One gateway at a time, started and stopped from another thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        #: Either an ErspanReceiver or a LiveCapture: both present open(),
        #: frames(), request_stop(), close() and snapshot(), and nothing here
        #: needs to know which one it is holding.
        self._receiver = None
        self._server: Optional[PcapOverIpServer] = None
        self._ring: Optional[FrameRing] = None

        self.state = STATE_IDLE
        self.error: Optional[str] = None
        self.stats: Optional[Stats] = None
        #: What reached Wireshark, which is a different question from what
        #: arrived and is not answerable from Stats.
        self.delivery: Optional[DeliveryTracker] = None
        self.config: Optional[Dict] = None
        self.started_at: Optional[float] = None
        self.stopped_at: Optional[float] = None

    # -- control -----------------------------------------------------------

    def is_running(self) -> bool:
        with self._lock:
            return self.state in (STATE_RUNNING, STATE_STOPPING)

    def start(self, config: Dict) -> None:
        # As in the simulator's controller: the whole of start() holds the
        # lock, so concurrent requests cannot each leave a socket bound.
        with self._lock:
            if self.state in (STATE_RUNNING, STATE_STOPPING):
                raise RuntimeError("the gateway is already running")

            cfg = validate_gateway(config)
            rx, srv, buf = cfg["receive"], cfg["serve"], cfg["buffer"]
            live = cfg["live"]

            ring = FrameRing(
                max_frames=buf["max_frames"],
                max_bytes=buf["max_mib"] * 1024 * 1024,
            )
            server = PcapOverIpServer(
                ring, bind=srv["bind"], port=srv["port"], snaplen=srv["snaplen"] or 0
            )

            # The server binds FIRST, before the source exists. With
            # serve.port set to 0 the kernel picks the port, and the whole
            # safety of a live capture rests on excluding the port we are
            # actually listening on: building the filter around 57012 while
            # serving on 43117 would leave the feedback loop wide open and
            # nothing would look wrong until the link melted.
            server.start()
            try:
                if cfg["source"] == "live":
                    receiver = LiveCapture(
                        live["iface"],
                        pcapoverip_port=server.port_in_use,
                        erspan_receiving=live["exclude_gre"],
                        exclude_ssh=live["exclude_ssh"],
                        user_filter=live["filter"] or None,
                        snaplen=live["snaplen"] or 0,
                    )
                elif cfg["source"] == "replay":
                    replay = cfg["replay"]
                    receiver = PcapReplay(
                        replay["file"],
                        loop=replay["loop"],
                        pace=replay["pace"],
                    )
                else:
                    receiver = ErspanReceiver(
                        bind=rx["bind"],
                        session_id=rx["session_id"],
                        from_host=rx["from_host"] or None,
                        rcvbuf=rx["rcvbuf_mib"] * 1024 * 1024,
                    )
                # Open before declaring success: a bound port with a dead
                # source is worse than a clean failure at start time.
                receiver.open()
            except BaseException:
                server.stop(timeout=1.0)
                raise

            self._ring, self._receiver, self._server = ring, receiver, server
            self.stats = Stats(interval=0.0, classify_traffic=True)
            self.delivery = DeliveryTracker()
            self.config = cfg
            self.state = STATE_RUNNING
            self.error = None
            self.started_at = time.time()
            self.stopped_at = None
            self._thread = threading.Thread(
                target=self._run, name="spantap-gw-rx", daemon=True
            )
            self._thread.start()

    def _run(self) -> None:
        receiver, ring, stats = self._receiver, self._ring, self.stats
        assert receiver is not None and ring is not None and stats is not None
        final, error = STATE_STOPPED, None
        try:
            for rf in receiver.frames():
                stats.record(rf.frame, len(rf.frame), truncated=rf.truncated)
                ring.put((rf.ts_ns, rf.frame, len(rf.frame)))
            if receiver.last_error:
                final, error = STATE_ERROR, receiver.last_error
        except (ReceiverError, CaptureError, ReplayError) as exc:
            final, error = STATE_ERROR, str(exc)
        except Exception as exc:  # noqa: BLE001 — surfaced in the UI, never silent
            final, error = STATE_ERROR, "%s: %s" % (type(exc).__name__, exc)
        with self._lock:
            if self.state != STATE_STOPPING or final == STATE_ERROR:
                self.state = final
                self.error = error
                self.stopped_at = time.time()

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            receiver, server, ring, thread = (
                self._receiver, self._server, self._ring, self._thread
            )
            if self.state == STATE_RUNNING:
                self.state = STATE_STOPPING
        if receiver is not None:
            receiver.request_stop()
        if server is not None:
            server.stop(timeout=timeout)
        if receiver is not None:
            receiver.close()
        if ring is not None:
            ring.close()
        if thread is not None:
            thread.join(timeout=timeout)
        with self._lock:
            if thread is not None and thread.is_alive():
                self.state = STATE_ERROR
                self.error = "the receiver did not stop within %.0fs" % timeout
            elif self.state == STATE_STOPPING:
                self.state = STATE_STOPPED
            self.stopped_at = self.stopped_at or time.time()

    # -- observation -------------------------------------------------------

    def snapshot(self, sample: bool = True) -> Dict:
        with self._lock:
            state, error, config = self.state, self.error, self.config
            receiver, server, ring, stats, delivery = (
                self._receiver, self._server, self._ring, self.stats, self.delivery
            )
            started, stopped = self.started_at, self.stopped_at

        rx_snap = receiver.snapshot() if receiver is not None else None
        ring_snap = ring.snapshot() if ring is not None else None
        srv_snap = server.snapshot() if server is not None else None

        if stats is not None and sample and state == STATE_RUNNING:
            stats.sample()
        if delivery is not None and srv_snap is not None:
            # Client history is recorded on every snapshot, not only sampled
            # ones: a Wireshark that attaches and leaves between two samples
            # would otherwise never appear.
            delivery.note_client(
                srv_snap.get("peer"), bool(srv_snap.get("connected")),
                srv_snap.get("connected_since"), srv_snap.get("frames_sent", 0))
            if sample and state == STATE_RUNNING:
                delivery.sample(srv_snap.get("frames_sent", 0),
                                srv_snap.get("bytes_sent", 0))

        return {
            "state": state,
            "error": error,
            "config": config,
            "started_at": started,
            "stopped_at": stopped,
            "receiver": rx_snap,
            "ring": ring_snap,
            "server": srv_snap,
            "stats": stats.snapshot() if stats is not None else None,
            "delivery": delivery.snapshot(srv_snap) if delivery is not None else None,
            "accounting": DeliveryTracker.reconcile(rx_snap, ring_snap, srv_snap),
        }


__all__ = [
    "GatewayController", "ConfigError",
    "STATE_IDLE", "STATE_RUNNING", "STATE_STOPPING", "STATE_STOPPED", "STATE_ERROR",
]
