# SPDX-License-Identifier: GPL-2.0-or-later
"""Turning a profile into a running simulation, in the background.

The web UI drives this; the CLI does not need it. Everything the monitor shows
comes from :meth:`SimulationController.snapshot`, which is safe to call from
another thread at any time.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, Optional, Tuple

from .config import ConfigError, validate
from .encap import EN_DOT1Q, EN_NONE, ErspanConfig, ErspanEncapsulator
from .exclusion import build_plan
from .pacer import Pacer
from .runner import Runner
from .sources.base import PacketSource
from .sources.filesrc import PcapFileSource
from .sources.live import LiveSource
from .sources.synth import SyntheticSource
from .stats import Stats
from .transport import (
    NullSender,
    PcapFileSender,
    RawSocketSender,
    Sender,
    guess_source_address,
)

STATE_IDLE = "idle"
STATE_RUNNING = "running"
STATE_STOPPING = "stopping"
STATE_FINISHED = "finished"
STATE_ERROR = "error"


def build_components(profile: Dict) -> Tuple[PacketSource, ErspanEncapsulator, Sender, Pacer, Dict]:
    """Assemble everything a run needs from a validated profile."""
    p = validate(profile, for_run=True)
    t = p["target"]
    src = t["src"] or guess_source_address(t["dst"])

    config = ErspanConfig(
        dst=t["dst"],
        src=src,
        session_id=t["session_id"],
        vlan=t["vlan"],
        cos=t["cos"],
        en=EN_DOT1Q if t["vlan"] else EN_NONE,
        index=t["index"],
        ttl=t["ttl"],
        dscp=t["dscp"],
        df=t["df"],
        mtu=t["mtu"],
    )
    encapsulator = ErspanEncapsulator(config)

    info: Dict = {
        "effective_src": src,
        "max_frame_len": config.max_frame_len(),
        "filter": None,
        "filter_clauses": [],
    }

    if p["source"] == "synth":
        s = p["synth"]
        source: PacketSource = SyntheticSource(
            scenario=s["scenario"], count=s["count"], seed=s["seed"],
            vlan=s.get("vlan") or None, v6_ratio=s["v6_ratio"],
        )
        pacer = Pacer(pps=s["pps"])
    elif p["source"] == "replay":
        r = p["replay"]
        source = PcapFileSource(r["file"], loop=r["loop"])
        pacer = Pacer(speed=r["speed"], pps=r["pps"])
    else:
        live_cfg, exc = p["live"], p["exclusions"]
        source = LiveSource(
            iface=live_cfg["iface"],
            dst=t["dst"],
            src=src,
            user_filter=live_cfg["filter"] or None,
            snaplen=live_cfg["snaplen"],
            pcapoverip_port=exc["pcapoverip_port"],
            pcapoverip_host=exc["pcapoverip_host"] or None,
            exclude_ssh=exc["exclude_ssh"],
        )
        pacer = Pacer()
        info["filter"] = source.bpf
        info["filter_clauses"] = source.plan.explain()

    mode = p["output"]["mode"]
    if mode == "dry":
        sender: Sender = NullSender()
    elif mode == "pcap":
        sender = PcapFileSender(p["output"]["pcap_path"])
    else:
        sender = RawSocketSender(t["dst"])

    info["source_description"] = source.description
    info["output_description"] = sender.description
    return source, encapsulator, sender, pacer, info


def preview_filter(profile: Dict) -> Dict:
    """What the capture filter would be, without starting anything.

    The UI calls this on every edit so the exclusions are visible before you
    commit to a run, rather than scrolling past in a log line.
    """
    p = validate(profile)
    t, live_cfg, exc = p["target"], p["live"], p["exclusions"]
    dst = t["dst"] or "<receiver>"
    src = t["src"] or (guess_source_address(dst) if t["dst"] else "")
    plan = build_plan(
        dst, src or None,
        pcapoverip_port=exc["pcapoverip_port"],
        pcapoverip_host=exc["pcapoverip_host"] or None,
        exclude_ssh=exc["exclude_ssh"],
        user_filter=live_cfg["filter"] or None,
    )
    return {"expression": plan.expression(), "clauses": plan.explain()}


class SimulationController:
    """One simulation at a time, started and stopped from another thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._runner: Optional[Runner] = None
        self._source: Optional[PacketSource] = None
        self._sender: Optional[Sender] = None
        self.state = STATE_IDLE
        self.error: Optional[str] = None
        self.stats: Optional[Stats] = None
        self.info: Dict = {}
        self.profile: Optional[Dict] = None
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None

    # -- control -----------------------------------------------------------

    def is_running(self) -> bool:
        with self._lock:
            return self.state in (STATE_RUNNING, STATE_STOPPING)

    def start(self, profile: Dict) -> None:
        # The whole of start() holds the lock. Checking the state, releasing,
        # then building is a race: several concurrent POSTs to /api/start all
        # pass the check and each leaves a running thread, of which only the
        # last is reachable by stop() — the rest keep transmitting until the
        # process is killed.
        with self._lock:
            if self.state in (STATE_RUNNING, STATE_STOPPING):
                raise RuntimeError("a simulation is already running")

            source, encapsulator, sender, pacer, info = build_components(profile)
            stats = Stats(interval=0.0, classify_traffic=True)
            runner = Runner(source, encapsulator, sender, pacer, stats)

            self._source, self._sender, self._runner = source, sender, runner
            self.stats, self.info = stats, info
            self.profile = validate(profile, for_run=True)
            self.state = STATE_RUNNING
            self.error = None
            self.started_at = time.time()
            self.finished_at = None
            self._thread = threading.Thread(target=self._run, name="spantap-sim", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        try:
            self._runner.run()          # type: ignore[union-attr]
            final_state, error = STATE_FINISHED, None
        except Exception as exc:        # noqa: BLE001 — surfaced in the UI
            final_state, error = STATE_ERROR, "%s: %s" % (type(exc).__name__, exc)
        finally:
            for closeable in (self._source, self._sender):
                try:
                    if closeable is not None:
                        closeable.close()
                except Exception:       # noqa: BLE001
                    pass
        with self._lock:
            self.state = final_state
            self.error = error
            self.finished_at = time.time()

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            runner, source, thread = self._runner, self._source, self._thread
            if self.state == STATE_RUNNING:
                self.state = STATE_STOPPING
        if runner is not None:
            runner.request_stop()
        # A live capture is blocked reading its pipe; closing the source ends
        # that read instead of waiting for the next packet, which may never come.
        if source is not None:
            try:
                source.close()
            except Exception:           # noqa: BLE001
                pass
        if thread is not None:
            thread.join(timeout=timeout)
            if thread.is_alive():
                # Do not leave the UI wedged in "stopping" with Start refused
                # and Stop greyed out: say what happened and accept a restart.
                with self._lock:
                    self.state = STATE_ERROR
                    self.error = (
                        "the run did not stop within %.0fs; its thread is still "
                        "winding down" % timeout
                    )
                    self.finished_at = time.time()

    # -- observation -------------------------------------------------------

    def snapshot(self, sample: bool = True) -> Dict:
        with self._lock:
            state, error, stats = self.state, self.error, self.stats
            info, profile = dict(self.info), self.profile
            started, finished = self.started_at, self.finished_at
        if stats is not None and sample and state == STATE_RUNNING:
            stats.sample()
        return {
            "state": state,
            "error": error,
            "info": info,
            "profile": profile,
            "started_at": started,
            "finished_at": finished,
            "stats": stats.snapshot() if stats is not None else None,
        }


__all__ = [
    "SimulationController", "build_components", "preview_filter", "ConfigError",
    "STATE_IDLE", "STATE_RUNNING", "STATE_STOPPING", "STATE_FINISHED", "STATE_ERROR",
]
