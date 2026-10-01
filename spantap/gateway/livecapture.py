# SPDX-License-Identifier: GPL-2.0-or-later
"""The other receiving half: frames straight off a local interface.

The gateway's job is to put frames in front of Wireshark over TCP. Where those
frames come from is a detail, and there is no reason it has to be a switch's
ERSPAN session: a host with an interface worth watching can feed the same
PCAP-over-IP endpoint, with the same buffering and the same back-pressure
behaviour, and you connect to it exactly the same way.

This class therefore presents the same surface as
:class:`~spantap.gateway.receiver.ErspanReceiver` — ``open``, ``frames``,
``request_stop``, ``close``, ``snapshot``, ``description``, ``last_error`` —
so :class:`~spantap.gateway.service.GatewayController` holds one or the
other and does not care which.

Two things differ, and both are worth being explicit about rather than
papering over:

**The feedback loop is worse here than in the simulator.** The gateway writes
captured frames to Wireshark over tcp/57012. If that session crosses the
interface being captured, each frame written is itself captured and written
again — and the second copy contains the first, so every round is larger than
the last. The exclusion is mandatory, lives in
:func:`spantap.exclusion.build_gateway_plan`, and is emitted before any
user filter because BPF's ``vlan`` keyword shifts the offsets of whatever
follows it.

**Sequence numbers mean nothing here.** ERSPAN carries a GRE sequence number,
so the receiver can say how many frames were lost between the switch and this
host. A local capture has no such thing: what the kernel did not give us, we
cannot count. ``lost`` is reported as None rather than 0, because "none lost"
and "cannot know" are different claims and a tap should not confuse them. What
*can* be counted is what the capture tool itself reports dropping, which is a
different number and is read from its exit summary.
"""

from __future__ import annotations

import collections
import subprocess
import threading
import time
from typing import Iterator, List, Optional, Sequence

from ..exclusion import DEFAULT_PCAPOVERIP_PORT, build_gateway_plan
from ..sources.live import CaptureError, build_command, capture_tool_status
from ..sources.pcapread import open_packet_stream, to_ethernet
from .receiver import ReceivedFrame


class LiveCapture:
    """Mirror a local interface into the gateway's ring."""

    def __init__(
        self,
        iface: str,
        *,
        pcapoverip_port: int = DEFAULT_PCAPOVERIP_PORT,
        pcapoverip_host: Optional[str] = None,
        erspan_receiving: bool = False,
        exclude_ssh: bool = False,
        user_filter: Optional[str] = None,
        snaplen: int = 0,
        tool: Optional[str] = None,
        capture_cmd: Optional[Sequence[str]] = None,
    ):
        if not iface:
            raise CaptureError("an interface name is required")
        self.iface = iface
        self.plan = build_gateway_plan(
            pcapoverip_port=pcapoverip_port,
            pcapoverip_host=pcapoverip_host,
            erspan_receiving=erspan_receiving,
            exclude_ssh=exclude_ssh,
            user_filter=user_filter,
        )
        self.bpf = self.plan.expression()
        self.mandatory_filter = " and ".join(
            c.expr for c in self.plan.clauses if c.mandatory
        )

        self.received = 0
        self.bytes = 0
        self.truncated = 0
        #: What the capture tool says the kernel dropped. Distinct from the
        #: ring's own drops, which happen later and for a different reason.
        self.kernel_dropped: Optional[int] = None
        self.last_error: Optional[str] = None

        self._proc: Optional[subprocess.Popen] = None
        self._closed = False
        self._stderr_tail: collections.deque = collections.deque(maxlen=30)

        if capture_cmd:
            self.cmd: List[str] = list(capture_cmd)
            self.tool = self.cmd[0]
        else:
            self.tool = tool or ""
            if not self.tool:
                found, problem = capture_tool_status()
                if not found:
                    raise CaptureError(problem or "no capture tool available")
                self.tool = found
            self.cmd = build_command(self.tool, iface, self.bpf, snaplen)

        self.description = "live capture on %s via %s" % (
            iface, self.tool.rsplit("/", 1)[-1])

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        """Spawn the capture tool.

        Separate from :meth:`frames` because the controller opens the source
        and binds the server *before* declaring the gateway started: a bound
        port with a capture tool that never launched is worse than a clean
        failure at start time.
        """
        if self._closed:
            return
        if self._proc is not None:
            return
        try:
            self._proc = subprocess.Popen(
                self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0
            )
        except OSError as exc:
            raise CaptureError("could not run %s: %s" % (self.tool, exc))
        threading.Thread(target=self._drain_stderr, daemon=True).start()

        # dumpcap exits immediately on a bad interface or an uncompilable
        # filter. Give it that moment, so the failure lands on start() rather
        # than as a gateway that reports "running" and never delivers a frame.
        deadline = time.time() + 0.6
        while time.time() < deadline:
            rc = self._proc.poll()
            if rc is None:
                time.sleep(0.05)
                continue
            if rc != 0:
                tail = "\n".join(self._stderr_tail) or "(no output)"
                self._proc = None
                raise CaptureError(
                    "%s exited immediately with status %d:\n%s"
                    % (self.tool, rc, tail))
            return          # exited cleanly already: nothing to capture, fine

    def _drain_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        for line in proc.stderr:
            text = line.decode("utf-8", "replace").rstrip()
            self._stderr_tail.append(text)
            self._note_drops(text)

    def _note_drops(self, line: str) -> None:
        """dumpcap reports kernel drops on exit; tcpdump on its stderr too."""
        lowered = line.lower()
        if "dropped" not in lowered and "dropped by" not in lowered:
            return
        for word in line.replace(",", " ").split():
            if word.isdigit():
                self.kernel_dropped = int(word)
                return

    def frames(self) -> Iterator[ReceivedFrame]:
        """Yield frames until the tool exits or a stop is requested."""
        if self._closed:
            return
        if self._proc is None:
            self.open()
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        try:
            for pkt in open_packet_stream(proc.stdout):
                if self._closed:
                    break
                # Whatever the link type, the ring and the PCAP-over-IP server
                # deal in Ethernet frames — the same shape ERSPAN delivers, so
                # a client cannot tell which source it is reading.
                frame = to_ethernet(pkt)
                self.received += 1
                self.bytes += len(frame)
                truncated = bool(pkt.orig_len and pkt.orig_len > len(frame))
                if truncated:
                    self.truncated += 1
                yield ReceivedFrame(
                    ts_ns=pkt.ts_ns,
                    frame=frame,
                    session_id=-1,          # no session: this is not ERSPAN
                    seq=-1,                 # and no sequence number either
                    truncated=truncated,
                    source=self.iface,
                )
        except Exception:
            self._raise_if_tool_failed()
            raise
        self._raise_if_tool_failed()

    def _raise_if_tool_failed(self) -> None:
        proc = self._proc
        if proc is None or self._closed:
            return
        rc = proc.poll()
        if rc not in (None, 0):
            tail = "\n".join(self._stderr_tail) or "(no output)"
            self.last_error = "%s exited with status %d:\n%s" % (self.tool, rc, tail)
            raise CaptureError(self.last_error)

    def request_stop(self) -> None:
        self._closed = True

    def close(self) -> None:
        self._closed = True
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
        for pipe in (proc.stdout, proc.stderr):
            try:
                if pipe is not None:
                    pipe.close()
            except OSError:
                pass

    # -- observation -------------------------------------------------------

    def snapshot(self) -> dict:
        return {
            "kind": "live",
            "description": self.description,
            "iface": self.iface,
            "received": self.received,
            "bytes": self.bytes,
            "ignored": 0,
            "filtered": 0,
            # None, not 0: a local capture carries no sequence number, so loss
            # between the wire and here is not something we can claim to know.
            "lost": None,
            "reordered": None,
            "truncated": self.truncated,
            "kernel_dropped": self.kernel_dropped,
            "sessions": {},
            "sources": {self.iface: self.received},
            "filter": self.bpf,
            "exclusions": self.plan.explain(),
            "last_error": self.last_error,
        }


__all__ = ["LiveCapture", "CaptureError"]
