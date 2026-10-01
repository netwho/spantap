# SPDX-License-Identifier: GPL-2.0-or-later
"""Live capture from a real interface, via dumpcap (preferred) or tcpdump.

Shelling out to a capture tool buys three things: the setcap-on-dumpcap
privilege model instead of running the simulator as root, a battle-tested BPF
compiler, and one less C dependency in the package.

The self-exclusion filter is NOT optional.  If the capture interface is also
the interface the ERSPAN stream leaves by, a simulator without it mirrors its
own output, mirrors the mirror, and saturates the link within seconds.  There
is no switch to turn it off; a user filter is ANDed with it, never instead of
it.  See :mod:`spantap.exclusion` for what else is excluded and why.

The one way round it is ``capture_cmd`` / ``--capture-cmd``, which replaces
the capture command wholesale — a testing hook that hands responsibility for
the filter back to the caller.  Nothing else bypasses it.
"""

from __future__ import annotations

import collections
import os
import shutil
import subprocess
import threading
from typing import Iterator, List, Optional, Sequence

from ..exclusion import DEFAULT_PCAPOVERIP_PORT, build_plan
from .base import Packet, PacketSource
from .pcapread import open_packet_stream


class CaptureError(RuntimeError):
    pass


def exclusion_filter(dst: str, src: Optional[str] = None) -> str:
    """BPF expression that hides our own ERSPAN stream from the capture."""
    if src and src != "0.0.0.0":
        return "not (ip proto 47 and src host %s and dst host %s)" % (src, dst)
    return "not (ip proto 47 and dst host %s)" % dst


def combine_filter(user_filter: Optional[str], mandatory: str) -> str:
    if user_filter and user_filter.strip():
        return "(%s) and %s" % (user_filter.strip(), mandatory)
    return mandatory


def find_capture_tool() -> Optional[str]:
    for tool in ("dumpcap", "tcpdump"):
        path = shutil.which(tool)
        if path:
            return path
    return None


#: Where a capture tool sits when it is installed but not on our PATH or not
#: executable by us — enough to tell "missing" from "present but out of reach".
_CAPTURE_PATHS = (
    "/usr/bin/dumpcap", "/usr/sbin/dumpcap", "/usr/local/bin/dumpcap",
    "/usr/bin/tcpdump", "/usr/sbin/tcpdump",
)


def capture_tool_status() -> tuple:
    """Return (path, problem). Exactly one of them is set.

    "Install dumpcap" is the wrong advice when dumpcap is sitting right there
    but owned by a group this process is not in — which is what Debian's
    wireshark-common does by default.
    """
    path = find_capture_tool()
    if path:
        return path, None
    for candidate in _CAPTURE_PATHS:
        if not os.path.exists(candidate):
            continue
        st = os.stat(candidate)
        return None, (
            "%s is installed but this process cannot execute it: it is mode "
            "%04o owned by %s:%s, and this runs as %s:%s. Add that group to "
            "this user, or give the group execute permission on it." % (
                candidate, st.st_mode & 0o7777,
                _owner_name(st.st_uid, "uid"), _group_name(st.st_gid),
                _owner_name(os.getuid(), "uid"), _group_name(os.getgid()),
            )
        )
    return None, "install dumpcap (wireshark-common) or tcpdump to mirror an interface"


def _owner_name(uid: int, _kind: str = "uid") -> str:
    try:
        import pwd

        return "%s(%d)" % (pwd.getpwuid(uid).pw_name, uid)
    except Exception:
        return "uid %d" % uid


def _group_name(gid: int) -> str:
    try:
        import grp

        return "%s(%d)" % (grp.getgrgid(gid).gr_name, gid)
    except Exception:
        return "gid %d" % gid


def build_command(tool: str, iface: str, bpf: str, snaplen: int = 0) -> List[str]:
    name = tool.rsplit("/", 1)[-1]
    if name == "dumpcap":
        cmd = [tool, "-i", iface, "-P", "-w", "-", "-q"]
        if snaplen:
            cmd += ["-s", str(snaplen)]
        cmd += ["-f", bpf]
        return cmd
    if name == "tcpdump":
        cmd = [tool, "-i", iface, "-w", "-", "-U", "-n", "-s", str(snaplen or 0), bpf]
        return cmd
    raise CaptureError("unknown capture tool %r" % tool)


class LiveSource(PacketSource):
    def __init__(
        self,
        iface: str,
        dst: str,
        src: Optional[str] = None,
        user_filter: Optional[str] = None,
        snaplen: int = 0,
        tool: Optional[str] = None,
        capture_cmd: Optional[Sequence[str]] = None,
        pcapoverip_port: int = DEFAULT_PCAPOVERIP_PORT,
        pcapoverip_host: Optional[str] = None,
        exclude_ssh: bool = False,
    ):
        self.iface = iface
        self.plan = build_plan(
            dst,
            src,
            pcapoverip_port=pcapoverip_port,
            pcapoverip_host=pcapoverip_host,
            exclude_ssh=exclude_ssh,
            user_filter=user_filter,
        )
        self.bpf = self.plan.expression()
        self.mandatory_filter = " and ".join(
            c.expr for c in self.plan.clauses if c.mandatory
        )
        self._proc: Optional[subprocess.Popen] = None
        self._closed = False
        self._stderr_tail: collections.deque = collections.deque(maxlen=20)

        if capture_cmd:
            self.cmd = list(capture_cmd)
            self.tool = self.cmd[0]
        else:
            self.tool = tool or find_capture_tool()
            if not self.tool:
                raise CaptureError(
                    "neither dumpcap nor tcpdump found in PATH; install wireshark-common "
                    "or tcpdump, or pass --capture-cmd"
                )
            self.cmd = build_command(self.tool, iface, self.bpf, snaplen)

        self.description = "live capture on %s via %s" % (iface, self.tool.rsplit("/", 1)[-1])

    def _drain_stderr(self) -> None:
        assert self._proc and self._proc.stderr
        for line in self._proc.stderr:
            self._stderr_tail.append(line.decode("utf-8", "replace").rstrip())

    def __iter__(self) -> Iterator[Packet]:
        # The capture tool is spawned here, on the consuming thread. If close()
        # already ran — a Stop that arrives before the first packet — starting
        # it now would orphan a dumpcap that nothing holds a handle to.
        if self._closed:
            return
        self._proc = subprocess.Popen(
            self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0
        )
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        assert self._proc.stdout is not None
        try:
            for pkt in open_packet_stream(self._proc.stdout):
                yield pkt
        except Exception:
            self._raise_if_tool_failed()
            raise
        self._raise_if_tool_failed()

    def _raise_if_tool_failed(self) -> None:
        proc = self._proc
        if proc is None:
            return
        rc = proc.poll()
        if rc not in (None, 0):
            tail = "\n".join(self._stderr_tail) or "(no output)"
            raise CaptureError(
                "%s exited with status %d:\n%s" % (self.tool, rc, tail)
            )

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
