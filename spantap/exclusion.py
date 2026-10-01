# SPDX-License-Identifier: GPL-2.0-or-later
"""Building the capture filter that keeps the simulator out of its own capture.

Two feedback loops are possible when mirroring a live interface, and both are
silent until the link is saturated:

1. **The ERSPAN stream itself.** We capture a frame, wrap it, send it out of
   the same interface — and capture that too, wrap it, send it. Each round adds
   36 bytes and one packet; it compounds immediately.

2. **The PCAP-over-IP gateway's client session.** The gateway this simulator
   feeds hands the de-encapsulated frames to Wireshark over TCP. If that
   session crosses the interface we are mirroring, every frame we send comes
   back at us inside the gateway's output stream, which we then mirror again.
   This one is easy to miss, because it only appears once the whole chain is
   running.

The ERSPAN self-exclusion is unconditional: there is no argument, no setting
and no code path that omits it.

The PCAP-over-IP exclusion is applied whenever a port is configured, and it is
on by default. Setting the port to 0 removes the clause, which is the honest
escape hatch for someone who is not running a gateway at all — but leaving the
default in place costs nothing even then, so there is rarely a reason to.

One caveat worth stating plainly: ``--capture-cmd`` replaces the capture
command outright, so a filter built here is only applied if that replacement
command applies it. That switch exists for testing and hands the problem back
to the caller.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

DEFAULT_PCAPOVERIP_PORT = 57012
SSH_PORT = 22


@dataclass
class Clause:
    """One piece of the compiled filter, with the reason it is there."""

    expr: str
    reason: str
    mandatory: bool = True


@dataclass
class ExclusionPlan:
    """The compiled capture filter plus an explanation of every clause."""

    clauses: List[Clause] = field(default_factory=list)

    def expression(self) -> str:
        return " and ".join(c.expr for c in self.clauses)

    def explain(self) -> List[dict]:
        return [
            {"expr": c.expr, "reason": c.reason, "mandatory": c.mandatory}
            for c in self.clauses
        ]


def build_plan(
    erspan_dst: str,
    erspan_src: Optional[str] = None,
    *,
    pcapoverip_port: int = DEFAULT_PCAPOVERIP_PORT,
    pcapoverip_host: Optional[str] = None,
    exclude_ssh: bool = False,
    user_filter: Optional[str] = None,
) -> ExclusionPlan:
    """Compile the capture filter for a live source.

    The user's own filter is ANDed in as one more clause; it can narrow what we
    capture but can never re-admit what the mandatory clauses remove.
    """
    plan = ExclusionPlan()

    # The mandatory clauses come first, and the user's filter last. Order is
    # not cosmetic in BPF: keywords such as `vlan` shift the offsets libpcap
    # uses for every predicate that follows them, so a user filter mentioning
    # `vlan` must not be able to move the ground under the exclusions.
    src_part = ""
    if erspan_src and erspan_src != "0.0.0.0":
        src_part = " and src host %s" % erspan_src
    plan.clauses.append(
        Clause(
            expr="not (ip proto 47%s and dst host %s)" % (src_part, erspan_dst),
            reason="the ERSPAN stream this simulator is sending — without this "
                   "it mirrors its own output and the link saturates in seconds",
        )
    )

    if pcapoverip_port:
        scope = ""
        if pcapoverip_host:
            scope = " and host %s" % pcapoverip_host
        plan.clauses.append(
            Clause(
                expr="not (tcp port %d%s)" % (pcapoverip_port, scope),
                reason="the PCAP-over-IP gateway's client session on tcp/%d — "
                       "the frames it feeds to Wireshark would otherwise come "
                       "back and be mirrored a second time" % pcapoverip_port,
            )
        )

    if exclude_ssh:
        plan.clauses.append(
            Clause(
                expr="not (tcp port %d)" % SSH_PORT,
                reason="your own SSH session to this host (optional)",
                mandatory=False,
            )
        )

    if user_filter and user_filter.strip():
        plan.clauses.append(
            Clause(
                expr="(%s)" % user_filter.strip(),
                reason="your own capture filter",
                mandatory=False,
            )
        )

    return plan


def build_gateway_plan(
    *,
    pcapoverip_port: int = DEFAULT_PCAPOVERIP_PORT,
    pcapoverip_host: Optional[str] = None,
    erspan_receiving: bool = False,
    exclude_ssh: bool = False,
    user_filter: Optional[str] = None,
) -> ExclusionPlan:
    """Compile the capture filter for the *gateway* mirroring a local interface.

    The loop here is the mirror image of the simulator's, and just as fatal.
    The gateway captures a frame, writes it to Wireshark over tcp/57012, and
    that TCP segment goes out of the same interface — where it is captured,
    written, and sent again. Each round trip is bigger than the last, because
    every frame now carries the previous round inside it. Left out, the link
    saturates in seconds and the capture is worthless long before that.

    So unlike the simulator's version, this clause is **not** conditional on a
    port being configured: the gateway always has a PCAP-over-IP server, that
    server is the only reason the gateway exists, and its port is therefore
    always known. There is no argument that removes it.

    ``erspan_receiving`` is for the case where the interface being captured is
    also the one ERSPAN arrives on. Those frames reach the ring through the
    receiver already, decapsulated; capturing the GRE packets as well would
    deliver each mirrored frame twice, once wrapped and once not. That clause
    is advisory — it is about duplication, not a loop — so it is marked
    non-mandatory and the UI lets you turn it off.
    """
    plan = ExclusionPlan()

    # Mandatory first: BPF's `vlan` keyword shifts the offsets of everything
    # after it, so a user filter must never be able to move the ground under
    # the clause that stops the feedback loop.
    scope = ""
    if pcapoverip_host:
        scope = " and host %s" % pcapoverip_host
    plan.clauses.append(
        Clause(
            expr="not (tcp port %d%s)" % (pcapoverip_port, scope),
            reason="this gateway's own PCAP-over-IP session on tcp/%d — the "
                   "frames it writes to Wireshark leave by the interface it is "
                   "capturing, so without this it captures its own output, "
                   "sends that, captures it again, and saturates the link"
                   % pcapoverip_port,
        )
    )

    if erspan_receiving:
        plan.clauses.append(
            Clause(
                expr="not (ip proto 47)",
                reason="GRE arriving on this interface — the ERSPAN receiver "
                       "already delivers those frames decapsulated, so "
                       "capturing them here would show each one twice",
                mandatory=False,
            )
        )

    if exclude_ssh:
        plan.clauses.append(
            Clause(
                expr="not (tcp port %d)" % SSH_PORT,
                reason="your own SSH session to this host (optional)",
                mandatory=False,
            )
        )

    if user_filter and user_filter.strip():
        plan.clauses.append(
            Clause(
                expr="(%s)" % user_filter.strip(),
                reason="your own capture filter",
                mandatory=False,
            )
        )

    return plan


def build_filter(*args, **kwargs) -> str:
    """Convenience wrapper returning just the filter expression."""
    return build_plan(*args, **kwargs).expression()
