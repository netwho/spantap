# SPDX-License-Identifier: GPL-2.0-or-later
"""Common shape for every packet source."""

from __future__ import annotations

from typing import Iterator, NamedTuple


class Packet(NamedTuple):
    """One captured or generated frame on its way to the encapsulator."""

    ts_ns: int      # capture timestamp, nanoseconds since the epoch
    linktype: int   # libpcap link type of ``data``
    data: bytes     # the frame as captured (possibly already snapped)
    orig_len: int   # length on the wire before any snapping


class PacketSource:
    """Iterable of :class:`Packet`.

    Sources are single-use iterators, not re-iterable containers.  ``close()``
    is always safe to call twice and is called for you by the CLI.
    """

    #: short human-readable description, shown at startup
    description = "packet source"

    def __iter__(self) -> Iterator[Packet]:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def __enter__(self) -> "PacketSource":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
