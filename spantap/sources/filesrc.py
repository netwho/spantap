# SPDX-License-Identifier: GPL-2.0-or-later
"""Replay a pcap / pcapng file as if it were a mirrored port."""

from __future__ import annotations

import os
from typing import Iterator, Optional

from .base import Packet, PacketSource
from .pcapread import open_packet_stream


class PcapFileSource(PacketSource):
    def __init__(
        self,
        path: str,
        loop: int = 1,
        limit: Optional[int] = None,
    ):
        """``loop`` of 0 means forever; ``limit`` caps the total packet count."""
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        self.path = path
        self.loop = loop
        self.limit = limit
        self.description = "pcap replay of %s%s" % (
            path,
            "" if loop == 1 else (" (looping forever)" if loop == 0 else " (%d passes)" % loop),
        )

    def __iter__(self) -> Iterator[Packet]:
        sent = 0
        pass_no = 0
        while self.loop == 0 or pass_no < self.loop:
            pass_no += 1
            with open(self.path, "rb") as fh:
                for pkt in open_packet_stream(fh):
                    yield pkt
                    sent += 1
                    if self.limit and sent >= self.limit:
                        return
