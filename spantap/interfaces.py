# SPDX-License-Identifier: GPL-2.0-or-later
"""Enumerate the host's network interfaces, for the source picker.

Reads /sys and asks the kernel directly through ioctl rather than shelling out
to ``ip``, so it works on a minimal box with no iproute2 installed.
"""

from __future__ import annotations

import fcntl
import os
import socket
import struct
from typing import Dict, List, Optional

SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B

SYS_NET = "/sys/class/net"


def _sysfs(iface: str, attr: str) -> Optional[str]:
    try:
        with open(os.path.join(SYS_NET, iface, attr)) as fh:
            return fh.read().strip()
    except (OSError, ValueError):
        return None


def _ioctl_addr(iface: str, request: int) -> Optional[str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = fcntl.ioctl(
            s.fileno(), request, struct.pack("256s", iface[:15].encode("ascii", "ignore"))
        )
        return socket.inet_ntoa(packed[20:24])
    except OSError:
        return None
    finally:
        s.close()


def _ipv6_addresses() -> Dict[str, List[str]]:
    """Parse /proc/net/if_inet6, which is the only place these are listed."""
    out: Dict[str, List[str]] = {}
    try:
        with open("/proc/net/if_inet6") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 6:
                    continue
                raw, iface = parts[0], parts[5]
                groups = [raw[i:i + 4] for i in range(0, 32, 4)]
                try:
                    addr = socket.inet_ntop(
                        socket.AF_INET6, socket.inet_pton(socket.AF_INET6, ":".join(groups))
                    )
                except OSError:
                    continue
                out.setdefault(iface, []).append(addr)
    except OSError:
        pass
    return out


def list_interfaces(include_down: bool = True) -> List[Dict]:
    """Return one dict per interface, sorted with the most useful ones first."""
    try:
        names = sorted(os.listdir(SYS_NET))
    except OSError:
        return []

    v6 = _ipv6_addresses()
    out = []
    for name in names:
        state = _sysfs(name, "operstate") or "unknown"
        if not include_down and state == "down":
            continue
        mtu = _sysfs(name, "mtu")
        flags = _sysfs(name, "flags")
        is_loopback = False
        if flags:
            try:
                is_loopback = bool(int(flags, 16) & 0x8)  # IFF_LOOPBACK
            except ValueError:
                pass
        out.append(
            {
                "name": name,
                "state": state,
                "mtu": int(mtu) if mtu and mtu.isdigit() else None,
                "mac": _sysfs(name, "address"),
                "ipv4": _ioctl_addr(name, SIOCGIFADDR),
                "ipv6": v6.get(name, []),
                "loopback": is_loopback,
                "carrier": _sysfs(name, "carrier") == "1",
            }
        )

    def rank(iface: Dict):
        # up-with-an-address first, then up, then the rest; loopback last.
        return (
            iface["loopback"],
            iface["state"] != "up",
            iface["ipv4"] is None,
            iface["name"],
        )

    return sorted(out, key=rank)
