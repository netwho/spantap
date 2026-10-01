# SPDX-License-Identifier: GPL-2.0-or-later
"""Command line for the gateway: spantap-gw."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import sys
import time
from typing import List, Optional

from .. import __version__
from ..config import (
    ConfigError,
    config_dir,
    default_gateway_config,
    gateway_path,
    load_gateway_or_default,
    save_gateway,
)
from .pcapoverip import DEFAULT_PORT
from .service import STATE_ERROR, STATE_RUNNING, GatewayController


def apply_overrides(config: dict, args: argparse.Namespace) -> dict:
    rx, srv, buf = config["receive"], config["serve"], config["buffer"]
    live = config["live"]
    replay = config["replay"]
    # --iface is what selects the live source, and --replay-file the replay
    # one: naming one and then having to say "and I mean it" would be a
    # second chance to get it wrong.
    if getattr(args, "iface", None):
        config["source"] = "live"
        live["iface"] = args.iface
    if getattr(args, "replay_file", None):
        config["source"] = "replay"
        replay["file"] = args.replay_file
    if getattr(args, "loop", None) is not None:
        replay["loop"] = args.loop
    if getattr(args, "no_pace", False):
        replay["pace"] = False
    if getattr(args, "capture_filter", None) is not None:
        live["filter"] = args.capture_filter
    if getattr(args, "exclude_gre", False):
        live["exclude_gre"] = True
    if getattr(args, "exclude_ssh", False):
        live["exclude_ssh"] = True
    if args.receive_on is not None:
        rx["bind"] = args.receive_on
    if args.session is not None:
        rx["session_id"] = None if args.session < 0 else args.session
    if args.from_host is not None:
        rx["from_host"] = args.from_host
    if args.bind is not None:
        srv["bind"] = args.bind
    if args.listen is not None:
        srv["port"] = args.listen
    if args.snaplen is not None:
        srv["snaplen"] = args.snaplen
    if args.ring is not None:
        buf["max_frames"] = args.ring
    if args.ring_mib is not None:
        buf["max_mib"] = args.ring_mib
    return config


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return "%.1f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024
    return "%.1f TiB" % n


def _fmt_lost(n) -> str:
    """``None`` means "no GRE sequence number to count it by" (the local
    interface and replay sources), which is not the same claim as 0 and must
    not print as one — or crash a %d formatter, which it did before this
    existed."""
    return "unknown" if n is None else str(n)


def cmd_run(args: argparse.Namespace) -> int:
    try:
        config = apply_overrides(load_gateway_or_default(), args)
        if args.save:
            config = save_gateway(config)
    except ConfigError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2

    controller = GatewayController()
    try:
        controller.start(config)
    except ConfigError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write("error: %s\n" % exc)
        if isinstance(exc, PermissionError) or "CAP_NET_RAW" in str(exc):
            sys.stderr.write("       run 'spantap-gw doctor' for how to grant it\n")
            return 13
        return 2

    snap = controller.snapshot(sample=False)
    rx, srv = snap["receiver"], snap["server"]
    if not args.quiet:
        sys.stderr.write("spantap-gw %s\n\n" % __version__)
        sys.stderr.write("  source  : %s\n" % rx["description"])
        if rx.get("filter"):
            sys.stderr.write("  filter  : %s\n" % rx["filter"])
        sys.stderr.write("  serve   : tcp/%d on %s, one client at a time\n"
                         % (srv["port"], srv["bind"]))
        sys.stderr.write("  buffer  : %d frames / %d MiB, drop-oldest\n"
                         % (config["buffer"]["max_frames"], config["buffer"]["max_mib"]))
        sys.stderr.write("\n  connect Wireshark with:\n    %s\n\n" % srv["hint"])
        sys.stderr.write("  Ctrl-C to stop.\n\n")

    stop = {"now": False}

    def on_signal(*_a):
        stop["now"] = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, on_signal)
        except (ValueError, OSError):
            pass

    interval = max(0.0, args.stats_interval)
    last = time.monotonic()
    last_received = 0
    try:
        while not stop["now"]:
            time.sleep(0.2)
            snap = controller.snapshot()
            if snap["state"] == STATE_ERROR:
                sys.stderr.write("\nerror: %s\n" % snap["error"])
                return 1
            if snap["state"] != STATE_RUNNING:
                break
            now = time.monotonic()
            if interval and now - last >= interval and not args.quiet:
                r, ring, s = snap["receiver"], snap["ring"], snap["server"]
                pps = (r["received"] - last_received) / (now - last)
                last, last_received = now, r["received"]
                sys.stderr.write(
                    "  %9d frames  %7.0f/s  lost %s  dropped %d  ring %3.0f%%  %s\n"
                    % (r["received"], pps, _fmt_lost(r["lost"]), ring["dropped"],
                       100 * ring["fill"],
                       "-> %s" % s["peer"] if s["connected"] else "(no client)")
                )
                sys.stderr.flush()
    finally:
        controller.stop()

    snap = controller.snapshot(sample=False)
    r, ring, s = snap["receiver"], snap["ring"], snap["server"]
    sys.stderr.write(
        "\n%d frames received (%s), %s lost per sequence number, %s reordered,\n"
        "%d dropped by the ring, %d served to %d client(s), %d connections refused\n"
        % (r["received"], _fmt_bytes(r["bytes"]), _fmt_lost(r["lost"]),
           _fmt_lost(r["reordered"]),
           ring["dropped"], s["frames_sent"], s["clients_served"], s["refused"])
    )
    if r["ignored"]:
        sys.stderr.write("%d GRE packets ignored (not ERSPAN Type II)\n" % r["ignored"])
    if snap["stats"]:
        for line in _protocol_lines(snap["stats"]):
            sys.stderr.write("%s\n" % line)
    return 0


def _protocol_lines(stats: dict) -> List[str]:
    total = stats.get("packets") or 0
    if not total:
        return []
    out = []
    for title in ("network", "transport", "application"):
        data = stats["protocols"].get(title) or {}
        if not data:
            continue
        parts = ["%s %d (%.0f%%)" % (k, v, 100.0 * v / total)
                 for k, v in sorted(data.items(), key=lambda kv: -kv[1])[:8]]
        out.append("  %-12s %s" % (title + ":", ", ".join(parts)))
    return out


def _check(label: str, ok: Optional[bool], detail: str = "") -> None:
    mark = {True: "ok  ", False: "FAIL", None: "warn"}[ok]
    print("  [%s] %-28s %s" % (mark, label, detail))


def cmd_doctor(args: argparse.Namespace) -> int:
    print("spantap-gw %s — environment check\n" % __version__)
    problems = 0
    config = load_gateway_or_default()
    port = args.listen if args.listen is not None else config["serve"]["port"]

    print("source: %s" % {"live": "local interface", "replay": "pcap replay"}
          .get(config["source"], "ERSPAN receiver"))
    if config["source"] == "live":
        _check("interface", bool(config["live"]["iface"]),
               config["live"]["iface"] or "none configured")
        if not config["live"]["iface"]:
            problems += 1
    if config["source"] == "replay":
        path = config["replay"]["file"]
        _check("capture file", bool(path) and os.path.isfile(path),
               path or "none configured")
        if not path or not os.path.isfile(path):
            problems += 1
    print()

    print("mirroring a local interface (needs a capture tool)")
    from ..sources.live import capture_tool_status
    tool, why = capture_tool_status()
    if tool:
        _check("capture tool", True, tool)
    else:
        _check("capture tool", None if config["source"] != "live" else False, why)
        if config["source"] == "live":
            problems += 1
    if config["source"] == "live":
        # The whole safety of this mode is one BPF clause. Print it, so a
        # deployment can be checked without starting it.
        from ..exclusion import build_gateway_plan
        plan = build_gateway_plan(
            pcapoverip_port=port or 57012,
            erspan_receiving=config["live"]["exclude_gre"],
            exclude_ssh=config["live"]["exclude_ssh"],
            user_filter=config["live"]["filter"] or None,
        )
        print("  [    ] %-28s %s" % ("capture filter", plan.expression()))
        if not port:
            print("         serve.port is 0, so the kernel picks it at start and")
            print("         the filter is built around whichever port it gets.")
    print()

    print("receiving ERSPAN (needs CAP_NET_RAW)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 47)
        s.close()
        _check("raw GRE socket", True, "can receive IP protocol 47")
    except PermissionError:
        problems += 1
        _check("raw GRE socket", False, "permission denied")
        print("         grant it to this interpreter without running as root:")
        print("           sudo setcap cap_net_raw+ep %s" % os.path.realpath(sys.executable))
        print("         (the installer does this for you)")
    except OSError as exc:
        problems += 1
        _check("raw GRE socket", False, str(exc))

    print("\nserving PCAP-over-IP")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind((config["serve"]["bind"], port))
        _check("tcp/%d" % port, True, "free on %s" % config["serve"]["bind"])
    except OSError as exc:
        problems += 1
        _check("tcp/%d" % port, False, "%s — pick another port with --listen" % exc)
    finally:
        probe.close()

    client = shutil.which("wireshark") or shutil.which("tshark")
    _check("wireshark/tshark", bool(client) or None,
           client or "not installed here (fine if you connect from elsewhere)")

    print("\nconfiguration")
    _check("config file", True,
           gateway_path() if os.path.exists(gateway_path())
           else "%s (not written yet, defaults in use)" % gateway_path())
    _check("config dir", True, config_dir())

    print("\nconnect with")
    print("    wireshark -k -i TCP@%s:%d"
          % ("127.0.0.1" if config["serve"]["bind"] in ("0.0.0.0", "") else config["serve"]["bind"],
             port))

    print("\n%s" % ("all good" if not problems else "%d problem(s) above" % problems))
    return 1 if problems else 0


def cmd_config(args: argparse.Namespace) -> int:
    if args.reset:
        save_gateway(default_gateway_config())
        print("reset to defaults: %s" % gateway_path())
        return 0
    try:
        print(json.dumps(load_gateway_or_default(), indent=2, sort_keys=True))
    except ConfigError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="spantap-gw",
        description="Receive ERSPAN Type II and serve the mirrored frames to "
                    "Wireshark over PCAP-over-IP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  spantap-gw doctor
  spantap-gw run
  spantap-gw run --session 23 --listen 57012 --save
  spantap-gw run --replay-file demo.pcapng --loop 0
  wireshark -k -i TCP@127.0.0.1:57012
""",
    )
    p.add_argument("--version", action="version", version="spantap-gw " + __version__)
    sub = p.add_subparsers(dest="command", required=True)

    pr = sub.add_parser("run", help="run the gateway in the foreground")
    g = pr.add_argument_group("source")
    g.add_argument("--iface", metavar="IF", default=None,
                   help="mirror a local interface instead of receiving ERSPAN; "
                        "naming one selects the live source")
    g.add_argument("--capture-filter", metavar="BPF", default=None,
                   help="extra capture filter for --iface, ANDed after the "
                        "mandatory exclusions (which it cannot undo)")
    g.add_argument("--exclude-gre", action="store_true",
                   help="with --iface, also skip GRE on the wire — use when this "
                        "host is an ERSPAN destination and you do not want each "
                        "frame both wrapped and unwrapped")
    g.add_argument("--exclude-ssh", action="store_true",
                   help="with --iface, also skip tcp/22")
    g.add_argument("--replay-file", metavar="PATH", default=None,
                   help="play back a stored pcap/pcapng file instead of "
                        "receiving ERSPAN or capturing live; naming one "
                        "selects the replay source")
    g.add_argument("--loop", type=int, default=None, metavar="N",
                   help="with --replay-file, how many passes: 0 = forever "
                        "(default), 1 = once")
    g.add_argument("--no-pace", action="store_true",
                   help="with --replay-file, deliver frames as fast as the "
                        "ring will take them instead of pacing them at "
                        "roughly the file's own gaps")

    g = pr.add_argument_group("receive (ERSPAN source)")
    g.add_argument("--receive-on", metavar="ADDR", default=None,
                   help="local address to receive ERSPAN on (default: 0.0.0.0)")
    g.add_argument("--session", type=int, default=None, metavar="N",
                   help="accept only this ERSPAN session ID; -1 for all (default: all)")
    g.add_argument("--from", dest="from_host", default=None, metavar="IP",
                   help="accept only mirrors from this source")
    g = pr.add_argument_group("serve")
    g.add_argument("--listen", type=int, default=None, metavar="PORT",
                   help="PCAP-over-IP port (default: %d)" % DEFAULT_PORT)
    g.add_argument("--bind", default=None, metavar="ADDR",
                   help="address to serve on (default: 127.0.0.1)")
    g.add_argument("--snaplen", type=int, default=None, metavar="N",
                   help="truncate frames sent to the client; 0 = whole frames")
    g = pr.add_argument_group("buffer")
    g.add_argument("--ring", type=int, default=None, metavar="N",
                   help="ring buffer depth in frames (default: 8192)")
    g.add_argument("--ring-mib", type=int, default=None, metavar="N",
                   help="ring buffer size in MiB (default: 64)")
    pr.add_argument("--save", action="store_true",
                    help="write these settings to the config file")
    pr.add_argument("--stats-interval", type=float, default=2.0, metavar="SEC",
                    help="seconds between progress lines, 0 to disable (default: 2)")
    pr.add_argument("-q", "--quiet", action="store_true", help="only print the summary")
    pr.set_defaults(func=cmd_run)

    pd = sub.add_parser("doctor", help="check privileges, the port and the config")
    pd.add_argument("--listen", type=int, default=None, metavar="PORT",
                    help="check this port instead of the configured one")
    pd.set_defaults(func=cmd_doctor)

    pc = sub.add_parser("config", help="show or reset the stored configuration")
    pc.add_argument("--reset", action="store_true", help="write the defaults back")
    pc.set_defaults(func=cmd_config)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except (ValueError, OSError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
