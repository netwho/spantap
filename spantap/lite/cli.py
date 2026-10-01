# SPDX-License-Identifier: GPL-2.0-or-later
"""Command line for spantap-lite: exactly three subcommands.

    spantap-lite configure     interactive setup wizard (also runnable with
                                flags and --non-interactive, for scripted
                                installs)
    spantap-lite start         run in the foreground, printing basic stats
    spantap-lite stop          stop a running instance, from anywhere

``start`` runs in the foreground rather than forking itself into the
background, on purpose: that is what a systemd ``Type=simple`` unit wants,
and it is also exactly what running it yourself with a trailing ``&`` (or
under ``nohup``, or ``tmux``) achieves without this tool having to implement
double-fork daemonisation. Either way, ``start`` writes its own PID to
``lite.pid`` in the config directory and installs signal handlers, and
``stop`` reads that file and sends SIGTERM -- the same two steps regardless
of who is managing the process, and it removes the file itself on the way
out.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from typing import List, Optional

from .. import __version__
from ..gateway.cli import _fmt_bytes
from .config import (
    ConfigError,
    DEFAULT_SAVE_MAX_MIB,
    build_noninteractive_config,
    check_writable,
    lite_path,
    load_lite_or_default,
    pid_path,
    run_configure_wizard,
    save_lite,
)
from ..config import in_container
from ..exclusion import DEFAULT_PCAPOVERIP_PORT
from .service import STATE_ERROR, STATE_RUNNING, LiteService

# --------------------------------------------------------------------------
# the pid file
# --------------------------------------------------------------------------

def _read_pid() -> Optional[int]:
    try:
        with open(pid_path()) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True     # exists, just owned by someone else
    return True


def _write_pid() -> None:
    check_writable(os.path.dirname(pid_path()))
    with open(pid_path(), "w") as fh:
        fh.write("%d\n" % os.getpid())


def _remove_pid() -> None:
    try:
        os.unlink(pid_path())
    except OSError:
        pass


# --------------------------------------------------------------------------
# configure
# --------------------------------------------------------------------------

def cmd_configure(args: argparse.Namespace) -> int:
    current = None if args.reset else load_lite_or_default()
    # Any override flag is a scripted-intent signal on its own, whether or not
    # --non-interactive was also passed: 'configure --iface eth0' from a shell
    # with a TTY attached (docker compose run, an installer's own terminal)
    # should apply --iface, not silently ignore it and launch the wizard.
    flags_given = any([
        args.iface, args.replay_file, args.bind, args.listen is not None,
        args.save_file, args.save_max_mib is not None, args.no_save,
        args.exclude_self is not None, args.filter is not None,
    ])
    interactive = not args.non_interactive and not flags_given and sys.stdin.isatty()
    try:
        if interactive:
            cfg = run_configure_wizard(current)
        else:
            cfg = build_noninteractive_config(
                current=current,
                iface=args.iface,
                replay_file=args.replay_file,
                bind=args.bind,
                port=args.listen,
                save_path=args.save_file,
                save_max_mib=args.save_max_mib,
                no_save=args.no_save,
                exclude_self=args.exclude_self,
                custom_filter=args.filter,
            )
    except ConfigError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except (KeyboardInterrupt, EOFError):
        sys.stderr.write("\ncancelled\n")
        return 130

    try:
        cfg = save_lite(cfg)
    except ConfigError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2

    print("\nsaved: %s" % lite_path())
    print("  source : %s" % (cfg["live"]["iface"] if cfg["source"] == "live"
                             else cfg["replay"]["file"]))
    print("  serve  : tcp/%d on %s" % (cfg["serve"]["port"], cfg["serve"]["bind"]))
    if cfg["save"]["enabled"]:
        print("  save   : %s (up to %d MiB)" % (cfg["save"]["path"], cfg["save"]["max_mib"]))
    if in_container():
        # Run as 'docker compose run --rm lite configure': the long-running
        # service is a different container, started or restarted from the host.
        print("\nstart it from the host:  docker compose --profile lite up -d lite\n"
              "(already running? docker compose --profile lite restart lite)")
    else:
        print("\nrun 'spantap-lite start' when ready.")
    return 0


# --------------------------------------------------------------------------
# start
# --------------------------------------------------------------------------

def cmd_start(args: argparse.Namespace) -> int:
    existing = _read_pid()
    if existing is not None:
        if _pid_alive(existing):
            sys.stderr.write(
                "error: spantap-lite is already running (pid %d) -- "
                "use 'spantap-lite stop' first\n" % existing)
            return 1
        _remove_pid()   # stale, from an unclean exit

    try:
        config = load_lite_or_default()
    except ConfigError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2

    unconfigured = (
        (config["source"] == "live" and not config["live"]["iface"])
        or (config["source"] == "replay" and not config["replay"]["file"])
    )
    if unconfigured:
        sys.stderr.write("error: not configured yet -- run 'spantap-lite configure' first\n")
        return 2

    service = LiteService()
    try:
        service.start(config)
    except ConfigError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write("error: %s\n" % exc)
        if isinstance(exc, PermissionError) or "CAP_NET_RAW" in str(exc):
            sys.stderr.write("       grant CAP_NET_RAW to this interpreter "
                             "(the installer does this for you)\n")
            return 13
        return 2

    try:
        _write_pid()
    except ConfigError as exc:
        service.stop(timeout=1.0)
        sys.stderr.write("error: %s\n" % exc)
        return 2

    snap = service.snapshot()
    rx, srv = snap["receiver"], snap["server"]
    if not args.quiet:
        sys.stderr.write("spantap-lite %s (pid %d)\n\n" % (__version__, os.getpid()))
        sys.stderr.write("  source  : %s\n" % rx["description"])
        if rx.get("filter"):
            sys.stderr.write("  filter  : %s\n" % rx["filter"])
        sys.stderr.write("  serve   : tcp/%d on %s, one client at a time\n"
                         % (srv["port"], srv["bind"]))
        if snap["save"]:
            sys.stderr.write("  save    : %s (up to %s)\n"
                             % (snap["save"]["path"], _fmt_bytes(snap["save"]["max_bytes"])))
        sys.stderr.write("\n  connect Wireshark with:\n    %s\n\n" % srv["hint"])
        sys.stderr.write("  Ctrl-C, or 'spantap-lite stop' from elsewhere, to stop.\n\n")

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
            snap = service.snapshot()
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
                    "  %9d packets  %7.0f/s  dropped %d  ring %3.0f%%  %s\n"
                    % (r["received"], pps, ring["dropped"], 100 * ring["fill"],
                       "-> %s connected" % s["peer"] if s["connected"]
                       else "(no client connected)")
                )
                sys.stderr.flush()
    finally:
        service.stop()
        _remove_pid()

    snap = service.snapshot()
    r, ring, s = snap["receiver"], snap["ring"], snap["server"]
    sys.stderr.write(
        "\n%d packets captured (%s), %d dropped by the ring, "
        "%d served to %d client(s), %d connections refused\n"
        % (r["received"], _fmt_bytes(r["bytes"]), ring["dropped"],
           s["frames_sent"], s["clients_served"], s["refused"])
    )
    if snap["save"]:
        sv = snap["save"]
        sys.stderr.write(
            "%d packets written to %s (%s%s)\n"
            % (sv["frames_written"], sv["path"], _fmt_bytes(sv["bytes"]),
               ", cap reached" if sv["capped"] else "")
        )
    return 0 if snap["state"] != STATE_ERROR else 1


# --------------------------------------------------------------------------
# stop
# --------------------------------------------------------------------------

def cmd_stop(args: argparse.Namespace) -> int:
    pid = _read_pid()
    if pid is None:
        print("not running (no pid file at %s)" % pid_path())
        return 0
    if not _pid_alive(pid):
        _remove_pid()
        print("not running (stale pid file removed)")
        return 0

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        _remove_pid()
        print("not running (stale pid file removed)")
        return 0
    except PermissionError:
        sys.stderr.write("error: no permission to signal pid %d\n" % pid)
        return 1

    deadline = time.time() + max(0.0, args.timeout)
    while time.time() < deadline:
        if not _pid_alive(pid):
            print("stopped (pid %d)" % pid)
            return 0
        time.sleep(0.2)
    sys.stderr.write("error: pid %d did not stop within %.0fs\n" % (pid, args.timeout))
    return 1


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="spantap-lite",
        description="A bare capture-to-PCAP-over-IP tap: no web UI, no "
                    "accounts, no simulator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  spantap-lite configure
  spantap-lite start
  spantap-lite stop
  wireshark -k -i TCP@<this host>:%d
""" % DEFAULT_PCAPOVERIP_PORT,
    )
    p.add_argument("--version", action="version", version="spantap-lite " + __version__)
    sub = p.add_subparsers(dest="command", required=True)

    pc = sub.add_parser("configure", help="interactively set up (or change) spantap-lite")
    pc.add_argument("--non-interactive", action="store_true",
                    help="apply the flags below without prompting -- for scripted installs")
    pc.add_argument("--reset", action="store_true",
                    help="start from the built-in defaults instead of the current configuration")
    pc.add_argument("--iface", metavar="IF", default=None, help="source interface to capture")
    pc.add_argument("--replay-file", metavar="PATH", default=None,
                    help="replay this stored capture instead of a live interface")
    pc.add_argument("--bind", metavar="ADDR", default=None,
                    help="PCAP-over-IP bind address (default: 0.0.0.0)")
    pc.add_argument("--listen", type=int, metavar="PORT", default=None,
                    help="PCAP-over-IP port (default: %d)" % DEFAULT_PCAPOVERIP_PORT)
    pc.add_argument("--save-file", metavar="PATH", default=None,
                    help="also save captured frames to this local pcap file")
    pc.add_argument("--save-max-mib", type=int, metavar="N", default=None,
                    help="cap the local file at this size (default: %d)" % DEFAULT_SAVE_MAX_MIB)
    pc.add_argument("--no-save", action="store_true", help="do not save to a local file")
    excl = pc.add_mutually_exclusive_group()
    excl.add_argument("--exclude-ssh", dest="exclude_self", action="store_true", default=None,
                      help="also exclude your own tcp/22 from the capture (default: yes)")
    excl.add_argument("--no-exclude-ssh", dest="exclude_self", action="store_false",
                      help="do not exclude tcp/22 (this tool's own PCAP-over-IP traffic "
                           "is always excluded regardless)")
    pc.add_argument("--filter", metavar="BPF", default=None,
                    help="extra capture filter, ANDed after the mandatory exclusions "
                         "(default: none)")
    pc.set_defaults(func=cmd_configure)

    ps = sub.add_parser("start", help="run in the foreground until stopped")
    ps.add_argument("--stats-interval", type=float, default=2.0, metavar="SEC",
                    help="seconds between progress lines, 0 to disable (default: 2)")
    ps.add_argument("-q", "--quiet", action="store_true", help="only print the summary")
    ps.set_defaults(func=cmd_start)

    pp = sub.add_parser("stop", help="stop a running spantap-lite, from anywhere")
    pp.add_argument("--timeout", type=float, default=10.0, metavar="SEC",
                    help="how long to wait for it to stop (default: 10)")
    pp.set_defaults(func=cmd_stop)

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
