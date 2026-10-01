# SPDX-License-Identifier: GPL-2.0-or-later
"""Command line for spantap-sim."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
from typing import List, Optional

from . import __version__
from .config import (
    DEFAULT_SIM_DST,
    ConfigError,
    config_dir,
    delete_profile,
    list_profiles,
    load_profile,
)
from .controller import build_components
from .decode import DecodeError, decode_erspan2
from .exclusion import DEFAULT_PCAPOVERIP_PORT
from .encap import (
    EN_DOT1Q,
    EN_NONE,
    ENCAP_OVERHEAD,
    ErspanConfig,
    ErspanEncapsulator,
)
from .pacer import Pacer
from .runner import Runner
from .sources.filesrc import PcapFileSource
from .sources.live import (
    CaptureError,
    LiveSource,
    capture_tool_status,
    exclusion_filter,
    find_capture_tool,
)
from .sources.pcapread import (
    LINKTYPE_ETHERNET,
    open_packet_stream,
    write_pcap_header,
    write_pcap_packet,
)
from .sources.synth import SCENARIOS, SyntheticSource
from .stats import Stats
from .transport import (
    NullSender,
    PcapFileSender,
    RawSocketSender,
    guess_source_address,
    interface_mtu,
)


# --------------------------------------------------------------------------
# argument plumbing
# --------------------------------------------------------------------------

def add_erspan_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("ERSPAN")
    g.add_argument("--dst", default=DEFAULT_SIM_DST, metavar="IP",
                   help="ERSPAN receiver (destination of the GRE tunnel; "
                        "default: %(default)s, i.e. a gateway on this host)")
    g.add_argument("--src", metavar="IP", default=None,
                   help="source IP to put in the outer header (default: from the routing table)")
    g.add_argument("--session-id", type=int, default=1, metavar="N",
                   help="ERSPAN session ID, 0-1023 (default: 1)")
    g.add_argument("--vlan", type=int, default=0, metavar="N",
                   help="VLAN to report in the ERSPAN header, 0-4095 (sets En=2)")
    g.add_argument("--cos", type=int, default=0, metavar="N", help="class of service, 0-7")
    g.add_argument("--index", type=int, default=0, metavar="N",
                   help="ERSPAN port index, 0-1048575 (default: 0)")
    g.add_argument("--ttl", type=int, default=64, metavar="N", help="outer IP TTL (default: 64)")
    g.add_argument("--dscp", type=int, default=0, metavar="N", help="outer IP DSCP (default: 0)")
    g.add_argument("--no-df", action="store_true", help="clear the outer Don't-Fragment bit")
    g.add_argument("--mtu", type=int, default=1500, metavar="N",
                   help="path MTU; larger frames are truncated with the T bit set (default: 1500)")


def add_output_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("output")
    g.add_argument("--write-pcap", metavar="FILE",
                   help="write the ERSPAN packets to a pcap file instead of sending them "
                        "(no privileges needed)")
    g.add_argument("--dry-run", action="store_true",
                   help="encapsulate everything but transmit nothing")
    g.add_argument("--bind-iface", metavar="IF",
                   help="pin the raw socket to an interface (SO_BINDTODEVICE, Linux)")
    g.add_argument("--stats-interval", type=float, default=2.0, metavar="SEC",
                   help="seconds between progress lines, 0 to disable (default: 2)")
    g.add_argument("--protocol-stats", action="store_true",
                   help="classify the mirrored frames and print a protocol breakdown at the end")
    g.add_argument("-q", "--quiet", action="store_true", help="only print the final summary")


def add_rate_args(p: argparse.ArgumentParser, with_speed: bool = True) -> None:
    g = p.add_argument_group("rate")
    if with_speed:
        g.add_argument("--speed", type=float, default=1.0, metavar="X",
                       help="replay speed relative to the capture timestamps; "
                            "0 means as fast as possible (default: 1.0)")
    g.add_argument("--pps", type=float, default=0.0, metavar="N",
                   help="fixed packet rate; overrides --speed")


def build_config(args: argparse.Namespace) -> ErspanConfig:
    src = args.src or guess_source_address(args.dst)
    return ErspanConfig(
        dst=args.dst,
        src=src,
        session_id=args.session_id,
        vlan=args.vlan,
        cos=args.cos,
        en=EN_DOT1Q if args.vlan else EN_NONE,
        index=args.index,
        ttl=args.ttl,
        dscp=args.dscp,
        df=not args.no_df,
        mtu=args.mtu,
    )


def build_sender(args: argparse.Namespace):
    if args.dry_run:
        return NullSender()
    if args.write_pcap:
        return PcapFileSender(args.write_pcap)
    return RawSocketSender(args.dst, bind_iface=getattr(args, "bind_iface", None))


def run_with(args: argparse.Namespace, source) -> int:
    config = build_config(args)
    try:
        sender = build_sender(args)
    except PermissionError:
        sys.stderr.write(
            "error: sending raw GRE needs CAP_NET_RAW.\n"
            "       Run 'spantap-sim doctor' for how to grant it, or use --write-pcap "
            "to produce a file instead.\n"
        )
        return 13

    encapsulator = ErspanEncapsulator(config)
    pacer = Pacer(speed=getattr(args, "speed", 0.0), pps=args.pps)
    stats = Stats(
        interval=0.0 if args.quiet else args.stats_interval,
        classify_traffic=getattr(args, "protocol_stats", False),
    )

    if not args.quiet:
        sys.stderr.write("source : %s\n" % source.description)
        sys.stderr.write("output : %s\n" % sender.description)
        sys.stderr.write(
            "erspan : %s -> %s  session %d  vlan %d  mtu %d (max frame %d B)\n"
            % (config.src, config.dst, config.session_id, config.vlan,
               config.mtu, config.max_frame_len())
        )
        if hasattr(source, "bpf"):
            sys.stderr.write("filter : %s\n" % source.bpf)
        sys.stderr.write("\n")

    runner = Runner(source, encapsulator, sender, pacer, stats)
    runner.install_signal_handlers()
    try:
        with source, sender:
            runner.run()
    except CaptureError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        pass

    sys.stderr.write("\n%s\n" % stats.summary())
    for line in stats.protocol_lines():
        sys.stderr.write("%s\n" % line)
    return 0


# --------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------

def cmd_replay(args: argparse.Namespace) -> int:
    source = PcapFileSource(args.file, loop=args.loop, limit=args.count or None)
    return run_with(args, source)


def cmd_live(args: argparse.Namespace) -> int:
    src = args.src or guess_source_address(args.dst)
    if args.capture_cmd:
        sys.stderr.write(
            "warning: --capture-cmd replaces the capture command, so the "
            "self-exclusion filter below is NOT applied unless your command "
            "applies it itself.\n"
        )
    source = LiveSource(
        iface=args.iface,
        dst=args.dst,
        src=src,
        user_filter=args.filter,
        snaplen=args.snaplen,
        capture_cmd=args.capture_cmd.split() if args.capture_cmd else None,
        pcapoverip_port=args.pcapoverip_port,
        pcapoverip_host=args.pcapoverip_host,
        exclude_ssh=args.exclude_ssh,
    )
    return run_with(args, source)


def cmd_synth(args: argparse.Namespace) -> int:
    source = SyntheticSource(
        scenario=args.scenario,
        count=args.count,
        seed=args.seed,
        vlan=args.traffic_vlan or None,
        v6_ratio=args.v6_ratio,
    )
    return run_with(args, source)


def cmd_run(args: argparse.Namespace) -> int:
    """Run a saved profile — the same configuration the web UI writes."""
    try:
        profile = load_profile(args.name)
        source, encapsulator, sender, pacer, info = build_components(profile)
    except (ConfigError, CaptureError, PermissionError, OSError, ValueError) as exc:
        if isinstance(exc, PermissionError):
            sys.stderr.write(
                "error: sending raw GRE needs CAP_NET_RAW. Run 'spantap-sim doctor', "
                "or set the profile's output to a pcap file.\n"
            )
            return 13
        sys.stderr.write("error: %s\n" % exc)
        return 2

    stats = Stats(
        interval=0.0 if args.quiet else args.stats_interval,
        classify_traffic=not args.quiet,
    )
    if not args.quiet:
        sys.stderr.write("profile: %s\n" % args.name)
        sys.stderr.write("source : %s\n" % info["source_description"])
        sys.stderr.write("output : %s\n" % info["output_description"])
        if info.get("filter"):
            sys.stderr.write("filter : %s\n" % info["filter"])
        sys.stderr.write("\n")

    runner = Runner(source, encapsulator, sender, pacer, stats)
    runner.install_signal_handlers()
    try:
        with source, sender:
            runner.run()
    except CaptureError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        pass
    sys.stderr.write("\n%s\n" % stats.summary())
    for line in stats.protocol_lines():
        sys.stderr.write("%s\n" % line)
    return 0


def cmd_profiles(args: argparse.Namespace) -> int:
    if args.delete:
        try:
            delete_profile(args.delete)
        except ConfigError as exc:
            sys.stderr.write("error: %s\n" % exc)
            return 2
        print("deleted %s" % args.delete)
        return 0
    if args.show:
        try:
            print(json.dumps(load_profile(args.show), indent=2, sort_keys=True))
        except ConfigError as exc:
            sys.stderr.write("error: %s\n" % exc)
            return 2
        return 0
    names = list_profiles()
    if not names:
        print("no saved profiles yet (%s)" % config_dir())
        print("create one in the web UI: spantap-sim gui")
        return 0
    print("profiles in %s:" % config_dir())
    for name in names:
        try:
            p = load_profile(name)
            detail = "%s -> %s" % (p["source"], p["target"]["dst"] or "(no receiver)")
        except ConfigError as exc:
            detail = "unreadable: %s" % exc
        print("  %-24s %s" % (name, detail))
    return 0


def _read_new_password(name: str, from_stdin: bool) -> str:
    """Get a password without it landing in shell history or the process list.

    That is why there is no --password flag: an argument is visible in `ps`
    to every user on the box and lands in .bash_history. --password-stdin is
    the scripting route, and a prompt is the interactive one.
    """
    import getpass
    from .webui.accounts import AccountError, check_password

    if from_stdin:
        password = sys.stdin.readline().rstrip("\n")
        check_password(password, name)
        return password
    if not sys.stdin.isatty():
        raise AccountError(
            "no terminal to prompt on. Pipe the password in with "
            "--password-stdin instead.")
    while True:
        password = getpass.getpass("password for %s: " % name)
        try:
            check_password(password, name)
        except AccountError as exc:
            sys.stderr.write("  %s\n" % exc)
            continue
        if password != getpass.getpass("repeat: "):
            sys.stderr.write("  those did not match\n")
            continue
        return password


def cmd_users(args: argparse.Namespace) -> int:
    from .webui.accounts import (
        AccountError, add_user, list_users, remove_user, set_disabled,
        set_password, users_path,
    )
    import time as _time

    if args.action != "list" and not args.name:
        sys.stderr.write("error: which account? usage: spantap-sim users %s <name>\n"
                         % args.action)
        return 2
    try:
        if args.action == "list":
            users = list_users()
            if not users:
                print("no accounts yet (%s)" % users_path())
                print("the web UI falls back to the access token until you add one:")
                print("  spantap-sim users add <name>")
                return 0
            print("accounts in %s:" % users_path())
            for u in users:
                last = ("never" if not u["last_login"] else
                        _time.strftime("%Y-%m-%d %H:%M",
                                       _time.localtime(u["last_login"])))
                print("  %-24s %-9s last sign-in %s"
                      % (u["name"], "disabled" if u["disabled"] else "enabled", last))
            return 0

        if args.action == "add":
            password = _read_new_password(args.name, args.password_stdin)
            name = add_user(args.name, password)
            print("added %s" % name)
            print("sign in at the web UI; the access token still works too.")
            return 0

        if args.action == "passwd":
            password = _read_new_password(args.name, args.password_stdin)
            set_password(args.name, password)
            print("changed the password for %s" % args.name)
            print("note: any session opened with the old password is now closed,")
            print("      but only in a server that is running — this wrote the file.")
            return 0

        if args.action == "remove":
            remove_user(args.name)
            print("removed %s" % args.name)
            return 0

        if args.action in ("disable", "enable"):
            set_disabled(args.name, args.action == "disable")
            print("%sd %s" % (args.action, args.name))
            return 0
    except AccountError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("\ncancelled\n")
        return 130

    sys.stderr.write("error: unknown action %r\n" % args.action)
    return 2


def cmd_gui(args: argparse.Namespace) -> int:
    from .webui import serve
    return serve(
        bind=args.bind,
        port=args.port,
        open_browser=not args.no_open,
        token=args.token,
        verbose=args.verbose,
        allow_hosts=args.allow_host,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
    )


def cmd_decode(args: argparse.Namespace) -> int:
    """Read a capture of ERSPAN packets, verify it, optionally de-encapsulate.

    This is the smallest possible stand-in for the receiving half of the
    gateway, and it is what the simulator checks itself against.
    """
    extract_fh = None
    if args.extract:
        extract_fh = open(args.extract, "wb")
        write_pcap_header(extract_fh, LINKTYPE_ETHERNET)

    total = bad = 0
    expected_seq: Optional[int] = None
    gaps = 0
    try:
        with open(args.file, "rb") as fh:
            for pkt in open_packet_stream(fh):
                data = pkt.data
                if pkt.linktype == LINKTYPE_ETHERNET:
                    if len(data) < 14:
                        continue
                    ethertype = int.from_bytes(data[12:14], "big")
                    offset = 14
                    if ethertype == 0x8100:
                        ethertype = int.from_bytes(data[16:18], "big")
                        offset = 18
                    if ethertype != 0x0800:
                        continue
                    data = data[offset:]
                total += 1
                try:
                    dec = decode_erspan2(data)
                except DecodeError as exc:
                    bad += 1
                    if not args.quiet:
                        print("packet %d: %s" % (total, exc))
                    continue
                if expected_seq is not None and dec.seq != expected_seq:
                    gaps += 1
                    if not args.quiet:
                        print("packet %d: sequence jump %d -> %d"
                              % (total, expected_seq, dec.seq))
                expected_seq = (dec.seq + 1) & 0xFFFFFFFF
                if not args.quiet:
                    print("%6d  %s" % (total, dec.summary()))
                if extract_fh:
                    write_pcap_packet(extract_fh, pkt.ts_ns, dec.frame)
    finally:
        if extract_fh:
            extract_fh.close()

    print("\n%d packets, %d not ERSPAN Type II, %d sequence gaps" % (total, bad, gaps))
    if args.extract:
        print("mirrored frames written to %s" % args.extract)
    return 1 if bad else 0


def _check(label: str, ok: Optional[bool], detail: str = "") -> None:
    mark = {True: "ok  ", False: "FAIL", None: "warn"}[ok]
    print("  [%s] %-28s %s" % (mark, label, detail))


def cmd_token(args: argparse.Namespace) -> int:
    """Print the web UI's token, or every URL it can be opened at with it.

    Makes one (and saves it) if the UI will need one and has none yet — the
    same thing the UI does on its first start — so it works before the UI
    has ever run. That is how install.sh can show the address to open.
    """
    from .config import legacy_env, load_webui_or_default, new_webui_token
    from .webui.server import LOOPBACK, reachable_urls

    settings = load_webui_or_default()
    token = legacy_env("SPANTAP_TOKEN", "ERSPAN_SIM_TOKEN") or settings["token"]
    if not token and settings["bind"] not in LOOPBACK:
        token, saved = new_webui_token()
        if not saved:
            sys.stderr.write("error: could not save a new token in %s\n" % config_dir())
            return 2
    if not args.urls:
        if not token:
            sys.stderr.write("no token: the UI is bound to %s, which needs none\n"
                             % settings["bind"])
            return 1
        print(token)
        return 0
    scheme = "https" if settings["tls"]["cert"] else "http"
    for url in reachable_urls(settings["bind"], settings["port"], scheme,
                              token or None, settings["allow_hosts"]):
        print(url)
    return 0


def cmd_tls_import(args: argparse.Namespace) -> int:
    """Store a certificate and key for the web UI and switch it to HTTPS.

    Reads PEM text — the certificate (chain) and the private key, in one
    stream or from --cert/--key files — validates it exactly as the Settings
    tab's upload does, writes it into the same fixed slot in the config
    directory, and points the saved UI settings at it. This is what
    install.sh uses for its paste prompt; it takes effect the next time the
    UI starts.
    """
    from .config import load_webui_raw, save_webui
    from .webui.certs import CertUploadError, describe, save_uploaded, split_pem

    parts = []
    for path in (args.cert, args.key):
        if path:
            with open(path) as fh:
                parts.append(fh.read())
    if not args.cert:
        if sys.stdin.isatty():
            sys.stderr.write("paste the certificate and private key (PEM), "
                             "then Ctrl-D:\n")
        parts.insert(0, sys.stdin.read())
    try:
        cert_pem, key_pem = split_pem("\n".join(parts))
        stored = save_uploaded(cert_pem, key_pem)
        settings = load_webui_raw()
        settings["tls"] = {"cert": stored["cert"], "key": stored["key"]}
        # No bind test: the UI this configures may well be running right now
        # and holding its own port, which is not a reason to refuse. The
        # default bind is 0.0.0.0, so a first import also settles the token.
        save_webui(settings, check_bind=False, auto_token=True)
    except CertUploadError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except ConfigError as exc:
        sys.stderr.write("error: the certificate was stored, but the UI settings "
                         "could not be updated: %s\n" % exc)
        return 2

    info = describe(stored["cert"])
    names = (info.get("dns") or []) + (info.get("ips") or [])
    print("certificate stored: %s" % stored["cert"])
    print("  subject   %s" % (info.get("subject") or "-"))
    print("  issuer    %s%s" % (info.get("issuer") or "-",
                                "  (self-signed)" if info.get("self_signed") else ""))
    print("  valid to  %s%s" % (info.get("not_after") or "-",
                                "" if info.get("days_left") is None
                                else "  (%d days left)" % info["days_left"]))
    print("  names     %s" % (", ".join(names) or "-"))
    if info.get("days_left") is not None and info["days_left"] < 0:
        print("  WARNING: this certificate has already expired")
    print("the web UI will serve HTTPS with it from its next start")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    print("spantap-sim %s — environment check\n" % __version__)
    problems = 0

    print("python")
    _check("version", sys.version_info >= (3, 9), sys.version.split()[0])
    _check("platform", sys.platform.startswith("linux") or None, sys.platform +
           ("" if sys.platform.startswith("linux") else "  (Linux is the supported target)"))

    print("\nsending (needs CAP_NET_RAW)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        _check("raw socket", True, "can open AF_INET/SOCK_RAW")
    except PermissionError:
        problems += 1
        _check("raw socket", False, "permission denied")
        print("         grant it to this interpreter without running as root:")
        print("           sudo setcap cap_net_raw+ep %s" % os.path.realpath(sys.executable))
        print("         (use a venv's own python, not the system one), or run under sudo,")
        print("         or skip the wire entirely with --write-pcap FILE.")
    except OSError as exc:
        problems += 1
        _check("raw socket", False, str(exc))

    print("\ncapture (needed only for 'spantap-sim live')")
    tool, capture_problem = capture_tool_status()
    if not tool and capture_problem:
        _check("capture tool", None, capture_problem)
    if tool:
        _check("capture tool", True, tool)
        caps = shutil.which("getcap")
        if caps and tool.endswith("dumpcap"):
            try:
                out = subprocess.run([caps, tool], capture_output=True, text=True, timeout=5)
                detail = out.stdout.strip() or "no file capabilities set"
                _check("dumpcap capabilities", bool(out.stdout.strip()) or None, detail)
                if not out.stdout.strip():
                    print("         sudo setcap cap_net_raw,cap_net_admin+eip %s" % tool)
            except (OSError, subprocess.SubprocessError):
                pass

    print("\nconfiguration")
    from .config import check_writable, config_dir as _cfgdir
    cfg = _cfgdir()
    try:
        check_writable(cfg)
        _check("config directory", True, cfg)
        try:
            from .webui.accounts import list_users, users_path
            users = list_users()
            _check("accounts", True,
                   "%d (%s)" % (len(users), users_path()) if users
                   else "none — the web UI uses the access token")
        except Exception as exc:          # noqa: BLE001 — never fail doctor
            _check("accounts", None, str(exc))
    except ConfigError as exc:
        problems += 1
        # This one has bitten a real deployment: a config volume created by an
        # older image keeps its ownership, and every save fails afterwards.
        _check("config directory", False, str(exc))

    print("\ncapture uploads (the web UI's 'Capture file' source)")
    from .webui.uploads import list_captures, storage as _upload_storage
    st = _upload_storage()
    _check(
        "upload directory",
        st["writable"] or None,
        "%s%s" % (st["dir"], "" if st["exists"] else " (not created yet)")
        if st["writable"] else
        "%s is not writable by uid %d — uploads will be offered as disabled. "
        "Run 'make captures', or set SPANTAP_CAPTURE_DIR."
        % (st["dir"], os.getuid()),
    )
    if st["writable"]:
        stored = list_captures()
        unreadable = [c["name"] for c in stored if not c["readable"]]
        _check("stored captures", True, "%d file(s)" % len(stored))
        if unreadable:
            _check("unreadable captures", None,
                   "these are not valid captures: %s" % ", ".join(unreadable))

    print("\ninterfaces")
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            mtu = interface_mtu(name)
            _check(name, True, "mtu %s" % mtu)
    except OSError:
        _check("/sys/class/net", None, "not readable on this platform")

    if args.dst:
        print("\npath to %s" % args.dst)
        src = guess_source_address(args.dst)
        _check("source address", src != "0.0.0.0", src)
        print("  [    ] %-28s %s" % ("self-exclusion filter", exclusion_filter(args.dst, src)))
        print("  [    ] %-28s %d bytes of every frame"
              % ("encapsulation overhead", ENCAP_OVERHEAD))

    print("\n%s" % ("all good" if not problems else "%d problem(s) above" % problems))
    return 1 if problems else 0


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="spantap-sim",
        description="Mirror packets to an ERSPAN Type II receiver, "
                    "from a pcap file, a live interface or a traffic generator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  spantap-sim synth --dst 10.0.0.5 --count 200 --write-pcap /tmp/out.pcap
  spantap-sim replay capture.pcapng --dst 10.0.0.5 --speed 2
  spantap-sim live --iface eth0 --dst 10.0.0.5 --filter "not port 22"
  spantap-sim decode /tmp/out.pcap --extract /tmp/inner.pcap
  spantap-sim doctor --dst 10.0.0.5
""",
    )
    p.add_argument("--version", action="version", version="spantap-sim " + __version__)
    sub = p.add_subparsers(dest="command", required=True)

    pr = sub.add_parser("replay", help="replay a pcap/pcapng file as ERSPAN")
    pr.add_argument("file", help="capture to replay (.pcap or .pcapng)")
    pr.add_argument("--loop", type=int, default=1, metavar="N",
                    help="number of passes; 0 loops forever (default: 1)")
    pr.add_argument("--count", type=int, default=0, metavar="N",
                    help="stop after N packets (default: whole file)")
    add_rate_args(pr)
    add_erspan_args(pr)
    add_output_args(pr)
    pr.set_defaults(func=cmd_replay)

    pl = sub.add_parser("live", help="mirror a live interface as ERSPAN")
    pl.add_argument("--iface", "-i", required=True, help="interface to capture from")
    pl.add_argument("--filter", "-f", default=None, metavar="BPF",
                    help="extra capture filter; the self-exclusion filter is always ANDed on")
    pl.add_argument("--snaplen", type=int, default=0, metavar="N",
                    help="capture snap length (default: full frames)")
    pl.add_argument("--capture-cmd", default=None, metavar="CMD",
                    help="override the capture command entirely (must write pcap to stdout)")
    pl.add_argument("--pcapoverip-port", type=int, default=DEFAULT_PCAPOVERIP_PORT, metavar="N",
                    help="port the PCAP-over-IP gateway serves Wireshark on; its session is "
                         "always excluded from the capture (default: %d, 0 disables the clause)"
                         % DEFAULT_PCAPOVERIP_PORT)
    pl.add_argument("--pcapoverip-host", default=None, metavar="IP",
                    help="narrow that exclusion to one gateway host")
    pl.add_argument("--exclude-ssh", action="store_true",
                    help="also keep your own SSH session out of the mirror")
    add_rate_args(pl, with_speed=False)
    add_erspan_args(pl)
    add_output_args(pl)
    pl.set_defaults(func=cmd_live, speed=0.0)

    ps = sub.add_parser("synth", help="generate synthetic traffic and mirror it")
    ps.add_argument("--scenario", choices=SCENARIOS, default="mixed",
                    help="traffic pattern to generate (default: mixed)")
    ps.add_argument("--count", type=int, default=0, metavar="N",
                    help="stop after N packets; 0 runs until interrupted")
    ps.add_argument("--seed", type=int, default=0, metavar="N",
                    help="RNG seed, for reproducible output")
    ps.add_argument("--v6-ratio", type=float, default=0.25, metavar="F",
                    help="fraction of flows that are IPv6 (default: 0.25)")
    ps.add_argument("--traffic-vlan", type=int, default=0, metavar="N",
                    help="802.1Q tag to put on the generated frames themselves "
                         "(--vlan sets the VLAN reported in the ERSPAN header)")
    add_rate_args(ps, with_speed=False)
    add_erspan_args(ps)
    add_output_args(ps)
    ps.set_defaults(func=cmd_synth, speed=0.0)

    pd = sub.add_parser("decode", help="verify / de-encapsulate a capture of ERSPAN packets")
    pd.add_argument("file", help="capture containing ERSPAN packets")
    pd.add_argument("--extract", metavar="FILE",
                    help="write the mirrored frames to this pcap (Ethernet)")
    pd.add_argument("-q", "--quiet", action="store_true", help="only print the summary")
    pd.set_defaults(func=cmd_decode)

    pg = sub.add_parser("gui", help="open the configuration and monitoring web UI")
    pg.add_argument("--port", type=int, default=None, metavar="N",
                    help="listen port (default: as saved in the UI, else 8420)")
    pg.add_argument("--bind", default=None, metavar="ADDR",
                    help="listen address (default: as saved in the UI, else 0.0.0.0; "
                         "anything but 127.0.0.1 requires a token, generated and saved "
                         "if none is set). A flag always overrides the "
                         "saved settings, which is how you get back in if they lock you out")
    pg.add_argument("--token", default=None, metavar="T",
                    help="require this token; generated automatically when not on "
                         "loopback (or set SPANTAP_TOKEN)")
    pg.add_argument("--allow-host", action="append", default=[], metavar="NAME",
                    help="also answer to this hostname or address — needed to reach "
                         "the UI by a DNS name; repeatable (or set "
                         "SPANTAP_ALLOW_HOSTS as a comma-separated list)")
    pg.add_argument("--tls-cert", default=None, metavar="FILE",
                    help="serve HTTPS with this certificate (PEM)")
    pg.add_argument("--tls-key", default=None, metavar="FILE",
                    help="private key for --tls-cert (default: the same file)")
    pg.add_argument("--no-open", action="store_true", help="do not open a browser")
    pg.add_argument("-v", "--verbose", action="store_true", help="log every request")
    pg.set_defaults(func=cmd_gui)

    prun = sub.add_parser("run", help="run a saved profile")
    prun.add_argument("name", help="profile name (see 'spantap-sim profiles')")
    prun.add_argument("--stats-interval", type=float, default=2.0, metavar="SEC",
                      help="seconds between progress lines, 0 to disable (default: 2)")
    prun.add_argument("-q", "--quiet", action="store_true", help="only print the final summary")
    prun.set_defaults(func=cmd_run)

    pp = sub.add_parser("profiles", help="list, show or delete saved profiles")
    pp.add_argument("--show", metavar="NAME", help="print one profile as JSON")
    pp.add_argument("--delete", metavar="NAME", help="delete a profile")
    pp.set_defaults(func=cmd_profiles)

    pu = sub.add_parser(
        "users",
        help="manage web UI accounts (the access token keeps working alongside)")
    pu.add_argument("action",
                    choices=["list", "add", "passwd", "remove", "disable", "enable"])
    pu.add_argument("name", nargs="?", default="",
                    help="the account to act on (not needed for 'list')")
    pu.add_argument("--password-stdin", action="store_true",
                    help="read the password from stdin instead of prompting, so it "
                         "never appears in ps output or shell history")
    pu.set_defaults(func=cmd_users)

    ptok = sub.add_parser(
        "token", help="print the web UI's access token (made and saved if needed)")
    ptok.add_argument("--urls", action="store_true",
                      help="print every URL the UI can be opened at, token included")
    ptok.set_defaults(func=cmd_token)

    pt = sub.add_parser("tls", help="set the web UI's TLS certificate")
    tsub = pt.add_subparsers(dest="tls_command", required=True)
    pti = tsub.add_parser(
        "import", help="store a certificate and key and switch the UI to HTTPS",
        description="Read a PEM certificate (chain) and private key — from "
                    "stdin, in one stream, or from --cert/--key — validate "
                    "them, and make them the web UI's certificate.")
    pti.add_argument("--cert", metavar="FILE",
                     help="certificate file (may also contain the key); default: stdin")
    pti.add_argument("--key", metavar="FILE",
                     help="private key file, if not in --cert or stdin")
    pti.set_defaults(func=cmd_tls_import)

    pdoc = sub.add_parser("doctor", help="check privileges, tooling and interfaces")
    pdoc.add_argument("--dst", default=None, metavar="IP",
                      help="also check the path to this receiver")
    pdoc.set_defaults(func=cmd_doctor)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError, CaptureError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
