# SPDX-License-Identifier: GPL-2.0-or-later
"""spantap-lite's own configuration: one JSON file, one interactive wizard.

    $XDG_CONFIG_HOME/spantap/lite.json      settings (same dir as gateway.json;
                                             a distinct file, since spantap-lite
                                             deliberately has no ERSPAN-receiving
                                             option and the two schemas would
                                             otherwise have to keep pretending
                                             to share fields they don't)
    $XDG_CONFIG_HOME/spantap/lite.pid       the running process's PID, written
                                             by ``start`` and removed by it on
                                             a clean exit; ``stop`` reads it

Validation follows :mod:`spantap.config`'s own gateway schema closely, and
reuses its private helpers directly (``_text``, ``_ipv4``, ``_num``,
``_check_pcap_path``, ``_write_json``) rather than re-implementing the same
checks slightly differently — this is one package talking to itself, not a
public API boundary.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, Optional

from ..config import (  # noqa: F401 -- re-exported for callers that only import config
    ConfigError,
    _check_pcap_path,
    _ipv4,
    _num,
    _text,
    _write_json,
    check_writable,
    config_dir,
    legacy_env,
)
from ..exclusion import DEFAULT_PCAPOVERIP_PORT


def capture_dir() -> str:
    """The shared capture store — ./captures on the host in Docker. The same
    rule as the web UI's, without importing the web UI into spantap-lite."""
    return legacy_env("SPANTAP_CAPTURE_DIR", "ERSPAN_SIM_CAPTURE_DIR") or os.path.join(
        os.path.expanduser("~"), "captures")


def _stored_captures() -> list:
    try:
        return sorted(n for n in os.listdir(capture_dir())
                      if n.lower().endswith((".pcap", ".pcapng", ".cap"))
                      and os.path.isfile(os.path.join(capture_dir(), n)))
    except OSError:
        return []

SOURCES = ("live", "replay")

#: Walter's spec: "max pcap size 500mb" as the default cap for the optional
#: local save-to-file feature.
DEFAULT_SAVE_MAX_MIB = 500


def lite_path() -> str:
    return os.path.join(config_dir(), "lite.json")


def pid_path() -> str:
    return os.path.join(config_dir(), "lite.pid")


def default_lite_config() -> Dict:
    return {
        # Which of the two feeds the ring. "live" mirrors an interface;
        # "replay" plays back an existing capture file, for trying the tool
        # (or reproducing something) with no interface at hand — same choice
        # Walter's spec makes with "source interface and optionally a pcap
        # file (existing file)".
        "source": "live",
        "live": {
            "iface": "",
        },
        "replay": {
            "file": "",
        },
        "serve": {
            # Unlike spantap-gw, which defaults to loopback because it is
            # normally driven from the local web UI, spantap-lite has no UI
            # to tunnel through — binding every interface by default is what
            # "install this on a box and reach it from elsewhere" needs.
            "bind": "0.0.0.0",
            "port": DEFAULT_PCAPOVERIP_PORT,
        },
        # One combined switch, matching how it is actually asked: "filter out
        # its own traffic pcapoverip and ssh (default yes)". The PCAP-over-IP
        # exclusion is mandatory in build_gateway_plan() regardless of this
        # value (there is no way to turn off the one clause that stops the
        # feedback loop) -- what this actually toggles is the SSH clause.
        "exclude_self": True,
        "filter": {
            "custom": "",       # ANDed in last; default empty ("no")
        },
        "save": {
            "enabled": False,
            "path": "",
            "max_mib": DEFAULT_SAVE_MAX_MIB,
        },
        "buffer": {
            "max_frames": 8192,
            "max_mib": 64,
        },
    }


def validate_lite(config: Dict) -> Dict:
    if not isinstance(config, dict):
        raise ConfigError("the spantap-lite configuration must be an object")
    out = default_lite_config()
    for section, value in config.items():
        if section not in out:
            continue          # unknown keys drop, so an older file still loads
        if isinstance(out[section], dict):
            if not isinstance(value, dict):
                raise ConfigError("%s must be an object" % section)
            out[section].update(value)
        else:
            out[section] = value

    if out["source"] not in SOURCES:
        raise ConfigError("source must be one of %s (got %r)"
                          % (", ".join(SOURCES), out["source"]))

    live = out["live"]
    live["iface"] = _text(live.get("iface"), "live.iface")
    if live["iface"] and not re.match(r"^[A-Za-z0-9._:@-]{1,15}$", live["iface"]):
        raise ConfigError("live.iface is not a valid interface name: %r" % live["iface"])

    replay = out["replay"]
    replay["file"] = _text(replay.get("file"), "replay.file")

    if out["source"] == "live" and not live["iface"]:
        raise ConfigError("live.iface is required when the source is an interface")
    if out["source"] == "replay":
        if not replay["file"]:
            raise ConfigError("replay.file is required when the source is a capture file")
        if not os.path.isfile(replay["file"]):
            raise ConfigError("replay.file does not exist: %s" % replay["file"])

    srv = out["serve"]
    srv["bind"] = _ipv4(srv.get("bind") or "0.0.0.0", "serve.bind")
    srv["port"] = _num("serve", "port", srv.get("port", DEFAULT_PCAPOVERIP_PORT), 0, 65535)

    out["exclude_self"] = bool(out.get("exclude_self", True))

    filt = out["filter"]
    filt["custom"] = _text(filt.get("custom"), "filter.custom")

    save = out["save"]
    save["enabled"] = bool(save.get("enabled", False))
    save["path"] = _check_pcap_path(_text(save.get("path"), "save.path"))
    save["max_mib"] = _num("save", "max_mib", save.get("max_mib", DEFAULT_SAVE_MAX_MIB), 1, 100_000)
    if save["enabled"] and not save["path"]:
        raise ConfigError("save.path is required when saving to a local file is enabled")

    buf = out["buffer"]
    buf["max_frames"] = _num("buffer", "max_frames", buf.get("max_frames", 8192), 64, 1_000_000)
    buf["max_mib"] = _num("buffer", "max_mib", buf.get("max_mib", 64), 1, 4096)

    return out


def load_lite() -> Dict:
    path = lite_path()
    try:
        with open(path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return default_lite_config()
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError("spantap-lite configuration is unusable: %s" % exc)
    try:
        return validate_lite(data)
    except ConfigError:
        raise
    except Exception as exc:  # noqa: BLE001 -- a bad file must not break startup
        raise ConfigError("spantap-lite configuration is unusable: %s: %s"
                          % (type(exc).__name__, exc))


def load_lite_or_default() -> Dict:
    try:
        return load_lite()
    except Exception:  # noqa: BLE001
        return default_lite_config()


def save_lite(config: Dict) -> Dict:
    clean = validate_lite(config)
    _write_json(lite_path(), clean)
    return clean


# --------------------------------------------------------------------------
# the interactive wizard
# --------------------------------------------------------------------------

def _ask(prompt: str, default: str = "") -> str:
    suffix = " [%s]" % default if default else ""
    try:
        answer = input("%s%s: " % (prompt, suffix)).strip()
    except EOFError:
        answer = ""
    return answer or default


def _ask_yn(prompt: str, default: bool = True) -> bool:
    suffix = " [Y/n]" if default else " [y/N]"
    try:
        answer = input("%s%s: " % (prompt, suffix)).strip().lower()
    except EOFError:
        answer = ""
    if not answer:
        return default
    return answer[0] == "y"


def run_configure_wizard(current: Optional[Dict] = None,
                         list_interfaces=None) -> Dict:
    """Interactively build a config, starting from *current* (or the default).

    ``list_interfaces`` is injectable for tests; in real use it is
    :func:`spantap.interfaces.list_interfaces`, called lazily so importing
    this module never requires /sys to exist.

    *current* is used as a starting point as-is, not validated first: an
    unconfigured default (no interface set yet) is exactly what this wizard
    exists to fill in, so requiring it to already be valid would make a
    first-time configure impossible. Everything is validated once, at the
    end, after the wizard's answers are folded in.
    """
    cfg = json.loads(json.dumps(current)) if current else default_lite_config()

    print("spantap-lite setup\n"
          "-------------------\n"
          "A bare capture-to-PCAP-over-IP tap: no web UI, no accounts, "
          "no simulator.\n")

    print("Source: capture from a live interface, or replay a stored pcap file.")
    if list_interfaces is None:
        from ..interfaces import list_interfaces as list_interfaces  # noqa: PLC0414
    try:
        ifaces = [i for i in list_interfaces() if not i["loopback"]]
    except Exception:  # noqa: BLE001 -- listing is a convenience, not a requirement
        ifaces = []
    if ifaces:
        print("  available interfaces:")
        for i in ifaces:
            addr = i["ipv4"] or (i["ipv6"][0] if i["ipv6"] else "no address")
            print("    %-10s %-6s %s" % (i["name"], i["state"], addr))

    stored = _stored_captures()
    if stored:
        print("\nCapture files in %s (in Docker: ./captures on the host):" % capture_dir())
        for name in stored:
            print("    %s" % name)
    pcap_file = _ask("Existing pcap file to replay instead of a live interface "
                     "(a name from the list above, or a full path; leave blank "
                     "to capture live)",
                     cfg["replay"]["file"] if cfg["source"] == "replay" else "")
    if pcap_file and not os.path.isabs(pcap_file) and pcap_file in stored:
        pcap_file = os.path.join(capture_dir(), pcap_file)
    if pcap_file:
        if not os.path.isfile(pcap_file):
            print("  warning: %s does not exist yet -- fix this before 'start'" % pcap_file)
        cfg["source"] = "replay"
        cfg["replay"]["file"] = pcap_file
    else:
        default_iface = cfg["live"]["iface"] or (ifaces[0]["name"] if ifaces else "")
        iface = _ask("Source interface to capture", default_iface)
        if not iface:
            raise ConfigError("an interface (or a replay file) is required")
        cfg["source"] = "live"
        cfg["live"]["iface"] = iface

    print("\nPCAP-over-IP service (what Wireshark connects to):")
    cfg["serve"]["bind"] = _ask("  bind address (0.0.0.0 for every interface)",
                                cfg["serve"]["bind"])
    port = _ask("  port", str(cfg["serve"]["port"]))
    try:
        cfg["serve"]["port"] = int(port)
    except ValueError:
        raise ConfigError("port must be a number (got %r)" % port)

    print("\nOptionally also save what is captured to a local pcap file.")
    save_enabled = _ask_yn("  save to a local file as well?", cfg["save"]["enabled"])
    cfg["save"]["enabled"] = save_enabled
    if save_enabled:
        cfg["save"]["path"] = _ask("  file path (.pcap or .pcapng)",
                                   cfg["save"]["path"]
                                   or os.path.join(capture_dir(), "lite.pcap"))
        max_mib = _ask("  maximum size in MiB before it stops growing",
                       str(cfg["save"]["max_mib"]))
        try:
            cfg["save"]["max_mib"] = int(max_mib)
        except ValueError:
            raise ConfigError("max size must be a number (got %r)" % max_mib)

    print("\nThis tool's own PCAP-over-IP traffic is always excluded from the "
          "capture -- otherwise it would capture what it just sent, and that "
          "loop saturates the link in seconds.")
    cfg["exclude_self"] = _ask_yn(
        "  also exclude your own SSH session (tcp/22) from the capture?",
        cfg["exclude_self"])

    custom = _ask_yn("\nAdd a custom BPF filter on top of the exclusions above?", False)
    if custom:
        cfg["filter"]["custom"] = _ask("  BPF expression", cfg["filter"]["custom"])
    else:
        cfg["filter"]["custom"] = ""

    return validate_lite(cfg)


def build_noninteractive_config(*, current: Optional[Dict] = None, iface: Optional[str] = None,
                                replay_file: Optional[str] = None, bind: Optional[str] = None,
                                port: Optional[int] = None, save_path: Optional[str] = None,
                                save_max_mib: Optional[int] = None, no_save: bool = False,
                                exclude_self: Optional[bool] = None,
                                custom_filter: Optional[str] = None) -> Dict:
    """Apply flag overrides without prompting -- for scripted installs
    (``install.sh --lite --yes``) and for tests. Anything left unset keeps
    *current*'s value, or the default.

    As in :func:`run_configure_wizard`, *current* is taken as-is rather than
    validated first, since an unconfigured default is a legitimate starting
    point here too; the result is validated once, after the overrides above
    are applied.
    """
    cfg = json.loads(json.dumps(current)) if current else default_lite_config()
    if replay_file:
        # A bare name means a file in the capture store (./captures in Docker).
        if (not os.path.isabs(replay_file) and not os.path.isfile(replay_file)
                and os.path.isfile(os.path.join(capture_dir(), replay_file))):
            replay_file = os.path.join(capture_dir(), replay_file)
        cfg["source"] = "replay"
        cfg["replay"]["file"] = replay_file
    elif iface:
        cfg["source"] = "live"
        cfg["live"]["iface"] = iface
    if bind is not None:
        cfg["serve"]["bind"] = bind
    if port is not None:
        cfg["serve"]["port"] = port
    if no_save:
        cfg["save"]["enabled"] = False
    elif save_path is not None:
        cfg["save"]["enabled"] = True
        cfg["save"]["path"] = save_path
    if save_max_mib is not None:
        cfg["save"]["max_mib"] = save_max_mib
    if exclude_self is not None:
        cfg["exclude_self"] = exclude_self
    if custom_filter is not None:
        cfg["filter"]["custom"] = custom_filter
    return validate_lite(cfg)
