# SPDX-License-Identifier: GPL-2.0-or-later
"""Named, persistent profiles.

A profile is one complete simulator setup — source, ERSPAN target, exclusions,
output — saved by name so you can keep a lab receiver, a classroom demo and a
real sensor side by side and switch in one click. Both the web UI and the CLI
(``--profile NAME``) read the same files.

    $XDG_CONFIG_HOME/spantap/             (default ~/.config/spantap)
        profiles/<name>.json
        state.json                        {"last_used": "<name>"}

Through 0.4.x this directory was named erspan-sim. :func:`_migrate_legacy_dir`
adopts it in place the first time this build runs somewhere it finds one, so
the rename does not look, to someone upgrading, like every profile and
account vanished.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import tempfile
from typing import Dict, List, Optional, Tuple

from .exclusion import DEFAULT_PCAPOVERIP_PORT

DEFAULT_SIM_DST = "127.0.0.1"   # the simulator's receiver unless told otherwise
from .sources.synth import SCENARIOS

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")

SOURCES = ("synth", "replay", "live")
OUTPUT_MODES = ("wire", "pcap", "dry")


class ConfigError(ValueError):
    pass


def legacy_env(new: str, old: str) -> Optional[str]:
    """Read *new*, falling back to the pre-rename variable *old*.

    Only ``SPANTAP_CONFIG_DIR`` needs the directory-migration dance above —
    everything else that used to start ``ERSPAN_SIM_`` (the auth token, the
    allowed-hosts list, the capture directory, the upload size cap) is a
    plain value with nothing to move, so honouring whichever name is set is
    enough: an old-named .env or systemd unit nobody has edited yet keeps
    working, without a second thing to remember when upgrading.
    """
    return os.environ.get(new) or os.environ.get(old)


# --------------------------------------------------------------------------
# locations
# --------------------------------------------------------------------------

def _migrate_legacy_dir(new_dir: str) -> None:
    """Adopt a pre-rename config directory in place, once.

    0.4.x and earlier stored everything — profiles, accounts, the gateway's
    own settings — under a directory named erspan-sim. Renaming the project
    must not make an upgrade look like all of that was reset: if the new
    directory has never been created and an old-named sibling sits right
    next to where it would go, rename that sibling into place rather than
    starting empty.

    This also covers the Docker image: the same named volume is still
    mounted, just at a new path inside the container, so its old-named
    subdirectory is what this finds and moves.
    """
    if os.path.exists(new_dir):
        return
    legacy = os.path.join(os.path.dirname(new_dir) or ".", "erspan-sim")
    if legacy == new_dir or not os.path.isdir(legacy):
        return
    try:
        os.makedirs(os.path.dirname(new_dir), exist_ok=True)
        os.rename(legacy, new_dir)
    except OSError:
        pass  # best-effort — a stale or unmovable legacy directory must not
              # stop startup; validate()/load_* still work from an empty dir


def config_dir() -> str:
    base = os.environ.get("SPANTAP_CONFIG_DIR")
    if base:
        _migrate_legacy_dir(base)
        return base
    legacy_base = os.environ.get("ERSPAN_SIM_CONFIG_DIR")
    if legacy_base:
        # An old deployment's environment still names the old variable
        # directly (a docker-compose.yml or systemd unit nobody has edited
        # yet). Honour it exactly rather than guessing a new location out
        # from under it.
        return legacy_base
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    new_dir = os.path.join(xdg, "spantap")
    _migrate_legacy_dir(new_dir)
    return new_dir


def profiles_dir() -> str:
    return os.path.join(config_dir(), "profiles")


def _state_path() -> str:
    return os.path.join(config_dir(), "state.json")


def _profile_path(name: str) -> str:
    return os.path.join(profiles_dir(), "%s.json" % check_name(name))


def check_name(name: str) -> str:
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise ConfigError(
            "profile names must be 1-40 characters of letters, digits, dot, dash "
            "or underscore (got %r)" % (name,)
        )
    return name


# --------------------------------------------------------------------------
# the schema
# --------------------------------------------------------------------------

def default_profile() -> Dict:
    return {
        "source": "synth",
        "target": {
            # Loopback by default: the gateway on the same host receives it
            # with no further setup, and nothing leaves the box until
            # someone deliberately points it at a real receiver.
            "dst": DEFAULT_SIM_DST,
            "src": "",
            "session_id": 1,
            "vlan": 0,
            "cos": 0,
            "index": 0,
            "ttl": 64,
            "dscp": 0,
            "df": True,
            "mtu": 1500,
        },
        "synth": {
            "scenario": "mixed",
            "pps": 100.0,
            "count": 0,
            "seed": 0,
            "v6_ratio": 0.25,
            # 802.1Q tag written into the *generated frames*. Distinct from
            # target.vlan, which is the VLAN reported in the ERSPAN header.
            "vlan": 0,
        },
        "replay": {
            "file": "",
            "loop": 0,          # 0 = endless
            "speed": 1.0,
            "pps": 0.0,
        },
        "live": {
            "iface": "",
            "filter": "",
            "snaplen": 0,
        },
        "exclusions": {
            "pcapoverip_port": DEFAULT_PCAPOVERIP_PORT,
            "pcapoverip_host": "",
            "exclude_ssh": False,
        },
        "output": {
            "mode": "wire",
            "pcap_path": "",
        },
    }


def _num(section: str, key: str, value, lo, hi, kind=int):
    try:
        v = kind(value)
    except (TypeError, ValueError):
        raise ConfigError("%s.%s must be a number (got %r)" % (section, key, value))
    if not lo <= v <= hi:
        raise ConfigError("%s.%s must be between %s and %s (got %s)" % (section, key, lo, hi, v))
    return v


def _text(value, what: str) -> str:
    """Accept only a real string; a JSON number or list here is a bug upstream."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ConfigError("%s must be a string (got %r)" % (what, value))
    if "\x00" in value:
        raise ConfigError("%s must not contain a NUL byte" % what)
    return value.strip()


def _ipv4(value, what: str, allow_empty: bool = False) -> str:
    value = _text(value, what)
    if not value:
        if allow_empty:
            return ""
        raise ConfigError("%s is required" % what)
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError:
        raise ConfigError("%s must be an IPv4 address (got %r)" % (what, value))
    if addr.is_multicast:
        raise ConfigError("%s must not be a multicast address" % what)
    return str(addr)


def _check_pcap_path(path: str) -> str:
    """Constrain where a run may write.

    Starting a run is reachable from the web UI, so the output path is an
    arbitrary-write primitive if left unconstrained — and this tool is often
    run as root. Requiring a capture-file extension, and refusing to write
    through a symlink or onto anything that is not a regular file, keeps a
    stray or hostile request from landing on ~/.ssh/authorized_keys.
    """
    if not path:
        return ""
    if not path.endswith((".pcap", ".pcapng")):
        raise ConfigError("output.pcap_path must end in .pcap or .pcapng (got %r)" % path)
    if os.path.islink(path):
        raise ConfigError("refusing to write through a symlink: %s" % path)
    if os.path.exists(path) and not os.path.isfile(path):
        raise ConfigError("output.pcap_path exists and is not a regular file: %s" % path)
    return path


def validate(profile: Dict, *, for_run: bool = False) -> Dict:
    """Normalise a profile, filling in defaults and rejecting nonsense.

    ``for_run`` additionally enforces what is only needed to actually start:
    a destination, an existing capture file, a named interface.
    """
    if not isinstance(profile, dict):
        raise ConfigError("a profile must be an object")

    out = default_profile()
    for section, value in profile.items():
        if section in out and isinstance(out[section], dict):
            if not isinstance(value, dict):
                raise ConfigError("%s must be an object" % section)
            out[section].update(value)
        elif section in out:
            out[section] = value
        # unknown keys are dropped rather than rejected, so an older profile
        # written by a newer build still loads

    if out["source"] not in SOURCES:
        raise ConfigError("source must be one of %s (got %r)" % (", ".join(SOURCES), out["source"]))

    t = out["target"]
    t["dst"] = _ipv4(t.get("dst"), "target.dst", allow_empty=not for_run)
    t["src"] = _ipv4(t.get("src"), "target.src", allow_empty=True)
    t["session_id"] = _num("target", "session_id", t.get("session_id", 1), 0, 1023)
    t["vlan"] = _num("target", "vlan", t.get("vlan", 0), 0, 4095)
    t["cos"] = _num("target", "cos", t.get("cos", 0), 0, 7)
    t["index"] = _num("target", "index", t.get("index", 0), 0, 0xFFFFF)
    t["ttl"] = _num("target", "ttl", t.get("ttl", 64), 1, 255)
    t["dscp"] = _num("target", "dscp", t.get("dscp", 0), 0, 63)
    t["mtu"] = _num("target", "mtu", t.get("mtu", 1500), 576, 65535)
    t["df"] = bool(t.get("df", True))

    s = out["synth"]
    if s.get("scenario") not in SCENARIOS:
        raise ConfigError("synth.scenario must be one of %s" % ", ".join(SCENARIOS))
    s["pps"] = _num("synth", "pps", s.get("pps", 0), 0, 1_000_000, float)
    s["count"] = _num("synth", "count", s.get("count", 0), 0, 1_000_000_000)
    s["seed"] = _num("synth", "seed", s.get("seed", 0), 0, 2 ** 31 - 1)
    s["v6_ratio"] = _num("synth", "v6_ratio", s.get("v6_ratio", 0.25), 0.0, 1.0, float)
    s["vlan"] = _num("synth", "vlan", s.get("vlan", 0), 0, 4095)

    r = out["replay"]
    r["file"] = _text(r.get("file"), "replay.file")
    r["loop"] = _num("replay", "loop", r.get("loop", 0), 0, 1_000_000)
    r["speed"] = _num("replay", "speed", r.get("speed", 1.0), 0.0, 10_000.0, float)
    r["pps"] = _num("replay", "pps", r.get("pps", 0), 0, 1_000_000, float)

    live = out["live"]
    live["iface"] = _text(live.get("iface"), "live.iface")
    if live["iface"] and not re.match(r"^[A-Za-z0-9._:@-]{1,15}$", live["iface"]):
        raise ConfigError("live.iface is not a valid interface name: %r" % live["iface"])
    live["filter"] = _text(live.get("filter"), "live.filter")
    live["snaplen"] = _num("live", "snaplen", live.get("snaplen", 0), 0, 262144)

    e = out["exclusions"]
    e["pcapoverip_port"] = _num("exclusions", "pcapoverip_port",
                                e.get("pcapoverip_port", DEFAULT_PCAPOVERIP_PORT), 0, 65535)
    e["pcapoverip_host"] = _ipv4(e.get("pcapoverip_host"), "exclusions.pcapoverip_host",
                                 allow_empty=True)
    e["exclude_ssh"] = bool(e.get("exclude_ssh", False))

    o = out["output"]
    if o.get("mode") not in OUTPUT_MODES:
        raise ConfigError("output.mode must be one of %s" % ", ".join(OUTPUT_MODES))
    o["pcap_path"] = _check_pcap_path(_text(o.get("pcap_path"), "output.pcap_path"))

    if for_run:
        if out["source"] == "replay":
            if not r["file"]:
                raise ConfigError("replay.file is required when the source is a capture file")
            if not os.path.isfile(r["file"]):
                raise ConfigError("replay.file does not exist: %s" % r["file"])
        if out["source"] == "live" and not live["iface"]:
            raise ConfigError("live.iface is required when the source is an interface")
        if o["mode"] == "pcap" and not o["pcap_path"]:
            raise ConfigError("output.pcap_path is required when writing to a file")

    return out


# --------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------

def _write_json(path: str, data: Dict) -> None:
    # Not os.makedirs alone: an OSError escaping from here reaches the user as
    # a traceback, or as a 500 from the web UI, neither of which says what to
    # do about it. check_writable turns it into a sentence with the fix in it.
    check_writable(os.path.dirname(path))
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)   # atomic: a crash never leaves a half profile
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def list_profiles() -> List[str]:
    try:
        names = os.listdir(profiles_dir())
    except OSError:
        return []
    return sorted(n[:-5] for n in names if n.endswith(".json") and NAME_RE.match(n[:-5]))


def load_profile(name: str) -> Dict:
    path = _profile_path(name)
    try:
        with open(path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise ConfigError("no such profile: %s" % name)
    except OSError as exc:
        raise ConfigError("cannot read profile %s: %s" % (name, exc))
    except json.JSONDecodeError as exc:
        raise ConfigError("profile %s is not valid JSON: %s" % (name, exc))
    try:
        return validate(data)
    except ConfigError:
        raise
    except Exception as exc:  # noqa: BLE001 — a bad file must not escape as a 500
        raise ConfigError("profile %s is unusable: %s: %s" % (name, type(exc).__name__, exc))


def save_profile(name: str, profile: Dict) -> Dict:
    clean = validate(profile)
    _write_json(_profile_path(name), clean)
    set_last_used(name)
    return clean


def delete_profile(name: str) -> None:
    try:
        os.unlink(_profile_path(name))
    except FileNotFoundError:
        raise ConfigError("no such profile: %s" % name)
    if last_used() == name:
        set_last_used(None)


# --------------------------------------------------------------------------
# the gateway's configuration
#
# One gateway per host, so this is a single file rather than named profiles.
# --------------------------------------------------------------------------

def gateway_path() -> str:
    return os.path.join(config_dir(), "gateway.json")


GATEWAY_SOURCES = ("erspan", "live", "replay")


def default_gateway_config() -> Dict:
    return {
        # Which third of the gateway feeds the ring. "erspan" is the raw GRE
        # receiver; "live" mirrors a local interface; "replay" plays back a
        # stored capture, for demoing or troubleshooting delivery without
        # either of the other two at hand. One at a time: GRE sequence
        # numbers make loss countable for ERSPAN and mean nothing for a
        # local capture or a replayed file, and a merged stream would have
        # to caveat every number it reported.
        "source": "erspan",
        "receive": {
            "bind": "0.0.0.0",      # every local address; the mirror may arrive anywhere
            "session_id": None,     # None = accept every ERSPAN session
            "from_host": "",        # "" = accept every mirroring source
            "rcvbuf_mib": 8,
        },
        "serve": {
            "bind": "127.0.0.1",    # Wireshark is normally local or on an SSH tunnel
            "port": 57012,
            "snaplen": 0,           # 0 = whole frames
        },
        "live": {
            "iface": "",
            "filter": "",           # ANDed after the mandatory exclusions
            "snaplen": 0,           # 0 = whole frames
            # The ERSPAN receiver is not running in this mode, so GRE seen on
            # the wire is somebody else's mirror and worth capturing. Turn it
            # on when this box is also an ERSPAN destination and you do not
            # want each frame twice.
            "exclude_gre": False,
            "exclude_ssh": False,
        },
        "replay": {
            "file": "",         # a real path — the shared capture store, or any other
            "loop": 0,          # 0 = forever, matching the simulator's own replay source
            "pace": True,       # sleep between frames at roughly the file's own gaps
        },
        "buffer": {
            "max_frames": 8192,
            "max_mib": 64,
        },
    }


def validate_gateway(config: Dict) -> Dict:
    if not isinstance(config, dict):
        raise ConfigError("the gateway configuration must be an object")
    out = default_gateway_config()
    for section, value in config.items():
        if section not in out:
            continue            # unknown keys drop, so an older file still loads
        if isinstance(out[section], dict):
            if not isinstance(value, dict):
                raise ConfigError("%s must be an object" % section)
            out[section].update(value)
        else:
            out[section] = value

    if out["source"] not in GATEWAY_SOURCES:
        raise ConfigError("source must be one of %s (got %r)"
                          % (", ".join(GATEWAY_SOURCES), out["source"]))

    live = out["live"]
    live["iface"] = _text(live.get("iface"), "live.iface")
    live["filter"] = _text(live.get("filter"), "live.filter")
    live["snaplen"] = _num("live", "snaplen", live.get("snaplen", 0), 0, 262144)
    if live["snaplen"] and live["snaplen"] < 64:
        raise ConfigError("live.snaplen must be 0 (whole frames) or at least 64")
    live["exclude_gre"] = bool(live.get("exclude_gre", False))
    live["exclude_ssh"] = bool(live.get("exclude_ssh", False))
    if out["source"] == "live" and not live["iface"]:
        raise ConfigError("live.iface is required when the gateway source is "
                          "a local interface")

    replay = out["replay"]
    replay["file"] = _text(replay.get("file"), "replay.file")
    replay["loop"] = _num("replay", "loop", replay.get("loop", 0), 0, 1_000_000)
    replay["pace"] = bool(replay.get("pace", True))
    if out["source"] == "replay":
        if not replay["file"]:
            raise ConfigError("replay.file is required when the gateway source "
                              "is a replayed capture")
        if not os.path.isfile(replay["file"]):
            raise ConfigError("replay.file does not exist: %s" % replay["file"])

    rx = out["receive"]
    rx["bind"] = _ipv4(rx.get("bind") or "0.0.0.0", "receive.bind")
    rx["from_host"] = _ipv4(rx.get("from_host"), "receive.from_host", allow_empty=True)
    session = rx.get("session_id")
    if session in (None, "", "all"):
        rx["session_id"] = None
    else:
        rx["session_id"] = _num("receive", "session_id", session, 0, 1023)
    rx["rcvbuf_mib"] = _num("receive", "rcvbuf_mib", rx.get("rcvbuf_mib", 8), 1, 512)

    srv = out["serve"]
    srv["bind"] = _ipv4(srv.get("bind") or "127.0.0.1", "serve.bind")
    # 0 means "let the kernel pick"; the CLI and the UI then report the port
    # that was actually bound. Useful for tests and for a second instance.
    srv["port"] = _num("serve", "port", srv.get("port", 57012), 0, 65535)
    srv["snaplen"] = _num("serve", "snaplen", srv.get("snaplen", 0), 0, 262144)
    if srv["snaplen"] and srv["snaplen"] < 64:
        raise ConfigError("serve.snaplen must be 0 (whole frames) or at least 64")

    buf = out["buffer"]
    buf["max_frames"] = _num("buffer", "max_frames", buf.get("max_frames", 8192), 64, 1_000_000)
    buf["max_mib"] = _num("buffer", "max_mib", buf.get("max_mib", 64), 1, 4096)

    return out


def load_gateway() -> Dict:
    path = gateway_path()
    try:
        with open(path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return default_gateway_config()
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError("gateway configuration is unusable: %s" % exc)
    try:
        return validate_gateway(data)
    except ConfigError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ConfigError("gateway configuration is unusable: %s: %s"
                          % (type(exc).__name__, exc))


def load_gateway_or_default() -> Dict:
    try:
        return load_gateway()
    except Exception:  # noqa: BLE001 — a bad file must not break startup
        return default_gateway_config()


def save_gateway(config: Dict) -> Dict:
    clean = validate_gateway(config)
    _write_json(gateway_path(), clean)
    return clean


# --------------------------------------------------------------------------
# the web UI's own settings
#
# These decide how the UI is reachable, so a bad value here is the one kind of
# mistake that cannot be fixed from the UI. Everything below is validated
# before it is written — a certificate is actually loaded, an address is
# actually bound — and the server falls back to loopback rather than refusing
# to start if a stored value stops working later.
# --------------------------------------------------------------------------

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                         r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def webui_path() -> str:
    return os.path.join(config_dir(), "webui.json")


def tls_dir() -> str:
    return os.path.join(config_dir(), "tls")


def default_webui_config() -> Dict:
    return {
        # Every address, so the UI is reachable from other hosts out of the
        # box. Never unauthenticated: serve() generates a token (and saves it)
        # when none is set. Bind 127.0.0.1 to keep it local-only.
        "bind": "0.0.0.0",
        "port": 8420,
        "allow_hosts": [],
        "tls": {"cert": "", "key": ""},
        "token": "",
    }


def in_container() -> bool:
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup") as fh:
            return any(m in fh.read() for m in ("docker", "containerd", "kubepods"))
    except OSError:
        return False


def _missing_path_hint(path: str) -> str:
    """Point at the container path when a host path was pasted in.

    Typing the path your shell shows you is the obvious thing to do, and it is
    wrong here: the server resolves it inside the container, where the host's
    ./tls directory appears at /tls.
    """
    name = os.path.basename(path)
    for candidate in ("/tls", tls_dir()):
        suggestion = os.path.join(candidate, name)
        if suggestion != path and os.path.isfile(suggestion):
            return " Did you mean %s? " % suggestion + (
                "Paths are resolved inside the container, not on the host."
                if in_container() else ""
            )
    if in_container() and not path.startswith(("/tls", tls_dir())):
        return (" Paths are resolved inside the container, not on the host: the "
                "./tls directory next to docker-compose.yml is mounted at /tls, "
                "so use /tls/%s." % name)
    return ""


def _unreadable_why(path: str) -> str:
    """Say who owns the file, who we are, and what to run.

    "Permission denied" on its own sends people round in circles, because the
    process doing the reading is inside a container and its uid is not the one
    they see in their shell. Both halves of the comparison belong in the
    message.
    """
    try:
        st = os.stat(path)
    except OSError as exc:
        return "%s: %s" % (path, exc)
    try:
        groups = set(os.getgroups())
    except OSError:
        groups = set()
    groups.add(os.getgid())

    detail = ("%s is mode %04o owned by uid %d gid %d; this process runs as "
              "uid %d gid %s."
              % (path, st.st_mode & 0o7777, st.st_uid, st.st_gid,
                 os.getuid(), ",".join(str(g) for g in sorted(groups))))

    if st.st_gid in groups:
        fix = ("The group is right but its read bit is not set. On the host: "
               "chmod g+r on that file.")
    elif st.st_uid == os.getuid():
        fix = "Owned by this process but not readable by it: chmod u+r on that file."
    else:
        fix = ("On the host, give that group access to the file behind it:  "
               "sudo chgrp %d <file> && chmod 0640 <file>" % os.getgid())
    return detail + " " + fix


def unwritable_why(directory: str) -> str:
    """Why this process cannot create a file in *directory*, and the fix.

    The same shape as :func:`_unreadable_why`, for the other direction. It
    exists because every stored thing — profiles, the UI's own settings, the
    account file — lands in one directory, and in Docker that directory is a
    named volume. A volume is initialised from the image path *only when it is
    first created*, ownership included: a volume made by an older image keeps
    the ownership it was made with, and every write into it then fails with
    nothing but "Permission denied" and a traceback.
    """
    probe = directory
    while probe and not os.path.exists(probe):
        parent = os.path.dirname(probe.rstrip(os.sep))
        if parent == probe:
            break
        probe = parent
    try:
        st = os.stat(probe)
    except OSError as exc:
        return "%s cannot be examined: %s" % (probe, exc)

    try:
        groups = set(os.getgroups())
    except OSError:
        groups = set()
    groups.add(os.getgid())

    detail = ("%s is mode %04o owned by uid %d gid %d; this process runs as "
              "uid %d gid %s."
              % (probe, st.st_mode & 0o7777, st.st_uid, st.st_gid,
                 os.getuid(), ",".join(str(g) for g in sorted(groups))))

    if in_container():
        fix = (" In Docker this is almost always a config volume created by an "
               "older image, which keeps the ownership it was made with. Fix it "
               "from the host, with the containers stopped:\n"
               "    docker run --rm -v erspan-config:/c alpine "
               "chown -R %d:%d /c\n"
               "  (that volume keeps its pre-rename name 'erspan-config' on "
               "purpose, so upgrading from erspan-sim does not lose it; it is "
               "usually prefixed by your compose project name — "
               "docker volume ls)" % (os.getuid(), os.getgid()))
    elif st.st_uid == os.getuid():
        fix = " Owned by this process but not writable by it: chmod u+w on it."
    else:
        fix = ("  sudo chown -R %d:%d %s" % (os.getuid(), os.getgid(), probe))
    return detail + fix


def check_writable(directory: str, what: str = "configuration") -> None:
    """Raise a ConfigError naming the fix, rather than letting OSError escape."""
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError:
        raise ConfigError("the %s directory %s cannot be created. %s"
                          % (what, directory, unwritable_why(directory)))
    if not os.access(directory, os.W_OK | os.X_OK):
        raise ConfigError("the %s directory %s is not writable. %s"
                          % (what, directory, unwritable_why(directory)))


def _check_tls(cert: str, key: str) -> None:
    """Load the pair the way the server will, so a bad cert fails here."""
    import ssl
    if not cert:
        return
    for label, path in (("certificate", cert), ("key", key or cert)):
        if not os.path.isfile(path):
            raise ConfigError("TLS %s not found: %s.%s"
                              % (label, path, _missing_path_hint(path)))
        if not os.access(path, os.R_OK):
            raise ConfigError("TLS %s is not readable. %s" % (label, _unreadable_why(path)))
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key or cert)
    except (ssl.SSLError, OSError) as exc:
        raise ConfigError("the TLS certificate and key could not be loaded: %s" % exc)


def _check_bindable(bind: str, port: int, skip: bool = False) -> None:
    """Refuse an address this host cannot actually listen on."""
    if skip:
        return
    import socket as _s
    probe = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
    probe.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
    try:
        probe.bind((bind, port))
    except OSError as exc:
        raise ConfigError(
            "cannot listen on %s:%d — %s. Pick an address this host owns, or "
            "0.0.0.0 for all of them." % (bind, port, exc)
        )
    finally:
        probe.close()


def validate_webui(config: Dict, *, current: Optional[Dict] = None,
                   check_bind: bool = True, auto_token: bool = False,
                   require_token: bool = True) -> Dict:
    """Normalise UI settings. ``current`` is what is running now, so the
    address already in use by this very server is not reported as taken.

    ``auto_token`` decides what happens when binding off loopback with no
    token set: by default (CLI callers, tests, anything scripted) that is a
    hard error, so a config pushed without a token fails loudly rather than
    silently exposing an unauthenticated UI. The web UI's own Settings save
    passes ``auto_token=True`` instead, matching what :func:`serve` already
    does at startup — generate one rather than block someone who just wants
    to reach the page from another host.

    The refusal applies only to a bind that was asked for. The default
    (0.0.0.0) with no token is accepted as it is, as is anything when
    ``require_token=False`` (reading settings back): :func:`serve` generates
    and saves a token at startup either way.
    """
    if not isinstance(config, dict):
        raise ConfigError("the web UI settings must be an object")
    out = default_webui_config()
    explicit_bind = bool(config.get("bind"))
    for key, value in config.items():
        if key == "tls" and isinstance(value, dict):
            out["tls"].update(value)
        elif key in out:
            out[key] = value

    out["bind"] = _text(out.get("bind"), "bind") or "0.0.0.0"
    if out["bind"] not in ("0.0.0.0", "localhost"):
        out["bind"] = _ipv4(out["bind"], "bind")
    out["port"] = _num("webui", "port", out.get("port", 8420), 1, 65535)

    hosts = out.get("allow_hosts") or []
    if isinstance(hosts, str):
        hosts = [h for h in re.split(r"[,\s]+", hosts) if h]
    if not isinstance(hosts, list):
        raise ConfigError("allow_hosts must be a list of names")
    clean_hosts = []
    for host in hosts:
        host = _text(host, "allow_hosts entry")
        if not host:
            continue
        if not HOSTNAME_RE.match(host):
            raise ConfigError("%r is not a valid hostname or address" % host)
        if host not in clean_hosts:
            clean_hosts.append(host)
    if len(clean_hosts) > 32:
        raise ConfigError("at most 32 allowed hostnames")
    out["allow_hosts"] = clean_hosts

    cert = _text(out["tls"].get("cert"), "tls.cert")
    key = _text(out["tls"].get("key"), "tls.key")
    if key and not cert:
        raise ConfigError("a TLS key needs a certificate as well")
    _check_tls(cert, key)
    out["tls"] = {"cert": cert, "key": key}

    token = out.get("token")
    out["token"] = "" if token is None else _text(token, "token")
    if out["token"] and len(out["token"]) < 8:
        raise ConfigError("a token shorter than 8 characters is not worth having")

    if out["bind"] not in ("127.0.0.1", "localhost") and not out["token"]:
        if auto_token:
            out["token"] = secrets.token_urlsafe(24)
        elif require_token and explicit_bind:
            raise ConfigError(
                "binding %s makes the UI reachable from the network, so it needs "
                "a token. Set one, or bind 127.0.0.1 and use an SSH tunnel."
                % out["bind"]
            )

    # Same port as what's running now means a bind-test can only ever fail —
    # not because the new address is bad, but because the current server
    # already holds that port. That's true even when the addresses don't
    # match as strings: a server effectively bound to 0.0.0.0 (e.g. forced
    # there by a compose/env override, while the saved config still says
    # 127.0.0.1) already occupies every address on that port, so testing
    # 127.0.0.1:port against it fails with the exact same "Address already
    # in use" a stranger's process would produce. There is no way to tell
    # those apart from here, so once the port matches, skip the test rather
    # than reject a config purely because this server is the one running it.
    unchanged = bool(current and int(current.get("port", 0)) == out["port"])
    _check_bindable(out["bind"], out["port"], skip=not check_bind or unchanged)
    return out


def load_webui_raw() -> Dict:
    """The stored UI settings exactly as saved, or {} if there are none.

    For editing one field in place: unlike :func:`load_webui_or_default`,
    this never swaps a stored-but-currently-invalid file for the defaults,
    so saving it back cannot silently drop a token or an allowed host.
    """
    try:
        with open(webui_path()) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise ConfigError("%s is not valid JSON: %s" % (webui_path(), exc))
    if not isinstance(data, dict):
        raise ConfigError("%s does not hold a settings object" % webui_path())
    return data


def load_webui_or_default() -> Dict:
    try:
        with open(webui_path()) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return default_webui_config()
    except (OSError, json.JSONDecodeError):
        return default_webui_config()
    try:
        # Never bind-check on load: the port is in use by the server reading it.
        return validate_webui(data, check_bind=False, require_token=False)
    except Exception:  # noqa: BLE001 — a stored value that stopped working
        return default_webui_config()


def new_webui_token() -> Tuple[str, bool]:
    """Generate a UI token and save it, so it is the same on the next start.

    Returns the token and whether it could be saved; an unwritable config
    directory still gets a token, just one that lasts only this run.
    """
    token = secrets.token_urlsafe(24)
    try:
        raw = load_webui_raw()
        raw["token"] = token
        save_webui(raw, check_bind=False)
        return token, True
    except (ConfigError, OSError):
        return token, False


def save_webui(config: Dict, current: Optional[Dict] = None,
              auto_token: bool = False, check_bind: bool = True) -> Dict:
    clean = validate_webui(config, current=current, auto_token=auto_token,
                           check_bind=check_bind)
    _write_json(webui_path(), clean)
    try:
        os.chmod(webui_path(), 0o600)   # it can hold a token
    except OSError:
        pass
    return clean


def redact_webui(config: Dict) -> Dict:
    """What the browser is allowed to see: everything but the token itself."""
    out = json.loads(json.dumps(config))
    out["token_set"] = bool(out.pop("token", ""))
    return out


def last_used() -> Optional[str]:
    try:
        with open(_state_path()) as fh:
            value = json.load(fh).get("last_used")
    except (OSError, json.JSONDecodeError, AttributeError):
        return None
    return value if isinstance(value, str) and value in list_profiles() else None


def set_last_used(name: Optional[str]) -> None:
    try:
        _write_json(_state_path(), {"last_used": name})
    except OSError:
        pass  # a read-only home must not stop a run


def load_last_or_default() -> Dict:
    name = last_used()
    if name:
        try:
            return load_profile(name)
        except Exception:  # noqa: BLE001 — one bad file must not break startup
            pass
    return default_profile()
