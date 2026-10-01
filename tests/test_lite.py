# SPDX-License-Identifier: GPL-2.0-or-later
"""spantap-lite: config validation, the capped local-file writer, the PID-file
lifecycle, and one real end-to-end run (replay -> ring -> PCAP-over-IP client,
with the local-file tee active at the same time).
"""

import json
import os
import signal
import socket
import struct
import time

import pytest

from spantap.config import ConfigError as GatewayConfigError
from spantap.gateway.pcapoverip import pcap_file_header, pcap_record
from spantap.lite import cli as lite_cli
from spantap.lite.config import (
    ConfigError,
    build_noninteractive_config,
    default_lite_config,
    lite_path,
    load_lite_or_default,
    pid_path,
    save_lite,
    validate_lite,
)
from spantap.lite.service import STATE_ERROR, STATE_RUNNING, CappedPcapWriter, LiteService

assert GatewayConfigError is ConfigError, "spantap.lite reuses spantap.config's own ConfigError"


@pytest.fixture(autouse=True)
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))


# -- configuration -----------------------------------------------------------

def test_the_default_is_deliberately_unconfigured():
    """Nothing to capture yet is the honest starting state, not a guess."""
    with pytest.raises(ConfigError) as exc:
        validate_lite(default_lite_config())
    assert "live.iface is required" in str(exc.value)


def test_a_live_source_needs_an_interface():
    with pytest.raises(ConfigError):
        validate_lite({"source": "live", "live": {"iface": ""}})


def test_a_replay_source_needs_a_real_file(tmp_path):
    with pytest.raises(ConfigError) as exc:
        validate_lite({"source": "replay", "replay": {"file": str(tmp_path / "nope.pcap")}})
    assert "does not exist" in str(exc.value)


def test_save_path_must_end_in_pcap(tmp_path):
    with pytest.raises(ConfigError):
        validate_lite({
            "source": "live", "live": {"iface": "lo"},
            "save": {"enabled": True, "path": str(tmp_path / "out.txt")},
        })


def test_save_enabled_needs_a_path():
    with pytest.raises(ConfigError):
        validate_lite({"source": "live", "live": {"iface": "lo"}, "save": {"enabled": True}})


def test_the_pcapoverip_exclusion_is_always_on_regardless_of_exclude_self():
    """Matches the gateway's own build_gateway_plan: there is no argument
    that removes the self-exclusion clause. exclude_self only ever adds or
    removes the *SSH* clause on top of it."""
    from spantap.gateway.livecapture import LiveCapture

    for exclude_self in (True, False):
        cap = LiveCapture("lo", pcapoverip_port=57012, exclude_ssh=exclude_self,
                          capture_cmd=["/bin/true"])
        mandatory = [c.expr for c in cap.plan.clauses if c.mandatory]
        assert mandatory == ["not (tcp port 57012)"]
        ssh_clauses = [c for c in cap.plan.clauses if "port 22" in c.expr]
        assert bool(ssh_clauses) == exclude_self


def test_a_custom_filter_is_anded_in_last():
    from spantap.gateway.livecapture import LiveCapture

    cap = LiveCapture("lo", exclude_ssh=True, user_filter="host 10.0.0.1",
                      capture_cmd=["/bin/true"])
    expr = cap.bpf
    assert expr.index("port 22") < expr.index("10.0.0.1")


def test_load_save_round_trip(tmp_path):
    cfg = build_noninteractive_config(iface="lo", port=12345, save_path=str(tmp_path / "x.pcap"))
    saved = save_lite(cfg)
    assert os.path.isfile(lite_path())
    reloaded = load_lite_or_default()
    assert reloaded == saved
    assert reloaded["live"]["iface"] == "lo"
    assert reloaded["serve"]["port"] == 12345


def test_an_unwritten_config_loads_as_the_default():
    assert load_lite_or_default() == default_lite_config()


def test_unknown_keys_in_a_stored_file_are_dropped_not_rejected(tmp_path):
    """A newer build must not brick an older config file."""
    path = lite_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump({"source": "live", "live": {"iface": "lo"}, "from_the_future": 123}, fh)
    cfg = load_lite_or_default()
    assert cfg["live"]["iface"] == "lo"
    assert "from_the_future" not in cfg


def test_build_noninteractive_config_prefers_replay_over_iface(tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(pcap_file_header())
    cfg = build_noninteractive_config(iface="lo", replay_file=str(pcap))
    assert cfg["source"] == "replay"
    assert cfg["replay"]["file"] == str(pcap)


def test_a_bare_replay_name_means_a_file_in_the_capture_store(tmp_path, monkeypatch):
    """In Docker that store is ./captures on the host: name the file, not the
    path it happens to have inside the container."""
    store = tmp_path / "captures"
    store.mkdir()
    (store / "demo.pcapng").write_bytes(pcap_file_header())
    monkeypatch.setenv("SPANTAP_CAPTURE_DIR", str(store))
    monkeypatch.chdir(tmp_path)          # so the bare name is not found as-is
    cfg = build_noninteractive_config(replay_file="demo.pcapng")
    assert cfg["replay"]["file"] == str(store / "demo.pcapng")


def test_no_save_flag_overrides_a_previously_saved_path(tmp_path):
    current = build_noninteractive_config(iface="lo", save_path=str(tmp_path / "a.pcap"))
    cfg = build_noninteractive_config(current=current, no_save=True)
    assert cfg["save"]["enabled"] is False


# -- the capped local-file writer --------------------------------------------

def test_capped_writer_writes_a_valid_pcap_header(tmp_path):
    w = CappedPcapWriter(str(tmp_path / "out.pcap"), max_bytes=1_000_000)
    w.close()
    data = (tmp_path / "out.pcap").read_bytes()
    magic = struct.unpack("<I", data[:4])[0]
    assert magic == 0xA1B2C3D4
    assert len(data) == 24


def test_capped_writer_stops_growing_at_the_cap(tmp_path):
    frame = b"x" * 100
    record_size = 16 + len(frame)
    cap_bytes = 24 + record_size * 5   # header + exactly 5 records
    w = CappedPcapWriter(str(tmp_path / "out.pcap"), max_bytes=cap_bytes)
    for i in range(20):
        w.write(i * 1000, frame, len(frame))
    w.close()
    snap_frames = w.frames_written
    on_disk = (tmp_path / "out.pcap").stat().st_size
    assert snap_frames == 5, "should have stopped exactly at the cap, not run past it"
    assert on_disk <= cap_bytes
    assert w.capped is True


def test_capped_writer_snapshot_reports_the_cap_state(tmp_path):
    w = CappedPcapWriter(str(tmp_path / "out.pcap"), max_bytes=40)
    w.write(0, b"y" * 100, 100)   # bigger than the whole cap: refused outright
    snap = w.snapshot()
    w.close()
    assert snap["capped"] is True
    assert snap["frames_written"] == 0


# -- the pid file --------------------------------------------------------

def test_pid_round_trip():
    lite_cli._write_pid()
    assert lite_cli._read_pid() == os.getpid()
    assert lite_cli._pid_alive(os.getpid()) is True
    lite_cli._remove_pid()
    assert lite_cli._read_pid() is None


def test_a_pid_that_cannot_exist_is_not_alive():
    # PIDs wrap well below this on every real system.
    assert lite_cli._pid_alive(2 ** 30) is False


def test_stop_with_no_pid_file_is_not_an_error():
    class Args:
        timeout = 1.0
    assert lite_cli.cmd_stop(Args()) == 0


def test_stop_removes_a_stale_pid_file():
    os.makedirs(os.path.dirname(pid_path()), exist_ok=True)
    with open(pid_path(), "w") as fh:
        fh.write("999999999\n")   # not a real pid

    class Args:
        timeout = 1.0
    assert lite_cli.cmd_stop(Args()) == 0
    assert not os.path.exists(pid_path())


# -- end to end: replay -> ring -> pcapoverip client, with the tee active ----

def _make_replay_source(path, n=200):
    frame = b"\xff" * 6 + b"\x00" * 6 + b"\x08\x00" + b"spantap-lite-test-frame"
    with open(path, "wb") as fh:
        fh.write(pcap_file_header())
        for i in range(n):
            fh.write(pcap_record(time.time_ns(), frame, len(frame)))


def test_replay_reaches_a_pcapoverip_client_and_the_capped_file(tmp_path):
    src = tmp_path / "src.pcap"
    out = tmp_path / "out.pcap"
    _make_replay_source(src, n=300)

    config = build_noninteractive_config(
        replay_file=str(src), bind="127.0.0.1", port=0,
        save_path=str(out), save_max_mib=1,
    )
    config = validate_lite(config)

    service = LiteService()
    service.start(config)
    try:
        port = service.snapshot()["server"]["port"]
        client = socket.create_connection(("127.0.0.1", port), timeout=10)
        client.settimeout(10)
        header = client.recv(24)
        assert len(header) == 24

        payload = b""
        deadline = time.time() + 10
        while time.time() < deadline and len(payload) < 4096:
            chunk = client.recv(65536)
            if not chunk:
                break
            payload += chunk
        client.close()
        assert len(payload) > 0, "the client received no frame data"

        snap = service.snapshot()
        assert snap["state"] == STATE_RUNNING
        assert snap["receiver"]["received"] > 0
        assert snap["server"]["frames_sent"] > 0
        assert snap["save"]["frames_written"] > 0
    finally:
        service.stop()

    final = service.snapshot()
    assert final["state"] != STATE_ERROR
    assert os.path.getsize(out) <= 1 * 1024 * 1024


def test_a_missing_replay_file_is_refused_at_validation():
    """validate_lite refuses this outright (mirroring the gateway's own
    for-run-style check), so a bad path can never even reach service.start()."""
    with pytest.raises(ConfigError) as exc:
        validate_lite(build_noninteractive_config(replay_file="/no/such/file.pcap"))
    assert "does not exist" in str(exc.value)
