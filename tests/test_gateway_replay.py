# SPDX-License-Identifier: GPL-2.0-or-later
"""The gateway's third source: a stored capture, played back.

For demoing or troubleshooting the ERSPAN-in, PCAP-over-IP-out pipeline
without a switch mirror or a NIC worth capturing from at hand. No feedback
loop is possible here (a file is not a live tap on anything the gateway's
own output could reach), so unlike the local-interface source there is no
exclusion filter to get right — these tests are mostly about the pacing
being interruptible and the loop/source-selection plumbing matching what
the local-interface source already established.
"""

import os
import socket
import time

import pytest

from spantap.config import ConfigError, default_gateway_config, validate_gateway
from spantap.gateway.replay import PcapReplay, ReplayError
from spantap.gateway.service import GatewayController
from spantap.sources.pcapread import (
    LINKTYPE_ETHERNET,
    write_pcap_header,
    write_pcap_packet,
)

FRAMES = [b"\x01" * 60, b"\x02" * 128, b"\x03" * 200]


@pytest.fixture(autouse=True)
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))


def _write_pcap(path, gaps_ns=None):
    """A tiny capture, spaced ``gaps_ns`` (default: no gap) apart."""
    gaps_ns = gaps_ns or [0] * len(FRAMES)
    ts = 1_700_000_000_000_000_000
    with open(path, "wb") as fh:
        write_pcap_header(fh, LINKTYPE_ETHERNET)
        for gap, frame in zip(gaps_ns, FRAMES):
            ts += gap
            write_pcap_packet(fh, ts, frame)
    return str(path)


# -- PcapReplay in isolation -------------------------------------------------

def test_a_missing_file_is_refused_up_front():
    with pytest.raises(ReplayError):
        PcapReplay("/no/such/file.pcap")


def test_a_capture_that_does_not_parse_is_refused_by_open(tmp_path):
    junk = tmp_path / "not-a-capture.pcap"
    junk.write_bytes(b"this is not a pcap file at all")
    replay = PcapReplay(str(junk))
    with pytest.raises(ReplayError):
        replay.open()


def test_all_frames_are_delivered_once_by_default(tmp_path):
    path = _write_pcap(tmp_path / "demo.pcap")
    replay = PcapReplay(path, loop=1, pace=False)
    replay.open()
    frames = list(replay.frames())
    assert [rf.frame for rf in frames] == FRAMES
    assert replay.received == len(FRAMES)
    assert replay.passes == 1


def test_loss_and_reorder_are_reported_as_unknown_not_zero(tmp_path):
    """A pcap file carries no GRE sequence number, same reasoning as a local
    interface capture: "none lost" and "cannot know" are different claims."""
    path = _write_pcap(tmp_path / "demo.pcap")
    replay = PcapReplay(path, loop=1, pace=False)
    list(replay.frames())
    snap = replay.snapshot()
    assert snap["lost"] is None
    assert snap["reordered"] is None
    assert snap["kind"] == "replay"


def test_frames_are_stamped_with_delivery_time_not_the_recorded_one(tmp_path):
    """The file's own timestamps (the year 2023, here) pace delivery; they
    must not leak into what the ring and Wireshark are told arrived now."""
    path = _write_pcap(tmp_path / "demo.pcap")
    replay = PcapReplay(path, loop=1, pace=False)
    before = time.time_ns()
    frames = list(replay.frames())
    after = time.time_ns()
    assert all(before <= rf.ts_ns <= after for rf in frames)


def test_loop_zero_repeats_until_told_to_stop(tmp_path):
    path = _write_pcap(tmp_path / "demo.pcap")
    replay = PcapReplay(path, loop=0, pace=False)
    seen = []
    for rf in replay.frames():
        seen.append(rf)
        if len(seen) >= len(FRAMES) * 3 + 1:
            replay.request_stop()
    assert len(seen) >= len(FRAMES) * 3 + 1
    assert replay.passes >= 4


def test_two_passes_means_exactly_two(tmp_path):
    path = _write_pcap(tmp_path / "demo.pcap")
    replay = PcapReplay(path, loop=2, pace=False)
    frames = list(replay.frames())
    assert len(frames) == len(FRAMES) * 2
    assert replay.passes == 2


def test_stopping_interrupts_a_long_paced_gap_promptly(tmp_path):
    """max_gap exists so one big recorded idle period cannot stall a demo for
    real time, but request_stop() must not have to wait for it either — a
    stop button that hangs for max_gap seconds is a UI bug waiting to happen.
    This is exactly the kind of guarantee worth removing to see it caught:
    replacing the Event-based wait with a plain time.sleep(gap) would make
    this test take ~30s instead of well under 1s.
    """
    # A single huge gap between two frames, way past any reasonable max_gap.
    path = _write_pcap(tmp_path / "demo.pcap", gaps_ns=[0, 30_000_000_000, 0])
    replay = PcapReplay(path, loop=1, pace=True, max_gap=30.0)

    import threading
    got_first = threading.Event()

    def consume():
        for i, _ in enumerate(replay.frames()):
            if i == 0:
                got_first.set()

    t = threading.Thread(target=consume, daemon=True)
    t.start()
    assert got_first.wait(timeout=5), "the first frame never arrived"

    started = time.monotonic()
    replay.request_stop()
    t.join(timeout=5)
    elapsed = time.monotonic() - started
    assert not t.is_alive(), "frames() did not stop promptly"
    assert elapsed < 5, "request_stop() waited out the paced gap (%.1fs)" % elapsed


def test_unpaced_replay_does_not_sleep_at_all(tmp_path):
    path = _write_pcap(tmp_path / "demo.pcap", gaps_ns=[0, 5_000_000_000, 0])
    replay = PcapReplay(path, loop=1, pace=False)
    started = time.monotonic()
    list(replay.frames())
    assert time.monotonic() - started < 2, "pace=False must not sleep between frames"


# -- config validation --------------------------------------------------------

def test_config_accepts_replay_as_a_source(tmp_path):
    path = _write_pcap(tmp_path / "demo.pcap")
    out = validate_gateway({"source": "replay", "replay": {"file": path}})
    assert out["source"] == "replay"
    assert out["replay"]["file"] == path
    assert out["replay"]["loop"] == 0
    assert out["replay"]["pace"] is True


def test_config_refuses_a_replay_source_with_no_file():
    with pytest.raises(ConfigError) as exc:
        validate_gateway({"source": "replay"})
    assert "replay.file is required" in str(exc.value)


def test_config_refuses_a_replay_file_that_does_not_exist():
    with pytest.raises(ConfigError) as exc:
        validate_gateway({"source": "replay", "replay": {"file": "/no/such/file.pcap"}})
    assert "does not exist" in str(exc.value)


def test_an_erspan_or_live_config_does_not_need_a_replay_file(tmp_path):
    """The replay.file field is only load-bearing when it is the chosen
    source — an ERSPAN deployment must not have to also point at a capture
    it will never use."""
    out = validate_gateway({"source": "erspan"})
    assert out["source"] == "erspan"
    assert out["replay"]["file"] == ""


# -- through the controller --------------------------------------------------

def test_a_replay_gateway_reaches_a_pcapoverip_client(tmp_path):
    """The whole chain, with a socket standing in for Wireshark — the same
    shape as the ERSPAN and local-interface end-to-end tests."""
    path = _write_pcap(tmp_path / "demo.pcap")
    config = default_gateway_config()
    config["source"] = "replay"
    config["replay"] = {"file": path, "loop": 0, "pace": False}
    config["serve"]["port"] = 0

    gw = GatewayController()
    gw.start(config)
    try:
        port = gw.snapshot(sample=False)["server"]["port"]
        client = socket.create_connection(("127.0.0.1", port), timeout=10)
        client.settimeout(10)
        header = client.recv(24)
        assert len(header) == 24, "no pcap header was written on connect"

        deadline = time.time() + 10
        payload = b""
        while time.time() < deadline and len(payload) < 100:
            try:
                chunk = client.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            payload += chunk
        client.close()

        snap = gw.snapshot(sample=False)
        assert snap["receiver"]["kind"] == "replay"
        assert snap["receiver"]["received"] > 0, "nothing was replayed"
        assert snap["server"]["frames_sent"] > 0, "nothing reached the client"
        assert len(payload) > 0, "the client received no frame data"
    finally:
        gw.stop()


def test_a_missing_replay_file_fails_at_start_not_silently(tmp_path):
    config = default_gateway_config()
    config["source"] = "replay"
    config["replay"] = {"file": str(tmp_path / "gone.pcap"), "loop": 0, "pace": False}
    config["serve"]["port"] = 0

    gw = GatewayController()
    with pytest.raises(Exception) as exc:
        gw.start(config)
    assert "does not exist" in str(exc.value)
    assert gw.snapshot(sample=False)["state"] != "running"


# -- the real CLI entrypoint, not just GatewayController --------------------
#
# Everything above drives GatewayController directly, which is how the rest
# of the gateway's own tests work too — and it is exactly why a bug in
# spantap-gw's own cmd_run() print statements went unnoticed: nothing had
# ever run the actual CLI to completion for a source that reports lost=None.
# `%d lost per sequence number, %d reordered` crashes with a TypeError the
# moment either is None, which the local-interface source has done since
# 0.4.0 and this replay source does too — caught here by actually running
# spantap-gw run as a real process would.

def test_the_cli_run_command_does_not_crash_on_unknown_loss(tmp_path, monkeypatch):
    from spantap.gateway.cli import build_parser

    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))
    path = _write_pcap(tmp_path / "demo.pcap")
    args = build_parser().parse_args([
        "run", "--replay-file", path, "--loop", "1", "--listen", "0",
        "--stats-interval", "0.05", "-q",
    ])
    rc = args.func(args)
    assert rc == 0


def test_the_cli_progress_line_does_not_crash_either(tmp_path, monkeypatch, capsys):
    """Same bug, different print statement: the periodic status line formats
    'lost %d' too, and fires while the gateway is still running — paced
    enough here to guarantee at least one tick before the file finishes."""
    from spantap.gateway.cli import build_parser

    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))
    path = _write_pcap(tmp_path / "demo.pcap", gaps_ns=[0, 300_000_000, 300_000_000])
    args = build_parser().parse_args([
        "run", "--replay-file", path, "--loop", "1", "--listen", "0",
        "--stats-interval", "0.1",
    ])
    rc = args.func(args)
    assert rc == 0
    err = capsys.readouterr().err
    assert "lost unknown" in err
    assert "reordered" in err
