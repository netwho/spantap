# SPDX-License-Identifier: GPL-2.0-or-later
"""The gateway: ring buffer, PCAP-over-IP server, receiver bookkeeping."""

import socket
import struct
import threading
import time

import pytest

from spantap import config
from spantap.encap import ErspanConfig, ErspanEncapsulator
from spantap.gateway.pcapoverip import (
    DEFAULT_PORT,
    PcapOverIpServer,
    pcap_file_header,
)
from spantap.gateway.receiver import ErspanReceiver
from spantap.gateway.ring import FrameRing
from spantap.gateway.service import GatewayController
from spantap.sources.pcapread import open_packet_stream
from spantap.sources.synth import SyntheticSource

import io


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))
    yield


# -- ring ------------------------------------------------------------------

def test_ring_discards_until_somebody_is_listening():
    ring = FrameRing(max_frames=8)
    assert ring.put((0, b"x" * 10, 10)) is False
    assert ring.snapshot()["skipped_idle"] == 1
    ring.start_accepting()
    assert ring.put((0, b"x" * 10, 10)) is True
    assert ring.depth() == 1


def test_ring_drops_oldest_and_counts_it():
    ring = FrameRing(max_frames=4)
    ring.start_accepting()
    for i in range(10):
        ring.put((i, bytes([i]) * 4, 4))
    got = ring.get_batch(max_items=10, timeout=0)
    assert [item[0] for item in got] == [6, 7, 8, 9]   # the newest four survive
    snap = ring.snapshot()
    assert snap["dropped"] == 6 and snap["high_water"] == 4


def test_ring_is_also_bounded_by_bytes():
    ring = FrameRing(max_frames=1_000_000, max_bytes=4096)
    ring.start_accepting()
    for i in range(20):
        ring.put((i, b"x" * 1000, 1000))
    assert ring.snapshot()["bytes"] <= 4096
    assert ring.snapshot()["dropped"] >= 15


def test_ring_never_empties_itself_completely_on_an_oversized_frame():
    ring = FrameRing(max_frames=4, max_bytes=1024)
    ring.start_accepting()
    assert ring.put((0, b"x" * 5000, 5000)) is True
    assert ring.depth() == 1        # kept, rather than looping forever


def test_get_batch_blocks_briefly_then_returns_empty():
    ring = FrameRing()
    began = time.monotonic()
    assert ring.get_batch(timeout=0.2) == []
    assert 0.15 < time.monotonic() - began < 1.0


# -- receiver bookkeeping --------------------------------------------------

def test_sequence_tracking_counts_loss_and_reordering():
    rx = ErspanReceiver()
    assert rx._track_sequence("10.0.0.1", 1, 0) == 0     # first packet, no baseline
    assert rx._track_sequence("10.0.0.1", 1, 1) == 0
    assert rx._track_sequence("10.0.0.1", 1, 5) == 3     # 2,3,4 missing
    assert rx.lost == 3
    assert rx._track_sequence("10.0.0.1", 1, 3) == 0     # a late arrival
    assert rx.reordered == 1
    assert rx.lost == 3                                   # not counted twice
    # A different source has its own counter.
    assert rx._track_sequence("10.0.0.2", 1, 900) == 0
    assert rx.lost == 3


def test_sequence_wrap_is_not_four_billion_lost_frames():
    rx = ErspanReceiver()
    rx._track_sequence("10.0.0.1", 1, 0xFFFFFFFF)
    assert rx._track_sequence("10.0.0.1", 1, 0) == 0
    assert rx.lost == 0


def test_session_filter_rejects_bad_values():
    with pytest.raises(ValueError):
        ErspanReceiver(session_id=1024)


# -- PCAP-over-IP server ---------------------------------------------------

@pytest.fixture
def server():
    ring = FrameRing(max_frames=256)
    srv = PcapOverIpServer(ring, bind="127.0.0.1", port=0)
    srv.start()
    yield srv, ring
    srv.stop()


def read_exactly(sock, n, timeout=5.0):
    sock.settimeout(timeout)
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            break
        out += chunk
    return out


def test_client_gets_a_classic_pcap_stream(server):
    srv, ring = server
    c = socket.create_connection(("127.0.0.1", srv.port_in_use), timeout=5)
    try:
        header = read_exactly(c, 24)
        assert header == pcap_file_header(1, srv.snaplen)
        for _ in range(20):
            if ring.accepting:
                break
            time.sleep(0.05)
        frames = [p.data for p in SyntheticSource(count=10, seed=4)]
        for i, f in enumerate(frames):
            ring.put((1_700_000_000_000_000_000 + i * 1000, f, len(f)))
        payload = b""
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            payload += read_exactly(c, 1, timeout=0.5) or b""
            try:
                c.settimeout(0.3)
                payload += c.recv(65536)
            except socket.timeout:
                pass
            got = list(open_packet_stream(io.BytesIO(header + payload)))
            if len(got) >= 10:
                break
        got = [p.data for p in open_packet_stream(io.BytesIO(header + payload))]
        assert got == frames
    finally:
        c.close()


def test_only_one_client_at_a_time(server):
    srv, ring = server
    first = socket.create_connection(("127.0.0.1", srv.port_in_use), timeout=5)
    try:
        read_exactly(first, 24)
        second = socket.create_connection(("127.0.0.1", srv.port_in_use), timeout=5)
        try:
            assert read_exactly(second, 24, timeout=2) == b""   # refused, closed
        finally:
            second.close()
        for _ in range(40):
            if srv.refused:
                break
            time.sleep(0.05)
        assert srv.refused == 1
    finally:
        first.close()


def test_a_client_that_leaves_without_reading_frees_the_slot(server):
    """A port scan or health check must not take the gateway offline."""
    srv, ring = server
    probe = socket.create_connection(("127.0.0.1", srv.port_in_use), timeout=5)
    probe.close()
    real = None
    for _ in range(60):
        try:
            real = socket.create_connection(("127.0.0.1", srv.port_in_use), timeout=2)
            if read_exactly(real, 24, timeout=2):
                break
            real.close(); real = None
        except OSError:
            pass
        time.sleep(0.05)
    try:
        assert real is not None, "the slot was never released"
    finally:
        if real:
            real.close()


def test_frames_are_dropped_while_nobody_is_connected(server):
    srv, ring = server
    for i in range(5):
        ring.put((i, b"x" * 64, 64))
    assert ring.snapshot()["skipped_idle"] == 5
    assert ring.depth() == 0


# -- the whole gateway, over a real socket ---------------------------------

def _send_erspan(frames, dst="127.0.0.1", session_id=7, mtu=65535):
    cfg = ErspanConfig(dst=dst, src="127.0.0.1", session_id=session_id, mtu=mtu)
    enc = ErspanEncapsulator(cfg)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        for frame in frames:
            sock.sendto(enc.encapsulate(frame), (dst, 0))
            time.sleep(0.001)
    finally:
        sock.close()


def _can_use_raw_sockets() -> bool:
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW).close()
        socket.socket(socket.AF_INET, socket.SOCK_RAW, 47).close()
        return True
    except (PermissionError, OSError):
        return False


needs_raw = pytest.mark.skipif(
    not _can_use_raw_sockets(), reason="needs CAP_NET_RAW for raw GRE sockets"
)


@needs_raw
def test_end_to_end_erspan_in_pcap_out():
    cfg = config.default_gateway_config()
    cfg["serve"]["port"] = 0
    cfg["receive"]["session_id"] = 7
    gw = GatewayController()
    gw.start(cfg)
    try:
        port = gw._server.port_in_use
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            header = read_exactly(client, 24)
            assert header[:4] == b"\xd4\xc3\xb2\xa1"
            for _ in range(40):
                if gw._ring.accepting:
                    break
                time.sleep(0.05)

            frames = [p.data for p in SyntheticSource(count=30, seed=9)]
            threading.Thread(target=_send_erspan, args=(frames,), daemon=True).start()

            payload = b""
            deadline = time.monotonic() + 10
            got = []
            while time.monotonic() < deadline:
                try:
                    client.settimeout(0.4)
                    chunk = client.recv(65536)
                except socket.timeout:
                    chunk = b""
                if chunk:
                    payload += chunk
                got = [p.data for p in open_packet_stream(io.BytesIO(header + payload))]
                if len(got) >= len(frames):
                    break
            assert got == frames
        finally:
            client.close()

        snap = gw.snapshot(sample=False)
        assert snap["receiver"]["received"] == 30
        assert snap["receiver"]["lost"] == 0
        assert snap["ring"]["dropped"] == 0
        assert snap["stats"]["protocols"]["network"]
    finally:
        gw.stop()
    assert gw.snapshot(sample=False)["state"] in ("stopped", "idle")


@needs_raw
def test_a_session_filter_ignores_other_sessions():
    cfg = config.default_gateway_config()
    cfg["serve"]["port"] = 0
    cfg["receive"]["session_id"] = 11
    gw = GatewayController()
    gw.start(cfg)
    try:
        frames = [p.data for p in SyntheticSource(count=6, seed=2)]
        _send_erspan(frames, session_id=11)
        _send_erspan(frames, session_id=12)
        for _ in range(60):
            snap = gw.snapshot(sample=False)
            if snap["receiver"]["received"] >= 6 and snap["receiver"]["filtered"] >= 6:
                break
            time.sleep(0.05)
        assert snap["receiver"]["received"] == 6
        assert snap["receiver"]["filtered"] == 6
    finally:
        gw.stop()


@needs_raw
def test_a_second_gateway_is_refused_and_leaves_the_first_alone():
    cfg = config.default_gateway_config()
    cfg["serve"]["port"] = 0
    gw = GatewayController()
    gw.start(cfg)
    try:
        with pytest.raises(RuntimeError):
            gw.start(cfg)
        assert gw.snapshot(sample=False)["state"] == "running"
    finally:
        gw.stop()


@needs_raw
def test_a_busy_port_fails_cleanly_without_leaking_the_receiver():
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    cfg = config.default_gateway_config()
    cfg["serve"]["port"] = port
    gw = GatewayController()
    try:
        with pytest.raises(OSError):
            gw.start(cfg)
        assert gw.snapshot(sample=False)["state"] == "idle"
        assert not any(t.name == "spantap-gw-rx" for t in threading.enumerate())
    finally:
        blocker.close()
        gw.stop()


# -- gateway configuration -------------------------------------------------

def test_gateway_config_round_trip():
    cfg = config.default_gateway_config()
    cfg["receive"]["session_id"] = 23
    cfg["serve"]["port"] = 40000
    saved = config.save_gateway(cfg)
    assert saved["receive"]["session_id"] == 23
    assert config.load_gateway()["serve"]["port"] == 40000


@pytest.mark.parametrize("blank", [None, "", "all"])
def test_blank_session_means_every_session(blank):
    cfg = config.default_gateway_config()
    cfg["receive"]["session_id"] = blank
    assert config.validate_gateway(cfg)["receive"]["session_id"] is None


@pytest.mark.parametrize("bad", [
    {"receive": {"session_id": 1024}},
    {"receive": {"bind": "not-an-ip"}},
    {"serve": {"port": -1}},
    {"serve": {"port": 70000}},
    {"serve": {"snaplen": 32}},
    {"buffer": {"max_frames": 1}},
    {"buffer": {"max_mib": 0}},
])
def test_bad_gateway_config_is_rejected(bad):
    with pytest.raises(config.ConfigError):
        config.validate_gateway(bad)


def test_a_corrupt_gateway_config_falls_back_to_defaults():
    import os
    os.makedirs(config.config_dir(), exist_ok=True)
    with open(config.gateway_path(), "w") as fh:
        fh.write("{ not json")
    assert config.load_gateway_or_default() == config.default_gateway_config()
    with pytest.raises(config.ConfigError):
        config.load_gateway()
