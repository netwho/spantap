# SPDX-License-Identifier: GPL-2.0-or-later
"""The gateway mirroring a local interface, and the loop that must not happen.

The gateway writes captured frames to Wireshark over tcp/57012. If that
session crosses the interface being captured, every frame written is itself
captured and written again — and the second copy contains the first, so each
round is larger than the last. These tests are mostly about that one clause
being impossible to remove.
"""

import os
import shutil
import socket
import subprocess
import threading
import time

import pytest

from spantap.config import ConfigError, default_gateway_config, validate_gateway
from spantap.exclusion import build_gateway_plan
from spantap.gateway.delivery import DeliveryTracker
from spantap.gateway.livecapture import LiveCapture
from spantap.gateway.service import GatewayController


@pytest.fixture(autouse=True)
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))


# -- the clause that stops the feedback loop --------------------------------

def test_the_pcapoverip_exclusion_is_always_present():
    """Unlike the simulator's, this one is not conditional on anything."""
    plan = build_gateway_plan()
    mandatory = [c for c in plan.clauses if c.mandatory]
    assert len(mandatory) == 1
    assert "not (tcp port 57012)" == mandatory[0].expr


def test_a_user_filter_cannot_displace_it():
    """It is ANDed in, never substituted — and it comes first."""
    plan = build_gateway_plan(user_filter="tcp port 57012")
    expr = plan.expression()
    assert expr.startswith("not (tcp port 57012) and ")
    assert expr == "not (tcp port 57012) and (tcp port 57012)"


def test_a_user_filter_mentioning_vlan_cannot_move_the_ground():
    """`vlan` shifts libpcap's offsets for everything after it, so order is
    not cosmetic: the exclusion must be compiled before the user's filter."""
    expr = build_gateway_plan(user_filter="vlan 100").expression()
    assert expr.index("not (tcp port 57012)") < expr.index("vlan 100")


def test_the_gre_clause_is_advisory_and_off_by_default():
    """Double delivery is untidy; the loop is fatal. They are not the same."""
    assert all("ip proto 47" not in c.expr for c in build_gateway_plan().clauses)
    plan = build_gateway_plan(erspan_receiving=True)
    gre = [c for c in plan.clauses if "ip proto 47" in c.expr]
    assert len(gre) == 1 and gre[0].mandatory is False


def test_the_filter_names_the_port_that_is_actually_bound():
    """serve.port 0 means the kernel picks. Excluding 57012 then protects
    nothing at all, and nothing would look wrong until the link melted."""
    config = default_gateway_config()
    config["source"] = "live"
    config["live"]["iface"] = "lo"
    config["serve"]["port"] = 0

    gw = GatewayController()
    gw.start(config)
    try:
        snap = gw.snapshot(sample=False)
        bound = snap["server"]["port"]
        assert bound not in (0, 57012), "the kernel did not pick a port"
        assert "not (tcp port %d)" % bound in snap["receiver"]["filter"]
    finally:
        gw.stop()


@pytest.mark.skipif(not shutil.which("dumpcap"),
                    reason="needs dumpcap to compile a filter for real")
@pytest.mark.parametrize("user_filter", [
    None, "port 80", "vlan 100", "host 10.0.0.1 and not port 53",
    "tcp port 57012", "icmp or arp",
])
def test_every_filter_this_can_emit_compiles(user_filter):
    """A filter that libpcap rejects means the gateway does not start at all,
    so the exclusions are worth nothing if they cannot be compiled."""
    for gre in (False, True):
        for ssh in (False, True):
            expr = build_gateway_plan(erspan_receiving=gre, exclude_ssh=ssh,
                                      user_filter=user_filter).expression()
            rc = subprocess.run(["dumpcap", "-d", "-i", "lo", "-f", expr],
                                capture_output=True, text=True, timeout=30)
            assert rc.returncode == 0, "dumpcap refused %r:\n%s" % (expr, rc.stderr)


# -- what a local capture can and cannot claim ------------------------------

def test_loss_is_reported_as_unknown_not_zero():
    """ERSPAN has a GRE sequence number; a local capture has nothing. Saying
    "0 lost" would be a claim we cannot make."""
    cap = LiveCapture("lo", capture_cmd=["/bin/true"])
    snap = cap.snapshot()
    assert snap["lost"] is None
    assert snap["reordered"] is None
    assert snap["kind"] == "live"


def test_an_erspan_snapshot_says_which_kind_it_is():
    from spantap.gateway.receiver import ErspanReceiver
    assert ErspanReceiver().snapshot()["kind"] == "erspan"


def test_an_empty_interface_is_refused():
    from spantap.sources.live import CaptureError
    with pytest.raises(CaptureError):
        LiveCapture("")


def test_config_refuses_a_live_source_with_no_interface():
    with pytest.raises(ConfigError) as exc:
        validate_gateway({"source": "live"})
    assert "live.iface is required" in str(exc.value)


def test_an_older_config_file_still_loads():
    """0.3.x wrote no 'source' key. It must keep meaning ERSPAN."""
    out = validate_gateway({"receive": {"bind": "10.0.0.1"},
                            "serve": {"port": 57013}})
    assert out["source"] == "erspan"
    assert out["receive"]["bind"] == "10.0.0.1"


def test_an_unknown_source_is_refused():
    with pytest.raises(ConfigError):
        validate_gateway({"source": "carrier-pigeon"})


# -- the accounting identity ------------------------------------------------

def test_every_arrived_frame_is_accounted_for():
    acct = DeliveryTracker.reconcile(
        {"received": 100}, {"dropped": 7, "skipped_idle": 13, "depth": 5},
        {"frames_sent": 75})
    assert acct["difference"] == 0 and acct["balanced"]


def test_an_unexplained_gap_is_reported_as_unbalanced():
    """This is the failure a tap must never have quietly."""
    acct = DeliveryTracker.reconcile(
        {"received": 1000}, {"dropped": 0, "skipped_idle": 0, "depth": 0},
        {"frames_sent": 400})
    assert acct["difference"] == 600
    assert not acct["balanced"]


def test_a_few_frames_in_flight_are_not_called_a_bug():
    acct = DeliveryTracker.reconcile(
        {"received": 100}, {"dropped": 0, "skipped_idle": 0, "depth": 0},
        {"frames_sent": 98})
    assert acct["balanced"], "two frames between the ring and the socket is normal"


def test_delivery_rates_are_never_negative_across_a_restart():
    """Counters only ever grow, but a snapshot from before a restart can make
    the arithmetic go backwards if it is not clamped."""
    d = DeliveryTracker()
    d.sample(1000, 100000, min_gap=0.0)
    time.sleep(0.01)
    d.sample(5, 500, min_gap=0.0)          # as if the server were replaced
    assert all(fps >= 0 and bps >= 0 for _, fps, bps in d.history)


def test_a_reader_is_recorded_once_and_closed_on_leaving():
    d = DeliveryTracker()
    d.note_client("10.0.0.9:5555", True, time.time(), 0)
    d.note_client("10.0.0.9:5555", True, time.time(), 40)   # still the same one
    assert len(d.clients) == 1 and d.clients[0]["until"] is None
    d.note_client(None, False, None, 120)
    assert d.clients[0]["until"] is not None
    assert d.clients[0]["frames_at_end"] == 120
    d.note_client("10.0.0.9:6666", True, time.time(), 120)
    assert len(d.clients) == 2


# -- end to end -------------------------------------------------------------

def _chatter(port, n):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)

    def serve():
        for _ in range(n):
            try:
                conn, _ = srv.accept()
                conn.recv(64)
                conn.sendall(b"PONG")
                conn.close()
            except OSError:
                return

    threading.Thread(target=serve, daemon=True).start()
    for _ in range(n):
        conn = socket.create_connection(("127.0.0.1", port))
        conn.sendall(b"PING")
        conn.recv(64)
        conn.close()
        time.sleep(0.05)
    srv.close()


@pytest.mark.skipif(not shutil.which("dumpcap"), reason="needs dumpcap")
@pytest.mark.skipif(os.getuid() != 0 and not os.access("/usr/bin/dumpcap", os.X_OK),
                    reason="dumpcap is not executable by this user")
def test_a_local_capture_reaches_a_pcapoverip_client():
    """The whole chain, with a socket standing in for Wireshark."""
    config = default_gateway_config()
    config["source"] = "live"
    config["live"]["iface"] = "lo"
    config["live"]["filter"] = "tcp port 19771"
    config["serve"]["port"] = 0

    gw = GatewayController()
    gw.start(config)
    try:
        port = gw.snapshot(sample=False)["server"]["port"]
        client = socket.create_connection(("127.0.0.1", port), timeout=10)
        client.settimeout(10)
        header = client.recv(24)
        assert len(header) == 24, "no pcap header was written on connect"
        assert header[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                              b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")

        for _ in range(40):
            if gw.snapshot(sample=False)["server"]["connected"]:
                break
            time.sleep(0.1)

        _chatter(19771, 4)

        deadline = time.time() + 15
        payload = b""
        while time.time() < deadline and len(payload) < 200:
            try:
                chunk = client.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            payload += chunk
        client.close()

        snap = gw.snapshot(sample=False)
        assert snap["receiver"]["received"] > 0, "nothing was captured"
        assert snap["server"]["frames_sent"] > 0, "nothing reached the client"
        assert len(payload) > 0, "the client received no frame data"
        assert snap["accounting"]["balanced"], snap["accounting"]
    finally:
        gw.stop()


@pytest.mark.skipif(not shutil.which("dumpcap"), reason="needs dumpcap")
def test_a_bad_interface_fails_at_start_not_silently():
    """A gateway that says "running" and never delivers a frame is worse than
    one that refuses to start."""
    config = default_gateway_config()
    config["source"] = "live"
    config["live"]["iface"] = "definitely-not-an-interface"
    config["serve"]["port"] = 0

    gw = GatewayController()
    with pytest.raises(Exception) as exc:
        gw.start(config)
    assert "definitely-not-an-interface" in str(exc.value) or "exited" in str(exc.value)
    assert gw.snapshot(sample=False)["state"] != "running"


@pytest.mark.skipif(not shutil.which("dumpcap"), reason="needs dumpcap")
def test_a_failed_start_does_not_leave_the_port_bound():
    """The server binds before the source is built, so a source that fails
    must take the listener down with it — or the next start cannot bind.

    The port has to be a FIXED one, and the check has to be an actual bind of
    that port. An earlier version of this test bound port 0 and asserted the
    controller's server attribute was None: both are true whether or not the
    listener was closed, so it passed with the cleanup deleted.
    """
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    config = default_gateway_config()
    config["source"] = "live"
    config["live"]["iface"] = "definitely-not-an-interface"
    config["serve"]["port"] = port

    gw = GatewayController()
    with pytest.raises(Exception):
        gw.start(config)

    # No SO_REUSEADDR: a socket still listening on this port must make this
    # fail, which is precisely what is being tested.
    again = socket.socket()
    try:
        again.bind(("127.0.0.1", port))
    except OSError as exc:
        pytest.fail("the listener is still bound to tcp/%d after a failed "
                    "start: %s" % (port, exc))
    finally:
        again.close()
