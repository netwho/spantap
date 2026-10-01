# SPDX-License-Identifier: GPL-2.0-or-later
import json
import os
import threading
import time

import pytest

from spantap import config
from spantap.controller import SimulationController, preview_filter
from spantap.stats import Stats


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))
    yield


def base_profile(**over):
    p = config.default_profile()
    p["target"]["dst"] = "198.51.100.5"
    p["target"]["src"] = "192.0.2.1"
    p["output"]["mode"] = "dry"
    p["synth"]["count"] = 60
    p["synth"]["pps"] = 0
    for k, v in over.items():
        p[k] = v
    return p


# -- validation ------------------------------------------------------------

def test_defaults_validate():
    assert config.validate(config.default_profile())["source"] == "synth"


@pytest.mark.parametrize("bad", [
    {"target": {"dst": 12345}},
    {"target": {"dst": ["10.0.0.1"]}},
    {"target": {"dst": True}},
    {"live": {"iface": 7}},
    {"replay": {"file": {"a": 1}}},
])
def test_non_string_addresses_are_a_config_error_not_a_crash(bad):
    """A hand-edited profile must never escape as an AttributeError."""
    with pytest.raises(config.ConfigError):
        config.validate(bad)


@pytest.mark.parametrize("bad", [
    {"target": {"session_id": 1024}},
    {"target": {"vlan": 4096}},
    {"target": {"mtu": 10}},
    {"target": {"dst": "not-an-ip"}},
    {"target": {"dst": "224.0.0.1"}},
    {"source": "telepathy"},
    {"synth": {"scenario": "nonsense"}},
    {"output": {"mode": "carrier-pigeon"}},
    {"live": {"iface": "eth0; rm -rf /"}},
])
def test_out_of_range_values_are_rejected(bad):
    with pytest.raises(config.ConfigError):
        config.validate(bad)


def test_output_path_must_look_like_a_capture_file(tmp_path):
    """Start is reachable from the browser, so the write target is constrained."""
    with pytest.raises(config.ConfigError):
        config.validate({"output": {"mode": "pcap", "pcap_path": str(tmp_path / "authorized_keys")}})
    ok = config.validate({"output": {"mode": "pcap", "pcap_path": str(tmp_path / "a.pcapng")}})
    assert ok["output"]["pcap_path"].endswith("a.pcapng")


def test_output_path_refuses_a_symlink(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("important")
    link = tmp_path / "link.pcap"
    os.symlink(victim, link)
    with pytest.raises(config.ConfigError):
        config.validate({"output": {"mode": "pcap", "pcap_path": str(link)}})
    assert victim.read_text() == "important"


def test_for_run_requires_what_a_run_actually_needs(tmp_path):
    no_receiver = config.default_profile()
    no_receiver["target"]["dst"] = ""
    config.validate(no_receiver)                       # fine as a draft
    with pytest.raises(config.ConfigError):
        config.validate(no_receiver, for_run=True)     # no receiver
    p = base_profile()
    p["source"] = "replay"
    p["replay"]["file"] = str(tmp_path / "missing.pcap")
    with pytest.raises(config.ConfigError):
        config.validate(p, for_run=True)


def test_unknown_keys_are_dropped_not_rejected():
    p = config.default_profile()
    p["from_a_future_version"] = {"x": 1}
    assert "from_a_future_version" not in config.validate(p)


# -- storage ---------------------------------------------------------------

def test_profile_round_trip_and_last_used():
    config.save_profile("lab", base_profile())
    assert config.list_profiles() == ["lab"]
    assert config.last_used() == "lab"
    assert config.load_profile("lab")["target"]["dst"] == "198.51.100.5"
    config.delete_profile("lab")
    assert config.list_profiles() == []
    assert config.last_used() is None


@pytest.mark.parametrize("name", ["", "../escape", "with/slash", "x" * 41, "no spaces"])
def test_profile_names_are_constrained(name):
    with pytest.raises(config.ConfigError):
        config.save_profile(name, base_profile())


def test_a_corrupt_profile_does_not_break_startup():
    config.save_profile("good", base_profile())
    os.makedirs(config.profiles_dir(), exist_ok=True)
    with open(os.path.join(config.profiles_dir(), "broken.json"), "w") as fh:
        json.dump({"target": {"dst": 999}}, fh)
    config.set_last_used("broken")
    # falls back to the built-in default, not to the broken file's value
    assert config.load_last_or_default() == config.default_profile()
    with pytest.raises(config.ConfigError):
        config.load_profile("broken")
    assert "good" in config.list_profiles()


def test_saving_is_atomic():
    config.save_profile("keep", base_profile())
    before = config.load_profile("keep")
    original = json.dump
    json.dump = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    try:
        with pytest.raises(RuntimeError):
            config.save_profile("keep", base_profile())
    finally:
        json.dump = original
    assert config.load_profile("keep") == before
    assert not [f for f in os.listdir(config.profiles_dir()) if f.startswith(".tmp-")]


# -- preview ---------------------------------------------------------------

def test_preview_filter_explains_itself():
    r = preview_filter(base_profile())
    assert "ip proto 47" in r["expression"]
    assert any("PCAP-over-IP" in c["reason"] for c in r["clauses"])


# -- controller ------------------------------------------------------------

def test_start_run_and_finish():
    c = SimulationController()
    c.start(base_profile())
    for _ in range(100):
        if c.snapshot()["state"] == "finished":
            break
        time.sleep(0.05)
    snap = c.snapshot()
    assert snap["state"] == "finished", snap["error"]
    assert snap["stats"]["packets"] == 60
    assert snap["stats"]["protocols"]["network"]


def test_a_second_start_is_refused():
    c = SimulationController()
    p = base_profile()
    p["synth"]["count"] = 0
    p["synth"]["pps"] = 200
    c.start(p)
    try:
        with pytest.raises(RuntimeError):
            c.start(p)
    finally:
        c.stop()
    assert not c.is_running()


def test_concurrent_starts_leave_exactly_one_run():
    """Six browsers hitting Start at once must not yield six transmitters."""
    c = SimulationController()
    p = base_profile()
    p["synth"]["count"] = 0
    p["synth"]["pps"] = 100
    started = []
    barrier = threading.Barrier(6)

    def go():
        barrier.wait()
        try:
            c.start(p)
            started.append(True)
        except RuntimeError:
            pass

    threads = [threading.Thread(target=go) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    try:
        assert len(started) == 1
        assert sum(1 for t in threading.enumerate() if t.name == "spantap-sim") == 1
    finally:
        c.stop()
    assert sum(1 for t in threading.enumerate() if t.name == "spantap-sim") == 0


def test_stop_is_prompt_and_idempotent():
    c = SimulationController()
    p = base_profile()
    p["synth"]["count"] = 0
    p["synth"]["pps"] = 500
    c.start(p)
    time.sleep(0.2)
    began = time.monotonic()
    c.stop()
    assert time.monotonic() - began < 3
    assert c.snapshot()["state"] == "finished"
    c.stop()  # must not raise
    c.start(p)  # and the controller is reusable
    c.stop()


def test_the_default_receiver_is_loopback():
    assert config.default_profile()["target"]["dst"] == "127.0.0.1"
    # and it is a complete, runnable destination, not a placeholder
    assert config.validate(config.default_profile(), for_run=True)["target"]["dst"] == "127.0.0.1"


def test_the_cli_defaults_to_loopback_too():
    from spantap.cli import build_parser
    assert build_parser().parse_args(["synth"]).dst == "127.0.0.1"
    assert build_parser().parse_args(["synth", "--dst", "10.0.0.5"]).dst == "10.0.0.5"


def test_a_bad_profile_never_starts_a_thread():
    c = SimulationController()
    bad = config.default_profile()
    bad["target"]["dst"] = ""
    with pytest.raises(config.ConfigError):
        c.start(bad)
    assert c.snapshot()["state"] == "idle"
    assert sum(1 for t in threading.enumerate() if t.name == "spantap-sim") == 0


# -- stats -----------------------------------------------------------------

def test_sample_is_thread_safe():
    """Several pollers sampling at once must never produce a negative rate."""
    s = Stats(interval=0.0, classify_traffic=False)
    stop = threading.Event()

    def produce():
        while not stop.is_set():
            s.record(b"\x00" * 64, 100)

    def poll():
        while not stop.is_set():
            s.sample(min_gap=0.0)

    workers = [threading.Thread(target=produce) for _ in range(2)] + \
              [threading.Thread(target=poll) for _ in range(8)]
    [t.start() for t in workers]
    time.sleep(1.0)
    stop.set()
    [t.join() for t in workers]
    assert s.history
    assert all(pps >= 0 and bps >= 0 for _, pps, bps in s.history)


def test_protocol_counters_add_up():
    s = Stats(interval=0.0, classify_traffic=True)
    frame = (b"\x02" * 6 + b"\x03" * 6 + b"\x08\x00"
             + b"\x45" + b"\x00" * 8 + b"\x06" + b"\x00" * 10
             + b"\x00\x50\x9c\x40" + b"\x00" * 16)
    for _ in range(10):
        s.record(frame, len(frame) + 36)
    snap = s.snapshot()
    assert snap["protocols"]["network"] == {"IPv4": 10}
    assert snap["protocols"]["transport"] == {"TCP": 10}
    assert snap["protocols"]["application"] == {"HTTP": 10}


# -- the erspan-sim -> spantap rename ---------------------------------------
#
# config_dir() must not make an upgrade look like every profile, account and
# gateway setting was reset. These bypass the autouse isolated_config fixture
# (it always sets SPANTAP_CONFIG_DIR) because the point is to exercise both
# the "no override, XDG default" path and the "explicit override" path — the
# native install and the Docker image, respectively.

def test_an_old_named_sibling_is_adopted_under_xdg_default(tmp_path, monkeypatch):
    monkeypatch.delenv("SPANTAP_CONFIG_DIR", raising=False)
    monkeypatch.delenv("ERSPAN_SIM_CONFIG_DIR", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    legacy = tmp_path / "erspan-sim"
    (legacy / "profiles").mkdir(parents=True)
    (legacy / "profiles" / "lab.json").write_text(json.dumps(base_profile()))

    new_dir = config.config_dir()
    assert new_dir == str(tmp_path / "spantap")
    assert os.path.isdir(new_dir)
    assert not legacy.exists()
    assert config.list_profiles() == ["lab"]


def test_an_old_named_sibling_is_adopted_next_to_an_explicit_override(tmp_path, monkeypatch):
    """The Docker case: the volume is mounted at a new path, but its content
    still has the old subdirectory name until the first run moves it."""
    monkeypatch.delenv("ERSPAN_SIM_CONFIG_DIR", raising=False)
    parent = tmp_path / "var-lib-spantap" / ".config"
    legacy = parent / "erspan-sim"
    legacy.mkdir(parents=True)
    (legacy / "gateway.json").write_text(json.dumps(config.default_gateway_config()))
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(parent / "spantap"))

    new_dir = config.config_dir()
    assert new_dir == str(parent / "spantap")
    assert os.path.isfile(os.path.join(new_dir, "gateway.json"))
    assert not legacy.exists()

    # idempotent: calling it again with the volume already migrated must not
    # error just because there is no legacy sibling left to find.
    assert config.config_dir() == new_dir


def test_a_fresh_install_has_no_legacy_sibling_to_find(tmp_path, monkeypatch):
    monkeypatch.delenv("SPANTAP_CONFIG_DIR", raising=False)
    monkeypatch.delenv("ERSPAN_SIM_CONFIG_DIR", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    new_dir = config.config_dir()
    assert new_dir == str(tmp_path / "spantap")
    assert not os.path.exists(new_dir)   # nothing to migrate, nothing created either
    assert config.list_profiles() == []


def test_an_unedited_legacy_env_var_still_works_directly(tmp_path, monkeypatch):
    """An old systemd unit or docker run -e nobody has updated yet."""
    monkeypatch.delenv("SPANTAP_CONFIG_DIR", raising=False)
    legacy = tmp_path / "wherever-it-was"
    legacy.mkdir()
    monkeypatch.setenv("ERSPAN_SIM_CONFIG_DIR", str(legacy))
    assert config.config_dir() == str(legacy)


def test_legacy_env_helper_prefers_the_new_name():
    assert config.legacy_env("NEW_X", "OLD_X") is None
    import os as _os
    _os.environ["OLD_X"] = "old"
    try:
        assert config.legacy_env("NEW_X", "OLD_X") == "old"
        _os.environ["NEW_X"] = "new"
        assert config.legacy_env("NEW_X", "OLD_X") == "new"
    finally:
        _os.environ.pop("OLD_X", None)
        _os.environ.pop("NEW_X", None)
