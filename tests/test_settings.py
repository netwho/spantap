# SPDX-License-Identifier: GPL-2.0-or-later
"""The UI's own settings: validation, lock-out protection, and the API."""

import json
import os
import socket
import ssl
import subprocess
import threading

import pytest

from spantap import config
from spantap.webui import certs
from spantap.webui.server import make_server

from test_webui import body_json, raw, req, status  # noqa: F401


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.delenv("SPANTAP_TOKEN", raising=False)
    monkeypatch.delenv("SPANTAP_ALLOW_HOSTS", raising=False)
    yield


def cert_pair():
    if not certs.openssl_path():
        pytest.skip("openssl not available")
    info = certs.generate_selfsigned(["nettools"], ["127.0.0.1"])
    return info["cert"], info["key"]


# -- validation ------------------------------------------------------------

def test_defaults_are_wide_and_tokenless():
    """0.0.0.0 by default; the token is serve()'s job, not a save-time error."""
    d = config.default_webui_config()
    assert d["bind"] == "0.0.0.0" and d["token"] == ""
    assert config.validate_webui({}, check_bind=False)["port"] == 8420


def test_a_saved_tokenless_wide_bind_still_loads(tmp_path):
    config.save_webui({"port": 8421}, check_bind=False)
    loaded = config.load_webui_or_default()
    assert loaded["bind"] == "0.0.0.0" and loaded["port"] == 8421


def test_binding_wide_without_a_token_is_refused():
    """The one mistake that would silently expose an unauthenticated UI."""
    with pytest.raises(config.ConfigError) as exc:
        config.validate_webui({"bind": "0.0.0.0", "token": ""}, check_bind=False)
    assert "token" in str(exc.value)


def test_a_wide_bind_with_a_token_is_fine():
    out = config.validate_webui(
        {"bind": "0.0.0.0", "token": "long-enough-token"}, check_bind=False)
    assert out["bind"] == "0.0.0.0"


@pytest.mark.parametrize("bad", [
    {"port": 0}, {"port": 99999},
    {"bind": "not-an-ip"},
    {"allow_hosts": ["has space"]},
    {"allow_hosts": ["-leading-dash"]},
    {"allow_hosts": "x" * 300},
    {"bind": "127.0.0.1", "token": "short"},
    {"tls": {"key": "/tmp/only-a-key.pem"}},
])
def test_bad_settings_are_rejected(bad):
    base = {"bind": "127.0.0.1", "token": ""}
    base.update(bad)
    with pytest.raises(config.ConfigError):
        config.validate_webui(base, check_bind=False)


def test_a_certificate_that_cannot_be_loaded_is_refused(tmp_path):
    """Saving an unusable certificate would make the UI fail to start."""
    junk = tmp_path / "not-a-cert.pem"
    junk.write_text("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n")
    with pytest.raises(config.ConfigError) as exc:
        config.validate_webui({"tls": {"cert": str(junk)}}, check_bind=False)
    assert "could not be loaded" in str(exc.value)

    with pytest.raises(config.ConfigError) as exc:
        config.validate_webui({"tls": {"cert": str(tmp_path / "absent.pem")}},
                              check_bind=False)
    assert "not found" in str(exc.value)


def test_a_real_certificate_is_accepted():
    cert, key = cert_pair()
    out = config.validate_webui({"tls": {"cert": cert, "key": key}}, check_bind=False)
    assert out["tls"]["cert"] == cert


def test_an_address_this_host_does_not_own_is_refused():
    with pytest.raises(config.ConfigError) as exc:
        config.validate_webui(
            {"bind": "203.0.113.99", "port": 8421, "token": "long-enough-token"})
    assert "cannot listen" in str(exc.value)


def test_the_address_already_in_use_by_this_server_is_not_reported_as_taken():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    try:
        # Without `current` this is "address in use"; with it, it is us.
        with pytest.raises(config.ConfigError):
            config.validate_webui({"bind": "127.0.0.1", "port": port})
        out = config.validate_webui({"bind": "127.0.0.1", "port": port},
                                    current={"bind": "127.0.0.1", "port": port})
        assert out["port"] == port
    finally:
        sock.close()


def test_a_wildcard_current_bind_covers_every_address_on_that_port():
    """The effective server can be forced to 0.0.0.0 by env/compose while the
    saved config, and so the Settings form, still says 127.0.0.1 (or the
    other way around) — a compose profile that overrides bind is exactly
    this. A bind-test at that port always collides with the already-running
    server no matter which address string either side uses, so it must be
    skipped rather than reported as "address already in use" — which is
    what it looked like from the caller's own socket, not a stranger's.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    try:
        out = config.validate_webui(
            {"bind": "127.0.0.1", "port": port},
            current={"bind": "0.0.0.0", "port": port})
        assert out["port"] == port
    finally:
        sock.close()


def test_the_token_is_never_handed_back_to_the_browser():
    saved = config.save_webui({"bind": "127.0.0.1", "token": "a-secret-token"})
    redacted = config.redact_webui(saved)
    assert "token" not in redacted and redacted["token_set"] is True
    assert "a-secret-token" not in json.dumps(redacted)
    assert oct(os.stat(config.webui_path()).st_mode)[-3:] == "600"


def test_unreadable_settings_fall_back_instead_of_failing():
    os.makedirs(config.config_dir(), exist_ok=True)
    with open(config.webui_path(), "w") as fh:
        fh.write("{ not json at all")
    assert config.load_webui_or_default() == config.default_webui_config()


def test_settings_that_stopped_working_fall_back(tmp_path):
    """A certificate deleted after it was saved must not break startup."""
    cert, key = cert_pair()
    config.save_webui({"bind": "127.0.0.1", "tls": {"cert": cert, "key": key}})
    os.unlink(cert)
    assert config.load_webui_or_default()["tls"]["cert"] == ""


# -- certificate generation ------------------------------------------------

def test_generated_certificate_covers_the_names_and_addresses_asked_for():
    if not certs.openssl_path():
        pytest.skip("openssl not available")
    info = certs.generate_selfsigned(["nettools", "nettools.lab"], ["192.0.2.50"])
    assert "nettools" in info["dns"] and "nettools.lab" in info["dns"]
    assert "192.0.2.50" in info["ips"]
    assert "localhost" in info["dns"] and "127.0.0.1" in info["ips"]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(info["cert"], info["key"])          # it really loads
    assert oct(os.stat(info["key"]).st_mode)[-3:] == "600"
    text = subprocess.run([certs.openssl_path(), "x509", "-in", info["cert"],
                           "-noout", "-text"], capture_output=True, text=True).stdout
    assert "DNS:nettools" in text and "IP Address:192.0.2.50" in text


# -- uploading your own certificate -----------------------------------------

def test_an_uploaded_cert_and_key_are_stored_and_loadable(tmp_path, monkeypatch):
    cert, key = cert_pair()
    directory = tmp_path / "tls"
    result = certs.save_uploaded(open(cert).read(), open(key).read(), str(directory))
    assert result["cert"] == str(directory / "cert.pem")
    assert result["key"] == str(directory / "key.pem")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(result["cert"], result["key"])   # it really loads
    assert oct(os.stat(result["cert"]).st_mode)[-3:] == "644"
    assert oct(os.stat(result["key"]).st_mode)[-3:] == "600"


def test_an_uploaded_combined_pem_needs_no_separate_key(tmp_path):
    cert, key = cert_pair()
    combined = open(cert).read() + open(key).read()
    directory = tmp_path / "tls"
    result = certs.save_uploaded(combined, "", str(directory))
    assert result["key"] == ""                 # the settings form leaves Key blank
    assert result["cert"] == str(directory / "cert.pem")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(result["cert"])          # loads cert and key from one file
    # It holds the private key, so it gets the key's permission, not 0644.
    assert oct(os.stat(result["cert"]).st_mode)[-3:] == "600"


def test_an_uploaded_non_certificate_is_refused_and_leaves_nothing(tmp_path):
    directory = tmp_path / "tls"
    with pytest.raises(certs.CertUploadError) as exc:
        certs.save_uploaded("this is not a certificate at all", "", str(directory))
    assert "does not look like a PEM" in str(exc.value)
    assert not os.path.exists(directory) or os.listdir(directory) == []


def test_a_cert_that_does_not_actually_load_is_refused_and_leaves_nothing(tmp_path):
    directory = tmp_path / "tls"
    junk = "-----BEGIN CERTIFICATE-----\nbm90IGEgcmVhbCBjZXJ0\n-----END CERTIFICATE-----\n"
    with pytest.raises(certs.CertUploadError) as exc:
        certs.save_uploaded(junk, "", str(directory))
    assert "could not be loaded" in str(exc.value)
    assert not os.path.exists(directory) or os.listdir(directory) == []


def test_an_uploaded_cert_without_a_matching_key_is_refused(tmp_path):
    cert, _ = cert_pair()
    other = certs.generate_selfsigned(["someone-else"], [], directory=str(tmp_path / "other"))
    directory = tmp_path / "tls"
    with pytest.raises(certs.CertUploadError):
        certs.save_uploaded(open(cert).read(), open(other["key"]).read(), str(directory))
    assert not os.path.exists(directory) or os.listdir(directory) == []


def test_an_empty_upload_is_refused(tmp_path):
    with pytest.raises(certs.CertUploadError) as exc:
        certs.save_uploaded("", "", str(tmp_path / "tls"))
    assert "no certificate" in str(exc.value)


def test_an_oversized_upload_is_refused(tmp_path):
    with pytest.raises(certs.CertUploadError) as exc:
        certs.save_uploaded("-----BEGIN CERTIFICATE-----\n" + "x" * 200_000, "",
                            str(tmp_path / "tls"))
    assert "too large" in str(exc.value)


def test_an_upload_replaces_the_previous_one_not_alongside_it(tmp_path):
    """Uploading and self-signed generation fill the same one slot."""
    cert1, key1 = cert_pair()
    directory = tmp_path / "tls"
    first = certs.save_uploaded(open(cert1).read(), open(key1).read(), str(directory))
    cert2, key2 = cert_pair()
    second = certs.save_uploaded(open(cert2).read(), open(key2).read(), str(directory))
    assert first["cert"] == second["cert"] == str(directory / "cert.pem")
    assert sorted(os.listdir(directory)) == ["cert.pem", "key.pem"]   # no leftover .tmp- files
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(second["cert"], second["key"])       # the newer pair, not the older


# -- using your own CA -----------------------------------------------------

@pytest.fixture(scope="module")
def ca_issued(tmp_path_factory):
    """A leaf signed by a private CA, plus the concatenated chain."""
    if not certs.openssl_path():
        pytest.skip("openssl not available")
    d = tmp_path_factory.mktemp("ca")
    ssl_ = str(d)
    run = lambda *a: subprocess.run(list(a), capture_output=True, check=True)
    run(certs.openssl_path(), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "3650", "-keyout", ssl_ + "/ca-key.pem", "-out", ssl_ + "/ca.pem",
        "-subj", "/CN=Test Root CA")
    run(certs.openssl_path(), "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", ssl_ + "/srv-key.pem", "-out", ssl_ + "/srv.csr",
        "-subj", "/CN=nettools.lab.example")
    with open(ssl_ + "/ext.cnf", "w") as fh:
        fh.write("subjectAltName=DNS:nettools.lab.example,DNS:nettools,IP:127.0.0.1\n")
    run(certs.openssl_path(), "x509", "-req", "-in", ssl_ + "/srv.csr",
        "-CA", ssl_ + "/ca.pem", "-CAkey", ssl_ + "/ca-key.pem", "-CAcreateserial",
        "-out", ssl_ + "/srv.pem", "-days", "397", "-extfile", ssl_ + "/ext.cnf")
    with open(ssl_ + "/fullchain.pem", "w") as out:
        for part in ("/srv.pem", "/ca.pem"):
            out.write(open(ssl_ + part).read())
    return {"leaf": ssl_ + "/srv.pem", "chain": ssl_ + "/fullchain.pem",
            "key": ssl_ + "/srv-key.pem"}


@pytest.mark.parametrize("which", ["leaf", "chain"])
def test_a_ca_issued_certificate_is_accepted(ca_issued, which):
    out = config.validate_webui(
        {"tls": {"cert": ca_issued[which], "key": ca_issued["key"]}}, check_bind=False)
    assert out["tls"]["cert"] == ca_issued[which]


def test_a_ca_issued_certificate_is_described_correctly(ca_issued):
    info = certs.describe(ca_issued["chain"])
    assert info["subject"] == "nettools.lab.example"
    assert info["issuer"] == "Test Root CA"
    assert info["self_signed"] is False
    assert "nettools" in info["dns"] and "127.0.0.1" in info["ips"]
    assert 300 < info["days_left"] < 400


def test_a_self_signed_certificate_is_marked_as_such():
    if not certs.openssl_path():
        pytest.skip("openssl not available")
    made = certs.generate_selfsigned(["box"], [])
    assert certs.describe(made["cert"])["self_signed"] is True


def test_names_the_certificate_does_not_cover_are_reported(ca_issued):
    from spantap.webui.server import GuiServer
    saved = config.validate_webui({
        "bind": "127.0.0.1",
        "allow_hosts": ["nettools", "somewhere.else"],
        "tls": {"cert": ca_issued["leaf"], "key": ca_issued["key"]},
    }, check_bind=False)
    info, warnings = GuiServer._cert_report(saved)
    assert info["issuer"] == "Test Root CA"
    assert len(warnings) == 1
    assert "somewhere.else" in warnings[0]
    assert "nettools," not in warnings[0]      # the covered one is not listed


def test_a_covered_certificate_produces_no_warnings(ca_issued):
    from spantap.webui.server import GuiServer
    saved = config.validate_webui({
        "bind": "127.0.0.1",
        "allow_hosts": ["nettools", "nettools.lab.example"],
        "tls": {"cert": ca_issued["chain"], "key": ca_issued["key"]},
    }, check_bind=False)
    assert GuiServer._cert_report(saved)[1] == []


def test_wildcards_cover_one_label_only():
    info = {"dns": ["*.lab.example"], "ips": []}
    assert certs.uncovered(info, ["host.lab.example"]) == []
    assert certs.uncovered(info, ["deep.host.lab.example"]) == ["deep.host.lab.example"]
    assert certs.uncovered(info, ["lab.example"]) == ["lab.example"]


def test_an_expired_certificate_is_called_out(ca_issued, tmp_path):
    if not certs.openssl_path():
        pytest.skip("openssl not available")
    from spantap.webui.server import GuiServer
    old_cert = tmp_path / "old.pem"
    old_key = tmp_path / "old-key.pem"
    subprocess.run(
        [certs.openssl_path(), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(old_key), "-out", str(old_cert),
         "-subj", "/CN=expired", "-not_before", "20200101000000Z",
         "-not_after", "20200201000000Z"],
        capture_output=True)
    if not old_cert.exists():
        pytest.skip("this openssl cannot backdate a certificate")
    saved = config.default_webui_config()
    saved["tls"] = {"cert": str(old_cert), "key": str(old_key)}
    info, warnings = GuiServer._cert_report(saved)
    assert any("expired" in w for w in warnings), warnings


def test_san_splitting():
    dns, ips = certs.build_san(["a.example", "10.0.0.1"], ["192.0.2.1"])
    assert dns[:1] == ["a.example"]
    assert "10.0.0.1" in ips and "192.0.2.1" in ips


# -- the API ---------------------------------------------------------------

@pytest.fixture
def server():
    # port 0 is the caller forcing an ephemeral port, exactly as --port would;
    # loopback is forced the same way, as --bind 127.0.0.1 would.
    srv, gui = make_server("127.0.0.1", 0, overridden=["bind", "port"])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, gui, srv.server_address[1]
    gui.controller.stop(); gui.gateway.stop()
    srv.shutdown(); srv.server_close()


def test_settings_round_trip_through_the_api(server):
    _, _, port = server
    r = body_json(raw(port, req(port, "GET", "/api/webui")))
    assert r["saved"]["bind"] == "0.0.0.0"
    assert r["restart_needed"] is False
    assert "token" not in r["saved"]

    r = body_json(raw(port, req(port, "POST", "/api/webui", {"settings": {
        "bind": "127.0.0.1", "port": 8420,
        "allow_hosts": ["nettools", "nettools.lab"],
        "token": "a-long-enough-token",
    }})))
    assert r["saved"]["allow_hosts"] == ["nettools", "nettools.lab"]
    assert r["saved"]["token_set"] is True
    assert r["restart_needed"] is True          # the running server differs now
    assert "allow_hosts" in r["differs"]


def test_saving_without_a_token_field_keeps_the_existing_one(server):
    _, _, port = server
    raw(port, req(port, "POST", "/api/webui",
                  {"settings": {"bind": "127.0.0.1", "token": "keep-this-token"}}))
    r = body_json(raw(port, req(port, "POST", "/api/webui",
                                {"settings": {"bind": "127.0.0.1", "port": 8421}})))
    assert r["saved"]["token_set"] is True
    assert config.load_webui_or_default()["token"] == "keep-this-token"


def test_clearing_the_token_is_explicit(server):
    _, _, port = server
    raw(port, req(port, "POST", "/api/webui",
                  {"settings": {"bind": "127.0.0.1", "token": "some-token-here"}}))
    r = body_json(raw(port, req(port, "POST", "/api/webui", {"settings": {
        "bind": "127.0.0.1", "clear_token": True}})))
    assert r["saved"]["token_set"] is False


def test_the_api_generates_a_token_instead_of_locking_you_out(server):
    """config.validate_webui() refuses this (see above) — the API is kinder.

    A person using the Settings tab has no way to invent a token from a
    blocked request; the CLI and any script pushing config directly still get
    the strict, explicit error tested above via ``auto_token`` defaulting to
    False everywhere except this one save path.
    """
    _, _, port = server
    r = raw(port, req(port, "POST", "/api/webui",
                      {"settings": {"bind": "0.0.0.0", "token": ""}}))
    assert status(r) == 200
    body = body_json(r)
    assert body["saved"]["token_set"] is True
    saved = config.load_webui_or_default()
    assert saved["bind"] == "0.0.0.0"
    assert saved["token"]                      # something was actually generated
    assert len(saved["token"]) >= 8


def test_the_generated_token_is_only_ever_in_the_save_response(server):
    _, _, port = server
    r = body_json(raw(port, req(port, "POST", "/api/webui",
                                {"settings": {"bind": "0.0.0.0", "token": ""}})))
    token = config.load_webui_or_default()["token"]
    assert token
    assert any(token in u for u in r["urls"])
    # A later, unrelated GET must not hand it back.
    later = body_json(raw(port, req(port, "GET", "/api/webui")))
    assert "urls" not in later
    assert token not in json.dumps(later)


def test_a_loopback_bind_still_gets_urls_without_a_token(server):
    _, _, port = server
    r = body_json(raw(port, req(port, "POST", "/api/webui",
                                {"settings": {"bind": "127.0.0.1"}})))
    assert r["urls"]
    assert all("token=" not in u for u in r["urls"])


def test_an_explicit_token_is_kept_not_replaced(server):
    _, _, port = server
    r = body_json(raw(port, req(port, "POST", "/api/webui", {"settings": {
        "bind": "0.0.0.0", "token": "my-own-chosen-token",
    }})))
    assert config.load_webui_or_default()["token"] == "my-own-chosen-token"
    assert any("my-own-chosen-token" in u for u in r["urls"])


# -- the auto_token parameter, at the config layer --------------------------

def test_validate_webui_still_refuses_by_default():
    """auto_token defaults to False: CLI and scripted callers keep the hard
    error, so a config pushed without a token fails loudly rather than
    silently exposing an unauthenticated UI."""
    with pytest.raises(config.ConfigError):
        config.validate_webui({"bind": "0.0.0.0", "token": ""}, check_bind=False)


def test_validate_webui_with_auto_token_generates_one():
    out = config.validate_webui({"bind": "0.0.0.0", "token": ""},
                                check_bind=False, auto_token=True)
    assert out["token"]
    assert len(out["token"]) >= 16


def test_auto_token_does_not_fire_when_one_is_already_given():
    out = config.validate_webui({"bind": "0.0.0.0", "token": "already-set-token"},
                                check_bind=False, auto_token=True)
    assert out["token"] == "already-set-token"


def test_auto_token_does_not_fire_on_loopback():
    out = config.validate_webui({"bind": "127.0.0.1", "token": ""},
                                check_bind=False, auto_token=True)
    assert out["token"] == ""


def test_selfsigned_through_the_api(server):
    if not certs.openssl_path():
        pytest.skip("openssl not available")
    _, _, port = server
    r = body_json(raw(port, req(port, "POST", "/api/webui/selfsigned",
                                {"names": ["nettools"], "addresses": ["192.0.2.7"]})))
    assert os.path.isfile(r["cert"]) and os.path.isfile(r["key"])
    assert "192.0.2.7" in r["ips"]
    # and it is immediately acceptable as a setting
    saved = body_json(raw(port, req(port, "POST", "/api/webui", {"settings": {
        "bind": "127.0.0.1", "tls": {"cert": r["cert"], "key": r["key"]}}})))
    assert saved["saved"]["tls"]["cert"] == r["cert"]


def test_tls_upload_through_the_api(server):
    _, _, port = server
    cert, key = cert_pair()
    r = body_json(raw(port, req(port, "POST", "/api/webui/tls/upload",
                                {"cert": open(cert).read(), "key": open(key).read()})))
    assert os.path.isfile(r["cert"]) and os.path.isfile(r["key"])
    assert r["info"]["subject"]
    # and it is immediately acceptable as a setting, same as self-signed
    saved = body_json(raw(port, req(port, "POST", "/api/webui", {"settings": {
        "bind": "127.0.0.1", "tls": {"cert": r["cert"], "key": r["key"]}}})))
    assert saved["saved"]["tls"]["cert"] == r["cert"]


def test_a_bad_tls_upload_through_the_api_is_refused(server):
    _, _, port = server
    r = raw(port, req(port, "POST", "/api/webui/tls/upload",
                      {"cert": "not a certificate", "key": ""}))
    assert status(r) == 400
    assert "does not look like a PEM" in body_json(r)["error"]


def test_flags_are_reported_as_overriding_the_saved_settings():
    """A value forced on the command line must not look editable in the UI."""
    srv, gui = make_server("127.0.0.1", 0, token="forced-token",
                           allow_hosts=["forced.example"], overridden=["token", "allow_hosts"])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        r = body_json(raw(port, req(port, "GET", "/api/webui?token=forced-token")))
        assert set(r["effective"]["overridden"]) == {"token", "allow_hosts"}
        # allow_hosts differs from the (empty) saved value but is forced, so it
        # must not be reported as needing a restart.
        assert "allow_hosts" not in r["differs"]
        assert "token" not in r["differs"]
    finally:
        gui.controller.stop(); gui.gateway.stop()
        srv.shutdown(); srv.server_close()


# -- host path vs container path -------------------------------------------

def test_a_host_path_gets_pointed_at_the_container_path(tmp_path, monkeypatch):
    """Typing the path your shell shows you is the obvious mistake to make."""
    mount = tmp_path / "tls"
    mount.mkdir()
    (mount / "cert.pem").write_text("x")
    monkeypatch.setattr(config, "tls_dir", lambda: str(mount))
    monkeypatch.setattr(config, "in_container", lambda: True)

    with pytest.raises(config.ConfigError) as exc:
        config.validate_webui(
            {"tls": {"cert": "/home/user/spantap/tls/cert.pem"}}, check_bind=False)
    message = str(exc.value)
    assert "not found" in message
    assert str(mount / "cert.pem") in message          # names the right path
    assert "inside the container" in message


def test_an_unmatched_path_still_explains_the_mount(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "tls_dir", lambda: str(tmp_path / "nowhere"))
    monkeypatch.setattr(config, "in_container", lambda: True)
    with pytest.raises(config.ConfigError) as exc:
        config.validate_webui({"tls": {"cert": "/srv/x/my.pem"}}, check_bind=False)
    assert "mounted at /tls" in str(exc.value)
    assert "/tls/my.pem" in str(exc.value)


def test_no_container_advice_when_not_in_a_container(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "tls_dir", lambda: str(tmp_path / "nowhere"))
    monkeypatch.setattr(config, "in_container", lambda: False)
    with pytest.raises(config.ConfigError) as exc:
        config.validate_webui({"tls": {"cert": "/srv/x/my.pem"}}, check_bind=False)
    assert "container" not in str(exc.value)


def test_an_unreadable_key_says_who_owns_it_and_who_we_are(tmp_path, monkeypatch):
    """"Permission denied" alone sends people in circles across a container boundary."""
    key = tmp_path / "key.pem"
    key.write_text("x")
    cert, real_key = cert_pair()

    # The owner is faked as well as our own uid. Otherwise the branch taken
    # depends on who happens to be running pytest: as root the file is owned
    # by uid 0 and the "wrong group" advice is right, but run the same test as
    # uid 10001 and the file is owned by us, so a different (also correct)
    # message comes back and the assertions below fail for no real reason.
    real_stat = config.os.stat

    class OwnedByRoot:
        st_mode = 0o100600
        st_uid = 0
        st_gid = 0

    monkeypatch.setattr(config.os, "access", lambda p, m: not str(p).endswith("key.pem"))
    monkeypatch.setattr(
        config.os, "stat",
        lambda p, *a, **k: OwnedByRoot() if str(p).endswith("key.pem") else real_stat(p))
    monkeypatch.setattr(config.os, "getuid", lambda: 10001)
    monkeypatch.setattr(config.os, "getgid", lambda: 10001)
    monkeypatch.setattr(config.os, "getgroups", lambda: [10001])

    with pytest.raises(config.ConfigError) as exc:
        config.validate_webui({"tls": {"cert": cert, "key": real_key}}, check_bind=False)
    message = str(exc.value)
    assert "is not readable" in message
    assert "this process runs as uid 10001" in message   # who we are
    assert "owned by uid" in message                     # who owns it
    assert "chgrp 10001" in message                      # what to run


# -- importing a certificate from the command line (install.sh's paste) -----

def _pem(path):
    with open(path) as fh:
        return fh.read()


def test_split_pem_takes_blocks_in_any_order_and_ignores_the_rest():
    cert, key = cert_pair()
    text = "Bag Attributes\n  junk: 1\n" + _pem(key) + "\n\n" + _pem(cert)
    chain, private = certs.split_pem(text)
    assert chain.startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE KEY" not in chain
    assert "PRIVATE KEY" in private and "CERTIFICATE" not in private


def test_split_pem_keeps_a_chain_in_the_order_given(tmp_path):
    cert, key = cert_pair()
    other = certs.generate_selfsigned(["other"], [], directory=str(tmp_path))["cert"]
    chain, _ = certs.split_pem(_pem(cert) + _pem(other) + _pem(key))
    assert chain.index(_pem(cert).strip()) < chain.index(_pem(other).strip())


@pytest.mark.parametrize("text, message", [
    ("", "no certificate"),
    ("hello", "no certificate"),
    ("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "no private key"),
])
def test_split_pem_says_what_is_missing(text, message):
    with pytest.raises(certs.CertUploadError) as exc:
        certs.split_pem(text)
    assert message in str(exc.value)


def test_split_pem_refuses_two_keys():
    cert, key = cert_pair()
    with pytest.raises(certs.CertUploadError) as exc:
        certs.split_pem(_pem(cert) + _pem(key) + _pem(key))
    assert "more than one" in str(exc.value)


def _encrypted_key(tmp_path, key):
    out = tmp_path / "enc.pem"
    subprocess.run([certs.openssl_path(), "pkey", "-in", key, "-out", str(out),
                    "-aes256", "-passout", "pass:secret"], check=True)
    return _pem(out)


def test_an_encrypted_key_is_refused_with_advice_not_a_prompt(tmp_path):
    cert, key = cert_pair()
    enc = _encrypted_key(tmp_path, key)
    with pytest.raises(certs.CertUploadError) as exc:
        certs.split_pem(_pem(cert) + enc)
    assert "passphrase" in str(exc.value)
    # save_uploaded on its own (the Settings tab's path) must refuse too,
    # rather than letting OpenSSL prompt on a terminal and hang the server
    directory = tmp_path / "tls"
    with pytest.raises(certs.CertUploadError) as exc:
        certs.save_uploaded(_pem(cert), enc, str(directory))
    assert "passphrase" in str(exc.value)
    assert os.listdir(directory) == []


def _run_cli(argv, stdin_text=""):
    return subprocess.run(
        [__import__("sys").executable, "-m", "spantap", *argv],
        input=stdin_text, capture_output=True, text=True, timeout=60,
        env=dict(os.environ))


def test_token_is_made_before_the_ui_ever_ran_and_then_kept():
    """install.sh prints the URLs before the UI starts; they must stay valid."""
    first = _run_cli(["token"])
    assert first.returncode == 0, first.stderr
    token = first.stdout.strip()
    assert len(token) >= 8
    assert config.load_webui_raw()["token"] == token
    urls = _run_cli(["token", "--urls"])
    assert urls.returncode == 0
    assert urls.stdout.splitlines()[0] == "http://127.0.0.1:8420/?token=" + token


def test_token_on_loopback_says_none_is_needed():
    config.save_webui({"bind": "127.0.0.1"}, check_bind=False)
    r = _run_cli(["token"])
    assert r.returncode == 1 and "needs none" in r.stderr
    assert _run_cli(["token", "--urls"]).stdout.strip() == "http://127.0.0.1:8420/"


def test_tls_import_from_stdin_stores_it_and_points_the_ui_at_it():
    cert, key = cert_pair()
    # settings already hold values that must survive the import untouched
    config.save_webui({"bind": "127.0.0.1", "allow_hosts": ["nettools"],
                       "token": "a-long-enough-token"}, check_bind=False)
    r = _run_cli(["tls", "import"], _pem(cert) + _pem(key))
    assert r.returncode == 0, r.stderr
    assert "certificate stored" in r.stdout and "nettools" in r.stdout
    saved = config.load_webui_raw()
    assert saved["tls"]["cert"].endswith("/tls/cert.pem")
    assert saved["tls"]["key"].endswith("/tls/key.pem")
    assert saved["token"] == "a-long-enough-token"
    assert saved["allow_hosts"] == ["nettools"]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(saved["tls"]["cert"], saved["tls"]["key"])


def test_tls_import_from_files():
    cert, key = cert_pair()
    r = _run_cli(["tls", "import", "--cert", cert, "--key", key])
    assert r.returncode == 0, r.stderr
    assert config.load_webui_raw()["tls"]["key"].endswith("key.pem")


def test_tls_import_of_a_mismatched_pair_changes_nothing(tmp_path):
    cert, _ = cert_pair()
    other = certs.generate_selfsigned(["other"], [], directory=str(tmp_path / "o"))
    before = config.load_webui_raw()
    r = _run_cli(["tls", "import"], _pem(cert) + _pem(other["key"]))
    assert r.returncode == 2
    assert "could not be loaded" in r.stderr
    assert config.load_webui_raw() == before


def test_tls_import_does_not_need_the_ui_port_to_be_free():
    cert, key = cert_pair()
    busy = socket.socket()
    busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    busy.bind(("127.0.0.1", 0))
    busy.listen(1)
    try:
        config.save_webui({"port": busy.getsockname()[1]}, check_bind=False)
        r = _run_cli(["tls", "import"], _pem(cert) + _pem(key))
        assert r.returncode == 0, r.stderr
    finally:
        busy.close()
