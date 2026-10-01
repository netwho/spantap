# SPDX-License-Identifier: GPL-2.0-or-later
"""The web UI's API, including the things a hostile local page would try."""

import json
import socket
import ssl
import subprocess
import threading
import time

import pytest

from spantap.webui.server import MAX_BODY, make_server


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))
    srv, gui = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv, gui, srv.server_address[1]
    gui.controller.stop()
    gui.gateway.stop()
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


def raw(port, request: bytes, timeout: float = 10.0) -> bytes:
    """Send bytes on the wire and read the whole reply — no HTTP client.

    Every request built by ``req`` carries ``Connection: close``, so reading
    to end-of-stream gets exactly one complete response.
    """
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(request)
        s.settimeout(timeout)
        out = b""
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
        return out
    finally:
        s.close()


def req(port, method, path, body=None, headers=None):
    head = ["%s %s HTTP/1.1" % (method, path), "Host: 127.0.0.1:%d" % port]
    payload = b""
    if body is not None:
        payload = json.dumps(body).encode()
        head.append("Content-Type: application/json")
        head.append("Content-Length: %d" % len(payload))
    for k, v in (headers or {}).items():
        head.append("%s: %s" % (k, v))
    head.append("Connection: close")
    return ("\r\n".join(head) + "\r\n\r\n").encode() + payload


def status(response: bytes) -> int:
    return int(response.split(b" ", 2)[1])


def body_json(response: bytes):
    return json.loads(response.split(b"\r\n\r\n", 1)[1].decode())


# -- the basics ------------------------------------------------------------

def test_index_and_bootstrap(server):
    _, _, port = server
    page = raw(port, req(port, "GET", "/"))
    assert status(page) == 200 and b"<title>spantap</title>" in page
    data = body_json(raw(port, req(port, "GET", "/api/bootstrap")))
    assert "defaults" in data and "interfaces" in data and "capabilities" in data


def test_unknown_endpoint_is_404(server):
    _, _, port = server
    assert status(raw(port, req(port, "GET", "/api/nope"))) == 404


# -- the guard -------------------------------------------------------------

def test_foreign_host_header_is_refused(server):
    _, _, port = server
    r = raw(port, b"GET /api/state HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
    assert status(r) == 403


def test_missing_host_header_is_refused(server):
    _, _, port = server
    assert status(raw(port, b"GET /api/state HTTP/1.1\r\nConnection: close\r\n\r\n")) == 400


def test_cross_origin_is_refused_even_from_the_same_machine(server):
    _, _, port = server
    for origin in ("http://evil.example", "http://localhost:1234",
                   "http://127.0.0.1:9999", "https://127.0.0.1:%d" % port):
        r = raw(port, req(port, "GET", "/api/state", headers={"Origin": origin}))
        assert status(r) == 403, origin


def test_our_own_origin_is_accepted(server):
    _, _, port = server
    r = raw(port, req(port, "GET", "/api/state",
                      headers={"Origin": "http://127.0.0.1:%d" % port}))
    assert status(r) == 200


def test_token_is_required_when_set(tmp_path, monkeypatch):
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))
    srv, gui = make_server("127.0.0.1", 0, token="s3cret")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        assert status(raw(port, req(port, "GET", "/api/state"))) == 401
        assert status(raw(port, req(port, "GET", "/api/state",
                                    headers={"X-Erspan-Token": "wrong"}))) == 401
        # A non-ASCII header must be a clean 401, not a 500.
        bad = raw(port, req(port, "GET", "/api/state").replace(
            b"Connection: close", b"X-Erspan-Token: \xc3\xa9\r\nConnection: close"))
        assert status(bad) == 401
        assert status(raw(port, req(port, "GET", "/api/state",
                                    headers={"X-Erspan-Token": "s3cret"}))) == 200
        # The renamed header works too — the old one is accepted alongside it,
        # not instead of it, so nothing that already speaks it breaks.
        assert status(raw(port, req(port, "GET", "/api/state",
                                    headers={"X-Spantap-Token": "s3cret"}))) == 200
        assert status(raw(port, req(port, "GET", "/api/state?token=s3cret"))) == 200
    finally:
        srv.shutdown(); srv.server_close()


@pytest.fixture
def token_server(tmp_path, monkeypatch):
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))
    srv, gui = make_server("127.0.0.1", 0, token="s3cret-token")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, gui, srv.server_address[1]
    gui.controller.stop(); gui.gateway.stop()
    srv.shutdown(); srv.server_close()


def html_request(port, path="/", headers=None):
    head = {"Accept": "text/html,application/xhtml+xml"}
    head.update(headers or {})
    return raw(port, req(port, "GET", path, headers=head))


def test_a_browser_without_a_token_gets_a_page_not_json(token_server):
    """Opening the bare address must not dead-end on raw JSON."""
    _, _, port = token_server
    r = html_request(port)
    assert status(r) == 401
    assert b"text/html" in r.split(b"\r\n\r\n", 1)[0]
    assert b"This page needs an access token" in r
    assert b'name="token"' in r          # it offers somewhere to put it


def test_the_token_page_says_when_a_token_was_rejected(token_server):
    _, _, port = token_server
    r = html_request(port, "/?token=wrong")
    assert status(r) == 401
    assert b"was not accepted" in r


def test_a_token_in_the_url_is_remembered_in_a_cookie(token_server):
    _, _, port = token_server
    r = html_request(port, "/?token=s3cret-token")
    assert status(r) == 200
    headers = r.split(b"\r\n\r\n", 1)[0].decode()
    assert "Set-Cookie: erspan_token=s3cret-token" in headers
    assert "HttpOnly" in headers and "SameSite=Strict" in headers
    assert "Secure" not in headers       # plain HTTP here


def test_the_cookie_alone_opens_the_bare_address(token_server):
    _, _, port = token_server
    r = html_request(port, "/", {"Cookie": "erspan_token=s3cret-token"})
    assert status(r) == 200
    assert b"<title>spantap</title>" in r
    # and it is not re-set on every request
    assert "Set-Cookie" not in r.split(b"\r\n\r\n", 1)[0].decode()


def test_a_wrong_cookie_does_not_open_it(token_server):
    _, _, port = token_server
    r = html_request(port, "/", {"Cookie": "erspan_token=nope"})
    assert status(r) == 401
    r = raw(port, req(port, "GET", "/api/state", headers={"Cookie": "erspan_token=nope"}))
    assert status(r) == 401


def test_the_cookie_also_authorises_the_api(token_server):
    """The page's own fetches rely on this once the token leaves the URL."""
    _, _, port = token_server
    r = raw(port, req(port, "GET", "/api/state",
                      headers={"Cookie": "erspan_token=s3cret-token"}))
    assert status(r) == 200


def test_api_clients_still_get_json_not_html(token_server):
    """curl and scripts must not suddenly receive a login page."""
    _, _, port = token_server
    r = raw(port, req(port, "GET", "/api/state"))
    assert status(r) == 401
    assert b"application/json" in r.split(b"\r\n\r\n", 1)[0]
    assert body_json(r)["error"]


def test_the_form_is_not_blocked_by_the_content_security_policy(token_server):
    """form-action 'none' would stop the submit with no visible error."""
    _, _, port = token_server
    headers = html_request(port).split(b"\r\n\r\n", 1)[0].decode()
    csp = [h for h in headers.splitlines() if h.startswith("Content-Security-Policy")][0]
    assert "form-action 'self'" in csp


def test_a_wrong_name_also_explains_itself_in_html(token_server):
    _, _, port = token_server
    r = raw(port, b"GET / HTTP/1.1\r\nHost: elsewhere\r\nAccept: text/html\r\n"
                  b"Connection: close\r\n\r\n")
    assert status(r) == 403
    assert b"Not reachable by that name" in r
    assert b"--allow-host elsewhere" in r


# -- request smuggling -----------------------------------------------------

def _smuggle(port, first: bytes, oversize: bytes):
    """One connection: a request that errors, with a second request in its body."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        s.sendall(first + oversize)
        s.settimeout(3)
        out = b""
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
        return out
    finally:
        s.close()


@pytest.mark.parametrize("content_length,expect", [
    (str(MAX_BODY + 10), 413),
    ("banana", 400),
    ("-5", 400),
])
def test_an_unread_body_is_never_parsed_as_the_next_request(server, content_length, expect):
    """The classic keep-alive desync: it would bypass the Origin check."""
    srv, gui, port = server
    smuggled = req(port, "POST", "/api/start",
                   {"profile": {"source": "synth", "target": {"dst": "198.51.100.5"},
                                "output": {"mode": "dry"}, "synth": {"count": 5}}})
    first = (
        "POST /api/preview HTTP/1.1\r\n"
        "Host: 127.0.0.1:%d\r\n"
        "Origin: http://evil.example\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %s\r\n\r\n" % (port, content_length)
    ).encode()
    out = _smuggle(port, first, smuggled + b"x" * 16)

    assert out.count(b"HTTP/1.") == 1, "a second response means the body was executed"
    assert status(out) in (expect, 403)
    assert gui.controller.snapshot()["state"] == "idle"


def test_a_well_formed_body_still_works_on_keep_alive(server):
    """The desync fix must not break ordinary pipelined requests."""
    _, _, port = server
    one = req(port, "POST", "/api/preview", {"profile": {"target": {"dst": "10.0.0.5"}}})
    one = one.replace(b"Connection: close\r\n", b"")
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        s.sendall(one)
        time.sleep(0.2)
        s.sendall(one)
        s.settimeout(2)
        out = b""
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
        assert out.count(b"HTTP/1.1 200") == 2
    finally:
        s.close()


# -- start / stop ----------------------------------------------------------

def test_start_validation_errors_are_400_not_500(server):
    _, _, port = server
    r = raw(port, req(port, "POST", "/api/start", {"profile": {
        "source": "synth", "target": {"dst": ""}}}))
    assert status(r) == 400
    assert "dst" in body_json(r)["error"]


def test_start_refuses_to_write_outside_a_capture_file(server, tmp_path):
    _, gui, port = server
    victim = tmp_path / "authorized_keys"
    victim.write_text("ssh-ed25519 AAAA...")
    r = raw(port, req(port, "POST", "/api/start", {"profile": {
        "source": "synth",
        "target": {"dst": "198.51.100.5", "src": "192.0.2.1"},
        "synth": {"count": 5},
        "output": {"mode": "pcap", "pcap_path": str(victim)},
    }}))
    assert status(r) == 400
    assert victim.read_text().startswith("ssh-ed25519")


def test_full_run_through_the_api(server, tmp_path):
    _, gui, port = server
    out = tmp_path / "run.pcap"
    r = raw(port, req(port, "POST", "/api/start", {"profile": {
        "source": "synth",
        "target": {"dst": "198.51.100.5", "src": "192.0.2.1", "session_id": 9},
        "synth": {"count": 40, "pps": 0, "seed": 3},
        "output": {"mode": "pcap", "pcap_path": str(out)},
    }}))
    assert status(r) == 200, body_json(r)
    for _ in range(100):
        snap = body_json(raw(port, req(port, "GET", "/api/state")))
        if snap["state"] in ("finished", "error"):
            break
        time.sleep(0.05)
    assert snap["state"] == "finished", snap["error"]
    assert snap["stats"]["packets"] == 40
    assert out.exists() and out.stat().st_size > 0

    from spantap.decode import decode_erspan2
    from spantap.sources.pcapread import open_packet_stream
    with open(out, "rb") as fh:
        decoded = [decode_erspan2(p.data) for p in open_packet_stream(fh)]
    assert len(decoded) == 40 and all(d.session_id == 9 for d in decoded)


def test_profiles_through_the_api(server):
    _, _, port = server
    p = {"source": "synth", "target": {"dst": "198.51.100.5"}, "output": {"mode": "dry"}}
    r = body_json(raw(port, req(port, "POST", "/api/profiles/save",
                                {"name": "lab", "profile": p})))
    assert r["profiles"] == ["lab"]
    loaded = body_json(raw(port, req(port, "GET", "/api/profiles/load?name=lab")))
    assert loaded["profile"]["target"]["dst"] == "198.51.100.5"
    assert status(raw(port, req(port, "GET", "/api/profiles/load?name=nope"))) == 404
    assert status(raw(port, req(port, "POST", "/api/profiles/save",
                                {"name": "../escape", "profile": p}))) == 400
    r = body_json(raw(port, req(port, "POST", "/api/profiles/delete", {"name": "lab"})))
    assert r["profiles"] == []


# -- reaching it from another host -----------------------------------------

def test_an_unknown_name_is_refused_but_says_how_to_fix_it(server):
    """The most likely way to hit this is a DNS name, so the 403 must explain."""
    _, _, port = server
    r = raw(port, b"GET /api/state HTTP/1.1\r\nHost: nettools:8420\r\n"
                  b"Connection: close\r\n\r\n")
    assert status(r) == 403
    message = body_json(r)["error"]
    assert "--allow-host nettools" in message


def test_allow_host_lets_a_dns_name_through(tmp_path, monkeypatch):
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))
    srv, gui = make_server("127.0.0.1", 0, allow_hosts=["nettools", "nettools.lab"])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        for name in ("nettools", "nettools.lab"):
            r = raw(port, ("GET /api/state HTTP/1.1\r\nHost: %s:%d\r\n"
                           "Connection: close\r\n\r\n" % (name, port)).encode())
            assert status(r) == 200, name
        # and its own Origin is accepted under that name too
        r = raw(port, ("GET /api/state HTTP/1.1\r\nHost: nettools:%d\r\n"
                       "Origin: http://nettools:%d\r\nConnection: close\r\n\r\n"
                       % (port, port)).encode())
        assert status(r) == 200
    finally:
        gui.controller.stop(); gui.gateway.stop()
        srv.shutdown(); srv.server_close()


def test_wildcard_bind_accepts_this_hosts_own_addresses(tmp_path, monkeypatch):
    from spantap.interfaces import list_interfaces
    addrs = [i["ipv4"] for i in list_interfaces() if i["ipv4"] and not i["loopback"]]
    if not addrs:
        pytest.skip("no non-loopback IPv4 address on this host")
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))
    srv, gui = make_server("0.0.0.0", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        r = raw(port, ("GET /api/state HTTP/1.1\r\nHost: %s:%d\r\n"
                       "Connection: close\r\n\r\n" % (addrs[0], port)).encode())
        assert status(r) == 200
    finally:
        gui.controller.stop(); gui.gateway.stop()
        srv.shutdown(); srv.server_close()


def test_reachable_urls_lists_every_address_with_the_token():
    from spantap.webui.server import reachable_urls
    urls = reachable_urls("0.0.0.0", 8420, "https", "sekrit", ["nettools"])
    assert all(u.startswith("https://") and u.endswith("?token=sekrit") for u in urls)
    assert any("127.0.0.1" in u for u in urls)
    assert any("nettools" in u for u in urls)
    plain = reachable_urls("192.0.2.9", 8420, "http", None)
    assert plain == ["http://192.0.2.9:8420/"]


# -- TLS -------------------------------------------------------------------

def _selfsigned(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    rc = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=nettools"],
        capture_output=True,
    )
    if rc.returncode != 0:
        pytest.skip("openssl could not generate a test certificate")
    return str(cert), str(key)


def test_https_serves_the_ui_and_expects_https_origins(tmp_path, monkeypatch):
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))
    cert, key = _selfsigned(tmp_path)
    srv, gui = make_server("127.0.0.1", 0, allow_hosts=["nettools"],
                           tls_cert=cert, tls_key=key)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def tls_request(request: bytes) -> bytes:
        plain = socket.create_connection(("127.0.0.1", port), timeout=10)
        s = ctx.wrap_socket(plain, server_hostname="nettools")
        try:
            s.sendall(request)
            out = b""
            s.settimeout(10)
            while True:
                try:
                    chunk = s.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                out += chunk
            return out
        finally:
            s.close()

    try:
        page = tls_request(("GET / HTTP/1.1\r\nHost: nettools:%d\r\n"
                            "Connection: close\r\n\r\n" % port).encode())
        assert status(page) == 200 and b"<title>spantap</title>" in page

        ok = tls_request(("GET /api/state HTTP/1.1\r\nHost: nettools:%d\r\n"
                          "Origin: https://nettools:%d\r\nConnection: close\r\n\r\n"
                          % (port, port)).encode())
        assert status(ok) == 200
        # An http:// Origin is a different origin and must not be accepted.
        bad = tls_request(("GET /api/state HTTP/1.1\r\nHost: nettools:%d\r\n"
                           "Origin: http://nettools:%d\r\nConnection: close\r\n\r\n"
                           % (port, port)).encode())
        assert status(bad) == 403
    finally:
        gui.controller.stop(); gui.gateway.stop()
        srv.shutdown(); srv.server_close()


def test_static_traversal_is_refused(server):
    _, _, port = server
    for path in ("/../../etc/passwd", "/%2e%2e%2fetc%2fpasswd", "/static/../server.py"):
        assert status(raw(port, req(port, "GET", path))) == 404, path


# -- capture upload --------------------------------------------------------

def nothing_stored(caps):
    """Refused before the directory was even created counts as stored nothing."""
    return not caps.exists() or list(caps.iterdir()) == []


def _pcap_payload(n=3):
    import io as _io
    from spantap.sources.pcapread import (
        LINKTYPE_ETHERNET, write_pcap_header, write_pcap_packet)
    buf = _io.BytesIO()
    write_pcap_header(buf, LINKTYPE_ETHERNET)
    for i in range(n):
        write_pcap_packet(buf, 1_700_000_000_000_000_000 + i * 1_000_000, b"\xaa" * 64)
    return buf.getvalue()


def upload_req(port, payload, name, headers=None, token=None):
    head = [
        "POST /api/captures/upload?name=%s HTTP/1.1" % name,
        "Host: 127.0.0.1:%d" % port,
        "Content-Type: application/octet-stream",
        "Content-Length: %d" % len(payload),
    ]
    if token:
        head.append("X-Erspan-Token: %s" % token)
    for k, v in (headers or {}).items():
        head.append("%s: %s" % (k, v))
    return ("\r\n".join(head) + "\r\n\r\n").encode() + payload


@pytest.fixture
def upload_server(tmp_path, monkeypatch):
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("SPANTAP_CAPTURE_DIR", str(tmp_path / "caps"))
    srv, gui = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv.server_address[1], tmp_path / "caps"
    gui.controller.stop()
    gui.gateway.stop()
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


def test_upload_stores_the_capture_and_lists_it(upload_server):
    port, caps = upload_server
    payload = _pcap_payload(5)
    r = raw(port, upload_req(port, payload, "walters%20trace.pcapng"))
    assert status(r) == 200
    data = body_json(r)
    assert data["capture"]["readable"] is True
    assert data["capture"]["linktype_name"] == "Ethernet"
    stored = data["capture"]["stored_as"]
    assert (caps / stored).read_bytes() == payload
    assert [c["name"] for c in data["captures"]] == [stored]

    listed = body_json(raw(port, req(port, "GET", "/api/captures")))
    assert [c["name"] for c in listed["captures"]] == [stored]
    assert listed["storage"]["writable"] is True


def test_upload_appears_in_bootstrap(upload_server):
    port, _ = upload_server
    raw(port, upload_req(port, _pcap_payload(), "boot.pcap"))
    data = body_json(raw(port, req(port, "GET", "/api/bootstrap")))
    assert [c["name"] for c in data["captures"]] == ["boot.pcap"]


def test_upload_of_something_that_is_not_a_capture_is_refused(upload_server):
    port, caps = upload_server
    r = raw(port, upload_req(port, b"<html>hi</html>" + b"x" * 500, "evil.pcap"))
    assert status(r) == 400
    assert b"not a capture file" in r
    assert nothing_stored(caps)


def test_upload_needs_the_token_and_does_not_read_the_body_first(tmp_path, monkeypatch):
    """An unauthorised upload must be refused without swallowing the file.

    The endpoint closes the connection instead of draining the body, so a
    stranger cannot make the server read half a gigabyte before saying no.
    """
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("SPANTAP_CAPTURE_DIR", str(tmp_path / "caps"))
    srv, gui = make_server("127.0.0.1", 0, token="s3cret")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        payload = _pcap_payload(200)
        # Announce the body but send only the headers: if the server waited to
        # read it, this would block until the timeout instead of answering.
        headers = upload_req(port, payload, "x.pcap").split(b"\r\n\r\n", 1)[0]
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            s.sendall(headers + b"\r\n\r\n")
            s.settimeout(5)
            out = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                out += chunk
        finally:
            s.close()
        assert status(out) == 401
        assert b"Connection: close" in out
        assert not (tmp_path / "caps").exists() or list((tmp_path / "caps").iterdir()) == []

        ok = raw(port, upload_req(port, payload, "x.pcap", token="s3cret"))
        assert status(ok) == 200
    finally:
        gui.controller.stop()
        gui.gateway.stop()
        srv.shutdown()
        srv.server_close()


def test_upload_refuses_a_foreign_host_header(upload_server):
    port, caps = upload_server
    payload = _pcap_payload()
    head = ("POST /api/captures/upload?name=x.pcap HTTP/1.1\r\n"
            "Host: evil.example\r\n"
            "Content-Length: %d\r\n\r\n" % len(payload)).encode()
    r = raw(port, head + payload)
    assert status(r) == 403
    assert nothing_stored(caps)


def test_upload_refuses_a_cross_origin_post(upload_server):
    port, caps = upload_server
    payload = _pcap_payload()
    r = raw(port, upload_req(port, payload, "x.pcap",
                             headers={"Origin": "http://evil.example"}))
    assert status(r) == 403
    assert nothing_stored(caps)


def test_upload_without_a_content_length_is_refused(upload_server):
    port, _ = upload_server
    head = ("POST /api/captures/upload?name=x.pcap HTTP/1.1\r\n"
            "Host: 127.0.0.1:%d\r\n\r\n" % port).encode()
    assert status(raw(port, head)) == 411


def test_upload_over_the_cap_is_refused_without_writing(upload_server, monkeypatch):
    port, caps = upload_server
    monkeypatch.setenv("SPANTAP_MAX_UPLOAD_MB", "1")
    head = ("POST /api/captures/upload?name=big.pcap HTTP/1.1\r\n"
            "Host: 127.0.0.1:%d\r\n"
            "Content-Length: %d\r\n\r\n" % (port, 8 * 1024 * 1024)).encode()
    r = raw(port, head)
    assert status(r) == 413 or status(r) == 400
    assert nothing_stored(caps)


def test_delete_through_the_api(upload_server):
    port, caps = upload_server
    raw(port, upload_req(port, _pcap_payload(), "gone.pcap"))
    assert (caps / "gone.pcap").exists()
    r = body_json(raw(port, req(port, "POST", "/api/captures/delete",
                                {"name": "gone.pcap"})))
    assert r["ok"] is True and r["captures"] == []
    assert not (caps / "gone.pcap").exists()


def test_delete_refuses_a_traversal(upload_server, tmp_path):
    port, caps = upload_server
    victim = tmp_path / "victim.pcap"
    victim.write_bytes(_pcap_payload())
    r = raw(port, req(port, "POST", "/api/captures/delete",
                      {"name": "../victim.pcap"}))
    assert status(r) == 400
    assert victim.exists()
