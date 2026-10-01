# SPDX-License-Identifier: GPL-2.0-or-later
"""Adding a password adds an attack the token never had. This is that attack.

A token cannot be guessed and cannot be reused from another site. A password
can be both, so these tests are about the machinery that exists only because
of it: the username oracle, session handling, brute-force backoff, and the
refusal to accept a password over a connection that would carry it in clear.
"""

import json
import os
import socket
import threading
import time
from urllib.parse import urlencode

import pytest

from spantap.webui import accounts, sessions
from spantap.webui.server import make_server

PASSWORD = "a long enough passphrase"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("SPANTAP_CAPTURE_DIR", str(tmp_path / "caps"))
    return tmp_path


@pytest.fixture
def server(cfg):
    accounts.add_user("walter", PASSWORD)
    srv, gui = make_server("127.0.0.1", 0, token="t0ken")
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv.server_address[1], gui
    gui.controller.stop()
    gui.gateway.stop()
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


def raw(port, request: bytes, timeout: float = 10.0) -> bytes:
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


def login_req(port, username, password, headers=None, host=None):
    payload = urlencode({"username": username, "password": password}).encode()
    head = [
        "POST /login HTTP/1.1",
        "Host: %s" % (host or "127.0.0.1:%d" % port),
        "Content-Type: application/x-www-form-urlencoded",
        "Content-Length: %d" % len(payload),
        "Connection: close",
    ]
    for k, v in (headers or {}).items():
        head.append("%s: %s" % (k, v))
    return ("\r\n".join(head) + "\r\n\r\n").encode() + payload


def get_req(port, path, cookie=None, headers=None):
    head = ["GET %s HTTP/1.1" % path, "Host: 127.0.0.1:%d" % port, "Connection: close"]
    if cookie:
        head.append("Cookie: %s" % cookie)
    for k, v in (headers or {}).items():
        head.append("%s: %s" % (k, v))
    return ("\r\n".join(head) + "\r\n\r\n").encode()


def post_req(port, path, body, cookie=None):
    payload = json.dumps(body).encode()
    head = ["POST %s HTTP/1.1" % path, "Host: 127.0.0.1:%d" % port,
            "Content-Type: application/json",
            "Content-Length: %d" % len(payload), "Connection: close"]
    if cookie:
        head.append("Cookie: %s" % cookie)
    return ("\r\n".join(head) + "\r\n\r\n").encode() + payload


def status(response: bytes) -> int:
    return int(response.split(b" ", 2)[1])


def headers_of(response: bytes):
    head = response.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")[1:]
    out = []
    for line in head:
        k, _, v = line.partition(":")
        out.append((k.strip().lower(), v.strip()))
    return out


def set_cookies(response: bytes):
    return [v for k, v in headers_of(response) if k == "set-cookie"]


def session_cookie(response: bytes) -> str:
    for value in set_cookies(response):
        if value.startswith(sessions.SESSION_COOKIE + "="):
            return value.split(";", 1)[0]
    return ""


def body_json(response: bytes):
    return json.loads(response.split(b"\r\n\r\n", 1)[1].decode())


# -- the happy path ---------------------------------------------------------

def test_a_correct_password_starts_a_session(server):
    port, _ = server
    r = raw(port, login_req(port, "walter", PASSWORD))
    assert status(r) == 303
    cookie = session_cookie(r)
    assert cookie, "no session cookie was set"

    page = raw(port, get_req(port, "/", cookie=cookie))
    assert status(page) == 200 and b"<title>spantap</title>" in page

    who = body_json(raw(port, get_req(port, "/api/whoami", cookie=cookie)))
    assert who["user"] == "walter" and who["method"] == "session"


def test_the_name_is_matched_case_insensitively(server):
    port, _ = server
    assert status(raw(port, login_req(port, "WALTER", PASSWORD))) == 303


def test_logout_ends_the_session_everywhere_it_matters(server):
    port, _ = server
    cookie = session_cookie(raw(port, login_req(port, "walter", PASSWORD)))
    out = raw(port, post_req(port, "/api/logout", {}, cookie=cookie))
    assert status(out) == 200
    # The cookie is cleared in the browser AND the session is gone server-side,
    # so replaying the old cookie is worthless.
    assert any("Max-Age=0" in c for c in set_cookies(out))
    assert status(raw(port, get_req(port, "/api/state", cookie=cookie))) == 401


def test_the_token_still_works_alongside_accounts(server):
    port, _ = server
    r = raw(port, get_req(port, "/api/state", headers={"X-Erspan-Token": "t0ken"}))
    assert status(r) == 200
    who = body_json(raw(port, get_req(port, "/api/whoami",
                                      headers={"X-Erspan-Token": "t0ken"})))
    assert who["method"] == "token" and who["user"] == ""


# -- what the password must not leak ---------------------------------------

def test_a_wrong_password_and_an_unknown_user_are_indistinguishable(server):
    port, _ = server
    wrong = raw(port, login_req(port, "walter", "not the password"))
    unknown = raw(port, login_req(port, "ghost", "not the password"))
    assert status(wrong) == status(unknown) == 401
    body_wrong = wrong.split(b"\r\n\r\n", 1)[1]
    body_unknown = unknown.split(b"\r\n\r\n", 1)[1]
    assert body_wrong == body_unknown, "the reply says which user names exist"


def test_an_unknown_user_costs_the_same_time_as_a_wrong_password(cfg):
    """Otherwise the clock enumerates the account list for free."""
    accounts.add_user("walter", PASSWORD)
    import statistics

    def timed(fn, n=5):
        out = []
        for _ in range(n):
            start = time.perf_counter()
            fn()
            out.append(time.perf_counter() - start)
        return statistics.median(out)

    wrong = timed(lambda: accounts.verify("walter", "nope"))
    unknown = timed(lambda: accounts.verify("ghost", "nope"))
    assert 0.5 < unknown / wrong < 2.0, (
        "unknown user %.4fs vs wrong password %.4fs" % (unknown, wrong))


def test_the_stored_file_holds_no_password(cfg):
    accounts.add_user("walter", PASSWORD)
    text = open(accounts.users_path()).read()
    assert PASSWORD not in text
    assert "scrypt$" in text


def test_the_user_file_is_not_readable_by_others(cfg):
    import os
    accounts.add_user("walter", PASSWORD)
    assert os.stat(accounts.users_path()).st_mode & 0o077 == 0


# -- session handling -------------------------------------------------------

def test_a_session_id_is_never_taken_from_the_client(server):
    """Fixation is impossible by construction, not by a check. Prove it."""
    port, gui = server
    planted = "%s=%s" % (sessions.SESSION_COOKIE, "attacker-chosen-value")
    r = raw(port, login_req(port, "walter", PASSWORD,
                            headers={"Cookie": planted}))
    assert status(r) == 303
    issued = session_cookie(r)
    assert issued and "attacker-chosen-value" not in issued
    # And the planted value is not valid afterwards either.
    assert status(raw(port, get_req(port, "/api/state", cookie=planted))) == 401


def test_signing_in_again_ends_the_earlier_session(server):
    """Otherwise a browser accumulates live sessions it has forgotten about.

    It also means signing in somewhere else is a way to cut off a session you
    left open on a machine you no longer have.
    """
    port, _ = server
    first = session_cookie(raw(port, login_req(port, "walter", PASSWORD)))
    assert status(raw(port, get_req(port, "/api/state", cookie=first))) == 200
    second = session_cookie(raw(port, login_req(port, "walter", PASSWORD,
                                                headers={"Cookie": first})))
    assert second and second != first
    assert status(raw(port, get_req(port, "/api/state", cookie=first))) == 401
    assert status(raw(port, get_req(port, "/api/state", cookie=second))) == 200


def test_a_forged_session_cookie_is_just_a_wrong_value(server):
    port, _ = server
    forged = "%s=%s" % (sessions.SESSION_COOKIE, "a" * 43)
    assert status(raw(port, get_req(port, "/api/state", cookie=forged))) == 401


def test_the_session_cookie_is_httponly_and_samesite_strict(server):
    port, _ = server
    cookie = [c for c in set_cookies(raw(port, login_req(port, "walter", PASSWORD)))
              if c.startswith(sessions.SESSION_COOKIE)][0]
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    # Not Secure here: this server is plain HTTP. A Secure cookie over HTTP is
    # simply dropped by the browser, which would lock everyone out.
    assert "Secure" not in cookie


def test_sessions_expire_on_idle_and_on_age():
    table = sessions.Sessions(idle=0.15, absolute=10)
    sid = table.create("walter")
    assert table.lookup(sid) == "walter"
    time.sleep(0.25)
    assert table.lookup(sid) is None, "an idle session outlived its timeout"

    table = sessions.Sessions(idle=100, absolute=0.15)
    sid = table.create("walter")
    for _ in range(4):
        time.sleep(0.05)
        table.lookup(sid)          # kept active the whole time
    assert table.lookup(sid) is None, "an active session outlived its absolute age"


def test_changing_a_password_logs_that_user_out(server):
    port, gui = server
    cookie = session_cookie(raw(port, login_req(port, "walter", PASSWORD)))
    assert status(raw(port, get_req(port, "/api/state", cookie=cookie))) == 200
    r = raw(port, post_req(port, "/api/users/passwd",
                           {"name": "walter", "password": "a different long phrase"},
                           cookie=cookie))
    assert status(r) == 200 and body_json(r)["sessions_closed"] >= 1
    assert status(raw(port, get_req(port, "/api/state", cookie=cookie))) == 401


def test_disabling_a_user_logs_them_out(server):
    port, _ = server
    # A second account, because the store refuses to disable the last one.
    accounts.add_user("colleague", "another long passphrase")
    cookie = session_cookie(raw(port, login_req(port, "colleague",
                                                "another long passphrase")))
    admin = session_cookie(raw(port, login_req(port, "walter", PASSWORD)))
    raw(port, post_req(port, "/api/users/disable",
                       {"name": "colleague", "disabled": True}, cookie=admin))
    assert status(raw(port, get_req(port, "/api/state", cookie=cookie))) == 401
    assert status(raw(port, login_req(port, "colleague", "another long passphrase"))) == 401


# -- brute force ------------------------------------------------------------

def test_guessing_gets_throttled(server):
    port, _ = server
    codes = [status(raw(port, login_req(port, "walter", "guess %d" % i)))
             for i in range(9)]
    assert codes[0] == 401, "the first wrong password should just be wrong"
    assert 429 in codes, "guessing was never throttled: %r" % codes
    # And the throttle does not care that the password is now right.
    assert status(raw(port, login_req(port, "walter", PASSWORD))) == 429


def test_the_throttle_counts_the_address_as_well_as_the_user():
    """Spraying one guess each at many names must still be caught."""
    t = sessions.Throttle(free=3, base=5.0)
    for i in range(6):
        assert t.retry_after("user:name%d" % i, "peer:10.0.0.9") == 0.0 or i > 3
        t.record_failure("user:name%d" % i, "peer:10.0.0.9")
    assert t.retry_after("user:fresh-name", "peer:10.0.0.9") > 0


def test_a_good_password_clears_that_user_but_not_the_address():
    """Owning one account must not reset the counter for guesses at others."""
    t = sessions.Throttle(free=1, base=5.0)
    t.record_failure("user:walter", "peer:10.0.0.9")
    t.record_failure("user:walter", "peer:10.0.0.9")
    t.clear("user:walter")
    assert t.retry_after("user:walter") == 0.0
    assert t.retry_after("peer:10.0.0.9") > 0


def test_the_lockout_grows_and_is_capped():
    t = sessions.Throttle(free=0, base=10.0, ceiling=40.0)
    waits = []
    for _ in range(6):
        t.record_failure("k")
        waits.append(t.retry_after("k"))
    assert waits[0] < waits[1] < waits[2], "the lockout does not grow: %r" % waits
    assert max(waits) <= 40.0 + 1, "the ceiling was exceeded: %r" % waits


# -- where a password may be sent ------------------------------------------

def test_a_password_is_refused_over_plain_http_from_another_host(cfg):
    """The token has no value anywhere else; a password usually does."""
    accounts.add_user("walter", PASSWORD)
    srv, gui = make_server("0.0.0.0", 0, token="t0ken")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        # Pretend to arrive from somewhere that is not loopback.
        handler_cls = type(srv.RequestHandlerClass.__name__,
                           (srv.RequestHandlerClass,), {})
        original = handler_cls._password_login_allowed
        assert original  # the method exists; the real check is below

        from spantap.webui.server import _Handler
        allowed = _Handler._password_login_allowed

        class FakeSelf:
            url_scheme = "http"
            client_address = ("10.1.2.3", 5555)
        assert allowed(FakeSelf()) is False

        class Loopback(FakeSelf):
            client_address = ("127.0.0.1", 5555)
        assert allowed(Loopback()) is True

        class Tls(FakeSelf):
            url_scheme = "https"
        assert allowed(Tls()) is True
    finally:
        gui.controller.stop()
        gui.gateway.stop()
        srv.shutdown()
        srv.server_close()


def test_the_login_form_is_still_origin_checked(server):
    """The page that receives a password is not the one to relax the guard on."""
    port, _ = server
    r = raw(port, login_req(port, "walter", PASSWORD,
                            headers={"Origin": "http://evil.example"}))
    assert status(r) == 403
    assert not session_cookie(r)


def test_the_login_form_is_still_host_checked(server):
    port, _ = server
    r = raw(port, login_req(port, "walter", PASSWORD, host="evil.example"))
    assert status(r) == 403


def test_form_encoding_is_accepted_only_by_the_login_route(server):
    """Nothing else has a use for it, so nothing else takes it."""
    port, _ = server
    cookie = session_cookie(raw(port, login_req(port, "walter", PASSWORD)))
    payload = urlencode({"name": "x"}).encode()
    head = ["POST /api/profiles/delete HTTP/1.1", "Host: 127.0.0.1:%d" % port,
            "Content-Type: application/x-www-form-urlencoded",
            "Content-Length: %d" % len(payload),
            "Cookie: %s" % cookie, "Connection: close"]
    r = raw(port, ("\r\n".join(head) + "\r\n\r\n").encode() + payload)
    assert status(r) == 400 and b"invalid JSON" in r


# -- the account store's own rules -----------------------------------------

def test_the_last_account_cannot_be_removed_or_disabled(cfg):
    accounts.add_user("walter", PASSWORD)
    with pytest.raises(accounts.AccountError):
        accounts.remove_user("walter")
    with pytest.raises(accounts.AccountError):
        accounts.set_disabled("walter", True)
    accounts.add_user("colleague", "another long passphrase")
    accounts.remove_user("walter")          # now there is someone else
    assert [u["name"] for u in accounts.list_users()] == ["colleague"]


@pytest.mark.parametrize("bad", ["short", "password", "walter", "", "12345678901"])
def test_weak_passwords_are_refused(cfg, bad):
    with pytest.raises(accounts.AccountError):
        accounts.check_password(bad, "walter")


@pytest.mark.parametrize("bad", ["", "-nope", "a" * 33, "has space", "UPPER!"])
def test_bad_user_names_are_refused(cfg, bad):
    with pytest.raises(accounts.AccountError):
        accounts.check_name(bad)


def test_a_disabled_user_cannot_log_in(cfg):
    accounts.add_user("walter", PASSWORD)
    accounts.add_user("colleague", "another long passphrase")
    accounts.set_disabled("colleague", True)
    assert accounts.verify("colleague", "another long passphrase") is None
    assert accounts.verify("walter", PASSWORD) == "walter"


def test_login_is_refused_when_no_accounts_exist(cfg):
    srv, gui = make_server("127.0.0.1", 0, token="t0ken")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        r = raw(port, login_req(port, "walter", PASSWORD))
        assert status(r) == 403 and b"no accounts exist yet" in r
        # ...and the page offered is the token one, not a sign-in form.
        page = raw(port, get_req(port, "/"))
        assert status(page) == 401
        assert b'name="token"' in page and b'name="password"' not in page
    finally:
        gui.controller.stop()
        gui.gateway.stop()
        srv.shutdown()
        srv.server_close()


def test_the_auth_page_offers_both_forms_when_both_are_possible(server):
    port, _ = server
    page = raw(port, get_req(port, "/login"))
    assert status(page) == 200
    assert b'name="password"' in page and b'name="token"' in page


# -- the header that broke the form ----------------------------------------

def test_the_sign_in_page_relaxes_the_referrer_policy_and_nothing_else(server):
    """A real browser found this; no hand-built request could have.

    Chrome derives the Origin header of a form submission from the referrer
    machinery, so under Referrer-Policy: no-referrer it posts our own sign-in
    form with Origin: null and the cross-origin check refuses it. The card
    therefore ships same-origin — and only the card, so a URL carrying
    ?token=... still never reaches a Referer header.
    """
    port, _ = server

    def policy(response):
        return [v for k, v in headers_of(response) if k == "referrer-policy"]

    card = raw(port, get_req(port, "/login"))
    assert policy(card) == ["same-origin"], policy(card)

    cookie = session_cookie(raw(port, login_req(port, "walter", PASSWORD)))
    app = raw(port, get_req(port, "/", cookie=cookie))
    assert policy(app) == ["no-referrer"], policy(app)
    api = raw(port, get_req(port, "/api/state", cookie=cookie))
    assert policy(api) == ["no-referrer"], policy(api)


def test_a_same_origin_login_post_is_accepted(server):
    """The case the hostile-origin test does not cover: the honest one."""
    port, _ = server
    r = raw(port, login_req(port, "walter", PASSWORD,
                            headers={"Origin": "http://127.0.0.1:%d" % port}))
    assert status(r) == 303 and session_cookie(r)


def test_an_opaque_origin_is_still_refused(server):
    """Origin: null is what a sandboxed frame sends. It is not us."""
    port, _ = server
    r = raw(port, login_req(port, "walter", PASSWORD, headers={"Origin": "null"}))
    assert status(r) == 403
    assert not session_cookie(r)


# -- over TLS, which is the point of refusing it without ------------------

def _tls_request(port, request: bytes) -> bytes:
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    plain = socket.create_connection(("127.0.0.1", port), timeout=10)
    s = ctx.wrap_socket(plain, server_hostname="nettools")
    try:
        s.sendall(request)
        s.settimeout(10)
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


def test_over_tls_a_password_works_from_anywhere_and_the_cookie_is_secure(
        cfg, tmp_path):
    """The other half of the plain-HTTP refusal: over TLS it just works.

    This is the state the first-run flow is aiming at — arrive with the token,
    configure the certificate, then sign in.
    """
    import subprocess
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    rc = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=nettools"], capture_output=True)
    if rc.returncode != 0:
        pytest.skip("openssl could not generate a test certificate")

    accounts.add_user("walter", PASSWORD)
    srv, gui = make_server("127.0.0.1", 0, allow_hosts=["nettools"],
                           tls_cert=str(cert), tls_key=str(key))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        payload = urlencode({"username": "walter", "password": PASSWORD}).encode()
        head = ["POST /login HTTP/1.1", "Host: nettools",
                "Origin: https://nettools:%d" % port,
                "Content-Type: application/x-www-form-urlencoded",
                "Content-Length: %d" % len(payload), "Connection: close"]
        r = _tls_request(port, ("\r\n".join(head) + "\r\n\r\n").encode() + payload)
        assert status(r) == 303, r.split(b"\r\n", 1)[0]
        cookie = [c for c in set_cookies(r)
                  if c.startswith(sessions.SESSION_COOKIE)][0]
        # Secure, now that there is a scheme it means something on.
        assert "Secure" in cookie and "HttpOnly" in cookie
        assert "SameSite=Strict" in cookie
    finally:
        gui.controller.stop()
        gui.gateway.stop()
        srv.shutdown()
        srv.server_close()


# -- the config directory, which is a Docker volume in practice -------------

def has_a_fix(message: str) -> bool:
    """The whole point of these messages is that they end in something to run."""
    return any(cmd in message for cmd in ("chown", "chmod", "docker run"))


@pytest.fixture
def unwritable_cfg(tmp_path, monkeypatch):
    """A config directory this process cannot write, as a stale volume is."""
    if os.getuid() == 0:
        pytest.skip("root ignores directory permissions, so this proves nothing")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    cfg.chmod(0o500)
    monkeypatch.setenv("SPANTAP_CONFIG_DIR", str(cfg))
    try:
        yield cfg
    finally:
        cfg.chmod(0o700)


def test_adding_a_user_says_what_to_fix_instead_of_raising(unwritable_cfg):
    """This reached a real deployment as a bare PermissionError traceback.

    The config directory is a named Docker volume, and a volume keeps the
    ownership it was created with — so an older volume under a newer image is
    unwritable, and every save fails with nothing that says why.
    """
    with pytest.raises(accounts.AccountError) as exc:
        accounts.add_user("walter", PASSWORD)
    message = str(exc.value)
    assert "not writable" in message
    assert str(unwritable_cfg) in message
    assert "uid %d" % os.getuid() in message, "does not say who we are"
    assert has_a_fix(message), "no command to run: %r" % message


def test_the_same_failure_is_a_400_not_a_500_in_the_ui(unwritable_cfg):
    """A traceback in a JSON 500 is no more use to a browser than to a shell."""
    srv, gui = make_server("127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        r = raw(port, post_req(port, "/api/users/add",
                               {"name": "walter", "password": PASSWORD}))
        assert status(r) == 400, r.split(b"\r\n", 1)[0]
        assert b"not writable" in r
        assert has_a_fix(r.decode("utf-8", "replace"))
    finally:
        gui.controller.stop()
        gui.gateway.stop()
        srv.shutdown()
        srv.server_close()


def test_saving_a_profile_fails_the_same_way(unwritable_cfg):
    """Accounts were not special: every write lands in the same directory."""
    from spantap.config import ConfigError, default_profile, save_profile
    with pytest.raises(ConfigError) as exc:
        save_profile("lab", default_profile())
    assert "not writable" in str(exc.value)
    assert has_a_fix(str(exc.value))


def test_a_writable_directory_is_not_complained_about(cfg):
    from spantap.config import check_writable, config_dir
    check_writable(config_dir())          # must not raise
    accounts.add_user("walter", PASSWORD)
    assert [u["name"] for u in accounts.list_users()] == ["walter"]


def test_a_directory_owned_by_someone_else_is_told_to_chown(monkeypatch, tmp_path):
    """The case Walter actually hit: root owns it, we are uid 10001.

    Real ownership cannot be arranged from inside a test that is not root, so
    the stat is faked — what is under test here is which fix gets offered, not
    the kernel's permission check, which the fixture above covers for real.
    """
    from spantap import config as cfgmod
    real_stat = os.stat

    class Foreign:
        st_mode = 0o40755
        st_uid = 0
        st_gid = 0

    monkeypatch.setattr(cfgmod, "in_container", lambda: False)
    monkeypatch.setattr(cfgmod.os, "stat", lambda p, *a, **k: Foreign())
    monkeypatch.setattr(cfgmod.os, "getuid", lambda: 10001)
    monkeypatch.setattr(cfgmod.os, "getgid", lambda: 10001)
    message = cfgmod.unwritable_why(str(tmp_path))
    monkeypatch.setattr(cfgmod.os, "stat", real_stat)
    assert "owned by uid 0 gid 0" in message
    assert "chown -R 10001:10001" in message


def test_the_container_message_names_the_volume_not_chown(monkeypatch, tmp_path):
    """Inside Docker, 'sudo chown' is the wrong advice — there is no sudo."""
    from spantap import config as cfgmod
    monkeypatch.setattr(cfgmod, "in_container", lambda: True)
    message = cfgmod.unwritable_why(str(tmp_path))
    assert "docker run --rm -v" in message
    assert "sudo chown" not in message
