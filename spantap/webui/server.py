# SPDX-License-Identifier: GPL-2.0-or-later
"""A small JSON API and one static page, served from the standard library.

Bound to 0.0.0.0 by default, behind a token. Two more things guard it, because a
browser will happily send a cross-site request to localhost on behalf of any
page you have open:

* the ``Host`` header must match the address we are actually bound to, which
  is what stops DNS rebinding from reaching this server;
* ``Origin``, when the browser sends one, must be our own origin.

Binding anywhere else requires a token, which is generated for you and carried
in the URL.
"""

from __future__ import annotations

import errno
import http.server
import json
import os
import secrets
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
from typing import Any, Callable, Dict, Iterable, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .. import __version__
from ..config import (
    ConfigError,
    check_writable,
    config_dir,
    default_gateway_config,
    default_profile,
    delete_profile,
    last_used,
    list_profiles,
    load_gateway_or_default,
    load_last_or_default,
    load_profile,
    in_container,
    legacy_env,
    load_webui_or_default,
    new_webui_token,
    redact_webui,
    save_gateway,
    save_profile,
    save_webui,
    set_last_used,
    tls_dir,
    webui_path,
)
from ..controller import SimulationController, preview_filter
from ..gateway.service import GatewayController
from ..interfaces import list_interfaces
from ..sources.live import capture_tool_status
from ..sources.synth import SCENARIOS
from .accounts import (
    AccountError,
    add_user,
    any_users,
    list_users,
    note_login,
    remove_user,
    set_disabled,
    set_password,
    verify as verify_password,
)
from .sessions import SESSION_COOKIE, Sessions, Throttle, describe_wait
from .uploads import (
    UploadError,
    delete_capture,
    list_captures,
    max_upload,
    save_upload,
    storage,
)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MAX_BODY = 256 * 1024

#: Handled before the JSON body reader: its body is a capture file, streamed
#: to disk rather than parsed. See _Handler._receive_capture.
UPLOAD_PATH = "/api/captures/upload"

#: Reachable without knowing who you are — that is what they are for. Both
#: still pass the Host and Origin checks like everything else.
LOGIN_PATH = "/login"
LOGOUT_PATH = "/api/logout"
WHOAMI_PATH = "/api/whoami"


TOKEN_COOKIE = "erspan_token"
#: A working day. Long enough not to be re-entered constantly, short enough
#: that an unattended browser does not stay authorised indefinitely.
TOKEN_COOKIE_MAX_AGE = 12 * 3600


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


TOKEN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>spantap</title>
<style>
:root { color-scheme: light dark; }
body { margin:0; min-height:100vh; display:grid; place-items:center;
  background:#f9f9f7; color:#0b0b0b;
  font:14px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif; }
@media (prefers-color-scheme: dark){ :root:not([data-theme="light"]) body{
  background:#0d0d0d; color:#fff; } }
:root[data-theme="dark"] body{ background:#0d0d0d; color:#fff; }
.card { background:#fcfcfb; border:1px solid rgba(11,11,11,.10); border-radius:10px;
  padding:26px 28px; max-width:460px; width:calc(100%% - 32px);
  box-shadow:0 1px 2px rgba(11,11,11,.06),0 4px 14px rgba(11,11,11,.05); }
@media (prefers-color-scheme: dark){ :root:not([data-theme="light"]) .card{
  background:#1a1a19; border-color:rgba(255,255,255,.10);
  box-shadow:0 4px 14px rgba(0,0,0,.45);} }
:root[data-theme="dark"] .card{ background:#1a1a19;
  border-color:rgba(255,255,255,.10); box-shadow:0 4px 14px rgba(0,0,0,.45); }
h1 { font-size:17px; margin:0 0 6px; }
p { margin:0 0 16px; color:#52514e; font-size:13px; }
@media (prefers-color-scheme: dark){ :root:not([data-theme="light"]) p{
  color:#c3c2b7; } }
:root[data-theme="dark"] p{ color:#c3c2b7; }
form { display:flex; gap:8px; }
form.stack { flex-direction:column; }
form.stack button { width:100%%; }
input { flex:1; min-width:0; padding:9px 11px; border-radius:7px;
  border:1px solid rgba(11,11,11,.18); background:#fff; color:inherit; font:inherit; }
@media (prefers-color-scheme: dark){ :root:not([data-theme="light"]) input{
  background:#232322; border-color:rgba(255,255,255,.18);} }
:root[data-theme="dark"] input{ background:#232322;
  border-color:rgba(255,255,255,.18); }
button { padding:9px 16px; border-radius:7px; border:0; background:#2a78d6;
  color:#fff; font:inherit; font-weight:600; cursor:pointer; }
@media (prefers-color-scheme: dark){ :root:not([data-theme="light"]) button{
  background:#3987e5; } }
:root[data-theme="dark"] button{ background:#3987e5; }
.hint { margin:16px 0 0; font-size:12px; color:#898781; }
code { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px; }
</style>
<script>
// The app persists the light/dark choice; this card is served separately and
// would otherwise ignore it, so the first page anyone sees is the one place
// the theme flickers or comes out wrong. Read it before the first paint.
try {
  var t = localStorage.getItem("spantap-theme");
  if (t) document.documentElement.dataset.theme = t;
} catch (e) { /* private mode: fall back to the OS setting */ }
</script>
</head><body>
<div class="card">
  <h1>%(title)s</h1>
  <p>%(message)s</p>
<!--LOGIN-->
  <form method="POST" action="/login" class="stack">
    <input type="text" name="username" placeholder="user name" autofocus
           autocomplete="username" spellcheck="false" autocapitalize="off">
    <input type="password" name="password" placeholder="password"
           autocomplete="current-password" spellcheck="false">
    <button type="submit">Sign in</button>
  </form>
  <p class="hint">No account yet? Create the first one on the host:
    <code>spantap-sim users add &lt;name&gt;</code> &mdash; or in Docker,
    <code>docker compose exec &lt;service&gt; spantap-sim users add &lt;name&gt;</code>
    (the service is <code>gui</code> or <code>gui-lan</code>).</p>
<!--/LOGIN-->
<!--TOKEN-->
  <form method="GET" action="/">
    <input type="password" name="token" placeholder="access token" autofocus
           autocomplete="current-password" spellcheck="false">
    <button type="submit">Open</button>
  </form>
  <p class="hint">%(token_hint)s It is remembered for this browser for 12
    hours, so you only do this once.</p>
<!--/TOKEN-->
</div></body></html>
"""


def _capabilities() -> Dict[str, Any]:
    """What this host can actually do, so the UI can say so up front."""
    raw_ok, raw_detail = True, "ready"
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW).close()
    except PermissionError:
        raw_ok, raw_detail = False, "needs CAP_NET_RAW — run 'spantap-sim doctor'"
    except OSError as exc:
        raw_ok, raw_detail = False, str(exc)
    tool, problem = capture_tool_status()
    return {
        "raw_socket": {"ok": raw_ok, "detail": raw_detail},
        "capture_tool": {"ok": bool(tool), "detail": tool or problem},
    }


class GuiServer:
    """Owns the controller and the routing table; the handler is a thin shell."""

    def __init__(self, controller: Optional[SimulationController] = None,
                 token: Optional[str] = None,
                 gateway: Optional[GatewayController] = None,
                 effective: Optional[Dict] = None):
        self.controller = controller or SimulationController()
        self.gateway = gateway or GatewayController()
        self.token = token
        #: In memory only: a restart logs everyone out, which is the right
        #: trade for a tool that is restarted deliberately.
        self.sessions = Sessions()
        #: Passwords can be guessed; the token cannot. This is the difference.
        self.throttle = Throttle()
        #: what this running server is actually using, so the UI can show the
        #: difference between what is saved and what is in effect.
        self.effective = effective or {}
        self.routes: Dict[Tuple[str, str], Callable[[Dict, Dict], Any]] = {
            ("GET", "/api/bootstrap"): self.api_bootstrap,
            ("GET", "/api/state"): self.api_state,
            ("GET", "/api/webui"): self.api_webui_get,
            ("POST", "/api/webui"): self.api_webui_save,
            ("POST", "/api/webui/selfsigned"): self.api_webui_selfsigned,
            ("POST", "/api/webui/tls/upload"): self.api_webui_tls_upload,
            ("GET", "/api/gw/state"): self.api_gw_state,
            ("POST", "/api/gw/start"): self.api_gw_start,
            ("POST", "/api/gw/stop"): self.api_gw_stop,
            ("POST", "/api/gw/config"): self.api_gw_config,
            ("GET", "/api/interfaces"): self.api_interfaces,
            ("GET", "/api/captures"): self.api_captures,
            ("POST", "/api/captures/delete"): self.api_capture_delete,
            ("GET", "/api/profiles"): self.api_profiles,
            ("GET", "/api/profiles/load"): self.api_profile_load,
            ("POST", "/api/preview"): self.api_preview,
            ("POST", "/api/start"): self.api_start,
            ("POST", "/api/stop"): self.api_stop,
            ("POST", "/api/profiles/save"): self.api_profile_save,
            ("POST", "/api/profiles/delete"): self.api_profile_delete,
            ("GET", "/api/users"): self.api_users,
            ("POST", "/api/users/add"): self.api_user_add,
            ("POST", "/api/users/passwd"): self.api_user_passwd,
            ("POST", "/api/users/remove"): self.api_user_remove,
            ("POST", "/api/users/disable"): self.api_user_disable,
        }

    # -- handlers ----------------------------------------------------------

    def api_bootstrap(self, body: Dict, query: Dict) -> Dict:
        return {
            "version": __version__,
            "scenarios": list(SCENARIOS),
            "defaults": default_profile(),
            "profile": load_last_or_default(),
            "profiles": list_profiles(),
            "last_used": last_used(),
            "config_dir": config_dir(),
            "interfaces": list_interfaces(),
            "captures": list_captures(),
            "storage": storage(),
            "capabilities": _capabilities(),
            "state": self.controller.snapshot(sample=False),
            "gateway": {
                "defaults": default_gateway_config(),
                "config": load_gateway_or_default(),
                "state": self.gateway.snapshot(sample=False),
            },
        }

    def api_state(self, body: Dict, query: Dict) -> Dict:
        return self.controller.snapshot()

    # -- the UI's own settings ---------------------------------------------

    @staticmethod
    def _cert_report(saved: Dict) -> Tuple[Dict, list]:
        """What the configured certificate is, and why it might not work."""
        from .certs import describe, uncovered
        path = saved["tls"]["cert"]
        if not path:
            return {}, []
        info = describe(path)
        warnings = []
        if info.get("error"):
            return info, ["This certificate could not be read: %s" % info["error"]]

        days = info.get("days_left")
        if days is not None:
            if days < 0:
                warnings.append("This certificate expired %d days ago — browsers "
                                "will refuse it." % -days)
            elif days < 30:
                warnings.append("This certificate expires in %d days." % days)

        # The names someone will actually type into the browser.
        expected = list(saved["allow_hosts"])
        if saved["bind"] not in ("0.0.0.0", "127.0.0.1", "localhost"):
            expected.append(saved["bind"])
        missing = uncovered(info, expected)
        if missing:
            warnings.append(
                "This certificate does not cover %s, so a browser using that "
                "address will report a name mismatch. Reissue it with those in "
                "the subjectAltName." % ", ".join(missing)
            )
        return info, warnings

    def _webui_payload(self) -> Dict:
        from .certs import local_addresses, local_names, openssl_path
        saved = load_webui_or_default()
        effective = dict(self.effective)
        forced = set(effective.get("overridden") or ())
        differs = [k for k in ("bind", "port", "allow_hosts")
                   if k not in forced and saved.get(k) != effective.get(k)]
        if "tls" not in forced and bool(saved["tls"]["cert"]) != bool(effective.get("tls")):
            differs.append("tls")
        if "token" not in forced and bool(saved.get("token")) != bool(effective.get("token_set")):
            differs.append("token")
        restart_needed = bool(differs)
        cert_info, cert_warnings = self._cert_report(saved)
        return {
            "cert": cert_info,
            "cert_warnings": cert_warnings,
            "saved": redact_webui(saved),
            "effective": effective,
            "restart_needed": restart_needed,
            "differs": differs,
            "openssl": bool(openssl_path()),
            "suggest": {"names": local_names(), "addresses": local_addresses()},
            "config_path": webui_path(),
            "tls_dir": tls_dir(),
            "in_container": in_container(),
        }

    def api_webui_get(self, body: Dict, query: Dict) -> Dict:
        return self._webui_payload()

    def api_webui_save(self, body: Dict, query: Dict) -> Dict:
        settings = body.get("settings")
        if not isinstance(settings, dict):
            raise ApiError(400, "no settings were sent")
        saved = load_webui_or_default()
        # The token is never sent to the browser, so an unchanged field must
        # not wipe it: only an explicit new value replaces it.
        if "token" not in settings or settings.get("token") in (None, ""):
            settings["token"] = saved.get("token", "")
        if settings.get("clear_token"):
            settings["token"] = ""
        settings.pop("clear_token", None)
        try:
            # auto_token=True: binding off loopback with the token field left
            # blank gets one generated rather than refused, the same rule
            # serve() already applies at startup — do it for you instead of
            # sending the request back to ask.
            clean = save_webui(settings, current=self.effective, auto_token=True)
        except ConfigError as exc:
            raise ApiError(400, str(exc))
        except OSError as exc:
            raise ApiError(500, "could not write the settings: %s" % exc)
        payload = self._webui_payload()
        # The complete address(es) this save just made reachable, token
        # included. This is the one moment that is allowed to: it is the
        # direct response to the very save that set or generated this token,
        # never handed back on a later, unrelated GET of these settings.
        scheme = "https" if clean["tls"]["cert"] else "http"
        payload["urls"] = reachable_urls(
            clean["bind"], clean["port"], scheme, clean["token"] or None,
            clean["allow_hosts"])
        return payload

    def api_webui_selfsigned(self, body: Dict, query: Dict) -> Dict:
        from .certs import generate_selfsigned
        names = body.get("names") or []
        addresses = body.get("addresses") or []
        if not isinstance(names, list) or not isinstance(addresses, list):
            raise ApiError(400, "names and addresses must be lists")
        try:
            return generate_selfsigned(names, addresses)
        except RuntimeError as exc:
            raise ApiError(400, str(exc))
        except (OSError, subprocess.SubprocessError) as exc:
            raise ApiError(500, "could not generate a certificate: %s" % exc)

    def api_webui_tls_upload(self, body: Dict, query: Dict) -> Dict:
        from .certs import CertUploadError, describe, save_uploaded
        cert_pem = body.get("cert")
        key_pem = body.get("key") or ""
        if not isinstance(cert_pem, str):
            raise ApiError(400, "no certificate was sent")
        if not isinstance(key_pem, str):
            raise ApiError(400, "key must be a string")
        try:
            result = save_uploaded(cert_pem, key_pem)
        except CertUploadError as exc:
            raise ApiError(400, str(exc))
        except OSError as exc:
            raise ApiError(500, "could not store the certificate: %s" % exc)
        result["info"] = describe(result["cert"])
        return result

    # -- gateway -----------------------------------------------------------

    def api_gw_state(self, body: Dict, query: Dict) -> Dict:
        return self.gateway.snapshot()

    def api_gw_start(self, body: Dict, query: Dict) -> Dict:
        try:
            self.gateway.start(body.get("config") or {})
        except ConfigError as exc:
            raise ApiError(400, str(exc))
        except PermissionError:
            raise ApiError(
                403,
                "receiving ERSPAN needs CAP_NET_RAW. Run 'spantap-gw doctor' for "
                "how to grant it.",
            )
        except (RuntimeError, OSError, ValueError) as exc:
            raise ApiError(400, str(exc))
        return self.gateway.snapshot(sample=False)

    def api_gw_stop(self, body: Dict, query: Dict) -> Dict:
        self.gateway.stop()
        return self.gateway.snapshot(sample=False)

    def api_gw_config(self, body: Dict, query: Dict) -> Dict:
        try:
            config = save_gateway(body.get("config") or {})
        except ConfigError as exc:
            raise ApiError(400, str(exc))
        return {"config": config}

    def api_interfaces(self, body: Dict, query: Dict) -> Dict:
        return {"interfaces": list_interfaces()}

    # -- accounts ----------------------------------------------------------
    #
    # Anyone who can log in can already start and stop traffic on this host,
    # so there is no privilege here to escalate to and no admin role to
    # invent: every signed-in user may manage users. What the store refuses
    # is removing or disabling the last account that can still log in, which
    # would leave the token as the only way back in.

    def api_users(self, body: Dict, query: Dict) -> Dict:
        return {"users": list_users(), "active_sessions": self.sessions.active()}

    @staticmethod
    def _str(body: Dict, key: str) -> str:
        value = body.get(key)
        if not isinstance(value, str):
            raise ApiError(400, "%s must be text" % key)
        return value

    def api_user_add(self, body: Dict, query: Dict) -> Dict:
        try:
            name = add_user(self._str(body, "name"), self._str(body, "password"))
        except AccountError as exc:
            raise ApiError(400, str(exc))
        return {"ok": True, "name": name, "users": list_users()}

    def api_user_passwd(self, body: Dict, query: Dict) -> Dict:
        name = self._str(body, "name")
        try:
            set_password(name, self._str(body, "password"))
        except AccountError as exc:
            raise ApiError(400, str(exc))
        # A changed password must invalidate the sessions opened with the old
        # one, or "I changed it because it leaked" does not mean anything.
        closed = self.sessions.destroy_user(name)
        return {"ok": True, "users": list_users(), "sessions_closed": closed}

    def api_user_remove(self, body: Dict, query: Dict) -> Dict:
        name = self._str(body, "name")
        try:
            remove_user(name)
        except AccountError as exc:
            raise ApiError(400, str(exc))
        self.sessions.destroy_user(name)
        return {"ok": True, "users": list_users()}

    def api_user_disable(self, body: Dict, query: Dict) -> Dict:
        name = self._str(body, "name")
        disabled = bool(body.get("disabled", True))
        try:
            set_disabled(name, disabled)
        except AccountError as exc:
            raise ApiError(400, str(exc))
        if disabled:
            self.sessions.destroy_user(name)
        return {"ok": True, "users": list_users()}

    # -- uploaded captures -------------------------------------------------

    def api_captures(self, body: Dict, query: Dict) -> Dict:
        return {"captures": list_captures(), "storage": storage()}

    def api_capture_delete(self, body: Dict, query: Dict) -> Dict:
        name = body.get("name")
        if not isinstance(name, str):
            raise ApiError(400, "name must be a string")
        try:
            delete_capture(name)
        except UploadError as exc:
            raise ApiError(400, str(exc))
        return {"ok": True, "captures": list_captures(), "storage": storage()}

    def api_profiles(self, body: Dict, query: Dict) -> Dict:
        return {"profiles": list_profiles(), "last_used": last_used()}

    def api_profile_load(self, body: Dict, query: Dict) -> Dict:
        name = (query.get("name") or [""])[0]
        try:
            profile = load_profile(name)
        except ConfigError as exc:
            raise ApiError(404, str(exc))
        set_last_used(name)
        return {"name": name, "profile": profile}

    def api_profile_save(self, body: Dict, query: Dict) -> Dict:
        name = body.get("name") or ""
        try:
            profile = save_profile(name, body.get("profile") or {})
        except ConfigError as exc:
            raise ApiError(400, str(exc))
        return {"name": name, "profile": profile, "profiles": list_profiles()}

    def api_profile_delete(self, body: Dict, query: Dict) -> Dict:
        try:
            delete_profile(body.get("name") or "")
        except ConfigError as exc:
            raise ApiError(404, str(exc))
        return {"profiles": list_profiles(), "last_used": last_used()}

    def api_preview(self, body: Dict, query: Dict) -> Dict:
        try:
            return preview_filter(body.get("profile") or {})
        except ConfigError as exc:
            raise ApiError(400, str(exc))

    def api_start(self, body: Dict, query: Dict) -> Dict:
        try:
            self.controller.start(body.get("profile") or {})
        except ConfigError as exc:
            raise ApiError(400, str(exc))
        except PermissionError:
            raise ApiError(
                403,
                "sending raw GRE needs CAP_NET_RAW. Run 'spantap-sim doctor', or "
                "choose the pcap-file output instead.",
            )
        except (RuntimeError, OSError, FileNotFoundError, ValueError) as exc:
            raise ApiError(400, str(exc))
        return self.controller.snapshot(sample=False)

    def api_stop(self, body: Dict, query: Dict) -> Dict:
        self.controller.stop()
        return self.controller.snapshot(sample=False)

    # -- dispatch ----------------------------------------------------------

    def dispatch(self, method: str, path: str, query: Dict, body: Dict) -> Any:
        handler = self.routes.get((method, path))
        if handler is None:
            raise ApiError(404, "no such endpoint: %s %s" % (method, path))
        return handler(body, query)


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "spantap/" + __version__
    protocol_version = "HTTP/1.1"

    gui: GuiServer
    allowed_hosts: Tuple[str, ...]
    url_scheme: str = "http"

    # -- helpers -----------------------------------------------------------

    def log_message(self, fmt, *args):  # quieter than the default
        if self.server.verbose:  # type: ignore[attr-defined]
            sys.stderr.write("  %s - %s\n" % (self.address_string(), fmt % args))

    #: set by _guard_auth when a token arrived in the URL and should be remembered
    _remember_token = ""
    #: a complete Set-Cookie value to emit with this response (sign in / out)
    _set_cookie = ""

    #: "no-referrer" everywhere, so a URL carrying ?token=... never appears in
    #: a Referer header at all. The sign-in card is the one exception, and the
    #: reason is not privacy: Chrome derives the Origin header of a form
    #: submission from the same machinery as the referrer, so under
    #: "no-referrer" it posts our own sign-in form with "Origin: null" — an
    #: opaque origin — which the cross-origin check then correctly refuses.
    #: "same-origin" lets that page identify itself to us and still sends
    #: nothing to any other site. Only a real browser finds this: a hand-built
    #: POST sets whatever Origin it likes. See test_webui.py.
    _referrer_policy = "no-referrer"

    def _send(self, status: int, payload: bytes, content_type: str) -> None:
        if status >= 400:
            # Never keep a connection alive after an error: if a request body
            # was not consumed, whatever is left in the stream would be parsed
            # as the next request, which is request smuggling against ourselves.
            self.close_connection = True
        self.send_response(status)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        if self._set_cookie:
            self.send_header("Set-Cookie", self._set_cookie)
        if self._remember_token:
            # HttpOnly so a script cannot read it, SameSite=Strict so a foreign
            # page cannot cause it to be sent — the Origin check already
            # refuses those, this is the belt to its braces.
            cookie = ("%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict"
                      % (TOKEN_COOKIE, self._remember_token, TOKEN_COOKIE_MAX_AGE))
            if self.url_scheme == "https":
                cookie += "; Secure"
            self.send_header("Set-Cookie", cookie)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", self._referrer_policy)
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            # 'self', not 'none': the token page is a form, and 'none' blocks
            # its submission silently, with no error anywhere the user can see.
            "img-src data:; connect-src 'self'; base-uri 'none'; form-action 'self'",
        )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _json(self, status: int, data: Any) -> None:
        self._send(status, json.dumps(data).encode("utf-8"), "application/json")

    def _expected_origins(self) -> set:
        port = self.server.server_address[1]  # type: ignore[attr-defined]
        scheme = self.url_scheme
        default_port = 443 if scheme == "https" else 80
        out = set()
        for host in self.allowed_hosts:
            bracketed = "[%s]" % host if ":" in host else host
            out.add("%s://%s:%d" % (scheme, bracketed, port))
            if port == default_port:
                out.add("%s://%s" % (scheme, bracketed))
        return out

    #: The signed-in user for this request: a name, "token" for token auth,
    #: or "" before _guard_auth has run.
    _user = ""

    def _guard_origin(self) -> None:
        """Reject anything that is not this page talking to its own server.

        This half runs for every request including the login form, because a
        page that is about to be handed a password must be at least as well
        protected as the rest — not less.
        """
        raw_host = self.headers.get("Host")
        if raw_host is None:
            raise ApiError(400, "missing Host header")
        host = raw_host.rsplit(":", 1)[0] if raw_host.count(":") == 1 else raw_host
        host = host.strip("[]") or raw_host
        if host not in self.allowed_hosts:
            # Reaching the UI by a name the server was not told about is the
            # single most likely way to hit this, so say how to fix it rather
            # than only that it was refused.
            raise ApiError(
                403,
                "this server does not answer to the name %r. If that is how you "
                "reach it, start it with --allow-host %s (or set "
                "SPANTAP_ALLOW_HOSTS)." % (raw_host, host),
            )

        origin = self.headers.get("Origin")
        # Compare the whole origin, not just the hostname: another service on
        # this very host is a different origin and must not drive this API.
        if origin and origin not in self._expected_origins():
            raise ApiError(403, "cross-origin request refused")

    def _guard_auth(self) -> None:
        """Establish who is asking: a login session, the token, or nobody."""
        # A session is checked first: it is the stronger statement, it names a
        # user, and it is what someone who has logged in expects to be using.
        user = self.gui.sessions.lookup(self._cookie(SESSION_COOKIE))
        if user:
            self._user = user
            return

        token = self.gui.token
        if not token:
            # No token configured means loopback-only, where the UI is as
            # reachable as any other program the user is already running.
            self._user = "local"
            return

        # The token may arrive three ways: the header the page's own fetches
        # use, a query parameter (the printed URL), or the cookie set after a
        # successful visit — which is what lets the bare address work later
        # without the token trailing behind it in history and screenshots.
        from_url = (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
        candidates = [
            (self.headers.get("X-Spantap-Token") or self.headers.get("X-Erspan-Token") or "", False),
            (from_url, True),
            (self._cookie(TOKEN_COOKIE), False),
        ]
        for given, should_remember in candidates:
            if not given:
                continue
            try:
                ok = secrets.compare_digest(given, token)
            except TypeError:       # a non-ASCII value cannot be the token
                ok = False
            if ok:
                if should_remember:
                    self._remember_token = given
                self._user = "token"
                return
        if any(given for given, _ in candidates):
            raise ApiError(401, "that token was not accepted")
        raise ApiError(401, "no access token was supplied")

    def _cookie(self, name: str) -> str:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value
        return ""

    def _wants_html(self, path: str) -> bool:
        if path.startswith("/api"):
            return False
        return "text/html" in (self.headers.get("Accept") or "") or path == "/"

    def _read_body(self, allow_form: bool = False) -> Dict:
        """Consume the request body — always, and before anything else.

        Every path out of here has already taken the declared number of bytes
        off the socket (or marked the connection for closing), so no unread
        body can ever be mistaken for the next request on a keep-alive
        connection.
        """
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            if (self.headers.get("Transfer-Encoding") or "").lower() != "identity" \
                    and self.headers.get("Transfer-Encoding"):
                self.close_connection = True
                raise ApiError(411, "chunked request bodies are not accepted")
            return {}
        try:
            length = int(raw_len)
        except ValueError:
            self.close_connection = True
            raise ApiError(400, "malformed Content-Length")
        if length < 0:
            self.close_connection = True
            raise ApiError(400, "negative Content-Length")
        if length == 0:
            return {}
        if length > MAX_BODY:
            self.close_connection = True
            raise ApiError(413, "request body too large")

        raw = self.rfile.read(length)
        if len(raw) != length:
            self.close_connection = True
            raise ApiError(400, "truncated request body")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if allow_form and ctype == "application/x-www-form-urlencoded":
            # Only the login route asks for this. Accepting form encoding
            # everywhere would let a plain cross-site <form> reach the whole
            # API; the Origin check and SameSite=Strict already refuse that,
            # but there is no reason to lean on them for routes that have no
            # use for it.
            try:
                fields = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
            except UnicodeDecodeError as exc:
                raise ApiError(400, "invalid form encoding: %s" % exc)
            return {k: v[0] for k, v in fields.items()}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(400, "invalid JSON: %s" % exc)
        if not isinstance(data, dict):
            raise ApiError(400, "the request body must be a JSON object")
        return data

    def _receive_capture(self, query: Dict) -> None:
        """The one request whose body is streamed to disk instead of parsed.

        A capture can be hundreds of megabytes, so it does not go through
        :meth:`_read_body`, which exists to keep an unread body from being
        mistaken for the next request on a keep-alive connection. This route
        buys the same guarantee a different way: the connection is closed
        unconditionally, before anything else happens. Nothing is left in the
        stream to smuggle because the stream is not reused — and that also
        means an unauthorised upload is refused without first reading half a
        gigabyte from whoever sent it.
        """
        self.close_connection = True
        self._guard_origin()
        self._guard_auth()

        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            raise ApiError(411, "an upload needs a Content-Length")
        try:
            length = int(raw_len)
        except ValueError:
            raise ApiError(400, "malformed Content-Length")
        if length <= 0:
            raise ApiError(400, "that upload is empty")

        name = (query.get("name") or [""])[0]
        try:
            entry = save_upload(self.rfile, length, name)
        except UploadError as exc:
            raise ApiError(400, str(exc))
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                raise ApiError(507, "no space left where captures are kept")
            raise ApiError(500, exc.strerror or str(exc))
        self._json(200, {
            "capture": entry,
            "captures": list_captures(),
            "storage": storage(),
        })

    # -- verbs -------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def _handle(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        try:
            if method == "POST" and path == UPLOAD_PATH:
                return self._receive_capture(parse_qs(parsed.query))
            body = self._read_body(allow_form=path == LOGIN_PATH)
            # Origin and Host first, for every request including the login
            # form. Only the check of *who* is asking is skipped below, and
            # only for the two routes whose whole purpose is not knowing yet.
            self._guard_origin()
            if path == LOGIN_PATH:
                return (self._login_page() if method == "GET"
                        else self._do_login(body))
            self._guard_auth()
            if method == "POST" and path == LOGOUT_PATH:
                return self._do_logout()
            if method == "GET" and path == WHOAMI_PATH:
                return self._json(200, self._auth_state())
            if not path.startswith("/api"):
                return self._serve_static(path)
            result = self.gui.dispatch(method, path, parse_qs(parsed.query), body)
            if path == "/api/bootstrap" and isinstance(result, dict):
                # Who is asking is known to the handler, not to GuiServer —
                # it is a property of the connection, not of the server — so
                # it is attached here rather than threaded through dispatch.
                result["auth"] = self._auth_state()
            self._json(200, result)
        except ApiError as exc:
            # A browser asking for a page deserves a page, not raw JSON it
            # cannot act on. This is the first thing anyone sees when they
            # open the bare address, so it explains itself and offers the box.
            if exc.status == 401 and self._wants_html(path):
                self._auth_page(exc.message)
            elif exc.status == 403 and self._wants_html(path):
                self._html_error(
                    403,
                    "Refused: this request came from another page"
                    if "cross-origin" in exc.message else
                    "Not reachable by that name",
                    exc.message)
            else:
                self._json(exc.status, {"error": exc.message})
        except BrokenPipeError:
            pass
        except Exception as exc:  # noqa: BLE001 — never take the server down
            self._json(500, {"error": "%s: %s" % (type(exc).__name__, exc)})

    @staticmethod
    def _strip_section(page: str, tag: str) -> str:
        start = page.find("<!--%s-->" % tag)
        end = page.find("<!--/%s-->" % tag)
        if start == -1 or end == -1:
            return page
        return page[:start] + page[end + len(tag) + 8:]

    def _token_hint(self) -> str:
        """Where this server's token can be found, as HTML."""
        if in_container():
            service = compose_service(self.gui.effective.get("overridden") or ())
            return ("To see it, on the host: <code>docker compose exec %s "
                    "spantap-sim token</code>." % service)
        return ("To see it, on the host: <code>spantap-sim token</code> — it "
                "was also printed when the UI started.")

    def _html_error(self, status: int, title: str, message: str,
                    forms: Tuple[str, ...] = ()) -> None:
        """Render the auth card, showing only the forms that can be used here."""
        import html
        page = TOKEN_PAGE % {"title": html.escape(title), "message": html.escape(message),
                             "token_hint": self._token_hint()}
        for tag in ("LOGIN", "TOKEN"):
            if tag.lower() not in forms:
                page = self._strip_section(page, tag)
        if "login" in forms:
            self._referrer_policy = "same-origin"   # see the attribute's note
        self._send(status, page.encode("utf-8"), "text/html; charset=utf-8")

    def _password_login_allowed(self) -> bool:
        """Whether a password may be sent on this connection at all.

        Over plain HTTP a password crosses the network in the clear, and
        unlike a single-purpose token it is the sort of secret people reuse
        elsewhere. So off loopback it is refused outright, and the token —
        which has no value anywhere but here — remains the way in until TLS
        is configured. That is deliberately the order of the first-run flow:
        arrive with the token, set up the certificate, then log in.
        """
        if self.url_scheme == "https":
            return True
        peer = (self.client_address[0] if self.client_address else "") or ""
        return peer in ("127.0.0.1", "::1", "::ffff:127.0.0.1") or peer.startswith("127.")

    def _offered_forms(self) -> Tuple[str, ...]:
        forms = []
        if any_users() and self._password_login_allowed():
            forms.append("login")
        if self.gui.token:
            forms.append("token")
        return tuple(forms)

    def _auth_page(self, message: str, status: int = 401) -> None:
        rejected = "not accepted" in message
        forms = self._offered_forms()
        if not forms:
            # Accounts exist but cannot be used here, and there is no token:
            # say which, because "unauthorised" alone is unactionable.
            return self._html_error(
                status, "Sign-in is not available on this connection",
                "This server has accounts, but a password will not be accepted "
                "over plain HTTP from another host. Reach it over HTTPS, or "
                "start it with a token.", ())
        if rejected:
            title, detail = "That was not accepted", "Check it and try again."
        elif "login" in forms and "token" in forms:
            title = "This page needs a sign-in"
            detail = ("Sign in with your account, or paste the access token if "
                      "you have not made an account yet.")
        elif "login" in forms:
            title = "This page needs a sign-in"
            detail = "It is served on an address other than loopback."
        else:
            title = "This page needs an access token"
            detail = ("It is served on an address other than loopback, so it "
                      "asks for the token before letting anyone start or stop "
                      "traffic on this host.")
        self._html_error(status, title, detail, forms)

    def _auth_state(self) -> Dict:
        """How this request is authenticated, and what else is possible here.

        The UI needs all of it: whose name to show, whether to offer a Logout
        control at all, and — when someone arrived with the token over plain
        HTTP — why the sign-in form is not being offered yet.
        """
        session_user = self.gui.sessions.lookup(self._cookie(SESSION_COOKIE))
        return {
            "user": session_user or "",
            "method": "session" if session_user else self._user,
            "accounts_exist": any_users(),
            "token_set": bool(self.gui.token),
            "password_login_possible": self._password_login_allowed(),
            "secure": self.url_scheme == "https",
        }

    # -- signing in and out ------------------------------------------------

    def _login_page(self) -> None:
        if self.gui.sessions.lookup(self._cookie(SESSION_COOKIE)):
            return self._redirect("/")
        self._auth_page("", status=200)

    def _redirect(self, where: str) -> None:
        self.send_response(303)
        self.send_header("Location", where)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        if self._set_cookie:
            self.send_header("Set-Cookie", self._set_cookie)
        self.end_headers()

    def _do_login(self, body: Dict) -> None:
        if not any_users():
            raise ApiError(
                403, "no accounts exist yet. Create one on the host with "
                     "'spantap-sim users add <name>'.")
        if not self._password_login_allowed():
            raise ApiError(
                403, "a password will not be accepted over plain HTTP from "
                     "another host — it would cross the network in the clear. "
                     "Use the token here and configure TLS in Settings, then "
                     "sign in over HTTPS.")

        name = (body.get("username") or "").strip()
        password = body.get("password") or ""
        peer = (self.client_address[0] if self.client_address else "") or ""
        user_key = "user:" + name.lower()
        peer_key = "peer:" + peer

        wait = self.gui.throttle.retry_after(user_key, peer_key)
        if wait > 0:
            # 429 rather than 401: this is not a wrong password, it is a
            # refusal to even look at one yet.
            raise ApiError(429, "too many failed sign-ins. Try again in %s."
                                % describe_wait(wait))

        user = verify_password(name, password)
        if not user:
            self.gui.throttle.record_failure(user_key, peer_key)
            self.log_message("failed sign-in for %r from %s", name, peer)
            # One message for both cases: saying which half was wrong tells a
            # stranger which user names exist.
            return self._auth_page("that was not accepted")

        self.gui.throttle.clear(user_key)
        note_login(user)
        sid = self.gui.sessions.create(
            user, peer=peer, old_sid=self._cookie(SESSION_COOKIE))
        self._set_cookie = self._session_cookie(sid)
        self.log_message("signed in as %r from %s", user, peer)
        self._redirect("/")

    def _do_logout(self) -> None:
        self.gui.sessions.destroy(self._cookie(SESSION_COOKIE))
        self._set_cookie = ("%s=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict%s"
                            % (SESSION_COOKIE,
                               "; Secure" if self.url_scheme == "https" else ""))
        self._json(200, {"ok": True})

    def _session_cookie(self, sid: str) -> str:
        cookie = "%s=%s; Path=/; HttpOnly; SameSite=Strict" % (SESSION_COOKIE, sid)
        # No Max-Age: a session cookie dies with the browser, and the server
        # is the thing that decides how long it stays valid anyway.
        if self.url_scheme == "https":
            cookie += "; Secure"
        return cookie

    def _serve_static(self, path: str) -> None:
        name = "index.html" if path == "/" else os.path.basename(path)
        full = os.path.join(STATIC_DIR, name)
        if not os.path.isfile(full) or os.path.dirname(os.path.abspath(full)) != STATIC_DIR:
            raise ApiError(404, "not found")
        with open(full, "rb") as fh:
            payload = fh.read()
        ctype = "text/html; charset=utf-8" if name.endswith(".html") else "application/octet-stream"
        self._send(200, payload, ctype)


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    verbose = False


LOOPBACK = ("127.0.0.1", "::1", "localhost")


def _env_list(name: str, legacy: Optional[str] = None) -> list:
    raw = os.environ.get(name) or (os.environ.get(legacy) if legacy else None) or ""
    return [part.strip() for part in raw.split(",") if part.strip()]


def make_server(
    bind: str,
    port: int,
    controller: Optional[SimulationController] = None,
    token: Optional[str] = None,
    verbose: bool = False,
    allow_hosts: Iterable[str] = (),
    tls_cert: Optional[str] = None,
    tls_key: Optional[str] = None,
    gateway=None,
    overridden: Iterable[str] = (),
) -> Tuple[_Server, GuiServer]:
    effective = {
        "bind": bind,
        "port": port,
        "allow_hosts": [h for h in allow_hosts if h],
        "tls": bool(tls_cert),
        "token_set": bool(token),
        "scheme": "https" if tls_cert else "http",
        # Settings a command-line flag or the environment is forcing. Saving a
        # different value in the UI cannot change these, and saying so is
        # better than letting someone save and restart into no change at all.
        "overridden": sorted(set(overridden)),
    }
    gui = GuiServer(controller, token, gateway, effective)

    allowed = {bind, "localhost", "127.0.0.1", "::1"}
    if bind in ("0.0.0.0", "::", ""):
        allowed.update(i["ipv4"] for i in list_interfaces() if i["ipv4"])
    allowed.update(h.strip() for h in allow_hosts if h and h.strip())
    allowed.discard("")

    scheme = "https" if tls_cert else "http"
    handler = type(
        "Handler", (_Handler,),
        {"gui": gui, "allowed_hosts": tuple(sorted(allowed)), "url_scheme": scheme},
    )
    server = _Server((bind, port), handler)
    server.verbose = verbose

    if tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tls_cert, tls_key or tls_cert)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    gui.effective["port"] = server.server_address[1]
    return server, gui


def _primary_ipv4() -> Optional[str]:
    """The address this host would send from; connect() on UDP sends nothing."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))   # TEST-NET-1, never actually reached
        addr = probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()
    return None if addr.startswith("127.") or addr == "0.0.0.0" else addr


def reachable_urls(bind: str, port: int, scheme: str, token: Optional[str],
                   allow_hosts: Iterable[str] = ()) -> list:
    """Every address this server can sensibly be opened at."""
    hosts = []
    if bind in ("0.0.0.0", "::", ""):
        hosts.append("127.0.0.1")
        hosts.extend(i["ipv4"] for i in list_interfaces()
                     if i["ipv4"] and not i["loopback"])
        if len(hosts) == 1:
            # No /sys/class/net (macOS): at least name the default-route address.
            primary = _primary_ipv4()
            if primary:
                hosts.append(primary)
    else:
        hosts.append(bind)
    hosts.extend(h for h in allow_hosts if h and h not in hosts)
    suffix = "?token=" + token if token else ""
    return ["%s://%s:%d/%s" % (scheme, h, port, suffix) for h in hosts]


DOCS_URL = "https://github.com/netwho/spantap#the-web-ui"
DOCS_REMOTE_URL = "https://github.com/netwho/spantap#reaching-it-from-another-host"
DOCS_ACCOUNTS_URL = "https://github.com/netwho/spantap#accounts-or-a-bare-token"


def compose_service(overridden: Iterable[str]) -> str:
    """Which docker-compose.yml service this is: only gui-lan forces --bind."""
    return "gui-lan" if "bind" in overridden else "gui"


def _print_banner(urls: list, port: int, loopback: bool, tls: bool,
                  token: Optional[str], token_saved: bool,
                  overridden: Iterable[str] = ()) -> None:
    """Where to open the UI, how to get in, and where it is documented."""
    w = sys.stderr.write
    w("spantap %s — web UI\n\n" % __version__)
    w("  Open it at:\n")
    for i, url in enumerate(urls):
        w("    %s%s\n" % (url, "   (this host)" if i == 0 else ""))
    w("\n")

    w("  Access:\n")
    if token:
        w("    token     %s\n" % token)
        if token_saved:
            w("              generated and saved to %s —\n"
              "              it stays the same across restarts\n" % webui_path())
        w("              in the URL (?token=…), pasted into the page it asks for,\n"
          "              or as the X-Spantap-Token header for curl/scripts\n")
    else:
        w("    no token  bound to loopback, so only this host can reach it\n")
        if "bind" not in overridden:
            w("              (127.0.0.1 is saved in %s — for the network, use\n"
              "              --bind 0.0.0.0 or set Listen on in the Settings tab)\n"
              % webui_path())
    w("    accounts  %s\n" % (
        "sign-in form enabled" if any_users()
        else "none yet — add one with: spantap-sim users add NAME"))
    if in_container():
        service = compose_service(overridden)
        w("    Docker    docker compose exec %s spantap-sim users add NAME\n"
          "              docker compose exec %s spantap-sim token --urls\n"
          % (service, service))
    else:
        w("    again     spantap-sim token --urls\n")
    w("    tunnel    ssh -L %d:127.0.0.1:%d <this host>\n\n" % (port, port))

    if not loopback:
        w("  ! Reachable from the network. Anyone who can open one of those\n"
          "    URLs can start and stop traffic on this host, so:\n"
          "      - the token above is the only thing in the way — keep it out\n"
          "        of shared terminals and shell history\n")
        if not tls:
            w("      - there is no TLS, so the token and everything the page\n"
              "        shows crosses the network in clear text. Enable HTTPS on\n"
              "        the Settings tab, pass --tls-cert/--tls-key, or bind\n"
              "        127.0.0.1 and use the SSH tunnel above\n")
        w("      - restrict the port to the hosts that need it\n"
          "    Reaching it by a DNS name also needs --allow-host <name>.\n\n")

    w("  Docs:\n"
      "    README.md in the source tree, section \"The web UI\"\n"
      "    %s\n"
      "    %s\n"
      "    %s\n\n" % (DOCS_URL, DOCS_ACCOUNTS_URL, DOCS_REMOTE_URL))

    w("  config: %s\n  Ctrl-C to quit.\n\n" % config_dir())


def serve(bind: Optional[str] = None, port: Optional[int] = None,
          open_browser: bool = True, token: Optional[str] = None,
          verbose: bool = False, allow_hosts: Iterable[str] = (),
          tls_cert: Optional[str] = None, tls_key: Optional[str] = None) -> int:
    """Run the UI until interrupted. Returns a process exit code.

    Settings come from three places, in order: an explicit command-line flag,
    then the environment, then what was saved from the Settings tab, then the
    defaults. A flag always wins, which is the way back in if a saved setting
    ever locks you out.
    """
    stored = load_webui_or_default()
    overridden = []
    if bind is None:
        bind = stored["bind"]
    else:
        overridden.append("bind")
    if port is None:
        port = stored["port"]
    else:
        overridden.append("port")
    env_hosts = _env_list("SPANTAP_ALLOW_HOSTS", legacy="ERSPAN_SIM_ALLOW_HOSTS")
    if allow_hosts or env_hosts:
        overridden.append("allow_hosts")
    allow_hosts = list(allow_hosts) + env_hosts + list(stored["allow_hosts"])
    env_token = legacy_env("SPANTAP_TOKEN", "ERSPAN_SIM_TOKEN")
    if token or env_token:
        overridden.append("token")
    token = token or env_token or stored["token"] or None
    if tls_cert is None:
        tls_cert = stored["tls"]["cert"] or None
        tls_key = tls_key or stored["tls"]["key"] or None
    else:
        overridden.append("tls")

    loopback = bind in LOOPBACK
    token_saved = False
    if not loopback and not token:
        # Reachable from the network without a token would be an unauthenticated
        # control plane for a traffic generator. Generate one rather than ask,
        # and keep it: with 0.0.0.0 the default, a token that changed on every
        # restart would lock people out of a bookmarked address each time.
        token, token_saved = new_webui_token()

    if tls_key and not tls_cert:
        sys.stderr.write("error: --tls-key needs --tls-cert\n")
        return 2

    # Say it at startup rather than at the first save. An unwritable config
    # directory does not stop the UI running — reading works, traffic runs —
    # but every Save, every profile and every account would fail later, one
    # error at a time, with nothing tying them together.
    try:
        check_writable(config_dir())
    except ConfigError as exc:
        sys.stderr.write(
            "\n  ! %s\n"
            "    The UI will still run, but nothing can be saved until that is\n"
            "    fixed: no settings, no profiles, no accounts.\n\n" % exc)
    try:
        server, gui = make_server(bind, port, token=token, verbose=verbose,
                                  allow_hosts=allow_hosts,
                                  tls_cert=tls_cert, tls_key=tls_key,
                                  overridden=overridden)
    except (ssl.SSLError, OSError) as exc:
        if isinstance(exc, OSError) and exc.errno == errno.EADDRINUSE:
            # Falling back would retry the same port and fail identically, so
            # say what is actually wrong instead of offering a useless retry.
            sys.stderr.write(
                "\nerror: something is already listening on %s:%s.\n"
                "       Another copy of the UI is the usual cause — the 'gui' and\n"
                "       'gui-lan' services are two ways to run the same thing and\n"
                "       cannot both hold this port. Stop one:\n"
                "         docker compose stop gui        # or gui-lan\n"
                "       Or give this one a different port with --port.\n"
                "       What has it:  ss -ltnp 'sport = :%s'\n\n" % (bind, port, port)
            )
            return 2
        # A saved address or certificate that stopped working must not leave
        # the UI unreachable with no way to fix it from the UI. Come back on
        # loopback without TLS — no new network exposure — and say why.
        sys.stderr.write(
            "\n  ! Could not start on %s:%s — %s\n"
            "    Falling back to 127.0.0.1 so you can reach it through an SSH\n"
            "    tunnel and correct the settings.\n\n" % (bind, port, exc)
        )
        try:
            bind, tls_cert, tls_key, loopback = "127.0.0.1", None, None, True
            server, gui = make_server(bind, port or 8420, token=token,
                                      verbose=verbose, allow_hosts=allow_hosts,
                                      overridden=overridden)
        except OSError as exc2:
            sys.stderr.write("error: and loopback failed too — %s\n" % exc2)
            return 2

    port = gui.effective["port"]
    scheme = "https" if tls_cert else "http"
    urls = reachable_urls(bind, port, scheme, token, allow_hosts)

    _print_banner(urls, port, loopback, bool(tls_cert), token, token_saved,
                  overridden)

    # urls[0] is always this host (127.0.0.1 for a wildcard bind).
    if open_browser and (loopback or bind in ("0.0.0.0", "::", "")) \
            and (os.environ.get("DISPLAY") or sys.platform == "darwin"):
        import webbrowser
        threading.Timer(0.3, lambda: webbrowser.open(urls[0])).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nstopping…\n")
    finally:
        gui.controller.stop()
        gui.gateway.stop()
        server.shutdown()
        server.server_close()
    return 0
