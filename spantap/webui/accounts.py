# SPDX-License-Identifier: GPL-2.0-or-later
"""Named accounts for the web UI.

A password is a weaker secret than the random token it sits beside — it is
short, chosen by a person, and often reused — so the value here is not
strength but *identity*: who started the traffic, whose access to revoke, and
a credential that can be changed without restarting anything.

Everything that follows exists because of that weakness:

* **scrypt**, from the standard library, with parameters that make a guess
  cost real memory and time rather than a hash.  The cost lands on an
  attacker's dictionary, not on the one login a person does a day.
* **A dummy verification for unknown users**, so the time taken to answer does
  not say whether the name exists.  Usernames are not secret, but leaking the
  list of them for free is a gift to anyone guessing.
* **Length, not composition.**  A long passphrase beats a short one with a
  digit bolted on, and composition rules mostly produce ``Password1!``.

The file is JSON at mode 0600.  It holds hashes, never passwords, and the
parameters are stored alongside each hash so that raising them later does not
invalidate anyone's existing password.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import time
from typing import Dict, List, Optional

from ..config import ConfigError, check_writable, config_dir


class AccountError(ValueError):
    """Something the caller can fix: a bad name, a weak password, a clash."""


#: scrypt work factors. n is the memory/time knob: 2**15 with r=8 is 32 MiB
#: and a few hundred milliseconds, which is nothing once a day and ruinous a
#: billion times. Stored per record so these can be raised without a flag day.
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
#: OpenSSL's default maxmem is 32 MiB, which the parameters above sit exactly
#: on; without this the call fails rather than running slowly.
SCRYPT_MAXMEM = 96 * 1024 * 1024

#: Long enough that guessing is hopeless, short enough that people comply.
MIN_PASSWORD = 12
MAX_PASSWORD = 1024

_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")


def users_path() -> str:
    return os.path.join(config_dir(), "users.json")


# -- hashing ---------------------------------------------------------------

def _derive(password: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
        dklen=dklen, maxmem=SCRYPT_MAXMEM,
    )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = _derive(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)
    return "scrypt$%d$%d$%d$%s$%s" % (
        SCRYPT_N, SCRYPT_R, SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(dk).decode(),
    )


def _check_hash(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, dk_b64 = encoded.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        got = _derive(password, salt, int(n), int(r), int(p), len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, expected)


#: Verified against when the account does not exist, so a wrong username costs
#: the same time as a wrong password and cannot be told apart from one.
_DUMMY = hash_password(secrets.token_urlsafe(32))


# -- validation ------------------------------------------------------------

def check_name(name: str) -> str:
    name = (name or "").strip().lower()
    if not _NAME.match(name):
        raise AccountError(
            "a user name is 1–32 characters of a–z, 0–9, dot, dash or "
            "underscore, starting with a letter or digit (got %r)" % name
        )
    return name


def check_password(password: str, name: str = "") -> str:
    if not isinstance(password, str):
        raise AccountError("the password must be text")
    if len(password) < MIN_PASSWORD:
        raise AccountError(
            "that password is %d characters; %d is the minimum. Length is what "
            "makes a password hard to guess — a phrase of a few words beats a "
            "short one with punctuation in it."
            % (len(password), MIN_PASSWORD)
        )
    if len(password) > MAX_PASSWORD:
        raise AccountError("that password is longer than %d characters" % MAX_PASSWORD)
    if name and password.strip().lower() == name.strip().lower():
        raise AccountError("the password cannot be the user name")
    if password.strip().lower() in ("spantap", "spantapsim", "password",
                                    "changeme", "letmein"):
        raise AccountError("that is one of the first passwords anyone tries")
    return password


# -- storage ---------------------------------------------------------------

def _empty() -> Dict:
    return {"version": 1, "users": {}}


def load() -> Dict:
    try:
        with open(users_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return _empty()
    except (OSError, ValueError) as exc:
        raise AccountError("%s could not be read: %s" % (users_path(), exc))
    if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
        raise AccountError("%s is not a user file" % users_path())
    return data


def _save(data: Dict) -> None:
    path = users_path()
    # An OSError escaping from here reached the user as a raw traceback, which
    # told them nothing about the config volume being owned by the wrong uid.
    try:
        check_writable(os.path.dirname(path), "configuration")
    except ConfigError as exc:
        raise AccountError(str(exc))
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".users-")
    try:
        os.fchmod(fd, 0o600)        # before any content is written to it
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise AccountError("%s could not be written: %s" % (path, exc.strerror or exc))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def any_users() -> bool:
    """Whether logging in is possible at all. False means token-only."""
    try:
        return bool(load()["users"])
    except AccountError:
        return False


def list_users() -> List[Dict]:
    users = load()["users"]
    out = []
    for name in sorted(users):
        rec = users[name]
        out.append({
            "name": name,
            "created": rec.get("created"),
            "last_login": rec.get("last_login"),
            "disabled": bool(rec.get("disabled")),
        })
    return out


def add_user(name: str, password: str) -> str:
    name = check_name(name)
    check_password(password, name)
    data = load()
    if name in data["users"]:
        raise AccountError("there is already a user called %r" % name)
    data["users"][name] = {
        "hash": hash_password(password),
        "created": time.time(),
        "last_login": None,
        "disabled": False,
    }
    _save(data)
    return name


def set_password(name: str, password: str) -> None:
    name = check_name(name)
    check_password(password, name)
    data = load()
    if name not in data["users"]:
        raise AccountError("no user called %r" % name)
    data["users"][name]["hash"] = hash_password(password)
    data["users"][name]["password_changed"] = time.time()
    _save(data)


def set_disabled(name: str, disabled: bool) -> None:
    name = check_name(name)
    data = load()
    if name not in data["users"]:
        raise AccountError("no user called %r" % name)
    if disabled and not _others_remain(data, name):
        raise AccountError(
            "%r is the only account that can still log in; disabling it would "
            "leave the token as the only way in" % name
        )
    data["users"][name]["disabled"] = bool(disabled)
    _save(data)


def remove_user(name: str) -> None:
    name = check_name(name)
    data = load()
    if name not in data["users"]:
        raise AccountError("no user called %r" % name)
    if not _others_remain(data, name):
        raise AccountError(
            "%r is the last account; removing it would leave the token as the "
            "only way in. Add another user first." % name
        )
    del data["users"][name]
    _save(data)


def _others_remain(data: Dict, name: str) -> bool:
    return any(n != name and not rec.get("disabled")
               for n, rec in data["users"].items())


def verify(name: str, password: str) -> Optional[str]:
    """Return the canonical user name, or None.

    An unknown or disabled account still pays for a full scrypt derivation, so
    the answer takes the same time however it is wrong.
    """
    try:
        name = check_name(name)
    except AccountError:
        _check_hash(password or "", _DUMMY)
        return None
    try:
        users = load()["users"]
    except AccountError:
        _check_hash(password or "", _DUMMY)
        return None
    rec = users.get(name)
    if rec is None or rec.get("disabled"):
        _check_hash(password or "", _DUMMY)
        return None
    if not _check_hash(password or "", rec.get("hash", "")):
        return None
    return name


def note_login(name: str) -> None:
    """Record a successful login. Best effort: never fail the login over it."""
    try:
        data = load()
        if name in data["users"]:
            data["users"][name]["last_login"] = time.time()
            _save(data)
    except (AccountError, OSError):
        pass
