# SPDX-License-Identifier: GPL-2.0-or-later
"""Generating a self-signed certificate for the UI, from the UI.

Only useful on a lab network — a self-signed certificate still makes browsers
complain, and it authenticates nothing. What it does buy is that the access
token and everything the page displays stop crossing the network in clear
text, which is the actual problem with binding the UI to an address.

This shells out to `openssl` rather than depending on a crypto library, since
the package has no dependencies and openssl is already present wherever this
runs. If it is missing, the UI says so and you point it at a certificate you
made elsewhere.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
from typing import Iterable, List, Tuple

from ..config import tls_dir
from ..interfaces import list_interfaces

DEFAULT_DAYS = 825   # what browsers accept for a leaf certificate


class CertUploadError(ValueError):
    """Refused: the caller can fix this by sending something else."""


def openssl_path() -> str:
    return shutil.which("openssl") or ""


# --------------------------------------------------------------------------
# reading a certificate back
#
# Pointing the UI at your own CA-issued certificate is the normal case; this
# is what lets it show you which one it actually loaded, and tell you when the
# names in it do not cover the names you configured — which is the failure a
# browser reports as an unhelpful security error.
# --------------------------------------------------------------------------

def _decode(path: str) -> dict:
    """Decode a PEM certificate without adding a dependency."""
    import ssl
    try:
        return ssl._ssl._test_decode_cert(path)          # type: ignore[attr-defined]
    except AttributeError:
        pass
    except Exception as exc:                              # noqa: BLE001
        raise ValueError(str(exc))
    openssl = openssl_path()
    if not openssl:
        raise ValueError("no way to read this certificate on this host")
    out = subprocess.run([openssl, "x509", "-in", path, "-noout", "-subject",
                          "-issuer", "-enddate", "-ext", "subjectAltName"],
                         capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        raise ValueError(out.stderr.strip()[:200] or "could not read the certificate")
    parsed: dict = {"subject": (), "issuer": (), "notAfter": "", "subjectAltName": ()}
    san = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if line.startswith("subject="):
            parsed["subject"] = ((("commonName", line.split("CN=", 1)[-1].strip()),),) \
                if "CN=" in line else ()
        elif line.startswith("issuer="):
            parsed["issuer"] = ((("commonName", line.split("CN=", 1)[-1].strip()),),) \
                if "CN=" in line else ()
        elif line.startswith("notAfter="):
            parsed["notAfter"] = line.split("=", 1)[1]
        elif line.startswith("DNS:") or line.startswith("IP Address:"):
            for item in line.split(","):
                item = item.strip()
                if item.startswith("DNS:"):
                    san.append(("DNS", item[4:]))
                elif item.startswith("IP Address:"):
                    san.append(("IP Address", item[11:]))
    parsed["subjectAltName"] = tuple(san)
    return parsed


def _rdn(value, key: str = "commonName") -> str:
    for rdn in value or ():
        for pair in rdn:
            if pair[0] == key:
                return pair[1]
    return ""


def describe(path: str) -> dict:
    """Subject, issuer, validity and the names a certificate covers."""
    import datetime
    if not path or not os.path.isfile(path):
        return {}
    try:
        raw = _decode(path)
    except ValueError as exc:
        return {"error": str(exc)}

    dns = [v for k, v in raw.get("subjectAltName", ()) if k == "DNS"]
    ips = [v for k, v in raw.get("subjectAltName", ()) if k == "IP Address"]
    subject = _rdn(raw.get("subject"))
    issuer = _rdn(raw.get("issuer"))
    days_left = None
    not_after = raw.get("notAfter") or ""
    if not_after:
        try:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days
        except ValueError:
            pass
    return {
        "subject": subject,
        "issuer": issuer,
        "not_after": not_after,
        "days_left": days_left,
        "dns": dns,
        "ips": ips,
        # Self-signed is only a hint for the UI, not a security judgement:
        # equal subject and issuer is what it looks like from here.
        "self_signed": bool(subject) and subject == issuer,
    }


def _matches(pattern: str, name: str) -> bool:
    pattern, name = pattern.lower(), name.lower()
    if pattern == name:
        return True
    if pattern.startswith("*.") and "." in name:
        # A wildcard covers exactly one label, per RFC 6125.
        return pattern[2:] == name.split(".", 1)[1]
    return False


def uncovered(info: dict, names: Iterable[str]) -> List[str]:
    """Which of ``names`` this certificate does not vouch for."""
    if not info or info.get("error"):
        return []
    dns = info.get("dns") or []
    ips = info.get("ips") or []
    missing = []
    for name in names:
        name = (name or "").strip()
        if not name:
            continue
        try:
            socket.inet_aton(name)
            is_ip = name.count(".") == 3
        except OSError:
            is_ip = False
        ok = name in ips if is_ip else any(_matches(p, name) for p in dns)
        if not ok and name not in missing:
            missing.append(name)
    return missing


def local_names() -> List[str]:
    """Names this host is plausibly reached by."""
    names = []
    try:
        host = socket.gethostname()
        if host:
            names.append(host)
            fqdn = socket.getfqdn()
            if fqdn and fqdn != host:
                names.append(fqdn)
    except OSError:
        pass
    return names


def local_addresses() -> List[str]:
    return [i["ipv4"] for i in list_interfaces() if i["ipv4"]]


def build_san(names: Iterable[str], addresses: Iterable[str]) -> Tuple[List[str], List[str]]:
    """Split the given values into DNS names and IP addresses, deduplicated."""
    dns: List[str] = []
    ips: List[str] = []
    for value in list(names) + list(addresses):
        value = (value or "").strip()
        if not value:
            continue
        try:
            socket.inet_aton(value)
            is_ip = value.count(".") == 3
        except OSError:
            is_ip = False
        target = ips if is_ip else dns
        if value not in target:
            target.append(value)
    if "localhost" not in dns:
        dns.append("localhost")
    if "127.0.0.1" not in ips:
        ips.append("127.0.0.1")
    return dns, ips


def generate_selfsigned(names: Iterable[str] = (), addresses: Iterable[str] = (),
                        days: int = DEFAULT_DAYS, directory: str = "") -> dict:
    """Write a certificate and key, returning their paths and what they cover."""
    openssl = openssl_path()
    if not openssl:
        raise RuntimeError(
            "openssl is not installed here, so a certificate cannot be generated. "
            "Create one elsewhere and give its path below."
        )

    names = list(names) or local_names()
    addresses = list(addresses) or local_addresses()
    dns, ips = build_san(names, addresses)
    subject_cn = (dns[0] if dns else ips[0])[:64]
    san = ",".join(["DNS:%s" % d for d in dns] + ["IP:%s" % i for i in ips])

    directory = directory or tls_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    cert = os.path.join(directory, "cert.pem")
    key = os.path.join(directory, "key.pem")

    result = subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", str(int(days)),
         "-subj", "/CN=%s" % subject_cn, "-addext", "subjectAltName=%s" % san],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError("openssl failed: %s" % (result.stderr.strip()[:400] or "unknown error"))

    try:
        os.chmod(key, 0o600)
        os.chmod(cert, 0o644)
    except OSError:
        pass

    return {
        "cert": cert,
        "key": key,
        "common_name": subject_cn,
        "dns": dns,
        "ips": ips,
        "days": int(days),
    }


# --------------------------------------------------------------------------
# uploading your own certificate and key, from the browser
#
# Fills the same fixed slot generate_selfsigned() writes into — cert.pem and
# key.pem in the config volume's tls directory — so an upload and a
# self-signed generation are two ways to set the one certificate currently in
# use, not an ever-growing list of files to manage. Nothing is kept unless it
# actually loads as a working certificate (and key), the same check the
# server itself runs at startup: a PEM-shaped blob that openssl would reject
# leaves nothing behind, exactly like a bad capture upload leaves no file.
# --------------------------------------------------------------------------

_MAX_PEM = 100_000   # generous for any real cert or key; not a limit worth raising

_PEM_BLOCK = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+)-----\r?\n.*?-----END \1-----", re.DOTALL)


def _is_encrypted(pem: str) -> bool:
    return "ENCRYPTED" in pem   # PKCS#8 "ENCRYPTED PRIVATE KEY" and legacy Proc-Type


def _refuse_encrypted(*_args) -> bytes:
    # Handed to load_cert_chain as the password callback: without one,
    # OpenSSL prompts on the controlling terminal for an encrypted key, which
    # hangs a server and confuses an installer. Refuse instead, with advice.
    raise CertUploadError(
        "the private key is encrypted (it has a passphrase). Remove the "
        "passphrase first, e.g. 'openssl pkey -in key.pem -out key-plain.pem', "
        "and use that file")


def split_pem(text: str) -> Tuple[str, str]:
    """Separate pasted PEM text into (certificate chain, private key).

    Accepts the certificate(s) and the key in any order, in one paste or
    concatenated from two, with anything between the blocks (the
    "Bag Attributes" lines some exports add, stray blank lines) ignored.
    The certificates keep the order they were given in, so a chain pasted
    leaf-first stays leaf-first.
    """
    text = (text or "").replace("\r\n", "\n")
    if len(text) > 2 * _MAX_PEM:
        raise CertUploadError("that is too large to be a certificate and key")
    certs: List[str] = []
    keys: List[str] = []
    for match in _PEM_BLOCK.finditer(text):
        label, block = match.group(1), match.group(0)
        if label == "CERTIFICATE":
            certs.append(block)
        elif label.endswith("PRIVATE KEY"):
            keys.append(block)
    if not certs:
        raise CertUploadError(
            "no certificate found — expected a block starting with "
            "'-----BEGIN CERTIFICATE-----'")
    if not keys:
        raise CertUploadError(
            "no private key found — expected a block starting with "
            "'-----BEGIN PRIVATE KEY-----' (or RSA/EC PRIVATE KEY)")
    if len(keys) > 1:
        raise CertUploadError("more than one private key was given; paste only the one "
                              "that belongs to the certificate")
    if _is_encrypted(keys[0]):
        _refuse_encrypted()
    return "\n".join(certs), keys[0]


def save_uploaded(cert_pem: str, key_pem: str = "", directory: str = "") -> dict:
    """Validate and store an uploaded certificate (and optionally a key).

    An empty *key_pem* means *cert_pem* is a combined PEM containing both the
    certificate and the key — the same convention the path-based fields
    already support by pointing both at the same file. In that case only one
    file is written and ``"key"`` in the return value is empty, matching what
    the Settings form already does with a combined file: leave the Key field
    blank.
    """
    cert_pem = (cert_pem or "").strip()
    key_pem = (key_pem or "").strip()
    if not cert_pem:
        raise CertUploadError("no certificate was sent")
    if len(cert_pem) > _MAX_PEM or len(key_pem) > _MAX_PEM:
        raise CertUploadError("that is too large to be a certificate or key")
    if "BEGIN" not in cert_pem:
        raise CertUploadError(
            "that does not look like a PEM certificate — it should start "
            "with a line like '-----BEGIN CERTIFICATE-----'")

    directory = directory or tls_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    combined = not key_pem

    cert_fd, cert_tmp = tempfile.mkstemp(prefix=".tmp-cert-", dir=directory)
    key_tmp = ""
    try:
        with os.fdopen(cert_fd, "w") as fh:
            fh.write(cert_pem)
            fh.write("\n")
        load_key_path = cert_tmp
        if not combined:
            key_fd, key_tmp = tempfile.mkstemp(prefix=".tmp-key-", dir=directory)
            with os.fdopen(key_fd, "w") as fh:
                fh.write(key_pem)
                fh.write("\n")
            load_key_path = key_tmp

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_tmp, load_key_path, password=_refuse_encrypted)
        except (ssl.SSLError, OSError) as exc:
            raise CertUploadError(
                "that could not be loaded as a certificate%s: %s"
                % ("" if combined else " and key", exc))

        cert_path = os.path.join(directory, "cert.pem")
        # A combined file holds the private key too, so it gets the key's
        # stricter permission rather than the certificate's public 0644.
        os.chmod(cert_tmp, 0o600 if combined else 0o644)
        os.replace(cert_tmp, cert_path)
        cert_tmp = ""
        key_path = ""
        if not combined:
            key_path = os.path.join(directory, "key.pem")
            os.chmod(key_tmp, 0o600)
            os.replace(key_tmp, key_path)
            key_tmp = ""
        return {"cert": cert_path, "key": key_path}
    finally:
        for tmp in (cert_tmp, key_tmp):
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
