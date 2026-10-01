# SPDX-License-Identifier: GPL-2.0-or-later
"""Capture files uploaded through the web UI.

A file arriving over the network from a browser is the least trustworthy input
this program has, and it lands on the filesystem, so three rules hold
throughout:

* **The server names the file, never the client.**  The submitted name is a
  hint; what is used is a sanitised basename in one fixed directory, and an
  existing file is never overwritten — a collision gets a numeric suffix.
* **The content must look like a capture before it is kept.**  The first bytes
  are checked against the pcap and pcapng magic numbers while the upload is
  still going to a temporary file.  Anything else is refused and the partial
  file removed, so an HTML page or a shell script cannot be parked here under
  a ``.pcap`` name.
* **Size is capped while reading, not by asking.**  ``Content-Length`` decides
  whether to start; the loop that reads the body enforces the cap regardless
  of what the header claimed.

The directory is deliberately flat and separate from the rest of the config:
everything in it is disposable, and nothing else in the program writes there.
"""

from __future__ import annotations

import errno
import os
import re
import tempfile
import time
from typing import BinaryIO, Dict, List, Optional, Tuple

from ..config import legacy_env
from ..sources.pcapread import (
    LINKTYPE_ETHERNET,
    LINKTYPE_IPV4,
    LINKTYPE_IPV6,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_RAW,
    LINKTYPE_RAW_BSD,
    PcapFormatError,
    open_packet_stream,
)


class UploadError(ValueError):
    """Refused: the caller can fix this by sending something else."""


#: Classic pcap in both byte orders and both timestamp resolutions, and the
#: pcapng Section Header Block. Everything else is rejected.
_MAGICS: Dict[bytes, str] = {
    b"\xd4\xc3\xb2\xa1": "pcap",            # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": "pcap",            # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": "pcap",            # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": "pcap",            # big-endian, nanoseconds
    b"\x0a\x0d\x0d\x0a": "pcapng",
}

_LINKTYPE_NAMES = {
    LINKTYPE_ETHERNET: "Ethernet",
    LINKTYPE_RAW: "raw IP",
    LINKTYPE_RAW_BSD: "raw IP (BSD)",
    LINKTYPE_IPV4: "raw IPv4",
    LINKTYPE_IPV6: "raw IPv6",
    LINKTYPE_LINUX_SLL: "Linux cooked",
    LINKTYPE_LINUX_SLL2: "Linux cooked v2",
}

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")

#: How much of a capture will be accepted in one upload. Generous enough for a
#: real trace, small enough that filling the disk takes deliberate effort.
DEFAULT_MAX_UPLOAD = 512 * 1024 * 1024

_CHUNK = 256 * 1024


def max_upload() -> int:
    raw = legacy_env("SPANTAP_MAX_UPLOAD_MB", "ERSPAN_SIM_MAX_UPLOAD_MB")
    if not raw:
        return DEFAULT_MAX_UPLOAD
    try:
        mb = int(raw)
    except ValueError:
        return DEFAULT_MAX_UPLOAD
    return max(1, mb) * 1024 * 1024


def capture_dir() -> str:
    """Where uploads live. One directory, no subdirectories, ever."""
    return legacy_env("SPANTAP_CAPTURE_DIR", "ERSPAN_SIM_CAPTURE_DIR") or os.path.join(
        os.path.expanduser("~"), "captures"
    )


def ensure_dir() -> str:
    path = capture_dir()
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise UploadError(
            "the capture directory %s cannot be created: %s. In a container this "
            "is usually a read-only mount — give it a writable one, or set "
            "SPANTAP_CAPTURE_DIR to somewhere this user can write."
            % (path, exc.strerror or exc)
        )
    if not os.access(path, os.W_OK | os.X_OK):
        raise UploadError(
            "the capture directory %s is not writable by uid %d. It is mounted "
            "read-only, or owned by another user." % (path, os.getuid())
        )
    return path


def safe_name(requested: str) -> str:
    """Turn a submitted filename into one that cannot escape the directory.

    Only the basename survives, and only characters that cannot mean anything
    to a shell, a path parser or a terminal. The extension is enforced rather
    than trusted: this directory holds captures and nothing else.
    """
    name = (requested or "").strip().replace("\\", "/")
    name = os.path.basename(name)
    name = _SAFE.sub("_", name).lstrip(".-") or "capture"

    stem, ext = os.path.splitext(name)
    if ext.lower() not in (".pcap", ".pcapng"):
        # Not a rejection: the magic-number check decides what the file really
        # is, and the extension is then made to agree with it.
        stem, ext = name, ""
    stem = stem[:96] or "capture"
    return stem + ext.lower()


def _unique(directory: str, name: str) -> str:
    """A path in *directory* that does not exist yet. Never overwrites."""
    stem, ext = os.path.splitext(name)
    candidate = name
    n = 1
    while os.path.lexists(os.path.join(directory, candidate)):
        candidate = "%s-%d%s" % (stem, n, ext)
        n += 1
        if n > 9999:
            raise UploadError("too many files named like %s" % name)
    return candidate


def _sniff(head: bytes) -> str:
    fmt = _MAGICS.get(head[:4])
    if fmt is None:
        raise UploadError(
            "this is not a capture file: it starts with %s, which is neither "
            "pcap nor pcapng. Wireshark can save one with File > Export "
            "Specified Packets, or convert it with 'editcap in.file out.pcapng'."
            % (" ".join("%02x" % b for b in head[:4]) or "nothing")
        )
    return fmt


def save_upload(stream: BinaryIO, length: int, requested: str) -> Dict:
    """Stream *length* bytes from *stream* into the capture directory.

    Returns the entry for the stored file. Raises :class:`UploadError` with
    something the user can act on, having left no partial file behind.
    """
    directory = ensure_dir()
    cap = max_upload()
    if length > cap:
        raise UploadError(
            "that capture is %s and the limit is %s. Cut it down with "
            "'editcap -c <packets>' or raise SPANTAP_MAX_UPLOAD_MB."
            % (human_size(length), human_size(cap))
        )

    fd, tmp = tempfile.mkstemp(prefix=".upload-", dir=directory)
    fmt = ""
    written = 0
    try:
        with os.fdopen(fd, "wb") as out:
            remaining = length
            while remaining > 0:
                chunk = stream.read(min(_CHUNK, remaining))
                if not chunk:
                    raise UploadError(
                        "the upload stopped after %s of %s — the connection "
                        "dropped or the browser gave up."
                        % (human_size(written), human_size(length))
                    )
                if not fmt and len(chunk) >= 4:
                    # Checked on the first bytes, before the bulk of the file
                    # has been written, so a wrong one costs nothing.
                    fmt = _sniff(chunk)
                written += len(chunk)
                remaining -= len(chunk)
                if written > cap:
                    raise UploadError("upload exceeded %s" % human_size(cap))
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        if not fmt:
            raise UploadError("that file is too short to be a capture")

        name = safe_name(requested)
        if not os.path.splitext(name)[1]:
            name += ".pcapng" if fmt == "pcapng" else ".pcap"
        name = _unique(directory, name)
        final = os.path.join(directory, name)
        # 0644, not mkstemp's 0600: in a container this directory is normally a
        # bind mount from the host, and files written here as the container's
        # uid would otherwise be unreadable to the person who uploaded them —
        # they could not open their own capture in Wireshark. Access is
        # controlled by the directory, which ensure_dir() creates as 0700 when
        # it creates it at all; a bind mount keeps whatever the host set.
        os.chmod(tmp, 0o644)
        os.rename(tmp, final)
        tmp = ""
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    entry = describe(final)
    entry["stored_as"] = name
    return entry


def describe(path: str) -> Dict:
    """Name, size and — if it parses — link type and first timestamp.

    Only the file header and the first record are read, so this stays cheap on
    a capture of any size.
    """
    st = os.stat(path)
    entry = {
        "name": os.path.basename(path),
        "path": path,
        "size": st.st_size,
        "mtime": st.st_mtime,
        "linktype": None,
        "linktype_name": "",
        "first_ts": None,
        "readable": False,
        "problem": "",
    }
    try:
        with open(path, "rb") as fh:
            for pkt in open_packet_stream(fh):
                entry["readable"] = True
                entry["linktype"] = pkt.linktype
                entry["linktype_name"] = _LINKTYPE_NAMES.get(
                    pkt.linktype, "link type %d" % pkt.linktype
                )
                entry["first_ts"] = pkt.ts_ns / 1e9
                break
            else:
                entry["problem"] = "the file parses but holds no packets"
    except PcapFormatError as exc:
        entry["problem"] = str(exc)
    except OSError as exc:
        entry["problem"] = exc.strerror or str(exc)
    return entry


def list_captures() -> List[Dict]:
    """Everything in the capture directory, newest first.

    A missing or unreadable directory is not an error here — it only means
    there is nothing to offer yet.
    """
    directory = capture_dir()
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    out = []
    for name in names:
        if name.startswith("."):
            continue                      # our own in-progress temporaries
        full = os.path.join(directory, name)
        try:
            if not os.path.isfile(full) or os.path.islink(full):
                continue
            out.append(describe(full))
        except OSError:
            continue
    out.sort(key=lambda e: e["mtime"], reverse=True)
    return out


def resolve(name: str) -> str:
    """The path of *name* inside the capture directory, or raise.

    The name is sanitised and then required to still match, so ``../`` and
    friends are refused rather than quietly rewritten into something valid.
    """
    directory = capture_dir()
    if not name or name != os.path.basename(name) or name in (".", ".."):
        raise UploadError("%r is not a name in the capture directory" % name)
    full = os.path.join(directory, name)
    if os.path.islink(full) or not os.path.isfile(full):
        raise UploadError("no capture named %r" % name)
    if os.path.dirname(os.path.realpath(full)) != os.path.realpath(directory):
        raise UploadError("%r is not in the capture directory" % name)
    return full


def delete_capture(name: str) -> None:
    full = resolve(name)
    try:
        os.unlink(full)
    except OSError as exc:
        if exc.errno == errno.EACCES:
            raise UploadError(
                "%s cannot be deleted: the capture directory is read-only for "
                "this user." % name
            )
        raise UploadError("%s could not be deleted: %s" % (name, exc.strerror or exc))


def human_size(n: float) -> str:
    for unit in ("B", "kB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f GB" % n


def _nearest_existing(path: str) -> Tuple[str, bool]:
    """The closest ancestor of *path* that exists, and whether *path* itself did.

    On a fresh install the capture directory has not been created yet, and
    ``ensure_dir`` will create it on the first upload. Judging writability by
    the directory alone would report "not writable" for a perfectly good
    location and disable the upload button before anyone ever used it.
    """
    if os.path.isdir(path):
        return path, True
    current = os.path.dirname(path.rstrip(os.sep)) or os.sep
    while current != os.sep and not os.path.isdir(current):
        current = os.path.dirname(current) or os.sep
    return current, False


def storage() -> Dict:
    """What the UI needs to explain the directory before anyone uploads."""
    directory = capture_dir()
    anchor, exists = _nearest_existing(directory)
    writable = os.path.isdir(anchor) and os.access(anchor, os.W_OK | os.X_OK)
    free: Optional[int] = None
    try:
        st = os.statvfs(anchor)
        free = st.f_bavail * st.f_frsize
    except OSError:
        pass
    return {
        "dir": directory,
        "writable": writable,
        "exists": exists,
        "free": free,
        "max_upload": max_upload(),
        "checked": time.time(),
    }
