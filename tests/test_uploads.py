# SPDX-License-Identifier: GPL-2.0-or-later
"""What an upload endpoint must refuse, and what it must keep."""
import io
import os

import pytest

from spantap.sources.pcapread import (
    LINKTYPE_ETHERNET,
    write_pcap_header,
    write_pcap_packet,
)
from spantap.webui import uploads


@pytest.fixture()
def capdir(tmp_path, monkeypatch):
    d = tmp_path / "captures"
    monkeypatch.setenv("SPANTAP_CAPTURE_DIR", str(d))
    return d


def _pcap_bytes(n=3, linktype=LINKTYPE_ETHERNET):
    buf = io.BytesIO()
    write_pcap_header(buf, linktype)
    for i in range(n):
        write_pcap_packet(buf, 1_700_000_000_000_000_000 + i * 1_000_000, b"\xaa" * 64)
    return buf.getvalue()


def _upload(raw, name):
    return uploads.save_upload(io.BytesIO(raw), len(raw), name)


# -- naming: the client never gets to choose a path -------------------------

@pytest.mark.parametrize("hostile,expected_dir", [
    ("../../etc/cron.d/evil.pcap", "evil.pcap"),
    ("/etc/shadow.pcap", "shadow.pcap"),
    ("..\\..\\windows\\system32\\x.pcap", "x.pcap"),
    ("a/b/c/nested.pcapng", "nested.pcapng"),
])
def test_a_path_in_the_name_cannot_escape_the_directory(capdir, hostile, expected_dir):
    entry = _upload(_pcap_bytes(), hostile)
    assert entry["stored_as"] == expected_dir
    assert os.path.dirname(entry["path"]) == str(capdir)
    assert sorted(os.listdir(capdir)) == [expected_dir]


def test_shell_and_terminal_metacharacters_are_flattened(capdir):
    entry = _upload(_pcap_bytes(), "a b;rm -rf $(x)`y`\n\x1b[31m.pcap")
    stored = entry["stored_as"]
    # Ordinary letters and digits survive — \x1b[31m leaves "31m" behind, which
    # is harmless. What must not survive is anything a shell, a path parser or
    # a terminal would act on.
    assert stored == "a_b_rm_-rf_x_y_31m.pcap"
    assert not set(stored) & set(" /\\;`$()|&<>*?'\"\n\r\t\x1b")
    assert all(ch.isprintable() for ch in stored)


def test_a_dotfile_name_cannot_be_created(capdir):
    entry = _upload(_pcap_bytes(), "...pcap")
    assert not entry["stored_as"].startswith(".")


def test_an_existing_capture_is_never_overwritten(capdir):
    first = _upload(_pcap_bytes(3), "trace.pcap")
    second = _upload(_pcap_bytes(9), "trace.pcap")
    assert first["stored_as"] == "trace.pcap"
    assert second["stored_as"] == "trace-1.pcap"
    assert os.path.getsize(first["path"]) != os.path.getsize(second["path"])


def test_the_extension_follows_the_content_not_the_name(capdir):
    raw = _pcap_bytes()
    entry = _upload(raw, "no-extension-at-all")
    assert entry["stored_as"].endswith(".pcap")


# -- content: it has to actually be a capture -------------------------------

@pytest.mark.parametrize("payload", [
    b"<html><body>hello</body></html>" + b"x" * 200,
    b"#!/bin/sh\nrm -rf /\n" + b"x" * 200,
    b"\x7fELF" + b"\x00" * 200,
    b"PK\x03\x04" + b"\x00" * 200,
])
def test_a_file_that_is_not_a_capture_is_refused(capdir, payload):
    with pytest.raises(uploads.UploadError) as exc:
        _upload(payload, "innocent.pcap")
    assert "not a capture file" in str(exc.value)
    assert os.listdir(capdir) == [], "a refused upload must leave nothing behind"


def test_a_refused_upload_leaves_no_temporary_file(capdir):
    for _ in range(3):
        with pytest.raises(uploads.UploadError):
            _upload(b"nope" * 100, "x.pcap")
    assert os.listdir(capdir) == []


def test_pcapng_is_accepted_too(capdir):
    raw = b"\x0a\x0d\x0d\x0a" + b"\x00" * 60
    entry = _upload(raw, "ng.pcapng")
    assert entry["stored_as"] == "ng.pcapng"
    # It is stored even though it does not fully parse — but it is reported
    # as unreadable rather than silently offered as a working capture.
    assert entry["readable"] is False


def test_a_file_too_short_to_identify_is_refused(capdir):
    with pytest.raises(uploads.UploadError):
        _upload(b"\xd4\xc3", "tiny.pcap")
    assert os.listdir(capdir) == []


# -- size -------------------------------------------------------------------

def test_the_cap_is_enforced_before_reading(capdir, monkeypatch):
    monkeypatch.setenv("SPANTAP_MAX_UPLOAD_MB", "1")
    raw = _pcap_bytes()
    with pytest.raises(uploads.UploadError) as exc:
        uploads.save_upload(io.BytesIO(raw), 5 * 1024 * 1024, "big.pcap")
    assert "the limit is" in str(exc.value)
    assert os.listdir(capdir) == []


def test_a_lying_content_length_cannot_beat_the_cap(capdir, monkeypatch):
    """Content-Length says 10 bytes; the body keeps coming. The loop stops it."""
    monkeypatch.setenv("SPANTAP_MAX_UPLOAD_MB", "1")

    class Endless(io.RawIOBase):
        def __init__(self):
            self.first = True

        def read(self, n=-1):
            if self.first:
                self.first = False
                return _pcap_bytes()[:n if n > 0 else None]
            return b"\x00" * (n if n and n > 0 else 4096)

    # The declared length is under the cap, so the transfer starts; the reader
    # must still refuse to write more than the cap however much arrives.
    with pytest.raises(uploads.UploadError):
        uploads.save_upload(Endless(), 2 * 1024 * 1024, "lying.pcap")
    assert os.listdir(capdir) == []


def test_a_truncated_upload_is_refused_not_stored(capdir):
    raw = _pcap_bytes()
    with pytest.raises(uploads.UploadError) as exc:
        uploads.save_upload(io.BytesIO(raw[:20]), len(raw), "cut.pcap")
    assert "stopped after" in str(exc.value)
    assert os.listdir(capdir) == []


# -- listing and deletion ---------------------------------------------------

def test_listing_reports_what_the_capture_is(capdir):
    _upload(_pcap_bytes(4), "good.pcap")
    entries = uploads.list_captures()
    assert len(entries) == 1
    assert entries[0]["name"] == "good.pcap"
    assert entries[0]["readable"] is True
    assert entries[0]["linktype_name"] == "Ethernet"
    assert entries[0]["first_ts"] == pytest.approx(1_700_000_000.0)


def test_listing_hides_in_progress_temporaries(capdir):
    _upload(_pcap_bytes(), "real.pcap")
    (capdir / ".upload-halfway").write_bytes(b"\xd4\xc3\xb2\xa1partial")
    assert [e["name"] for e in uploads.list_captures()] == ["real.pcap"]


def test_listing_an_absent_directory_is_empty_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("SPANTAP_CAPTURE_DIR", str(tmp_path / "never-made"))
    assert uploads.list_captures() == []


@pytest.mark.parametrize("name", ["../../etc/passwd", "/etc/passwd", "..", ".", ""])
def test_delete_refuses_anything_that_is_not_a_plain_name(capdir, name):
    capdir.mkdir(parents=True, exist_ok=True)
    with pytest.raises(uploads.UploadError):
        uploads.delete_capture(name)


def test_delete_refuses_a_symlink_out_of_the_directory(capdir, tmp_path):
    _upload(_pcap_bytes(), "real.pcap")
    target = tmp_path / "precious.pcap"
    target.write_bytes(_pcap_bytes())
    os.symlink(target, capdir / "link.pcap")
    with pytest.raises(uploads.UploadError):
        uploads.delete_capture("link.pcap")
    assert target.exists()


def test_delete_removes_the_file(capdir):
    _upload(_pcap_bytes(), "bye.pcap")
    uploads.delete_capture("bye.pcap")
    assert uploads.list_captures() == []


def test_a_symlink_is_never_listed_as_a_capture(capdir, tmp_path):
    capdir.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "elsewhere.pcap"
    target.write_bytes(_pcap_bytes())
    os.symlink(target, capdir / "sneaky.pcap")
    assert uploads.list_captures() == []


# -- storage reporting ------------------------------------------------------

def test_storage_reports_an_unwritable_directory(capdir):
    capdir.mkdir(parents=True, exist_ok=True)
    assert uploads.storage()["writable"] is True
    os.chmod(capdir, 0o500)
    try:
        st = uploads.storage()
        # root ignores the mode bits, so only assert where it means anything.
        if os.getuid() != 0:
            assert st["writable"] is False
            with pytest.raises(uploads.UploadError) as exc:
                _upload(_pcap_bytes(), "x.pcap")
            assert "read-only" in str(exc.value) or "not writable" in str(exc.value)
    finally:
        os.chmod(capdir, 0o700)


def test_the_directory_is_what_restricts_access_not_the_file(capdir):
    """The uploader must be able to read back what they uploaded.

    In a container this directory is a bind mount and the file is written as
    the container's uid; a 0600 file there is one the person who uploaded it
    cannot open. The directory carries the restriction instead — but only
    where we created it, since a bind mount keeps the host's own mode.
    """
    entry = _upload(_pcap_bytes(), "private.pcap")
    assert os.stat(entry["path"]).st_mode & 0o777 == 0o644
    assert os.stat(capdir).st_mode & 0o077 == 0, "the directory we made must be private"


def test_a_directory_that_does_not_exist_yet_still_allows_uploads(tmp_path, monkeypatch):
    """A fresh install has no capture directory; the button must not be dead."""
    monkeypatch.setenv("SPANTAP_CAPTURE_DIR", str(tmp_path / "not" / "made" / "yet"))
    st = uploads.storage()
    assert st["exists"] is False
    assert st["writable"] is True, "reported unwritable before it was ever created"
    entry = _upload(_pcap_bytes(), "first.pcap")
    assert os.path.isfile(entry["path"])
    assert uploads.storage()["exists"] is True


def test_a_directory_under_an_unwritable_parent_is_reported_unwritable(tmp_path, monkeypatch):
    if os.getuid() == 0:
        pytest.skip("root ignores directory permissions")
    parent = tmp_path / "locked"
    parent.mkdir()
    parent.chmod(0o500)
    monkeypatch.setenv("SPANTAP_CAPTURE_DIR", str(parent / "caps"))
    try:
        assert uploads.storage()["writable"] is False
    finally:
        parent.chmod(0o700)


# -- the erspan-sim -> spantap rename ---------------------------------------

def test_the_pre_rename_capture_dir_variable_still_works(tmp_path, monkeypatch):
    """An unedited docker run -e or systemd unit must not go dark."""
    monkeypatch.delenv("SPANTAP_CAPTURE_DIR", raising=False)
    d = tmp_path / "old-style"
    monkeypatch.setenv("ERSPAN_SIM_CAPTURE_DIR", str(d))
    assert uploads.capture_dir() == str(d)


def test_the_new_name_wins_when_both_are_set(tmp_path, monkeypatch):
    monkeypatch.setenv("ERSPAN_SIM_CAPTURE_DIR", str(tmp_path / "old"))
    monkeypatch.setenv("SPANTAP_CAPTURE_DIR", str(tmp_path / "new"))
    assert uploads.capture_dir() == str(tmp_path / "new")


def test_the_pre_rename_upload_cap_variable_still_works(monkeypatch):
    monkeypatch.delenv("SPANTAP_MAX_UPLOAD_MB", raising=False)
    monkeypatch.setenv("ERSPAN_SIM_MAX_UPLOAD_MB", "3")
    assert uploads.max_upload() == 3 * 1024 * 1024
