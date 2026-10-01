# SPDX-License-Identifier: GPL-2.0-or-later
import struct

import pytest

from spantap.decode import DecodeError, decode_erspan2
from spantap.encap import (
    EN_DOT1Q,
    ENCAP_OVERHEAD,
    ErspanConfig,
    ErspanEncapsulator,
    checksum16,
    erspan2_header,
    gre_header,
    ipv4_header,
)

FRAME = bytes.fromhex("020000000002") + bytes.fromhex("020000000001") + b"\x08\x00" + b"x" * 46


def test_gre_header_is_the_cisco_shape():
    hdr = gre_header(0x11223344)
    assert len(hdr) == 8
    assert hdr[:2] == b"\x10\x00"          # only the sequence flag
    assert hdr[2:4] == b"\x88\xbe"          # ERSPAN Type II ethertype
    assert hdr[4:] == b"\x11\x22\x33\x44"


def test_erspan2_header_bit_layout():
    hdr = erspan2_header(session_id=0x2A9, vlan=0xABC, cos=5, en=EN_DOT1Q,
                         truncated=True, index=0xFACE1)
    word0, word1 = struct.unpack("!II", hdr)
    assert (word0 >> 28) & 0xF == 1          # Ver
    assert (word0 >> 16) & 0xFFF == 0xABC    # VLAN
    assert (word0 >> 13) & 0x7 == 5          # COS
    assert (word0 >> 11) & 0x3 == EN_DOT1Q   # En
    assert (word0 >> 10) & 0x1 == 1          # T
    assert word0 & 0x3FF == 0x2A9            # Session ID
    assert (word1 >> 20) & 0xFFF == 0        # Reserved must be zero
    assert word1 & 0xFFFFF == 0xFACE1        # Index


@pytest.mark.parametrize("bad", [
    dict(session_id=1024), dict(vlan=4096), dict(index=1 << 20),
])
def test_erspan2_header_rejects_out_of_range(bad):
    with pytest.raises(ValueError):
        erspan2_header(**bad)


def test_ipv4_header_checksum_verifies():
    hdr = ipv4_header("192.0.2.1", "198.51.100.1", 100)
    assert len(hdr) == 20
    assert checksum16(hdr) == 0
    assert struct.unpack("!H", hdr[2:4])[0] == 120


def test_overhead_is_36_bytes():
    assert ENCAP_OVERHEAD == 36
    assert ErspanConfig(dst="198.51.100.1", mtu=1500).max_frame_len() == 1464


def test_roundtrip_through_the_decoder():
    cfg = ErspanConfig(dst="198.51.100.1", src="192.0.2.1", session_id=7,
                       vlan=100, cos=3, en=EN_DOT1Q, index=42, ttl=32, dscp=46)
    enc = ErspanEncapsulator(cfg)
    dec = decode_erspan2(enc.encapsulate(FRAME))
    assert (dec.src, dec.dst) == ("192.0.2.1", "198.51.100.1")
    assert dec.ttl == 32 and dec.dscp == 46 and dec.df is True
    assert dec.ip_checksum_ok
    assert dec.session_id == 7 and dec.vlan == 100 and dec.cos == 3
    assert dec.en == EN_DOT1Q and dec.index == 42
    assert dec.truncated is False
    assert dec.frame == FRAME


def test_sequence_and_ident_advance():
    enc = ErspanEncapsulator(ErspanConfig(dst="198.51.100.1"), start_seq=0)
    seqs = [decode_erspan2(enc.encapsulate(FRAME)).seq for _ in range(5)]
    assert seqs == [0, 1, 2, 3, 4]


def test_sequence_wraps_at_32_bits():
    enc = ErspanEncapsulator(ErspanConfig(dst="198.51.100.1"), start_seq=0xFFFFFFFF)
    assert decode_erspan2(enc.encapsulate(FRAME)).seq == 0xFFFFFFFF
    assert decode_erspan2(enc.encapsulate(FRAME)).seq == 0


def test_oversized_frames_are_truncated_and_flagged():
    cfg = ErspanConfig(dst="198.51.100.1", mtu=1500)
    enc = ErspanEncapsulator(cfg)
    big = b"\xaa" * 9000
    dec = decode_erspan2(enc.encapsulate(big))
    assert dec.truncated is True
    assert len(dec.frame) == cfg.max_frame_len() == 1464
    assert enc.truncated_count == 1


def test_exactly_mtu_sized_frame_is_not_truncated():
    cfg = ErspanConfig(dst="198.51.100.1", mtu=1500)
    enc = ErspanEncapsulator(cfg)
    dec = decode_erspan2(enc.encapsulate(b"\xbb" * cfg.max_frame_len()))
    assert dec.truncated is False
    assert len(dec.frame) == 1464


def test_decoder_rejects_non_erspan():
    with pytest.raises(DecodeError):
        decode_erspan2(b"\x45\x00\x00\x14" + b"\x00" * 16)  # IPv4, proto 0
    with pytest.raises(DecodeError):
        decode_erspan2(b"not ip at all")
