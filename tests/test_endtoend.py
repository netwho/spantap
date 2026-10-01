# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate -> encapsulate -> file -> decode -> compare, through the real CLI."""

import io

from spantap.cli import main
from spantap.decode import decode_erspan2
from spantap.sources.pcapread import open_packet_stream
from spantap.sources.synth import SyntheticSource


def _run(argv):
    return main(argv)


def test_synth_to_pcap_to_decode_roundtrip(tmp_path, capsys):
    outer = tmp_path / "erspan.pcap"
    inner = tmp_path / "inner.pcap"

    rc = _run([
        "synth", "--dst", "198.51.100.5", "--src", "192.0.2.1",
        "--count", "50", "--seed", "42", "--session-id", "23",
        "--mtu", "9216",  # big enough that nothing is truncated
        "--write-pcap", str(outer), "--quiet",
    ])
    assert rc == 0
    assert outer.exists()

    with open(outer, "rb") as fh:
        packets = [p.data for p in open_packet_stream(fh)]
    assert len(packets) == 50

    decoded = [decode_erspan2(p) for p in packets]
    assert [d.seq for d in decoded] == list(range(50))
    assert all(d.session_id == 23 for d in decoded)
    assert all(d.src == "192.0.2.1" and d.dst == "198.51.100.5" for d in decoded)
    assert all(d.ip_checksum_ok for d in decoded)

    rc = _run(["decode", str(outer), "--extract", str(inner), "--quiet"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "50 packets, 0 not ERSPAN Type II, 0 sequence gaps" in out

    with open(inner, "rb") as fh:
        extracted = [p.data for p in open_packet_stream(fh)]

    expected = [p.data for p in SyntheticSource(count=50, seed=42)]
    assert extracted == expected


def test_jumbo_frames_come_back_truncated_with_the_t_bit(tmp_path):
    outer = tmp_path / "jumbo.pcap"
    rc = _run([
        "synth", "--dst", "198.51.100.5", "--src", "192.0.2.1",
        "--scenario", "jumbo", "--count", "5", "--seed", "1",
        "--mtu", "1500", "--write-pcap", str(outer), "--quiet",
    ])
    assert rc == 0
    with open(outer, "rb") as fh:
        decoded = [decode_erspan2(p.data) for p in open_packet_stream(fh)]
    assert len(decoded) == 5
    assert all(d.truncated for d in decoded)
    assert all(len(d.frame) == 1464 for d in decoded)
    assert all(len(p) <= 1500 for p in [bytes(20 + 8 + 8 + len(d.frame)) for d in decoded])


def test_vlan_reaches_the_erspan_header(tmp_path):
    outer = tmp_path / "vlan.pcap"
    rc = _run([
        "synth", "--dst", "198.51.100.5", "--src", "192.0.2.1",
        "--count", "6", "--seed", "5", "--vlan", "987",
        "--write-pcap", str(outer), "--quiet",
    ])
    assert rc == 0
    with open(outer, "rb") as fh:
        decoded = [decode_erspan2(p.data) for p in open_packet_stream(fh)]
    assert all(d.vlan == 987 and d.en == 2 for d in decoded)


def test_replay_of_our_own_output_matches_the_source(tmp_path):
    src_pcap = tmp_path / "src.pcap"
    first = tmp_path / "first.pcap"
    second = tmp_path / "second.pcap"

    # Build an ordinary Ethernet capture to replay.
    from spantap.sources.pcapread import write_pcap_header, write_pcap_packet
    frames = [p.data for p in SyntheticSource(count=25, seed=11)]
    with open(src_pcap, "wb") as fh:
        write_pcap_header(fh, 1)
        for i, f in enumerate(frames):
            write_pcap_packet(fh, 1_700_000_000_000_000_000 + i * 1_000_000, f)

    common = ["--dst", "198.51.100.5", "--src", "192.0.2.1", "--speed", "0",
              "--mtu", "9216", "--quiet"]
    assert _run(["replay", str(src_pcap), "--write-pcap", str(first)] + common) == 0
    assert _run(["replay", str(src_pcap), "--write-pcap", str(second),
                 "--loop", "2"] + common) == 0

    with open(first, "rb") as fh:
        one = [decode_erspan2(p.data).frame for p in open_packet_stream(fh)]
    with open(second, "rb") as fh:
        two = [decode_erspan2(p.data) for p in open_packet_stream(fh)]

    assert one == frames
    assert len(two) == 50
    assert [d.seq for d in two] == list(range(50))  # seq keeps running across loops
    assert [d.frame for d in two] == frames + frames
