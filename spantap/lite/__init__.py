# SPDX-License-Identifier: GPL-2.0-or-later
"""spantap-lite — a bare capture-to-PCAP-over-IP tap, nothing else.

Where :mod:`spantap.gateway` is one third of a larger tool (it shares its
configuration directory, its web UI and its account system with the
simulator), spantap-lite is meant to be the *only* thing installed: no
management UI, no accounts, no simulator, no ERSPAN receiver. Just a source —
a live interface, or a stored capture replayed for testing — feeding a
PCAP-over-IP server, started and stopped like any other small service.

It reuses the gateway's own building blocks (:mod:`spantap.gateway.livecapture`,
:mod:`spantap.gateway.replay`, :mod:`spantap.gateway.ring`,
:mod:`spantap.gateway.pcapoverip`, :mod:`spantap.exclusion`) rather than
reimplementing any of them — the capture pipeline is the same well-exercised
code either way. What is new here is everything around it:

``spantap.lite.config``
    Its own small JSON config file (``lite.json``, alongside the gateway's
    ``gateway.json`` and the simulator's profiles — same config directory,
    separate file) and an interactive ``configure`` wizard, since nothing
    like that exists for the gateway today.
``spantap.lite.service``
    The run loop wiring source -> ring -> server, plus the one genuinely new
    capability: optionally teeing every frame to a size-capped local pcap
    file (the gateway's PcapOverIpServer only ever serves over the network).
``spantap.lite.cli``
    Exactly three subcommands — ``configure``, ``start``, ``stop`` — using a
    PID file rather than the gateway's foreground-only ``spantap-gw run``, so
    it behaves the same way whether started by systemd, by hand, or in the
    background with ``&``.
"""
