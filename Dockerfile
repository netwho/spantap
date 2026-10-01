# SPDX-License-Identifier: GPL-2.0-or-later
#
# spantap container image. (Formerly erspan-sim — see README.md.)
#
#   docker build -t spantap:0.1.0 .
#   docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN \
#       spantap:0.1.0 synth --dst 10.0.0.5 --pps 100
#
# Includes tshark/dumpcap, so all three sources work in the container —
# including 'live', which additionally needs --network host so the container
# can see the host's interfaces.

FROM python:3.12-slim

LABEL org.opencontainers.image.title="spantap" \
      org.opencontainers.image.description="SPAN/ERSPAN and local-interface capture to PCAP-over-IP" \
      org.opencontainers.image.licenses="GPL-2.0-or-later" \
      org.opencontainers.image.source="https://github.com/netwho/spantap"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# tshark's postinst asks whether non-root users may capture; answer it up front
# so the build never blocks on debconf.
#
# install-setuid=false, and the answer is not obvious. Measured on the package
# this image installs:
#   true  -> /usr/bin/dumpcap  0754 root:wireshark, capabilities already set
#   false -> /usr/bin/dumpcap  0755 root:root,      NO capabilities
# "true" sounds like the permissive answer but is the one that breaks us: mode
# 0754 gives "other" read but not execute, so the unprivileged user this image
# runs as cannot execute it at all, shutil.which() returns None, and the UI
# reports no capture tool. "false" leaves it executable by everyone and
# unprivileged, so we grant the capability ourselves and narrow execution to our
# own group below — tighter than the wireshark-group arrangement either way.
# Because "false" strips the capabilities, the setcap below is load-bearing, not
# belt-and-braces; the build asserts it stuck.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends tshark libcap2-bin iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY spantap ./spantap
RUN pip install --no-cache-dir . && rm -rf /src/*

# Capabilities rather than root: the interpreter may open raw sockets and
# dumpcap may capture, but nothing in the image runs as uid 0.  The container
# still has to be started with --cap-add NET_RAW (and NET_ADMIN for 'live'),
# otherwise these file capabilities are outside its bounding set and ignored.
RUN set -eux; \
    # A fixed uid/gid, not whatever useradd picks next. It has to be
    # documentable: mounting your own TLS key read-only means naming this id
    # on the host, and it must not move between rebuilds. Kept numerically
    # identical across the erspan-sim -> spantap rename, so a config volume's
    # ownership needs no fixing up just because the image changed names.
    groupadd --system --gid 10001 spantap; \
    useradd --system --uid 10001 --gid 10001 \
            --create-home --home-dir /var/lib/spantap spantap; \
    \
    dumpcap="$(command -v dumpcap)"; \
    python="$(readlink -f "$(command -v python3)")"; \
    \
    # ORDER MATTERS. chgrp/chown clears the security.capability xattr — the
    # kernel drops it exactly as it drops setuid — so granting the group first
    # and setting capabilities second is the only order that leaves a dumpcap
    # that is both reachable by our user and actually able to capture.
    chgrp spantap "$dumpcap"; \
    chmod 0750 "$dumpcap"; \
    setcap cap_net_raw,cap_net_admin+eip "$dumpcap"; \
    setcap cap_net_raw+ep "$python"; \
    \
    # The config directory must exist *and* be owned by the unprivileged user
    # before any volume is mounted on it: Docker initialises an empty named
    # volume from the image path, ownership included. Without this the volume
    # arrives owned by root and the container cannot save its own settings.
    #
    # A deployment upgrading from erspan-sim mounts the SAME named volume here
    # (docker-compose.yml keeps its pre-rename key on purpose) — its content
    # still has an erspan-sim/ subdirectory from before, which shadows this
    # empty spantap/ one the moment the volume is mounted. spantap.config
    # notices there is no spantap/ but an erspan-sim/ sits right next to
    # where it would go, and renames it into place on first use — see
    # spantap/config.py:_migrate_legacy_dir.
    mkdir -p /var/lib/spantap/.config/spantap /var/lib/spantap/captures; \
    chown -R spantap:spantap /var/lib/spantap; \
    \
    # Fail the build rather than ship an image where live capture silently
    # cannot work. Each of these has been a real bug.
    getcap "$dumpcap" | grep -q cap_net_raw; \
    getcap "$python"  | grep -q cap_net_raw; \
    [ "$(stat -c %G "$dumpcap")" = spantap ]; \
    [ "$(stat -c %U /var/lib/spantap/.config)" = spantap ]

ENV SPANTAP_CONFIG_DIR=/var/lib/spantap/.config/spantap \
    SPANTAP_CAPTURE_DIR=/var/lib/spantap/captures

USER spantap
WORKDIR /var/lib/spantap

# The web UI. It binds 0.0.0.0:8420 by default, so it works with --network
# host and with published ports alike, and prints its URLs with a token that
# is generated once and saved in the config volume. For loopback only:
#   spantap-sim gui --bind 127.0.0.1 --no-open
EXPOSE 8420

# Fails the health check if the tool cannot encapsulate and decode its own output.
HEALTHCHECK --interval=60s --timeout=10s --start-period=5s --retries=2 \
    CMD spantap-sim synth --dst 198.51.100.5 --count 5 --write-pcap /tmp/hc.pcap -q \
        && spantap-sim decode /tmp/hc.pcap -q | grep -q '0 not ERSPAN Type II'

ENTRYPOINT ["spantap-sim"]
CMD ["--help"]
