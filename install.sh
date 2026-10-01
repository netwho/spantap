#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# spantap installer — container-based deployment (docker compose).
# (Formerly erspan-sim — see README.md for what changed and how to carry an
# existing install over. A native, no-Docker install used to be offered here
# too; it was dropped because every prerequisite it needed to check for —
# a python3-venv package, setcap living somewhere the running user's $PATH
# doesn't include, distro-specific tool package names — is exactly the kind
# of friction Docker removes outright. If you need a non-container install,
# an older release still has it.)
#
#   ./install.sh                    preflight, build, smoke-test
#   ./install.sh --check-only       run the preflight checks and stop
#   ./install.sh --uninstall        docker compose down (config volume kept)
#   ./install.sh --dst 10.0.0.5     receiver address, used for the path checks
#                                   (the simulator itself sends to 127.0.0.1
#                                   unless told otherwise)
#
# After the build it offers to set the web UI's TLS certificate: paste the
# certificate and then the key (PEM), or just press Enter to skip and stay
# on plain HTTP. --tls-cert FILE [--tls-key FILE] does the same without
# prompting.
#
# spantap-lite — a bare capture-to-PCAP-over-IP tap, no web UI, no accounts,
# no simulator — as a separate container, using the same image:
#   ./install.sh --lite             install just spantap-lite
#   ./install.sh --lite --uninstall
#
# Checks the docker engine and compose plugin, sets up ./captures and ./tls
# with the permissions the container's uid needs, builds the image from
# docker-compose.yml, and runs the generate-and-decode smoke test inside the
# built container. It does not need root — being in the "docker" group is
# enough.
#
# --lite runs the same image as the "lite" compose service instead, so it
# neither needs nor disturbs the rest of spantap. It ends by running
# 'spantap-lite configure' (interactively, if a terminal is attached) since
# that is the one step nothing else does for you.

set -euo pipefail

SRCDIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

ASSUME_YES=0
CHECK_ONLY=0
DO_UNINSTALL=0
RECEIVER=""
GATEWAY_PORT=57012     # reserved for the PCAP-over-IP side of the gateway
LITE=0                 # 1 selects the separate spantap-lite install
TLS_CERT_FILE=""       # --tls-cert: import this instead of prompting
TLS_KEY_FILE=""        # --tls-key: its key, when not in the same file
COMPOSE_CMD=""          # set by detect_compose once docker is confirmed present

FAILURES=0
WARNINGS=0

# --------------------------------------------------------------------------
# output helpers
# --------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
    C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""; C_OFF=""
fi

section() { printf '\n%s\n' "$1"; }
ok()      { printf '  [%sok  %s] %-30s %s\n' "$C_OK" "$C_OFF" "$1" "${2:-}"; }
warn()    { printf '  [%swarn%s] %-30s %s\n' "$C_WARN" "$C_OFF" "$1" "${2:-}"; WARNINGS=$((WARNINGS+1)); }
bad()     { printf '  [%sFAIL%s] %-30s %s\n' "$C_ERR" "$C_OFF" "$1" "${2:-}"; FAILURES=$((FAILURES+1)); }
info()    { printf '  %s%s%s\n' "$C_DIM" "$1" "$C_OFF"; }
die()     { printf '\n%serror:%s %s\n' "$C_ERR" "$C_OFF" "$1" >&2; exit 1; }

confirm() {
    # confirm "question" [default_yes]
    if [ "$ASSUME_YES" = 1 ]; then return 0; fi
    if [ ! -t 0 ]; then return 1; fi   # non-interactive and no --yes: decline
    local prompt="  $1 [y/N] "
    [ "${2:-}" = "y" ] && prompt="  $1 [Y/n] "
    local answer
    read -r -p "$prompt" answer || true
    case "${answer:-${2:-n}}" in [yY]*) return 0 ;; *) return 1 ;; esac
}

usage() {
    sed -n '3,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

options:
  --yes, -y            answer every prompt with yes
  --check-only         run the preflight checks and exit
  --uninstall          remove an existing installation
  --dst IP             receiver address, used for the path checks
  --tls-cert FILE      web UI certificate (PEM; may also hold the key) --
                        imported without the paste prompt
  --tls-key FILE       private key for --tls-cert, if in a separate file

  --lite               install spantap-lite instead: no web UI, no accounts,
                        no simulator, just capture-to-PCAP-over-IP. A fully
                        separate compose service from the above -- combine
                        with --check-only or --uninstall as above

  -h, --help            this text
EOF
}

# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes)          ASSUME_YES=1 ;;
        --check-only)      CHECK_ONLY=1 ;;
        --uninstall)       DO_UNINSTALL=1 ;;
        --dst)             RECEIVER="${2:?--dst needs an address}"; shift ;;
        --lite)            LITE=1 ;;
        --tls-cert)        TLS_CERT_FILE="${2:?--tls-cert needs a file}"; shift ;;
        --tls-key)         TLS_KEY_FILE="${2:?--tls-key needs a file}"; shift ;;
        --docker)          info "--docker is no longer needed — docker compose is the only install mode now" ;;
        -h|--help)         usage; exit 0 ;;
        *)                 die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

# --------------------------------------------------------------------------
# container-based deployment (docker compose)
# --------------------------------------------------------------------------
detect_compose() {
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD="docker-compose"
    else
        COMPOSE_CMD=""
    fi
}

check_docker_engine() {
    section "docker engine"
    if ! command -v docker >/dev/null 2>&1; then
        bad "docker" "not found — install Docker Engine (docs.docker.com/engine/install/)"
        return
    fi
    ok "docker" "$(command -v docker)"

    if docker info >/dev/null 2>&1; then
        ok "daemon" "reachable"
    else
        local err
        err="$(docker info 2>&1 | head -n1)"
        case "$err" in
            *"permission denied"*)
                bad "daemon" "permission denied — add this user to the docker group \
(sudo usermod -aG docker \$USER, then log back in), or re-run this installer with sudo" ;;
            *)
                bad "daemon" "not reachable — is the docker service running? ($err)" ;;
        esac
        return
    fi

    detect_compose
    if [ "$COMPOSE_CMD" = "docker compose" ]; then
        ok "compose" "$(docker compose version --short 2>/dev/null || echo 'v2 plugin')"
    elif [ "$COMPOSE_CMD" = "docker-compose" ]; then
        warn "compose" "only the standalone v1 docker-compose was found — the v2 \
plugin (docker compose) is what docker-compose.yml's profiles were written for"
    else
        bad "compose" "not found — install the compose plugin (docs.docker.com/compose/install/)"
    fi
}

check_docker_source() {
    section "source tree"
    if [ -f "$SRCDIR/Dockerfile" ] && [ -f "$SRCDIR/docker-compose.yml" ]; then
        ok "compose project" "$SRCDIR"
    else
        bad "compose project" "Dockerfile / docker-compose.yml not found next to this script"
    fi
}

check_network() {
    section "network"
    local iface mtu
    if command -v ip >/dev/null 2>&1; then
        ok "iproute2" "$(command -v ip)"
    else
        warn "iproute2" "not found — package iproute2 (Debian/Ubuntu) or iproute (Fedora/RHEL); \
skipping route and MTU checks"
        return
    fi

    if [ -n "$RECEIVER" ]; then
        local route
        route="$(ip -o route get "$RECEIVER" 2>/dev/null || true)"
        if [ -n "$route" ]; then
            iface="$(printf '%s' "$route" | sed -n 's/.* dev \([^ ]*\).*/\1/p')"
            local src
            src="$(printf '%s' "$route" | sed -n 's/.* src \([^ ]*\).*/\1/p')"
            ok "route to $RECEIVER" "via ${iface:-?} src ${src:-?}"
            if [ -n "$iface" ] && [ -r "/sys/class/net/$iface/mtu" ]; then
                mtu="$(cat "/sys/class/net/$iface/mtu")"
                if [ "$mtu" -ge 1536 ]; then
                    ok "path MTU" "$mtu — full 1518-byte frames fit"
                else
                    warn "path MTU" "$mtu — frames over $((mtu - 36)) bytes will be \
truncated with the ERSPAN T bit (this is normal; use a jumbo path to avoid it)"
                fi
            fi
        else
            warn "route to $RECEIVER" "no route — the receiver is unreachable from here"
        fi
    else
        info "pass --dst IP to also check the route and MTU to a receiver"
    fi

    # GRE is IP protocol 47 and has no port. What can still block it is a local
    # firewall, so say what is loaded rather than guessing at rule semantics.
    if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1 \
       && [ -n "$(nft list ruleset 2>/dev/null)" ]; then
        warn "firewall" "nftables rules are loaded — make sure IP protocol 47 may leave this host"
    elif command -v iptables >/dev/null 2>&1 \
         && iptables -S OUTPUT 2>/dev/null | grep -qv '^-P OUTPUT ACCEPT$'; then
        warn "firewall" "iptables OUTPUT rules are present — allow IP protocol 47"
    else
        ok "firewall" "nothing obvious in the way of IP protocol 47"
    fi

    # Forward-looking: the gateway's PCAP-over-IP listener will want this port.
    if command -v ss >/dev/null 2>&1; then
        if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$GATEWAY_PORT\$"; then
            warn "tcp/$GATEWAY_PORT" "already in use — the gateway's PCAP-over-IP \
listener will need a different port"
        else
            ok "tcp/$GATEWAY_PORT" "free (reserved for the PCAP-over-IP side later)"
        fi
    fi
}

check_docker_existing() {
    section "existing containers"
    if [ -z "$COMPOSE_CMD" ]; then
        info "skipped — compose was not found above"
        return
    fi
    local running
    running="$(cd "$SRCDIR" && $COMPOSE_CMD ps --services --status running 2>/dev/null || true)"
    if [ -n "$running" ]; then
        warn "running services" "$(printf '%s' "$running" | tr '\n' ' ') — left running; \
rebuild then 'docker compose up -d --force-recreate' those, or see 'make upgrade'"
    else
        ok "running services" "none"
    fi
    if [ -d "$SRCDIR/captures" ]; then
        ok "./captures" "present"
    else
        info "./captures does not exist yet — created below, for the web UI's upload feature"
    fi
}

preflight() {
    printf 'spantap installer — preflight\n'
    section "platform"
    if [ "$(uname -s)" = "Linux" ]; then
        ok "operating system" "$(uname -sr)"
    else
        warn "operating system" "$(uname -s) — docker-compose.yml uses network_mode: host \
throughout, which Docker Desktop does not support the same way outside Linux; a Linux \
host or VM is recommended"
    fi
    check_docker_engine
    check_docker_source
    check_network
    check_docker_existing
    printf '\n'
    if [ "$FAILURES" -gt 0 ]; then
        printf '%s%d check(s) failed%s, %d warning(s).\n' "$C_ERR" "$FAILURES" "$C_OFF" "$WARNINGS"
        return 1
    fi
    printf '%sall checks passed%s (%d warning(s)).\n' "$C_OK" "$C_OFF" "$WARNINGS"
    return 0
}

setup_docker_dirs() {
    section "host directories"
    local uid_in_image=10001

    if [ ! -d "$SRCDIR/captures" ]; then
        mkdir -p "$SRCDIR/captures"
        ok "captures/" "created"
    else
        ok "captures/" "exists"
    fi
    # The web UI's upload button needs uid 10001 (the container's user) to be
    # able to write here. An ACL needs no root and does not change who owns
    # the directory; chown is the fallback where the filesystem has no ACL
    # support — the same dance as 'make captures'.
    if command -v setfacl >/dev/null 2>&1 && setfacl -m "u:$uid_in_image:rwx" "$SRCDIR/captures" 2>/dev/null; then
        ok "captures/ access" "granted to uid $uid_in_image via ACL"
    elif [ "$(stat -c %u "$SRCDIR/captures" 2>/dev/null)" = "$uid_in_image" ]; then
        ok "captures/ access" "already owned by uid $uid_in_image"
    elif [ "$(id -u)" = "0" ]; then
        if chown "$uid_in_image:$uid_in_image" "$SRCDIR/captures"; then
            ok "captures/ access" "chowned to uid $uid_in_image"
        else
            warn "captures/ access" "chown failed — the web UI's upload button will say uploads are disabled"
        fi
    else
        warn "captures/ access" "no ACL support and not root — run \
'sudo chown $uid_in_image:$uid_in_image captures' yourself, or the web UI's upload \
button will say uploads are disabled (replaying a file you place there stays fine)"
    fi

    if [ ! -d "$SRCDIR/tls" ]; then
        mkdir -p "$SRCDIR/tls"
        ok "tls/" "created (empty — drop a CA-issued cert/key here, or use the Settings tab's self-signed option)"
    else
        ok "tls/" "exists"
    fi
}

setup_docker_env() {
    section "project configuration"
    local envfile="$SRCDIR/.env"
    if [ -f "$envfile" ]; then
        if grep -q '^COMPOSE_PROJECT_NAME=' "$envfile"; then
            ok ".env" "COMPOSE_PROJECT_NAME already set"
        else
            warn ".env" "exists but has no COMPOSE_PROJECT_NAME — add one \
(COMPOSE_PROJECT_NAME=spantap) so the config volume's name stays stable if this \
directory is ever moved or renamed"
        fi
    elif confirm "create .env with COMPOSE_PROJECT_NAME=spantap (keeps the config volume's name stable)?" y; then
        printf 'COMPOSE_PROJECT_NAME=spantap\n' > "$envfile"
        ok ".env" "created"
    else
        info "skipped — the config volume will be named after this directory instead"
    fi
}

build_docker_image() {
    section "building the image"
    if (cd "$SRCDIR" && $COMPOSE_CMD build sim); then
        ok "image" "built"
    else
        die "image build failed"
    fi
}

docker_smoke_test() {
    section "smoke test"
    if (cd "$SRCDIR" && $COMPOSE_CMD run --rm --no-deps --entrypoint sh sim -c \
            'spantap-sim synth --dst 198.51.100.5 --count 25 --seed 1 --mtu 9216 \
             --write-pcap /tmp/t.pcap -q && spantap-sim decode /tmp/t.pcap -q') \
            | grep -q '25 packets, 0 not ERSPAN Type II, 0 sequence gaps'; then
        ok "generate + decode round-trip" "25/25 valid, no sequence gaps, inside the container"
    else
        bad "generate + decode round-trip" "the built image did not pass its own round-trip"
        return 1
    fi
}

# --------------------------------------------------------------------------
# the web UI's TLS certificate
#
# Stored in the config volume through the image's own 'spantap-sim tls
# import', which validates it exactly like the Settings tab's upload does (the
# certificate must load with its key, an encrypted key is refused rather than
# prompting for a passphrase) and writes nothing unless it passes. The PEM
# text only ever travels over a pipe into the container — never a temporary
# file on the host.
# --------------------------------------------------------------------------
read_pem() {
    # read_pem SILENT — PEM lines from the terminal until an empty line once
    # every BEGIN has its END (so a paste may carry several blocks, and a
    # trailing newline in the clipboard is harmless). An empty FIRST line
    # returns nothing: that is the "skip" answer.
    local silent="$1" line text="" n=0 begins=0 ends=0
    while :; do
        if [ "$silent" = 1 ]; then
            IFS= read -r -s line || break
        else
            IFS= read -r line || break
        fi
        line="${line%$'\r'}"
        if [ -z "$line" ]; then
            [ "$n" -eq 0 ] && break
            if [ "$begins" -eq 0 ] || [ "$begins" -eq "$ends" ]; then break; fi
            continue
        fi
        n=$((n + 1))
        case "$line" in
            -----BEGIN*) begins=$((begins + 1)) ;;
            -----END*)   ends=$((ends + 1)) ;;
        esac
        text+="$line"$'\n'
    done
    printf '%s' "$text"
}

tls_import() {
    # PEM text on stdin -> 'spantap-sim tls import' inside the gui service,
    # which is the one that mounts the config volume the UI reads.
    (cd "$SRCDIR" && $COMPOSE_CMD --profile gui run --rm --no-deps -T \
        --entrypoint spantap-sim gui tls import)
}

setup_tls() {
    section "web UI certificate (optional)"
    TLS_DONE=0

    if [ -n "$TLS_CERT_FILE" ]; then
        [ -r "$TLS_CERT_FILE" ] || die "--tls-cert: cannot read $TLS_CERT_FILE"
        if [ -n "$TLS_KEY_FILE" ]; then
            [ -r "$TLS_KEY_FILE" ] || die "--tls-key: cannot read $TLS_KEY_FILE"
        fi
        if cat "$TLS_CERT_FILE" ${TLS_KEY_FILE:+"$TLS_KEY_FILE"} | tls_import; then
            ok "certificate" "imported from $TLS_CERT_FILE"
            TLS_DONE=1
        else
            die "the certificate in $TLS_CERT_FILE was refused (see above)"
        fi
        return 0
    fi

    if [ "$ASSUME_YES" = 1 ] || [ ! -t 0 ]; then
        info "skipped (no prompt with --yes or without a terminal) — the UI stays on"
        info "plain HTTP. Use --tls-cert FILE here, or the Settings tab, to set one."
        return 0
    fi

    local cert key
    while :; do
        printf '\n  The web UI serves plain HTTP until it has a certificate.\n'
        printf '  Paste the certificate (PEM, including -----BEGIN/END----- lines;\n'
        printf '  a full chain is fine), then press Enter on an empty line.\n'
        printf '  %sJust press Enter to skip.%s\n\n' "$C_DIM" "$C_OFF"
        cert="$(read_pem 0)"
        if [ -z "$cert" ]; then
            info "skipped — plain HTTP. Set one later on the Settings tab, or with:"
            info "  $COMPOSE_CMD --profile gui run --rm -T --entrypoint spantap-sim gui tls import < bundle.pem"
            return 0
        fi

        if printf '%s' "$cert" | grep -q -- '-----BEGIN .*PRIVATE KEY-----'; then
            key=""
            info "that paste already contains the private key"
        else
            printf '\n  Now paste the private key (not shown on screen), then press\n'
            printf '  Enter on an empty line.\n'
            key="$(read_pem 1)"
            printf '\n'
            if [ -n "$key" ]; then
                info "key received ($(printf '%s' "$key" | wc -l | tr -d ' ') lines)"
            fi
        fi

        if printf '%s\n%s' "$cert" "$key" | tls_import; then
            ok "certificate" "stored in the config volume"
            TLS_DONE=1
            return 0
        fi
        warn "certificate" "refused — nothing was stored"
        confirm "try again?" y || { info "skipped — the UI stays on plain HTTP"; return 0; }
    done
}

# Every IPv4 address of this host other than loopback, one per line.
host_ipv4s() {
    if command -v hostname >/dev/null 2>&1 && hostname -I >/dev/null 2>&1; then
        hostname -I | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$'
    elif command -v ip >/dev/null 2>&1; then
        ip -4 -o addr show scope global | awk '{sub(/\/.*/, "", $4); print $4}'
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig | awk '$1 == "inet" && $2 !~ /^127\./ {print $2}'
    fi
}

webui_urls() {
    # The UI's own view — its saved bind, port, TLS and token — from inside
    # the gui service, so it reads the same config volume. Makes and saves
    # the token if there is none yet, so it is the one the UI will use.
    (cd "$SRCDIR" && $COMPOSE_CMD --profile gui run --rm --no-deps -T \
        --entrypoint spantap-sim gui token --urls) 2>/dev/null
}

print_webui_access() {
    local scheme="$1" ip urls
    urls="$(webui_urls)"
    printf '  web UI — once the gui service is up, open:\n'
    if [ -n "$urls" ]; then
        printf '%s\n' "$urls" | sed 's/^/    /'
    else
        printf '    %s://127.0.0.1:8420/          (this host)\n' "$scheme"
        for ip in $(host_ipv4s); do
            printf '    %s://%s:8420/\n' "$scheme" "$ip"
        done
    fi
    printf '\n  access: the token is the ?token= part above, kept in the config\n'
    printf '  volume so it stays the same. Print it again any time with:\n'
    printf '    %s --profile gui run --rm --no-deps -T --entrypoint spantap-sim gui token --urls\n' "$COMPOSE_CMD"
    printf '  or, while the UI runs:  %s exec gui spantap-sim token --urls\n' "$COMPOSE_CMD"
    printf '  or add a named account for the sign-in form:\n'
    printf '    %s exec gui spantap-sim users add NAME\n' "$COMPOSE_CMD"
    printf '  local-only instead: set --bind 127.0.0.1 on the gui service and use\n'
    printf '    ssh -L 8420:127.0.0.1:8420 <this host>\n\n'
    printf '  docs: %s/README.md, or on GitHub:\n' "$SRCDIR"
    printf '    https://github.com/netwho/spantap#the-web-ui\n'
    printf '    https://github.com/netwho/spantap#accounts-or-a-bare-token\n'
    printf '    https://github.com/netwho/spantap#reaching-it-from-another-host\n\n'
}

do_install() {
    preflight || die "preflight failed; fix the items above or re-run with --check-only to review"
    if [ "$CHECK_ONLY" = 1 ]; then exit 0; fi
    printf '\n'
    confirm "set up the container-based deployment in $SRCDIR?" y || die "cancelled"

    setup_docker_dirs
    setup_docker_env
    build_docker_image
    docker_smoke_test || die "the container did not pass its own smoke test"
    setup_tls

    section "done"
    printf '  built and verified. From %s:\n\n' "$SRCDIR"
    printf '    %s run --rm sim doctor\n' "$COMPOSE_CMD"
    printf '    %s up -d sim                       # synthetic feed -> %s\n' "$COMPOSE_CMD" "${RECEIVER:-127.0.0.1}"
    printf '    %s --profile gateway up -d gateway  # ERSPAN in, PCAP-over-IP out on tcp/%s\n' "$COMPOSE_CMD" "$GATEWAY_PORT"
    local scheme=http
    [ "${TLS_DONE:-0}" = 1 ] && scheme=https
    printf '    %s --profile gui up -d gui          # web UI on tcp/8420, all addresses\n\n' "$COMPOSE_CMD"
    print_webui_access "$scheme"
    if [ "${TLS_DONE:-0}" = 1 ]; then
        printf '  a UI container that is already running picks the certificate up on\n'
        printf '  restart: %s --profile gui restart gui   (or gui-lan)\n\n' "$COMPOSE_CMD"
    fi
    printf '  edit the "sim" service'"'"'s --dst in docker-compose.yml, or override it:\n'
    printf '    %s run --rm sim synth --dst %s --count 200 --pps 100\n\n' "$COMPOSE_CMD" "${RECEIVER:-127.0.0.1}"
    printf '  Remove it again with: %s --uninstall\n' "$0"
}

do_uninstall() {
    section "removing the container deployment"
    [ -n "$COMPOSE_CMD" ] || detect_compose
    [ -n "$COMPOSE_CMD" ] || die "docker compose not found"

    if (cd "$SRCDIR" && $COMPOSE_CMD down --remove-orphans); then
        ok "containers" "stopped and removed"
    else
        warn "containers" "'compose down' reported a problem — check above"
    fi
    if confirm "also remove the erspan-config volume (saved settings, accounts, TLS state)?" n; then
        if (cd "$SRCDIR" && $COMPOSE_CMD down -v); then
            ok "volume" "removed"
        else
            warn "volume" "removal failed"
        fi
    else
        info "config volume kept — a fresh 'up' picks your settings back up"
    fi
    printf '\ndone. ./captures and ./tls on the host were left in place.\n'
}

do_install_lite() {
    preflight || die "preflight failed; fix the items above or re-run with --check-only to review"
    if [ "$CHECK_ONLY" = 1 ]; then exit 0; fi
    printf '\n'
    confirm "set up spantap-lite (container-based) in $SRCDIR?" y || die "cancelled"

    # ./captures is mounted by the lite service too: files to replay, and the
    # optional local save. (./tls comes along unused; it is harmless.)
    setup_docker_dirs
    setup_docker_env
    build_docker_image
    docker_smoke_test || die "the container did not pass its own smoke test"

    section "initial configuration"
    if [ -t 0 ]; then
        (cd "$SRCDIR" && $COMPOSE_CMD run --rm lite configure) \
            || warn "configure" "not completed — run '$COMPOSE_CMD run --rm lite configure' yourself"
    else
        info "no terminal attached — run '$COMPOSE_CMD run --rm lite configure' before starting it"
    fi

    section "done"
    printf '  built and verified. From %s:\n\n' "$SRCDIR"
    printf '    %s run --rm lite configure   # change settings any time\n' "$COMPOSE_CMD"
    printf '    %s --profile lite up -d lite  # start it\n' "$COMPOSE_CMD"
    printf '    %s --profile lite logs -f lite   # watch its stats\n' "$COMPOSE_CMD"
    printf '    %s --profile lite stop lite      # stop it\n' "$COMPOSE_CMD"
    printf '    wireshark -k -i TCP@<this host>:%s\n\n' "$GATEWAY_PORT"
    printf '  to replay a file instead of a card, put it in %s/captures and:\n' "$SRCDIR"
    printf '    %s run --rm lite configure --non-interactive \\\n' "$COMPOSE_CMD"
    printf '        --replay-file FILE.pcapng\n'
    printf '    %s --profile lite restart lite\n\n' "$COMPOSE_CMD"
    printf '  docs: %s/README.md, or https://github.com/netwho/spantap#spantap-lite\n\n' "$SRCDIR"
    printf '  Remove it again with: %s --lite --uninstall\n' "$0"
}

do_uninstall_lite() {
    section "removing spantap-lite (container)"
    [ -n "$COMPOSE_CMD" ] || detect_compose
    [ -n "$COMPOSE_CMD" ] || die "docker compose not found"

    if (cd "$SRCDIR" && $COMPOSE_CMD --profile lite rm -sf lite); then
        ok "container" "stopped and removed"
    else
        warn "container" "'compose rm' reported a problem — check above"
    fi
    printf '\ndone. The shared config volume, and ./captures and ./tls on the host \
(used by other services, not this one), were left in place.\n'
}

# --------------------------------------------------------------------------
if [ "$LITE" = 1 ]; then
    if [ "$DO_UNINSTALL" = 1 ]; then do_uninstall_lite; else do_install_lite; fi
else
    if [ "$DO_UNINSTALL" = 1 ]; then do_uninstall; else do_install; fi
fi
