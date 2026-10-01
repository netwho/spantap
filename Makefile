# SPDX-License-Identifier: GPL-2.0-or-later
.PHONY: help test check install uninstall lite docker upgrade docker-run demo gateway gui captures clean

IMAGE ?= spantap:0.9.3
DST   ?= 10.0.0.5

help:
	@echo "targets:"
	@echo "  make test        run the test suite"
	@echo "  make check       installer preflight only"
	@echo "  make install     set up the container-based deployment [DST=$(DST)]"
	@echo "  make uninstall   docker compose down (config volume kept)"
	@echo "  make docker      build the container image ($(IMAGE))"
	@echo "  make captures    let the container write ./captures (for UI uploads)"
	@echo "  make upgrade     rebuild AND recreate the containers (restart is not enough)"
	@echo "  make docker-run  run a synthetic feed in the container [DST=$(DST)]"
	@echo "  make gui         open the web UI (simulator + gateway)"
	@echo "  make gateway     run the gateway in the foreground"
	@echo "  make lite        install spantap-lite only, as its own container"
	@echo "  make demo        generate a sample ERSPAN pcap in /tmp and decode it"
	@echo "  make clean       remove build artefacts"

test:
	python3 -m pytest -q

check:
	./install.sh --check-only --dst $(DST)

install:
	./install.sh --dst $(DST)

uninstall:
	./install.sh --uninstall

lite:
	./install.sh --lite

docker:
	docker build -t $(IMAGE) .

# The UI uploads captures into ./captures, and the container runs as uid 10001,
# so that uid needs write access to the host directory. An ACL is the polite
# way: it needs no root and does not change who owns your files. chown is the
# fallback where the filesystem has no ACL support.
#
# Skipping this costs you only the upload button — replaying a file you put
# there yourself works either way, and the UI says so rather than failing.
UID_IN_IMAGE ?= 10001
captures:
	@mkdir -p captures
	@if setfacl -m u:$(UID_IN_IMAGE):rwx captures 2>/dev/null; then \
		echo "captures/: granted uid $(UID_IN_IMAGE) write access via ACL"; \
	elif [ "`stat -c %u captures`" = "$(UID_IN_IMAGE)" ]; then \
		echo "captures/: already owned by uid $(UID_IN_IMAGE)"; \
	else \
		echo "captures/: no ACL support here, falling back to chown (needs sudo)"; \
		sudo chown $(UID_IN_IMAGE):$(UID_IN_IMAGE) captures; \
	fi
	@ls -ld captures

# Build and actually put the new image into service. `docker compose restart`
# does NOT do this: it re-runs the existing container, which keeps the image it
# was created from, so new code appears to have no effect.
#
# It recreates only what is ALREADY running. Enabling every profile here would
# start services you did not ask for — and `gui` and `gui-lan` are two ways to
# run the same UI, so starting both leaves one crash-looping on a port clash.
upgrade:
	docker build -t $(IMAGE) .
	@running=`docker compose ps --services --status running 2>/dev/null`; \
	if [ -z "$$running" ]; then \
		echo; \
		echo "Nothing is running, so nothing to recreate. Start what you want:"; \
		echo "  docker compose --profile gateway up -d gateway"; \
		echo "  docker compose --profile gui-lan up -d gui-lan"; \
	else \
		echo; \
		echo "recreating: $$running"; \
		docker compose up -d --force-recreate $$running; \
	fi
	@echo
	@docker compose ps --format 'table {{.Service}}\t{{.Image}}\t{{.Status}}' 2>/dev/null || true

docker-run:
	docker run --rm --network host --cap-add NET_RAW $(IMAGE) \
		synth --dst $(DST) --count 200 --pps 100

demo:
	python3 -m spantap synth --dst 198.51.100.5 --src 192.0.2.1 \
		--count 100 --seed 42 --session-id 23 --vlan 100 --write-pcap /tmp/erspan-demo.pcap
	python3 -m spantap decode /tmp/erspan-demo.pcap -q
	@echo "open /tmp/erspan-demo.pcap in Wireshark"

gateway:
	python3 -c "from spantap.gateway.cli import main; raise SystemExit(main(['run']))"

gui:
	python3 -m spantap gui

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
