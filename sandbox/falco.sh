#!/bin/sh
# Manage the Falco sensor. Must run as root: reading kernel events needs it.
# It is the only privileged part of Airlock. Packages run in rootless Podman.
#
# Usage: sudo sandbox/falco.sh start|stop|status
set -eu

IMAGE="docker.io/falcosecurity/falco@sha256:69e957f91b3a6beb5c82e2afae33ec3e4479dab2d4421475d288d0cd113cedf6"  # 0.45.1
NAME=airlock-falco
STATE_DIR=/var/lib/airlock/falco
RULES_DIR="$(cd "$(dirname "$0")/falco" && pwd)"

start() {
    install -d -m 0755 "$STATE_DIR"
    touch "$STATE_DIR/events.jsonl"
    chmod 0644 "$STATE_DIR/events.jsonl"
    podman rm -f "$NAME" >/dev/null 2>&1 || true
    # No --privileged: only the capabilities the modern eBPF probe needs.
    podman run -d --name "$NAME" --restart=unless-stopped \
        --cap-drop=ALL \
        --cap-add=BPF --cap-add=PERFMON --cap-add=SYS_RESOURCE --cap-add=SYS_PTRACE \
        --security-opt=label=disable --security-opt=seccomp=unconfined \
        --pid=host \
        -v /proc:/host/proc:ro \
        -v /etc:/host/etc:ro \
        -v "$RULES_DIR/airlock_rules.yaml:/etc/falco/airlock_rules.yaml:ro" \
        -v "$STATE_DIR:/var/lib/airlock/falco" \
        "$IMAGE" \
        falco \
            -o engine.kind=modern_ebpf \
            -o rules_files[]=/etc/falco/airlock_rules.yaml \
            -o json_output=true \
            -o json_include_output_property=true \
            -o file_output.enabled=true \
            -o file_output.keep_alive=true \
            -o file_output.filename=/var/lib/airlock/falco/events.jsonl \
            -o stdout_output.enabled=true \
            -o buffered_outputs=false \
            -o priority=informational
    sleep 5
    podman logs --tail 15 "$NAME"
    podman ps --filter "name=$NAME" --format '{{.Names}} {{.Status}}'
}

case "${1:-}" in
    start) start ;;
    stop) podman rm -f "$NAME" ;;
    status) podman ps -a --filter "name=$NAME" --format '{{.Names}} {{.Status}}'; podman logs --tail 15 "$NAME" ;;
    *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
