"""
airlock.detonation.sandbox
===========================

Runs a package in a disposable sandbox and reports what it did. This is the
only place where package code is executed.

    host (rootless Podman)
      |- detonation container: decoy home, no route out, archive given on stdin
      |- sink container: the only reachable host, fakes DNS and TCP services
    host (root)
      |- Falco: kernel view of the detonation, independent from the container

Two independent witnesses are combined:
  - Falco reports behaviours (decoy read, persistence, dropped program...);
  - the sink proves exfiltration when it receives the per-run canary token,
    even for secrets read from the environment, which no file event shows.

Falco being silent proves nothing by itself. Each detonation starts by reading a
sentinel file: if Falco does not report it, the sensor was blind and the result
is "unavailable", never "clean".
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

IMAGE = "localhost/airlock-sandbox:1"
NETWORK = "airlock-det"
SUBNET = "10.253.66.0/24"
SINK_IP = "10.253.66.2"
FALCO_EVENTS = Path(os.environ.get("AIRLOCK_FALCO_EVENTS", "/var/lib/airlock/falco/events.jsonl"))

DEFAULT_TIMEOUT = 120  # seconds for a whole detonation
SINK_START_TIMEOUT = 15
FALCO_FLUSH_TIMEOUT = 6  # seconds to wait for the sentinel after the run
MAX_LOG_CHARS = 20_000

SENTINEL_RULE = "airlock_sentinel"
LOCK_FILE = Path(tempfile.gettempdir()) / "airlock-detonation.lock"

_CONTAINER_LIMITS = [
    "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
    "--pids-limit=256", "--memory=1g", "--cpus=2",
]


class SandboxError(Exception):
    """The sandbox could not be prepared or run."""


@dataclass
class DetonationFinding:
    source: str    # "falco" or "sink"
    rule: str
    priority: str  # Falco priority: "Critical", "Warning"...
    detail: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class DetonationResult:
    findings: list[DetonationFinding] = field(default_factory=list)
    sensor_alive: bool = False  # Falco reported the sentinel of this run
    dns_queries: list[str] = field(default_factory=list)
    log: str = ""
    duration_seconds: float = 0.0
    scan_failed: bool = False
    error_message: str | None = None

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "sensor_alive": self.sensor_alive,
            "dns_queries": self.dns_queries,
            "log": self.log,
            "duration_seconds": self.duration_seconds,
            "scan_failed": self.scan_failed,
            "error_message": self.error_message,
        }


def _podman(*args: str, timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(["podman", *args], capture_output=True, text=True, timeout=timeout, check=False)
    if check and proc.returncode != 0:
        raise SandboxError(f"podman {args[0]} failed: {proc.stderr.strip()[-500:]}")
    return proc


def _prepare() -> None:
    if shutil.which("podman") is None:
        raise SandboxError("podman is not installed")
    if _podman("image", "exists", IMAGE, check=False).returncode != 0:
        raise SandboxError(f"image {IMAGE} is missing: run `podman build -t {IMAGE} sandbox/`")
    if _podman("network", "exists", NETWORK, check=False).returncode != 0:
        # --internal: no route out of this network, whatever the container does.
        _podman("network", "create", "--internal", "--subnet", SUBNET, NETWORK)


def _start_sink(name: str) -> None:
    _podman(
        "run", "-d", "--name", name, "--network", NETWORK, "--ip", SINK_IP,
        "--user", "0", "--read-only", "--cap-drop=ALL", "--cap-add=NET_BIND_SERVICE",
        "--security-opt=no-new-privileges", "--pids-limit=64", "--memory=256m",
        IMAGE, "python3", "-u", "/opt/airlock/sink.py", SINK_IP,
    )
    deadline = time.monotonic() + SINK_START_TIMEOUT
    while time.monotonic() < deadline:
        if '"ready"' in _podman("logs", name, check=False).stdout:
            return
        time.sleep(0.2)
    raise SandboxError("the network sink did not start")


def _archive_format(archive: Path) -> str:
    return "zip" if archive.name.endswith((".whl", ".zip")) else "tar"


def _falco_offset() -> int | None:
    try:
        return FALCO_EVENTS.stat().st_size
    except OSError:
        return None


def _read_falco_events(offset: int | None, container_id: str) -> list[dict]:
    """Return the events of this container after its sentinel, sentinel included."""
    if offset is None:
        return []
    deadline = time.monotonic() + FALCO_FLUSH_TIMEOUT
    while True:
        events = _parse_falco_events(offset, container_id)
        if any(e.get("rule") == SENTINEL_RULE for e in events) or time.monotonic() > deadline:
            break
        time.sleep(0.5)
    if events:
        time.sleep(1)  # the kernel ring buffer delivers the last events slightly later
        events = _parse_falco_events(offset, container_id)
    for index, event in enumerate(events):
        if event.get("rule") == SENTINEL_RULE:
            return events[index:]
    return []


def _parse_falco_events(offset: int, container_id: str) -> list[dict]:
    with open(FALCO_EVENTS, encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        lines = f.readlines()
    events = []
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        event_container = str(event.get("output_fields", {}).get("container.id", ""))
        if event_container and container_id.startswith(event_container):
            events.append(event)
    return events


def _decoded_views(data: bytes) -> list[bytes]:
    """The payload as sent, plus what its hex and base64 looking runs decode to."""
    views = [data]
    for run in re.findall(rb"[0-9a-fA-F]{16,}", data):
        try:
            views.append(binascii.unhexlify(run[: len(run) // 2 * 2]))
        except binascii.Error:
            pass
    for run in re.findall(rb"[A-Za-z0-9+/_-]{16,}={0,2}", data):
        padded = run.replace(b"-", b"+").replace(b"_", b"/").rstrip(b"=")
        try:
            views.append(base64.b64decode(padded + b"=" * (-len(padded) % 4)))
        except binascii.Error:
            pass
    return views


def _contains_canary(data: bytes, canary: str) -> bool:
    token = canary.encode()
    return any(token in view for view in _decoded_views(data))


def analyse_sink_log(log: str, canary: str) -> tuple[list[DetonationFinding], list[str]]:
    """Turn the sink's JSON lines into findings and the list of DNS names queried."""
    findings: list[DetonationFinding] = []
    names: list[str] = []
    for line in log.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("kind") == "dns":
            name = record.get("name", "")
            names.append(name)
            payload = name.replace(".", "").encode()
            if _contains_canary(payload, canary):
                findings.append(DetonationFinding(
                    "sink", "canary_exfiltrated", "Critical", f"canary token sent over DNS: {name[:100]}",
                ))
        elif record.get("kind") == "tcp":
            data = base64.b64decode(record.get("data", ""))
            if _contains_canary(data, canary):
                findings.append(DetonationFinding(
                    "sink", "canary_exfiltrated", "Critical",
                    f"canary token sent over TCP port {record.get('port')}",
                ))
    return findings, names


def _falco_findings(events: list[dict]) -> list[DetonationFinding]:
    findings, seen = [], set()
    for event in events:
        rule = event.get("rule", "")
        if rule == SENTINEL_RULE:
            continue
        detail = re.sub(r"^\S+ \S+: \w+ ", "", event.get("output", ""))[:300]
        key = (rule, detail)
        if key not in seen:
            seen.add(key)
            findings.append(DetonationFinding("falco", rule, event.get("priority", "Warning"), detail))
    return findings


def detonate(archive: Path, ecosystem: str, timeout: int = DEFAULT_TIMEOUT) -> DetonationResult:
    """Detonate a package archive. Never raises: failures give scan_failed=True."""
    started = time.monotonic()
    try:
        # One detonation at a time: the sink owns a fixed address on the network.
        with open(LOCK_FILE, "w", encoding="utf-8") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = _detonate(archive, ecosystem, timeout)
    except (SandboxError, OSError, subprocess.SubprocessError) as e:
        result = DetonationResult(scan_failed=True, error_message=str(e))
    result.duration_seconds = round(time.monotonic() - started, 1)
    return result


def _detonate(archive: Path, ecosystem: str, timeout: int) -> DetonationResult:
    _prepare()
    run_id = secrets.token_hex(6)
    canary = f"AIRLOCKCANARY{secrets.token_hex(12)}"
    sink, target = f"airlock-sink-{run_id}", f"airlock-det-{run_id}"

    try:
        _start_sink(sink)
        offset = _falco_offset()
        with open(archive, "rb") as stdin:
            log = _run_target(target, stdin, ecosystem, _archive_format(archive), canary, timeout)
        container_id = _podman("inspect", target, "--format", "{{.Id}}").stdout.strip()
        sink_log = _podman("logs", sink, check=False).stdout
    finally:
        _podman("rm", "-f", "-t", "0", target, check=False)
        _podman("rm", "-f", "-t", "0", sink, check=False)

    events = _read_falco_events(offset, container_id)
    sink_findings, dns_queries = analyse_sink_log(sink_log, canary)
    sensor_alive = any(e.get("rule") == SENTINEL_RULE for e in events)

    return DetonationResult(
        findings=[*_falco_findings(events), *sink_findings],
        sensor_alive=sensor_alive,
        dns_queries=dns_queries[:50],
        log=log.replace(canary, "<canary>")[-MAX_LOG_CHARS:],
        scan_failed=not sensor_alive,
        error_message=None if sensor_alive else "Falco did not see the sentinel: the sensor is blind or stopped",
    )


def _run_target(name: str, stdin, ecosystem: str, archive_format: str,
                canary: str, timeout: int) -> str:
    # No --rm: the container id is read after the run. _detonate always removes it.
    cmd = [
        "podman", "run", "-i", "--name", name,
        "--network", NETWORK, "--dns", SINK_IP, "--user", "1500:1500", *_CONTAINER_LIMITS,
        # exec is on purpose: droppers must be able to run for Falco to see them.
        "--tmpfs", "/home/dev:rw,exec,mode=1777",
        "--tmpfs", "/tmp:rw,exec,mode=1777",
        "--tmpfs", "/work:rw,exec,mode=1777",
        "--env", f"AIRLOCK_CANARY={canary}", "--env", "AIRLOCK_SANDBOX=1", "--env", "HOME=/home/dev",
        IMAGE, "/opt/airlock/detonate.sh", ecosystem, archive_format,
    ]
    try:
        proc = subprocess.run(cmd, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired as e:
        return (e.stdout or b"").decode("utf-8", "replace") + "\n[airlock] detonation timed out"
    output = proc.stdout.decode("utf-8", "replace")
    if "[airlock] detonation starts" not in output:
        raise SandboxError(f"the sandbox did not start (exit {proc.returncode}): {output[-500:]}")
    return output
