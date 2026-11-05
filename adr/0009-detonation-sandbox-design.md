# ADR-0009: Detonation sandbox — rootless containers, a network sink and Falco

Status: accepted · Date: 2026-11-05

## Context
The brief asks for detonation in a disposable sandbox watching network and
files (Falco). Running untrusted package code means two risks to contain:
escape from the sandbox, and a result that lies (code that stays quiet because
it detects the sandbox, or a sensor that is simply blind).

## Options for isolation
1. Run package code directly on the host under Falco.
2. Rootless Podman container per detonation, no route out.
3. A dedicated VM (microVM) per detonation.

## Decision
Option 2 for milestone 1. Each detonation is a fresh rootless container
(`--read-only`, `--cap-drop=ALL`, `--no-new-privileges`, pids/memory/cpu caps,
`tmpfs` for the writable paths), on an `--internal --disable-dns` network. The
archive is passed on stdin, so no host path is ever shared with the code.
Option 3 is noted for the final delivery (the Warden project uses microVMs; the
brief mentions microsandbox) and will get its own ADR.

## Three design decisions worth recording

### A network sink is the only reachable host
Malware that cannot reach anything often does nothing. A sink container
(`sink.py`) answers every DNS query with its own address and accepts TCP on
common ports, so the code believes it reached the outside. Each run seeds the
decoy files and the environment with a one-time **canary** token; when the sink
receives that token, data left the machine. This catches exfiltration of
secrets read from the environment, which no file event would show, and it works
even when Falco is down. The sink reassembles data split across many DNS queries
(the technique the home-made sample uses).

### Two independent witnesses
Falco (kernel view, see ADR-0010) reports *behaviour* (decoy read, persistence,
dropped program run); the sink proves *exfiltration*. They fail independently,
so one covers the other. Priorities map to the verdict: a Critical finding
blocks, a Warning quarantines (ADR-0007 reserves BLOCK for dynamic proof).

### A silent sensor must never read as "clean"
Falco being quiet can mean "nothing happened" or "Falco saw nothing". These are
opposite for a security tool. Every detonation first reads a sentinel file; if
Falco does not report that read, the sensor was blind and the stage is
`unavailable`, never `ok`. Events before the sentinel (the harness seeding
decoys) and events from other containers are dropped.

## Consequences
+ No host path shared, no route out, fresh container each time.
+ Exfiltration is caught even without Falco (the sink is independent).
+ A blind sensor degrades honestly to `unavailable` (then fail-open or
  fail-closed per ADR-0005), never to a false "clean".
− A container escape would still reach the host kernel; a VM (option 3) would
  not. Accepted for milestone 1, to revisit for the final delivery.
− One detonation at a time: the sink owns a fixed address (a file lock enforces
  this). Throughput is a concern for the proxy on the critical path, noted for
  the final delivery.
