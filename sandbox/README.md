# Airlock detonation sandbox

Everything needed to run an untrusted package and watch what it does. The design
and its trade-offs are in [ADR-0009](../adr/0009-detonation-sandbox-design.md)
and [ADR-0010](../adr/0010-falco-ebpf-least-privilege.md).

```
host (rootless Podman)
  |- detonation container   decoy home, no route out, archive on stdin
  |- sink container         the only reachable host; fakes DNS + TCP
host (root)
  |- Falco (eBPF)           kernel view of the detonation, independent witness
```

## Files

| File | Role |
|---|---|
| `Containerfile` | the disposable image (`localhost/airlock-sandbox:1`), base pinned by digest |
| `detonate.sh` | runs inside the container: seeds decoys with a canary, runs the install hooks and the load step |
| `sink.py` | the fake network: answers all DNS, accepts TCP, logs every exchange as JSON |
| `falco.sh` | starts/stops the Falco sensor (root), least privilege, eBPF |
| `falco/airlock_rules.yaml` | detection rules (behaviours, not signatures) |

The harness that drives all this lives in `../airlock/detonation/sandbox.py`.

## Build

```bash
podman build -t localhost/airlock-sandbox:1 sandbox/
```

## Run the sensor (root)

Falco reads kernel events, so it needs root — the only privileged part of
Airlock. Packages always run rootless.

```bash
sudo sandbox/falco.sh start    # start the eBPF sensor
sudo sandbox/falco.sh status   # check it
sudo sandbox/falco.sh stop     # stop it
```

Without the sensor, detonation still catches exfiltration through the sink
(canary tokens), but file-only behaviour (persistence, dropper) is not seen and
the result is reported as `unavailable` (never "clean"). See the evaluation
report `../airlock/corpus/detonation_eval_report.json` (`sensor_alive_for_all`).

## What makes a detonation trustworthy

- **One-time canary**: decoys and the environment hold a per-run token. If the
  sink sees it, data left the machine — even secrets read from the environment.
- **Sentinel**: each run begins by reading `/opt/airlock/sentinel`. If Falco
  does not report that read, the sensor was blind and the run is `unavailable`.
- **No route out**: the detonation network is `--internal`; the sink is the only
  reachable address, so nothing actually reaches the real internet.

## Requirements

- rootless Podman (tested with 5.x);
- a kernel with BTF at `/sys/kernel/btf/vmlinux` for the modern eBPF driver
  (fallback noted in ADR-0010);
- root only to run `falco.sh`.
