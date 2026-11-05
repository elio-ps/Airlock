# ADR-0010: Falco as a least-privilege eBPF sensor, not a privileged container

Status: accepted · Date: 2026-11-05

## Context
Falco reads kernel events, which needs privilege. The documented quick start is
`--privileged` with the kernel-module driver. Airlock fights supply chain risk,
so it should not grant more than needed to its own sensor.

## Options
1. `--privileged` with the kernel module (the documented default).
2. Modern eBPF driver (`CO-RE`, no module build) with only the capabilities it
   needs: `BPF`, `PERFMON`, `SYS_RESOURCE`, `SYS_PTRACE`.
3. Falco on the host (packages), not in a container.

## Decision
Option 2 (`sandbox/falco.sh`): `--cap-drop=ALL` then add only those four
capabilities, `engine.kind=modern_ebpf`, `--pid=host` and read-only `/proc` and
`/etc`. The image is pinned by digest. Falco is the only component that needs
root; packages always run rootless (ADR-0009).

Requires a kernel with BTF (`/sys/kernel/btf/vmlinux`), checked on the dev
machine (kernel 6.x, BTF present).

## Consequences
+ The sensor runs without `--privileged` and without building a kernel module.
+ Capabilities are explicit and auditable; the image is reproducible.
+ Airlock's own trust base stays small.
− eBPF needs a recent kernel with BTF. On an older kernel, fall back to the
  `kmod` or `ebpf` driver (a one-line change in `falco.sh`), to record in the
  decision log.
− `--pid=host` and host `/proc` are still a broad view; it is read-only and
  Falco is trusted infrastructure, but it is not nothing.
