# Architecture dossier — Airlock (milestone 1)

Scope of this milestone: the manual analysis of a single package, end to end,
from ingestion to a justified verdict, plus the disposable detonation sandbox.
The package proxy on the critical path and the AI arbiter stage belong to the
final delivery and are out of scope here.

## 1. Context and threat

The asset Airlock protects is the **developer's / CI machine and the build
chain**. The attacker publishes (or compromises) an npm/PyPI package; the victim
installs it, and install-time code (`postinstall`, `setup.py`) runs before any
project code. Airlock sits between the registry and the machine and decides
whether a package may enter. The full risk analysis is in
[`risk-analysis.md`](risk-analysis.md).

## 2. Components and data flow

```
                 ┌─────────────┐
   npm / PyPI ──►│ ingestion   │ download, verify integrity (sha512/sha256),
   registry      │ fetch.py    │ extract safely (no code executed)
                 └──────┬──────┘
                        │ FetchedPackage (bytes on disk, metadata)
                        ▼
                 ┌─────────────┐
                 │ SBOM        │ CycloneDX 1.5 + resolved dependency graph
                 │ generate.py │ (deps.dev), so dependencies carry a purl
                 └──────┬──────┘
          ┌────────────┼───────────────┬────────────────┐
          ▼            ▼               ▼                ▼
     ┌─────────┐ ┌───────────┐  ┌───────────┐   ┌──────────────┐
     │ Trivy   │ │ GuardDog  │  │ deps.dev  │   │ detonation   │
     │ CVE     │ │ behaviour │  │ reputation│   │ sandbox      │
     │ (static)│ │ (static)  │  │ (network) │   │ (dynamic)    │
     └────┬────┘ └─────┬─────┘  └─────┬─────┘   └──────┬───────┘
          └────────────┴──────────────┴────────────────┘
                        │ per-stage signals (ok / suspect / unavailable / skipped)
                        ▼
                 ┌─────────────┐
                 │ verdict     │ ALLOW / QUARANTINE / BLOCK + readable reasons
                 │ aggregate.py│ monotonic (can only worsen), policy-driven
                 └─────────────┘
```

Orchestration is `airlock/pipeline.py`. A full JSON report per run is written to
`airlock_runs/<ecosystem>-<name>-<version>/report.json`.

## 3. Network flows

| From | To | Why | Notes |
|---|---|---|---|
| ingestion | `registry.npmjs.org`, `pypi.org` | download the package | integrity checked against the registry digest |
| Trivy | `mirror.gcr.io`, `ghcr.io` | vulnerability DB | can be pre-cached; degrades to `unavailable` |
| deps.dev | `api.deps.dev` | scorecard, dependents, resolved graph | degrades to `unavailable` |
| detonation container | **none** (internal network) | — | the sink is the only reachable host |
| detonation container | sink (`10.253.66.2`) | DNS + TCP, faked | nothing leaves the host |
| Falco | — | reads kernel events locally | no network |

The analysed package **never** has a route to the real internet. The only
outbound flows are Airlock's own tooling (registries, Trivy DB, deps.dev).

## 4. Isolation model

- Package **ingestion and static analysis** never execute package code.
- Package **detonation** runs rootless, read-only, capability-dropped, on an
  `--internal` network, with the archive passed on stdin (no shared host path).
  Details and trade-offs: [ADR-0009](../adr/0009-detonation-sandbox-design.md).
- The only **root** component is the Falco sensor, run with least privilege and
  the eBPF driver: [ADR-0010](../adr/0010-falco-ebpf-least-privilege.md).

## 5. The verdict

A deliberately readable rule set, not an opaque score, so each decision is
explainable and tunable per company (`Policy`, loadable from JSON). The verdict
is **monotonic**: it can only worsen across stages. Only behaviour observed at
detonation can BLOCK; static signals quarantine. The full table is in
[`../airlock/README.md`](../airlock/README.md) and the rationale in
[ADR-0004](../adr/0004-readable-monotonic-verdict.md),
[ADR-0007](../adr/0007-block-needs-dynamic-proof.md) and
[ADR-0008](../adr/0008-undetonated-hook-quarantine.md).

## 6. Degradation (fail-open / fail-closed)

Each stage reports `ok` / `suspect` / `unavailable` / `skipped`. An
`unavailable` signal never, on its own, means "clean". Whether an unavailable
stage lets a package through (fail-open) or quarantines it (fail-closed) is a
policy choice, defaulting to fail-open in dev and fail-closed in production:
[ADR-0005](../adr/0005-unavailable-stage-fail-open-or-closed.md).

## 7. Technology choices

Python for the whole pipeline ([ADR-0001](../adr/0001-python-over-go.md)),
GuardDog as a library ([ADR-0002](../adr/0002-guarddog-as-library.md)), Trivy
pinned and verified ([ADR-0006](../adr/0006-verified-trivy-installation.md)),
Podman (rootless) + Falco (eBPF) for detonation. Every choice is an ADR in
[`../adr/`](../adr/).

## 8. Compliance references

The relevant frameworks for this project and where Airlock already aligns:

- **ANSSI guide d'hygiène** — controlling third-party code (rule on supply
  chain), reproducible deployment, least privilege (the Falco sensor).
- **CIS / container hardening** — read-only root filesystem, dropped
  capabilities, no-new-privileges, non-root user, pinned base image by digest.
- **SLSA / supply chain** — SBOM generation (CycloneDX), integrity verification
  on download, provenance of the corpus.
- **GDPR / data** — no personal data is processed; the sandbox uses only decoy
  data with canary tokens.

These are starting points to deepen for the final delivery, not a certification.
