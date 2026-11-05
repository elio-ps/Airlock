# Airlock

**Controlling what enters the software build chain.** AIR-02, second-year
Bachelor Cybersecurity annual project — team Airlock.

A supply chain attack does not target the application; it targets the
developer's machine, before any code of the project runs. Airlock takes an npm
or PyPI package and inspects it through several independent stages, then returns
a verdict — **ALLOW / QUARANTINE / BLOCK** — that a human can read and a company
can tune.

```
ingestion -> SBOM -> Trivy -> GuardDog -> deps.dev -> detonation -> verdict
```

Static signals (CVEs, suspicious code patterns, poor project hygiene) raise
suspicion; only behaviour **observed when the package is run** in a disposable
sandbox can block it. This matches the brief's goal: detect the home-made
malware by dynamic analysis, without a signature.

## Repository layout

| Path | What it is |
|---|---|
| [`airlock/`](airlock/README.md) | the pipeline (ingestion → verdict), tests, corpora |
| [`sandbox/`](sandbox/README.md) | the detonation sandbox: image, network sink, Falco sensor |
| [`adr/`](adr/README.md) | architecture decision records — every significant choice, argued |
| [`docs/`](docs/) | architecture dossier, risk analysis, Day 2 operations, AI-usage log |
| [`fixtures/`](fixtures/) | small npm fixtures used by the unit tests |

## Quick start

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r airlock/requirements.txt
podman build -t localhost/airlock-sandbox:1 sandbox/   # for detonation

python3 -m airlock.pipeline pypi requests --version 2.31.0
```

Full install and usage: [`airlock/README.md`](airlock/README.md). Running the
Falco sensor: [`sandbox/README.md`](sandbox/README.md).

## Milestone 1 (January) — status

The brief's milestone-1 deliverables ("analyse à la main"):

- [x] Put an npm/PyPI package through the wringer: SBOM, Trivy, GuardDog, deps.dev
- [x] Detonation in a disposable sandbox (Falco: network + files)
- [x] Frozen corpus: 10 malicious + 10 benign, verdict documented
- [x] A home-made, original malware in a postinstall (caught dynamically)
- [x] Deliverable: judgement method + reference corpus
- [x] Common deliverables: architecture, ADRs, risk analysis, Day 2, traceability

## A note on scope

This is a school project with an educational purpose. The malicious samples in
the detonation corpus are **simulated and inert** (see
[`airlock/corpus/detonation/README.md`](airlock/corpus/detonation/README.md)):
they do nothing outside the sandbox, target only the reserved `.invalid` domain,
and touch no real secret.

## AI usage

AI assistance is declared and logged, as required by the school's AI charter
(level 2–3). See [`docs/ai-usage-log.md`](docs/ai-usage-log.md).
