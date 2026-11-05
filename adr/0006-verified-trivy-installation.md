# ADR-0006: Trivy installed at a fixed, verified version

Status: accepted · Date: 2026-11-05

## Context
Airlock calls the Trivy binary, which cannot be installed from PyPI. The
`install.sh` script on the `main` branch changes over time and runs with `sudo`.
This is a supply chain risk, exactly what Airlock fights.

## Options
1. `curl ... | sudo sh` from `main`: simple, but neither script nor version is fixed.
2. Script from the version tag: version and script are fixed.
3. Release archive with SHA-256 verification: longer, fully verifiable.

## Decision
Option 2 for development:
`curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/v<VERSION>/contrib/install.sh | sudo sh -s -- -b /usr/local/bin v<VERSION>`
Option 3 in the production image (Dockerfile). A single version recorded in the
repository (`v0.76.1`, to confirm on the releases page before use).

## Consequences
+ Reproducible, auditable installation.
+ The vulnerability database can be prepared in advance
  (`trivy image --download-db-only`) and passed through `cache_dir` (to wire
  into `pipeline.py`).
− Version updates are manual and must be recorded in the decision log.
