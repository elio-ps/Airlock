# ADR-0001: Python rather than Go for the pipeline

Status: accepted · Date: 2026-11-05 (earlier decision, written after the fact)

## Context
Airlock chains ingestion, SBOM, Trivy, GuardDog, deps.dev and the verdict.
GuardDog is written in Python. Trivy, Falco and OPA are written in Go. The
project is run by a pair, and a single language is wanted to limit integration
complexity.

## Options
1. Python for the whole pipeline.
2. Go for the package proxy, Python for the analysis.
3. Go for everything.

## Decision
Option 1 for the current analysis stage. Option 2 remains possible for the
package proxy of the final delivery, to be settled in a new ADR.

## Consequences
+ GuardDog is used as a library (see ADR-0002); the SBOM
  (`cyclonedx-python-lib`) and `requests` are in the same ecosystem.
+ A future AI stage stays in the same language.
− A Python proxy will perform worse than a Go one under load.
− Trivy remains an external binary to install (see ADR-0006).
