# ADR-0002: GuardDog used as a Python library

Status: accepted · Date: 2026-11-05 (earlier decision, written after the fact)

## Context
GuardDog detects malicious behaviour in npm and PyPI packages. It can be called
from the command line or imported in Python.

## Options
1. Call the `guarddog` command in a subprocess and read its text output.
2. Import GuardDog and use its structured results.

## Decision
Option 2 (`analysis/guarddog_scan.py`).

## Consequences
+ Structured results (rule name, location) without text parsing.
+ Easier to test (`scan_local` mode, fixtures).
− Coupling to GuardDog's internal API: an update can break the wrapper. The
  version must be pinned in `requirements.txt`.
− GuardDog runs in the same process as Airlock, with no isolation. Analysed
  code is not executed, but an analysis bug affects the main process.
