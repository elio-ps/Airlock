# ADR-0004: Readable verdict that can only get worse

Status: accepted · Date: 2026-11-05 (earlier decision, written after the fact)

## Context
The verdict (ALLOW / QUARANTINE / BLOCK) must be explainable to a human and
adjustable to a company's policy.

## Options
1. Single weighted score with a threshold.
2. Explicit rules, each signal able to raise the severity level.

## Decision
Option 2 (`verdict/aggregate.py`):
- a GuardDog `threat-*` rule: BLOCK;
- a HIGH or CRITICAL CVE: QUARANTINE;
- Scorecard < 3/10 on a little-used package (< 50 dependents): QUARANTINE;
- otherwise ALLOW.
The verdict can only get worse across stages: a BLOCK is never cancelled by a
good deps.dev score. Thresholds are isolated in `Policy`, loadable from a JSON
file.

## Consequences
+ Each decision is justified by a readable reason in the report.
+ Thresholds can change without touching the logic.
− Less fine-grained than a score: two weak signals do not add up.
− The dependents rule relies on the `dependent_count` field of deps.dev, to
  verify on a real response (a missing value counts as 0 in the code).
