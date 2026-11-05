# ADR-0003: `threat-*` rules block, `capability-*` rules are ignored

Status: superseded by [ADR-0007](0007-block-needs-dynamic-proof.md) and [ADR-0008](0008-undetonated-hook-quarantine.md) · Date: 2026-11-05 (written after the fact)

## Context
GuardDog produces two rule families. `capability-*` describes what the code can
do (network, files, processes) and appears in almost all legitimate code.
`threat-*` describes behaviour documented as malicious (exfiltration, execution
of obfuscated code, persistence).

## Options
1. Block on any GuardDog rule.
2. Block on `threat-*`, ignore `capability-*`.
3. Weighted score mixing both.

## Decision
Option 2: a `threat-*` rule gives BLOCK, `capability-*` rules do not change the
verdict.

## Consequences
+ Few false positives on the evaluation corpus (10/10 malicious, 0 false
  positives on 10 benign).
− Known gap: the `hook-evil-sim` fixture (simulated postinstall) only triggers
  `capability-*` rules and is therefore allowed. The matching test is marked
  xfail.
− To review: add a "`capability-*` in an install hook (postinstall)" rule, then
  remove the xfail.
