# ADR-0007: BLOCK needs dynamic proof, static signals only quarantine

Status: accepted · Date: 2026-11-05 · Supersedes part of ADR-0003

## Context
The 10/10 result of the static corpus suggested that any `threat-*` rule could
block. That corpus is made of GuardDog's own fixtures. Analysing the real sdist
of popular packages told a different story: 6 of 18 trigger at least one
`threat-*` rule.

| Package | Example of a false positive |
|---|---|
| requests 2.31.0 | `file:///etc/passwd` as a test string in `tests/test_requests.py` |
| flask 3.0.3 | `threat-filesystem-read` |
| django 5.0.6 | six rules, including `threat-network-exfiltration` in tests |
| pyyaml 6.0.1 | `threat-runtime-dynamic-loader` |
| pillow 10.3.0 | `threat-process-download-exec` |
| webpack 5.91.0 | `threat-filesystem-read` |

Measured on: requests, flask, django, pyyaml, boto3, pytest, cryptography,
pillow, express, lodash, axios, react, esbuild, core-js, typescript, webpack,
sharp, husky.

## Options
1. Keep `threat-*` = BLOCK: 6 of 18 wrongly blocked.
2. BLOCK only for rules of high severity and high specificity: 3 of 18 still
   wrongly blocked (django, pyyaml, pillow).
3. `threat-*` = QUARANTINE, BLOCK reserved for behaviour observed at detonation.

## Decision
Option 3. `Policy.block_on_any_threat_rule` defaults to `False`; a company can
set it to `True` to restore option 1.

## Consequences
+ 0 of 18 wrongly blocked. A static pattern is treated as what it is: a reason to
  look closer.
+ Matches the project goal: detect by dynamic analysis, without signatures.
+ A package that evades the sandbox but triggers a rule stays in QUARANTINE: the
  verdict never improves (ADR-0004).
− 6 of 18 popular packages need human review. Stage 4 (AI arbiter, final delivery)
  is expected to reduce this load.
− The static corpus now measures "flagged" rather than "blocked".
