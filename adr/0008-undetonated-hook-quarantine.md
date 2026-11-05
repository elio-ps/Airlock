# ADR-0008: Install-time code that was not detonated is quarantined

Status: accepted · Date: 2026-11-05 · Supersedes part of ADR-0003

## Context
ADR-0003 left a known gap: the `hook-evil-sim` fixture only triggers
`capability-*` rules and was allowed. The first idea was a rule "`capability-*`
in an install hook". It does not cover inline hooks such as
`"postinstall": "curl ... | sh"`, which are in no scanned source file, and
static analysis cannot vouch for code it cannot see running.

## Options
1. Rule "`capability-*` in a hook file": needs hook-to-file resolution, misses
   inline commands.
2. Any install hook requires detonation; without it, QUARANTINE.

## Decision
Option 2 (`Policy.quarantine_on_undetonated_hook`, default `True`). Install-time
code means npm `preinstall`, `install`, `postinstall`, an implicit `node-gyp`
build (`binding.gyp`), or a `setup.py` in a PyPI sdist.

## Consequences
+ The known gap is closed and the matching xfail test removed.
+ Simple to explain: no one watched this code run, so no one vouches for it.
− When the sandbox is down, every package with a hook waits in QUARANTINE.
  This is the intended fail-safe; the procedure is in the operations guide.
