# ADR-0005: Behaviour when a stage is unavailable

Status: accepted · Date: 2026-11-05

## Context
Trivy and deps.dev depend on the network. Today an unavailable stage is marked
`unavailable` and never worsens the verdict: if GuardDog finds nothing, the
package is allowed (ALLOW) even with no CVE data and no score. For a proxy on
the critical path, this is a security choice to own.

## Options
1. Fail-open (current): stage unavailable, carry on.
2. Fail-closed: at least one stage unavailable, so QUARANTINE.
3. Configurable per policy, with fail-closed as the production default.

## Decision
Option 3: `Policy.fail_closed`. Fail-open by
default for development and tests, fail-closed in production. Also distinguish
"package unknown to deps.dev" (404, a signal in itself for a recent package)
from a network failure.

## Consequences
+ A Trivy or deps.dev outage no longer lets a package through without a full
  check.
− More quarantines to handle by hand during an outage: plan a Day 2 procedure
  (and result caching, ADR to come).
+ A stage skipped on purpose (`--skip`, local package) has its own `skipped`
  status and does not count as an outage.
