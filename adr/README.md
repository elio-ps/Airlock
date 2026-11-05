# Architecture Decision Records (ADR)

One record per decision: context, options, decision, consequences.
Format: increasing number, status `proposed` / `accepted` / `superseded`.
ADRs 0001 to 0005 were written after the fact (5 November 2026) for decisions
already made in the code.

| No. | Decision | Status |
|---|---|---|
| [0001](0001-python-over-go.md) | Python rather than Go for the pipeline | accepted |
| [0002](0002-guarddog-as-library.md) | GuardDog used as a Python library | accepted |
| [0003](0003-threat-blocks-capability-ignored.md) | `threat-*` rules block, `capability-*` rules are ignored | superseded |
| [0004](0004-readable-monotonic-verdict.md) | Readable verdict that can only get worse | accepted |
| [0005](0005-unavailable-stage-fail-open-or-closed.md) | Behaviour when a stage is unavailable | accepted |
| [0006](0006-verified-trivy-installation.md) | Trivy installed at a fixed, verified version | accepted |
| [0007](0007-block-needs-dynamic-proof.md) | BLOCK needs dynamic proof, static signals only quarantine | accepted |
| [0008](0008-undetonated-hook-quarantine.md) | Install-time code that was not detonated is quarantined | accepted |
| [0009](0009-detonation-sandbox-design.md) | Detonation sandbox: rootless containers, a network sink and Falco | accepted |
| [0010](0010-falco-ebpf-least-privilege.md) | Falco as a least-privilege eBPF sensor | accepted |
