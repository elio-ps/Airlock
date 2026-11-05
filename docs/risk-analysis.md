# Risk analysis — Airlock (milestone 1)

This analysis justifies Airlock's security choices. It follows a simple
EBIOS-like shape: what we protect, what threatens it, what we do about it, and
what residual risk we accept.

## Assets

| # | Asset | Why it matters |
|---|---|---|
| A1 | The developer / CI machine | the real target; where install hooks run |
| A2 | Developer credentials (registry tokens, cloud keys, SSH) | pivot to the whole supply chain |
| A3 | The build chain integrity | a poisoned build ships to users |
| A4 | Airlock itself (its verdict, its sensor) | if Airlock lies, it is worse than nothing |

## Threat sources

Opportunistic malware in public packages (typosquatting, dependency confusion),
a targeted attacker compromising a specific dependency, and a self-propagating
worm stealing registry tokens to publish further.

## Risks and measures

| # | Risk (threat → asset) | Likelihood | Impact | Measures in Airlock | Residual |
|---|---|---|---|---|---|
| R1 | Install hook steals secrets (malware → A2) | high | high | detonation with decoy secrets + canary; undetonated hooks quarantined (ADR-0008) | medium: a sandbox-aware payload may stay quiet |
| R2 | Malware evades static detection (malware → A1) | high | high | dynamic detonation; BLOCK requires observed behaviour (ADR-0007); home-made sample proves it | medium: coverage limited to observed phases |
| R3 | Known-vulnerable dependency pulled in (→ A3) | medium | medium | Trivy on a SBOM with the resolved graph (purls), HIGH/CRITICAL → quarantine | low |
| R4 | Analysed code escapes the sandbox (→ A1) | low | high | rootless, read-only, cap-drop, no-new-privileges, internal network (ADR-0009) | low→medium: container escape still hits the host kernel; VM planned |
| R5 | Analysed code exfiltrates during detonation (→ A2) | high | high | `--internal` network, sink is the only host, nothing routes out | low |
| R6 | A scanner outage looks like "clean" (→ A4) | medium | high | explicit `unavailable` state; fail-closed option (ADR-0005) | low |
| R7 | The sensor is blind but silent (→ A4) | medium | high | sentinel check: no sentinel → `unavailable`, never "clean" (ADR-0009) | low |
| R8 | Airlock's own supply chain is poisoned (→ A4) | low | high | pinned Trivy (ADR-0006), image pinned by digest, GuardDog pinned (ADR-0002) | medium: Python deps not yet fully pinned/hashed |
| R9 | Path traversal / archive bomb on extraction (→ A1) | medium | medium | traversal + symlink + size/member limits (`fetch.py`), no code run on ingestion | low |
| R10 | False positives flood the team (→ usability) | medium | medium | static patterns only quarantine; benign corpus measures FPs (0/6, 0/10) | medium: 6/18 popular packages still need review |

## Accepted residual risks

- **Sandbox-aware or time-delayed malware** (R1, R2): a payload that detects the
  sandbox, or waits, may not reveal itself. Mitigated by the decoy environment
  and multiple phases; a VM and longer observation are for the final delivery.
- **Container escape** (R4): the sandbox shares the host kernel. Accepted for
  milestone 1; a microVM is the planned step (noted in ADR-0009).
- **Airlock's Python dependencies** (R8): pinned to ranges, not yet hashed. A
  `pip`-hash lock file is a milestone-2 task.
- **Review load from static quarantines** (R10): the AI arbiter stage (final
  delivery) is expected to reduce it.

## How the measures are evidenced

Every measure above is implemented and tested: see `airlock/tests/` (ingestion
hardening, verdict logic, detonation witnesses) and the two corpus evaluation
reports (`airlock/corpus/corpus_eval_report.json`,
`airlock/corpus/detonation_eval_report.json`).
