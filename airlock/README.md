# Airlock — controlling what enters the build chain

Educational school project (AIR-02). The victim of a supply chain attack is not
the application, it is the developer's machine: the attack happens *before* a
single line of code runs. Airlock inspects an npm or PyPI package before it is
allowed into the build chain and returns a justified verdict.

## The pipeline

```
ingestion -> SBOM -> Trivy -> GuardDog -> deps.dev -> detonation -> verdict
 (fetch)    (CycloneDX) (CVE)  (behaviour)  (reputation)  (sandbox)
```

Every stage is isolated: a stage that fails (typically on the network) does not
crash the next ones. Its signal is marked `unavailable` and, by design, never
confused with "nothing found" — a failed scanner must not look like a clean one.

| Stage | Module | What it answers |
|---|---|---|
| ingestion | `ingest/fetch.py` | download + verify integrity + extract safely (no code run) |
| SBOM | `sbom/generate.py` | CycloneDX 1.5 inventory, with the resolved dependency graph |
| Trivy | `analysis/trivy_scan.py` | known CVEs in the package and its dependencies |
| GuardDog | `analysis/guarddog_scan.py` | suspicious behaviour in the source (static) |
| deps.dev | `analysis/depsdev.py` | OpenSSF Scorecard, usage, known advisories |
| detonation | `detonation/sandbox.py` | what the package *does* when run (dynamic) |
| verdict | `verdict/aggregate.py` | combine everything into ALLOW / QUARANTINE / BLOCK |

## Install

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r airlock/requirements.txt

# Trivy (a Go binary, not on PyPI), pinned version (ADR-0006):
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/v0.76.1/contrib/install.sh \
  | sudo sh -s -- -b /usr/local/bin v0.76.1

# Detonation sandbox (see ../sandbox/README.md for the Falco sensor):
podman build -t localhost/airlock-sandbox:1 sandbox/
```

## Use

```bash
# Full scan of a package (static stages; detonation needs the sandbox image)
python3 -m airlock.pipeline pypi requests --version 2.31.0
python3 -m airlock.pipeline npm left-pad

# Skip stages (e.g. when offline, or without the sandbox)
python3 -m airlock.pipeline npm some-package --skip trivy,depsdev,detonation

# Company policy (thresholds)
python3 -m airlock.pipeline pypi some-package --policy my_policy.json
```

The CLI exit code carries the verdict (0 allow, 2 quarantine, 3 block, 1 error),
so a CI job or a shell script can act on it. Each run also writes a full report
to `airlock_runs/<ecosystem>-<name>-<version>/report.json`.

## The verdict: a method, not an opaque score

The verdict is deliberately readable so it can be explained to a human and tuned
per company (`Policy`, loadable from JSON). It can only get **worse** across
stages, never better: a BLOCK is never cancelled by a good deps.dev score.

| Signal | Trigger | Verdict |
|---|---|---|
| Detonation | Critical behaviour observed (decoy read, persistence, dropper, canary leak) | **BLOCK** |
| Detonation | Warning behaviour (outbound connection, network tool) | QUARANTINE |
| GuardDog | ≥1 `threat-*` rule (a static pattern, not a proof) | QUARANTINE |
| Trivy | HIGH/CRITICAL CVE | QUARANTINE |
| deps.dev | Scorecard < 3/10 on a little-used package, or package unknown | QUARANTINE |
| install hooks | install-time code that was not detonated clean | QUARANTINE |
| — | nothing suspicious | ALLOW |

Only a behaviour **observed at detonation** can BLOCK (ADR-0007): static
patterns are noisy (measured: 6 of 18 popular packages trigger a `threat-*`
rule, see ADR-0007), so on their own they quarantine for human review.

## Corpora and evaluation

Two corpora, measured as test sets (false positives / negatives):

- **static** (`corpus/samples/`, 10 malicious + 10 benign): GuardDog's own
  fixtures, re-used for verifiable provenance. Run `python3 -m airlock.corpus.run_eval`.
  Measures that our integration reads GuardDog correctly, not GuardDog itself.
- **detonation** (`corpus/detonation/`, 6 malicious + 6 benign): home-made,
  simulated and inert (see its README). Run `python3 -m airlock.corpus.run_detonation`
  (needs the sandbox image and, for the file-only samples, the Falco sensor).
  Includes the brief's required home-made sample, caught dynamically without a
  static signature.

## Tests

```bash
python3 -m pytest airlock/tests -c airlock/pytest.ini -p no:cacheprovider
# Add real registry calls (npm/PyPI/deps.dev):
python3 -m pytest airlock/tests -c airlock/pytest.ini -m network
```

## Known limits of the dev environment

The static corpus scores 100% because it is GuardDog's own fixtures: it tests
our integration, not detection in the wild. Trivy and deps.dev need outbound
access (`mirror.gcr.io`/`ghcr.io` for the Trivy DB, `api.deps.dev` for
scorecards); in a restricted network they degrade to `unavailable`.

## Design decisions

All significant choices are recorded as ADRs in [`../adr/`](../adr/). Start
there to understand *why* the pipeline looks like this.
