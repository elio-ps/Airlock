# Day 2 operations — Airlock

How to deploy, run, update, supervise, back up and recover Airlock after the
first install. "Day 2" is everything that is not the initial build.

## Deployment / reproducibility

Everything starts from a clean machine:

```bash
git clone <repo> && cd Airlock
python3 -m venv venv && . venv/bin/activate
pip install -r airlock/requirements.txt
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/v0.76.1/contrib/install.sh \
  | sudo sh -s -- -b /usr/local/bin v0.76.1          # pinned, verified (ADR-0006)
podman build -t localhost/airlock-sandbox:1 sandbox/  # base image pinned by digest
python3 -m pytest airlock/tests -c airlock/pytest.ini  # should be all green
```

Reproducibility rests on: pinned Trivy version, the sandbox base image pinned by
digest, GuardDog pinned to a major range, and the frozen corpora. No step needs
state from a previous install.

## Running a scan

```bash
. venv/bin/activate
sudo sandbox/falco.sh start                 # sensor up (see Supervision)
python3 -m airlock.pipeline npm <package>   # exit code = verdict (0/2/3, 1=error)
```

## Updating

| Component | How | Record it |
|---|---|---|
| Trivy | change the version in the install command and in `airlock/README.md`; re-run | decision log / ADR-0006 |
| Trivy vulnerability DB | `trivy image --download-db-only` (cache), scheduled daily | — |
| GuardDog | bump the pin in `requirements.txt`, re-run **both** corpora, check no regression | decision log |
| Sandbox base image | update the digest in `sandbox/Containerfile`, rebuild, re-run the detonation corpus | decision log |
| Falco | update the digest in `sandbox/falco.sh`, restart, confirm the sentinel fires | decision log |

After any update to GuardDog or the sandbox, re-run the corpora
(`run_eval`, `run_detonation`) — a changed metric is the signal to investigate.

## Supervision

- **Is the sensor alive?** `sudo sandbox/falco.sh status`, and every detonation
  self-checks via the sentinel. If `sensor_alive` is false in a report, the
  sensor is blind: scans silently degrade to `unavailable`, not to "clean".
- **Scan outcomes**: each run writes `airlock_runs/<...>/report.json` with the
  verdict, the per-stage status and the reasons. These are the audit trail.
- **Stage availability**: a run whose Trivy or deps.dev stage is `unavailable`
  points to a network/DB problem, not a clean package.

## Incident response (a package is BLOCKed or a scan looks wrong)

1. Read `report.json`: the `reasons` list says exactly which signal fired.
2. For a detonation BLOCK, read `details.detonation` (the Falco findings and the
   sink's canary hits) and the captured `log`.
3. If a stage is `unavailable`, fix the dependency (DB, network) and re-run;
   do not treat `unavailable` as `allow`.
4. A confirmed malicious package: keep the report, remove the package from any
   cache/proxy, rotate any credential that a canary showed leaving.

## Backup and restore (tested, not just configured)

Airlock is **stateless**: the source is in Git, and everything else is derived
(venv, Trivy binary and DB, the sandbox image, the run reports). So the backup
is the Git repository plus, optionally, the reports to keep for audit.

Restore drill (what we actually test):

```bash
# simulate a lost machine: fresh clone in a new directory
git clone <repo> /tmp/airlock-restore && cd /tmp/airlock-restore
python3 -m venv venv && . venv/bin/activate && pip install -r airlock/requirements.txt
podman build -t localhost/airlock-sandbox:1 sandbox/
python3 -m pytest airlock/tests -c airlock/pytest.ini   # green == restored
```

The green test suite on a fresh clone is the restore proof: no hidden state is
required. Reports worth keeping (`airlock_runs/`) are backed up separately
because they are intentionally git-ignored.

## Routine schedule (suggested)

| When | Task |
|---|---|
| each scan | Falco sensor up, sentinel confirmed |
| daily | refresh the Trivy DB cache |
| on dependency bump | re-run both corpora, compare metrics |
| per release of Airlock | full restore drill on a clean checkout |
