# Detonation corpus

Home-made test set for the **dynamic** stage: 6 malicious + 6 benign packages.
Run it with `python3 -m airlock.corpus.run_detonation` (needs the sandbox image
and, for the file-only samples, the Falco sensor). Output:
`../detonation_eval_report.json`.

This is distinct from `../samples/`, which tests the *static* stage (GuardDog).

## Safety

Every sample is **simulated and inert outside the sandbox**:

- a **safety interlock** at the top of each payload returns immediately unless
  `AIRLOCK_SANDBOX=1`, an environment variable only the sandbox sets;
- every network target is under the **`.invalid` TLD** (RFC 2606), which can
  never resolve to a real host — and inside the sandbox the only reachable
  address is the fake sink anyway;
- samples read only the **decoy** files the sandbox plants (fake keys holding a
  canary), never anything real;
- no sample contains a working exploit or real malware.

They are safe to keep in a public repository and to run on a developer machine
(outside the sandbox they do nothing).

## Malicious samples — one detection path each

| Sample | Ecosystem | Technique reproduced | Caught by |
|---|---|---|---|
| m01-npm-env-http | npm | environment theft over HTTP (postinstall) | sink (canary), Falco (outbound) |
| m02-npm-npmrc-read | npm | registry-token theft from `~/.npmrc` (preinstall) | Falco (decoy read), sink |
| m03-npm-persistence | npm | shell-startup persistence in `~/.bashrc` (install) | Falco (persistence) |
| m04-npm-dropper | npm | second stage dropped in `/tmp` and executed (postinstall) | Falco (exec from writable dir) |
| m05-pypi-setup-exfil | PyPI | credential theft from `setup.py` at install time | Falco (decoy read), sink |
| **m06-npm-prebuild-grabber** | npm | **home-made**: fake prebuilt-binary downloader | sink + Falco |

`m06` is the brief's required home-made original. It evades static detection
(GuardDog raises no `threat-*` rule): the files to steal are data in a JSON
"mirror list", a plausible cache lookup wraps the reads, and exfiltration is
disguised as a mirror-availability probe (one DNS query per chunk). It is caught
only at detonation — by the decoy reads and by the sink reassembling the canary
across the DNS queries.

## Benign samples — harmless, to measure false positives

| Sample | Why it must stay ALLOW |
|---|---|
| b01-npm-echo | postinstall just prints a message |
| b02-npm-build-own-dir | a real build, writing only inside its own tree |
| b03-npm-read-own-file | reads a config file it ships (not a decoy) |
| b04-pypi-setup-normal | a normal `setup.py` reading its own README |
| b05-npm-pure-lib | a pure library, no install hook |
| b06-npm-loopback | connects to `127.0.0.1` only (loopback must not be flagged) |

## Expected results

With Falco running: TP=6, FN=0, TN=6, FP=0. Without Falco, the two file-only
samples (m03, m04) cannot be seen and show as false negatives; the report sets
`sensor_alive_for_all: false` so this is never mistaken for a clean pass.
