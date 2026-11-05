# Reference corpus: provenance

This corpus (10 malicious + 10 benign samples) was not written for this project:
it is taken unchanged from the **official GuardDog unit test fixtures**
(DataDog), published at https://github.com/DataDog/guarddog under the
**Apache 2.0** license (see `THIRD_PARTY_LICENSE_guarddog_Apache2.0.txt`).

## Why this choice rather than writing our own samples?

1. **Verifiable, documented provenance**: each sample matches a real case seen
   by security researchers (network exfiltration, base64 obfuscation, DLL
   hijacking, silent process execution...), not a student's guess at what
   malware looks like.
2. **An adversarial corpus**: GuardDog's `benign/` directory deliberately holds
   snippets that *look like* the malicious ones (same lexical patterns: hardcoded
   IP, network calls, process reads) but are semantically safe (e.g. loopback or
   private addresses rather than an exfiltration server).
3. **Reproducibility**: anyone can download the same files from the official
   repository and check our results.

## Composition

### `malicious/` (10 files, must trigger at least one GuardDog `threat-*` rule)

| # | File | Expected behaviour |
|---|------|--------------------|
| 01 | threat-network-exfiltration.py | Sends data to a hardcoded public IP |
| 02 | exec-base64.py | Runs code decoded from base64 |
| 03 | threat-process-download-exec.py | Downloads then runs a binary |
| 04 | threat-runtime-obfuscation-base64exec.py | Execution obfuscated with base64 |
| 05 | exfiltrate-sensitive-data.py | Exfiltrates sensitive data (env, credentials) |
| 06 | dll-hijacking.py | Hijacks DLL loading |
| 07 | code-execution.py | Arbitrary code execution |
| 08 | threat-filesystem-autostart.py | Persistence through autostart |
| 09 | silent-process-execution.py | Launches a silent, windowless process |
| 10 | npm-exfiltrate-sensitive-data.js | Exfiltrates sensitive data (npm equivalent) |

### `benign/` (10 files, must trigger NO `threat-*` rule)

| # | File | Why it is safe despite appearances |
|---|------|------------------------------------|
| 01 | threat-network-exfiltration.py | Loopback/private (RFC 1918) targets, no real exfiltration |
| 02 | threat-process-download-exec.js | Download without execution, or a safe context |
| 03 | threat-runtime-obfuscation-base64exec.py | Legitimate base64 use (no `exec` on the result) |
| 04 | threat-filesystem-autostart.py | Config files outside persistence paths |
| 05 | threat-process-sysinfo.py | Reads system information for plain diagnostics |
| 06 | capability-network-lolbas.py | Uses a system binary with no evasion intent |
| 07 | capability-filesystem-browser.py | File browsing without sensitive reads |
| 08 | threat-process-cryptomining.py | Heavy computation unrelated to mining |
| 09 | threat-runtime-keylogging.py | Keyboard capture in a legitimate context (e.g. accessibility) |
| 10 | threat-runtime-dynamic-loader.py | Dynamic loading of a standard module, no hidden payload |

## Accepted limit

This corpus tests **static pattern detection** (GuardDog source code analyzer).
It does not replace the dynamic detonation corpus, a separate deliverable
focused on runtime behaviour rather than source code.
