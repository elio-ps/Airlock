"""
airlock.corpus.run_popular
============================

Measures the false-positive rate of the static stage on popular, legitimate
packages: how many trigger at least one GuardDog `threat-*` rule. This is the
measurement behind ADR-0007 ("BLOCK needs dynamic proof"), kept as a script so
that the number can be re-checked rather than taken on trust.

Each package is ingested exactly as the pipeline does (registry download,
integrity check, safe extraction, sdist preferred), then scanned with GuardDog
source-code rules only. Nothing is executed.

Needs network access to npm, PyPI and the GuardDog rules. Output:
airlock/corpus/popular_eval_report.json.
"""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from airlock.analysis.guarddog_scan import scan_local
from airlock.ingest.fetch import FetchError, fetch_package

REPORT_PATH = Path(__file__).parent / "popular_eval_report.json"

# The 18 packages of ADR-0007, at the versions measured then when one is given.
POPULAR = [
    ("pypi", "requests", "2.31.0"),
    ("pypi", "flask", "3.0.3"),
    ("pypi", "django", "5.0.6"),
    ("pypi", "pyyaml", "6.0.1"),
    ("pypi", "boto3", None),
    ("pypi", "pytest", None),
    ("pypi", "cryptography", None),
    ("pypi", "pillow", "10.3.0"),
    ("npm", "express", None),
    ("npm", "lodash", None),
    ("npm", "axios", None),
    ("npm", "react", None),
    ("npm", "esbuild", None),
    ("npm", "core-js", None),
    ("npm", "typescript", None),
    ("npm", "webpack", "5.91.0"),
    ("npm", "sharp", None),
    ("npm", "husky", None),
]


def measure(ecosystem: str, name: str, version: str | None) -> dict:
    with tempfile.TemporaryDirectory(prefix="airlock-popular-") as tmp:
        try:
            pkg = fetch_package(ecosystem, name, version, workdir=Path(tmp))
        except FetchError as e:
            return {"ecosystem": ecosystem, "name": name, "version": version,
                    "status": "unavailable", "error": str(e)}
        # Source-code rules only: metadata rules need the registry document and
        # are not what ADR-0007 measured.
        result = scan_local(ecosystem, pkg.source_root, pkg.name, pkg.version)
    if result.scan_failed:
        return {"ecosystem": ecosystem, "name": name, "version": pkg.version,
                "status": "unavailable", "error": result.error_message}
    threats = sorted(f.rule_name for f in result.threat_findings)
    return {"ecosystem": ecosystem, "name": name, "version": pkg.version,
            "status": "flagged" if threats else "clean", "threat_rules": threats}


def run_popular_eval() -> dict:
    packages = []
    for ecosystem, name, version in POPULAR:
        print(f"[popular] {ecosystem}:{name}{'@' + version if version else ''}...", file=sys.stderr)
        packages.append(measure(ecosystem, name, version))
    measured = [p for p in packages if p["status"] != "unavailable"]
    flagged = [p for p in measured if p["status"] == "flagged"]
    return {
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "measured": len(measured),
        "flagged_by_a_threat_rule": len(flagged),
        "unavailable": len(packages) - len(measured),
        "packages": packages,
    }


if __name__ == "__main__":
    report = run_popular_eval()
    REPORT_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{report['flagged_by_a_threat_rule']} of {report['measured']} popular packages "
          f"trigger a threat-* rule ({report['unavailable']} unavailable). Report: {REPORT_PATH}")
