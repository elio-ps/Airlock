"""
airlock.analysis.guarddog_scan
================================

Runs GuardDog (https://github.com/DataDog/guarddog) on an npm or PyPI package.
GuardDog combines two rule families:

  - "metadata" rules:   typosquatting, suspicious author, repository/package
                        mismatch, etc. (need network access to the registry
                        and sometimes to third-party services)
  - "sourcecode" rules: pattern detection (Semgrep + heuristics) in the
                        package code: capabilities (`capability-*`, e.g.
                        network access, file write) and signatures of known
                        malicious behaviour (`threat-*`, e.g. reverse shell,
                        exfiltration, obfuscation).

The GuardDog Python API is used rather than wrapping its CLI in a subprocess:
it avoids text parsing and cleanly separates triggered rules from rules that
do not apply.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Ecosystem = Literal["npm", "pypi"]

# Rules whose trigger is a strong signal of malicious behaviour, as opposed to
# "capability-*" rules, which describe what the code can do (often legitimate)
# rather than suspicious behaviour in itself.
THREAT_PREFIX = "threat-"
CAPABILITY_PREFIX = "capability-"


class GuardDogError(Exception):
    """Error while running GuardDog."""


@dataclass
class GuardDogFinding:
    rule_name: str
    category: str  # "threat" | "capability" | "metadata"
    matches: list | dict  # raw content returned by the rule (depends on the rule type)

    def to_dict(self) -> dict:
        return {"rule_name": self.rule_name, "category": self.category, "matches": self.matches}


@dataclass
class GuardDogResult:
    package_name: str
    version: str | None
    ecosystem: Ecosystem
    issue_count: int
    findings: list[GuardDogFinding]
    rule_errors: dict[str, str]  # rules that could not run (often: third-party network access unavailable)
    scan_failed: bool = False
    error_message: str | None = None

    @property
    def threat_findings(self) -> list[GuardDogFinding]:
        return [f for f in self.findings if f.category == "threat"]

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "issue_count": self.issue_count,
            "finding_count": len(self.findings),
            "threat_finding_count": len(self.threat_findings),
            "findings": [f.to_dict() for f in self.findings],
            "rule_errors": self.rule_errors,
            "scan_failed": self.scan_failed,
            "error_message": self.error_message,
        }


def _categorize(rule_name: str) -> str:
    if rule_name.startswith(THREAT_PREFIX):
        return "threat"
    if rule_name.startswith(CAPABILITY_PREFIX):
        return "capability"
    return "metadata"


def _rule_triggered(value) -> bool:
    """
    GuardDog encodes 'rule not triggered' differently depending on the rule
    type: `None` for metadata rules, empty `{}` or `[]` for sourcecode rules
    with no occurrence. Anything else (non-empty list or dict) is a match.
    """
    if value is None:
        return False
    if isinstance(value, (list, dict)) and len(value) == 0:
        return False
    return True


def _get_scanner(ecosystem: Ecosystem):
    if ecosystem == "pypi":
        from guarddog.scanners.pypi_package_scanner import PypiPackageScanner
        return PypiPackageScanner()
    if ecosystem == "npm":
        from guarddog.scanners.npm_package_scanner import NPMPackageScanner
        return NPMPackageScanner()
    raise ValueError(f"Ecosystem not supported by GuardDog: {ecosystem}")


def scan_package(ecosystem: Ecosystem, name: str, version: str | None = None) -> GuardDogResult:
    """
    Run GuardDog on a remote package (GuardDog downloads it itself into a
    temporary directory that it cleans up).
    """
    try:
        raw = _get_scanner(ecosystem).scan_remote(name, version=version)
    except Exception as e:  # GuardDog can raise many exception types (network, parsing...)
        return GuardDogResult(
            package_name=name, version=version, ecosystem=ecosystem,
            issue_count=0, findings=[], rule_errors={},
            scan_failed=True, error_message=str(e),
        )
    return _build_result(raw, ecosystem, name, version)


def scan_local(ecosystem: Ecosystem, path: Path, name: str | None = None,
                version: str | None = None) -> GuardDogResult:
    """
    Run GuardDog on an ALREADY extracted directory (no download).

    Only "sourcecode" rules apply: "metadata" rules (typosquatting, suspicious
    author...) need registry metadata and do not run in local mode.
    """
    label = name or Path(path).name
    try:
        raw = _get_scanner(ecosystem).scan_local(str(path))
    except Exception as e:
        return GuardDogResult(
            package_name=label, version=version, ecosystem=ecosystem,
            issue_count=0, findings=[], rule_errors={},
            scan_failed=True, error_message=str(e),
        )
    return _build_result(raw, ecosystem, label, version)


def _build_result(raw: dict, ecosystem: Ecosystem, name: str, version: str | None) -> GuardDogResult:
    results = raw.get("results", {})
    findings = [
        GuardDogFinding(rule_name=rule, category=_categorize(rule), matches=value)
        for rule, value in results.items()
        if _rule_triggered(value)
    ]

    return GuardDogResult(
        package_name=name,
        version=version,
        ecosystem=ecosystem,
        issue_count=raw.get("issues", len(findings)),
        findings=findings,
        rule_errors=raw.get("errors", {}),
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="GuardDog scan of an npm/PyPI package")
    parser.add_argument("ecosystem", choices=["npm", "pypi"])
    parser.add_argument("name")
    parser.add_argument("--version", default=None)
    args = parser.parse_args()

    result = scan_package(args.ecosystem, args.name, args.version)
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
