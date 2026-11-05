"""
Unit tests. Tests marked `network` make real calls to the npm and PyPI
registries on purpose: they test real integration rather than mocks.

Run: python3 -m pytest airlock/tests/ -v
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from airlock.ingest.fetch import FetchError, fetch_package
from airlock.sbom.generate import build_sbom, sbom_to_json
from airlock.verdict.aggregate import (
    Policy,
    StageStatus,
    Verdict,
    aggregate,
)


# ---------------------------------------------------------------------------
# Ingestion (real network, public registries)
# ---------------------------------------------------------------------------

@pytest.mark.network
def test_fetch_pypi_known_package():
    pkg = fetch_package("pypi", "requests", "2.31.0")
    assert pkg.name == "requests"
    assert pkg.version == "2.31.0"
    assert pkg.extract_path.exists()
    assert len(pkg.sha256) == 64
    shutil.rmtree(pkg.extract_path.parent, ignore_errors=True)


@pytest.mark.network
def test_fetch_npm_known_package():
    pkg = fetch_package("npm", "left-pad", "1.3.0")
    assert pkg.name == "left-pad"
    assert pkg.version == "1.3.0"
    assert pkg.extract_path.exists()
    shutil.rmtree(pkg.extract_path.parent, ignore_errors=True)


@pytest.mark.network
def test_fetch_nonexistent_package_raises():
    with pytest.raises(FetchError):
        fetch_package("pypi", "this-package-really-does-not-exist-xyz123", None)


# ---------------------------------------------------------------------------
# SBOM (needs network ingestion, but tests the generation logic)
# ---------------------------------------------------------------------------

@pytest.mark.network
def test_sbom_captures_declared_dependencies():
    pkg = fetch_package("pypi", "requests", "2.31.0")
    bom = build_sbom(pkg)
    json_str = sbom_to_json(bom)

    assert "charset-normalizer" in json_str
    assert "idna" in json_str
    assert "pkg:pypi/requests@2.31.0" in json_str
    shutil.rmtree(pkg.extract_path.parent, ignore_errors=True)


# ---------------------------------------------------------------------------
# Verdict aggregation, tested with test doubles (no network needed)
# ---------------------------------------------------------------------------

class _FakeTrivyResult:
    def __init__(self, findings, scan_failed=False, error_message=None):
        self.findings = findings
        self.scan_failed = scan_failed
        self.error_message = error_message


class _FakeFinding:
    def __init__(self, vuln_id, pkg_name, severity):
        self.vuln_id = vuln_id
        self.pkg_name = pkg_name
        self.severity = severity


class _FakeGuardDogResult:
    def __init__(self, threat_findings, issue_count=0, scan_failed=False, error_message=None):
        self.threat_findings = threat_findings
        self.issue_count = issue_count
        self.scan_failed = scan_failed
        self.error_message = error_message


class _FakeDepsDevResult:
    def __init__(self, scorecard_score, dependent_count, scan_failed=False, error_message=None):
        self.scorecard_score = scorecard_score
        self.dependent_count = dependent_count
        self.scan_failed = scan_failed
        self.error_message = error_message


def test_aggregate_allow_when_all_clean():
    verdict = aggregate(
        package_name="clean-pkg", version="1.0.0", ecosystem="pypi",
        trivy_result=_FakeTrivyResult([]),
        guarddog_result=_FakeGuardDogResult([], issue_count=0),
        depsdev_result=_FakeDepsDevResult(scorecard_score=8.5, dependent_count=500),
    )
    assert verdict.verdict == Verdict.ALLOW
    assert all(s.status != StageStatus.UNAVAILABLE for s in verdict.stages if s.name != "sbom")


def test_aggregate_block_on_guarddog_threat():
    threat = type("F", (), {"rule_name": "threat-network-exfiltration"})()
    verdict = aggregate(
        package_name="evil-pkg", version="1.0.0", ecosystem="npm",
        trivy_result=_FakeTrivyResult([]),
        guarddog_result=_FakeGuardDogResult([threat], issue_count=1),
        depsdev_result=_FakeDepsDevResult(scorecard_score=7.0, dependent_count=10),
    )
    assert verdict.verdict == Verdict.BLOCK
    assert any("threat-network-exfiltration" in r for r in verdict.reasons)


def test_aggregate_quarantine_on_critical_cve():
    cve = _FakeFinding("CVE-2024-0001", "some-dep", "CRITICAL")
    verdict = aggregate(
        package_name="vuln-pkg", version="1.0.0", ecosystem="pypi",
        trivy_result=_FakeTrivyResult([cve]),
        guarddog_result=_FakeGuardDogResult([], issue_count=0),
        depsdev_result=_FakeDepsDevResult(scorecard_score=7.0, dependent_count=10),
    )
    assert verdict.verdict == Verdict.QUARANTINE


def test_aggregate_quarantine_on_low_scorecard_low_usage():
    verdict = aggregate(
        package_name="obscure-pkg", version="0.0.1", ecosystem="npm",
        trivy_result=_FakeTrivyResult([]),
        guarddog_result=_FakeGuardDogResult([], issue_count=0),
        depsdev_result=_FakeDepsDevResult(scorecard_score=1.5, dependent_count=2),
    )
    assert verdict.verdict == Verdict.QUARANTINE


def test_aggregate_does_not_quarantine_low_scorecard_if_widely_used():
    # a low score on a widely used package is a different signal:
    # do not block it blindly (see the comment in Policy)
    verdict = aggregate(
        package_name="widely-used-pkg", version="1.0.0", ecosystem="npm",
        trivy_result=_FakeTrivyResult([]),
        guarddog_result=_FakeGuardDogResult([], issue_count=0),
        depsdev_result=_FakeDepsDevResult(scorecard_score=1.5, dependent_count=50_000),
    )
    assert verdict.verdict == Verdict.ALLOW


def test_aggregate_marks_unavailable_stage_distinctly():
    verdict = aggregate(
        package_name="pkg", version="1.0.0", ecosystem="pypi",
        trivy_result=_FakeTrivyResult([], scan_failed=True, error_message="DB unavailable"),
        guarddog_result=_FakeGuardDogResult([], issue_count=0),
        depsdev_result=None,
    )
    stage_by_name = {s.name: s for s in verdict.stages}
    assert stage_by_name["trivy"].status == StageStatus.UNAVAILABLE
    assert stage_by_name["deps.dev"].status == StageStatus.UNAVAILABLE
    # an unavailable signal must never trigger a block on its own
    assert verdict.verdict == Verdict.ALLOW


def test_verdict_never_downgrades():
    """The verdict can only get worse across stages, never better."""
    threat = type("F", (), {"rule_name": "threat-x"})()
    cve = _FakeFinding("CVE-1", "dep", "CRITICAL")
    verdict = aggregate(
        package_name="pkg", version="1.0.0", ecosystem="npm",
        trivy_result=_FakeTrivyResult([cve]),          # -> QUARANTINE
        guarddog_result=_FakeGuardDogResult([threat]),  # -> BLOCK (must win)
        depsdev_result=_FakeDepsDevResult(scorecard_score=9.0, dependent_count=1000),  # -> ALLOW, must change nothing
    )
    assert verdict.verdict == Verdict.BLOCK


def test_policy_thresholds_are_configurable():
    strict_policy = Policy(quarantine_on_scorecard_below=9.0, quarantine_on_scorecard_below_dependents=999_999)
    verdict = aggregate(
        package_name="pkg", version="1.0.0", ecosystem="pypi",
        depsdev_result=_FakeDepsDevResult(scorecard_score=8.5, dependent_count=100),
        policy=strict_policy,
    )
    assert verdict.verdict == Verdict.QUARANTINE  # 8.5 < 9.0 under the strict policy
