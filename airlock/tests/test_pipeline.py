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

from airlock.analysis import depsdev
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


@pytest.mark.network
def test_depsdev_returns_a_real_scorecard():
    """Regression: unencoded project keys made this silently return nothing."""
    result = depsdev.query_package("pypi", "requests", "2.31.0")
    assert not result.scan_failed
    assert result.scorecard_score is not None
    assert result.dependent_count and result.dependent_count > 50
    assert all(a.startswith(("GHSA-", "PYSEC-")) for a in result.default_branch_advisories)


@pytest.mark.network
def test_depsdev_handles_scoped_npm_packages():
    assert not depsdev.query_package("npm", "@babel/core", "7.24.0").scan_failed


@pytest.mark.network
def test_depsdev_flags_unknown_package_distinctly():
    result = depsdev.query_package("npm", "this-package-really-does-not-exist-xyz123", "1.0.0")
    assert result.package_unknown and not result.scan_failed


@pytest.mark.network
def test_sbom_with_resolved_graph_is_visible_to_cve_scanners():
    """Regression: components without a purl were invisible to Trivy."""
    pkg = fetch_package("npm", "express", "4.18.2")
    resolved = depsdev.resolved_dependencies("npm", "express", "4.18.2")
    assert resolved and len(resolved) > 20
    assert "pkg:npm/accepts@" in sbom_to_json(build_sbom(pkg, resolved))
    shutil.rmtree(pkg.extract_path.parent, ignore_errors=True)


@pytest.mark.network
def test_fetch_scoped_npm_package():
    pkg = fetch_package("npm", "@babel/helper-string-parser", "7.24.1")
    assert "pkg:npm/%40babel/helper-string-parser@7.24.1" in sbom_to_json(build_sbom(pkg))
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
    package_unknown = False

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
        skipped={"detonation"},
    )
    assert verdict.verdict == Verdict.ALLOW
    assert all(s.status != StageStatus.UNAVAILABLE for s in verdict.stages)


def test_aggregate_quarantine_on_guarddog_threat():
    """A static pattern alone is not a proof: 6 of 18 popular packages trigger one."""
    threat = type("F", (), {"rule_name": "threat-network-exfiltration"})()
    verdict = aggregate(
        package_name="evil-pkg", version="1.0.0", ecosystem="npm",
        trivy_result=_FakeTrivyResult([]),
        guarddog_result=_FakeGuardDogResult([threat], issue_count=1),
        depsdev_result=_FakeDepsDevResult(scorecard_score=7.0, dependent_count=10),
    )
    assert verdict.verdict == Verdict.QUARANTINE
    assert any("threat-network-exfiltration" in r for r in verdict.reasons)


def test_policy_can_restore_blocking_on_static_threats():
    threat = type("F", (), {"rule_name": "threat-x"})()
    verdict = aggregate(
        package_name="pkg", version="1.0.0", ecosystem="npm",
        guarddog_result=_FakeGuardDogResult([threat]),
        policy=Policy(block_on_any_threat_rule=True),
    )
    assert verdict.verdict == Verdict.BLOCK


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


def test_fail_closed_policy_quarantines_on_unavailable_stage():
    verdict = aggregate(
        package_name="pkg", version="1.0.0", ecosystem="pypi",
        trivy_result=_FakeTrivyResult([], scan_failed=True, error_message="DB unavailable"),
        guarddog_result=_FakeGuardDogResult([]),
        depsdev_result=_FakeDepsDevResult(scorecard_score=9.0, dependent_count=500),
        policy=Policy(fail_closed=True),
    )
    assert verdict.verdict == Verdict.QUARANTINE


def test_fail_closed_policy_ignores_deliberately_skipped_stages():
    verdict = aggregate(
        package_name="pkg", version="1.0.0", ecosystem="npm",
        guarddog_result=_FakeGuardDogResult([]),
        policy=Policy(fail_closed=True), skipped={"trivy", "depsdev", "detonation"},
    )
    assert verdict.verdict == Verdict.ALLOW
    assert {s.name: s.status for s in verdict.stages}["trivy"] == StageStatus.SKIPPED


def test_unknown_package_is_quarantined():
    unknown = _FakeDepsDevResult(scorecard_score=None, dependent_count=None)
    unknown.package_unknown = True
    verdict = aggregate(package_name="new", version="0.0.1", ecosystem="npm", depsdev_result=unknown)
    assert verdict.verdict == Verdict.QUARANTINE


def test_verdict_never_downgrades():
    """The verdict can only get worse across stages, never better."""
    threat = type("F", (), {"rule_name": "threat-x"})()
    cve = _FakeFinding("CVE-1", "dep", "CRITICAL")
    verdict = aggregate(
        package_name="pkg", version="1.0.0", ecosystem="npm",
        trivy_result=_FakeTrivyResult([cve]),          # -> QUARANTINE
        guarddog_result=_FakeGuardDogResult([threat]),  # -> BLOCK under this policy (must win)
        depsdev_result=_FakeDepsDevResult(scorecard_score=9.0, dependent_count=1000),  # -> ALLOW, must change nothing
        policy=Policy(block_on_any_threat_rule=True),
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
