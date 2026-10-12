"""
Tests unitaires. Les tests marqués `network` font de vrais appels réseau
(registres npm/PyPI) — c'est volontaire pour cet étage du projet : on
teste l'intégration réelle plutôt que de tout mocker, cohérent avec la
philosophie "détonation sur de vrais paquets" du brief.

Lancer : python3 -m pytest airlock/tests/ -v
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
# Ingestion (réseau réel, registres publics)
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
        fetch_package("pypi", "ce-paquet-nexiste-vraiment-pas-xyz123", None)


# ---------------------------------------------------------------------------
# SBOM (dépend de l'ingestion réseau, mais teste la logique de génération)
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
# Agrégation de verdict — testée avec des doublures (pas de réseau nécessaire)
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
    # un score bas sur un paquet massivement dépendu est un signal différent :
    # on ne bloque pas aveuglément (cf. commentaire dans Policy)
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
        trivy_result=_FakeTrivyResult([], scan_failed=True, error_message="DB indisponible"),
        guarddog_result=_FakeGuardDogResult([], issue_count=0),
        depsdev_result=None,
    )
    stage_by_name = {s.name: s for s in verdict.stages}
    assert stage_by_name["trivy"].status == StageStatus.UNAVAILABLE
    assert stage_by_name["deps.dev"].status == StageStatus.UNAVAILABLE
    # un signal indisponible ne doit jamais, à lui seul, déclencher un blocage
    assert verdict.verdict == Verdict.ALLOW


def test_verdict_never_downgrades():
    """Le verdict ne peut qu'empirer au fil des étages, jamais s'améliorer."""
    threat = type("F", (), {"rule_name": "threat-x"})()
    cve = _FakeFinding("CVE-1", "dep", "CRITICAL")
    verdict = aggregate(
        package_name="pkg", version="1.0.0", ecosystem="npm",
        trivy_result=_FakeTrivyResult([cve]),          # -> QUARANTINE
        guarddog_result=_FakeGuardDogResult([threat]),  # -> BLOCK (doit l'emporter)
        depsdev_result=_FakeDepsDevResult(scorecard_score=9.0, dependent_count=1000),  # -> ALLOW, ne doit rien changer
    )
    assert verdict.verdict == Verdict.BLOCK


def test_policy_thresholds_are_configurable():
    strict_policy = Policy(quarantine_on_scorecard_below=9.0, quarantine_on_scorecard_below_dependents=999_999)
    verdict = aggregate(
        package_name="pkg", version="1.0.0", ecosystem="pypi",
        depsdev_result=_FakeDepsDevResult(scorecard_score=8.5, dependent_count=100),
        policy=strict_policy,
    )
    assert verdict.verdict == Verdict.QUARANTINE  # 8.5 < 9.0 sous la policy stricte
