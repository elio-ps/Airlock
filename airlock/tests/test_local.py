"""
Tests for LOCAL ingestion (`--local`) and the postinstall fixtures.

No registry calls: .tgz archives are built on the fly from `fixtures/` with the
same layout as `npm pack` (everything under `package/`), so neither npm nor
Node is needed.

Run: python3 -m pytest airlock/tests/test_local.py -v
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from airlock import pipeline
from airlock.analysis import guarddog_scan
from airlock.ingest.fetch import FetchError, fetch_local
from airlock.sbom.generate import build_sbom, sbom_to_json
from airlock.verdict.aggregate import Verdict

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def _pack(fixture: str, dest_dir: Path) -> Path:
    """Equivalent of `npm pack --ignore-scripts`: archive with a `package/` prefix."""
    src = FIXTURES / fixture
    assert src.is_dir(), f"missing fixture: {src}"
    name = {
        "clean-pkg": "airlock-test-clean",
        "hook-benign": "airlock-test-hook-benign",
        "hook-evil-sim": "airlock-test-evil-sim",
    }[fixture]
    out = dest_dir / f"{name}-1.0.0.tgz"
    with tarfile.open(out, "w:gz") as tar:
        for path in sorted(src.rglob("*")):
            if path.is_file():
                tar.add(path, arcname=f"package/{path.relative_to(src).as_posix()}")
    return out


# ---------------------------------------------------------------------------
# Local ingestion
# ---------------------------------------------------------------------------

def test_fetch_local_reads_name_and_version(tmp_path):
    pkg = fetch_local("npm", _pack("hook-evil-sim", tmp_path), workdir=tmp_path / "w")
    assert pkg.name == "airlock-test-evil-sim"
    assert pkg.version == "1.0.0"
    assert pkg.origin == "local"
    assert len(pkg.sha256) == 64
    assert (pkg.source_root / "scripts" / "postinstall.js").is_file()


def test_fetch_local_sbom_needs_no_network(tmp_path):
    pkg = fetch_local("npm", _pack("clean-pkg", tmp_path), workdir=tmp_path / "w")
    assert "pkg:npm/airlock-test-clean@1.0.0" in sbom_to_json(build_sbom(pkg))


def test_fetch_local_missing_archive_raises(tmp_path):
    with pytest.raises(FetchError):
        fetch_local("npm", tmp_path / "does-not-exist.tgz")


def test_fetch_local_rejects_pypi(tmp_path):
    with pytest.raises(FetchError):
        fetch_local("pypi", _pack("clean-pkg", tmp_path))


def test_fetch_local_blocks_path_traversal(tmp_path):
    evil = tmp_path / "evil-1.0.0.tgz"
    with tarfile.open(evil, "w:gz") as tar:
        data = b"x"
        info = tarfile.TarInfo(name="package/../../escaped.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with pytest.raises(FetchError):
        fetch_local("npm", evil, workdir=tmp_path / "w")
    assert not (tmp_path / "escaped.txt").exists()


# ---------------------------------------------------------------------------
# Local GuardDog ("sourcecode" rules only, no network needed)
# ---------------------------------------------------------------------------

def test_guarddog_local_clean_package_has_no_findings(tmp_path):
    pkg = fetch_local("npm", _pack("clean-pkg", tmp_path), workdir=tmp_path / "w")
    result = guarddog_scan.scan_local(pkg.ecosystem, pkg.source_root, pkg.name, pkg.version)
    assert not result.scan_failed
    assert result.findings == []


def test_guarddog_local_evil_sim_raises_capability_signals(tmp_path):
    """GuardDog sees the simulated postinstall (network + spawn), at least as capability."""
    pkg = fetch_local("npm", _pack("hook-evil-sim", tmp_path), workdir=tmp_path / "w")
    result = guarddog_scan.scan_local(pkg.ecosystem, pkg.source_root, pkg.name, pkg.version)
    assert not result.scan_failed
    rules = {f.rule_name for f in result.findings}
    assert "capability-process-spawn" in rules
    assert rules & {"capability-network-outbound", "capability-network-download"}


# ---------------------------------------------------------------------------
# End-to-end pipeline on fixtures (Trivy and deps.dev skipped)
# ---------------------------------------------------------------------------

def _run(fixture: str, tmp_path, monkeypatch) -> Verdict:
    monkeypatch.setattr(pipeline, "WORKDIR_ROOT", tmp_path / "runs")
    report = pipeline.run_pipeline(
        "npm", skip={"trivy"}, verbose=False,
        local_archive=_pack(fixture, tmp_path),
    )
    return Verdict(report["verdict"]["verdict"])


def test_pipeline_local_clean_is_allowed(tmp_path, monkeypatch):
    assert _run("clean-pkg", tmp_path, monkeypatch) == Verdict.ALLOW


def test_pipeline_local_benign_hook_is_allowed(tmp_path, monkeypatch):
    assert _run("hook-benign", tmp_path, monkeypatch) == Verdict.ALLOW


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known gap: the simulated postinstall only triggers capability-* rules, "
        "ignored by the aggregation. Remove this marker once the "
        "'capability in an install hook' rule is added."
    ),
)
def test_pipeline_local_evil_postinstall_should_not_be_allowed(tmp_path, monkeypatch):
    assert _run("hook-evil-sim", tmp_path, monkeypatch) != Verdict.ALLOW
