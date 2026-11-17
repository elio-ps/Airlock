"""
airlock.pipeline
==================

Orchestrates the package analysis:

    ingestion -> SBOM -> Trivy -> GuardDog -> deps.dev -> detonation -> verdict

Usage:
    python3 -m airlock.pipeline pypi requests --version 2.31.0
    python3 -m airlock.pipeline npm left-pad
    python3 -m airlock.pipeline npm some-package --skip trivy,depsdev
    python3 -m airlock.pipeline npm --local ./my-package-1.0.0.tgz --skip trivy

Each stage is isolated: when a stage fails (typically on the network) the next
ones still run, and it is marked "unavailable" in the final verdict (see
airlock.verdict.aggregate).
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from airlock.analysis import depsdev, guarddog_scan, trivy_scan
from airlock.detonation import sandbox
from airlock.ingest.fetch import (
    FetchedPackage, FetchError, fetch_local, fetch_package, safe_slug,
)
from airlock.sbom.generate import declared_dependencies, generate_sbom_file
from airlock.verdict.aggregate import Policy, aggregate

WORKDIR_ROOT = Path("./airlock_runs")

# Exit codes, so that a CI job or a shell script can act on the verdict.
EXIT_CODES = {"allow": 0, "quarantine": 2, "block": 3}
EXIT_ERROR = 1


def run_pipeline(
    ecosystem: str,
    name: str | None = None,
    version: str | None = None,
    skip: set[str] | None = None,
    policy: Policy | None = None,
    verbose: bool = True,
    trivy_timeout: int = 120,
    local_archive: Path | None = None,
) -> dict:
    """Run every stage on one package and return the full report (also saved to disk)."""
    skip = set(skip or ())

    def log(msg: str) -> None:
        if verbose:
            print(f"[airlock] {msg}", file=sys.stderr)

    # The downloaded archive and its extracted files are deleted at the end.
    with tempfile.TemporaryDirectory(prefix="airlock-") as tmp:
        try:
            pkg = _ingest(ecosystem, name, version, local_archive, Path(tmp), log)
        except FetchError as e:
            log(f"Ingestion FAILED: {e}")
            return {"error": f"ingestion failed: {e}"}

        if pkg.origin == "local" and "depsdev" not in skip:
            skip.add("depsdev")
            log("  -> local package: deps.dev stage skipped (no registry to query)")

        run_dir = WORKDIR_ROOT / f"{pkg.ecosystem}-{safe_slug(pkg.name)}-{safe_slug(pkg.version)}"
        run_dir.mkdir(parents=True, exist_ok=True)

        sbom_path, sbom_error, unresolved = None, None, 0
        if "sbom" not in skip:
            sbom_path, sbom_error, unresolved = _run_sbom(pkg, run_dir, skip, log)
        # Trivy reads the SBOM: without one it has nothing to scan.
        trivy_result = None
        if "trivy" not in skip and sbom_path is not None:
            trivy_result = _run_trivy(sbom_path, trivy_timeout, log)
        guarddog_result = _run_guarddog(pkg, log) if "guarddog" not in skip else None
        depsdev_result = _run_depsdev(pkg, log) if "depsdev" not in skip else None
        detonation_result = _run_detonation(pkg, log) if "detonation" not in skip else None

        log("Aggregating the verdict...")
        verdict = aggregate(
            package_name=pkg.name, version=pkg.version, ecosystem=pkg.ecosystem,
            trivy_result=trivy_result, guarddog_result=guarddog_result,
            depsdev_result=depsdev_result, detonation_result=detonation_result,
            sbom_path=sbom_path, sbom_error=sbom_error, policy=policy,
            skipped=skip, install_hooks=pkg.install_hooks,
            unresolved_dependencies=unresolved,
        )
        log(f"  -> VERDICT: {verdict.verdict.value.upper()}")

        report = {
            "package": pkg.to_dict(),
            "verdict": verdict.to_dict(),
            "details": {
                "trivy": trivy_result.to_dict() if trivy_result else None,
                "guarddog": guarddog_result.to_dict() if guarddog_result else None,
                "depsdev": depsdev_result.to_dict() if depsdev_result else None,
                "detonation": detonation_result.to_dict() if detonation_result else None,
            },
        }
        # Kept after the run, for the corpus and for audit.
        report_path = run_dir / "report.json"
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        log(f"Full report: {report_path}")
        return report


# --- One function per stage -------------------------------------------------
# Each one logs what it does and returns the stage result. None of them raises
# on a scanner failure: the result says "scan_failed" instead.

def _ingest(ecosystem, name, version, local_archive, workdir, log) -> FetchedPackage:
    if local_archive is not None:
        log(f"Ingesting local archive {local_archive} ({ecosystem})...")
        pkg = fetch_local(ecosystem, local_archive, workdir=workdir)
    elif not name:
        raise FetchError("missing package name (or --local required)")
    else:
        log(f"Ingesting {ecosystem}:{name}{'@' + version if version else ''}...")
        pkg = fetch_package(ecosystem, name, version, workdir=workdir)
    log(f"  -> {pkg.name}@{pkg.version} fetched, sha256={pkg.sha256[:12]}...")
    return pkg


def _run_sbom(pkg, run_dir, skip, log) -> tuple[Path | None, str | None, int]:
    """
    Return (SBOM path, None, unresolved) on success, (None, error, 0) on failure.
    `unresolved` counts declared dependencies without an exact version: Trivy
    cannot match them against CVEs, so its silence about them means nothing.
    """
    log("Generating the CycloneDX SBOM...")
    resolved = None
    if pkg.origin == "registry" and "depsdev" not in skip:
        resolved = depsdev.resolved_dependencies(pkg.ecosystem, pkg.name, pkg.version)
    try:
        unresolved = 0 if resolved is not None else len(declared_dependencies(pkg))
        sbom_path = generate_sbom_file(pkg, run_dir / "sbom", resolved)
    except Exception as e:  # untrusted metadata must not crash the whole pipeline
        error = f"{type(e).__name__}: {e}"
        log(f"  -> unavailable: {error[:150]}")
        return None, error, 0
    if unresolved:
        log(f"  -> dependency graph unavailable: {unresolved} declared dependenc(y/ies) "
            "without an exact version, invisible to the CVE scan")
    log(f"  -> {sbom_path}")
    return sbom_path, None, unresolved


def _run_trivy(sbom_path, timeout, log):
    log("Trivy scan (CVEs)...")
    result = trivy_scan.scan_sbom(sbom_path, timeout=timeout)
    if result.scan_failed:
        log(f"  -> unavailable: {result.error_message[:150]}")
    else:
        log(f"  -> {len(result.findings)} CVE(s) found")
    return result


def _run_guarddog(pkg, log):
    log("GuardDog scan (behaviour)...")
    # Always the ingested bytes: a second download could return something else.
    result = guarddog_scan.scan_local(
        pkg.ecosystem, pkg.source_root, pkg.name, pkg.version, info=pkg.registry_package_info,
    )
    if result.scan_failed:
        log(f"  -> unavailable: {result.error_message[:150]}")
    else:
        log(f"  -> {result.issue_count} signal(s), {len(result.threat_findings)} threat")
    return result


def _run_depsdev(pkg, log):
    log("deps.dev query (reputation)...")
    result = depsdev.query_package(pkg.ecosystem, pkg.name, pkg.version)
    if result.scan_failed:
        log(f"  -> unavailable: {result.error_message[:150]}")
    else:
        log(f"  -> Scorecard={result.scorecard_score}")
    return result


def _run_detonation(pkg, log):
    log("Detonation in the sandbox (behaviour)...")
    result = sandbox.detonate(pkg.archive_path, pkg.ecosystem)
    if result.scan_failed:
        log(f"  -> unavailable: {result.error_message[:150]}")
    if result.incomplete_phases:
        log(f"  -> install incomplete: {', '.join(result.incomplete_phases)}")
    log(f"  -> {len(result.findings)} behaviour(s) observed in {result.duration_seconds}s")
    return result


class _ArgumentParser(argparse.ArgumentParser):
    """argparse exits with 2 on a usage error, which is the QUARANTINE code here."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def main() -> None:
    parser = _ArgumentParser(description="Airlock package analysis pipeline")
    parser.add_argument("ecosystem", choices=["npm", "pypi"])
    parser.add_argument("name", nargs="?", default=None,
                         help="package name (omitted with --local)")
    parser.add_argument("--version", default=None)
    parser.add_argument("--local", type=Path, default=None, metavar="ARCHIVE",
                         help="analyse a local archive (.tgz from `npm pack "
                              "--ignore-scripts`) instead of downloading a package; npm only")
    parser.add_argument("--skip", default="", help="comma-separated stages to skip "
                                                     "(sbom,trivy,guarddog,depsdev,detonation)")
    parser.add_argument("--policy", type=Path, default=None, help="custom JSON policy file")
    parser.add_argument("--trivy-timeout", type=int, default=120,
                         help="Trivy timeout in seconds (default 120; raise it for the "
                              "first scan while the DB downloads, e.g. 300)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    if args.local is None and not args.name:
        parser.error("give a package name, or an archive with --local")
    if args.local is not None and args.name:
        parser.error("--local and a package name are mutually exclusive")

    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    try:
        policy = Policy.from_file(args.policy) if args.policy else None
    except ValueError as e:
        parser.error(str(e))

    report = run_pipeline(
        args.ecosystem, args.name, args.version,
        skip=skip, policy=policy, verbose=not args.quiet,
        trivy_timeout=args.trivy_timeout, local_archive=args.local,
    )
    print(json.dumps(report.get("verdict", report), indent=2, ensure_ascii=False))
    sys.exit(EXIT_CODES[report["verdict"]["verdict"]] if "verdict" in report else EXIT_ERROR)


if __name__ == "__main__":
    main()
