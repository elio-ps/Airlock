"""
airlock.pipeline
==================

Orchestrateur de l'étage "Passer un paquet npm/PyPI au crible" :

    ingestion -> SBOM -> Trivy -> GuardDog -> deps.dev -> verdict

Usage :
    python3 -m airlock.pipeline pypi requests --version 2.31.0
    python3 -m airlock.pipeline npm left-pad
    python3 -m airlock.pipeline npm some-package --skip trivy,depsdev
    python3 -m airlock.pipeline npm --local ./mon-paquet-1.0.0.tgz --skip trivy

Chaque étage est isolé : l'échec d'un étage (typiquement réseau) ne fait
pas planter les suivants, il est simplement marqué "unavailable" dans le
verdict final (voir airlock.verdict.aggregate).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from airlock.analysis import depsdev, guarddog_scan, trivy_scan
from airlock.ingest.fetch import FetchError, fetch_local, fetch_package
from airlock.sbom.generate import generate_sbom_file
from airlock.verdict.aggregate import Policy, aggregate

WORKDIR_ROOT = Path("./airlock_runs")


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
    skip = set(skip or set())

    def log(msg: str) -> None:
        if verbose:
            print(f"[airlock] {msg}", file=sys.stderr)

    # --- 1. Ingestion ---
    try:
        if local_archive is not None:
            log(f"Ingestion de l'archive locale {local_archive} ({ecosystem})...")
            pkg = fetch_local(ecosystem, local_archive)
            # Un paquet local n'existe sur aucun registre : deps.dev n'a rien à dire.
            if "depsdev" not in skip:
                skip.add("depsdev")
                log("  -> paquet local : étage deps.dev ignoré (aucun registre à interroger)")
        else:
            if not name:
                return {"error": "ingestion échouée : nom de paquet manquant (ou --local requis)"}
            log(f"Ingestion de {ecosystem}:{name}{'@' + version if version else ''}...")
            pkg = fetch_package(ecosystem, name, version)
    except FetchError as e:
        log(f"ÉCHEC ingestion : {e}")
        return {"error": f"ingestion échouée : {e}"}
    log(f"  -> {pkg.name}@{pkg.version} récupéré, sha256={pkg.sha256[:12]}...")

    run_dir = WORKDIR_ROOT / f"{pkg.ecosystem}-{pkg.name.replace('/', '__')}-{pkg.version}"
    run_dir.mkdir(parents=True, exist_ok=True)

    # --- 2. SBOM ---
    sbom_path = None
    if "sbom" not in skip:
        log("Génération du SBOM CycloneDX...")
        sbom_path = generate_sbom_file(pkg, run_dir / "sbom")
        log(f"  -> {sbom_path}")

    # --- 3. Trivy (nécessite le SBOM) ---
    trivy_result = None
    if "trivy" not in skip and sbom_path is not None:
        log("Scan Trivy (CVE)...")
        trivy_result = trivy_scan.scan_sbom(sbom_path, timeout=trivy_timeout)
        if trivy_result.scan_failed:
            log(f"  -> indisponible : {trivy_result.error_message[:150]}")
        else:
            log(f"  -> {len(trivy_result.findings)} CVE trouvée(s)")

    # --- 4. GuardDog ---
    guarddog_result = None
    if "guarddog" not in skip:
        log("Scan GuardDog (comportement)...")
        if pkg.origin == "local":
            guarddog_result = guarddog_scan.scan_local(
                pkg.ecosystem, pkg.source_root, pkg.name, pkg.version
            )
        else:
            guarddog_result = guarddog_scan.scan_package(pkg.ecosystem, pkg.name, pkg.version)
        if guarddog_result.scan_failed:
            log(f"  -> indisponible : {guarddog_result.error_message[:150]}")
        else:
            log(f"  -> {guarddog_result.issue_count} signal(aux), "
                f"{len(guarddog_result.threat_findings)} threat")

    # --- 5. deps.dev ---
    depsdev_result = None
    if "depsdev" not in skip:
        log("Requête deps.dev (réputation)...")
        depsdev_result = depsdev.query_package(pkg.ecosystem, pkg.name, pkg.version)
        if depsdev_result.scan_failed:
            log(f"  -> indisponible : {depsdev_result.error_message[:150]}")
        else:
            log(f"  -> Scorecard={depsdev_result.scorecard_score}")

    # --- 6. Verdict ---
    log("Agrégation du verdict...")
    verdict = aggregate(
        package_name=pkg.name, version=pkg.version, ecosystem=pkg.ecosystem,
        trivy_result=trivy_result, guarddog_result=guarddog_result,
        depsdev_result=depsdev_result, sbom_path=sbom_path, policy=policy,
    )
    log(f"  -> VERDICT : {verdict.verdict.value.upper()}")

    # persistance du rapport complet pour le corpus / audit
    report = {
        "package": pkg.to_dict(),
        "verdict": verdict.to_dict(),
        "details": {
            "trivy": trivy_result.to_dict() if trivy_result else None,
            "guarddog": guarddog_result.to_dict() if guarddog_result else None,
            "depsdev": depsdev_result.to_dict() if depsdev_result else None,
        },
    }
    report_path = run_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    log(f"Rapport complet : {report_path}")

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Airlock — étage 'paquet au crible'")
    parser.add_argument("ecosystem", choices=["npm", "pypi"])
    parser.add_argument("name", nargs="?", default=None,
                         help="nom du paquet (omis avec --local)")
    parser.add_argument("--version", default=None)
    parser.add_argument("--local", type=Path, default=None, metavar="ARCHIVE",
                         help="analyser une archive locale (.tgz issu de `npm pack "
                              "--ignore-scripts`) au lieu de télécharger un paquet ; npm uniquement")
    parser.add_argument("--skip", default="", help="étages à sauter, séparés par des virgules "
                                                     "(sbom,trivy,guarddog,depsdev)")
    parser.add_argument("--policy", type=Path, default=None, help="fichier JSON de policy custom")
    parser.add_argument("--trivy-timeout", type=int, default=120,
                         help="timeout Trivy en secondes (défaut 120 ; augmentez lors du "
                              "premier scan le temps du téléchargement de la DB, ex. 300)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    if args.local is None and not args.name:
        parser.error("indiquez un nom de paquet, ou une archive avec --local")
    if args.local is not None and args.name:
        parser.error("--local et un nom de paquet sont exclusifs")

    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    policy = Policy.from_file(args.policy) if args.policy else None

    report = run_pipeline(
        args.ecosystem, args.name, args.version,
        skip=skip, policy=policy, verbose=not args.quiet,
        trivy_timeout=args.trivy_timeout, local_archive=args.local,
    )
    print(json.dumps(report.get("verdict", report), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
