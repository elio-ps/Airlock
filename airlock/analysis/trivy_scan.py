"""
airlock.analysis.trivy_scan
=============================

Exécute Trivy sur le SBOM CycloneDX généré à l'étage précédent pour
détecter des vulnérabilités connues (CVE) dans le paquet et ses
dépendances déclarées.

IMPORTANT — dépendance réseau externe :
Trivy télécharge sa base de vulnérabilités depuis un registre OCI
(par défaut `mirror.gcr.io/aquasec/trivy-db`, avec `ghcr.io` en repli).
Ces deux domaines doivent être joignables au moment de l'exécution.
Dans un environnement réseau restreint (proxy d'entreprise, sandbox CI),
il faut soit whitelister ces domaines, soit pré-télécharger la DB une
fois (`trivy image --download-db-only`) et la monter/cacher localement
via `--cache-dir`, ce que ce module supporte via `cache_dir`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


class TrivyNotFoundError(Exception):
    """Le binaire trivy n'est pas trouvable dans le PATH."""


class TrivyScanError(Exception):
    """Erreur lors de l'exécution de trivy."""


@dataclass
class TrivyFinding:
    vuln_id: str          # ex. CVE-2023-32681
    pkg_name: str
    installed_version: str
    fixed_version: str | None
    severity: str          # LOW / MEDIUM / HIGH / CRITICAL
    title: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "vuln_id": self.vuln_id,
            "pkg_name": self.pkg_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "severity": self.severity,
            "title": self.title,
            "references": self.references,
        }


@dataclass
class TrivyResult:
    sbom_path: Path
    findings: list[TrivyFinding]
    raw_output: dict
    scan_failed: bool = False
    error_message: str | None = None

    @property
    def max_severity(self) -> str | None:
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: order.index(s) if s in order else -1)

    def to_dict(self) -> dict:
        return {
            "sbom_path": str(self.sbom_path),
            "scan_failed": self.scan_failed,
            "error_message": self.error_message,
            "max_severity": self.max_severity,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def _find_trivy_binary() -> str:
    binary = shutil.which("trivy")
    if binary is None:
        raise TrivyNotFoundError(
            "Le binaire 'trivy' est introuvable dans le PATH. "
            "Installez-le : https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        )
    return binary


def scan_sbom(sbom_path: Path, cache_dir: Path | None = None, timeout: int = 120) -> TrivyResult:
    """
    Lance `trivy sbom <fichier>` en sortie JSON et parse les vulnérabilités trouvées.

    En cas d'échec réseau (DB inaccessible) ou d'erreur trivy, on ne lève pas
    d'exception fatale : on retourne un TrivyResult avec scan_failed=True et
    le message d'erreur, pour que le pipeline puisse continuer et marquer ce
    signal comme "indisponible" plutôt que de bloquer tout le verdict.
    """
    binary = _find_trivy_binary()

    cmd = [binary, "sbom", str(sbom_path), "--format", "json", "--quiet"]
    if cache_dir is not None:
        cmd += ["--cache-dir", str(cache_dir)]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as e:
        return TrivyResult(
            sbom_path=sbom_path, findings=[], raw_output={},
            scan_failed=True, error_message=f"Timeout Trivy après {timeout}s : {e}",
        )

    if proc.returncode != 0:
        return TrivyResult(
            sbom_path=sbom_path, findings=[], raw_output={},
            scan_failed=True,
            error_message=proc.stderr.strip()[-2000:] or "trivy a échoué sans message d'erreur",
        )

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return TrivyResult(
            sbom_path=sbom_path, findings=[], raw_output={},
            scan_failed=True, error_message="Sortie trivy non-JSON, parsing impossible",
        )

    findings: list[TrivyFinding] = []
    for result in data.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(
                TrivyFinding(
                    vuln_id=vuln.get("VulnerabilityID", "UNKNOWN"),
                    pkg_name=vuln.get("PkgName", "unknown"),
                    installed_version=vuln.get("InstalledVersion", "unknown"),
                    fixed_version=vuln.get("FixedVersion"),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    title=vuln.get("Title", vuln.get("Description", ""))[:200],
                    references=vuln.get("References", [])[:5],
                )
            )

    return TrivyResult(sbom_path=sbom_path, findings=findings, raw_output=data)


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Scan de vulnérabilités Trivy sur un SBOM CycloneDX")
    parser.add_argument("sbom_path", type=Path)
    parser.add_argument("--cache-dir", type=Path, default=None)
    args = parser.parse_args()

    try:
        result = scan_sbom(args.sbom_path, cache_dir=args.cache_dir)
    except TrivyNotFoundError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    if result.scan_failed:
        sys.exit(2)
