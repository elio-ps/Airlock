"""
airlock.analysis.depsdev
==========================

Client pour l'API publique deps.dev (https://deps.dev), qui agrège pour
chaque paquet :
  - le score OpenSSF Scorecard (0-10) du dépôt source associé, avec le
    détail par critère (maintenance, revue de code, dépendances épinglées,
    présence de fuzzing, etc.) ;
  - des informations projet (dépôt, licence déclarée, nombre de
    dépendants directs/indirects dans l'écosystème) ;
  - les avisories de sécurité connues (recoupement avec OSV.dev).

C'est un signal de RÉPUTATION/HYGIÈNE, complémentaire à Trivy (CVE connues)
et GuardDog (comportement suspect dans le code) : un score Scorecard bas
n'est pas une preuve de malveillance, mais un paquet très mal noté (pas de
CI, un seul mainteneur, pas de revue de code, aucun dépendant) mérite un
examen plus poussé avant d'entrer dans la chaîne de build.

IMPORTANT — dépendance réseau externe :
Nécessite un accès sortant à `api.deps.dev`. Comme pour Trivy, ce domaine
doit être explicitement autorisé dans l'environnement réseau si celui-ci
est restreint (proxy d'entreprise, sandbox CI).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Literal

import requests

Ecosystem = Literal["npm", "pypi"]

API_BASE = "https://api.deps.dev/v3"

# deps.dev utilise "PyPI" (casse précise) et "NPM" comme noms de système
_SYSTEM_MAP = {"npm": "NPM", "pypi": "PyPI"}

DEFAULT_TIMEOUT = 15


class DepsDevError(Exception):
    """Erreur lors de l'appel à l'API deps.dev."""


@dataclass
class ScorecardCheck:
    name: str
    score: int | None  # -1 ou None si non applicable/non déterminé
    reason: str = ""


@dataclass
class DepsDevResult:
    package_name: str
    version: str | None
    ecosystem: Ecosystem
    scorecard_score: float | None            # score global OpenSSF, 0-10
    scorecard_checks: list[ScorecardCheck]
    default_branch_advisories: list[str]      # identifiants d'avisories connues (OSV/GHSA)
    dependent_count: int | None               # nombre de paquets dépendant de celui-ci (signal d'usage)
    project_repo: str | None
    licenses: list[str]
    raw: dict = field(default_factory=dict)
    scan_failed: bool = False
    error_message: str | None = None

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "scorecard_score": self.scorecard_score,
            "scorecard_checks": [c.__dict__ for c in self.scorecard_checks],
            "default_branch_advisories": self.default_branch_advisories,
            "dependent_count": self.dependent_count,
            "project_repo": self.project_repo,
            "licenses": self.licenses,
            "scan_failed": self.scan_failed,
            "error_message": self.error_message,
        }


def _get(url: str) -> dict:
    resp = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={"User-Agent": "airlock-scanner/0.1"})
    if resp.status_code != 200:
        raise DepsDevError(f"deps.dev a répondu {resp.status_code} pour {url}")
    return resp.json()


def query_package(ecosystem: Ecosystem, name: str, version: str | None = None) -> DepsDevResult:
    system = _SYSTEM_MAP.get(ecosystem)
    if system is None:
        raise ValueError(f"Écosystème non supporté par deps.dev : {ecosystem}")

    try:
        # 1. Résoudre la version si non précisée (deps.dev veut une version explicite)
        if version is None:
            pkg_meta = _get(f"{API_BASE}/systems/{system}/packages/{name}")
            versions = pkg_meta.get("versions", [])
            if not versions:
                raise DepsDevError(f"Aucune version trouvée sur deps.dev pour {name}")
            # la dernière version publiée est généralement en fin de liste ; on prend
            # celle marquée "isDefault" si disponible, sinon la dernière
            default = next((v for v in versions if v.get("isDefault")), versions[-1])
            version = default["versionKey"]["version"]

        version_data = _get(
            f"{API_BASE}/systems/{system}/packages/{name}/versions/{version}"
        )

        project_key = None
        for link in version_data.get("relatedProjects", []) or []:
            project_key = link.get("projectKey", {}).get("id")
            if project_key:
                break

        scorecard_score = None
        scorecard_checks: list[ScorecardCheck] = []
        project_repo = None
        dependent_count = None

        if project_key:
            project_repo = f"https://{project_key}" if not project_key.startswith("http") else project_key
            try:
                project_data = _get(f"{API_BASE}/projects/{project_key}")
                scorecard = project_data.get("scorecard", {})
                scorecard_score = scorecard.get("overallScore")
                scorecard_checks = [
                    ScorecardCheck(
                        name=chk.get("name", "unknown"),
                        score=chk.get("score"),
                        reason=chk.get("reason", ""),
                    )
                    for chk in scorecard.get("checks", [])
                ]
                dependent_count = project_data.get("depsdevCounts", {}).get("directDependentCount")
            except DepsDevError:
                pass  # projet trouvé mais pas de scorecard calculé : on continue sans

        advisories = [
            a.get("advisoryKey", {}).get("id", "unknown")
            for a in version_data.get("advisoryKeys", []) or []
        ]

        licenses = version_data.get("licenses", []) or []

        return DepsDevResult(
            package_name=name,
            version=version,
            ecosystem=ecosystem,
            scorecard_score=scorecard_score,
            scorecard_checks=scorecard_checks,
            default_branch_advisories=advisories,
            dependent_count=dependent_count,
            project_repo=project_repo,
            licenses=licenses,
            raw=version_data,
        )

    except (DepsDevError, requests.RequestException) as e:
        return DepsDevResult(
            package_name=name, version=version, ecosystem=ecosystem,
            scorecard_score=None, scorecard_checks=[], default_branch_advisories=[],
            dependent_count=None, project_repo=None, licenses=[],
            scan_failed=True, error_message=str(e),
        )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Interroge deps.dev pour un paquet npm/PyPI")
    parser.add_argument("ecosystem", choices=["npm", "pypi"])
    parser.add_argument("name")
    parser.add_argument("--version", default=None)
    args = parser.parse_args()

    result = query_package(args.ecosystem, args.name, args.version)
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
