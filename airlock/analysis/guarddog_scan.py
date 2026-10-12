"""
airlock.analysis.guarddog_scan
================================

Exécute GuardDog (https://github.com/DataDog/guarddog) sur un paquet npm
ou PyPI. GuardDog combine deux familles de règles :

  - règles "metadata"   : typosquatting, auteur suspect, incohérence
                           dépôt/paquet, etc. (nécessitent un accès réseau
                           au registre et parfois à des services tiers)
  - règles "sourcecode" : détection de patterns (Semgrep + heuristiques)
                           dans le code du paquet — capacités
                           (`capability-*`, ex. accès réseau, écriture
                           fichier) et signatures de comportements
                           malveillants connus (`threat-*`, ex. reverse
                           shell, exfiltration, obfuscation).

On utilise l'API Python de GuardDog plutôt que de wrapper son CLI en
sous-processus : plus robuste (pas de parsing de texte), et ça permet de
distinguer proprement les règles déclenchées des règles non applicables.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Ecosystem = Literal["npm", "pypi"]

# Règles dont le déclenchement est un signal fort de comportement malveillant
# (par opposition aux règles "capability-*", qui décrivent une capacité du
# code — souvent légitime — plutôt qu'un comportement suspect en soi).
THREAT_PREFIX = "threat-"
CAPABILITY_PREFIX = "capability-"


class GuardDogError(Exception):
    """Erreur lors de l'exécution de GuardDog."""


@dataclass
class GuardDogFinding:
    rule_name: str
    category: str  # "threat" | "capability" | "metadata"
    matches: list | dict  # contenu brut retourné par la règle (variable selon le type de règle)

    def to_dict(self) -> dict:
        return {"rule_name": self.rule_name, "category": self.category, "matches": self.matches}


@dataclass
class GuardDogResult:
    package_name: str
    version: str | None
    ecosystem: Ecosystem
    issue_count: int
    findings: list[GuardDogFinding]
    rule_errors: dict[str, str]  # règles n'ayant pas pu s'exécuter (souvent : accès réseau tiers indisponible)
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
    GuardDog encode 'règle non déclenchée' de façons différentes selon le type
    de règle : `None` pour les règles metadata, `{}` ou `[]` vide pour les
    règles sourcecode qui n'ont trouvé aucune occurrence. Tout le reste
    (liste non vide, dict non vide) signifie que la règle a matché.
    """
    if value is None:
        return False
    if isinstance(value, (list, dict)) and len(value) == 0:
        return False
    return True


def scan_package(ecosystem: Ecosystem, name: str, version: str | None = None) -> GuardDogResult:
    """
    Lance GuardDog sur un paquet distant (téléchargement géré en interne par
    GuardDog, dans un répertoire temporaire qu'il nettoie lui-même).
    """
    try:
        if ecosystem == "pypi":
            from guarddog.scanners.pypi_package_scanner import PypiPackageScanner
            scanner = PypiPackageScanner()
        elif ecosystem == "npm":
            from guarddog.scanners.npm_package_scanner import NPMPackageScanner
            scanner = NPMPackageScanner()
        else:
            raise ValueError(f"Écosystème non supporté par GuardDog : {ecosystem}")

        raw = scanner.scan_remote(name, version=version)
    except Exception as e:  # GuardDog peut lever des exceptions variées (réseau, parsing...)
        return GuardDogResult(
            package_name=name, version=version, ecosystem=ecosystem,
            issue_count=0, findings=[], rule_errors={},
            scan_failed=True, error_message=str(e),
        )

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

    parser = argparse.ArgumentParser(description="Scan GuardDog d'un paquet npm/PyPI")
    parser.add_argument("ecosystem", choices=["npm", "pypi"])
    parser.add_argument("name")
    parser.add_argument("--version", default=None)
    args = parser.parse_args()

    result = scan_package(args.ecosystem, args.name, args.version)
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
