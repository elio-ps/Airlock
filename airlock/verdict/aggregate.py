"""
airlock.verdict.aggregate
============================

Combine les signaux des différents étages (SBOM, Trivy, GuardDog, deps.dev)
en un verdict unique, structuré et JUSTIFIÉ : chaque décision doit pouvoir
être expliquée à un humain (c'est le livrable "méthodo de jugement" du
projet), pas juste un score opaque.

Principe de conception : un signal INDISPONIBLE (ex. Trivy sans accès à sa
DB) ne doit jamais être confondu avec un signal "RAS". On distingue
explicitement trois états par étage : OK / SUSPECT / INDISPONIBLE.

Le verdict final suit une logique simple et volontairement lisible plutôt
qu'un score pondéré opaque :
  - un seul "threat-*" GuardDog déclenché => BLOCK (signal comportemental
    fort, peu de faux positifs sur ces règles)
  - une CVE CRITICAL/HIGH avec correctif disponible => QUARANTINE
  - un score OpenSSF Scorecard très bas (< 3/10) sur un paquet peu
    dépendu => QUARANTINE (hygiène du projet insuffisante)
  - sinon => ALLOW
Ces seuils sont des points de départ pédagogiques : le brief demande des
"policies configurables selon la politique d'entreprise", donc ils sont
isolés dans `Policy` pour être ajustés sans toucher à la logique.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class StageStatus(str, Enum):
    OK = "ok"                    # étage exécuté, aucun signal suspect
    SUSPECT = "suspect"          # étage exécuté, signal(aux) suspect(s) trouvé(s)
    UNAVAILABLE = "unavailable"  # étage n'a pas pu s'exécuter (réseau, timeout, etc.)


class Verdict(str, Enum):
    ALLOW = "allow"
    QUARANTINE = "quarantine"     # nécessite revue humaine avant usage
    BLOCK = "block"


@dataclass
class Policy:
    """Seuils de décision, pensés pour être surchargés par une config d'entreprise (YAML/JSON)."""
    block_on_any_threat_rule: bool = True
    quarantine_on_cve_severity: tuple[str, ...] = ("HIGH", "CRITICAL")
    quarantine_on_scorecard_below: float = 3.0
    quarantine_on_scorecard_below_dependents: int = 50  # le seuil scorecard ne s'applique
    # qu'aux paquets peu utilisés : un paquet massivement dépendu avec un score bas
    # est un signal différent (à documenter côté rapport, pas à bloquer aveuglément)

    @classmethod
    def from_file(cls, path: Path) -> "Policy":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)


@dataclass
class StageSummary:
    name: str
    status: StageStatus
    detail: str
    raw_ref: str = ""  # pointeur vers le rapport détaillé de l'étage (fichier, id...)

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status.value, "detail": self.detail, "raw_ref": self.raw_ref}


@dataclass
class PackageVerdict:
    package_name: str
    version: str
    ecosystem: str
    verdict: Verdict
    reasons: list[str]
    stages: list[StageSummary]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "verdict": self.verdict.value,
            "reasons": self.reasons,
            "stages": [s.to_dict() for s in self.stages],
            "timestamp": self.timestamp,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def aggregate(
    package_name: str,
    version: str,
    ecosystem: str,
    trivy_result=None,       # airlock.analysis.trivy_scan.TrivyResult | None
    guarddog_result=None,    # airlock.analysis.guarddog_scan.GuardDogResult | None
    depsdev_result=None,     # airlock.analysis.depsdev.DepsDevResult | None
    sbom_path: Path | None = None,
    policy: Policy | None = None,
) -> PackageVerdict:
    policy = policy or Policy()
    stages: list[StageSummary] = []
    reasons: list[str] = []
    verdict = Verdict.ALLOW

    # --- Étage SBOM (toujours "ok" s'il a produit un fichier : c'est un inventaire, pas un scanner) ---
    if sbom_path is not None:
        stages.append(StageSummary(
            name="sbom", status=StageStatus.OK,
            detail="SBOM CycloneDX généré", raw_ref=str(sbom_path),
        ))

    # --- Étage Trivy (CVE) ---
    if trivy_result is None:
        stages.append(StageSummary(name="trivy", status=StageStatus.UNAVAILABLE, detail="non exécuté"))
    elif trivy_result.scan_failed:
        stages.append(StageSummary(
            name="trivy", status=StageStatus.UNAVAILABLE,
            detail=f"échec d'exécution : {trivy_result.error_message}",
        ))
    else:
        severe = [f for f in trivy_result.findings if f.severity in policy.quarantine_on_cve_severity]
        if severe:
            stages.append(StageSummary(
                name="trivy", status=StageStatus.SUSPECT,
                detail=f"{len(severe)} CVE {'/'.join(policy.quarantine_on_cve_severity)} sur "
                       f"{len(trivy_result.findings)} au total",
            ))
            reasons.append(
                f"Trivy : {len(severe)} vulnérabilité(s) sévère(s) détectée(s) "
                f"(ex. {severe[0].vuln_id} sur {severe[0].pkg_name})"
            )
            verdict = _escalate(verdict, Verdict.QUARANTINE)
        else:
            stages.append(StageSummary(
                name="trivy", status=StageStatus.OK,
                detail=f"{len(trivy_result.findings)} CVE trouvée(s), aucune sévère",
            ))

    # --- Étage GuardDog (comportement) ---
    if guarddog_result is None:
        stages.append(StageSummary(name="guarddog", status=StageStatus.UNAVAILABLE, detail="non exécuté"))
    elif guarddog_result.scan_failed:
        stages.append(StageSummary(
            name="guarddog", status=StageStatus.UNAVAILABLE,
            detail=f"échec d'exécution : {guarddog_result.error_message}",
        ))
    else:
        threats = guarddog_result.threat_findings
        if threats:
            rule_list = ", ".join(f.rule_name for f in threats)
            stages.append(StageSummary(
                name="guarddog", status=StageStatus.SUSPECT,
                detail=f"{len(threats)} règle(s) 'threat-*' déclenchée(s) : {rule_list}",
            ))
            reasons.append(f"GuardDog : comportement(s) suspect(s) détecté(s) dans le code ({rule_list})")
            if policy.block_on_any_threat_rule:
                verdict = _escalate(verdict, Verdict.BLOCK)
        else:
            stages.append(StageSummary(
                name="guarddog", status=StageStatus.OK,
                detail=f"{guarddog_result.issue_count} signal(aux) capability, 0 threat",
            ))

    # --- Étage deps.dev (réputation/hygiène) ---
    if depsdev_result is None:
        stages.append(StageSummary(name="deps.dev", status=StageStatus.UNAVAILABLE, detail="non exécuté"))
    elif depsdev_result.scan_failed:
        stages.append(StageSummary(
            name="deps.dev", status=StageStatus.UNAVAILABLE,
            detail=f"échec d'exécution : {depsdev_result.error_message}",
        ))
    else:
        score = depsdev_result.scorecard_score
        dependents = depsdev_result.dependent_count or 0
        if (
            score is not None
            and score < policy.quarantine_on_scorecard_below
            and dependents < policy.quarantine_on_scorecard_below_dependents
        ):
            stages.append(StageSummary(
                name="deps.dev", status=StageStatus.SUSPECT,
                detail=f"score OpenSSF Scorecard bas ({score}/10) pour un paquet peu dépendu "
                       f"({dependents} dépendants directs)",
            ))
            reasons.append(
                f"deps.dev : hygiène du projet faible (Scorecard {score}/10, {dependents} dépendants)"
            )
            verdict = _escalate(verdict, Verdict.QUARANTINE)
        else:
            detail = f"score OpenSSF Scorecard {score}/10" if score is not None else "score non disponible"
            stages.append(StageSummary(name="deps.dev", status=StageStatus.OK, detail=detail))

    if not reasons:
        reasons.append("Aucun signal suspect sur les étages exécutés.")

    return PackageVerdict(
        package_name=package_name, version=version, ecosystem=ecosystem,
        verdict=verdict, reasons=reasons, stages=stages,
    )


_VERDICT_ORDER = [Verdict.ALLOW, Verdict.QUARANTINE, Verdict.BLOCK]


def _escalate(current: Verdict, candidate: Verdict) -> Verdict:
    """Un verdict ne peut être qu'aggravé, jamais adouci, au fil des étages."""
    return candidate if _VERDICT_ORDER.index(candidate) > _VERDICT_ORDER.index(current) else current
