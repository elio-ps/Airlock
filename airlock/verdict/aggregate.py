"""
airlock.verdict.aggregate
============================

Combines the signals of the stages (SBOM, Trivy, GuardDog, deps.dev, detonation)
into a single, structured and JUSTIFIED verdict: each decision can be explained to a
human, it is not an opaque score.

Design principle: an UNAVAILABLE signal (e.g. Trivy without its DB) must never
be mistaken for a clean signal. Each stage has three explicit states:
OK / SUSPECT / UNAVAILABLE.

The final verdict follows simple, deliberately readable logic:
  - behaviour observed at detonation: Critical => BLOCK, Warning => QUARANTINE
  - one GuardDog "threat-*" rule => QUARANTINE (a static pattern, not a proof)
  - a CRITICAL/HIGH CVE => QUARANTINE
  - a very low OpenSSF Scorecard (< 3/10) on a little-used package =>
    QUARANTINE (weak project hygiene)
  - install-time code that was not detonated => QUARANTINE
  - otherwise => ALLOW
Thresholds live in `Policy` so they can be tuned without touching the logic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class StageStatus(str, Enum):
    OK = "ok"                    # stage ran, no suspicious signal
    SUSPECT = "suspect"          # stage ran, suspicious signal(s) found
    UNAVAILABLE = "unavailable"  # stage could not run (network, timeout, etc.)
    SKIPPED = "skipped"          # stage deliberately not run (--skip, local package)


class Verdict(str, Enum):
    ALLOW = "allow"
    QUARANTINE = "quarantine"     # needs human review before use
    BLOCK = "block"


@dataclass
class Policy:
    """Decision thresholds, meant to be overridden by a company configuration."""
    # False: static signals alone only quarantine, see ADR-0007.
    block_on_any_threat_rule: bool = False
    quarantine_on_cve_severity: tuple[str, ...] = ("HIGH", "CRITICAL")
    quarantine_on_scorecard_below: float = 3.0
    quarantine_on_scorecard_below_dependents: int = 50  # the scorecard threshold only
    # applies to little-used packages: a widely used package with a low score is a
    # different signal (to report, not to block blindly)
    quarantine_on_unknown_package: bool = True  # unknown to deps.dev: typically brand new
    quarantine_on_undetonated_hook: bool = True  # install-time code nobody watched run
    fail_closed: bool = False  # an unavailable stage means QUARANTINE (ADR-0005)
    block_on_detonation_priority: tuple[str, ...] = ("Emergency", "Alert", "Critical")
    quarantine_on_detonation_priority: tuple[str, ...] = ("Error", "Warning")

    @classmethod
    def from_file(cls, path: Path) -> "Policy":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)


@dataclass
class StageSummary:
    name: str
    status: StageStatus
    detail: str
    raw_ref: str = ""  # pointer to the stage's detailed report (file, id...)

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
    detonation_result=None,  # airlock.detonation.sandbox.DetonationResult | None
    sbom_path: Path | None = None,
    policy: Policy | None = None,
    skipped: frozenset[str] | set[str] = frozenset(),
    install_hooks: list[str] | None = None,
) -> PackageVerdict:
    policy = policy or Policy()
    stages: list[StageSummary] = []
    reasons: list[str] = []
    verdict = Verdict.ALLOW

    # --- SBOM stage (always "ok" when it produced a file: an inventory, not a scanner) ---
    if sbom_path is not None:
        stages.append(StageSummary(
            name="sbom", status=StageStatus.OK,
            detail="CycloneDX SBOM generated", raw_ref=str(sbom_path),
        ))

    # --- Trivy stage (CVEs) ---
    if trivy_result is None:
        stages.append(_not_run("trivy", "trivy" in skipped))
    elif trivy_result.scan_failed:
        stages.append(StageSummary(
            name="trivy", status=StageStatus.UNAVAILABLE,
            detail=f"execution failed: {trivy_result.error_message}",
        ))
    else:
        severe = [f for f in trivy_result.findings if f.severity in policy.quarantine_on_cve_severity]
        if severe:
            stages.append(StageSummary(
                name="trivy", status=StageStatus.SUSPECT,
                detail=f"{len(severe)} {'/'.join(policy.quarantine_on_cve_severity)} CVE(s) out of "
                       f"{len(trivy_result.findings)} in total",
            ))
            reasons.append(
                f"Trivy: {len(severe)} severe vulnerabilit(y/ies) detected "
                f"(e.g. {severe[0].vuln_id} in {severe[0].pkg_name})"
            )
            verdict = _escalate(verdict, Verdict.QUARANTINE)
        else:
            stages.append(StageSummary(
                name="trivy", status=StageStatus.OK,
                detail=f"{len(trivy_result.findings)} CVE(s) found, none severe",
            ))

    # --- GuardDog stage (behaviour) ---
    if guarddog_result is None:
        stages.append(_not_run("guarddog", "guarddog" in skipped))
    elif guarddog_result.scan_failed:
        stages.append(StageSummary(
            name="guarddog", status=StageStatus.UNAVAILABLE,
            detail=f"execution failed: {guarddog_result.error_message}",
        ))
    else:
        threats = guarddog_result.threat_findings
        if threats:
            rule_list = ", ".join(f.rule_name for f in threats)
            stages.append(StageSummary(
                name="guarddog", status=StageStatus.SUSPECT,
                detail=f"{len(threats)} 'threat-*' rule(s) triggered: {rule_list}",
            ))
            reasons.append(f"GuardDog: suspicious behaviour detected in the code ({rule_list})")
            verdict = _escalate(
                verdict, Verdict.BLOCK if policy.block_on_any_threat_rule else Verdict.QUARANTINE
            )
        else:
            stages.append(StageSummary(
                name="guarddog", status=StageStatus.OK,
                detail=f"{guarddog_result.issue_count} capability signal(s), 0 threat",
            ))

    # --- deps.dev stage (reputation/hygiene) ---
    if depsdev_result is None:
        stages.append(_not_run("deps.dev", "depsdev" in skipped))
    elif depsdev_result.scan_failed:
        stages.append(StageSummary(
            name="deps.dev", status=StageStatus.UNAVAILABLE,
            detail=f"execution failed: {depsdev_result.error_message}",
        ))
    elif depsdev_result.package_unknown:
        stages.append(StageSummary(
            name="deps.dev", status=StageStatus.SUSPECT, detail="package unknown to deps.dev",
        ))
        if policy.quarantine_on_unknown_package:
            reasons.append("deps.dev: package unknown, possibly published very recently")
            verdict = _escalate(verdict, Verdict.QUARANTINE)
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
                detail=f"low OpenSSF Scorecard score ({score}/10) for a little-used package "
                       f"({dependents} direct dependents)",
            ))
            reasons.append(
                f"deps.dev: weak project hygiene (Scorecard {score}/10, {dependents} dependents)"
            )
            verdict = _escalate(verdict, Verdict.QUARANTINE)
        else:
            detail = f"OpenSSF Scorecard score {score}/10" if score is not None else "score not available"
            stages.append(StageSummary(name="deps.dev", status=StageStatus.OK, detail=detail))

    # --- Detonation stage (observed behaviour, the only proof that can BLOCK) ---
    detonated = False
    if detonation_result is None:
        stages.append(_not_run("detonation", "detonation" in skipped))
    else:
        # Findings count even when the sensor was blind: the sink is a separate witness.
        blocking = [f for f in detonation_result.findings
                    if f.priority in policy.block_on_detonation_priority]
        doubtful = [f for f in detonation_result.findings
                    if f.priority in policy.quarantine_on_detonation_priority]
        detonated = not detonation_result.scan_failed
        if blocking or doubtful:
            rules = ", ".join(sorted({f.rule for f in blocking + doubtful}))
            stages.append(StageSummary(
                name="detonation", status=StageStatus.SUSPECT, detail=f"behaviour observed: {rules}",
            ))
        elif detonated:
            stages.append(StageSummary(
                name="detonation", status=StageStatus.OK, detail="no suspicious behaviour observed",
            ))
        else:
            stages.append(StageSummary(
                name="detonation", status=StageStatus.UNAVAILABLE,
                detail=f"execution failed: {detonation_result.error_message}",
            ))
        if blocking:
            reasons.extend(f"Detonation: {f.rule} ({f.detail})" for f in blocking)
            verdict = _escalate(verdict, Verdict.BLOCK)
        if doubtful:
            reasons.extend(f"Detonation: {f.rule} ({f.detail})" for f in doubtful)
            verdict = _escalate(verdict, Verdict.QUARANTINE)

    # --- Install-time code that no sandbox has watched (ADR-0008) ---
    if install_hooks and policy.quarantine_on_undetonated_hook and not detonated:
        reasons.append(f"Install-time code was not detonated: {'; '.join(install_hooks)}")
        verdict = _escalate(verdict, Verdict.QUARANTINE)

    # --- Unavailable stages (ADR-0005) ---
    unavailable = [s.name for s in stages if s.status == StageStatus.UNAVAILABLE]
    if unavailable and policy.fail_closed:
        reasons.append(f"Fail-closed policy: stage(s) unavailable ({', '.join(unavailable)})")
        verdict = _escalate(verdict, Verdict.QUARANTINE)

    if not reasons:
        reasons.append("No suspicious signal on the stages that ran.")

    return PackageVerdict(
        package_name=package_name, version=version, ecosystem=ecosystem,
        verdict=verdict, reasons=reasons, stages=stages,
    )


def _not_run(name: str, deliberately: bool) -> StageSummary:
    if deliberately:
        return StageSummary(name=name, status=StageStatus.SKIPPED, detail="skipped")
    return StageSummary(name=name, status=StageStatus.UNAVAILABLE, detail="not run")


_VERDICT_ORDER = [Verdict.ALLOW, Verdict.QUARANTINE, Verdict.BLOCK]


def _escalate(current: Verdict, candidate: Verdict) -> Verdict:
    """A verdict can only get worse across stages, never better."""
    return candidate if _VERDICT_ORDER.index(candidate) > _VERDICT_ORDER.index(current) else current
