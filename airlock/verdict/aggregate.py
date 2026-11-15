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
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(**data)
        except (OSError, json.JSONDecodeError, TypeError) as e:
            # TypeError: an unknown or misspelt key, which must not be silently ignored.
            raise ValueError(f"invalid policy file {path}: {e}") from e


@dataclass
class StageSummary:
    name: str
    status: StageStatus
    detail: str
    raw_ref: str = ""  # pointer to the stage's detailed report (file, id...)

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status.value, "detail": self.detail, "raw_ref": self.raw_ref}


@dataclass
class Judgement:
    """What one stage contributes to the verdict."""
    stage: StageSummary | None  # None: the signal has no stage line of its own
    verdict: Verdict = Verdict.ALLOW
    reasons: list[str] = field(default_factory=list)


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


def aggregate(
    package_name: str,
    version: str,
    ecosystem: str,
    trivy_result=None,       # airlock.analysis.trivy_scan.TrivyResult | None
    guarddog_result=None,    # airlock.analysis.guarddog_scan.GuardDogResult | None
    depsdev_result=None,     # airlock.analysis.depsdev.DepsDevResult | None
    detonation_result=None,  # airlock.detonation.sandbox.DetonationResult | None
    sbom_path: Path | None = None,
    sbom_error: str | None = None,
    policy: Policy | None = None,
    skipped: frozenset[str] | set[str] = frozenset(),
    install_hooks: list[str] | None = None,
) -> PackageVerdict:
    """Judge each stage on its own, then keep the worst verdict and every reason."""
    policy = policy or Policy()
    judgements = [
        _judge_sbom(sbom_path, sbom_error),
        _judge_trivy(trivy_result, policy, "trivy" in skipped),
        _judge_guarddog(guarddog_result, policy, "guarddog" in skipped),
        _judge_depsdev(depsdev_result, policy, "depsdev" in skipped),
        _judge_detonation(detonation_result, policy, "detonation" in skipped),
        _judge_install_hooks(install_hooks, detonation_result, policy),
    ]
    stages = [j.stage for j in judgements if j.stage is not None]
    judgements.append(_judge_unavailable_stages(stages, policy))

    verdict = Verdict.ALLOW
    reasons: list[str] = []
    for judgement in judgements:
        verdict = _worst(verdict, judgement.verdict)
        reasons.extend(judgement.reasons)
    if not reasons:
        reasons.append("No suspicious signal on the stages that ran.")

    return PackageVerdict(
        package_name=package_name, version=version, ecosystem=ecosystem,
        verdict=verdict, reasons=reasons, stages=stages,
    )


# --- One function per stage -------------------------------------------------

def _judge_sbom(sbom_path: Path | None, sbom_error: str | None) -> Judgement:
    # The SBOM is an inventory, not a scanner: it is never "suspect".
    if sbom_path is not None:
        return Judgement(StageSummary("sbom", StageStatus.OK, "CycloneDX SBOM generated",
                                      raw_ref=str(sbom_path)))
    if sbom_error is not None:
        return Judgement(StageSummary("sbom", StageStatus.UNAVAILABLE,
                                      f"generation failed: {sbom_error}"))
    return Judgement(None)


def _judge_trivy(result, policy: Policy, skipped: bool) -> Judgement:
    if result is None:
        return Judgement(_not_run("trivy", skipped))
    if result.scan_failed:
        return Judgement(_failed("trivy", result.error_message))

    severe = [f for f in result.findings if f.severity in policy.quarantine_on_cve_severity]
    if not severe:
        return Judgement(StageSummary(
            "trivy", StageStatus.OK, f"{len(result.findings)} CVE(s) found, none severe"))

    levels = "/".join(policy.quarantine_on_cve_severity)
    return Judgement(
        StageSummary("trivy", StageStatus.SUSPECT,
                     f"{len(severe)} {levels} CVE(s) out of {len(result.findings)} in total"),
        Verdict.QUARANTINE,
        [f"Trivy: {len(severe)} severe vulnerabilit(y/ies) detected "
         f"(e.g. {severe[0].vuln_id} in {severe[0].pkg_name})"],
    )


def _judge_guarddog(result, policy: Policy, skipped: bool) -> Judgement:
    if result is None:
        return Judgement(_not_run("guarddog", skipped))
    if result.scan_failed:
        return Judgement(_failed("guarddog", result.error_message))

    threats = result.threat_findings
    if not threats:
        return Judgement(StageSummary(
            "guarddog", StageStatus.OK, f"{result.issue_count} capability signal(s), 0 threat"))

    rules = ", ".join(f.rule_name for f in threats)
    # A static pattern is not a proof: it only quarantines by default (ADR-0007).
    verdict = Verdict.BLOCK if policy.block_on_any_threat_rule else Verdict.QUARANTINE
    return Judgement(
        StageSummary("guarddog", StageStatus.SUSPECT,
                     f"{len(threats)} 'threat-*' rule(s) triggered: {rules}"),
        verdict,
        [f"GuardDog: suspicious behaviour detected in the code ({rules})"],
    )


def _judge_depsdev(result, policy: Policy, skipped: bool) -> Judgement:
    if result is None:
        return Judgement(_not_run("deps.dev", skipped))
    if result.scan_failed:
        return Judgement(_failed("deps.dev", result.error_message))

    if result.package_unknown:
        stage = StageSummary("deps.dev", StageStatus.SUSPECT, "package unknown to deps.dev")
        if not policy.quarantine_on_unknown_package:
            return Judgement(stage)
        return Judgement(stage, Verdict.QUARANTINE,
                         ["deps.dev: package unknown, possibly published very recently"])

    score = result.scorecard_score
    dependents = result.dependent_count or 0
    # A low score only matters on a little-used package: a popular one with a low
    # score is worth reporting, not quarantining blindly.
    weak_hygiene = (
        score is not None
        and score < policy.quarantine_on_scorecard_below
        and dependents < policy.quarantine_on_scorecard_below_dependents
    )
    if not weak_hygiene:
        detail = f"OpenSSF Scorecard score {score}/10" if score is not None else "score not available"
        return Judgement(StageSummary("deps.dev", StageStatus.OK, detail))

    return Judgement(
        StageSummary("deps.dev", StageStatus.SUSPECT,
                     f"low OpenSSF Scorecard score ({score}/10) for a little-used package "
                     f"({dependents} direct dependents)"),
        Verdict.QUARANTINE,
        [f"deps.dev: weak project hygiene (Scorecard {score}/10, {dependents} dependents)"],
    )


def _judge_detonation(result, policy: Policy, skipped: bool) -> Judgement:
    """Observed behaviour: the only proof that can BLOCK (ADR-0007)."""
    if result is None:
        return Judgement(_not_run("detonation", skipped))

    # Findings count even when the sensor was blind: the sink is a separate witness.
    blocking = [f for f in result.findings if f.priority in policy.block_on_detonation_priority]
    doubtful = [f for f in result.findings if f.priority in policy.quarantine_on_detonation_priority]

    if blocking or doubtful:
        rules = ", ".join(sorted({f.rule for f in blocking + doubtful}))
        return Judgement(
            StageSummary("detonation", StageStatus.SUSPECT, f"behaviour observed: {rules}"),
            Verdict.BLOCK if blocking else Verdict.QUARANTINE,
            [f"Detonation: {f.rule} ({f.detail})" for f in blocking + doubtful],
        )

    if _was_fully_detonated(result):
        return Judgement(StageSummary("detonation", StageStatus.OK,
                                      "no suspicious behaviour observed"))

    # Seeing nothing proves nothing when the sensor was blind or the install broke.
    problems = []
    if result.scan_failed:
        problems.append(f"execution failed: {result.error_message}")
    if result.incomplete_phases:
        problems.append("install did not complete: " + ", ".join(result.incomplete_phases))
    return Judgement(StageSummary("detonation", StageStatus.UNAVAILABLE, "; ".join(problems)))


def _judge_install_hooks(install_hooks, detonation_result, policy: Policy) -> Judgement:
    """Install-time code that no sandbox has fully watched run (ADR-0008)."""
    watched = detonation_result is not None and _was_fully_detonated(detonation_result)
    if not install_hooks or watched or not policy.quarantine_on_undetonated_hook:
        return Judgement(None)
    return Judgement(None, Verdict.QUARANTINE,
                     [f"Install-time code was not detonated: {'; '.join(install_hooks)}"])


def _judge_unavailable_stages(stages: list[StageSummary], policy: Policy) -> Judgement:
    """Fail-closed policy: a stage that could not run is a reason to wait (ADR-0005)."""
    unavailable = [s.name for s in stages if s.status == StageStatus.UNAVAILABLE]
    if not unavailable or not policy.fail_closed:
        return Judgement(None)
    return Judgement(None, Verdict.QUARANTINE,
                     [f"Fail-closed policy: stage(s) unavailable ({', '.join(unavailable)})"])


# --- Small helpers ----------------------------------------------------------

def _was_fully_detonated(result) -> bool:
    """The sensor saw the run and every install phase finished."""
    return not result.scan_failed and not result.incomplete_phases


def _not_run(name: str, deliberately: bool) -> StageSummary:
    if deliberately:
        return StageSummary(name, StageStatus.SKIPPED, "skipped")
    return StageSummary(name, StageStatus.UNAVAILABLE, "not run")


def _failed(name: str, error_message: str | None) -> StageSummary:
    return StageSummary(name, StageStatus.UNAVAILABLE, f"execution failed: {error_message}")


_VERDICT_ORDER = [Verdict.ALLOW, Verdict.QUARANTINE, Verdict.BLOCK]


def _worst(a: Verdict, b: Verdict) -> Verdict:
    """A verdict can only get worse across stages, never better (ADR-0004)."""
    return max(a, b, key=_VERDICT_ORDER.index)
