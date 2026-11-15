"""
airlock.analysis.depsdev
==========================

Client for the public deps.dev API (https://deps.dev), which aggregates for
each package:
  - the OpenSSF Scorecard score (0-10) of the related source repository, with
    per-check details (maintenance, code review, pinned dependencies,
    fuzzing, etc.);
  - project information (repository, declared license);
  - known security advisories (cross-referenced with OSV.dev).

This is a REPUTATION/HYGIENE signal, complementary to Trivy (known CVEs) and
GuardDog (suspicious behaviour in the code): a low Scorecard score does not
prove malice, but a very poorly rated package deserves a closer look before
it enters the build chain.

External network dependency: requires outbound access to `api.deps.dev`.
Like Trivy, this domain must be allowed in restricted networks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import quote

import requests

Ecosystem = Literal["npm", "pypi"]

API_BASE = "https://api.deps.dev/v3"
API_ALPHA_BASE = "https://api.deps.dev/v3alpha"  # only endpoint exposing dependent counts

# deps.dev system names
_SYSTEM_MAP = {"npm": "NPM", "pypi": "PyPI"}

DEFAULT_TIMEOUT = 15


class DepsDevError(Exception):
    """Error while calling the deps.dev API."""


class DepsDevNotFound(DepsDevError):
    """deps.dev does not know this resource (a signal, not an outage)."""


@dataclass
class ScorecardCheck:
    name: str
    score: int | None  # -1 or None when not applicable or undetermined
    reason: str = ""


@dataclass
class DepsDevResult:
    package_name: str
    version: str | None
    ecosystem: Ecosystem
    scorecard_score: float | None            # overall OpenSSF score, 0-10
    scorecard_checks: list[ScorecardCheck]
    default_branch_advisories: list[str]      # known advisory identifiers (OSV/GHSA)
    dependent_count: int | None               # number of packages depending on this one (usage signal)
    project_repo: str | None
    licenses: list[str]
    raw: dict = field(default_factory=dict)
    scan_failed: bool = False
    error_message: str | None = None
    package_unknown: bool = False  # 404: unknown to deps.dev, typical of a very recent package

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
            "package_unknown": self.package_unknown,
            "scan_failed": self.scan_failed,
            "error_message": self.error_message,
        }


def _get(url: str) -> dict:
    resp = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={"User-Agent": "airlock-scanner/0.1"})
    if resp.status_code == 404:
        raise DepsDevNotFound(f"deps.dev does not know {url}")
    if resp.status_code != 200:
        raise DepsDevError(f"deps.dev answered {resp.status_code} for {url}")
    return resp.json()


def _q(value: str) -> str:
    """Encode a path segment: scoped npm names and project keys contain slashes."""
    return quote(value, safe="")


def resolved_dependencies(ecosystem: Ecosystem, name: str, version: str) -> list[tuple[str, str]] | None:
    """
    Return the (name, version) pairs of the resolved dependency graph, transitive
    dependencies included, without installing anything. None when unavailable.

    This is deps.dev's resolution at query time: a real install could pick
    other versions within the declared ranges.
    """
    url = f"{API_BASE}/systems/{_SYSTEM_MAP[ecosystem]}/packages/{_q(name)}/versions/{_q(version)}:dependencies"
    try:
        graph = _get(url)
    except (DepsDevError, requests.RequestException, ValueError):
        return None
    return [
        (node["versionKey"]["name"], node["versionKey"]["version"])
        for node in graph.get("nodes", [])
        if node.get("relation") != "SELF"
    ]


def query_package(ecosystem: Ecosystem, name: str, version: str | None = None) -> DepsDevResult:
    """Collect the reputation signals of one package version. Never raises."""
    system = _SYSTEM_MAP.get(ecosystem)
    if system is None:
        raise ValueError(f"Ecosystem not supported by deps.dev: {ecosystem}")

    try:
        version = version or _default_version(system, name)
        version_data = _get(f"{API_BASE}/systems/{system}/packages/{_q(name)}/versions/{_q(version)}")
        project_key = _project_key(version_data)
        score, checks = _scorecard(project_key) if project_key else (None, [])
        return DepsDevResult(
            package_name=name, version=version, ecosystem=ecosystem,
            scorecard_score=score,
            scorecard_checks=checks,
            default_branch_advisories=[a.get("id", "unknown")
                                       for a in version_data.get("advisoryKeys") or []],
            dependent_count=_dependent_count(system, name, version),
            project_repo=_repo_url(project_key),
            licenses=version_data.get("licenses") or [],
            raw=version_data,
        )
    except DepsDevNotFound as e:
        # Unknown to deps.dev is a signal (often a brand-new package), not an outage.
        return _empty_result(name, version, ecosystem, error_message=str(e), package_unknown=True)
    except (DepsDevError, requests.RequestException, ValueError, KeyError) as e:
        return _empty_result(name, version, ecosystem, error_message=str(e), scan_failed=True)


def _default_version(system: str, name: str) -> str:
    """deps.dev needs an explicit version: use the one it flags as default."""
    versions = _get(f"{API_BASE}/systems/{system}/packages/{_q(name)}").get("versions", [])
    if not versions:
        raise DepsDevError(f"No version found on deps.dev for {name}")
    default = next((v for v in versions if v.get("isDefault")), versions[-1])
    return default["versionKey"]["version"]


def _project_key(version_data: dict) -> str | None:
    """The source repository linked to the package, e.g. "github.com/psf/requests"."""
    for link in version_data.get("relatedProjects") or []:
        key = link.get("projectKey", {}).get("id")
        if key:
            return key
    return None


def _repo_url(project_key: str | None) -> str | None:
    if project_key is None or project_key.startswith("http"):
        return project_key
    return f"https://{project_key}"


def _scorecard(project_key: str) -> tuple[float | None, list[ScorecardCheck]]:
    try:
        scorecard = _get(f"{API_BASE}/projects/{_q(project_key)}").get("scorecard", {})
    except DepsDevError:
        return None, []  # project found but no scorecard computed: carry on without it
    checks = [
        ScorecardCheck(name=c.get("name", "unknown"), score=c.get("score"), reason=c.get("reason", ""))
        for c in scorecard.get("checks", [])
    ]
    return scorecard.get("overallScore"), checks


def _dependent_count(system: str, name: str, version: str) -> int | None:
    url = f"{API_ALPHA_BASE}/systems/{system}/packages/{_q(name)}/versions/{_q(version)}:dependents"
    try:
        return _get(url).get("directDependentCount")
    except DepsDevError:
        return None  # alpha endpoint: a missing count must not fail the whole stage


def _empty_result(name, version, ecosystem, **status) -> DepsDevResult:
    return DepsDevResult(
        package_name=name, version=version, ecosystem=ecosystem,
        scorecard_score=None, scorecard_checks=[], default_branch_advisories=[],
        dependent_count=None, project_repo=None, licenses=[], **status,
    )
