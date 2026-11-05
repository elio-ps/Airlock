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

import json
from dataclasses import dataclass, field
from typing import Literal

import requests

Ecosystem = Literal["npm", "pypi"]

API_BASE = "https://api.deps.dev/v3"

# deps.dev system names
_SYSTEM_MAP = {"npm": "NPM", "pypi": "PyPI"}

DEFAULT_TIMEOUT = 15


class DepsDevError(Exception):
    """Error while calling the deps.dev API."""


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
        raise DepsDevError(f"deps.dev answered {resp.status_code} for {url}")
    return resp.json()


def query_package(ecosystem: Ecosystem, name: str, version: str | None = None) -> DepsDevResult:
    system = _SYSTEM_MAP.get(ecosystem)
    if system is None:
        raise ValueError(f"Ecosystem not supported by deps.dev: {ecosystem}")

    try:
        # 1. Resolve the version when not given (deps.dev needs an explicit version)
        if version is None:
            pkg_meta = _get(f"{API_BASE}/systems/{system}/packages/{name}")
            versions = pkg_meta.get("versions", [])
            if not versions:
                raise DepsDevError(f"No version found on deps.dev for {name}")
            # the latest release is usually at the end of the list; use the one
            # flagged "isDefault" when available, otherwise the last one
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
                pass  # project found but no scorecard computed: carry on without it

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

    parser = argparse.ArgumentParser(description="Query deps.dev for an npm/PyPI package")
    parser.add_argument("ecosystem", choices=["npm", "pypi"])
    parser.add_argument("name")
    parser.add_argument("--version", default=None)
    args = parser.parse_args()

    result = query_package(args.ecosystem, args.name, args.version)
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
