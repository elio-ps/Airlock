"""
airlock.ingest.fetch
=====================

Fetches a package (npm or PyPI) from its official registry and extracts it
into an isolated working directory, ready for the next pipeline stages (SBOM,
Trivy, GuardDog, deps.dev).

This module NEVER runs package code: it only downloads and extracts the
archive. Execution (post-install, etc.) belongs to the detonation stage,
which is deliberately separate.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import requests

Ecosystem = Literal["npm", "pypi"]

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org/pypi"

# An explicit User-Agent is good practice towards registries and makes our
# requests traceable server-side.
USER_AGENT = "airlock-scanner/0.1 (student-project; +https://example.local)"

DEFAULT_TIMEOUT = 20  # seconds, so that a slow registry cannot stall the pipeline


class FetchError(Exception):
    """Error while fetching or extracting a package."""


@dataclass
class FetchedPackage:
    """Ingestion result: where the package is and what is known about it."""

    name: str
    version: str
    ecosystem: Ecosystem
    archive_path: Path
    extract_path: Path
    sha256: str
    registry_metadata: dict = field(default_factory=dict)
    origin: str = "registry"  # "registry" (downloaded) or "local" (archive provided)

    @property
    def source_root(self) -> Path:
        """Directory that actually holds the package files (npm: `package/`)."""
        candidate = self.extract_path / "package"
        return candidate if candidate.is_dir() else self.extract_path

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "archive_path": str(self.archive_path),
            "extract_path": str(self.extract_path),
            "sha256": self.sha256,
            "origin": self.origin,
        }


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path) -> None:
    headers = {"User-Agent": USER_AGENT}
    with requests.get(url, headers=headers, stream=True, timeout=DEFAULT_TIMEOUT) as r:
        if r.status_code != 200:
            raise FetchError(f"Download failed ({r.status_code}): {url}")
        with open(dest, "wb") as f:
            shutil.copyfileobj(r.raw, f)


def _safe_extract_tar(archive: Path, dest: Path) -> None:
    """Tar extraction with basic path traversal (Zip Slip) protection."""
    with tarfile.open(archive, "r:*") as tar:
        for member in tar.getmembers():
            member_path = (dest / member.name).resolve()
            if not str(member_path).startswith(str(dest.resolve())):
                raise FetchError(f"Suspicious path in archive (path traversal): {member.name}")
        tar.extractall(dest)  # noqa: S202 - paths validated above


def _safe_extract_zip(archive: Path, dest: Path) -> None:
    with zipfile.ZipFile(archive) as z:
        for name in z.namelist():
            member_path = (dest / name).resolve()
            if not str(member_path).startswith(str(dest.resolve())):
                raise FetchError(f"Suspicious path in archive (path traversal): {name}")
        z.extractall(dest)


def fetch_npm(name: str, version: str | None, workdir: Path) -> FetchedPackage:
    """Download an npm package (.tgz tarball) and extract it."""
    meta_url = f"{NPM_REGISTRY}/{name}"
    resp = requests.get(meta_url, headers={"User-Agent": USER_AGENT}, timeout=DEFAULT_TIMEOUT)
    if resp.status_code != 200:
        raise FetchError(f"npm package not found: {name} ({resp.status_code})")
    meta = resp.json()

    if version is None:
        version = meta.get("dist-tags", {}).get("latest")
        if not version:
            raise FetchError(f"Cannot resolve the 'latest' version of {name}")

    version_meta = meta.get("versions", {}).get(version)
    if version_meta is None:
        raise FetchError(f"Version {version} not found for npm package {name}")

    tarball_url = version_meta["dist"]["tarball"]
    expected_shasum = version_meta["dist"].get("shasum")

    archive_path = workdir / f"{name.replace('/', '__')}-{version}.tgz"
    _download(tarball_url, archive_path)

    # Integrity check against the registry (not a safety guarantee, only proof
    # that the archive was not altered in transit).
    if expected_shasum:
        sha1 = hashlib.sha1(archive_path.read_bytes()).hexdigest()  # noqa: S324 - format imposed by npm
        if sha1 != expected_shasum:
            raise FetchError(
                f"Integrity failure for {name}@{version}: shasum does not match the registry"
            )

    extract_path = workdir / f"{name.replace('/', '__')}-{version}"
    extract_path.mkdir(parents=True, exist_ok=True)
    _safe_extract_tar(archive_path, extract_path)

    return FetchedPackage(
        name=name,
        version=version,
        ecosystem="npm",
        archive_path=archive_path,
        extract_path=extract_path,
        sha256=_sha256_of(archive_path),
        registry_metadata=version_meta,
    )


def fetch_pypi(name: str, version: str | None, workdir: Path) -> FetchedPackage:
    """Download a PyPI package (sdist when possible, else a wheel) and extract it."""
    meta_url = f"{PYPI_REGISTRY}/{name}/json" if version is None else f"{PYPI_REGISTRY}/{name}/{version}/json"
    resp = requests.get(meta_url, headers={"User-Agent": USER_AGENT}, timeout=DEFAULT_TIMEOUT)
    if resp.status_code != 200:
        raise FetchError(f"PyPI package not found: {name}=={version} ({resp.status_code})")
    meta = resp.json()

    resolved_version = meta["info"]["version"]
    releases = meta.get("urls", [])
    if not releases:
        raise FetchError(f"No downloadable release for {name}=={resolved_version}")

    # Prefer the sdist (.tar.gz): it holds the full source code, including
    # potentially malicious setup.py scripts. Fallback: wheel (.whl, a zip).
    sdist = next((r for r in releases if r["packagetype"] == "sdist"), None)
    chosen = sdist or releases[0]

    file_url = chosen["url"]
    expected_sha256 = chosen.get("digests", {}).get("sha256")
    filename = chosen["filename"]

    archive_path = workdir / filename
    _download(file_url, archive_path)

    if expected_sha256:
        actual = _sha256_of(archive_path)
        if actual != expected_sha256:
            raise FetchError(
                f"Integrity failure for {name}=={resolved_version}: sha256 does not match the registry"
            )

    extract_path = workdir / f"{name}-{resolved_version}"
    extract_path.mkdir(parents=True, exist_ok=True)

    if filename.endswith((".tar.gz", ".tgz")):
        _safe_extract_tar(archive_path, extract_path)
    elif filename.endswith(".zip") or filename.endswith(".whl"):
        _safe_extract_zip(archive_path, extract_path)
    else:
        raise FetchError(f"Unsupported archive format: {filename}")

    return FetchedPackage(
        name=name,
        version=resolved_version,
        ecosystem="pypi",
        archive_path=archive_path,
        extract_path=extract_path,
        sha256=_sha256_of(archive_path),
        registry_metadata=meta["info"],
    )


def fetch_local(ecosystem: Ecosystem, archive: Path, workdir: Path | None = None) -> FetchedPackage:
    """
    Ingest a LOCAL archive (e.g. from `npm pack --ignore-scripts`) instead of
    downloading it. Useful to test the pipeline on an unpublished package.

    Same safeguards as network ingestion: no code execution, extraction
    protected against path traversal. There is no registry checksum to compare
    with; the archive sha256 is recorded for traceability. npm only for now.
    """
    if ecosystem != "npm":
        raise FetchError("Local ingestion: only the npm ecosystem is supported for now")

    archive = Path(archive)
    if not archive.is_file():
        raise FetchError(f"Local archive not found: {archive}")
    if not archive.name.endswith((".tgz", ".tar.gz")):
        raise FetchError(f"npm archive expected (.tgz / .tar.gz): {archive.name}")

    workdir = workdir or Path(tempfile.mkdtemp(prefix="airlock-"))
    workdir.mkdir(parents=True, exist_ok=True)

    stem = archive.name.removesuffix(".tgz").removesuffix(".tar.gz")
    extract_path = workdir / stem
    extract_path.mkdir(parents=True, exist_ok=True)
    try:
        _safe_extract_tar(archive, extract_path)
    except tarfile.TarError as e:
        raise FetchError(f"Unreadable archive: {archive} ({e})") from e

    pkg_json = extract_path / "package" / "package.json"
    if not pkg_json.exists():
        pkg_json = extract_path / "package.json"
    if not pkg_json.exists():
        raise FetchError(f"package.json not found in archive: {archive.name}")
    try:
        meta = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError as e:
        raise FetchError(f"Invalid package.json in {archive.name}: {e}") from e

    name, version = meta.get("name"), meta.get("version")
    if not name or not version:
        raise FetchError(f"'name' and 'version' are required in the package.json of {archive.name}")

    return FetchedPackage(
        name=name,
        version=version,
        ecosystem="npm",
        archive_path=archive.resolve(),
        extract_path=extract_path,
        sha256=_sha256_of(archive),
        registry_metadata=meta,
        origin="local",
    )


def fetch_package(ecosystem: Ecosystem, name: str, version: str | None = None,
                   workdir: Path | None = None) -> FetchedPackage:
    """Single entry point: download and extract an npm or PyPI package."""
    workdir = workdir or Path(tempfile.mkdtemp(prefix="airlock-"))
    workdir.mkdir(parents=True, exist_ok=True)

    if ecosystem == "npm":
        return fetch_npm(name, version, workdir)
    elif ecosystem == "pypi":
        return fetch_pypi(name, version, workdir)
    else:
        raise ValueError(f"Unsupported ecosystem: {ecosystem}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Download and extract an npm/PyPI package")
    parser.add_argument("ecosystem", choices=["npm", "pypi"])
    parser.add_argument("name")
    parser.add_argument("--version", default=None)
    args = parser.parse_args()

    pkg = fetch_package(args.ecosystem, args.name, args.version)
    print(json.dumps(pkg.to_dict(), indent=2, ensure_ascii=False))
