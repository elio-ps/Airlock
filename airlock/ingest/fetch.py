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

import base64
import hashlib
import json
import re
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import quote

import requests

Ecosystem = Literal["npm", "pypi"]

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org/pypi"

# An explicit User-Agent is good practice towards registries and makes our
# requests traceable server-side.
USER_AGENT = "airlock-scanner/0.1 (student-project; +https://example.local)"

DEFAULT_TIMEOUT = 20  # seconds, so that a slow registry cannot stall the pipeline

# Limits against archive bombs: packages are untrusted input.
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 50_000

# npm runs these scripts automatically on `npm install`.
NPM_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")


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
    registry_package_info: dict | None = None  # full registry document, for GuardDog metadata rules

    @property
    def source_root(self) -> Path:
        """Directory that actually holds the package files (npm: `package/`)."""
        candidate = self.extract_path / "package"
        return candidate if candidate.is_dir() else self.extract_path

    @property
    def install_hooks(self) -> list[str]:
        """Code that runs at install time, before the developer runs anything."""
        if self.ecosystem == "npm":
            return _npm_install_hooks(self.source_root)
        return _pypi_install_hooks(self.extract_path)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "archive_path": str(self.archive_path),
            "extract_path": str(self.extract_path),
            "sha256": self.sha256,
            "origin": self.origin,
            "install_hooks": self.install_hooks,
        }


def _npm_install_hooks(root: Path) -> list[str]:
    try:
        data = json.loads((root / "package.json").read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return []
    scripts = data.get("scripts") if isinstance(data, dict) else None
    scripts = scripts if isinstance(scripts, dict) else {}
    hooks = [f"{name}: {scripts[name]}" for name in NPM_INSTALL_SCRIPTS if name in scripts]
    # Without an install script, npm implicitly runs node-gyp when binding.gyp exists.
    if "install" not in scripts and (root / "binding.gyp").is_file():
        hooks.append("install: node-gyp rebuild (implicit, binding.gyp)")
    return hooks


def _pypi_install_hooks(extract_path: Path) -> list[str]:
    # An sdist with a setup.py runs arbitrary code when built. Wheels never do.
    found = [*extract_path.glob("setup.py"), *extract_path.glob("*/setup.py")]
    return ["setup.py"] if found else []


def safe_slug(value: str) -> str:
    """Make a registry-controlled string safe to use as a single path component."""
    slug = re.sub(r"[^A-Za-z0-9._+-]", "__", value).lstrip(".")
    return slug or "unnamed"


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
        written = 0
        with open(dest, "wb") as f:
            for chunk in r.iter_content(chunk_size=65536):
                written += len(chunk)
                if written > MAX_ARCHIVE_BYTES:
                    raise FetchError(f"Archive larger than {MAX_ARCHIVE_BYTES} bytes: {url}")
                f.write(chunk)


def _safe_extract_tar(archive: Path, dest: Path) -> None:
    """Extract regular files and directories only, refusing traversal and bombs."""
    try:
        with tarfile.open(archive, "r:*") as tar:
            members = tar.getmembers()
            _check_archive_size(archive, len(members), sum(m.size for m in members if m.isfile()))
            for member in members:
                _check_member_path(dest, member.name)
            # Links and device nodes are dropped: they are how an archive escapes
            # `dest` after a first, seemingly harmless, member.
            regular = [m for m in members if m.isfile() or m.isdir()]
            tar.extractall(dest, members=regular, filter="data")
    except (tarfile.TarError, OSError, EOFError) as e:
        raise FetchError(f"Unreadable archive: {archive.name} ({e})") from e


def _safe_extract_zip(archive: Path, dest: Path) -> None:
    try:
        with zipfile.ZipFile(archive) as z:
            infos = z.infolist()
            _check_archive_size(archive, len(infos), sum(i.file_size for i in infos))
            for info in infos:
                _check_member_path(dest, info.filename)
            z.extractall(dest)
    except (zipfile.BadZipFile, OSError) as e:
        raise FetchError(f"Unreadable archive: {archive.name} ({e})") from e


def _check_member_path(dest: Path, name: str) -> None:
    if not (dest / name).resolve().is_relative_to(dest.resolve()):
        raise FetchError(f"Suspicious path in archive (path traversal): {name}")


def _check_archive_size(archive: Path, member_count: int, total_bytes: int) -> None:
    if member_count > MAX_ARCHIVE_MEMBERS or total_bytes > MAX_EXTRACTED_BYTES:
        raise FetchError(
            f"Archive refused (possible bomb): {archive.name} has {member_count} members "
            f"and {total_bytes} bytes once extracted"
        )


def fetch_npm(name: str, version: str | None, workdir: Path) -> FetchedPackage:
    """Download an npm package (.tgz tarball) and extract it."""
    meta_url = f"{NPM_REGISTRY}/{quote(name, safe='@')}"  # scoped: @scope%2Fname
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
    expected_integrity = version_meta["dist"].get("integrity", "")
    expected_shasum = version_meta["dist"].get("shasum")

    archive_path = workdir / f"{safe_slug(name)}-{safe_slug(version)}.tgz"
    _download(tarball_url, archive_path)

    # Integrity check against the registry (not a safety guarantee, only proof
    # that the archive was not altered in transit).
    if expected_integrity.startswith("sha512-"):
        digest = base64.b64encode(hashlib.sha512(archive_path.read_bytes()).digest()).decode()
        if digest != expected_integrity.removeprefix("sha512-"):
            raise FetchError(
                f"Integrity failure for {name}@{version}: sha512 does not match the registry"
            )
    elif expected_shasum:
        sha1 = hashlib.sha1(archive_path.read_bytes()).hexdigest()  # noqa: S324 - format imposed by npm
        if sha1 != expected_shasum:
            raise FetchError(
                f"Integrity failure for {name}@{version}: shasum does not match the registry"
            )

    extract_path = workdir / f"{safe_slug(name)}-{safe_slug(version)}"
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
        registry_package_info=meta,
    )


def fetch_pypi(name: str, version: str | None, workdir: Path) -> FetchedPackage:
    """Download a PyPI package (sdist when possible, else a wheel) and extract it."""
    quoted = quote(name, safe="")
    meta_url = (
        f"{PYPI_REGISTRY}/{quoted}/json" if version is None
        else f"{PYPI_REGISTRY}/{quoted}/{quote(version, safe='')}/json"
    )
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
    filename = Path(chosen["filename"]).name  # registry-controlled: keep the basename only

    archive_path = workdir / filename
    _download(file_url, archive_path)

    if expected_sha256:
        actual = _sha256_of(archive_path)
        if actual != expected_sha256:
            raise FetchError(
                f"Integrity failure for {name}=={resolved_version}: sha256 does not match the registry"
            )

    extract_path = workdir / f"{safe_slug(name)}-{safe_slug(resolved_version)}"
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
        registry_package_info=meta,
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
    _safe_extract_tar(archive, extract_path)

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

    try:
        if ecosystem == "npm":
            return fetch_npm(name, version, workdir)
        if ecosystem == "pypi":
            return fetch_pypi(name, version, workdir)
    except requests.RequestException as e:
        raise FetchError(f"Registry unreachable for {name}: {e}") from e
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
