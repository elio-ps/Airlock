"""
airlock.ingest.fetch
=====================

Récupère un paquet (npm ou PyPI) depuis son registre officiel et l'extrait
dans un répertoire de travail isolé, prêt à être analysé par les étages
suivants du pipeline (SBOM, Trivy, GuardDog, deps.dev).

Ce module ne fait AUCUNE exécution de code du paquet : il se contente de
télécharger l'archive et de l'extraire sur disque. L'exécution éventuelle
(post-install, etc.) est du ressort de l'étage de détonation (sandbox),
volontairement séparé.
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

# Un User-Agent explicite : bonne pratique vis-à-vis des registres,
# et ça permet de tracer nos requêtes côté serveur si besoin.
USER_AGENT = "airlock-scanner/0.1 (projet-etudiant; +https://example.local)"

DEFAULT_TIMEOUT = 20  # secondes, évite qu'un registre lent bloque tout le pipeline


class FetchError(Exception):
    """Erreur lors de la récupération ou de l'extraction d'un paquet."""


@dataclass
class FetchedPackage:
    """Résultat de l'ingestion : où est le paquet, et ce qu'on sait de lui."""

    name: str
    version: str
    ecosystem: Ecosystem
    archive_path: Path
    extract_path: Path
    sha256: str
    registry_metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "archive_path": str(self.archive_path),
            "extract_path": str(self.extract_path),
            "sha256": self.sha256,
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
            raise FetchError(f"Téléchargement échoué ({r.status_code}) : {url}")
        with open(dest, "wb") as f:
            shutil.copyfileobj(r.raw, f)


def _safe_extract_tar(archive: Path, dest: Path) -> None:
    """Extraction tar avec protection basique contre le path traversal (Zip Slip)."""
    with tarfile.open(archive, "r:*") as tar:
        for member in tar.getmembers():
            member_path = (dest / member.name).resolve()
            if not str(member_path).startswith(str(dest.resolve())):
                raise FetchError(f"Chemin suspect dans l'archive (path traversal) : {member.name}")
        tar.extractall(dest)  # noqa: S202 - chemins déjà validés ci-dessus


def _safe_extract_zip(archive: Path, dest: Path) -> None:
    with zipfile.ZipFile(archive) as z:
        for name in z.namelist():
            member_path = (dest / name).resolve()
            if not str(member_path).startswith(str(dest.resolve())):
                raise FetchError(f"Chemin suspect dans l'archive (path traversal) : {name}")
        z.extractall(dest)


def fetch_npm(name: str, version: str | None, workdir: Path) -> FetchedPackage:
    """Télécharge un paquet npm (tarball .tgz) et l'extrait."""
    meta_url = f"{NPM_REGISTRY}/{name}"
    resp = requests.get(meta_url, headers={"User-Agent": USER_AGENT}, timeout=DEFAULT_TIMEOUT)
    if resp.status_code != 200:
        raise FetchError(f"Paquet npm introuvable : {name} ({resp.status_code})")
    meta = resp.json()

    if version is None:
        version = meta.get("dist-tags", {}).get("latest")
        if not version:
            raise FetchError(f"Impossible de résoudre la version 'latest' pour {name}")

    version_meta = meta.get("versions", {}).get(version)
    if version_meta is None:
        raise FetchError(f"Version {version} introuvable pour le paquet npm {name}")

    tarball_url = version_meta["dist"]["tarball"]
    expected_shasum = version_meta["dist"].get("shasum")

    archive_path = workdir / f"{name.replace('/', '__')}-{version}.tgz"
    _download(tarball_url, archive_path)

    # Vérification d'intégrité vis-à-vis du registre (pas une garantie de sûreté,
    # juste une preuve que l'archive n'a pas été altérée en transit).
    if expected_shasum:
        sha1 = hashlib.sha1(archive_path.read_bytes()).hexdigest()  # noqa: S324 - format imposé par npm
        if sha1 != expected_shasum:
            raise FetchError(
                f"Intégrité invalide pour {name}@{version} : shasum ne correspond pas au registre"
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
    """Télécharge un paquet PyPI (sdist si possible, sinon wheel) et l'extrait."""
    meta_url = f"{PYPI_REGISTRY}/{name}/json" if version is None else f"{PYPI_REGISTRY}/{name}/{version}/json"
    resp = requests.get(meta_url, headers={"User-Agent": USER_AGENT}, timeout=DEFAULT_TIMEOUT)
    if resp.status_code != 200:
        raise FetchError(f"Paquet PyPI introuvable : {name}=={version} ({resp.status_code})")
    meta = resp.json()

    resolved_version = meta["info"]["version"]
    releases = meta.get("urls", [])
    if not releases:
        raise FetchError(f"Aucune release téléchargeable pour {name}=={resolved_version}")

    # Préférence : sdist (.tar.gz) car il contient le code source complet,
    # y compris les scripts setup.py potentiellement malveillants.
    # Fallback : wheel (.whl, qui est un zip).
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
                f"Intégrité invalide pour {name}=={resolved_version} : sha256 ne correspond pas au registre"
            )

    extract_path = workdir / f"{name}-{resolved_version}"
    extract_path.mkdir(parents=True, exist_ok=True)

    if filename.endswith((".tar.gz", ".tgz")):
        _safe_extract_tar(archive_path, extract_path)
    elif filename.endswith(".zip") or filename.endswith(".whl"):
        _safe_extract_zip(archive_path, extract_path)
    else:
        raise FetchError(f"Format d'archive non géré : {filename}")

    return FetchedPackage(
        name=name,
        version=resolved_version,
        ecosystem="pypi",
        archive_path=archive_path,
        extract_path=extract_path,
        sha256=_sha256_of(archive_path),
        registry_metadata=meta["info"],
    )


def fetch_package(ecosystem: Ecosystem, name: str, version: str | None = None,
                   workdir: Path | None = None) -> FetchedPackage:
    """Point d'entrée unique : télécharge et extrait un paquet npm ou PyPI."""
    workdir = workdir or Path(tempfile.mkdtemp(prefix="airlock-"))
    workdir.mkdir(parents=True, exist_ok=True)

    if ecosystem == "npm":
        return fetch_npm(name, version, workdir)
    elif ecosystem == "pypi":
        return fetch_pypi(name, version, workdir)
    else:
        raise ValueError(f"Écosystème non supporté : {ecosystem}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Télécharge et extrait un paquet npm/PyPI")
    parser.add_argument("ecosystem", choices=["npm", "pypi"])
    parser.add_argument("name")
    parser.add_argument("--version", default=None)
    args = parser.parse_args()

    pkg = fetch_package(args.ecosystem, args.name, args.version)
    print(json.dumps(pkg.to_dict(), indent=2, ensure_ascii=False))
