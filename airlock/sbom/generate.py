"""
airlock.sbom.generate
======================

Construit un SBOM CycloneDX (format JSON, spec 1.5) pour un paquet ingéré
par airlock.ingest.fetch. Le composant racine correspond au paquet lui-même ;
ses dépendances déclarées (package.json pour npm, PKG-INFO/METADATA pour
PyPI) sont ajoutées comme composants enfants.

On ne cherche pas ici l'exhaustivité d'un `npm ls` ou d'un `pip freeze`
(qui nécessiteraient d'installer réellement le paquet, ce qu'on refuse de
faire hors sandbox) : on se contente de ce qui est déclaré statiquement.
C'est suffisant pour nourrir Trivy et documenter la chaîne de dépendances.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from uuid import uuid4

from cyclonedx.model import ExternalReference, ExternalReferenceType, HashAlgorithm, HashType
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.license import DisjunctiveLicense, LicenseExpression
from cyclonedx.output.json import JsonV1Dot5
from packageurl import PackageURL

from airlock.ingest.fetch import FetchedPackage


def _npm_dependencies(extract_path: Path) -> dict[str, str]:
    pkg_json = extract_path / "package" / "package.json"
    if not pkg_json.exists():
        # certains tarballs npm n'ont pas de sous-dossier "package/"
        pkg_json = extract_path / "package.json"
    if not pkg_json.exists():
        return {}
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return {}
    return {**data.get("dependencies", {}), **data.get("optionalDependencies", {})}


_REQUIRES_DIST_LINE_RE = re.compile(r"^Requires-Dist:\s*(.+)$")
# Ex. d'entrée à parser : "charset-normalizer (<4,>=2)" ou "PySocks (!=1.5.7) ; extra == 'socks'"
_REQUIRES_DIST_ENTRY_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(\(([^)]*)\))?\s*(;.*)?$")


def _parse_requires_dist_entries(entries: list[str]) -> dict[str, str]:
    deps: dict[str, str] = {}
    for entry in entries:
        m = _REQUIRES_DIST_ENTRY_RE.match(entry.strip())
        if not m:
            continue
        name = m.group(1)
        version_spec = (m.group(3) or "*").strip() or "*"
        deps[name] = version_spec
    return deps


def _pypi_dependencies(extract_path: Path, registry_metadata: dict) -> dict[str, str]:
    """
    Résout les dépendances déclarées d'un paquet PyPI.

    Source privilégiée : le champ `requires_dist` de l'API JSON PyPI, qui est
    fiable même pour les anciens paquets dont le sdist ne contient pas cette
    métadonnée statiquement (déclaration dynamique via setup.py). On retombe
    sur un parsing de PKG-INFO/METADATA en secours si l'API ne fournit rien.
    """
    requires_dist = registry_metadata.get("requires_dist")
    if requires_dist:
        return _parse_requires_dist_entries(requires_dist)

    # Fallback : parsing statique des fichiers de métadonnées extraits
    candidates = list(extract_path.rglob("PKG-INFO")) + list(extract_path.rglob("METADATA"))
    for candidate in candidates:
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        entries = [
            m.group(1) for line in text.splitlines()
            if (m := _REQUIRES_DIST_LINE_RE.match(line))
        ]
        if entries:
            return _parse_requires_dist_entries(entries)
    return {}


def _make_purl(ecosystem: str, name: str, version: str) -> PackageURL:
    if ecosystem == "npm":
        return PackageURL(type="npm", name=name, version=version)
    elif ecosystem == "pypi":
        return PackageURL(type="pypi", name=name, version=version)
    raise ValueError(f"Écosystème non supporté pour purl : {ecosystem}")


def build_sbom(pkg: FetchedPackage) -> Bom:
    """Construit l'objet Bom CycloneDX pour le paquet ingéré."""
    bom = Bom()
    bom.metadata.component = root = Component(
        name=pkg.name,
        version=pkg.version,
        type=ComponentType.LIBRARY,
        purl=_make_purl(pkg.ecosystem, pkg.name, pkg.version),
        bom_ref=f"{pkg.ecosystem}:{pkg.name}@{pkg.version}",
    )
    root.hashes.add(HashType(alg=HashAlgorithm.SHA_256, content=pkg.sha256))

    registry_url = (
        f"https://www.npmjs.com/package/{pkg.name}/v/{pkg.version}"
        if pkg.ecosystem == "npm"
        else f"https://pypi.org/project/{pkg.name}/{pkg.version}/"
    )
    root.external_references.add(
        ExternalReference(type=ExternalReferenceType.DISTRIBUTION, url=registry_url)
    )

    license_expr = None
    if pkg.ecosystem == "npm":
        license_expr = pkg.registry_metadata.get("license")
        deps = _npm_dependencies(pkg.extract_path)
    else:
        license_expr = pkg.registry_metadata.get("license")
        deps = _pypi_dependencies(pkg.extract_path, pkg.registry_metadata)

    if license_expr and isinstance(license_expr, str):
        try:
            root.licenses.add(LicenseExpression(license_expr))
        except ValueError:
            pass  # expression non parsable (licence libre non SPDX) : on l'ignore proprement

    # NB : le composant racine ne doit PAS être dupliqué dans bom.components
    # (il vit uniquement dans bom.metadata.component selon la spec CycloneDX 1.5) ;
    # l'ajouter en double provoquait une réécriture du bom-ref par le sérialiseur.

    for dep_name, dep_range in deps.items():
        dep_ref = f"{pkg.ecosystem}:{dep_name}@{dep_range}"
        dep_component = Component(
            name=dep_name,
            version=dep_range,  # on garde le range déclaré, pas de résolution ici
            type=ComponentType.LIBRARY,
            bom_ref=dep_ref,
        )
        bom.components.add(dep_component)
        bom.register_dependency(root, [dep_component])

    return bom


def sbom_to_json(bom: Bom) -> str:
    return JsonV1Dot5(bom).output_as_string(indent=2)


def generate_sbom_file(pkg: FetchedPackage, output_dir: Path) -> Path:
    """Génère le SBOM et l'écrit sur disque, retourne le chemin du fichier."""
    output_dir.mkdir(parents=True, exist_ok=True)
    bom = build_sbom(pkg)
    out_path = output_dir / f"{pkg.name.replace('/', '__')}-{pkg.version}.cdx.json"
    out_path.write_text(sbom_to_json(bom), encoding="utf-8")
    return out_path


if __name__ == "__main__":
    import argparse
    import sys

    from airlock.ingest.fetch import fetch_package

    parser = argparse.ArgumentParser(description="Génère un SBOM CycloneDX pour un paquet npm/PyPI")
    parser.add_argument("ecosystem", choices=["npm", "pypi"])
    parser.add_argument("name")
    parser.add_argument("--version", default=None)
    parser.add_argument("--out", default="./sbom_out")
    args = parser.parse_args()

    pkg = fetch_package(args.ecosystem, args.name, args.version)
    out_path = generate_sbom_file(pkg, Path(args.out))
    print(f"SBOM écrit : {out_path}", file=sys.stderr)
    print(out_path.read_text())
