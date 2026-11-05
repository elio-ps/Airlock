"""
airlock.sbom.generate
======================

Builds a CycloneDX SBOM (JSON, spec 1.5) for a package ingested by
airlock.ingest.fetch. The root component is the package itself; its declared
dependencies (package.json for npm, PKG-INFO/METADATA for PyPI) are added as
child components.

This is not as exhaustive as `npm ls` or `pip freeze`, which would require
installing the package, something refused outside the sandbox: only what is
statically declared is used.
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

from airlock.ingest.fetch import FetchedPackage, safe_slug


def _npm_dependencies(extract_path: Path) -> dict[str, str]:
    pkg_json = extract_path / "package" / "package.json"
    if not pkg_json.exists():
        # some npm tarballs have no "package/" subdirectory
        pkg_json = extract_path / "package.json"
    if not pkg_json.exists():
        return {}
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return {}
    return {**data.get("dependencies", {}), **data.get("optionalDependencies", {})}


_REQUIRES_DIST_LINE_RE = re.compile(r"^Requires-Dist:\s*(.+)$")
# Example entries: "charset-normalizer (<4,>=2)" or "PySocks (!=1.5.7) ; extra == 'socks'"
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
    Resolve the declared dependencies of a PyPI package.

    Preferred source: the `requires_dist` field of the PyPI JSON API, reliable
    even for old packages whose sdist lacks this metadata (dynamic declaration
    in setup.py). Falls back to parsing PKG-INFO/METADATA.
    """
    requires_dist = registry_metadata.get("requires_dist")
    if requires_dist:
        return _parse_requires_dist_entries(requires_dist)

    # Fallback: static parsing of the extracted metadata files
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
        namespace, _, short_name = name.rpartition("/")  # "@scope/pkg" or "pkg"
        return PackageURL(type="npm", namespace=namespace or None, name=short_name, version=version)
    elif ecosystem == "pypi":
        return PackageURL(type="pypi", name=name, version=version)
    raise ValueError(f"Ecosystem not supported for purl: {ecosystem}")


def build_sbom(pkg: FetchedPackage, resolved: list[tuple[str, str]] | None = None) -> Bom:
    """
    Build the CycloneDX Bom object for the ingested package.

    `resolved` is the resolved dependency graph (see depsdev.resolved_dependencies).
    Only exact versions can carry a purl, and Trivy ignores components without
    one: declared ranges are an inventory, not something a CVE scanner can match.
    """
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
            pass  # unparsable expression (free-form, non-SPDX license): ignore it

    # The root component must NOT be duplicated in bom.components: per the
    # CycloneDX 1.5 spec it only lives in bom.metadata.component, and adding it
    # twice made the serializer rewrite its bom-ref.

    if resolved is not None:
        components = [
            Component(
                name=dep_name, version=dep_version, type=ComponentType.LIBRARY,
                purl=_make_purl(pkg.ecosystem, dep_name, dep_version),
                bom_ref=f"{pkg.ecosystem}:{dep_name}@{dep_version}",
            )
            for dep_name, dep_version in resolved
        ]
    else:
        components = [
            Component(
                name=dep_name, version=dep_range, type=ComponentType.LIBRARY,
                bom_ref=f"{pkg.ecosystem}:{dep_name}@{dep_range}",
            )
            for dep_name, dep_range in deps.items()
        ]

    for component in components:
        bom.components.add(component)
    bom.register_dependency(root, components)

    return bom


def sbom_to_json(bom: Bom) -> str:
    return JsonV1Dot5(bom).output_as_string(indent=2)


def generate_sbom_file(pkg: FetchedPackage, output_dir: Path,
                       resolved: list[tuple[str, str]] | None = None) -> Path:
    """Generate the SBOM, write it to disk and return the file path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    bom = build_sbom(pkg, resolved)
    out_path = output_dir / f"{safe_slug(pkg.name)}-{safe_slug(pkg.version)}.cdx.json"
    out_path.write_text(sbom_to_json(bom), encoding="utf-8")
    return out_path


if __name__ == "__main__":
    import argparse
    import sys

    from airlock.ingest.fetch import fetch_package

    parser = argparse.ArgumentParser(description="Generate a CycloneDX SBOM for an npm/PyPI package")
    parser.add_argument("ecosystem", choices=["npm", "pypi"])
    parser.add_argument("name")
    parser.add_argument("--version", default=None)
    parser.add_argument("--out", default="./sbom_out")
    args = parser.parse_args()

    pkg = fetch_package(args.ecosystem, args.name, args.version)
    out_path = generate_sbom_file(pkg, Path(args.out))
    print(f"SBOM written: {out_path}", file=sys.stderr)
    print(out_path.read_text())
