from __future__ import annotations

import hashlib
from pathlib import Path

from app.services.sca_parser import ParsedComponent


MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
    "poetry.lock", "Pipfile.lock", "pom.xml", "go.mod", "go.sum", "gradle.lockfile",
    "Gemfile.lock", "composer.lock", "Cargo.toml", "Cargo.lock", "packages.lock.json",
}


def collect_artifact_hashes(source_path: str, components: list[ParsedComponent]) -> dict[str, object]:
    """Capture reproducible local evidence without uploading package contents."""
    root = Path(source_path).expanduser().resolve()
    files: list[dict[str, object]] = []
    if not root.is_dir():
        return {"status": "unavailable", "files": files, "component_hash_count": 0}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or (path.name not in MANIFEST_NAMES and path.suffix.lower() != ".csproj"):
            continue
        files.append(file_hash(path, root, "dependency_manifest"))
    package_hashes = installed_package_hashes(root, components)
    return {
        "status": "available" if files or package_hashes else "not_found",
        "algorithm": "sha256",
        "files": files,
        "packages": package_hashes,
        "component_hash_count": len(package_hashes),
    }


def source_fingerprint(source_path: str) -> dict[str, object]:
    """Return a stable digest of SCA inputs without retaining source contents."""
    root = Path(source_path).expanduser().resolve()
    if not root.is_dir():
        return {"status": "unavailable", "sha256": None, "file_count": 0}
    candidates = [
        path for path in root.rglob("*")
        if path.is_file() and (path.name in MANIFEST_NAMES or path.suffix.lower() == ".csproj")
        and not any(part in {".git", "node_modules", ".venv", "venv", "target", "dist", "build"} for part in path.parts)
    ]
    digest = hashlib.sha256()
    records: list[dict[str, object]] = []
    for path in sorted(candidates):
        record = file_hash(path, root, "scan_input")
        digest.update(record["path"].encode("utf-8"))
        digest.update(str(record["sha256"]).encode("ascii"))
        records.append(record)
    return {
        "status": "available" if records else "not_found",
        "algorithm": "sha256",
        "sha256": digest.hexdigest() if records else None,
        "file_count": len(records),
        "files": records,
    }


def installed_package_hashes(root: Path, components: list[ParsedComponent]) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    seen: set[str] = set()
    for component in components:
        candidates = artifact_candidates(root, component)
        for path, kind in candidates:
            if not path.is_file():
                continue
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            entry = file_hash(path, root, kind)
            entry.update({"ecosystem": component.ecosystem, "name": component.name, "version": component.version})
            results.append(entry)
    return results


def artifact_candidates(root: Path, component: ParsedComponent) -> list[tuple[Path, str]]:
    if component.ecosystem == "pypi":
        normalized = component.name.lower().replace("-", "_")
        return [
            (record, "python_installed_record")
            for environment in (root / ".venv", root / "venv")
            for record in (environment / "Lib" / "site-packages").glob(f"{normalized}-*.dist-info/RECORD")
        ]
    if component.ecosystem == "npm":
        package_path = root / "node_modules"
        for segment in component.name.split("/"):
            package_path /= segment
        return [(package_path / "package.json", "npm_installed_manifest")]
    if component.ecosystem == "maven" and component.version and ":" in component.name:
        group, artifact = component.name.split(":", 1)
        base = root / ".m2" / "repository" / Path(*group.split(".")) / artifact / component.version
        return [
            (base / f"{artifact}-{component.version}.jar", "maven_local_jar"),
            (base / f"{artifact}-{component.version}.pom", "maven_local_pom"),
        ]
    if component.ecosystem == "go":
        vendor_root = root / "vendor" / Path(*component.name.split("/"))
        return [(vendor_root / "go.mod", "go_vendor_module_manifest")]
    if component.ecosystem == "composer":
        vendor_root = root / "vendor" / Path(*component.name.split("/"))
        return [(vendor_root / "composer.json", "composer_installed_manifest")]
    if component.ecosystem == "cargo":
        vendor_root = root / "vendor" / component.name
        return [(vendor_root / "Cargo.toml", "cargo_vendor_manifest")]
    if component.ecosystem == "gem" and component.version:
        return [(path, "gem_cached_specification") for path in root.glob(f"vendor/bundle/**/gems/{component.name}-{component.version}/*.gemspec")]
    if component.ecosystem == "nuget" and component.version:
        normalized = component.name.lower()
        return [
            (root / ".nuget" / "packages" / normalized / component.version / f"{normalized}.{component.version}.nupkg", "nuget_local_package"),
            (root / "packages" / f"{component.name}.{component.version}.nupkg", "nuget_local_package"),
        ]
    return []


def file_hash(path: Path, root: Path, kind: str) -> dict[str, object]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    try:
        label = path.relative_to(root).as_posix()
    except ValueError:
        label = str(path)
    return {"path": label, "kind": kind, "sha256": digest.hexdigest(), "size": path.stat().st_size}
