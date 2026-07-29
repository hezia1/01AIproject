from __future__ import annotations

import hashlib
from pathlib import Path

from app.services.sca_parser import ParsedComponent


MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
    "poetry.lock", "Pipfile.lock", "pom.xml", "go.mod", "go.sum",
}


def collect_artifact_hashes(source_path: str, components: list[ParsedComponent]) -> dict[str, object]:
    """Capture reproducible local evidence without uploading package contents."""
    root = Path(source_path).expanduser().resolve()
    files: list[dict[str, object]] = []
    if not root.is_dir():
        return {"status": "unavailable", "files": files, "component_hash_count": 0}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name not in MANIFEST_NAMES:
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


def installed_package_hashes(root: Path, components: list[ParsedComponent]) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    seen: set[str] = set()
    for component in components:
        if component.ecosystem != "pypi":
            continue
        normalized = component.name.lower().replace("-", "_")
        for environment in (root / ".venv", root / "venv"):
            site_packages = environment / "Lib" / "site-packages"
            if not site_packages.is_dir():
                continue
            candidates = list(site_packages.glob(f"{normalized}-*.dist-info/RECORD"))
            for record in candidates[:1]:
                key = str(record.resolve())
                if key in seen:
                    continue
                seen.add(key)
                entry = file_hash(record, root, "installed_package_record")
                entry.update({"ecosystem": component.ecosystem, "name": component.name, "version": component.version})
                results.append(entry)
    return results


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
