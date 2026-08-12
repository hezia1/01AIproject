from __future__ import annotations

import json
import os
import re
import shutil
import stat
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path, PurePosixPath
from uuid import uuid4


STAGING_SCHEMA = "ai-security-platform.agent-filtered-staging/v1"
MANIFEST_NAME = ".agent-staging-manifest.json"
MAX_STAGING_FILES = 5_000
MAX_STAGING_BYTES = 50 * 1024 * 1024
MAX_STAGING_FILE_BYTES = 5 * 1024 * 1024
MAX_EXCLUSION_RECORDS = 1_000
MAX_DISCOVERED_ENTRIES = 20_000

EXCLUDED_DIRECTORY_NAMES = {
    ".git", ".svn", ".hg", ".ssh", ".aws", ".azure", ".kube",
    "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".cache", "dist", "build", "coverage",
    "outputs", "artifacts",
}
SENSITIVE_NAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    "id_rsa", "id_ed25519", "credentials", "credentials.json",
    "secrets.json", "secret.json", ".npmrc", ".pypirc", ".netrc",
}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".kdbx"}
SECRET_CONTENT_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("private-key-content", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key-content", re.compile(rb"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")),
    (
        "credential-assignment-content",
        re.compile(
            rb"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)"
            rb"\s*[=:]\s*[\"']?[A-Za-z0-9_./+=-]{16,}"
        ),
    ),
)


def build_filtered_staging(
    *,
    source_path: str,
    project_id: str,
    destination_root: Path,
    binding: dict[str, object] | None = None,
) -> dict[str, object]:
    source = resolve_source_directory(source_path)
    project_root = destination_root.resolve(strict=False)
    validate_destination_root(project_root)
    candidates, exclusions, excluded_count = collect_staging_candidates(source, project_root)
    build_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:10]}"
    temporary = project_root / f".{build_id}.building"
    destination = project_root / build_id
    project_root.mkdir(parents=True, exist_ok=True)
    if temporary.exists() or destination.exists():
        raise ValueError("A staging build path collision was detected; no files were copied.")

    temporary.mkdir()
    entries: list[dict[str, object]] = []
    renamed = False
    try:
        for candidate in candidates:
            copied = copy_verified_file(source, temporary, candidate)
            if copied.get("excluded_reason"):
                excluded_count += 1
                append_exclusion(exclusions, str(candidate["path"]), str(copied["excluded_reason"]))
                continue
            entries.append(copied)

        payload_sha256 = staging_payload_sha256(entries)
        manifest: dict[str, object] = {
            "schema": STAGING_SCHEMA,
            "status": "ready",
            "build_id": build_id,
            "project_id": project_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_path": str(source),
            "destination_path": str(destination),
            "staging_sha256": payload_sha256,
            "limits": {
                "max_files": MAX_STAGING_FILES,
                "max_total_bytes": MAX_STAGING_BYTES,
                "max_file_bytes": MAX_STAGING_FILE_BYTES,
                "max_discovered_entries": MAX_DISCOVERED_ENTRIES,
            },
            "summary": {
                "copied_file_count": len(entries),
                "copied_bytes": sum(int(item["size"]) for item in entries),
                "excluded_count": excluded_count,
                "exclusion_records_truncated": excluded_count > len(exclusions),
                "runtime_executed": False,
            },
            "files": entries,
            "exclusions": exclusions,
            "security": {
                "links_followed": False,
                "secret_values_returned": False,
                "existing_destination_overwritten": False,
                "container_or_agent_executed": False,
            },
            "binding": normalized_staging_binding(binding),
        }
        manifest["manifest_sha256"] = manifest_sha256(manifest)
        (temporary / MANIFEST_NAME).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        verify_filtered_staging(temporary)
        temporary.rename(destination)
        renamed = True
        verified = verify_filtered_staging(destination)
        return {**manifest, "verification": verified}
    except Exception:
        cleanup_temporary_directory(temporary, project_root)
        if renamed:
            cleanup_created_build(destination, project_root, build_id)
        raise


def collect_staging_candidates(
    source: Path,
    destination_root: Path,
) -> tuple[list[dict[str, object]], list[dict[str, str]], int]:
    candidates: list[dict[str, object]] = []
    exclusions: list[dict[str, str]] = []
    excluded_count = 0
    discovered_entries = 0
    total_bytes = 0
    casefolded_paths: set[str] = set()

    def exclude(path: str, reason: str) -> None:
        nonlocal excluded_count
        excluded_count += 1
        append_exclusion(exclusions, path, reason)

    for current_root, directories, files in os.walk(source, followlinks=False):
        current = Path(current_root)
        retained: list[str] = []
        for name in sorted(directories):
            discovered_entries += 1
            if discovered_entries > MAX_DISCOVERED_ENTRIES:
                raise ValueError(f"Staging discovery exceeds the {MAX_DISCOVERED_ENTRIES}-entry limit.")
            candidate = current / name
            relative = portable_relative_path(candidate, source)
            if name.casefold() in EXCLUDED_DIRECTORY_NAMES:
                exclude(relative, "excluded-directory")
            elif path_is_within(candidate, destination_root):
                exclude(relative, "staging-destination-boundary")
            elif is_link_or_junction(candidate):
                exclude(relative, "link-or-junction")
            else:
                retained.append(name)
        directories[:] = retained
        for name in sorted(files):
            discovered_entries += 1
            if discovered_entries > MAX_DISCOVERED_ENTRIES:
                raise ValueError(f"Staging discovery exceeds the {MAX_DISCOVERED_ENTRIES}-entry limit.")
            candidate = current / name
            relative = portable_relative_path(candidate, source)
            if is_link_or_junction(candidate):
                exclude(relative, "link-or-junction")
                continue
            sensitive_reason = sensitive_file_reason(name)
            if sensitive_reason:
                exclude(relative, sensitive_reason)
                continue
            resolved = candidate.resolve(strict=True)
            if not path_is_within(resolved, source):
                raise ValueError(f"Staging input escapes the configured source boundary: {relative}")
            metadata = candidate.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"Staging input is not a regular file: {relative}")
            if metadata.st_size > MAX_STAGING_FILE_BYTES:
                raise ValueError(f"Staging file exceeds the {MAX_STAGING_FILE_BYTES}-byte per-file limit: {relative}")
            if len(candidates) + 1 > MAX_STAGING_FILES:
                raise ValueError(f"Staging input exceeds the {MAX_STAGING_FILES}-file limit.")
            total_bytes += metadata.st_size
            if total_bytes > MAX_STAGING_BYTES:
                raise ValueError(f"Staging input exceeds the {MAX_STAGING_BYTES}-byte total limit.")
            collision_key = relative.casefold()
            if collision_key in casefolded_paths:
                raise ValueError(f"Staging contains a case-insensitive path collision: {relative}")
            casefolded_paths.add(collision_key)
            candidates.append({
                "path": relative,
                "source": candidate,
                "size": metadata.st_size,
                "mtime_ns": metadata.st_mtime_ns,
            })
    return candidates, exclusions, excluded_count


def copy_verified_file(source_root: Path, temporary: Path, candidate: dict[str, object]) -> dict[str, object]:
    relative = str(candidate["path"])
    source = Path(candidate["source"])
    if path_has_link_component(source, source_root) or not path_is_within(source.resolve(strict=True), source_root):
        raise ValueError(f"Staging input changed to a link or escaped the source boundary: {relative}")
    before = source.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"Staging input changed to a non-regular file: {relative}")
    if before.st_size != int(candidate["size"]) or before.st_mtime_ns != int(candidate["mtime_ns"]):
        raise ValueError(f"Staging input changed after inventory: {relative}")
    content = source.read_bytes()
    after = source.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(after.st_mode)
        or path_has_link_component(source, source_root)
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
        or len(content) != before.st_size
    ):
        raise ValueError(f"Staging input changed while it was being copied: {relative}")
    secret_signal = secret_content_reason(content)
    if secret_signal:
        return {"path": relative, "excluded_reason": secret_signal}
    target = safe_manifest_target(temporary, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as handle:
        handle.write(content)
    return {"path": relative, "size": len(content), "sha256": sha256(content).hexdigest()}


def verify_filtered_staging(destination: Path) -> dict[str, object]:
    root = destination.resolve(strict=True)
    if not root.is_dir() or is_link_or_junction(root):
        raise ValueError("Filtered staging is missing or is a link/junction.")
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file() or is_link_or_junction(manifest_path):
        raise ValueError("Filtered staging manifest is missing or unsafe.")
    if manifest_path.stat().st_size > MAX_STAGING_FILE_BYTES:
        raise ValueError("Filtered staging manifest exceeds the verification limit.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema") != STAGING_SCHEMA:
        raise ValueError("Filtered staging manifest schema is invalid.")
    if manifest.get("manifest_sha256") != manifest_sha256(manifest):
        raise ValueError("Filtered staging manifest digest does not match.")
    expected_entries = manifest.get("files")
    if not isinstance(expected_entries, list) or len(expected_entries) > MAX_STAGING_FILES:
        raise ValueError("Filtered staging file inventory is invalid.")
    observed_paths: set[str] = set()
    observed_casefolded_paths: set[str] = set()
    verified_entries: list[dict[str, object]] = []
    total_bytes = 0
    for item in expected_entries:
        if not isinstance(item, dict):
            raise ValueError("Filtered staging file entry is invalid.")
        relative = str(item.get("path") or "")
        if relative.casefold() in observed_casefolded_paths:
            raise ValueError(f"Filtered staging manifest contains a duplicate path: {relative}")
        target = safe_manifest_target(root, relative)
        if not target.is_file() or is_link_or_junction(target):
            raise ValueError(f"Filtered staging file is missing or unsafe: {relative}")
        declared_size = int(item.get("size") or -1)
        if declared_size < 0 or declared_size > MAX_STAGING_FILE_BYTES or total_bytes + declared_size > MAX_STAGING_BYTES:
            raise ValueError(f"Filtered staging file inventory exceeds a verification limit: {relative}")
        if target.stat().st_size != declared_size:
            raise ValueError(f"Filtered staging file integrity mismatch: {relative}")
        content = target.read_bytes()
        digest = sha256(content).hexdigest()
        if len(content) != declared_size or digest != item.get("sha256"):
            raise ValueError(f"Filtered staging file integrity mismatch: {relative}")
        total_bytes += len(content)
        observed_paths.add(relative)
        observed_casefolded_paths.add(relative.casefold())
        verified_entries.append({"path": relative, "size": len(content), "sha256": digest})
    actual_paths = {
        portable_relative_path(path, root)
        for path in root.rglob("*")
        if path.is_file() and path.name != MANIFEST_NAME
    }
    if any(is_link_or_junction(path) for path in root.rglob("*")):
        raise ValueError("Filtered staging contains a link or junction.")
    if actual_paths != observed_paths:
        raise ValueError("Filtered staging contains unmanifested or missing files.")
    payload_digest = staging_payload_sha256(verified_entries)
    if payload_digest != manifest.get("staging_sha256"):
        raise ValueError("Filtered staging payload digest does not match.")
    return {
        "status": "verified",
        "staging_sha256": payload_digest,
        "manifest_sha256": manifest.get("manifest_sha256"),
        "file_count": len(verified_entries),
        "total_bytes": total_bytes,
        "runtime_executed": False,
    }


def load_filtered_staging_manifest(destination: Path) -> dict[str, object]:
    root = destination.resolve(strict=True)
    verify_filtered_staging(root)
    manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("Filtered staging manifest is invalid.")
    return manifest


def normalized_staging_binding(value: dict[str, object] | None) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    result = {
        "schema": "ai-security-platform.agent-staging-binding/v1",
        "scan_task_id": str(value.get("scan_task_id") or "")[:100],
        "plan_sha256": str(value.get("plan_sha256") or "")[:64],
        "command_sha256": str(value.get("command_sha256") or "")[:64],
        "image": str(value.get("image") or "")[:300],
        "timeout_seconds": max(1, min(30, int(value.get("timeout_seconds") or 10))),
    }
    for key in ("plan_sha256", "command_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(result[key])):
            raise ValueError(f"Filtered staging {key} binding is invalid.")
    if not result["scan_task_id"] or not result["image"]:
        raise ValueError("Filtered staging execution binding is incomplete.")
    return result


def resolve_source_directory(value: str) -> Path:
    try:
        source = Path(value).resolve(strict=True)
    except OSError as exc:
        raise ValueError("Configured staging source directory does not exist.") from exc
    if not source.is_dir() or is_link_or_junction(source):
        raise ValueError("Configured staging source must be a real directory, not a link or junction.")
    return source


def validate_destination_root(destination: Path) -> None:
    if os.name == "nt" and destination.drive.upper() != "D:":
        raise ValueError("Filtered staging must be stored on the D drive.")
    if destination == Path(destination.anchor) or not destination.name:
        raise ValueError("Filtered staging destination is too broad.")
    for existing in (destination, *destination.parents):
        if existing.exists() and is_link_or_junction(existing):
            raise ValueError("Filtered staging destination cannot traverse a link or junction.")


def sensitive_file_reason(name: str) -> str | None:
    lowered = name.casefold()
    if lowered == ".env" or lowered.startswith(".env."):
        return "environment-file"
    if lowered in SENSITIVE_NAMES:
        return "credential-file"
    if Path(lowered).suffix in SENSITIVE_SUFFIXES:
        return "private-key-or-certificate"
    return None


def secret_content_reason(content: bytes) -> str | None:
    for reason, pattern in SECRET_CONTENT_PATTERNS:
        if pattern.search(content):
            return reason
    return None


def portable_relative_path(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError("Staging path escapes the configured boundary.") from exc
    value = relative.as_posix()
    validate_relative_path(value)
    return value


def validate_relative_path(value: str) -> None:
    candidate = PurePosixPath(value)
    if not value or value.startswith(("/", "\\")) or candidate.is_absolute() or ".." in candidate.parts or "\\" in value:
        raise ValueError("Staging manifest contains an unsafe relative path.")


def safe_manifest_target(root: Path, relative: str) -> Path:
    validate_relative_path(relative)
    target = root.joinpath(*PurePosixPath(relative).parts)
    if not path_is_within(target.resolve(strict=False), root.resolve(strict=False)):
        raise ValueError("Staging manifest path escapes the destination boundary.")
    return target


def path_is_within(path: Path, boundary: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(boundary.resolve(strict=False))
        return True
    except ValueError:
        return False


def is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    junction_check = getattr(os.path, "isjunction", None)
    return bool(junction_check and junction_check(path))


def path_has_link_component(path: Path, boundary: Path) -> bool:
    current = path
    resolved_boundary = boundary.resolve(strict=True)
    while True:
        if is_link_or_junction(current):
            return True
        if current == resolved_boundary:
            return False
        if current.parent == current or not path_is_within(current, resolved_boundary):
            return True
        current = current.parent


def append_exclusion(records: list[dict[str, str]], path: str, reason: str) -> None:
    if len(records) < MAX_EXCLUSION_RECORDS:
        records.append({"path": path, "reason": reason})


def staging_payload_sha256(entries: list[dict[str, object]]) -> str:
    normalized = [
        {"path": str(item["path"]), "size": int(item["size"]), "sha256": str(item["sha256"])}
        for item in sorted(entries, key=lambda value: str(value["path"]))
    ]
    return sha256(json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def manifest_sha256(manifest: dict[str, object]) -> str:
    payload = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    return sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def cleanup_temporary_directory(temporary: Path, project_root: Path) -> None:
    if not temporary.exists():
        return
    resolved = temporary.resolve(strict=True)
    if resolved.parent != project_root.resolve(strict=True) or not temporary.name.startswith(".") or not temporary.name.endswith(".building"):
        raise RuntimeError("Refusing to clean an unexpected staging path.")
    if is_link_or_junction(temporary):
        raise RuntimeError("Refusing to clean a linked staging path.")
    shutil.rmtree(temporary)


def cleanup_created_build(destination: Path, project_root: Path, build_id: str) -> None:
    if not destination.exists():
        return
    resolved = destination.resolve(strict=True)
    if resolved.parent != project_root.resolve(strict=True) or destination.name != build_id:
        raise RuntimeError("Refusing to clean an unexpected completed staging path.")
    if is_link_or_junction(destination):
        raise RuntimeError("Refusing to clean a linked completed staging path.")
    shutil.rmtree(destination)
