from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
from typing import Any, Iterable
from uuid import uuid4

from app.services.sast_scanner import ParsedFinding


DEFAULT_SAST_PROFILE: dict[str, object] = {
    "profile_version": 1,
    "semgrep_enabled": True,
    "semgrep_config": "p/default",
    "include_local_rules": True,
    "clear_previous": True,
    "suppressions": [],
}


def effective_sast_profile(config: dict[str, object] | None) -> dict[str, object]:
    saved = (config or {}).get("sast_profile")
    profile = dict(DEFAULT_SAST_PROFILE)
    if isinstance(saved, dict):
        profile.update({key: value for key, value in saved.items() if key in DEFAULT_SAST_PROFILE})
    profile["semgrep_config"] = validate_semgrep_config(profile.get("semgrep_config"))
    try:
        profile["profile_version"] = max(1, int(profile.get("profile_version") or 1))
    except (TypeError, ValueError):
        profile["profile_version"] = 1
    profile["semgrep_enabled"] = bool(profile.get("semgrep_enabled"))
    profile["include_local_rules"] = bool(profile.get("include_local_rules"))
    profile["clear_previous"] = bool(profile.get("clear_previous"))
    profile["suppressions"] = normalize_suppressions(profile.get("suppressions"))
    return profile


def update_sast_profile(config: dict[str, object] | None, payload: dict[str, object]) -> dict[str, object]:
    profile = effective_sast_profile(config)
    for key in ("semgrep_enabled", "include_local_rules", "clear_previous"):
        if key in payload:
            if not isinstance(payload[key], bool):
                raise ValueError(f"{key} must be a boolean")
            profile[key] = payload[key]
    if "semgrep_config" in payload:
        profile["semgrep_config"] = validate_semgrep_config(payload["semgrep_config"])
    if not profile["semgrep_enabled"] and not profile["include_local_rules"]:
        raise ValueError("At least one SAST engine must be enabled")
    return profile


def add_suppression(config: dict[str, object] | None, payload: dict[str, object]) -> dict[str, object]:
    profile = effective_sast_profile(config)
    item = normalize_suppression(payload, require_reason=True)
    item["id"] = str(uuid4())
    item["created_at"] = utc_now()
    profile["suppressions"] = [*profile["suppressions"], item]
    return profile


def update_suppression(config: dict[str, object] | None, suppression_id: str, payload: dict[str, object]) -> dict[str, object]:
    profile = effective_sast_profile(config)
    updated = False
    items: list[dict[str, object]] = []
    for item in profile["suppressions"]:
        if item.get("id") != suppression_id:
            items.append(item)
            continue
        candidate = normalize_suppression({**item, **payload}, require_reason=True)
        candidate["id"] = suppression_id
        candidate["created_at"] = item.get("created_at") or utc_now()
        items.append(candidate)
        updated = True
    if not updated:
        raise ValueError("SAST suppression not found")
    profile["suppressions"] = items
    return profile


def apply_suppressions(
    findings: Iterable[ParsedFinding],
    suppressions: object,
) -> tuple[list[ParsedFinding], list[dict[str, object]]]:
    active = [item for item in normalize_suppressions(suppressions) if suppression_is_active(item)]
    kept: list[ParsedFinding] = []
    applied: list[dict[str, object]] = []
    for finding in findings:
        matched = next((item for item in active if suppression_matches(item, finding)), None)
        if matched is None:
            kept.append(finding)
            continue
        applied.append({
            "suppression_id": matched["id"],
            "rule_id": finding.rule_id,
            "file_path": finding.file_path,
            "reason": matched["reason"],
        })
    return kept, applied


def normalize_suppressions(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        try:
            normalized.append(normalize_suppression(item, require_reason=True))
        except ValueError:
            continue
    return normalized


def normalize_suppression(value: dict[str, object], require_reason: bool) -> dict[str, object]:
    rule_id = str(value.get("rule_id") or "*").strip()
    path_pattern = str(value.get("path_pattern") or "**").strip().replace("\\", "/")
    reason = str(value.get("reason") or "").strip()
    if not rule_id or len(rule_id) > 300:
        raise ValueError("rule_id must be between 1 and 300 characters")
    if not path_pattern or len(path_pattern) > 800 or path_pattern.startswith("/") or ".." in PurePosixPath(path_pattern).parts:
        raise ValueError("path_pattern must be a relative glob without '..'")
    if require_reason and not reason:
        raise ValueError("suppression reason is required")
    if len(reason) > 2000:
        raise ValueError("suppression reason is too long")
    expires_at = string_or_none(value.get("expires_at"))
    if expires_at:
        try:
            datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("expires_at must be an ISO 8601 timestamp") from exc
    return {
        "id": string_or_none(value.get("id")) or str(uuid4()),
        "rule_id": rule_id,
        "path_pattern": path_pattern,
        "reason": reason,
        "expires_at": expires_at,
        "enabled": bool(value.get("enabled", True)),
        "created_at": string_or_none(value.get("created_at")) or utc_now(),
    }


def validate_semgrep_config(value: object) -> str:
    config = str(value or "p/default").strip()
    if not config or len(config) > 500:
        raise ValueError("semgrep_config must be between 1 and 500 characters")
    if config.startswith("p/"):
        return config
    path = PurePosixPath(config.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or path.suffix.lower() not in {".yaml", ".yml", ".json"}:
        raise ValueError("semgrep_config must be a registry pack (p/...) or a project-relative .yml/.yaml/.json file")
    return path.as_posix()


def suppression_matches(item: dict[str, object], finding: ParsedFinding) -> bool:
    rule_id = str(item.get("rule_id") or "*")
    path_pattern = str(item.get("path_pattern") or "**")
    return fnmatchcase(finding.rule_id, rule_id) and PurePosixPath(finding.file_path).match(path_pattern)


def suppression_is_active(item: dict[str, object]) -> bool:
    if not item.get("enabled", True):
        return False
    expires_at = string_or_none(item.get("expires_at"))
    if not expires_at:
        return True
    try:
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > datetime.now(timezone.utc)


def string_or_none(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
