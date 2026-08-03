from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
import re
from typing import Any, Iterable
from uuid import uuid4

from app.services.sast_scanner import ParsedFinding


DEFAULT_SAST_PROFILE: dict[str, object] = {
    "profile_version": 1,
    "rule_pack_version": "local-2026.08.03.1",
    "semgrep_enabled": True,
    "semgrep_config": "p/default",
    "include_local_rules": True,
    "clear_previous": True,
    "suppressions": [],
    "custom_rules": [],
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
    profile["custom_rules"] = normalize_custom_rules(profile.get("custom_rules"))
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


def add_custom_rule(config: dict[str, object] | None, payload: dict[str, object]) -> dict[str, object]:
    profile = effective_sast_profile(config)
    rule = normalize_custom_rule(payload, require_title=True)
    rule["id"] = str(uuid4())
    rule["version"] = 1
    rule["created_at"] = utc_now()
    profile["custom_rules"] = [*profile["custom_rules"], rule]
    return profile


def update_custom_rule(config: dict[str, object] | None, rule_id: str, payload: dict[str, object]) -> dict[str, object]:
    profile = effective_sast_profile(config)
    updated = False
    rules: list[dict[str, object]] = []
    for rule in profile["custom_rules"]:
        if rule.get("id") != rule_id:
            rules.append(rule)
            continue
        candidate = normalize_custom_rule({**rule, **payload}, require_title=True)
        candidate["id"] = rule_id
        candidate["created_at"] = rule.get("created_at") or utc_now()
        candidate["version"] = int(rule.get("version") or 1) + 1
        rules.append(candidate)
        updated = True
    if not updated:
        raise ValueError("SAST custom rule not found")
    profile["custom_rules"] = rules
    return profile


def validate_custom_rule_payload(payload: dict[str, object]) -> dict[str, object]:
    rule = normalize_custom_rule(payload, require_title=True)
    sample = str(payload.get("test_sample") or "")
    matched = bool(re.search(str(rule["pattern"]), sample)) if sample else None
    return {
        "valid": True,
        "rule": rule,
        "test_sample_provided": bool(sample),
        "test_sample_matched": matched,
        "message": "规则可编译；样例命中结果仅验证正则，不代表真实数据流可达性。",
    }


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


def normalize_custom_rules(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        try:
            normalized.append(normalize_custom_rule(item, require_title=True))
        except ValueError:
            continue
    return normalized


def normalize_custom_rule(value: dict[str, object], require_title: bool) -> dict[str, object]:
    rule_id = str(value.get("rule_id") or "").strip()
    title = str(value.get("title") or "").strip()
    pattern = str(value.get("pattern") or "").strip()
    severity = str(value.get("severity") or "medium").strip().lower()
    category = str(value.get("category") or "custom").strip() or "custom"
    description = str(value.get("description") or "项目自定义 SAST 规则命中。").strip()
    remediation = str(value.get("remediation") or "确认风险上下文，修复后添加回归测试并重新扫描。").strip()
    extensions = value.get("file_extensions") or []
    if not rule_id or len(rule_id) > 300 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", rule_id):
        raise ValueError("rule_id must contain only letters, numbers, '.', '_', ':', or '-'")
    if require_title and (not title or len(title) > 300):
        raise ValueError("title must be between 1 and 300 characters")
    if not pattern or len(pattern) > 2000:
        raise ValueError("pattern must be between 1 and 2000 characters")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"pattern is not a valid regular expression: {exc}") from exc
    if severity not in {"critical", "high", "medium", "low", "info"}:
        raise ValueError("severity must be critical, high, medium, low, or info")
    if not isinstance(extensions, list) or any(not isinstance(item, str) or not item.startswith(".") or len(item) > 20 for item in extensions):
        raise ValueError("file_extensions must be an array of suffixes such as ['.py', '.ts']")
    try:
        version = max(1, int(value.get("version") or 1))
    except (TypeError, ValueError):
        version = 1
    return {
        "id": string_or_none(value.get("id")) or str(uuid4()),
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "category": category[:80],
        "pattern": pattern,
        "file_extensions": sorted(set(extensions)),
        "description": description[:2000],
        "remediation": remediation[:2000],
        "enabled": bool(value.get("enabled", True)),
        "version": version,
        "created_at": string_or_none(value.get("created_at")) or utc_now(),
    }


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
