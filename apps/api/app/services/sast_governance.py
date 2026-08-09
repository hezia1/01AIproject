from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
import re
from typing import Any, Iterable
from uuid import uuid4

from app.services.sast_scanner import ParsedFinding
from app.services.sast_semgrep_rules import BUILTIN_CONFIG, validate_semgrep_yaml

BUILTIN_RULE_PACK_VERSION = "local-2026.08.09.1"

DEFAULT_SAST_PROFILE: dict[str, object] = {
    "profile_version": 1,
    "rule_pack_version": BUILTIN_RULE_PACK_VERSION,
    "semgrep_enabled": True,
    "semgrep_config": BUILTIN_CONFIG,
    "include_local_rules": True,
    "clear_previous": True,
    "suppressions": [],
    "custom_rules": [],
    "semgrep_rules": [],
    "git_baseline_ref": "",
    "scan_git_history_secrets": True,
    "changed_files_only": False,
    "ai_enabled": False,
    "ai_auto_scan": True,
    "ai_max_input_chars": 60_000,
    "ai_confidence_threshold": 80,
    "ai_include_fix_drafts": True,
    "quality_gate": {
        "enabled": True,
        "threshold": "high",
        "block_new_only": False,
        "max_blocking_findings": 0,
        "branch_patterns": ["*"],
        "excluded_rule_ids": [],
    },
}


def effective_sast_profile(config: dict[str, object] | None) -> dict[str, object]:
    saved = (config or {}).get("sast_profile")
    profile = dict(DEFAULT_SAST_PROFILE)
    if isinstance(saved, dict):
        profile.update({key: value for key, value in saved.items() if key in DEFAULT_SAST_PROFILE})
    # The built-in scanner code and rule bundle are versioned together. A stored
    # project profile must not make a newer runtime report an obsolete rule version.
    profile["rule_pack_version"] = BUILTIN_RULE_PACK_VERSION
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
    profile["semgrep_rules"] = normalize_semgrep_rules(profile.get("semgrep_rules"))
    profile["git_baseline_ref"] = validate_git_baseline_ref(profile.get("git_baseline_ref"))
    profile["scan_git_history_secrets"] = bool(profile.get("scan_git_history_secrets"))
    profile["changed_files_only"] = bool(profile.get("changed_files_only"))
    profile["ai_enabled"] = bool(profile.get("ai_enabled"))
    profile["ai_auto_scan"] = bool(profile.get("ai_auto_scan"))
    profile["ai_include_fix_drafts"] = bool(profile.get("ai_include_fix_drafts"))
    profile["ai_max_input_chars"] = bounded_profile_int(profile.get("ai_max_input_chars"), 60_000, 10_000, 200_000)
    profile["ai_confidence_threshold"] = bounded_profile_int(profile.get("ai_confidence_threshold"), 80, 50, 100)
    profile["quality_gate"] = normalize_quality_gate(profile.get("quality_gate"))
    return profile


def update_sast_profile(config: dict[str, object] | None, payload: dict[str, object]) -> dict[str, object]:
    profile = effective_sast_profile(config)
    for key in ("semgrep_enabled", "include_local_rules", "clear_previous", "scan_git_history_secrets", "changed_files_only", "ai_enabled", "ai_auto_scan", "ai_include_fix_drafts"):
        if key in payload:
            if not isinstance(payload[key], bool):
                raise ValueError(f"{key} must be a boolean")
            profile[key] = payload[key]
    if "semgrep_config" in payload:
        profile["semgrep_config"] = validate_semgrep_config(payload["semgrep_config"])
    if "git_baseline_ref" in payload:
        profile["git_baseline_ref"] = validate_git_baseline_ref(payload["git_baseline_ref"])
    if "quality_gate" in payload:
        profile["quality_gate"] = normalize_quality_gate(payload["quality_gate"])
    if "ai_max_input_chars" in payload:
        profile["ai_max_input_chars"] = bounded_profile_int(payload["ai_max_input_chars"], 60_000, 10_000, 200_000)
    if "ai_confidence_threshold" in payload:
        profile["ai_confidence_threshold"] = bounded_profile_int(payload["ai_confidence_threshold"], 80, 50, 100)
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


def add_semgrep_rule(config: dict[str, object] | None, payload: dict[str, object]) -> dict[str, object]:
    profile = effective_sast_profile(config)
    rule = normalize_semgrep_rule(payload, require_name=True)
    rule["id"] = str(uuid4())
    rule["version"] = 1
    rule["created_at"] = utc_now()
    profile["semgrep_rules"] = [*profile["semgrep_rules"], rule]
    return profile


def update_semgrep_rule(config: dict[str, object] | None, rule_id: str, payload: dict[str, object]) -> dict[str, object]:
    profile = effective_sast_profile(config)
    updated = False
    rules: list[dict[str, object]] = []
    for rule in profile["semgrep_rules"]:
        if rule.get("id") != rule_id:
            rules.append(rule)
            continue
        candidate = normalize_semgrep_rule({**rule, **payload}, require_name=True)
        candidate["id"] = rule_id
        candidate["created_at"] = rule.get("created_at") or utc_now()
        candidate["version"] = int(rule.get("version") or 1) + 1
        rules.append(candidate)
        updated = True
    if not updated:
        raise ValueError("Semgrep YAML rule pack not found")
    profile["semgrep_rules"] = rules
    return profile


def validate_semgrep_rule_payload(payload: dict[str, object]) -> dict[str, object]:
    rule = normalize_semgrep_rule(payload, require_name=True)
    return {"valid": True, "rule": rule, "yaml": validate_semgrep_yaml(rule["content"])}


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


def normalize_semgrep_rules(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        try:
            normalized.append(normalize_semgrep_rule(item, require_name=True))
        except ValueError:
            continue
    return normalized


def normalize_semgrep_rule(value: dict[str, object], require_name: bool) -> dict[str, object]:
    name = str(value.get("name") or value.get("title") or "").strip()
    content = str(value.get("content") or "").replace("\r\n", "\n").strip()
    if require_name and (not name or len(name) > 160):
        raise ValueError("Semgrep YAML rule pack name must be between 1 and 160 characters")
    try:
        validation = validate_semgrep_yaml(content)
    except ValueError:
        raise
    try:
        version = max(1, int(value.get("version") or 1))
    except (TypeError, ValueError):
        version = 1
    status = str(value.get("status") or "published").lower()
    if status not in {"draft", "published", "archived"}:
        raise ValueError("Semgrep YAML rule pack status must be draft, published, or archived")
    return {
        "id": string_or_none(value.get("id")) or str(uuid4()),
        "name": name,
        "content": content,
        "rule_ids": validation["rule_ids"],
        "sha256": validation["sha256"],
        "enabled": bool(value.get("enabled", True)),
        "status": status,
        "approved_by": string_or_none(value.get("approved_by")),
        "version": version,
        "created_at": string_or_none(value.get("created_at")) or utc_now(),
    }


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
    config = str(value or BUILTIN_CONFIG).strip()
    if not config or len(config) > 500:
        raise ValueError("semgrep_config must be between 1 and 500 characters")
    if config in {BUILTIN_CONFIG, "p/default"}:
        return BUILTIN_CONFIG
    if config.startswith("p/"):
        raise ValueError("Remote Semgrep registry packs are disabled; import a local YAML rule pack instead")
    path = PurePosixPath(config.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or path.suffix.lower() not in {".yaml", ".yml", ".json"}:
        raise ValueError("semgrep_config must be the built-in offline pack or a project-relative .yml/.yaml/.json file")
    return path.as_posix()


def bounded_profile_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value) if value not in {None, ""} else default
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def validate_git_baseline_ref(value: object) -> str:
    ref = str(value or "").strip()
    if not ref:
        return ""
    if len(ref) > 200 or not re.fullmatch(r"[A-Za-z0-9_./:@~^{}-]+", ref) or ".." in ref:
        raise ValueError("git_baseline_ref contains unsupported Git revision characters")
    return ref


def normalize_quality_gate(value: object) -> dict[str, object]:
    defaults = dict(DEFAULT_SAST_PROFILE["quality_gate"])
    if not isinstance(value, dict):
        return defaults
    enabled = value.get("enabled", defaults["enabled"])
    threshold = str(value.get("threshold", defaults["threshold"])).lower()
    block_new_only = value.get("block_new_only", defaults["block_new_only"])
    try:
        maximum = max(0, min(10_000, int(value.get("max_blocking_findings", defaults["max_blocking_findings"]))))
    except (TypeError, ValueError):
        maximum = 0
    patterns = value.get("branch_patterns", defaults["branch_patterns"])
    excluded = value.get("excluded_rule_ids", defaults["excluded_rule_ids"])
    if not isinstance(enabled, bool) or not isinstance(block_new_only, bool):
        raise ValueError("quality_gate enabled and block_new_only must be booleans")
    if threshold not in {"critical", "high", "medium", "low", "info", "none"}:
        raise ValueError("quality_gate threshold must be critical, high, medium, low, info, or none")
    if not isinstance(patterns, list) or not patterns or any(not isinstance(item, str) or not item or len(item) > 200 for item in patterns):
        raise ValueError("quality_gate branch_patterns must be a non-empty array of globs")
    if not isinstance(excluded, list) or any(not isinstance(item, str) or len(item) > 300 for item in excluded):
        raise ValueError("quality_gate excluded_rule_ids must be an array of rule IDs")
    return {"enabled": enabled, "threshold": threshold, "block_new_only": block_new_only, "max_blocking_findings": maximum, "branch_patterns": sorted(set(patterns)), "excluded_rule_ids": sorted(set(excluded))}


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
