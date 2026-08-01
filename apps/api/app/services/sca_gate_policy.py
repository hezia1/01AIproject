from __future__ import annotations

from typing import Iterable

from app.services.sca_policy_overrides import dictionary_value, ordered_overrides


DEFAULT_GATE_POLICY: dict[str, object] = {
    "enabled": True,
    "block_severities": ["critical", "high"],
    "block_license_policies": ["restricted"],
    "min_risk_score": 80,
    "block_kev": True,
    "max_scan_age_hours": 168,
    "require_intelligence_for_critical": False,
}


def effective_gate_policy(overrides: Iterable[object]) -> dict[str, object]:
    policy = dict(DEFAULT_GATE_POLICY)
    for override in ordered_overrides(overrides, "gate"):
        policy_id = getattr(override, "policy_id", None)
        if policy_id is None and isinstance(override, dict):
            policy_id = override.get("policy_id")
        if str(policy_id or "") != "default":
            continue
        enabled = getattr(override, "enabled", None)
        if enabled is None and isinstance(override, dict):
            enabled = override.get("enabled")
        policy["enabled"] = bool(enabled) if enabled is not None else True
        policy.update(validate_gate_config(dictionary_value(override, "config")))
    return policy


def validate_gate_config(config: dict[str, object]) -> dict[str, object]:
    allowed = set(DEFAULT_GATE_POLICY)
    unknown = set(config) - allowed
    if unknown:
        raise ValueError("Unsupported gate policy fields: " + ", ".join(sorted(unknown)))
    result: dict[str, object] = {}
    for name in ("block_severities", "block_license_policies"):
        if name not in config:
            continue
        value = config[name]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"{name} must be an array of strings")
        result[name] = [item.lower() for item in value]
    for name in ("enabled", "block_kev", "require_intelligence_for_critical"):
        if name in config:
            result[name] = bool(config[name])
    for name in ("min_risk_score", "max_scan_age_hours"):
        if name not in config:
            continue
        try:
            value = int(config[name])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be an integer") from exc
        if value < 0 or (name == "min_risk_score" and value > 100):
            raise ValueError(f"{name} is out of range")
        result[name] = value
    return result
