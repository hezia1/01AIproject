from __future__ import annotations

from dataclasses import replace
from typing import Iterable

from app.services.sca_license_policy import LicensePolicy, parse_policy
from app.services.sca_vulnerability_rules import VulnerabilityRule, parse_rule


def effective_vulnerability_rules(
    defaults: Iterable[VulnerabilityRule],
    overrides: Iterable[object],
) -> tuple[VulnerabilityRule, ...]:
    """Apply global then project overrides while leaving packaged rules immutable."""
    rules = {rule.vulnerability_id: rule for rule in defaults}
    for override in ordered_overrides(overrides, "vulnerability"):
        policy_id = string_value(override, "policy_id")
        if not policy_id:
            continue
        config = dictionary_value(override, "config")
        existing = rules.get(policy_id)
        if existing is None:
            rules[policy_id] = parse_rule(custom_vulnerability_payload(policy_id, config, bool_value(override, "enabled", True)))
            continue
        if config:
            payload = vulnerability_payload(existing)
            payload.update(config)
            payload["id"] = policy_id
            payload["enabled"] = bool_value(override, "enabled", existing.enabled)
            rules[policy_id] = parse_rule(payload)
        else:
            rules[policy_id] = replace(existing, enabled=bool_value(override, "enabled", existing.enabled))
    return tuple(sorted(rules.values(), key=lambda item: item.vulnerability_id))


def effective_license_policies(
    defaults: Iterable[LicensePolicy],
    overrides: Iterable[object],
) -> tuple[LicensePolicy, ...]:
    policies = {policy.policy_id: policy for policy in defaults}
    for override in ordered_overrides(overrides, "license"):
        policy_id = string_value(override, "policy_id")
        if not policy_id:
            continue
        config = dictionary_value(override, "config")
        existing = policies.get(policy_id)
        if existing is None:
            policies[policy_id] = parse_policy(custom_license_payload(policy_id, config, bool_value(override, "enabled", True)))
            continue
        payload = license_payload(existing)
        payload.update(config)
        payload["id"] = policy_id
        if not bool_value(override, "enabled", True):
            payload["keywords"] = []
        policies[policy_id] = parse_policy(payload)
    return tuple(sorted(policies.values(), key=lambda item: item.policy_id))


def ordered_overrides(overrides: Iterable[object], kind: str) -> list[object]:
    selected = [item for item in overrides if string_value(item, "policy_kind") == kind]
    return sorted(selected, key=lambda item: (string_value(item, "project_id") is not None, string_value(item, "updated_at") or ""))


def vulnerability_payload(rule: VulnerabilityRule) -> dict[str, object]:
    return {
        "id": rule.vulnerability_id,
        "ecosystem": rule.ecosystem,
        "package": rule.package,
        "affected": rule.affected,
        "severity": rule.severity.value,
        "summary": rule.summary,
        "fixed_version": rule.fixed_version,
        "references": list(rule.references),
        "enabled": rule.enabled,
    }


def license_payload(policy: LicensePolicy) -> dict[str, object]:
    return {
        "id": policy.policy_id,
        "keywords": list(policy.keywords),
        "policy": policy.policy,
        "summary": policy.summary,
        "obligations": list(policy.obligations),
        "approval_required": policy.approval_required,
        "approval_roles": list(policy.approval_roles),
        "remediation": policy.remediation,
    }


def custom_vulnerability_payload(policy_id: str, config: dict[str, object], enabled: bool) -> dict[str, object]:
    required = ("ecosystem", "package", "affected", "severity", "summary", "fixed_version")
    missing = [key for key in required if not str(config.get(key) or "").strip()]
    if missing:
        raise ValueError(f"Custom vulnerability policy {policy_id} is missing: {', '.join(missing)}")
    return {**config, "id": policy_id, "enabled": enabled}


def custom_license_payload(policy_id: str, config: dict[str, object], enabled: bool) -> dict[str, object]:
    required = ("keywords", "policy", "summary", "remediation")
    missing = [key for key in required if not config.get(key)]
    if missing:
        raise ValueError(f"Custom license policy {policy_id} is missing: {', '.join(missing)}")
    payload = {**config, "id": policy_id}
    if not enabled:
        # Disabled license policies are represented by an impossible keyword set.
        payload["keywords"] = []
    return payload


def string_value(value: object, field: str) -> str | None:
    raw = getattr(value, field, None)
    if raw is None and isinstance(value, dict):
        raw = value.get(field)
    return str(raw) if raw not in {None, ""} else None


def bool_value(value: object, field: str, default: bool) -> bool:
    raw = getattr(value, field, None)
    if raw is None and isinstance(value, dict):
        raw = value.get(field)
    return default if raw is None else bool(raw)


def dictionary_value(value: object, field: str) -> dict[str, object]:
    raw = getattr(value, field, None)
    if raw is None and isinstance(value, dict):
        raw = value.get(field)
    return dict(raw) if isinstance(raw, dict) else {}
