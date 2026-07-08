from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


POLICIES_PATH = Path(__file__).resolve().parents[1] / "rules" / "sca_license_policies.json"

POLICY_ORDER = {
    "restricted": 4,
    "review_required": 3,
    "unknown": 2,
    "allowed": 1,
}


@dataclass(frozen=True)
class LicensePolicy:
    policy_id: str
    keywords: tuple[str, ...]
    policy: str
    summary: str
    obligations: tuple[str, ...]
    approval_required: bool
    approval_roles: tuple[str, ...]
    remediation: str


@dataclass(frozen=True)
class LicenseAssessment:
    license_name: str
    policy: str
    summary: str
    obligations: tuple[str, ...]
    approval_required: bool
    approval_roles: tuple[str, ...]
    remediation: str


@lru_cache(maxsize=1)
def load_license_policies() -> tuple[LicensePolicy, ...]:
    with POLICIES_PATH.open("r", encoding="utf-8") as file:
        raw_policies = json.load(file)
    if not isinstance(raw_policies, list):
        raise ValueError("SCA license policies must be a JSON array")
    return tuple(parse_policy(item) for item in raw_policies if isinstance(item, dict))


def parse_policy(item: dict[str, object]) -> LicensePolicy:
    keywords = item.get("keywords") or []
    obligations = item.get("obligations") or []
    approval_roles = item.get("approval_roles") or []
    return LicensePolicy(
        policy_id=str(item["id"]).strip(),
        keywords=tuple(str(keyword).strip().lower() for keyword in keywords if str(keyword).strip()),
        policy=str(item["policy"]).strip(),
        summary=str(item.get("summary") or "").strip(),
        obligations=tuple(str(obligation).strip() for obligation in obligations if str(obligation).strip()),
        approval_required=bool(item.get("approval_required", False)),
        approval_roles=tuple(str(role).strip() for role in approval_roles if str(role).strip()),
        remediation=str(item.get("remediation") or "").strip(),
    )


def assess_license(license_name: str | None) -> LicenseAssessment:
    label = license_name.strip() if license_name else "unknown"
    normalized = label.lower()
    matched = [
        policy
        for policy in load_license_policies()
        if any(license_keyword_matches(normalized, keyword) for keyword in policy.keywords)
    ]
    if not matched:
        return fallback_review_required(label)
    selected = max(matched, key=lambda item: POLICY_ORDER.get(item.policy, 0))
    return LicenseAssessment(
        license_name=label,
        policy=selected.policy,
        summary=f"许可证 {label}：{selected.summary}",
        obligations=selected.obligations,
        approval_required=selected.approval_required,
        approval_roles=selected.approval_roles,
        remediation=selected.remediation,
    )


def fallback_review_required(label: str) -> LicenseAssessment:
    return LicenseAssessment(
        license_name=label,
        policy="review_required",
        summary=f"许可证 {label} 未命中已知策略，需要合规复核后再确认使用边界。",
        obligations=("补充许可证文本、来源和分发方式。",),
        approval_required=True,
        approval_roles=("security", "legal"),
        remediation="由安全与法务/合规负责人确认许可证义务、分发方式和使用边界。",
    )


def license_keyword_matches(normalized_license: str, keyword: str) -> bool:
    if keyword == "gpl":
        return bool(re.search(r"(?<![al])gpl", normalized_license))
    return keyword in normalized_license


def format_license_summary(assessment: LicenseAssessment) -> str:
    parts = [assessment.summary]
    if assessment.obligations:
        parts.append("义务：" + "；".join(assessment.obligations))
    if assessment.approval_required:
        roles = "、".join(approval_role_label(role) for role in assessment.approval_roles) or "负责人"
        parts.append(f"例外审批：需要 {roles} 审批。")
    return " ".join(parts)


def approval_role_label(role: str) -> str:
    labels = {
        "security": "安全负责人",
        "legal": "法务/合规负责人",
        "business_owner": "业务负责人",
    }
    return labels.get(role, role)
