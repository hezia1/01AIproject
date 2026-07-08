from __future__ import annotations

import re
from dataclasses import replace

from app.models import Severity
from app.services.osv_client import OsvLookupError, supports_osv, query_osv
from app.services.sca_parser import ParsedComponent
from app.services.sca_vulnerability_rules import load_vulnerability_rules, matches_vulnerability_rule

LICENSE_POLICY_RULES = {
    "mit": "allowed",
    "apache-2.0": "allowed",
    "apache 2.0": "allowed",
    "bsd": "allowed",
    "isc": "allowed",
    "mpl": "review_required",
    "lgpl": "review_required",
    "epl": "review_required",
    "cddl": "review_required",
    "gpl": "restricted",
    "agpl": "restricted",
    "sspl": "restricted",
    "commercial": "review_required",
    "proprietary": "review_required",
    "unknown": "unknown",
}

LICENSE_POLICY_ORDER = {
    "restricted": 4,
    "review_required": 3,
    "unknown": 2,
    "allowed": 1,
}

SEVERITY_WEIGHT = {
    Severity.critical: 5,
    Severity.high: 4,
    Severity.medium: 3,
    Severity.low: 2,
    Severity.info: 1,
}


def analyze_components(components: list[ParsedComponent]) -> list[ParsedComponent]:
    return [analyze_component(component) for component in components]


def analyze_component(component: ParsedComponent) -> ParsedComponent:
    matched_rules = [
        rule
        for rule in load_vulnerability_rules()
        if matches_vulnerability_rule(component.ecosystem, component.name, component.version, rule)
    ]
    osv_vulnerabilities, osv_checked, osv_error = lookup_osv_vulnerabilities(component)
    vulnerability_ids = [item.vulnerability_id for item in osv_vulnerabilities] + [
        rule.vulnerability_id for rule in matched_rules
    ]
    severity = highest_severity([item.severity for item in osv_vulnerabilities] + [rule.severity for rule in matched_rules])
    license_policy = classify_license(component.license)

    summaries: list[str] = []
    remediation: list[str] = []
    if osv_vulnerabilities:
        summaries.extend(f"{item.vulnerability_id}: {item.summary}" for item in osv_vulnerabilities[:5])
        remediation.append("根据 OSV 漏洞公告升级到不受影响版本，必要时替换组件并执行回归验证。")
    if matched_rules:
        summaries.extend(rule.summary for rule in matched_rules)
        summaries.extend(rule_references_summary(rule.references) for rule in matched_rules if rule.references)
        remediation.extend(f"升级 {rule.package} 到 {rule.fixed_version} 或更高版本。" for rule in matched_rules)
    if license_policy in {"restricted", "review_required", "unknown"}:
        summaries.append(license_summary(component.license, license_policy))
        remediation.append(license_remediation(license_policy))

    if osv_vulnerabilities or matched_rules:
        risk_status = "vulnerable"
    elif license_policy in {"restricted", "review_required", "unknown"}:
        risk_status = "license-risk"
    elif component.version is None:
        risk_status = "review-required"
        summaries.append("组件版本缺失，无法完成精确漏洞匹配。")
        remediation.append("补全锁文件或固定依赖版本后重新执行 SCA。")
    else:
        risk_status = "clean"
    risk_source = determine_risk_source(
        osv_matched=bool(osv_vulnerabilities),
        local_matched=bool(matched_rules),
        license_risk=license_policy,
        version_missing=component.version is None,
        osv_checked=osv_checked,
        osv_error=osv_error,
    )

    return replace(
        component,
        risk_status=risk_status,
        vulnerability_ids=list(dict.fromkeys(vulnerability_ids)),
        severity=severity.value if severity else None,
        risk_summary=" ".join(dict.fromkeys(summaries)) or None,
        remediation=" ".join(dict.fromkeys(remediation)) or None,
        license_risk=license_policy,
        risk_source=risk_source,
        osv_checked=osv_checked,
        osv_error=osv_error,
    )


def lookup_osv_vulnerabilities(component: ParsedComponent):
    if not supports_osv(component.ecosystem) or component.version is None:
        return [], False, None
    try:
        return query_osv(component.ecosystem, component.name, component.version), True, None
    except OsvLookupError as exc:
        return [], True, str(exc)[:300]


def determine_risk_source(
    osv_matched: bool,
    local_matched: bool,
    license_risk: str | None,
    version_missing: bool,
    osv_checked: bool,
    osv_error: str | None,
) -> str:
    if osv_matched:
        return "osv"
    if local_matched:
        return "local_rule"
    if license_risk and license_risk != "allowed":
        return "license_rule"
    if version_missing:
        return "version_missing"
    if osv_error:
        return "osv_error"
    if osv_checked:
        return "clean"
    return "not_supported"


def classify_license(license_name: str | None) -> str:
    if not license_name:
        return "unknown"
    normalized = license_name.lower()
    matched_policies: list[str] = []
    for keyword, policy in LICENSE_POLICY_RULES.items():
        if license_keyword_matches(normalized, keyword):
            matched_policies.append(policy)
    if not matched_policies:
        return "review_required"
    return max(matched_policies, key=lambda item: LICENSE_POLICY_ORDER[item])


def license_keyword_matches(normalized_license: str, keyword: str) -> bool:
    if keyword == "gpl":
        return bool(re.search(r"(?<![al])gpl", normalized_license))
    return keyword in normalized_license


def license_summary(license_name: str | None, policy: str) -> str:
    label = license_name or "unknown"
    if policy == "restricted":
        return f"许可证 {label} 命中受限策略，需要确认是否允许在当前交付场景中使用。"
    if policy == "review_required":
        return f"许可证 {label} 需要合规复核后再确认使用边界。"
    return f"许可证 {label} 未明确识别，需要补充许可证信息或人工确认。"


def license_remediation(policy: str) -> str:
    if policy == "restricted":
        return "优先替换为允许许可证组件，或由法务/合规负责人审批例外使用。"
    if policy == "review_required":
        return "由安全与法务/合规负责人确认许可证义务、分发方式和使用边界。"
    return "补全许可证元数据，无法确认前按需复核处理。"


def rule_references_summary(references: tuple[str, ...]) -> str:
    return "本地规则参考：" + "，".join(references[:2])


def highest_severity(severities: list[Severity]) -> Severity | None:
    if not severities:
        return None
    return max(severities, key=lambda item: SEVERITY_WEIGHT[item])
