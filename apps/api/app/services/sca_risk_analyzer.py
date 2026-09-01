from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os

from app.models import Severity
from app.services.sca_license_policy import LicensePolicy, assess_license, format_license_summary
from app.services.sca_intelligence import assess_vulnerability_intelligence
from app.services.sca_osv_mirror import lookup_osv_mirror
from app.services.osv_client import OsvLookupError, OsvVulnerability, supports_osv, query_osv
from app.services.sca_parser import ParsedComponent
from app.services.sca_vulnerability_rules import VulnerabilityRule, load_vulnerability_rules, matches_vulnerability_rule
from app.services.sca_assurance import component_resolution

SEVERITY_WEIGHT = {
    Severity.critical: 5,
    Severity.high: 4,
    Severity.medium: 3,
    Severity.low: 2,
    Severity.info: 1,
}
OSV_LOOKUP_WORKERS = 8


def analyze_components(
    components: list[ParsedComponent],
    vulnerability_rules: tuple[VulnerabilityRule, ...] | None = None,
    license_policies: tuple[LicensePolicy, ...] | None = None,
    *,
    offline_only: bool = False,
) -> list[ParsedComponent]:
    forced_offline = offline_only or offline_mode_enabled()
    if forced_offline:
        return [analyze_component(component, vulnerability_rules, license_policies, offline_only=True) for component in components]

    queries = unique_online_queries(components)
    if not queries:
        return [analyze_component(component, vulnerability_rules, license_policies) for component in components]
    first_key, first_component, first_version = queries[0]
    try:
        first_result = query_osv(first_component.ecosystem, first_component.name, first_version)
    except OsvLookupError as exc:
        online_error = str(exc)[:300]
        return [
            analyze_component(
                component,
                vulnerability_rules,
                license_policies,
                online_osv_available=False,
                online_osv_error=online_error,
            )
            for component in components
        ]

    online_results: dict[tuple[str, str, str], list[OsvVulnerability]] = {first_key: first_result}
    online_errors: dict[tuple[str, str, str], str] = {}

    def query_online(
        item: tuple[tuple[str, str, str], ParsedComponent, str],
    ) -> tuple[tuple[str, str, str], list[OsvVulnerability] | None, str | None]:
        key, component, version = item
        try:
            return key, query_osv(component.ecosystem, component.name, version), None
        except OsvLookupError as exc:
            return key, None, str(exc)[:300]

    remaining = queries[1:]
    if remaining:
        with ThreadPoolExecutor(max_workers=min(OSV_LOOKUP_WORKERS, len(remaining))) as executor:
            for key, vulnerabilities, error in executor.map(query_online, remaining):
                if vulnerabilities is not None:
                    online_results[key] = vulnerabilities
                elif error:
                    online_errors[key] = error
    analyzed: list[ParsedComponent] = []
    for component in components:
        key = online_query_key(component)
        if key in online_results:
            analyzed.append(
                analyze_component(
                    component,
                    vulnerability_rules,
                    license_policies,
                    online_osv_available=True,
                    online_osv_result=online_results[key],
                )
            )
        elif key in online_errors:
            analyzed.append(
                analyze_component(
                    component,
                    vulnerability_rules,
                    license_policies,
                    online_osv_available=False,
                    online_osv_error=online_errors[key],
                )
            )
        else:
            analyzed.append(analyze_component(component, vulnerability_rules, license_policies))
    return analyzed


def analyze_component(
    component: ParsedComponent,
    vulnerability_rules: tuple[VulnerabilityRule, ...] | None = None,
    license_policies: tuple[LicensePolicy, ...] | None = None,
    *,
    offline_only: bool = False,
    online_osv_available: bool | None = None,
    online_osv_error: str | None = None,
    online_osv_result: list[OsvVulnerability] | None = None,
) -> ParsedComponent:
    matched_rules = [
        rule
        for rule in (vulnerability_rules or load_vulnerability_rules())
        if matches_vulnerability_rule(component.ecosystem, component.name, component.version, rule)
    ]
    resolution = component_resolution(component)
    osv_vulnerabilities, osv_checked, osv_error, mirror_matched = lookup_osv_vulnerabilities(
        component,
        resolution,
        offline_only=offline_only,
        online_osv_available=online_osv_available,
        online_osv_error=online_osv_error,
        online_osv_result=online_osv_result,
    )
    vulnerability_ids = [item.vulnerability_id for item in osv_vulnerabilities] + [
        rule.vulnerability_id for rule in matched_rules
    ]
    vulnerability_ids = list(dict.fromkeys(vulnerability_ids))
    intelligence = assess_vulnerability_intelligence(vulnerability_ids)
    intelligence_severity = severity_from_cvss(intelligence["advisories"])
    severity = highest_severity([item.severity for item in osv_vulnerabilities] + [rule.severity for rule in matched_rules] + ([intelligence_severity] if intelligence_severity else []))
    license_assessment = assess_license(component.license, license_policies)
    license_policy = license_assessment.policy

    summaries: list[str] = []
    remediation: list[str] = []
    if osv_vulnerabilities:
        summaries.extend(f"{item.vulnerability_id}: {item.summary}" for item in osv_vulnerabilities[:5])
        remediation.append("根据 OSV 漏洞公告升级到不受影响版本，必要时替换组件并执行回归验证。")
    if matched_rules:
        summaries.extend(rule.summary for rule in matched_rules)
        summaries.extend(rule_references_summary(rule.references) for rule in matched_rules if rule.references)
        remediation.extend(f"升级 {rule.package} 到 {rule.fixed_version} 或更高版本。" for rule in matched_rules)
    if intelligence["advisories"]:
        if intelligence["kev"]:
            summaries.append("命中 CISA KEV / 已知在野利用情报，应优先处置。")
        if intelligence["max_epss"] is not None:
            summaries.append(f"离线情报 EPSS 最高概率：{float(intelligence['max_epss']):.3f}；综合风险分：{int(intelligence['risk_score'])}/100。")
        remediation.extend(f"升级到 {version} 或更高安全版本。" for version in intelligence["fixed_versions"])
    if license_policy in {"restricted", "review_required", "unknown"}:
        summaries.append(format_license_summary(license_assessment))
        remediation.append(license_assessment.remediation)

    if osv_vulnerabilities or matched_rules:
        risk_status = "vulnerable"
    elif license_policy in {"restricted", "review_required", "unknown"}:
        risk_status = "license-risk"
    elif resolution["status"] in {"missing", "constraint"}:
        risk_status = "review-required"
        summaries.append(str(resolution["reason"]) + "，无法完成精确漏洞匹配。")
        remediation.append("补全锁文件或固定依赖版本后重新执行 SCA。")
    elif not osv_checked:
        risk_status = "review-required"
        summaries.append("漏洞情报未完成验证；未发现匹配不代表组件安全。")
        remediation.append("提供可信锁文件或实际安装环境，并配置可用的 OSV/Grype/Trivy 情报后重新扫描。")
    else:
        risk_status = "clean"
    risk_source = determine_risk_source(
        osv_matched=bool(osv_vulnerabilities),
        local_matched=bool(matched_rules),
        license_risk=license_policy,
        version_missing=resolution["status"] == "missing",
        osv_checked=osv_checked,
        osv_error=osv_error,
        osv_mirror_matched=mirror_matched,
    )

    return replace(
        component,
        risk_status=risk_status,
        vulnerability_ids=vulnerability_ids,
        severity=severity.value if severity else None,
        risk_summary=" ".join(dict.fromkeys(summaries)) or None,
        remediation=" ".join(dict.fromkeys(remediation)) or None,
        license_risk=license_policy,
        risk_source=risk_source,
        osv_checked=osv_checked,
        osv_error=osv_error,
        risk_metadata={
            **intelligence,
            "version_resolution": resolution,
            "vulnerability_verification": (
                "unverified"
                if resolution["status"] in {"missing", "constraint"}
                else "matched"
                if vulnerability_ids
                else "verified_no_match"
                if osv_checked
                else "unverified"
            ),
        },
    )


def lookup_osv_vulnerabilities(
    component: ParsedComponent,
    resolution: dict[str, object] | None = None,
    *,
    offline_only: bool = False,
    online_osv_available: bool | None = None,
    online_osv_error: str | None = None,
    online_osv_result: list[OsvVulnerability] | None = None,
):
    resolved = resolution or component_resolution(component)
    lookup_version = resolved.get("lookup_version")
    if not supports_osv(component.ecosystem):
        return [], False, "OSV does not support this ecosystem", False
    if not isinstance(lookup_version, str) or not lookup_version:
        return [], False, str(resolved.get("reason") or "exact component version is unavailable"), False
    if online_osv_result is not None:
        return online_osv_result, True, None, False
    if offline_only or offline_mode_enabled():
        return offline_osv_fallback(component, lookup_version, "SCA 显式离线模式", report_degradation=False)
    if online_osv_available is False:
        return offline_osv_fallback(component, lookup_version, f"在线 OSV 不可用：{online_osv_error or '网络探测失败'}")
    try:
        return query_osv(component.ecosystem, component.name, lookup_version), True, None, False
    except OsvLookupError as exc:
        return offline_osv_fallback(component, lookup_version, f"在线 OSV 不可用：{str(exc)[:240]}")


def offline_osv_fallback(
    component: ParsedComponent,
    lookup_version: str,
    reason: str,
    *,
    report_degradation: bool = True,
) -> tuple[list[OsvVulnerability], bool, str | None, bool]:
    mirrored, mirror_matched = lookup_osv_mirror(component.ecosystem, component.name, lookup_version)
    if mirror_matched:
        error = f"{reason}；已使用本地 OSV 镜像" if report_degradation else None
        return mirrored, True, error, True
    return [], False, f"{reason}；本地 OSV 镜像没有匹配记录", False


def offline_mode_enabled() -> bool:
    return os.getenv("SCA_OFFLINE_ONLY", "").lower() in {"1", "true", "yes"}


def online_query_key(component: ParsedComponent) -> tuple[str, str, str] | None:
    resolution = component_resolution(component)
    version = resolution.get("lookup_version")
    if not supports_osv(component.ecosystem) or not isinstance(version, str):
        return None
    return component.ecosystem, component.name.lower(), version


def unique_online_queries(components: list[ParsedComponent]) -> list[tuple[tuple[str, str, str], ParsedComponent, str]]:
    queries: list[tuple[tuple[str, str, str], ParsedComponent, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for component in components:
        key = online_query_key(component)
        if key is None or key in seen:
            continue
        seen.add(key)
        queries.append((key, component, key[2]))
    return queries


def determine_risk_source(
    osv_matched: bool,
    local_matched: bool,
    license_risk: str | None,
    version_missing: bool,
    osv_checked: bool,
    osv_error: str | None,
    osv_mirror_matched: bool,
) -> str:
    if osv_mirror_matched:
        return "osv_mirror"
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


def rule_references_summary(references: tuple[str, ...]) -> str:
    return "本地规则参考：" + "，".join(references[:2])


def severity_from_cvss(advisories: object) -> Severity | None:
    if not isinstance(advisories, list):
        return None
    scores = [float(item.get("cvss_score")) for item in advisories if isinstance(item, dict) and item.get("cvss_score") is not None]
    if not scores:
        return None
    score = max(scores)
    if score >= 9:
        return Severity.critical
    if score >= 7:
        return Severity.high
    if score >= 4:
        return Severity.medium
    return Severity.low


def highest_severity(severities: list[Severity]) -> Severity | None:
    if not severities:
        return None
    return max(severities, key=lambda item: SEVERITY_WEIGHT[item])
