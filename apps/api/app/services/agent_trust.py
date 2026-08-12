from __future__ import annotations

import json
from hashlib import sha256
from typing import Any


TRUST_SCORE_SCHEMA = "ai-security-platform.agent-trust-score/v1"
TRUST_SCORE_ALGORITHM = "agent-trust-static-1.0"
MAX_STATIC_SCORE = 90
RESOLVED_FINDING_STATUSES = {"fixed", "closed", "false_positive"}


def calculate_agent_trust_score(
    *,
    assets: list[object],
    permissions: list[object],
    findings: list[dict[str, object]],
    coverage: dict[str, object],
    intelligence: dict[str, object] | None,
    dataflow: dict[str, object] | None,
    runtime_validation: dict[str, object] | None,
) -> dict[str, object]:
    """Build a deterministic, evidence-backed trust score without executing an Agent."""
    asset_items = [mapping(item) for item in assets]
    permission_items = [mapping(item) for item in permissions]
    active_findings = [
        item for item in findings
        if str(item.get("status") or "open").lower() not in RESOLVED_FINDING_STATUSES
    ]
    intel = intelligence if isinstance(intelligence, dict) else {}
    flow = dataflow if isinstance(dataflow, dict) else {}
    runtime = runtime_validation if isinstance(runtime_validation, dict) else {}

    dimensions = [
        coverage_dimension(coverage),
        provenance_dimension(asset_items, active_findings),
        intelligence_dimension(intel),
        permission_dimension(permission_items),
        dataflow_dimension(flow),
        runtime_dimension(runtime),
    ]
    uncapped_score = sum(int(item["score"]) for item in dimensions)
    caps = score_caps(coverage, intel, runtime)
    score_cap = min([100, *[int(item["maximum_score"]) for item in caps]])
    discovered = integer(coverage.get("discovered_asset_count"), len(asset_items))
    score = 0 if discovered == 0 else min(uncapped_score, score_cap)
    evidence_completeness = evidence_completeness_score(
        asset_items, coverage, intel, flow, runtime
    )
    target_runtime_observed = has_target_runtime_evidence(runtime)
    confidence = confidence_label(evidence_completeness, target_runtime_observed)
    deductions = sorted(
        [
            {**item, "dimension_id": dimension["id"], "dimension_label": dimension["label"]}
            for dimension in dimensions
            for item in dimension["deductions"]
        ],
        key=lambda item: (-int(item["points"]), str(item["id"])),
    )
    report: dict[str, object] = {
        "schema": TRUST_SCORE_SCHEMA,
        "algorithm_version": TRUST_SCORE_ALGORITHM,
        "score": score,
        "uncapped_score": uncapped_score,
        "score_cap": score_cap,
        "grade": grade(score, discovered),
        "confidence": confidence,
        "evidence_completeness": evidence_completeness,
        "dimensions": dimensions,
        "top_deductions": deductions[:8],
        "improvements": improvements(deductions, coverage, intel, runtime),
        "score_caps": caps,
        "evidence_summary": {
            "asset_count": len(asset_items),
            "active_finding_count": len(active_findings),
            "permission_count": len(permission_items),
            "package_coordinate_count": integer(summary(intel).get("coordinate_count")),
            "dataflow_path_count": integer(summary(flow).get("path_count")),
            "target_runtime_observed": target_runtime_observed,
        },
        "limitations": [
            "The score summarizes current scanner evidence; it is not a security guarantee or publisher identity attestation.",
            "Accepted-risk findings still reduce the score. A false-positive status removes only direct finding-based deductions; independent provenance, intelligence, permission or data-flow evidence can still reduce the score.",
            "A local intelligence checked_no_match result means only that configured local sources did not match the exact version; it does not prove safety.",
            "Static data-flow paths are confidence-labelled inferences, not observed runtime calls or transfers.",
            "Harmless fixture validation tests the laboratory controls and never increases the scanned target's trust score.",
        ],
    }
    report["trust_sha256"] = sha256(
        json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return report


def coverage_dimension(coverage: dict[str, object]) -> dict[str, object]:
    maximum = 15
    discovered = integer(coverage.get("discovered_asset_count"))
    parsed = integer(coverage.get("parsed_asset_count"))
    failed = integer(coverage.get("failed_asset_count"))
    skipped = integer(coverage.get("skipped_file_count"))
    if discovered <= 0:
        return dimension(
            "inventory_coverage", "资产发现与解析", 0, maximum, "insufficient_evidence",
            [deduction("no-agent-assets", maximum, 1, "未发现可评分的 Agent、MCP 或插件资产。")],
            [], ["没有资产时不能推断项目安全。"],
        )
    score = round(maximum * min(parsed, discovered) / discovered)
    deductions: list[dict[str, object]] = []
    if failed:
        deductions.append(deduction("parse-failures", maximum - score, failed, "部分已发现资产未能成功解析。"))
    skipped_points = min(3, skipped)
    if skipped_points:
        score = max(0, score - skipped_points)
        deductions.append(deduction("skipped-files", skipped_points, skipped, "扫描限制或读取问题导致文件被跳过。"))
    return dimension(
        "inventory_coverage", "资产发现与解析", score, maximum,
        "complete" if parsed == discovered and not skipped else "partial",
        deductions,
        [f"已解析 {parsed}/{discovered} 个已发现资产。"],
        ["跳过文件可能包含未纳入评分的声明或配置。"] if skipped else [],
    )


def provenance_dimension(
    assets: list[dict[str, object]], findings: list[dict[str, object]]
) -> dict[str, object]:
    maximum = 20
    if not assets:
        return dimension("provenance_integrity", "来源、版本与哈希", 0, maximum, "insufficient_evidence", [], [], [])
    integrity_units = 0.0
    provenance: list[dict[str, object]] = []
    for asset in assets:
        status = str(asset.get("integrity_status") or "unavailable")
        has_digest = bool(asset.get("file_sha256") or asset.get("directory_sha256"))
        integrity_units += 1.0 if status == "recorded" and has_digest else 0.5 if status == "partial" else 0.0
        provenance.extend(item for item in list_of_dicts(asset.get("provenance")))
    integrity_score = round(10 * integrity_units / len(assets))
    known_sources = sum(str(item.get("source_type") or "unknown") != "unknown" for item in provenance)
    locked_sources = sum(
        str(item.get("version_status") or "missing") in {"locked", "not-applicable"}
        for item in provenance
    )
    source_score = 4 if not provenance else round(
        4 + 3 * known_sources / len(provenance) + 3 * locked_sources / len(provenance)
    )
    score = integrity_score + source_score
    deductions: list[dict[str, object]] = []
    missing_integrity = len(assets) - int(integrity_units)
    if integrity_score < 10:
        deductions.append(deduction("missing-integrity-evidence", 10 - integrity_score, missing_integrity, "部分资产缺少完整 SHA-256 证据。"))
    if source_score < 10:
        deductions.append(deduction("incomplete-source-evidence", 10 - source_score, max(1, len(provenance) - locked_sources), "来源未知、版本未锁定，或未声明可验证的来源记录。"))
    issue_weights = {
        "embedded-source-credentials": 8,
        "insecure-http-source": 6,
        "local-path-escape": 5,
        "source-unknown": 4,
        "version-unpinned": 3,
    }
    issues = [str(issue) for item in provenance for issue in (item.get("issues") or [])]
    for issue, points in issue_weights.items():
        count = issues.count(issue)
        if count:
            applied = min(score, min(10, points * count))
            score -= applied
            deductions.append(deduction(f"provenance-{issue}", applied, count, f"来源证据包含 {issue}。"))
    inline_secrets = sum(str(item.get("rule_id") or "") == "AGENT.SECRET.INLINE_TOKEN" for item in findings)
    if inline_secrets:
        applied = min(score, min(8, 4 * inline_secrets))
        score -= applied
        deductions.append(deduction("inline-secret-material", applied, inline_secrets, "资产声明中发现疑似内联令牌或密钥材料。"))
    limitations = ["发布者字段当前只是声明，尚未通过签名或注册表身份进行验证。"]
    if not provenance:
        limitations.append("未解析到包、镜像、Git 或本地启动来源；来源分只反映有限的本地文件证据。")
    return dimension(
        "provenance_integrity", "来源、版本与哈希", score, maximum,
        "complete" if score == maximum else "partial", deductions,
        [f"{len(assets)} 个资产中有 {int(integrity_units)} 个具备完整哈希证据。"], limitations,
    )


def intelligence_dimension(intelligence: dict[str, object]) -> dict[str, object]:
    maximum = 20
    values = summary(intelligence)
    coordinate_count = integer(values.get("coordinate_count"))
    if coordinate_count == 0:
        return dimension(
            "local_intelligence", "离线漏洞与恶意包情报", maximum, maximum, "not_applicable", [],
            ["未解析到可查询的精确包坐标，本分项不适用。"],
            ["不适用不等于组件安全；当前没有可供本地情报匹配的包坐标。"],
        )
    covered = integer(values.get("covered_count"))
    score = round(maximum * min(covered, coordinate_count) / coordinate_count)
    deductions: list[dict[str, object]] = []
    if covered < coordinate_count:
        deductions.append(deduction("intelligence-coverage-gap", maximum - score, coordinate_count - covered, "部分包坐标未被当前本地情报源覆盖。"))
    malicious = integer(values.get("malicious_match_count"))
    vulnerable = integer(values.get("vulnerable_package_count"))
    confusion = integer(values.get("package_confusion_count"))
    for identifier, count, points, detail in (
        ("malicious-package-match", malicious, maximum, "本地恶意包情报存在命中。"),
        ("known-vulnerable-package", vulnerable, 6, "本地漏洞情报存在精确版本命中。"),
        ("package-confusion-signal", confusion, 8, "检测到包混淆或相似名称威胁信号。"),
    ):
        if count:
            applied = min(score, points * count)
            score -= applied
            deductions.append(deduction(identifier, applied, count, detail))
    return dimension(
        "local_intelligence", "离线漏洞与恶意包情报", score, maximum,
        "complete" if covered == coordinate_count else "partial", deductions,
        [f"本地情报覆盖 {covered}/{coordinate_count} 个包坐标。"],
        ["checked_no_match 仅表示配置的本地源未匹配精确版本，不是安全结论。"],
    )


def permission_dimension(permissions: list[dict[str, object]]) -> dict[str, object]:
    maximum = 15
    score = maximum
    deductions: list[dict[str, object]] = []
    wildcard = sum(
        str(item.get("scope") or "").strip() in {"*", "**", "all"}
        or str(item.get("capability") or "") == "all-capabilities"
        for item in permissions
    )
    unapproved_high = sum(
        str(item.get("risk_level") or "").lower() in {"high", "critical"}
        and str(item.get("approval") or "").lower() != "required"
        for item in permissions
    )
    if wildcard:
        applied = min(score, 5 * wildcard)
        score -= applied
        deductions.append(deduction("wildcard-permissions", applied, wildcard, "存在全局或通配权限范围。"))
    if unapproved_high:
        applied = min(score, 3 * unapproved_high)
        score -= applied
        deductions.append(deduction("high-risk-without-approval", applied, unapproved_high, "高风险能力未声明人工审批要求。"))
    approved = sum(str(item.get("approval") or "").lower() == "required" for item in permissions)
    return dimension(
        "permission_approval", "权限范围与审批", score, maximum,
        "complete" if score == maximum else "partial", deductions,
        [f"识别 {len(permissions)} 条权限，其中 {approved} 条声明需要审批。"],
        ["声明了审批要求不代表运行时一定执行了审批。"] if approved else [],
    )


def dataflow_dimension(dataflow: dict[str, object]) -> dict[str, object]:
    maximum = 20
    values = summary(dataflow)
    if not dataflow:
        return dimension(
            "instruction_dataflow", "Prompt、工具与资源路径", 0, maximum, "missing",
            [deduction("missing-dataflow-model", maximum, 1, "没有可用的静态数据流模型。")], [],
            ["缺少模型时不能推断 Prompt、工具和资源之间不存在路径。"],
        )
    counts = {
        "critical-dataflow-path": (integer(values.get("critical_path_count")), 7, "存在严重静态数据流路径。"),
        "high-dataflow-path": (integer(values.get("high_path_count")), 4, "存在高风险静态数据流路径。"),
        "medium-dataflow-path": (integer(values.get("medium_path_count")), 2, "存在中风险静态数据流路径。"),
        "unguarded-dataflow-path": (integer(values.get("unguarded_path_count")), 2, "路径缺少审批、范围或隔离控制。"),
        "prompt-injection-path": (integer(values.get("prompt_injection_path_count")), 3, "检测到指令覆盖与工具/资源之间的关联路径。"),
    }
    score = maximum
    deductions: list[dict[str, object]] = []
    for identifier, (count, points, detail) in counts.items():
        if count:
            applied = min(score, points * count)
            score -= applied
            deductions.append(deduction(identifier, applied, count, detail))
    return dimension(
        "instruction_dataflow", "Prompt、工具与资源路径", score, maximum,
        "complete" if score == maximum else "risk_detected", deductions,
        [f"已建模 {integer(values.get('path_count'))} 条静态路径。"],
        ["静态路径包含保守推断，不等同于运行时已发生调用或数据传输。"],
    )


def runtime_dimension(runtime: dict[str, object]) -> dict[str, object]:
    maximum = 10
    if has_target_runtime_evidence(runtime):
        return dimension(
            "runtime_assurance", "受控运行验证", maximum, maximum, "observed", [],
            ["已记录目标 Agent 的受控运行证据。"],
            ["运行证据只覆盖该次镜像、命令、输入与策略。"],
        )
    has_plan = bool(runtime.get("schema") and isinstance(runtime.get("isolation_policy"), dict))
    score = 3 if has_plan else 0
    deductions = [deduction(
        "target-runtime-not-observed", maximum - score, 1,
        "尚未对被扫描目标执行受控沙箱运行验证。",
    )]
    return dimension(
        "runtime_assurance", "受控运行验证", score, maximum,
        "preflight_only" if has_plan else "not_run", deductions,
        ["已生成静态隔离预检计划；计划本身不会运行 Agent。"] if has_plan else [],
        ["无运行证据不代表风险路径未发生，也不代表目标安全。"],
    )


def score_caps(
    coverage: dict[str, object], intelligence: dict[str, object], runtime: dict[str, object]
) -> list[dict[str, object]]:
    caps: list[dict[str, object]] = []
    if not has_target_runtime_evidence(runtime):
        caps.append({"id": "static-evidence-only", "maximum_score": MAX_STATIC_SCORE, "detail": "缺少目标 Agent 运行证据，静态总分最高 90。"})
    if integer(coverage.get("failed_asset_count")):
        caps.append({"id": "parse-failures", "maximum_score": 70, "detail": "存在解析失败资产，总分最高 70。"})
    if integer(coverage.get("skipped_file_count")):
        caps.append({"id": "skipped-files", "maximum_score": 85, "detail": "存在跳过文件，总分最高 85。"})
    values = summary(intelligence)
    if integer(values.get("coordinate_count")) and integer(values.get("covered_count")) < integer(values.get("coordinate_count")):
        caps.append({"id": "intelligence-gaps", "maximum_score": 80, "detail": "包情报覆盖不完整，总分最高 80。"})
    return caps


def evidence_completeness_score(
    assets: list[dict[str, object]], coverage: dict[str, object], intelligence: dict[str, object],
    dataflow: dict[str, object], runtime: dict[str, object],
) -> int:
    discovered = integer(coverage.get("discovered_asset_count"), len(assets))
    parsed = integer(coverage.get("parsed_asset_count"), len(assets))
    coverage_points = round(20 * parsed / discovered) if discovered else 0
    digest_points = round(20 * sum(bool(item.get("file_sha256") or item.get("directory_sha256")) for item in assets) / len(assets)) if assets else 0
    provenance_points = round(15 * sum(bool(list_of_dicts(item.get("provenance"))) for item in assets) / len(assets)) if assets else 0
    intel_values = summary(intelligence)
    coordinates = integer(intel_values.get("coordinate_count"))
    intel_points = round(15 * integer(intel_values.get("covered_count")) / coordinates) if coordinates else 15
    dataflow_points = 15 if dataflow.get("schema") else 0
    runtime_points = 15 if has_target_runtime_evidence(runtime) else 5 if runtime.get("schema") else 0
    return min(100, coverage_points + digest_points + provenance_points + intel_points + dataflow_points + runtime_points)


def has_target_runtime_evidence(runtime: dict[str, object]) -> bool:
    evidence = runtime.get("evidence")
    if not isinstance(evidence, dict):
        return False
    return str(evidence.get("status") or "").lower() in {"completed", "passed", "observed"} and bool(evidence.get("execution_id"))


def confidence_label(completeness: int, target_runtime_observed: bool) -> str:
    label = "high" if completeness >= 80 else "medium" if completeness >= 50 else "low"
    return "medium" if label == "high" and not target_runtime_observed else label


def grade(score: int, discovered: int) -> str:
    if discovered == 0:
        return "insufficient-evidence"
    if score >= 90:
        return "provisional-high"
    if score >= 75:
        return "guarded"
    if score >= 50:
        return "low"
    return "untrusted"


def improvements(
    deductions: list[dict[str, object]], coverage: dict[str, object],
    intelligence: dict[str, object], runtime: dict[str, object],
) -> list[dict[str, str]]:
    mapping_by_id = {
        "no-agent-assets": ("确认扫描范围", "配置包含 AGENTS.md、MCP 配置或插件清单的正确目录。"),
        "parse-failures": ("修复解析失败", "修正格式或解析器不支持的声明，再重新扫描。"),
        "skipped-files": ("消除扫描盲区", "检查跳过原因并调整文件大小、权限或排除配置。"),
        "missing-integrity-evidence": ("补齐哈希证据", "确保目标文件和目录能够生成完整 SHA-256 快照。"),
        "incomplete-source-evidence": ("锁定来源和版本", "为包、Git 提交或镜像使用明确且不可变的版本标识。"),
        "inline-secret-material": ("移除内联密钥", "改用运行时秘密注入，并立即轮换疑似已暴露凭据。"),
        "intelligence-coverage-gap": ("补齐本地情报覆盖", "为未覆盖的生态和精确版本配置受控的离线情报源。"),
        "malicious-package-match": ("移除恶意包命中", "隔离命中的依赖并核验名称、来源与替代版本。"),
        "known-vulnerable-package": ("修复已知漏洞", "升级或替换命中的精确依赖版本。"),
        "package-confusion-signal": ("核验包身份", "核对私有包命名空间、注册表来源和锁文件。"),
        "wildcard-permissions": ("收敛通配权限", "把全局权限改成最小能力和最小资源范围。"),
        "high-risk-without-approval": ("增加高风险审批", "为写文件、执行命令、读取秘密等能力声明审批控制。"),
        "critical-dataflow-path": ("切断严重路径", "在 Prompt 到敏感工具或资源之间增加范围、审批和隔离。"),
        "high-dataflow-path": ("治理高风险路径", "复核高风险工具调用链并增加最小权限控制。"),
        "unguarded-dataflow-path": ("补齐路径控制", "为未受控路径增加审批、范围限制或沙箱策略。"),
        "prompt-injection-path": ("隔离指令覆盖影响", "阻止不可信指令直接控制敏感工具和资源。"),
        "target-runtime-not-observed": ("执行受控目标验证", "在确认命令、摘要锁定镜像和过滤副本后，单独批准沙箱运行。"),
    }
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in deductions:
        identifier = str(item.get("id") or "")
        key = identifier
        if identifier.startswith("provenance-"):
            key = "incomplete-source-evidence"
        if key in seen or key not in mapping_by_id:
            continue
        title, action = mapping_by_id[key]
        result.append({"id": key, "title": title, "action": action})
        seen.add(key)
    if not has_target_runtime_evidence(runtime) and "target-runtime-not-observed" not in seen:
        title, action = mapping_by_id["target-runtime-not-observed"]
        result.append({"id": "target-runtime-not-observed", "title": title, "action": action})
    return result[:8]


def dimension(
    identifier: str, label: str, score: int, maximum: int, status: str,
    deductions: list[dict[str, object]], positive_evidence: list[str], limitations: list[str],
) -> dict[str, object]:
    return {
        "id": identifier,
        "label": label,
        "score": max(0, min(maximum, int(score))),
        "max_score": maximum,
        "status": status,
        "deductions": [item for item in deductions if int(item.get("points") or 0) > 0],
        "positive_evidence": positive_evidence,
        "limitations": limitations,
    }


def deduction(identifier: str, points: int, count: int, detail: str) -> dict[str, object]:
    return {"id": identifier, "points": max(0, int(points)), "count": max(0, int(count)), "detail": detail}


def summary(report: dict[str, object]) -> dict[str, object]:
    value = report.get("summary")
    return value if isinstance(value, dict) else {}


def list_of_dicts(value: object) -> list[dict[str, object]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def mapping(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "model_dump"):
        result = value.model_dump()
        return result if isinstance(result, dict) else {}
    if hasattr(value, "__dict__"):
        return {key: item for key, item in vars(value).items() if not key.startswith("_")}
    return {}


def integer(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value if value is not None else default))
    except (TypeError, ValueError):
        return max(0, default)
