import re
from pathlib import PurePath
from urllib.parse import unquote, urlparse

from app.db_models import ComponentRecord, DastValidationRecord, FindingRecord
from app.models import LinkSuggestion


IDENTIFIER_PATTERN = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|CWE-\d+)\b", re.IGNORECASE)
TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_\-]{3,}")
RISK_FAMILIES: dict[str, tuple[str, ...]] = {
    "SQL 注入": ("sql", "sqli", "database", "query", "login"),
    "跨站脚本": ("xss", "script", "html", "template", "search", "comment"),
    "命令执行": ("command", "exec", "shell", "rce", "process", "upload"),
    "路径穿越": ("path", "traversal", "file", "download", "read"),
    "服务端请求伪造": ("ssrf", "request", "fetch", "proxy", "url"),
    "身份认证": ("auth", "login", "token", "session", "password", "jwt"),
    "开放重定向": ("redirect", "return", "next", "callback"),
    "文件上传": ("upload", "file", "attachment", "import"),
}


def build_dast_link_suggestions(
    target_url: str,
    findings: list[FindingRecord],
    components: dict[str, ComponentRecord],
    limit: int = 5,
) -> list[LinkSuggestion]:
    target_text = unquote(target_url).lower()
    parsed = urlparse(target_url)
    target_tokens = tokens(" ".join((parsed.path, parsed.query, parsed.fragment)))
    suggestions: list[LinkSuggestion] = []

    for finding in findings:
        score = 0
        reasons: list[str] = []
        finding_text = finding_blob(finding)
        finding_tokens = tokens(finding_text)

        identifiers = sorted(set(IDENTIFIER_PATTERN.findall(finding_text)))
        matched_identifiers = [item for item in identifiers if item.lower() in target_text]
        if matched_identifiers:
            score += 45
            reasons.append(f"目标地址包含风险标识：{', '.join(matched_identifiers)}")

        overlap = sorted(target_tokens & finding_tokens)
        if overlap:
            token_score = min(30, 10 + len(overlap) * 5)
            score += token_score
            reasons.append(f"URL 路径与风险字段命中关键词：{', '.join(overlap[:5])}")

        family_matches = matched_risk_families(target_text, finding_text)
        if family_matches:
            score += min(35, 20 + (len(family_matches) - 1) * 5)
            reasons.append(f"漏洞类型与目标场景匹配：{', '.join(family_matches)}")

        if finding.source.upper() == "SAST":
            score += 10
            reasons.append("SAST 代码发现适合进入动态验证")
        elif finding.source.upper() == "SCA" and finding.component_id:
            score += 8
            reasons.append("供应链风险已定位到具体组件")

        if finding.severity in {"critical", "high"}:
            score += 5
            reasons.append("风险等级较高，建议优先验证")

        component = components.get(str(finding.component_id)) if finding.component_id else None
        suggestions.append(
            suggestion(
                score,
                reasons,
                f"{finding.source} · {finding.severity} · {finding.title}",
                finding_id=finding.id,
                component_id=component.id if component else None,
            )
        )

    return ranked(suggestions, limit)


def build_sandbox_link_suggestions(
    run_command: str,
    findings: list[FindingRecord],
    components: dict[str, ComponentRecord],
    validations: list[DastValidationRecord],
    selected_finding_id: str | None = None,
    selected_component_id: str | None = None,
    limit: int = 5,
) -> list[LinkSuggestion]:
    command_text = run_command.lower()
    command_tokens = tokens(command_text)
    findings_by_id = {str(item.id): item for item in findings}
    suggestions: list[LinkSuggestion] = []

    for validation in validations:
        finding = findings_by_id.get(str(validation.finding_id)) if validation.finding_id else None
        component_id = validation.component_id or (finding.component_id if finding else None)
        score = 0
        reasons: list[str] = []

        if selected_finding_id and validation.finding_id == selected_finding_id:
            score += 55
            reasons.append("DAST 验证与当前 Finding 完全一致")
        if selected_component_id and component_id == selected_component_id:
            score += 45
            reasons.append("DAST 验证与当前组件完全一致")

        if finding:
            overlap = sorted(command_tokens & tokens(finding_blob(finding)))
            if overlap:
                score += min(40, 15 + len(overlap) * 5)
                reasons.append(f"运行命令与风险字段命中关键词：{', '.join(overlap[:5])}")
            if finding.file_path:
                file_name = PurePath(finding.file_path).name.lower()
                file_stem = PurePath(finding.file_path).stem.lower()
                if file_name in command_text or file_stem in command_tokens:
                    score += 45
                    reasons.append(f"运行命令直接引用风险文件：{file_name}")

        if validation.verdict == "exploitable":
            score += 30
            reasons.append("DAST 已裁决为可利用，适合进入沙箱复现")
        elif validation.verdict == "uncertain":
            score += 20
            reasons.append("DAST 裁决不确定，建议通过沙箱补充证据")
        else:
            score += 5
            reasons.append("已有 DAST 验证记录可供交叉核验")

        if validation.finding_id or component_id:
            score += 10
            reasons.append("该验证已有可追溯的上游关联")

        suggestions.append(
            suggestion(
                score,
                reasons,
                f"DAST · {validation.verdict} · {validation.target_url}",
                finding_id=validation.finding_id,
                component_id=component_id,
                validation_id=validation.id,
            )
        )

    linked_finding_ids = {str(item.finding_id) for item in validations if item.finding_id}
    for finding in findings:
        if str(finding.id) in linked_finding_ids:
            continue
        score = 0
        reasons: list[str] = []
        overlap = sorted(command_tokens & tokens(finding_blob(finding)))
        if overlap:
            score += min(50, 20 + len(overlap) * 5)
            reasons.append(f"运行命令与风险字段命中关键词：{', '.join(overlap[:5])}")
        if finding.file_path:
            file_name = PurePath(finding.file_path).name.lower()
            file_stem = PurePath(finding.file_path).stem.lower()
            if file_name in command_text or file_stem in command_tokens:
                score += 45
                reasons.append(f"运行命令直接引用风险文件：{file_name}")
        if selected_finding_id and str(finding.id) == selected_finding_id:
            score += 55
            reasons.append("与当前已选 Finding 一致")
        if selected_component_id and finding.component_id == selected_component_id:
            score += 45
            reasons.append("与当前已选组件一致")
        if finding.source.upper() in {"SAST", "AGENT"}:
            score += 10
            reasons.append(f"{finding.source} 发现可通过运行时行为补充证据")
        component = components.get(str(finding.component_id)) if finding.component_id else None
        suggestions.append(
            suggestion(
                score,
                reasons,
                f"{finding.source} · {finding.severity} · {finding.title}",
                finding_id=finding.id,
                component_id=component.id if component else None,
            )
        )

    return ranked(suggestions, limit)


def finding_blob(finding: FindingRecord) -> str:
    ai_review = finding.ai_review or {}
    fields = [
        finding.rule_id,
        finding.title,
        finding.file_path or "",
        finding.evidence or "",
        str(ai_review.get("category") or ""),
        str(ai_review.get("cwe") or ""),
        str(ai_review.get("owasp") or ""),
        str(ai_review.get("description") or ""),
    ]
    if finding.file_path:
        fields.append(PurePath(finding.file_path).name)
    return " ".join(fields).lower()


def tokens(value: str) -> set[str]:
    return {token.lower() for token in TOKEN_PATTERN.findall(value)}


def matched_risk_families(target_text: str, finding_text: str) -> list[str]:
    matches: list[str] = []
    for label, keywords in RISK_FAMILIES.items():
        if any(keyword in target_text for keyword in keywords) and any(
            keyword in finding_text for keyword in keywords
        ):
            matches.append(label)
    return matches


def suggestion(
    score: int,
    reasons: list[str],
    label: str,
    finding_id: str | None = None,
    component_id: str | None = None,
    validation_id: str | None = None,
) -> LinkSuggestion:
    confidence = min(100, score)
    return LinkSuggestion(
        finding_id=finding_id,
        component_id=component_id,
        validation_id=validation_id,
        confidence=confidence,
        confidence_level="high" if confidence >= 80 else "medium" if confidence >= 50 else "low",
        reasons=reasons or ["当前仅有同项目上下文，缺少可区分的匹配信号"],
        label=label,
    )


def ranked(suggestions: list[LinkSuggestion], limit: int) -> list[LinkSuggestion]:
    return sorted(suggestions, key=lambda item: item.confidence, reverse=True)[:limit]
