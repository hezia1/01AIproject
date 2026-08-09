"""Evidence-based SCA resolution and coverage summaries.

The scanner must not equate an unavailable vulnerability lookup with a clean
component.  This module keeps version resolution and vulnerability coverage
separate from the risk verdict so API and standalone CI use the same rules.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from app.services.sca_parser import ParsedComponent


RESOLVED_SOURCES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pipfile.lock",
    "gemfile.lock",
    "composer.lock",
    "cargo.lock",
    "packages.lock.json",
}


def component_resolution(component: ParsedComponent) -> dict[str, object]:
    version = str(component.version or "").strip()
    source = component.source_file.replace("\\", "/")
    source_name = PurePosixPath(source).name.lower()
    if not version:
        return {
            "status": "missing",
            "confidence": "none",
            "lookup_version": None,
            "source": source,
            "reason": "组件版本缺失",
        }
    if source_name in RESOLVED_SOURCES or "pip inspect" in source.lower() or source.lower().startswith("syft:"):
        return {
            "status": "resolved",
            "confidence": "high",
            "lookup_version": canonical_version(version),
            "source": source,
            "reason": "版本来自锁文件、实际安装环境或 Syft 清单",
        }
    if is_version_constraint(version):
        return {
            "status": "constraint",
            "confidence": "low",
            "lookup_version": None,
            "source": source,
            "reason": "依赖清单只声明版本范围，无法确定实际安装版本",
        }
    return {
        "status": "declared_exact",
        "confidence": "medium",
        "lookup_version": canonical_version(version),
        "source": source,
        "reason": "清单声明了固定版本，但未由锁文件或安装环境证明",
    }


def canonical_version(version: str) -> str:
    value = version.strip()
    if value.startswith("==="):
        return value[3:].strip()
    if value.startswith("=="):
        return value[2:].strip()
    return value


def is_version_constraint(version: str) -> bool:
    value = version.strip()
    if value.startswith(("==", "===")):
        return False
    if value.lower().startswith(("workspace:", "file:", "link:", "git+", "http://", "https://")):
        return True
    if re.search(r"(?:\^|~|>=|<=|!=|>|<|\*|\bx\b|\bX\b|\|\||\s+-\s)", value):
        return True
    return "," in value or ";" in value


def vulnerability_verification(component: ParsedComponent) -> str:
    resolution = component_resolution(component)
    if resolution["status"] in {"missing", "constraint"}:
        return "unverified"
    metadata = component.risk_metadata or {}
    if component.vulnerability_ids:
        return "matched"
    if component.osv_checked:
        return "verified_no_match"
    tool_coverage = metadata.get("tool_coverage")
    if isinstance(tool_coverage, dict) and tool_coverage.get("verified") is True:
        return "verified_no_match"
    return "unverified"


def build_sca_assurance(
    components: list[ParsedComponent],
    scanned_files: list[str],
    *,
    tool_status: dict[str, object] | None = None,
) -> dict[str, object]:
    resolutions = [component_resolution(component) for component in components]
    verifications = [vulnerability_verification(component) for component in components]
    total = len(components)
    resolved = sum(item["status"] in {"resolved", "declared_exact"} for item in resolutions)
    locked = sum(item["status"] == "resolved" for item in resolutions)
    declared_exact = sum(item["status"] == "declared_exact" for item in resolutions)
    constrained = sum(item["status"] == "constraint" for item in resolutions)
    unverified = sum(item == "unverified" for item in verifications)
    verified = total - unverified
    completeness = round((verified / total) * 100) if total else 0
    status = "complete" if total and unverified == 0 and locked == total else "partial" if total else "empty"
    reasons: list[str] = []
    if not scanned_files:
        reasons.append("未发现受支持的依赖清单或锁文件")
    if constrained:
        reasons.append(f"{constrained} 个组件只有版本范围，无法确认实际安装版本")
    if declared_exact:
        reasons.append(f"{declared_exact} 个组件仅由清单声明固定版本，未由锁文件或实际安装环境证明")
    if unverified:
        reasons.append(f"{unverified} 个组件没有完成漏洞情报验证")
    if tool_status and str(tool_status.get("status") or "") in {"failed", "partial_failed"}:
        reasons.append("一个或多个增强扫描引擎未完整执行")
    return {
        "status": status,
        "confidence": "high" if status == "complete" and locked == total else "medium" if completeness >= 80 else "low",
        "component_count": total,
        "resolved_component_count": resolved,
        "lock_or_environment_component_count": locked,
        "declared_exact_component_count": declared_exact,
        "constraint_component_count": constrained,
        "verified_component_count": verified,
        "unverified_component_count": unverified,
        "vulnerability_coverage_percent": completeness,
        "scanned_files": list(scanned_files),
        "reasons": reasons,
        "statement": (
            "漏洞情报已覆盖全部已解析组件；仍需结合运行环境确认业务可利用性。"
            if status == "complete"
            else "扫描结果不完整；未验证不代表安全，门禁应按策略阻断或人工复核。"
        ),
    }
