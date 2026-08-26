"""DAST-owned contract for an isolated SANDBOX execution backend.

DAST defines the approved intent, identifiers and evidence requirements.  The
SANDBOX module owns process/container/browser/OAST execution and returns facts;
it never decides the final vulnerability verdict.
"""
from __future__ import annotations

from hashlib import sha256
import os
from urllib.parse import urlparse
from uuid import uuid4
from typing import Any

from app.services.sandbox_identity import AUTO_REF_PREFIX, resolve_credential


LOCAL_STEP_KINDS = {"http_request", "login", "extract", "assert", "assert_compare", "switch_identity"}
SANDBOX_CAPABILITIES = {"browser", "oast", "timing_probe", "isolated_http", "agent_runtime"}
SAFE_HTTP_METHODS = {"GET", "HEAD", "OPTIONS"}
HTTP_PROBES = {"sql_injection", "ssrf", "command_injection", "path_traversal", "template_injection", "xxe", "open_redirect", "cors", "file_upload", "unsafe_deserialization", "code_injection", "account_recovery", "sensitive_data_exposure", "security_misconfiguration"}
BROWSER_PROBES = {"csrf", "xss", "access_control_mutation"}
AGENT_PROBES = {"agent_capability", "prompt_injection"}
ALLOWED_PROBES = HTTP_PROBES | BROWSER_PROBES | AGENT_PROBES
DESTRUCTIVE_ACTIONS = {"delete", "payment", "purchase", "send_email", "email", "upload", "file_upload", "modify", "write_file"}


def required_capabilities(flow: Any) -> list[str]:
    criteria = flow.sufficiency_criteria if isinstance(flow.sufficiency_criteria, dict) else {}
    capabilities = {
        str(value)
        for value in criteria.get("required_capabilities", [])
        if str(value) in SANDBOX_CAPABILITIES
    }
    for step in flow.steps if isinstance(flow.steps, list) else []:
        if not isinstance(step, dict):
            continue
        if str(step.get("kind") or "") in LOCAL_STEP_KINDS:
            capabilities.add("isolated_http")
        if str(step.get("kind") or "") == "sandbox_probe" and str(step.get("capability") or "") in SANDBOX_CAPABILITIES:
            capabilities.add(str(step["capability"]))
        if str(step.get("kind") or "") == "browser_action":
            capabilities.add("browser")
    return sorted(capabilities)


def probe_adapter(step: dict[str, object]) -> str | None:
    """Return the concrete fixed executor for a declared sandbox probe.

    Keeping this mapping next to the DAST contract prevents a probe from passing
    policy validation merely because its name is known while no runtime adapter
    can actually execute it.
    """
    probe = str(step.get("probe") or "")
    if probe in HTTP_PROBES:
        return "http"
    if probe in BROWSER_PROBES:
        return "browser"
    if probe in AGENT_PROBES:
        return "agent"
    return None


def step_adapter(step: dict[str, object]) -> str | None:
    """Return the concrete SANDBOX executor for every accepted contract step."""
    kind = str(step.get("kind") or "")
    if kind in LOCAL_STEP_KINDS:
        return "http"
    if kind == "browser_action":
        return "browser"
    if kind == "sandbox_probe":
        return probe_adapter(step)
    return None


def execution_preflight(project: Any, flow: Any) -> dict[str, object]:
    checks: list[dict[str, object]] = []

    def add(code: str, label: str, status: str, detail: str, remediation: str | None = None) -> None:
        checks.append({"code": code, "label": label, "status": status, "detail": detail, "remediation": remediation})

    configured_targets = [value for value in (getattr(project, "api_base_url", None), getattr(project, "runtime_url", None)) if value]
    has_sandbox_target = bool(getattr(project, "sandbox_image", None) and getattr(project, "sandbox_command", None))
    target_ready = bool(configured_targets) or has_sandbox_target
    add("target", "运行目标", "passed" if target_ready else "blocked", str(flow.target_url) if target_ready else "项目既没有运行地址，也没有 SANDBOX 目标配置。", "配置 runtime_url/api_base_url，或配置 sandbox_image 与 sandbox_command。" if not target_ready else None)
    add("approval", "授权审批", "passed" if flow.status == "approved" else "blocked", "策略范围已审批。" if flow.status == "approved" else "策略仍是草稿。", "填写审批依据和审批人后锁定策略。" if flow.status != "approved" else None)
    scope_ready = _same_origin(flow.target_url, configured_targets) or has_sandbox_target
    add("scope", "目标范围", "passed" if scope_ready else "blocked", "目标与项目配置同源，或将在项目专属隔离实例内重写同源地址。" if scope_ready else "目标不属于项目已配置同源范围。")
    add("paths", "路径白名单", "passed" if flow.allowed_paths else "blocked", f"已批准 {len(flow.allowed_paths or [])} 条路径。" if flow.allowed_paths else "未配置允许路径。")
    steps = flow.steps if isinstance(flow.steps, list) else []
    add("steps", "策略步骤", "passed" if steps else "blocked", f"共 {len(steps)} 个步骤。" if steps else "策略没有执行步骤。")
    policy_issues = validate_flow_policy(flow)
    add("policy", "安全策略", "blocked" if policy_issues else "passed", "；".join(policy_issues) if policy_issues else "方法、目标、角色和探针均通过静态安全校验。", "修改策略后重新审批。" if policy_issues else None)
    credential_refs = sorted({str(role.get("credential_ref")) for role in flow.roles if isinstance(role, dict) and role.get("credential_ref")})
    missing_credentials = [
        ref for ref in credential_refs
        if (ref.startswith("env:") and not os.getenv(ref[4:]))
        or (ref.startswith(AUTO_REF_PREFIX) and not resolve_credential(getattr(project, "id", ""), ref))
    ]
    add("sessions", "测试会话", "blocked" if missing_credentials else "passed", "缺少项目测试身份：" + "、".join(missing_credentials) if missing_credentials else (f"{len(credential_refs)} 个受保护会话引用已就绪。" if credential_refs else "当前策略使用匿名隔离会话。"), "先在 SANDBOX 启动项目隔离实例；系统会尝试自动创建一次性测试用户。只有无法识别登录流程时才需要管理员接入项目级密钥。" if missing_credentials else None)
    blocking_items = [str(value) for value in (flow.sufficiency_criteria or {}).get("blocking_items", []) if str(value)]
    add("context", "运行时上下文", "blocked" if blocking_items else "passed", "仍缺少：" + "、".join(blocking_items) if blocking_items else "策略所需运行时上下文已齐备。", "先完成上游自动映射或后端测试身份配置。" if blocking_items else None)
    capabilities = required_capabilities(flow)
    local_only = bool(steps) and all(isinstance(step, dict) and str(step.get("kind") or "") in LOCAL_STEP_KINDS for step in steps)
    unmapped_steps = [
        str(step.get("id") or index)
        for index, step in enumerate(steps, start=1)
        if not isinstance(step, dict) or step_adapter(step) is None
    ]
    add(
        "executor",
        "执行后端",
        "blocked" if unmapped_steps else "waiting",
        "缺少 SANDBOX 固定执行适配器：" + "、".join(unmapped_steps)
        if unmapped_steps
        else f"已映射 SANDBOX 执行器：{'、'.join(capabilities)}。",
        "为缺失步骤实现并注册固定执行适配器后重新审批。" if unmapped_steps else None,
    )
    blockers = [item for item in checks if item["status"] == "blocked"]
    waiting = [item for item in checks if item["status"] == "waiting"]
    return {
        "status": "blocked" if blockers else "waiting_sandbox" if waiting else "ready",
        "can_execute_local": not blockers and local_only,
        "can_handoff_sandbox": not blockers and bool(steps) and not unmapped_steps and bool(capabilities),
        "required_capabilities": capabilities,
        "checks": checks,
    }


def validate_flow_policy(flow: Any) -> list[str]:
    steps = flow.steps if isinstance(flow.steps, list) else []
    roles = flow.roles if isinstance(flow.roles, list) else []
    if len(steps) > 50:
        return ["策略步骤超过 50 个"]
    aliases = {str(role.get("alias") or "") for role in roles if isinstance(role, dict)} - {""}
    issues: list[str] = []
    seen: set[str] = set()
    target_origin = _origin(str(flow.target_url))
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            issues.append(f"步骤 {index} 不是对象")
            continue
        step_id = str(step.get("id") or "")
        kind = str(step.get("kind") or "")
        if not step_id or step_id in seen:
            issues.append(f"步骤 {index} 缺少唯一 ID")
        seen.add(step_id)
        if kind not in LOCAL_STEP_KINDS | {"sandbox_probe", "browser_action"}:
            issues.append(f"{step_id or index} 使用未知步骤类型")
        role = str(step.get("role") or "")
        if kind in {"http_request", "login", "sandbox_probe", "browser_action"} and role and role not in aliases:
            issues.append(f"{step_id or index} 引用了未定义角色")
        method = str(step.get("method") or ("POST" if kind == "login" else "GET")).upper()
        if kind == "http_request" and method not in SAFE_HTTP_METHODS:
            issues.append(f"{step_id or index} 的 HTTP 方法不在 DAST 安全白名单")
        if kind == "login" and method != "POST":
            issues.append(f"{step_id or index} 的登录步骤必须使用 POST")
        url = str(step.get("url") or "")
        if url and _origin(url) != target_origin:
            issues.append(f"{step_id or index} 的目标不是批准的同源地址")
        if kind == "browser_action" and str(step.get("action") or "").lower() in DESTRUCTIVE_ACTIONS:
            issues.append(f"{step_id or index} 包含被禁止的浏览器业务动作")
        if kind == "sandbox_probe":
            if str(step.get("capability") or "") not in SANDBOX_CAPABILITIES:
                issues.append(f"{step_id or index} 声明了未知 SANDBOX 能力")
            if str(step.get("probe") or "") not in ALLOWED_PROBES:
                issues.append(f"{step_id or index} 声明了未知探针")
            elif probe_adapter(step) is None:
                issues.append(f"{step_id or index} 的探针尚无固定执行适配器")
            if str(step.get("probe") or "") == "csrf":
                if method != "POST":
                    issues.append(f"{step_id or index} 的 CSRF 探针必须针对 POST 状态变更表单")
                if not [value for value in step.get("parameters", []) if str(value)] if isinstance(step.get("parameters"), list) else True:
                    issues.append(f"{step_id or index} 的 CSRF 探针缺少已映射表单参数")
    for role in roles:
        if not isinstance(role, dict):
            issues.append("角色配置不是对象")
            continue
        ref = str(role.get("credential_ref") or "")
        valid_env = ref.startswith("env:") and ref[4:].replace("_", "").isalnum()
        valid_sandbox = ref.startswith(AUTO_REF_PREFIX) and ref[len(AUTO_REF_PREFIX):].replace("_", "").isalnum()
        if ref and not (valid_env or valid_sandbox):
            issues.append(f"角色 {role.get('alias') or 'unknown'} 的凭据不是安全的后端引用")
    return issues


def build_sandbox_handoff(project: Any, flow: Any, run_id: str, callback_token: str) -> dict[str, object]:
    preflight = execution_preflight(project, flow)
    if preflight["status"] == "blocked" or not preflight["can_handoff_sandbox"]:
        raise ValueError("DAST execution preflight is blocked")
    steps = [_safe_step(step) for step in flow.steps if isinstance(step, dict)]
    return {
        "schema": "ai-security-platform.dast-sandbox-handoff/v1",
        "task_id": run_id,
        "strategy_id": str(flow.id),
        "project_id": str(flow.project_id),
        "finding_id": str(flow.finding_id) if flow.finding_id else None,
        "target": {"url": flow.target_url, "same_origin_only": True, "allowed_paths": list(flow.allowed_paths or [])},
        "authorization": {"reference": flow.approval_reference, "approved_by": flow.approved_by, "approved_at": flow.approved_at.isoformat() if flow.approved_at else None},
        "limits": {"timeout_seconds": 120, "max_requests": 40, "max_concurrency": 2, "requests_per_second": 2, "max_response_bytes": 1_048_576, "follow_cross_origin_redirects": False, "destructive_actions": False},
        "network_policy": {"target_only": True, "deny_cloud_metadata": True, "deny_platform_services": True, "oast_exception_requires_capability": True},
        "required_capabilities": preflight["required_capabilities"],
        "roles": [{"alias": role.get("alias"), "credential_ref": role.get("credential_ref"), "description": role.get("description")} for role in flow.roles if isinstance(role, dict)],
        "steps": steps,
        "evidence_requirements": (flow.sufficiency_criteria or {}).get("evidence_requirements", []),
        "callback": {"path": f"/dast/business-runs/{run_id}/sandbox-result", "token": callback_token},
    }


def callback_token_hash(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def new_callback_token() -> str:
    return f"dast_{uuid4().hex}_{uuid4().hex}"


def _same_origin(target: str, configured: list[str]) -> bool:
    target_origin = _origin(target)
    return target_origin is not None and target_origin in {_origin(value) for value in configured}


def _origin(value: str) -> tuple[str, str, int] | None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)


def _safe_step(step: dict[str, object]) -> dict[str, object]:
    # Credential values are never part of the handoff.  Only protected backend
    # references are allowed; SANDBOX resolves them at execution time.
    safe = {str(key): value for key, value in step.items() if str(key) not in {"cookie", "token", "password", "secret"}}
    if str(step.get("kind") or "") in {"http_request", "login", "sandbox_probe", "browser_action"}:
        safe["request_id"] = str(uuid4())
    return safe
