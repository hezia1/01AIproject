"""Safe, bounded execution primitives for DAST business-flow verification.

This module intentionally has no browser adapter. Browser steps are represented
and audited, but remain blocked until an approved browser runtime is installed.
"""
from __future__ import annotations

from http.cookiejar import CookieJar
import json
import os
import re
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, Request, build_opener


class BusinessFlowError(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
STEP_KINDS = {"http_request", "login", "extract", "assert", "switch_identity", "browser_action"}
BLOCKED_BROWSER_ACTIONS = {"delete", "payment", "send", "email", "upload", "file_upload", "modify"}
SECRET_PATTERN = re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+|(?:api[_-]?key|token|password|secret)\s*[:=]\s*)[^\s,;]+")


def redact(value: str) -> str:
    return SECRET_PATTERN.sub(lambda match: f"{match.group(1)}[REDACTED]", value)


def dry_run(flow: Any) -> tuple[list[dict[str, object]], list[str]]:
    """Validate flow structure without constructing a request or contacting a target."""
    roles = flow.roles if isinstance(flow.roles, list) else []
    steps = flow.steps if isinstance(flow.steps, list) else []
    role_aliases = {str(item.get("alias") or "") for item in roles if isinstance(item, dict)} - {""}
    seen_ids: set[str] = set()
    snapshots: list[dict[str, object]] = []
    errors: list[str] = []
    for index, raw_step in enumerate(steps, start=1):
        step = raw_step if isinstance(raw_step, dict) else {}
        step_id = str(step.get("id") or f"step-{index}")
        kind = str(step.get("kind") or "")
        detail: dict[str, object] = {"index": index}
        status = "ready"
        message = "步骤结构通过本地校验。"
        if step_id in seen_ids:
            status, message = "blocked", "步骤 ID 重复。"
        elif kind not in STEP_KINDS:
            status, message = "blocked", "不支持的步骤类型。"
        elif kind in {"http_request", "login"}:
            role = str(step.get("role") or "")
            method = str(step.get("method") or ("POST" if kind == "login" else "GET")).upper()
            if role not in role_aliases:
                status, message = "blocked", "请求步骤必须引用已定义的业务角色。"
            elif not str(step.get("url") or "").strip():
                status, message = "blocked", "请求步骤缺少 URL。"
            elif method not in SAFE_METHODS and not (kind == "login" and method == "POST"):
                status, message = "blocked", "仅允许 GET、HEAD、OPTIONS，以及明确标记的登录 POST。"
            else:
                detail["method"] = method
        elif kind == "switch_identity" and str(step.get("role") or "") not in role_aliases:
            status, message = "blocked", "身份切换引用了未定义角色。"
        elif kind == "browser_action":
            action = str(step.get("action") or "").lower()
            if action in BLOCKED_BROWSER_ACTIONS:
                status, message = "blocked", "页面步骤包含被禁止的业务动作。"
            else:
                status, message = "blocked", "浏览器自动化适配器尚未安装；不会连接目标。"
        seen_ids.add(step_id)
        snapshots.append({"step_id": step_id, "step_kind": kind or "unknown", "role_alias": step.get("role"), "status": status, "request_summary": None, "response_summary": message, "detail": detail})
        if status == "blocked":
            errors.append(f"{step_id}: {message}")
    if not steps:
        errors.append("流程没有步骤。")
    if not role_aliases:
        errors.append("流程没有定义业务角色。")
    return snapshots, errors


def execute_api_flow(flow: Any, *, timeout_seconds: int = 15) -> tuple[list[dict[str, object]], str, str]:
    """Execute only the explicitly approved, safe HTTP portion of a flow.

    Browser actions, unsafe methods and missing credential references return a
    bounded uncertain outcome instead of attempting a best-effort action.
    """
    dry_snapshots, errors = dry_run(flow)
    if errors:
        return dry_snapshots, "uncertain", "流程未通过本地预执行校验。"
    sessions = _sessions_for_roles(flow.roles)
    variables: dict[str, object] = {}
    latest: dict[str, object] = {}
    snapshots: list[dict[str, object]] = []
    verdicts: list[str] = []
    for index, raw_step in enumerate(flow.steps, start=1):
        step = raw_step if isinstance(raw_step, dict) else {}
        step_id = str(step.get("id") or f"step-{index}")
        kind = str(step.get("kind") or "")
        role = str(step.get("role") or "")
        if kind == "browser_action":
            snapshots.append(_snapshot(step_id, kind, role, "blocked", None, "浏览器自动化适配器尚未安装；未连接目标。", {}))
            return snapshots, "uncertain", "流程需要浏览器步骤，但浏览器适配器尚不可用。"
        if kind == "switch_identity":
            snapshots.append(_snapshot(step_id, kind, role, "completed", None, "已切换到独立身份会话。", {}))
            continue
        if kind in {"http_request", "login"}:
            try:
                result = _request_step(flow, step, sessions, variables, timeout_seconds)
            except BusinessFlowError as exc:
                snapshots.append(_snapshot(step_id, kind, role, "blocked", None, str(exc), {}))
                return snapshots, "uncertain", f"步骤 {step_id} 被安全策略阻止。"
            except (HTTPError, URLError, TimeoutError, OSError) as exc:
                snapshots.append(_snapshot(step_id, kind, role, "failed", None, f"请求异常：{type(exc).__name__}", {}))
                return snapshots, "uncertain", f"步骤 {step_id} 未获得充分响应证据。"
            latest = result
            snapshots.append(_snapshot(step_id, kind, role, "completed", str(result["request_summary"]), str(result["response_summary"]), {"status_code": result["status_code"]}))
            continue
        if kind == "extract":
            variable = str(step.get("variable") or "")
            source = str(step.get("source") or "json")
            path = str(step.get("path") or "")
            value = _extract(latest, source, path)
            if not variable or value is None:
                snapshots.append(_snapshot(step_id, kind, role or None, "failed", None, "无法从上一步响应提取变量。", {"variable": variable, "path": path}))
                return snapshots, "uncertain", f"步骤 {step_id} 缺少后续所需变量。"
            variables[variable] = value
            snapshots.append(_snapshot(step_id, kind, role or None, "completed", None, "变量已提取并仅保留在本次运行内存中。", {"variable": variable}))
            continue
        if kind == "assert":
            passed, message = _assert(latest, step)
            snapshots.append(_snapshot(step_id, kind, role or None, "passed" if passed else "failed", None, message, {}))
            if not passed:
                return snapshots, "uncertain", f"步骤 {step_id} 的断言未满足。"
            verdict = str(step.get("verdict_on_pass") or "")
            if verdict in {"exploitable", "not_exploitable"}:
                verdicts.append(verdict)
            continue
        snapshots.append(_snapshot(step_id, kind or "unknown", role or None, "blocked", None, "未实现的步骤类型。", {}))
        return snapshots, "uncertain", f"步骤 {step_id} 不可执行。"
    if verdicts and len(set(verdicts)) == 1:
        return snapshots, verdicts[0], "所有必需步骤和裁决断言均已完成。"
    return snapshots, "uncertain", "流程完成，但未提供充分且一致的三色裁决断言。"


def _sessions_for_roles(roles: list[dict[str, object]]) -> dict[str, object]:
    sessions: dict[str, object] = {}
    for role in roles:
        alias = str(role.get("alias") or "")
        if alias:
            sessions[alias] = build_opener(NoRedirect(), HTTPCookieProcessor(CookieJar()))
    return sessions


def _request_step(flow: Any, step: dict[str, object], sessions: dict[str, object], variables: dict[str, object], timeout_seconds: int) -> dict[str, object]:
    role = str(step.get("role") or "")
    opener = sessions.get(role)
    if opener is None:
        raise BusinessFlowError("业务角色没有独立会话。")
    kind = str(step.get("kind") or "")
    method = str(step.get("method") or ("POST" if kind == "login" else "GET")).upper()
    if method not in SAFE_METHODS and not (kind == "login" and method == "POST"):
        raise BusinessFlowError("请求方法不在安全白名单。")
    url = _render(str(step.get("url") or ""), variables, _credential_values(flow.roles, role))
    parsed = urlparse(url)
    target = urlparse(flow.target_url)
    if not parsed.scheme or (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)) != (target.scheme, target.hostname, target.port or (443 if target.scheme == "https" else 80)):
        raise BusinessFlowError("请求 URL 不属于流程批准的目标同源范围。")
    allowed_paths = [str(value) for value in flow.allowed_paths]
    if allowed_paths and not any(parsed.path.startswith(path) for path in allowed_paths):
        raise BusinessFlowError("请求路径不在流程批准范围内。")
    query = step.get("query") if isinstance(step.get("query"), dict) else {}
    if query:
        separator = "&" if parsed.query else "?"
        url = f"{url}{separator}{urlencode({str(key): _render(str(value), variables, _credential_values(flow.roles, role)) for key, value in query.items()})}"
    headers = {str(key): _render(str(value), variables, _credential_values(flow.roles, role)) for key, value in (step.get("headers") if isinstance(step.get("headers"), dict) else {}).items()}
    body = step.get("body") if isinstance(step.get("body"), dict) else None
    data = json.dumps(_render_object(body, variables, _credential_values(flow.roles, role)), ensure_ascii=False).encode("utf-8") if body is not None else None
    if data is not None:
        headers.setdefault("Content-Type", "application/json")
    request = Request(url, data=data, headers=headers, method=method)
    response = opener.open(request, timeout=max(1, min(int(timeout_seconds), 30)))
    raw = response.read(65536).decode("utf-8", errors="replace")
    status = int(getattr(response, "status", 200))
    response_headers = {str(key): str(value) for key, value in response.headers.items()}
    return {"status_code": status, "headers": response_headers, "body": raw, "request_summary": redact(f"{method} {url}"), "response_summary": redact(f"HTTP {status}; body bytes={len(raw.encode('utf-8'))}")}


def _credential_values(roles: list[dict[str, object]], alias: str) -> dict[str, object]:
    role = next((item for item in roles if str(item.get("alias") or "") == alias), None)
    ref = str((role or {}).get("credential_ref") or "")
    if not ref:
        return {}
    if not ref.startswith("env:"):
        raise BusinessFlowError("凭据引用必须使用 env:变量名，不接受明文凭据。")
    value = os.getenv(ref[4:], "")
    if not value:
        raise BusinessFlowError("所引用的测试身份凭据未在后端环境中配置。")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {"token": value}
    return parsed if isinstance(parsed, dict) else {"token": value}


def _render(value: str, variables: dict[str, object], credentials: dict[str, object]) -> str:
    def replace(match: re.Match[str]) -> str:
        expression = match.group(1).strip()
        source, _, key = expression.partition(".")
        if source == "credential":
            return str(credentials.get(key, ""))
        return str(variables.get(expression, ""))
    return re.sub(r"\{\{\s*([^}]+)\s*\}\}", replace, value)


def _render_object(value: object, variables: dict[str, object], credentials: dict[str, object]) -> object:
    if isinstance(value, str):
        return _render(value, variables, credentials)
    if isinstance(value, list):
        return [_render_object(item, variables, credentials) for item in value]
    if isinstance(value, dict):
        return {str(key): _render_object(item, variables, credentials) for key, item in value.items()}
    return value


def _extract(latest: dict[str, object], source: str, path: str) -> object | None:
    if source == "header":
        return (latest.get("headers") if isinstance(latest.get("headers"), dict) else {}).get(path)
    if source != "json":
        return None
    try:
        value: object = json.loads(str(latest.get("body") or ""))
    except json.JSONDecodeError:
        return None
    for part in [item for item in path.split(".") if item]:
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _assert(latest: dict[str, object], step: dict[str, object]) -> tuple[bool, str]:
    allowed = step.get("status_in") if isinstance(step.get("status_in"), list) else []
    if allowed and int(latest.get("status_code") or 0) not in {int(item) for item in allowed}:
        return False, f"实际状态码 {latest.get('status_code')} 不在允许集合。"
    contains = str(step.get("body_contains") or "")
    if contains and contains not in str(latest.get("body") or ""):
        return False, "响应正文未包含断言标记。"
    if not allowed and not contains:
        return False, "断言没有定义状态码或响应标记。"
    return True, "断言满足。"


def _snapshot(step_id: str, kind: str, role: str | None, status: str, request: str | None, response: str | None, detail: dict[str, object]) -> dict[str, object]:
    return {"step_id": step_id, "step_kind": kind, "role_alias": role, "status": status, "request_summary": request, "response_summary": response, "detail": detail}
