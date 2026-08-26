"""Safe, bounded execution primitives for DAST business-flow verification.

This module intentionally has no browser adapter. Browser steps are represented
and audited, but remain blocked until an approved browser runtime is installed.
"""
from __future__ import annotations

from http.cookiejar import CookieJar
from hashlib import sha256
from dataclasses import dataclass
from difflib import SequenceMatcher
import json
import os
import re
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, Request, build_opener

from app.services.sandbox_identity import AUTO_REF_PREFIX, resolve_credential


class BusinessFlowError(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MAX_FLOW_STEPS = 50
MAX_HTTP_REQUESTS = 40
MIN_REQUEST_INTERVAL_SECONDS = 0.2
STEP_KINDS = {"http_request", "login", "extract", "assert", "assert_compare", "switch_identity", "browser_action", "sandbox_probe"}
BLOCKED_BROWSER_ACTIONS = {"delete", "payment", "send", "email", "upload", "file_upload", "modify"}
SECRET_PATTERN = re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+|(?:api[_-]?key|token|password|secret|cookie)\s*[:=]\s*)[^\s,;]+")
SENSITIVE_HEADER_LINE = re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*).+$")
DB_ERROR_PATTERN = re.compile(r"(?i)(sql syntax|syntax error.*sql|mysql|postgresql|sqlite|ora-\d+|odbc|jdbc|unterminated quoted|database error)")


@dataclass(frozen=True)
class FlowExecutionResult:
    snapshots: list[dict[str, object]]
    terminal_status: str
    verdict: str | None
    reason: str


def redact(value: str) -> str:
    redacted = SENSITIVE_HEADER_LINE.sub(r"\1[REDACTED]", value)
    return SECRET_PATTERN.sub(lambda match: f"{match.group(1)}[REDACTED]", redacted)


def dry_run(flow: Any) -> tuple[list[dict[str, object]], list[str]]:
    """Validate flow structure without constructing a request or contacting a target."""
    roles = flow.roles if isinstance(flow.roles, list) else []
    steps = flow.steps if isinstance(flow.steps, list) else []
    role_aliases = {str(item.get("alias") or "") for item in roles if isinstance(item, dict)} - {""}
    seen_ids: set[str] = set()
    snapshots: list[dict[str, object]] = []
    errors: list[str] = []
    if len(steps) > MAX_FLOW_STEPS:
        return [], [f"流程步骤超过上限 {MAX_FLOW_STEPS}。"]
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
        elif kind == "sandbox_probe":
            capability = str(step.get("capability") or "").strip()
            probe = str(step.get("probe") or "").strip()
            if not capability or not probe:
                status, message = "blocked", "SANDBOX 探针必须声明 capability 和 probe。"
            else:
                detail.update({"capability": capability, "probe": probe, "execution_backend": "sandbox"})
                message = "SANDBOX 探针结构已通过校验；真实执行须由隔离执行后端接管。"
        elif kind == "assert_compare":
            mode = str(step.get("mode") or "")
            references = [str(step.get(key) or "") for key in ("left", "right", "true", "false")]
            baseline = step.get("baseline") if isinstance(step.get("baseline"), list) else []
            if mode not in {"access_control", "sql_injection"}:
                status, message = "blocked", "差分断言模式不受支持。"
            elif not any(references) and not baseline:
                status, message = "blocked", "差分断言没有引用请求步骤。"
        seen_ids.add(step_id)
        snapshots.append({"step_id": step_id, "step_kind": kind or "unknown", "role_alias": step.get("role"), "status": status, "request_summary": None, "response_summary": message, "detail": detail})
        if status == "blocked":
            errors.append(f"{step_id}: {message}")
    if not steps:
        errors.append("流程没有步骤。")
    if not role_aliases:
        errors.append("流程没有定义业务角色。")
    return snapshots, errors


def execute_api_flow_result(flow: Any, *, timeout_seconds: int = 15, task_id: str | None = None) -> FlowExecutionResult:
    """Execute only the explicitly approved, safe HTTP portion of a flow.

    Browser actions, unsafe methods and missing credential references return a
    bounded uncertain outcome instead of attempting a best-effort action.
    """
    dry_snapshots, errors = dry_run(flow)
    if errors:
        return FlowExecutionResult(dry_snapshots, "blocked", None, "流程未通过本地预执行校验。")
    sessions = _sessions_for_roles(flow.roles)
    variables: dict[str, object] = {"run.id": task_id or "preview"}
    latest: dict[str, object] = {}
    observations: dict[str, dict[str, object]] = {}
    snapshots: list[dict[str, object]] = []
    verdicts: list[str] = []
    request_count = 0
    last_request_at = 0.0
    for index, raw_step in enumerate(flow.steps, start=1):
        step = raw_step if isinstance(raw_step, dict) else {}
        step_id = str(step.get("id") or f"step-{index}")
        kind = str(step.get("kind") or "")
        role = str(step.get("role") or "")
        if kind == "sandbox_probe":
            capability = str(step.get("capability") or "unknown")
            snapshots.append(_snapshot(step_id, kind, role or None, "blocked", None, f"需要 SANDBOX 能力：{capability}；本地 HTTP 执行器未发起该探针。", {"capability": capability, "handoff_required": True}))
            return FlowExecutionResult(snapshots, "blocked", None, f"策略需要 SANDBOX {capability} 能力，当前尚未收到隔离执行结果。")
        if kind == "browser_action":
            snapshots.append(_snapshot(step_id, kind, role, "blocked", None, "浏览器自动化适配器尚未安装；未连接目标。", {}))
            return FlowExecutionResult(snapshots, "blocked", None, "流程需要浏览器步骤，但浏览器适配器尚不可用。")
        if kind == "switch_identity":
            snapshots.append(_snapshot(step_id, kind, role, "completed", None, "已切换到独立身份会话。", {}))
            continue
        if kind in {"http_request", "login"}:
            request_count += 1
            if request_count > MAX_HTTP_REQUESTS:
                snapshots.append(_snapshot(step_id, kind, role, "blocked", None, "请求数量超过单任务安全上限。", {"max_requests": MAX_HTTP_REQUESTS}))
                return FlowExecutionResult(snapshots, "blocked", None, "单任务请求数量超过安全上限。")
            remaining = MIN_REQUEST_INTERVAL_SECONDS - (time.perf_counter() - last_request_at)
            if remaining > 0:
                time.sleep(remaining)
            try:
                result = _request_step(flow, step, sessions, variables, timeout_seconds)
            except BusinessFlowError as exc:
                snapshots.append(_snapshot(step_id, kind, role, "blocked", None, str(exc), {}))
                return FlowExecutionResult(snapshots, "blocked", None, f"步骤 {step_id} 被安全策略阻止。")
            except (HTTPError, URLError, TimeoutError, OSError) as exc:
                snapshots.append(_snapshot(step_id, kind, role, "failed", None, f"请求异常：{type(exc).__name__}", {}))
                return FlowExecutionResult(snapshots, "failed", None, f"步骤 {step_id} 未获得响应；本次任务未验证。")
            latest = result
            last_request_at = time.perf_counter()
            observations[step_id] = result
            snapshots.append(_snapshot(step_id, kind, role, "completed", str(result["request_summary"]), str(result["response_summary"]), {
                "status_code": result["status_code"], "duration_ms": result["duration_ms"], "exchange": result["exchange"],
            }))
            continue
        if kind == "extract":
            variable = str(step.get("variable") or "")
            source = str(step.get("source") or "json")
            path = str(step.get("path") or "")
            value = _extract(latest, source, path)
            if not variable or value is None:
                snapshots.append(_snapshot(step_id, kind, role or None, "failed", None, "无法从上一步响应提取变量。", {"variable": variable, "path": path}))
                return FlowExecutionResult(snapshots, "blocked", None, f"步骤 {step_id} 缺少后续所需变量。")
            variables[variable] = value
            snapshots.append(_snapshot(step_id, kind, role or None, "completed", None, "变量已提取并仅保留在本次运行内存中。", {"variable": variable}))
            continue
        if kind == "assert":
            passed, message = _assert(latest, step)
            snapshots.append(_snapshot(step_id, kind, role or None, "passed" if passed else "failed", None, message, {}))
            if not passed:
                return FlowExecutionResult(snapshots, "completed", "uncertain", f"步骤 {step_id} 的断言未满足，证据不足。")
            verdict = str(step.get("verdict_on_pass") or "")
            if verdict in {"exploitable", "not_exploitable", "uncertain"}:
                verdicts.append(verdict)
            continue
        if kind == "assert_compare":
            verdict, message, detail = _assert_compare(observations, step)
            snapshots.append(_snapshot(step_id, kind, role or None, "passed" if verdict in {"exploitable", "not_exploitable"} else "inconclusive", None, message, detail))
            verdicts.append(verdict)
            continue
        snapshots.append(_snapshot(step_id, kind or "unknown", role or None, "blocked", None, "未实现的步骤类型。", {}))
        return FlowExecutionResult(snapshots, "blocked", None, f"步骤 {step_id} 不可执行。")
    if verdicts and len(set(verdicts)) == 1:
        return FlowExecutionResult(snapshots, "completed", verdicts[0], "所有必需步骤和裁决断言均已完成。")
    return FlowExecutionResult(snapshots, "completed", "uncertain", "流程完成，但未提供充分且一致的三色裁决断言。")


def execute_api_flow(flow: Any, *, timeout_seconds: int = 15) -> tuple[list[dict[str, object]], str, str]:
    """Compatibility wrapper for callers that still consume the v1 tuple."""
    result = execute_api_flow_result(flow, timeout_seconds=timeout_seconds)
    return result.snapshots, result.verdict or "uncertain", result.reason


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
    credentials = _credential_values(flow.roles, role, getattr(flow, "project_id", ""))
    url = _render(str(step.get("url") or ""), variables, credentials)
    parsed = urlparse(url)
    target = urlparse(flow.target_url)
    if not parsed.scheme or (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)) != (target.scheme, target.hostname, target.port or (443 if target.scheme == "https" else 80)):
        raise BusinessFlowError("请求 URL 不属于流程批准的目标同源范围。")
    request_path = parsed.path or "/"
    allowed_paths = ["/" + str(value).strip().lstrip("/") if str(value).strip() else "/" for value in flow.allowed_paths]
    if allowed_paths and not any(request_path == path or request_path.startswith(path.rstrip("/") + "/") for path in allowed_paths):
        raise BusinessFlowError("请求路径不在流程批准范围内。")
    query = step.get("query") if isinstance(step.get("query"), dict) else {}
    if query:
        separator = "&" if parsed.query else "?"
        url = f"{url}{separator}{urlencode({str(key): _render(str(value), variables, credentials) for key, value in query.items()})}"
    headers = _credential_headers(credentials)
    headers.update({str(key): _render(str(value), variables, credentials) for key, value in (step.get("headers") if isinstance(step.get("headers"), dict) else {}).items()})
    body = step.get("body") if isinstance(step.get("body"), dict) else None
    data = json.dumps(_render_object(body, variables, credentials), ensure_ascii=False).encode("utf-8") if body is not None else None
    if data is not None:
        headers.setdefault("Content-Type", "application/json")
    request = Request(url, data=data, headers=headers, method=method)
    started = time.perf_counter()
    try:
        response = opener.open(request, timeout=max(1, min(int(timeout_seconds), 30)))
    except HTTPError as exc:
        response = exc
    raw_bytes = response.read(65536)
    raw = raw_bytes.decode("utf-8", errors="replace")
    status = int(getattr(response, "status", 200))
    response_headers = {str(key): str(value) for key, value in response.headers.items()}
    location = str(response_headers.get("Location") or response_headers.get("location") or "")
    if role and status in {301, 302, 303, 307, 308} and urlparse(urljoin(url, location)).path in {"/login", "/signin", "/users/login", "/auth/login"}:
        raise BusinessFlowError("测试身份未被目标接受，请先刷新 SANDBOX 一次性登录会话。")
    duration_ms = round((time.perf_counter() - started) * 1000)
    request_body = data.decode("utf-8", errors="replace") if data else ""
    exchange = {
        "request": {"method": method, "url": redact(url), "headers": _redact_headers(headers), "body": redact(request_body), "body_sha256": sha256(data or b"").hexdigest()},
        "response": {"status_code": status, "headers": _redact_headers(response_headers), "body": redact(raw), "body_sha256": sha256(raw_bytes).hexdigest(), "truncated": len(raw_bytes) >= 65536},
        "timing": {"duration_ms": duration_ms},
    }
    return {"status_code": status, "headers": response_headers, "body": raw, "duration_ms": duration_ms, "exchange": exchange, "request_summary": redact(f"{method} {url}"), "response_summary": redact(f"HTTP {status}; body bytes={len(raw_bytes)}; duration={duration_ms}ms")}


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    secret_names = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
    return {key: "[REDACTED]" if key.lower() in secret_names else redact(value) for key, value in headers.items()}


def _credential_values(roles: list[dict[str, object]], alias: str, project_id: object = "") -> dict[str, object]:
    role = next((item for item in roles if str(item.get("alias") or "") == alias), None)
    ref = str((role or {}).get("credential_ref") or "")
    if not ref:
        return {}
    if ref.startswith(AUTO_REF_PREFIX):
        value = resolve_credential(project_id, ref)
        if not value:
            raise BusinessFlowError("SANDBOX 尚未为当前项目准备所引用的测试身份。")
        return value
    if not ref.startswith("env:"):
        raise BusinessFlowError("凭据引用必须使用受保护的后端引用，不接受明文凭据。")
    value = os.getenv(ref[4:], "")
    if not value:
        raise BusinessFlowError("所引用的测试身份凭据未在后端环境中配置。")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {"token": value}
    return parsed if isinstance(parsed, dict) else {"token": value}


def _credential_headers(credentials: dict[str, object]) -> dict[str, str]:
    configured = credentials.get("headers") if isinstance(credentials.get("headers"), dict) else {}
    headers = {str(key): str(value) for key, value in configured.items()}
    if credentials.get("token") and "Authorization" not in headers:
        scheme = str(credentials.get("scheme") or "Bearer")
        headers["Authorization"] = f"{scheme} {credentials['token']}"
    if credentials.get("cookie") and "Cookie" not in headers:
        headers["Cookie"] = str(credentials["cookie"])
    if credentials.get("api_key"):
        headers.setdefault(str(credentials.get("api_key_header") or "X-API-Key"), str(credentials["api_key"]))
    return headers


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


def _assert_compare(observations: dict[str, dict[str, object]], step: dict[str, object]) -> tuple[str, str, dict[str, object]]:
    mode = str(step.get("mode") or "")
    if mode == "access_control":
        left = observations.get(str(step.get("left") or ""))
        right = observations.get(str(step.get("right") or ""))
        if left is None or right is None:
            return "uncertain", "双身份请求证据不完整。", {"mode": mode}
        left_status, right_status = int(left.get("status_code") or 0), int(right.get("status_code") or 0)
        similarity = _similarity(str(left.get("body") or ""), str(right.get("body") or ""))
        detail = {"mode": mode, "owner_status": left_status, "peer_status": right_status, "body_similarity": similarity}
        if left_status in {200, 201, 202, 204} and right_status in {401, 403, 404}:
            return "not_exploitable", "资源所有者可访问，而另一身份被明确拒绝。", detail
        if left_status in {200, 201, 202, 204} and right_status == left_status and similarity >= 0.92:
            return "exploitable", "另一身份获得了与资源所有者高度一致的成功响应。", detail
        return "uncertain", "双身份响应存在差异，但不足以确认越权或有效阻断。", detail
    if mode == "sql_injection":
        baseline_ids = [str(value) for value in step.get("baseline", [])] if isinstance(step.get("baseline"), list) else []
        baselines = [observations.get(value) for value in baseline_ids]
        truth = observations.get(str(step.get("true") or ""))
        falsehood = observations.get(str(step.get("false") or ""))
        if len(baselines) < 2 or any(item is None for item in baselines) or truth is None or falsehood is None:
            return "uncertain", "SQL 差分请求证据不完整。", {"mode": mode}
        baseline_a, baseline_b = baselines[0], baselines[1]
        assert baseline_a is not None and baseline_b is not None
        baseline_similarity = _similarity(str(baseline_a.get("body") or ""), str(baseline_b.get("body") or ""))
        true_false_similarity = _similarity(str(truth.get("body") or ""), str(falsehood.get("body") or ""))
        baseline_true_similarity = _similarity(str(baseline_a.get("body") or ""), str(truth.get("body") or ""))
        baseline_errors = bool(DB_ERROR_PATTERN.search(str(baseline_a.get("body") or "") + str(baseline_b.get("body") or "")))
        payload_errors = bool(DB_ERROR_PATTERN.search(str(truth.get("body") or "") + str(falsehood.get("body") or "")))
        statuses = [int(item.get("status_code") or 0) for item in (baseline_a, baseline_b, truth, falsehood)]
        detail = {
            "mode": mode, "baseline_similarity": baseline_similarity,
            "true_false_similarity": true_false_similarity, "baseline_true_similarity": baseline_true_similarity,
            "status_codes": statuses, "database_error_only_after_payload": payload_errors and not baseline_errors,
        }
        if payload_errors and not baseline_errors:
            return "exploitable", "注入请求触发了基线中不存在的数据库错误特征。", detail
        if baseline_similarity >= 0.90 and baseline_true_similarity >= 0.80 and true_false_similarity <= 0.65:
            return "exploitable", "稳定基线下，真/假条件产生了显著且可解释的响应差分。", detail
        if len(set(statuses)) == 1 and baseline_similarity >= 0.90 and true_false_similarity >= 0.90:
            return "not_exploitable", "重复基线和真/假条件响应均保持稳定一致，未发现注入差分。", detail
        return "uncertain", "观察到响应变化，但差分稳定性或特异性不足。", detail
    return "uncertain", "未知差分断言模式。", {"mode": mode}


def _similarity(left: str, right: str) -> float:
    return round(SequenceMatcher(None, left[:65536], right[:65536]).ratio(), 4)


def _snapshot(step_id: str, kind: str, role: str | None, status: str, request: str | None, response: str | None, detail: dict[str, object]) -> dict[str, object]:
    return {"step_id": step_id, "step_kind": kind, "role_alias": role, "status": status, "request_summary": request, "response_summary": response, "detail": detail}
