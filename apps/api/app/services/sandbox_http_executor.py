"""Fixed, non-interactive HTTP probe program used inside the SANDBOX container.

The program accepts one DAST handoff contract on stdin.  It does not accept a
shell command and it refuses cross-origin or out-of-scope requests.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import statistics
import sys
import time
from difflib import SequenceMatcher
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener
from uuid import uuid4


MAX_BODY = 1_048_576
LOCAL_STEP_KINDS = {"http_request", "login", "extract", "assert", "assert_compare", "switch_identity"}
SAFE_FLOW_METHODS = {"GET", "HEAD", "OPTIONS"}
DB_ERROR = re.compile(r"(?i)(sql syntax|syntax error.*sql|mysql|postgresql|sqlite|ora-\d+|odbc|jdbc|unterminated quoted|database error)")
SAFE_PROBES = {
    "sql_injection", "ssrf", "command_injection", "path_traversal",
    "template_injection", "xxe", "open_redirect", "cors", "file_upload",
    "unsafe_deserialization", "code_injection",
    "account_recovery", "sensitive_data_exposure", "security_misconfiguration",
}
SECRET = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+|((?:token|password|secret|api[_-]?key|cookie)\s*[:=]\s*)\S+")
SENSITIVE_HEADER_NAMES = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
SENSITIVE_HEADER_LINE = re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*).+$")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = build_opener(NoRedirect())


def redact_text(value: object) -> str:
    text = SECRET.sub("[REDACTED]", str(value))
    return SENSITIVE_HEADER_LINE.sub(r"\1[REDACTED]", text)


def redact_headers(headers: dict) -> dict[str, str]:
    return {
        str(key): ("[REDACTED]" if str(key).lower() in SENSITIVE_HEADER_NAMES else redact_text(str(value))[:2000])
        for key, value in headers.items()
    }


def origin(value: str) -> tuple[str, str, int] | None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)


def in_scope(url: str, target: str, paths: list[str]) -> bool:
    parsed = urlparse(url)
    if origin(url) != origin(target):
        return False
    if not paths:
        return False
    return any(parsed.path == path or parsed.path.startswith(path.rstrip("/") + "/") for path in paths)


def with_parameter(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[name or "q"] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def credential_values(roles: list[dict], alias: str) -> dict:
    role = next((item for item in roles if isinstance(item, dict) and str(item.get("alias") or "") == alias), None)
    ref = str((role or {}).get("credential_ref") or "")
    if not ref:
        return {}
    if not ref.startswith("env:") or not os.getenv(ref[4:]):
        raise ValueError(f"missing sandbox credential reference for role: {alias}")
    raw = os.environ[ref[4:]]
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {"token": raw}
    return parsed if isinstance(parsed, dict) else {"token": raw}


def credential_headers(roles: list[dict], alias: str) -> dict[str, str]:
    values = credential_values(roles, alias)
    configured = values.get("headers") if isinstance(values.get("headers"), dict) else {}
    headers = {str(key): str(value) for key, value in configured.items()}
    if values.get("token") and "Authorization" not in headers:
        headers["Authorization"] = f"{values.get('scheme') or 'Bearer'} {values['token']}"
    if values.get("cookie") and "Cookie" not in headers:
        headers["Cookie"] = str(values["cookie"])
    if values.get("api_key"):
        headers.setdefault(str(values.get("api_key_header") or "X-API-Key"), str(values["api_key"]))
    return headers


def multipart_file(field: str, content: bytes, content_type: str, *, filename: str = "dast-input") -> tuple[bytes, str]:
    boundary = f"----DAST{uuid4().hex}"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\n"
        f"Content-Type: {content_type}\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def request(method: str, url: str, *, headers=None, body: bytes | None = None, timeout=10.0, opener=None) -> dict:
    started = time.perf_counter()
    req = Request(url, data=body, headers=headers or {}, method=method)
    try:
        response = (opener or OPENER).open(req, timeout=timeout)
        status, response_headers = response.status, dict(response.headers.items())
        content = response.read(MAX_BODY + 1)
    except HTTPError as exc:
        status, response_headers = exc.code, dict(exc.headers.items())
        content = exc.read(MAX_BODY + 1)
    except (URLError, TimeoutError, OSError) as exc:
        return {"status": 0, "headers": {}, "body": "", "error": redact_text(exc)[:500], "duration_ms": round((time.perf_counter() - started) * 1000, 2)}
    truncated = len(content) > MAX_BODY
    content = content[:MAX_BODY]
    return {
        "status": status,
        "headers": {str(k): str(v)[:2000] for k, v in response_headers.items()},
        "body": content.decode("utf-8", errors="replace")[:65536],
        "body_sha256": hashlib.sha256(content).hexdigest(),
        "body_bytes": len(content),
        "truncated": truncated,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def compact_exchange(method: str, url: str, result: dict) -> dict:
    return {
        "request": {"method": method, "url": url, "headers": {}},
        "response": {
            "status": result.get("status"), "headers": redact_headers(result.get("headers", {})),
            "body_excerpt": redact_text(result.get("body") or "")[:4000],
            "body_sha256": result.get("body_sha256"), "body_bytes": result.get("body_bytes", 0),
            "truncated": bool(result.get("truncated")), "error": redact_text(result.get("error") or "") if result.get("error") else None,
        },
    }


def upload_references(result: dict, request_url: str, filename: str) -> list[str]:
    """Extract only server-returned locations that reference the random file."""
    candidates: list[str] = []
    headers = result.get("headers") if isinstance(result.get("headers"), dict) else {}
    location = str(headers.get("Location") or headers.get("location") or "")
    if location and filename in location:
        candidates.append(urljoin(request_url, location))
    body = str(result.get("body") or "")
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        parsed = None

    def collect(value: object, depth: int = 0) -> None:
        if depth > 5:
            return
        if isinstance(value, str) and filename in value and len(value) <= 4000:
            candidates.append(urljoin(request_url, value))
        elif isinstance(value, list):
            for item in value[:50]:
                collect(item, depth + 1)
        elif isinstance(value, dict):
            for item in list(value.values())[:50]:
                collect(item, depth + 1)

    collect(parsed)
    candidates.extend(
        urljoin(request_url, match)
        for match in re.findall(r"(?:https?://[^\s\"'<>]+|/[A-Za-z0-9_./%-]+)", body)
        if filename in match
    )
    return list(dict.fromkeys(candidates))


def render(value: str, variables: dict[str, object], credentials: dict) -> str:
    def replace(match: re.Match[str]) -> str:
        expression = match.group(1).strip()
        source, _, key = expression.partition(".")
        return str(credentials.get(key, "")) if source == "credential" else str(variables.get(expression, ""))

    return re.sub(r"\{\{\s*([^}]+)\s*\}\}", replace, value)


def render_object(value: object, variables: dict[str, object], credentials: dict) -> object:
    if isinstance(value, str):
        return render(value, variables, credentials)
    if isinstance(value, list):
        return [render_object(item, variables, credentials) for item in value]
    if isinstance(value, dict):
        return {str(key): render_object(item, variables, credentials) for key, item in value.items()}
    return value


def similarity(left: str, right: str) -> float:
    return round(SequenceMatcher(None, left[:65536], right[:65536]).ratio(), 4)


def compare_observations(observations: dict[str, dict], step: dict) -> tuple[str, str, dict]:
    mode = str(step.get("mode") or "")
    if mode == "privileged_route":
        anonymous = observations.get(str(step.get("left") or ""))
        ordinary = observations.get(str(step.get("right") or ""))
        if anonymous is None or ordinary is None:
            return "uncertain", "匿名与普通用户请求证据不完整。", {"mode": mode}
        anonymous_status = int(anonymous.get("status") or 0)
        ordinary_status = int(ordinary.get("status") or 0)
        denied = {301, 302, 303, 307, 308, 401, 403, 404}
        detail = {"mode": mode, "anonymous_status": anonymous_status, "ordinary_user_status": ordinary_status}
        if ordinary_status in {200, 201, 202, 204}:
            return "exploitable", "已知普通测试用户成功访问了静态标记为特权路由的接口。", detail
        if anonymous_status in denied and ordinary_status in denied:
            return "not_exploitable", "匿名和已知普通测试用户均被特权路由拒绝。", detail
        return "uncertain", "特权路由返回结果不足以确认越权或有效阻断。", detail
    if mode == "access_control":
        owner = observations.get(str(step.get("left") or ""))
        peer = observations.get(str(step.get("right") or ""))
        if owner is None or peer is None:
            return "uncertain", "双身份请求证据不完整。", {"mode": mode}
        owner_status, peer_status = int(owner.get("status") or 0), int(peer.get("status") or 0)
        body_similarity = similarity(str(owner.get("body") or ""), str(peer.get("body") or ""))
        detail = {"mode": mode, "owner_status": owner_status, "peer_status": peer_status, "body_similarity": body_similarity}
        if owner_status in {200, 201, 202, 204} and peer_status in {401, 403, 404}:
            return "not_exploitable", "资源所有者可访问，而另一身份被明确拒绝。", detail
        if owner_status in {200, 201, 202, 204} and peer_status == owner_status and body_similarity >= 0.92:
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
        baseline_similarity = similarity(str(baseline_a.get("body") or ""), str(baseline_b.get("body") or ""))
        true_false_similarity = similarity(str(truth.get("body") or ""), str(falsehood.get("body") or ""))
        baseline_true_similarity = similarity(str(baseline_a.get("body") or ""), str(truth.get("body") or ""))
        baseline_errors = bool(DB_ERROR.search(str(baseline_a.get("body") or "") + str(baseline_b.get("body") or "")))
        payload_errors = bool(DB_ERROR.search(str(truth.get("body") or "") + str(falsehood.get("body") or "")))
        statuses = [int(item.get("status") or 0) for item in (baseline_a, baseline_b, truth, falsehood)]
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


def execute_flow_steps(contract: dict, target: str, paths: list[str], roles: list[dict]) -> dict:
    steps = [step for step in contract.get("steps", []) if isinstance(step, dict) and str(step.get("kind") or "") in LOCAL_STEP_KINDS]
    if not steps:
        return {"status": "skipped", "evidence": [], "verdict_signal": "uncertain", "verdict_reason": ""}
    sessions = {
        str(role.get("alias") or ""): build_opener(NoRedirect(), HTTPCookieProcessor(CookieJar()))
        for role in roles if str(role.get("alias") or "")
    }
    variables: dict[str, object] = {"run.id": str(contract.get("task_id") or "sandbox")}
    observations: dict[str, dict] = {}
    latest: dict = {}
    evidence: list[dict] = []
    verdicts: list[str] = []
    request_count = 0
    first_request_id = ""
    timeout = max(1, min(int((contract.get("limits") or {}).get("timeout_seconds", 120)), 30))

    for index, step in enumerate(steps, start=1):
        kind = str(step.get("kind") or "")
        step_id = str(step.get("id") or f"step-{index}")
        role = str(step.get("role") or "")
        request_id = str(step.get("request_id") or "")
        if request_id and not first_request_id:
            first_request_id = request_id
        if kind == "switch_identity":
            if role not in sessions:
                raise ValueError(f"flow step {step_id} references an unknown role")
            continue
        if kind in {"http_request", "login"}:
            request_count += 1
            if request_count > int((contract.get("limits") or {}).get("max_requests", 40)):
                raise ValueError("flow request count exceeds the approved contract limit")
            if role not in sessions:
                raise ValueError(f"flow step {step_id} references an unknown role")
            method = str(step.get("method") or ("POST" if kind == "login" else "GET")).upper()
            if method not in SAFE_FLOW_METHODS and not (kind == "login" and method == "POST"):
                raise ValueError(f"flow step {step_id} uses a non-allowlisted HTTP method")
            credentials = credential_values(roles, role)
            url = render(str(step.get("url") or target), variables, credentials)
            query = step.get("query") if isinstance(step.get("query"), dict) else {}
            if query:
                parsed = urlparse(url)
                merged = dict(parse_qsl(parsed.query, keep_blank_values=True))
                merged.update({str(key): render(str(value), variables, credentials) for key, value in query.items()})
                url = urlunparse(parsed._replace(query=urlencode(merged)))
            if not in_scope(url, target, paths):
                raise ValueError(f"out-of-scope flow request rejected: {url}")
            headers = credential_headers(roles, role)
            headers.update({str(key): render(str(value), variables, credentials) for key, value in (step.get("headers") if isinstance(step.get("headers"), dict) else {}).items()})
            body_value = step.get("body") if isinstance(step.get("body"), dict) else None
            form_value = step.get("form") if isinstance(step.get("form"), dict) else None
            body = json.dumps(render_object(body_value, variables, credentials), ensure_ascii=False).encode() if body_value is not None else None
            if body is not None:
                headers.setdefault("Content-Type", "application/json")
            elif form_value is not None:
                form = render_object(form_value, variables, credentials)
                if not isinstance(form, dict):
                    raise ValueError(f"flow step {step_id} form payload is invalid")
                body = urlencode({str(key): str(value) for key, value in form.items()}).encode()
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            result = request(method, url, headers=headers, body=body, timeout=timeout, opener=sessions[role])
            if int(result.get("status") or 0) == 0:
                raise ValueError(f"flow step {step_id} did not receive a target response: {result.get('error') or 'network error'}")
            redirect = str(result.get("headers", {}).get("Location") or result.get("headers", {}).get("location") or "")
            if credentials and int(result.get("status") or 0) in {301, 302, 303, 307, 308} and urlparse(urljoin(url, redirect)).path in {"/login", "/signin", "/users/login", "/auth/login"}:
                raise ValueError("authenticated test identity was redirected to login; refresh the SANDBOX identity session")
            latest = result
            observations[step_id] = result
            exchange = compact_exchange(method, url, result)
            evidence.append({
                "evidence_id": str(uuid4()), "type": "http_exchange", "request_id": request_id,
                "confirmed": False, "facts": f"有界流程步骤 {step_id} 已在隔离 HTTP 执行器中完成。",
                "complete": True, "exchange": exchange,
            })
            time.sleep(0.2)
            continue
        if kind == "extract":
            source = str(step.get("source") or "json")
            path = str(step.get("path") or "")
            variable = str(step.get("variable") or "")
            value: object | None = None
            if source == "header":
                value = (latest.get("headers") if isinstance(latest.get("headers"), dict) else {}).get(path)
            elif source == "json":
                try:
                    value = json.loads(str(latest.get("body") or ""))
                    for part in [item for item in path.split(".") if item]:
                        value = value.get(part) if isinstance(value, dict) else None
                except json.JSONDecodeError:
                    value = None
            if not variable or value is None:
                raise ValueError(f"flow step {step_id} could not extract its required variable")
            variables[variable] = value
            continue
        if kind == "assert":
            allowed = step.get("status_in") if isinstance(step.get("status_in"), list) else []
            contains = str(step.get("body_contains") or "")
            passed = (not allowed or int(latest.get("status") or 0) in {int(item) for item in allowed}) and (not contains or contains in str(latest.get("body") or "")) and bool(allowed or contains)
            requested_verdict = str(step.get("verdict_on_pass") or "")
            signal = requested_verdict if passed and requested_verdict in {"exploitable", "not_exploitable", "uncertain"} else "uncertain"
            verdicts.append(signal)
            facts = "流程断言满足。" if passed else "流程断言未满足，证据不足。"
            evidence.append({"evidence_id": str(uuid4()), "type": "assertion", "request_id": first_request_id, "confirmed": passed and signal == "exploitable", "facts": facts, "complete": True, "assertion": {"step_id": step_id, "passed": passed}})
            continue
        if kind == "assert_compare":
            signal, facts, detail = compare_observations(observations, step)
            verdicts.append(signal)
            evidence.append({"evidence_id": str(uuid4()), "type": "differential", "request_id": first_request_id, "confirmed": signal == "exploitable", "facts": facts, "complete": True, "assertion": {"step_id": step_id, **detail}})

    signal = "exploitable" if "exploitable" in verdicts else "not_exploitable" if verdicts and all(item == "not_exploitable" for item in verdicts) else "uncertain"
    reason = next((str(item.get("facts") or "") for item in reversed(evidence) if item.get("type") in {"differential", "assertion"}), "隔离 HTTP 流程已完整执行；策略未声明可形成三色裁决的断言。")
    evidence.append({
        "evidence_id": str(uuid4()), "type": "coverage", "request_id": first_request_id,
        "confirmed": False, "facts": f"完成 {request_count} 个有界流程请求和 {len(steps) - request_count} 个本地断言/状态步骤。",
        "complete": True, "probe_count": request_count, "expected_probe_count": request_count,
        "negative_conclusion_supported": signal == "not_exploitable" and request_count > 0,
    })
    return {"status": "completed", "evidence": evidence, "verdict_signal": signal, "verdict_reason": reason}


class CallbackHandler(BaseHTTPRequestHandler):
    hits: list[dict] = []

    def do_GET(self):
        self.__class__.hits.append({"method": "GET", "path": self.path, "at": time.time()})
        self.send_response(204)
        self.end_headers()

    do_POST = do_GET

    def log_message(self, *_args):
        return


def start_callback_server() -> tuple[ThreadingHTTPServer, str]:
    CallbackHandler.hits = []
    server = ThreadingHTTPServer(("0.0.0.0", 8765), CallbackHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    callback_host = os.getenv("SANDBOX_CALLBACK_HOST", "sandbox-executor")
    return server, f"http://{callback_host}:8765/callback/{uuid4().hex}"


def probe(step: dict, target: str, paths: list[str], roles: list[dict]) -> tuple[list[dict], bool, int, bool]:
    probe_name = str(step.get("probe") or "")
    if probe_name not in SAFE_PROBES:
        raise ValueError(f"unsupported fixed probe: {probe_name}")
    url = str(step.get("url") or target)
    method = str(step.get("method") or "GET").upper()
    parameter = str(step.get("parameter") or "q")
    location = str(step.get("location") or "query").lower()
    role = str(step.get("role") or "")
    role_values = credential_values(roles, role)
    role_headers = credential_headers(roles, role)
    request_id = str(step.get("request_id") or "")
    variants: list[tuple[str, str, dict, bytes | None]] = []
    callback_server = None
    callback_url = ""
    if probe_name == "sql_injection":
        variants = [("baseline", "DAST_BASELINE", {}, None), ("true", "DAST' OR '1'='1", {}, None), ("false", "DAST' AND '1'='2", {}, None)]
    elif probe_name == "command_injection":
        variants = [(f"baseline-{i}", "DAST_MARKER", {}, None) for i in range(3)] + [(f"delay-{i}", "DAST;sleep 2", {}, None) for i in range(3)]
    elif probe_name == "path_traversal":
        variants = [("baseline", "DAST_MARKER.txt", {}, None), ("unix", "../../../../etc/passwd", {}, None), ("encoded", "..%2f..%2f..%2f..%2fetc%2fpasswd", {}, None)]
    elif probe_name == "template_injection":
        variants = [("baseline", "DAST_MARKER", {}, None), ("expression", "{{7*7}}", {}, None), ("alternative", "${7*7}", {}, None)]
    elif probe_name == "open_redirect":
        variants = [("baseline", "/", {}, None), ("absolute", "https://example.invalid/dast", {}, None), ("scheme-relative", "//example.invalid/dast", {}, None)]
    elif probe_name == "cors":
        variants = [("baseline", "", {"Origin": "https://same-origin.invalid"}, None), ("foreign", "", {"Origin": "https://dast.invalid"}, None)]
    elif probe_name in {"ssrf", "xxe"}:
        callback_server, callback_url = start_callback_server()
        if probe_name == "ssrf":
            variants = [("baseline", "http://127.0.0.1:1/dast", {}, None), ("callback", callback_url, {}, None)]
        else:
            marker = f'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "{callback_url}">]><x>&xxe;</x>'.encode()
            variants = [("baseline", "", {"Content-Type": "application/xml"}, b"<x>DAST</x>"), ("callback", "", {"Content-Type": "application/xml"}, marker)]
    elif probe_name == "unsafe_deserialization":
        baseline = b'{"dast":"baseline"}'
        marker = b'{"dast":"_$$ND_FUNC$$_function(){return \'DAST_DESERIALIZATION_EXEC_8675309\'}()"}'
        variants = [("baseline", "", {"Content-Type": "application/json"}, baseline), ("controlled-marker", "", {"Content-Type": "application/json"}, marker)]
    elif probe_name == "code_injection":
        variants = [
            ("baseline", "1+1", {}, None),
            ("controlled-expression", "8675309+11", {}, None),
        ]
    elif probe_name == "account_recovery":
        username = str(role_values.get("username") or role_values.get("login") or "")
        if not username:
            raise ValueError("account_recovery requires username/login in the referenced test account")
        variants = [("random-token", uuid4().hex, {}, None), ("identity-derived-token", hashlib.md5(username.encode()).hexdigest(), {}, None)]
    elif probe_name in {"sensitive_data_exposure", "security_misconfiguration"}:
        variants = [("baseline", "", {}, None)]
    elif probe_name == "file_upload":
        if method != "POST":
            raise ValueError("file_upload requires a POST upload endpoint")
        marker = f"DAST_UPLOAD_{uuid4().hex}"
        benign_body, benign_type = multipart_file(
            parameter, marker.encode(), "text/plain", filename=f"{marker}.txt",
        )
        active_body, active_type = multipart_file(
            parameter,
            f"<!doctype html><meta charset=utf-8><title>{marker}</title><p>{marker}</p>".encode(),
            "text/html",
            filename=f"{marker}.html",
        )
        variants = [
            ("benign-text", f"{marker}.txt", {"Content-Type": benign_type}, benign_body),
            ("active-extension", f"{marker}.html", {"Content-Type": active_type}, active_body),
        ]
    else:
        variants = [("baseline", "DAST_MARKER", {"Content-Type": "application/json"}, json.dumps({parameter: "DAST_MARKER"}).encode()), ("variant", "DAST_SAFE_FILE.txt", {"Content-Type": "application/json"}, json.dumps({parameter: "DAST_SAFE_FILE.txt"}).encode())]

    exchanges = []
    for label, value, headers, body in variants:
        headers = {**role_headers, **headers}
        actual_url = url
        if probe_name == "account_recovery":
            names = [str(item) for item in step.get("parameters", [])]
            login_name = next((item for item in names if item.lower() in {"login", "username", "user"}), "login")
            token_name = next((item for item in names if "token" in item.lower()), "token")
            username = str(role_values.get("username") or role_values.get("login") or "")
            if method in {"GET", "HEAD", "OPTIONS"} or location == "query":
                actual_url = with_parameter(with_parameter(url, login_name, username), token_name, value)
            elif location in {"json", "body"}:
                body, headers["Content-Type"] = json.dumps({login_name: username, token_name: value}).encode(), "application/json"
            else:
                body, headers["Content-Type"] = urlencode({login_name: username, token_name: value}).encode(), "application/x-www-form-urlencoded"
        elif probe_name in {"sensitive_data_exposure", "security_misconfiguration", "file_upload"}:
            actual_url = url
        elif probe_name != "cors":
            if location in {"json", "body"} and body is None:
                body, headers["Content-Type"] = json.dumps({parameter: value}).encode(), "application/json"
            elif location == "form_field" and body is None:
                body, headers["Content-Type"] = urlencode({parameter: value}).encode(), "application/x-www-form-urlencoded"
            elif location == "form":
                content = body if body is not None else value.encode()
                content_type = headers.pop("Content-Type", "application/octet-stream")
                body, headers["Content-Type"] = multipart_file(parameter, content, content_type)
            elif location == "header":
                headers[parameter] = value
            elif location == "cookie":
                headers["Cookie"] = "; ".join(filter(None, [headers.get("Cookie"), f"{parameter}={value}"]))
            elif body is None:
                actual_url = with_parameter(url, parameter, value)
        if not in_scope(actual_url, target, paths):
            raise ValueError(f"out-of-scope request rejected: {actual_url}")
        result = request(method, actual_url, headers=headers, body=body)
        redirect = str(result.get("headers", {}).get("Location") or result.get("headers", {}).get("location") or "")
        if role_values and int(result.get("status") or 0) in {301, 302, 303, 307, 308} and urlparse(urljoin(actual_url, redirect)).path in {"/login", "/signin", "/users/login", "/auth/login"}:
            raise ValueError("authenticated test identity was redirected to login; refresh the SANDBOX identity session")
        exchanges.append({"label": label, "url": actual_url, "result": result})
        time.sleep(0.5)
    if callback_server:
        time.sleep(1.0)
        callback_server.shutdown()

    bodies = [str(item["result"].get("body") or "") for item in exchanges]
    confirmed = False
    facts = "固定安全探针已完成，未观察到明确触发证据。"
    if probe_name == "sql_injection":
        db_error = any(any(token in body.lower() for token in ("sql syntax", "postgresql", "mysql", "ora-", "sqlite")) for body in bodies[1:])
        true_result, false_result = exchanges[1]["result"], exchanges[2]["result"]
        response_delta = true_result.get("status") != false_result.get("status") or abs(int(true_result.get("body_bytes") or 0) - int(false_result.get("body_bytes") or 0)) >= max(20, int(true_result.get("body_bytes") or 0) // 20)
        reflected = "DAST' OR '1'='1" in bodies[1] or "DAST' AND '1'='2" in bodies[2]
        stable_diff = response_delta and not reflected and true_result.get("status") != 0 and false_result.get("status") != 0
        confirmed, facts = db_error or stable_diff, "检测到数据库错误或真假条件稳定差分。" if db_error or stable_diff else facts
    elif probe_name == "command_injection":
        base = [item["result"]["duration_ms"] for item in exchanges[:3]]
        delayed = [item["result"]["duration_ms"] for item in exchanges[3:]]
        confirmed = statistics.median(delayed) - statistics.median(base) >= 1500
        facts = "多轮时延探针相对基线出现可重复的显著延迟。" if confirmed else facts
    elif probe_name == "path_traversal":
        confirmed = any("root:x:" in body for body in bodies[1:])
        facts = "响应包含受控路径穿越的系统文件特征。" if confirmed else facts
    elif probe_name == "template_injection":
        confirmed = "49" not in bodies[0] and any("49" in body and "{{7*7}}" not in body and "${7*7}" not in body for body in bodies[1:])
        facts = "无副作用模板表达式被运行时求值。" if confirmed else facts
    elif probe_name == "open_redirect":
        locations = [str(item["result"].get("headers", {}).get("Location") or item["result"].get("headers", {}).get("location") or "") for item in exchanges[1:]]
        confirmed = any(origin(location) and origin(location) != origin(target) for location in locations)
        facts = "目标返回跨域 Location；执行器未跟随跳转。" if confirmed else facts
    elif probe_name == "cors":
        foreign = exchanges[-1]["result"].get("headers", {})
        acao = str(foreign.get("Access-Control-Allow-Origin") or foreign.get("access-control-allow-origin") or "")
        acac = str(foreign.get("Access-Control-Allow-Credentials") or foreign.get("access-control-allow-credentials") or "").lower()
        confirmed = acao in {"*", "https://dast.invalid"} and acac == "true"
        facts = "任意/不可信 Origin 被允许携带凭据。" if confirmed else facts
    elif probe_name in {"ssrf", "xxe"}:
        confirmed = bool(CallbackHandler.hits)
        facts = "一次性 HTTP 外带端点收到与本任务关联的目标回调。" if confirmed else facts
    elif probe_name == "unsafe_deserialization":
        confirmed = any("DAST_DESERIALIZATION_EXEC_8675309" in body and "_$$ND_FUNC$$_" not in body for body in bodies[1:])
        facts = "无副作用函数标记被反序列化执行并进入响应。" if confirmed else facts
    elif probe_name == "code_injection":
        confirmed = "8675320" in bodies[1] and "8675309+11" not in bodies[1]
        facts = "唯一无副作用算术表达式被动态求值。" if confirmed else facts
    elif probe_name == "account_recovery":
        random_result, predicted_result = exchanges[0]["result"], exchanges[1]["result"]
        confirmed = (
            method in {"GET", "HEAD"}
            and predicted_result.get("status") not in {0, 301, 302, 303, 307, 308, 401, 403, 404}
            and (predicted_result.get("status") != random_result.get("status") or predicted_result.get("body_sha256") != random_result.get("body_sha256"))
        )
        facts = "由测试账号名派生的令牌通过校验，而随机令牌被拒绝。" if confirmed else facts
    elif probe_name == "sensitive_data_exposure":
        body = bodies[0].lower() if bodies else ""
        confirmed = any(re.search(rf"['\"]{name}['\"]\s*:", body) for name in ("password", "password_hash", "passwd", "reset_token", "secret"))
        facts = "最低权限接口响应包含密码哈希、令牌或密钥字段。" if confirmed else facts
    elif probe_name == "security_misconfiguration":
        headers = exchanges[0]["result"].get("headers", {}) if exchanges else {}
        lowered_headers = {str(key).lower(): str(value) for key, value in headers.items()}
        cookie = lowered_headers.get("set-cookie", "").lower()
        powered = bool(lowered_headers.get("x-powered-by"))
        weak_cookie = bool(cookie) and ("secure" not in cookie or "httponly" not in cookie or "samesite" not in cookie)
        confirmed = powered or weak_cookie
        facts = "响应暴露框架标识或会话 Cookie 缺少安全属性。" if confirmed else facts
    elif probe_name == "file_upload":
        benign, active = exchanges[0]["result"], exchanges[1]["result"]
        active_filename = str(variants[1][1])
        active_marker = active_filename.rsplit(".", 1)[0]
        references = upload_references(active, url, active_filename)
        retrieved: list[dict] = []
        for reference in references[:3]:
            if not in_scope(reference, target, paths):
                continue
            result = request("GET", reference, headers=role_headers)
            exchanges.append({"label": "retrieve-active", "url": reference, "result": result})
            retrieved.append(result)
        unsafe_types = {"text/html", "application/xhtml+xml", "image/svg+xml", "application/javascript", "text/javascript"}
        confirmed = any(
            active_marker in str(item.get("body") or "")
            and str(item.get("headers", {}).get("Content-Type") or item.get("headers", {}).get("content-type") or "").split(";", 1)[0].strip().lower() in unsafe_types
            for item in retrieved
        )
        benign_accepted = int(benign.get("status") or 0) in {200, 201, 202, 204}
        active_rejected = int(active.get("status") or 0) in {400, 403, 406, 413, 415, 422}
        safely_served = any(
            active_marker in str(item.get("body") or "")
            and (
                "attachment" in str(item.get("headers", {}).get("Content-Disposition") or item.get("headers", {}).get("content-disposition") or "").lower()
                or str(item.get("headers", {}).get("X-Content-Type-Options") or item.get("headers", {}).get("x-content-type-options") or "").lower() == "nosniff"
            )
            and str(item.get("headers", {}).get("Content-Type") or item.get("headers", {}).get("content-type") or "").split(";", 1)[0].strip().lower() not in unsafe_types
            for item in retrieved
        )
        file_upload_negative = not confirmed and ((benign_accepted and active_rejected) or safely_served)
        if confirmed:
            facts = "无害 HTML 标记文件被公开存储，并以活动内容类型返回。"
        elif file_upload_negative:
            facts = "普通文本对照可用，活动扩展被拒绝或只能以安全下载类型访问。"

    statuses = [int(item["result"].get("status") or 0) for item in exchanges]
    responses_reached_target = bool(statuses) and all(100 <= status < 500 for status in statuses)
    if probe_name in {"sensitive_data_exposure", "security_misconfiguration"}:
        negative_supported = not confirmed and bool(statuses) and all(200 <= status < 400 for status in statuses)
    elif probe_name == "account_recovery":
        # A generic 400/422 only proves that required form fields were missing; it
        # does not prove that an unpredictable reset token would be rejected.
        negative_supported = not confirmed and bool(statuses) and all(status in {401, 403, 404} for status in statuses)
    elif probe_name == "file_upload":
        negative_supported = bool(file_upload_negative)
    else:
        negative_supported = not confirmed and responses_reached_target

    evidence_type = "timing" if probe_name == "command_injection" else "oast_callback" if probe_name in {"ssrf", "xxe"} else "differential"
    payload = json.dumps(exchanges, ensure_ascii=False, sort_keys=True).encode()
    evidence = [{
        "evidence_id": str(uuid4()), "type": evidence_type, "request_id": request_id,
        "confirmed": confirmed, "facts": facts, "probe_count": len(exchanges), "complete": True,
        "expected_probe_count": len(variants), "negative_conclusion_supported": negative_supported,
        "artifact_reference": f"inline://{request_id}/{probe_name}",
        "artifact_sha256": hashlib.sha256(payload).hexdigest(), "mime_type": "application/json",
        "size_bytes": len(payload),
        "exchange": {"probe": probe_name, "attempts": [{"label": item["label"], **compact_exchange(method, item["url"], item["result"])} for item in exchanges]},
        "timing": {"samples_ms": [item["result"].get("duration_ms") for item in exchanges]} if probe_name == "command_injection" else None,
        "environment": {"executor": "sandbox-http-v1", "network_target": origin(target)},
    }]
    return evidence, confirmed, len(exchanges), negative_supported


def main() -> None:
    contract = json.load(sys.stdin)
    if contract.get("schema") != "ai-security-platform.dast-sandbox-handoff/v1":
        raise ValueError("unsupported handoff schema")
    target = str(contract.get("target", {}).get("url") or "")
    paths = [str(value) for value in contract.get("target", {}).get("allowed_paths", [])]
    roles = [item for item in contract.get("roles", []) if isinstance(item, dict)]
    if not origin(target) or not paths:
        raise ValueError("contract target or path scope is missing")
    contract_steps = [item for item in contract.get("steps", []) if isinstance(item, dict)]
    if any(item.get("kind") == "sandbox_probe" and item.get("probe") == "file_upload" for item in contract_steps):
        isolation = contract.get("isolation") if isinstance(contract.get("isolation"), dict) else {}
        if not bool(isolation.get("disposable")):
            raise ValueError("file_upload validation requires a disposable Docker target")
    all_evidence, confirmed_count, probe_count = [], 0, 0
    fixed_negative_results: list[bool] = []
    signals: list[str] = []
    reasons: list[str] = []
    for step in contract_steps:
        if step.get("kind") != "sandbox_probe":
            continue
        evidence, confirmed, count, negative_supported = probe(step, target, paths, roles)
        all_evidence.extend(evidence)
        confirmed_count += int(confirmed)
        probe_count += count
        fixed_negative_results.append(negative_supported)
    if probe_count:
        fixed_signal = "exploitable" if confirmed_count else "not_exploitable" if fixed_negative_results and all(fixed_negative_results) else "uncertain"
        signals.append(fixed_signal)
        reasons.append(
            "发现明确、可重复的固定探针触发证据。"
            if fixed_signal == "exploitable"
            else "固定安全探针完整执行，且满足对应的阴性判定条件。"
            if fixed_signal == "not_exploitable"
            else "固定探针已执行，但目标响应不足以支持阴性裁决。"
        )
    flow_result = execute_flow_steps(contract, target, paths, roles)
    if flow_result["status"] == "completed":
        all_evidence.extend(list(flow_result.get("evidence") or []))
        signals.append(str(flow_result.get("verdict_signal") or "uncertain"))
        reasons.append(str(flow_result.get("verdict_reason") or ""))
    if not all_evidence:
        raise ValueError("contract contains no executable SANDBOX HTTP steps")
    first_request_id = str(next((step.get("request_id") for step in contract.get("steps", []) if isinstance(step, dict) and step.get("request_id")), ""))
    if probe_count:
        all_evidence.append({
            "evidence_id": str(uuid4()), "type": "coverage", "request_id": first_request_id,
            "confirmed": False, "facts": f"完成 {probe_count} 个固定探针请求。", "complete": True,
            "probe_count": probe_count, "expected_probe_count": probe_count,
            "negative_conclusion_supported": bool(fixed_negative_results) and all(fixed_negative_results),
            "artifact_sha256": hashlib.sha256(str(probe_count).encode()).hexdigest(),
            "mime_type": "application/json", "size_bytes": 0,
        })
    signal = "exploitable" if "exploitable" in signals else "not_exploitable" if signals and all(item == "not_exploitable" for item in signals) else "uncertain"
    print(json.dumps({
        "status": "completed", "evidence": all_evidence,
        "verdict_signal": signal,
        "verdict_reason": " ".join(item for item in reasons if item),
    }, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"status": "failed", "error": redact_text(exc)[:2000]}, ensure_ascii=False))
        sys.exit(2)
