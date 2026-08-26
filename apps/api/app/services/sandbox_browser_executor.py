"""Fixed Playwright evidence executor used by the SANDBOX orchestrator.

The process accepts one DAST handoff contract on stdin and prints one JSON
result.  It deliberately exposes a small action vocabulary and enforces the
contract origin/path policy again inside the browser container.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys
import time
from http.cookies import SimpleCookie
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.parse import urlencode
from uuid import uuid4


SAFE_ACTIONS = {"navigate", "goto", "click", "fill", "select", "wait", "assert_text", "screenshot"}
SECRET = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+|((?:token|password|secret|api[_-]?key|cookie)\s*[:=]\s*)\S+")
SENSITIVE_HEADER_LINE = re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*).+$")
CSRF_TOKEN_NAME = re.compile(r"(?i)(csrf|xsrf|authenticity|requestverificationtoken|nonce)")
UNSAFE_MUTATION_NAME = re.compile(r"(?i)(^id$|_id$|userid|user_id|password|passwd|token|csrf|xsrf|role|permission|admin|balance|price|amount)")
LOGIN_PATHS = {"/login", "/signin", "/users/login", "/auth/login"}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


HTTP_OPENER = build_opener(NoRedirect())


def _origin(value: str) -> tuple[str, str, int] | None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)


def _allowed(url: str, base: str, paths: list[str]) -> bool:
    parsed = urlparse(url)
    if _origin(url) != _origin(base):
        return False
    path = parsed.path or "/"
    return any(path == allowed or path.startswith(allowed.rstrip("/") + "/") for allowed in paths)


def _artifact(path: Path, kind: str, request_id: str, facts: str) -> dict[str, object]:
    content = path.read_bytes()
    return {
        "evidence_id": str(uuid4()), "type": kind, "request_id": request_id,
        "confirmed": False, "facts": facts, "artifact_reference": f"sandbox-artifact://{path.name}",
        "artifact_sha256": sha256(content).hexdigest(), "mime_type": "image/png" if path.suffix == ".png" else "application/json",
        "size_bytes": len(content), "complete": True,
    }


def _credential(ref: str) -> dict[str, object]:
    if not ref.startswith("env:"):
        return {}
    raw = os.getenv(ref[4:], "")
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {"cookie": raw}
    return value if isinstance(value, dict) else {}


def _redact_text(value: object) -> str:
    text = str(value)
    text = SECRET.sub("[REDACTED]", text)
    return SENSITIVE_HEADER_LINE.sub(r"\1[REDACTED]", text)


def _context_cookie_header(context: object, url: str) -> str:
    try:
        cookies = context.cookies([url])
    except Exception:
        return ""
    pairs = []
    for item in cookies if isinstance(cookies, list) else []:
        if isinstance(item, dict) and item.get("name") and item.get("value") is not None:
            pairs.append(f"{item['name']}={item['value']}")
    return "; ".join(pairs)


def _add_set_cookie_headers(context: object, url: str, set_cookie_headers: list[str]) -> None:
    parsed = urlparse(url)
    if not parsed.hostname or not set_cookie_headers:
        return
    cookies: list[dict[str, object]] = []
    for header in set_cookie_headers[:20]:
        jar = SimpleCookie()
        try:
            jar.load(header)
        except Exception:
            continue
        for name, morsel in jar.items():
            if not name:
                continue
            cookies.append({
                "name": name,
                "value": morsel.value,
                "domain": parsed.hostname,
                "path": morsel["path"] or "/",
                "secure": parsed.scheme == "https" or bool(morsel["secure"]),
                "httpOnly": bool(morsel["httponly"]),
            })
    if cookies:
        context.add_cookies(cookies)


def _http_post_form(url: str, payload: dict[str, str], headers: dict[str, str] | None = None) -> dict[str, object]:
    started = time.perf_counter()
    request = Request(
        url,
        data=urlencode(payload).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded", **(headers or {})},
        method="POST",
    )
    try:
        response = HTTP_OPENER.open(request, timeout=15)
        status, response_headers = int(response.status), response.headers
        body = response.read(65_536)
    except HTTPError as exc:
        status, response_headers = int(exc.code), exc.headers
        body = exc.read(65_536)
    except (URLError, TimeoutError, OSError) as exc:
        return {"status": 0, "headers": {}, "set_cookie_headers": [], "body": b"", "error": _redact_text(exc)[:500], "duration_ms": round((time.perf_counter() - started) * 1000, 2)}
    return {
        "status": status,
        "headers": {str(key): ("[REDACTED]" if str(key).lower() in {"set-cookie", "cookie", "authorization"} else _redact_text(value)[:1000]) for key, value in response_headers.items()},
        "set_cookie_headers": [str(value) for value in response_headers.get_all("Set-Cookie", [])],
        "body": body,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def _submit_dom_form(page: object, form: dict[str, object], payload: dict[str, str], remove_names: list[str] | None = None) -> dict[str, object]:
    started = time.perf_counter()
    try:
        page.evaluate(
            """({index, payload, removeNames}) => {
              const form = document.forms[index];
              if (!form) throw new Error('approved form is no longer present');
              for (const name of removeNames) {
                for (const element of Array.from(form.elements).filter(item => item.name === name)) {
                  element.disabled = true;
                }
              }
              for (const [name, value] of Object.entries(payload)) {
                const elements = Array.from(form.elements).filter(item => item.name === name);
                if (!elements.length) {
                  const hidden = document.createElement('input');
                  hidden.type = 'hidden';
                  hidden.name = name;
                  hidden.value = value;
                  form.appendChild(hidden);
                } else {
                  for (const element of elements) {
                    element.disabled = false;
                    if (element.type === 'checkbox' || element.type === 'radio') element.checked = Boolean(value);
                    else element.value = value;
                  }
                }
              }
              form.submit();
            }""",
            {"index": int(form.get("index") or 0), "payload": payload, "removeNames": list(remove_names or [])},
        )
        try:
            page.wait_for_load_state("networkidle", timeout=15_000)
        except Exception:
            page.wait_for_timeout(500)
        try:
            body = str(page.content()).encode("utf-8", errors="replace")[:65_536]
        except Exception:
            body = b""
        return {"status": 200, "headers": {}, "set_cookie_headers": [], "body": body, "duration_ms": round((time.perf_counter() - started) * 1000, 2), "fallback": "browser_form"}
    except Exception as exc:
        return {"status": 0, "headers": {}, "set_cookie_headers": [], "body": b"", "error": _redact_text(exc)[:500], "duration_ms": round((time.perf_counter() - started) * 1000, 2), "fallback": "browser_form"}


def _redact_har(path: Path) -> None:
    try:
        document = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return

    def walk(value: object, key: str = "") -> object:
        lowered = key.lower()
        if lowered in {"cookies", "querystring"} and isinstance(value, list):
            return [{**item, "value": "[REDACTED]"} if isinstance(item, dict) and "value" in item else walk(item) for item in value[:200]]
        if isinstance(value, list):
            return [walk(item, key) for item in value]
        if not isinstance(value, dict):
            return value
        result: dict[str, object] = {}
        for raw_key, item in value.items():
            item_key = str(raw_key)
            if item_key.lower() in {"postdata", "text"} and key.lower() == "postdata":
                result[item_key] = "[REDACTED]"
            elif item_key.lower() == "value" and str(value.get("name") or "").lower() in {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}:
                result[item_key] = "[REDACTED]"
            else:
                result[item_key] = walk(item, item_key)
        return result

    path.write_text(json.dumps(walk(document), ensure_ascii=False, separators=(",", ":")), encoding="utf-8")


def _browser_forms(page: object) -> list[dict[str, object]]:
    forms = page.locator("form").evaluate_all(
        """forms => forms.map((form, index) => ({
          index,
          action: new URL(form.getAttribute('action') || location.href, location.href).href,
          method: (form.getAttribute('method') || 'GET').toUpperCase(),
          enctype: (form.getAttribute('enctype') || 'application/x-www-form-urlencoded').toLowerCase(),
          fields: Array.from(form.elements).filter(element => element.name && !element.disabled).map(element => ({
            name: element.name,
            type: (element.type || element.tagName || 'text').toLowerCase(),
            value: element.value == null ? '' : String(element.value),
            checked: element.checked !== false,
            max_length: Number.isFinite(element.maxLength) ? element.maxLength : -1
          }))
        }))"""
    )
    return [item for item in forms if isinstance(item, dict)] if isinstance(forms, list) else []


def _mapped_parameter_names(step: dict[str, object]) -> list[str]:
    raw = step.get("parameters") if isinstance(step.get("parameters"), list) else [step.get("parameter")]
    result: list[str] = []
    for item in raw:
        name = str(item.get("name") or "") if isinstance(item, dict) else str(item or "")
        if name and name not in result:
            result.append(name)
    return result


def _select_csrf_form(forms: list[dict[str, object]], mapped: list[str]) -> dict[str, object] | None:
    candidates = [form for form in forms if str(form.get("method") or "GET").upper() == "POST" and "multipart/form-data" not in str(form.get("enctype") or "")]
    if not candidates:
        return None
    mapped_set = set(mapped)
    return max(
        candidates,
        key=lambda form: len(mapped_set & {str(field.get("name") or "") for field in form.get("fields", []) if isinstance(field, dict)}),
    )


def _csrf_mutation_field(form: dict[str, object], mapped: list[str]) -> dict[str, object] | None:
    fields = [item for item in form.get("fields", []) if isinstance(item, dict)]
    by_name = {str(item.get("name") or ""): item for item in fields}
    ordered = [by_name[name] for name in mapped if name in by_name] + [item for item in fields if str(item.get("name") or "") not in mapped]
    for field in ordered:
        name = str(field.get("name") or "")
        field_type = str(field.get("type") or "text").lower()
        if name and not UNSAFE_MUTATION_NAME.search(name) and field_type not in {"hidden", "submit", "button", "reset", "file", "checkbox", "radio", "password", "number", "range"}:
            return field
    return None


def _csrf_marker(field: dict[str, object]) -> str:
    suffix = uuid4().hex[:12]
    name = str(field.get("name") or "").lower()
    field_type = str(field.get("type") or "text").lower()
    if field_type == "email" or "email" in name:
        value = f"dast-csrf-{suffix}@example.invalid"
    elif field_type == "tel" or "phone" in name:
        value = f"555{int(suffix[:8], 16) % 10_000_000:07d}"
    else:
        value = f"DAST_CSRF_{suffix}"
    max_length = int(field.get("max_length") or -1)
    return value[:max_length] if max_length > 0 else value


def _form_payload(form: dict[str, object]) -> dict[str, str]:
    result: dict[str, str] = {}
    for field in form.get("fields", []):
        if not isinstance(field, dict) or not bool(field.get("checked", True)):
            continue
        name = str(field.get("name") or "")
        field_type = str(field.get("type") or "text").lower()
        if name and field_type not in {"submit", "button", "reset", "file"}:
            result[name] = str(field.get("value") or "")
    return result


def _login_payload(form: dict[str, object], credential: dict[str, object]) -> dict[str, str]:
    payload = _form_payload(form)
    for field in form.get("fields", []):
        if not isinstance(field, dict):
            continue
        name = str(field.get("name") or "")
        lowered = name.lower()
        field_type = str(field.get("type") or "text").lower()
        if field_type == "password" or "password" in lowered or lowered in {"passwd", "pwd"}:
            payload[name] = str(credential.get("password") or "")
        elif lowered in {"username", "login", "user", "userid", "user_name", "name"}:
            payload[name] = str(credential.get("username") or credential.get("email") or "")
        elif "email" in lowered:
            payload[name] = str(credential.get("email") or credential.get("username") or "")
    return payload


def _is_login_form(form: dict[str, object]) -> bool:
    action_path = urlparse(str(form.get("action") or "")).path
    if action_path not in LOGIN_PATHS:
        return False
    return any(
        isinstance(field, dict)
        and (str(field.get("type") or "").lower() == "password" or "password" in str(field.get("name") or "").lower())
        for field in form.get("fields", [])
    )


def _ensure_authenticated(context: object, page: object, target_url: str, credential: dict[str, object], request_id: str) -> dict[str, object] | None:
    """Complete a same-origin login prerequisite when the target redirects there."""
    forms = _browser_forms(page)
    login_form = next((form for form in forms if str(form.get("method") or "GET").upper() == "POST" and _is_login_form(form)), None)
    if login_form is None:
        return None
    action = str(login_form.get("action") or "")
    if _origin(action) != _origin(target_url):
        raise ValueError("test identity login form left the approved target origin")
    if not credential.get("password") or not (credential.get("username") or credential.get("email")):
        raise ValueError("authenticated target redirected to login but the test identity has no login adapter values")
    payload = _login_payload(login_form, credential)
    cookie_header = _context_cookie_header(context, action)
    headers = {"Cookie": cookie_header} if cookie_header else {}
    response = _http_post_form(action, payload, headers=headers)
    if int(response["status"]) == 0:
        response = _submit_dom_form(page, login_form, payload)
    if int(response["status"]) >= 400 or int(response["status"]) == 0:
        detail = f": {response.get('error')}" if response.get("error") else ""
        raise ValueError(f"test identity login failed with HTTP {int(response['status'])}{detail}")
    _add_set_cookie_headers(context, action, list(response.get("set_cookie_headers") or []))
    page.goto(target_url, wait_until="networkidle", timeout=15_000)
    if urlparse(str(page.url)).path in LOGIN_PATHS or any(_is_login_form(form) for form in _browser_forms(page)):
        raise ValueError("test identity login did not establish an authenticated target session")
    return {
        "evidence_id": str(uuid4()), "type": "authorization", "request_id": request_id,
        "confirmed": False, "facts": "Disposable test identity authenticated through the target's same-origin login prerequisite.",
        "complete": True,
    }


def _csrf_state(page: object, target_url: str, mapped: list[str], field_name: str) -> tuple[dict[str, object], dict[str, object]]:
    page.goto(target_url, wait_until="networkidle", timeout=15_000)
    form = _select_csrf_form(_browser_forms(page), mapped)
    if form is None:
        raise ValueError("approved CSRF target has no non-multipart POST form")
    field = next((item for item in form.get("fields", []) if isinstance(item, dict) and str(item.get("name") or "") == field_name), None)
    if field is None:
        raise ValueError("mapped CSRF state field disappeared after submission")
    state = {"field": field_name, "value": str(field.get("value") or ""), "url": str(page.url)}
    state["sha256"] = sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()
    return form, state


def _csrf_submit(context: object, page: object, form: dict[str, object], field_name: str, value: str, variant: str) -> dict[str, object]:
    payload = _form_payload(form)
    payload[field_name] = value
    token_names = [name for name in list(payload) if CSRF_TOKEN_NAME.search(name)]
    headers = {"Origin": "https://dast-cross-site.invalid", "Referer": "https://dast-cross-site.invalid/probe"}
    remove_names: list[str] = []
    if variant == "missing":
        for name in token_names:
            payload.pop(name, None)
        remove_names = token_names
    elif variant == "invalid":
        for name in token_names:
            payload[name] = "DAST_INVALID_CSRF_TOKEN"
        headers["X-CSRF-Token"] = "DAST_INVALID_CSRF_TOKEN"
        headers["X-XSRF-Token"] = "DAST_INVALID_CSRF_TOKEN"
    else:
        headers = {}
    action = str(form.get("action") or "")
    cookie_header = _context_cookie_header(context, action)
    if cookie_header:
        headers = {**headers, "Cookie": cookie_header}
    response = _http_post_form(action, payload, headers=headers)
    if int(response["status"]) == 0:
        response = _submit_dom_form(page, form, payload, remove_names)
    body = bytes(response.get("body") or b"")[:65_536]
    return {
        "variant": variant, "status": int(response["status"]), "duration_ms": response.get("duration_ms"),
        "response_sha256": sha256(body).hexdigest(), "response_bytes": len(body), "token_field_count": len(token_names),
        "error": response.get("error"),
    }


def _execute_csrf_probe(context: object, page: object, step: dict[str, object], base: str, paths: list[str], artifact_root: Path, index: int, credential: dict[str, object]) -> dict[str, object]:
    target_url = urljoin(base.rstrip("/") + "/", str(step.get("url") or base))
    if not _allowed(target_url, base, paths):
        raise ValueError("CSRF target left the approved origin/path scope")
    mapped = _mapped_parameter_names(step)
    page.goto(target_url, wait_until="networkidle", timeout=15_000)
    request_id = str(step.get("request_id") or "")
    authentication_evidence = _ensure_authenticated(context, page, target_url, credential, request_id)
    form = _select_csrf_form(_browser_forms(page), mapped)
    if form is None:
        raise ValueError("approved CSRF target has no non-multipart POST form")
    action = str(form.get("action") or "")
    if not _allowed(action, base, paths):
        raise ValueError("CSRF form action left the approved origin/path scope")
    initial_payload = _form_payload(form)
    identifier = next((name for name in mapped if name in initial_payload and re.search(r"(?i)(^id$|_id$|userid|user_id)", name)), "")
    if identifier and str(initial_payload.get(identifier) or "") in {"", "0", "None", "null"}:
        reason = "CSRF 表单缺少可回滚的既有资源标识，已停止状态变更，无法形成裁决。"
        return {
            "status": "completed",
            "evidence": [{
                "evidence_id": str(uuid4()), "type": "differential", "request_id": request_id,
                "confirmed": False, "facts": reason, "complete": True,
                "exchange": {"resource_identifier": identifier, "mutation_sent": False},
            }, {
                "evidence_id": str(uuid4()), "type": "coverage", "request_id": request_id,
                "confirmed": False, "facts": "CSRF 目标不是可安全回滚的既有资源表单。", "complete": False,
                "probe_count": 0, "expected_probe_count": 3, "negative_conclusion_supported": False,
            }],
            "verdict_signal": "uncertain", "verdict_reason": reason,
        }
    field = _csrf_mutation_field(form, mapped)
    if field is None:
        raise ValueError("CSRF probe has no safe mapped state field to mutate and roll back")
    field_name = str(field.get("name") or "")
    original = str(field.get("value") or "")
    exchanges: list[dict[str, object]] = []
    changed: dict[str, bool] = {}
    restore_results: list[bool] = []

    def restore() -> bool:
        fresh, _ = _csrf_state(page, target_url, mapped, field_name)
        _csrf_submit(context, page, fresh, field_name, original, "valid")
        _, state = _csrf_state(page, target_url, mapped, field_name)
        restored = str(state["value"]) == original
        restore_results.append(restored)
        return restored

    for variant in ("missing", "invalid", "valid"):
        fresh, before = _csrf_state(page, target_url, mapped, field_name)
        marker = _csrf_marker(field)
        exchange = _csrf_submit(context, page, fresh, field_name, marker, variant)
        _, after = _csrf_state(page, target_url, mapped, field_name)
        did_change = str(after["value"]) == marker and str(before["value"]) != marker
        changed[variant] = did_change
        exchange["state_before_sha256"] = before["sha256"]
        exchange["state_after_sha256"] = after["sha256"]
        exchange["state_changed_to_unique_marker"] = did_change
        exchanges.append(exchange)
        if did_change and not restore():
            raise RuntimeError("CSRF probe changed state but rollback verification failed")

    valid_control = changed.get("valid", False)
    bypassed = changed.get("missing", False) or changed.get("invalid", False)
    if bypassed and valid_control and all(restore_results):
        signal = "exploitable"
        reason = "缺失或错误 CSRF 令牌的跨站来源请求造成了与有效对照相同的状态变更，且测试数据已回滚。"
    elif valid_control and not bypassed and all(restore_results):
        signal = "not_exploitable"
        reason = "有效令牌对照可完成状态变更，而缺失和错误令牌请求均未改变状态；测试数据已回滚。"
    else:
        signal = "uncertain"
        reason = "CSRF 三组请求已执行，但有效令牌对照未形成可观察状态变化，无法据此裁决。"
    shot = artifact_root / f"csrf-step-{index:02d}.png"
    page.screenshot(path=str(shot), full_page=True)
    evidence = [
        {
            "evidence_id": str(uuid4()), "type": "differential", "request_id": request_id,
            "confirmed": signal == "exploitable", "facts": reason, "complete": True,
            "exchange": {"variants": exchanges, "rollback_verified": bool(restore_results) and all(restore_results), "state_field": field_name},
        },
        {
            "evidence_id": str(uuid4()), "type": "coverage", "request_id": request_id,
            "confirmed": False, "facts": "CSRF missing/invalid/valid token variants completed with state snapshots.",
            "complete": True, "probe_count": 3, "expected_probe_count": 3,
            "negative_conclusion_supported": signal == "not_exploitable",
        },
        _artifact(shot, "screenshot", request_id, "Post-rollback CSRF target state captured at the approved origin."),
    ]
    if authentication_evidence is not None:
        evidence.insert(0, authentication_evidence)
    return {"status": "completed", "evidence": evidence, "verdict_signal": signal, "verdict_reason": reason}


def _execute_access_control_mutation_probe(
    owner_context: object,
    owner_page: object,
    peer_context: object,
    peer_page: object,
    step: dict[str, object],
    base: str,
    paths: list[str],
    artifact_root: Path,
    index: int,
    owner_credential: dict[str, object],
    peer_credential: dict[str, object],
) -> dict[str, object]:
    """Verify a form-based IDOR update and restore every touched test record."""
    target_url = urljoin(base.rstrip("/") + "/", str(step.get("url") or base))
    if not _allowed(target_url, base, paths):
        raise ValueError("access-control mutation target left the approved origin/path scope")
    request_id = str(step.get("request_id") or "")
    mapped = _mapped_parameter_names(step)

    def load_state(context: object, page: object, credential: dict[str, object]) -> tuple[dict[str, object], dict[str, str]]:
        page.goto(target_url, wait_until="networkidle", timeout=15_000)
        _ensure_authenticated(context, page, target_url, credential, request_id)
        form = _select_csrf_form(_browser_forms(page), mapped)
        if form is None:
            raise ValueError("approved access-control target has no mapped non-multipart POST form")
        action = str(form.get("action") or "")
        if not _allowed(action, base, paths):
            raise ValueError("access-control form action left the approved origin/path scope")
        return form, _form_payload(form)

    owner_form, owner_original = load_state(owner_context, owner_page, owner_credential)
    peer_form, peer_original = load_state(peer_context, peer_page, peer_credential)
    identifier = next((name for name in mapped if name in owner_original and re.search(r"(?i)(^id$|_id$|userid|user_id)", name)), "")
    if not identifier or not owner_original.get(identifier) or owner_original.get(identifier) == peer_original.get(identifier):
        reason = "双身份表单未提供可区分的资源标识，已停止状态变更，无法形成裁决。"
        return {
            "status": "completed",
            "evidence": [{
                "evidence_id": str(uuid4()), "type": "differential", "request_id": request_id,
                "confirmed": False, "facts": reason, "complete": True,
                "exchange": {"owner_fixture_ready": False, "mutation_sent": False},
            }, {
                "evidence_id": str(uuid4()), "type": "coverage", "request_id": request_id,
                "confirmed": False, "facts": "资源归属夹具不足，未执行变更请求。", "complete": False,
                "probe_count": 0, "expected_probe_count": 2, "negative_conclusion_supported": False,
            }],
            "verdict_signal": "uncertain", "verdict_reason": reason,
        }
    state_field = _csrf_mutation_field(owner_form, mapped)
    if state_field is None:
        raise ValueError("access-control mutation probe has no safe field to change and restore")
    field_name = str(state_field.get("name") or "")
    marker = _csrf_marker(state_field).replace("DAST_CSRF_", "DAST_IDOR_")

    def submit(context: object, page: object, form: dict[str, object], payload: dict[str, str]) -> dict[str, object]:
        action = str(form.get("action") or "")
        cookie_header = _context_cookie_header(context, action)
        response = _http_post_form(action, payload, headers={"Cookie": cookie_header} if cookie_header else {})
        if int(response.get("status") or 0) == 0:
            response = _submit_dom_form(page, form, payload)
        return response

    attack_payload = dict(peer_original)
    attack_payload[identifier] = owner_original[identifier]
    attack_payload[field_name] = marker
    attack_response = submit(peer_context, peer_page, peer_form, attack_payload)
    owner_after_form, owner_after = load_state(owner_context, owner_page, owner_credential)
    peer_after_form, peer_after = load_state(peer_context, peer_page, peer_credential)
    owner_changed = owner_after.get(field_name) == marker
    peer_changed = peer_after.get(field_name) == marker

    rollback_results: list[bool] = []
    if owner_changed:
        submit(owner_context, owner_page, owner_after_form, owner_original)
        _, restored = load_state(owner_context, owner_page, owner_credential)
        rollback_results.append(restored.get(field_name) == owner_original.get(field_name))
    if peer_changed:
        submit(peer_context, peer_page, peer_after_form, peer_original)
        _, restored = load_state(peer_context, peer_page, peer_credential)
        rollback_results.append(restored.get(field_name) == peer_original.get(field_name))

    # A valid owner update is the positive control required for a green result.
    control_form, control_original = load_state(owner_context, owner_page, owner_credential)
    control_marker = _csrf_marker(state_field).replace("DAST_CSRF_", "DAST_OWNER_")
    control_payload = dict(control_original)
    control_payload[field_name] = control_marker
    control_response = submit(owner_context, owner_page, control_form, control_payload)
    control_after_form, control_after = load_state(owner_context, owner_page, owner_credential)
    control_changed = control_after.get(field_name) == control_marker
    if control_changed:
        submit(owner_context, owner_page, control_after_form, owner_original)
        _, restored = load_state(owner_context, owner_page, owner_credential)
        rollback_results.append(restored.get(field_name) == owner_original.get(field_name))

    rollback_verified = bool(rollback_results) and all(rollback_results)
    if (owner_changed or peer_changed or control_changed) and not rollback_verified:
        raise RuntimeError("access-control mutation probe changed state but rollback verification failed")
    if owner_changed and rollback_verified:
        signal = "exploitable"
        reason = "另一普通测试用户可用资源所有者标识修改其字段，且隔离测试数据已回滚。"
    elif not owner_changed and control_changed and rollback_verified:
        signal = "not_exploitable"
        reason = "所有者有效对照可更新资源，而另一普通用户无法修改该资源；测试数据已回滚。"
    else:
        signal = "uncertain"
        reason = "双身份变更已执行，但有效对照或回滚证据不足，无法形成裁决。"
    shot = artifact_root / f"access-control-step-{index:02d}.png"
    owner_page.screenshot(path=str(shot), full_page=True)
    evidence = [{
        "evidence_id": str(uuid4()), "type": "authorization", "request_id": request_id,
        "confirmed": signal == "exploitable", "facts": reason, "complete": True,
        "exchange": {
            "peer_attempt_status": int(attack_response.get("status") or 0),
            "owner_control_status": int(control_response.get("status") or 0),
            "owner_changed_by_peer": owner_changed, "peer_record_changed": peer_changed,
            "owner_control_changed": control_changed, "rollback_verified": rollback_verified,
        },
    }, {
        "evidence_id": str(uuid4()), "type": "coverage", "request_id": request_id,
        "confirmed": False, "facts": "Peer mutation and owner control completed with post-state observations.",
        "complete": True, "probe_count": 2, "expected_probe_count": 2,
        "negative_conclusion_supported": signal == "not_exploitable",
    }, _artifact(shot, "screenshot", request_id, "Post-rollback access-control target state captured.")]
    return {"status": "completed", "evidence": evidence, "verdict_signal": signal, "verdict_reason": reason}


def _execute_xss_probe(
    context: object,
    page: object,
    step: dict[str, object],
    base: str,
    paths: list[str],
    artifact_root: Path,
    index: int,
    credential: dict[str, object],
    console: list[str],
) -> dict[str, object]:
    observer_url = urljoin(base.rstrip("/") + "/", str(step.get("url") or base))
    setup_url = urljoin(base.rstrip("/") + "/", str(step.get("setup_url") or observer_url))
    if not _allowed(observer_url, base, paths) or not _allowed(setup_url, base, paths):
        raise ValueError("XSS setup or observer URL left the approved origin/path scope")
    request_id = str(step.get("request_id") or "")
    parameter = str(step.get("parameter") or "q")
    location = str(step.get("location") or "query").lower()
    method = str(step.get("setup_method") or step.get("method") or "GET").upper()
    marker = f"DAST_XSS_{uuid4().hex}"
    payload = f'<img src=x onerror="console.log(\'{marker}\')">'
    page.goto(setup_url, wait_until="networkidle", timeout=15_000)
    authentication_evidence = _ensure_authenticated(context, page, setup_url, credential, request_id)
    setup: dict[str, object] = {"method": method, "url": setup_url, "location": location, "status": None}
    persistent = observer_url != setup_url
    original_form_payload: dict[str, str] | None = None
    submitted_form: dict[str, object] | None = None

    if method == "GET" and location == "query":
        parsed = urlparse(setup_url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[parameter] = payload
        injected_url = urlunparse(parsed._replace(query=urlencode(query)))
        if not _allowed(injected_url, base, paths):
            raise ValueError("XSS query request left the approved origin/path scope")
        response = page.goto(injected_url, wait_until="networkidle", timeout=15_000)
        setup.update({"url": injected_url, "status": int(response.status) if response is not None else 0})
    elif location in {"form", "form_field"}:
        forms = _browser_forms(page)
        form = next(
            (
                item for item in forms
                if str(item.get("method") or "GET").upper() == method
                and parameter in {str(field.get("name") or "") for field in item.get("fields", []) if isinstance(field, dict)}
            ),
            None,
        )
        if form is None:
            raise ValueError("approved XSS target has no form containing the mapped parameter")
        action = str(form.get("action") or "")
        if not _allowed(action, base, paths):
            raise ValueError("XSS form action left the approved origin/path scope")
        form_payload = _form_payload(form)
        original_form_payload = dict(form_payload)
        submitted_form = form
        form_payload[parameter] = payload
        response = _submit_dom_form(page, form, form_payload)
        if int(response.get("status") or 0) == 0:
            cookie_header = _context_cookie_header(context, action)
            response = _http_post_form(action, form_payload, headers={"Cookie": cookie_header} if cookie_header else {})
        if int(response.get("status") or 0) == 0:
            raise ValueError(f"XSS setup request failed: {response.get('error') or 'network error'}")
        setup.update({"url": action, "status": int(response.get("status") or 0)})
    elif location in {"json", "body"}:
        result = page.evaluate(
            """async ({url, method, parameter, payload}) => {
              const response = await fetch(url, {
                method,
                headers: {'Content-Type': 'application/json'},
                credentials: 'include',
                redirect: 'follow',
                body: JSON.stringify({[parameter]: payload})
              });
              const text = await response.text();
              document.open();
              document.write(text);
              document.close();
              return {status: response.status, url: response.url};
            }""",
            {"url": setup_url, "method": method, "parameter": parameter, "payload": payload},
        )
        if isinstance(result, dict):
            setup.update({"status": int(result.get("status") or 0), "url": str(result.get("url") or setup_url)})
        else:
            setup["status"] = 0
    else:
        raise ValueError(f"XSS probe does not support mapped parameter location: {location}")

    if persistent:
        page.goto(observer_url, wait_until="networkidle", timeout=15_000)
    page.wait_for_timeout(500)
    dom = str(page.content())
    executed = any(marker in item for item in console)
    observed = marker in dom
    rollback_verified = True
    if persistent and submitted_form is not None and original_form_payload is not None:
        page.goto(setup_url, wait_until="networkidle", timeout=15_000)
        _ensure_authenticated(context, page, setup_url, credential, request_id)
        restore_form = next(
            (
                item for item in _browser_forms(page)
                if str(item.get("method") or "GET").upper() == method
                and parameter in {str(field.get("name") or "") for field in item.get("fields", []) if isinstance(field, dict)}
            ),
            None,
        )
        if restore_form is None:
            rollback_verified = False
        else:
            restore_response = _submit_dom_form(page, restore_form, original_form_payload)
            rollback_verified = int(restore_response.get("status") or 0) != 0
            page.goto(observer_url, wait_until="networkidle", timeout=15_000)
            rollback_verified = rollback_verified and marker not in str(page.content())
    if executed:
        signal = "exploitable"
        reason = "唯一 XSS 标记在隔离浏览器控制台中执行。"
    elif observed:
        signal = "not_exploitable"
        reason = "唯一标记到达观察页面但未执行脚本，浏览器证据显示其被编码或作为文本处理。"
    else:
        signal = "uncertain"
        reason = "已完成 XSS 写入与观察步骤，但唯一标记未到达观察页面，无法形成裁决。"
    if persistent and not rollback_verified:
        signal = "uncertain"
        reason = "持久化 XSS 写入与观察已执行，但回滚证据不足，无法形成裁决。"
    shot = artifact_root / f"xss-step-{index:02d}.png"
    page.screenshot(path=str(shot), full_page=True)
    evidence = [
        {
            "evidence_id": str(uuid4()), "type": "browser", "request_id": request_id,
            "confirmed": executed and not (persistent and not rollback_verified), "facts": reason, "complete": True,
            "exchange": {
                "setup": setup, "observer_url": observer_url, "persistent": persistent,
                "marker_observed": observed, "marker_executed": executed,
                "rollback_verified": rollback_verified,
            },
        },
        {
            "evidence_id": str(uuid4()), "type": "coverage", "request_id": request_id,
            "confirmed": False, "facts": "XSS setup and browser observation completed.",
            "complete": True, "probe_count": 1, "expected_probe_count": 1,
            "negative_conclusion_supported": signal == "not_exploitable",
        },
        _artifact(shot, "screenshot", request_id, "XSS observer state captured at the approved origin."),
    ]
    if authentication_evidence is not None:
        evidence.insert(0, authentication_evidence)
    return {"status": "completed", "evidence": evidence, "verdict_signal": signal, "verdict_reason": reason}


def execute(contract: dict[str, object]) -> dict[str, object]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        return {"status": "failed", "error": f"Playwright runtime unavailable: {exc}", "evidence": []}
    target = contract.get("target") if isinstance(contract.get("target"), dict) else {}
    base = str(target.get("url") or "")
    paths = [str(item) for item in target.get("allowed_paths", []) if str(item).startswith("/")]
    if not _origin(base) or not paths:
        return {"status": "failed", "error": "Browser contract has no valid target origin/path allowlist", "evidence": []}
    steps = [
        item for item in contract.get("steps", [])
        if isinstance(item, dict)
        and (item.get("kind") == "browser_action" or (item.get("kind") == "sandbox_probe" and item.get("probe") in {"csrf", "xss", "access_control_mutation"}))
    ]
    if not steps:
        return {"status": "failed", "error": "Browser contract contains no supported browser steps", "evidence": []}
    artifact_root = Path(os.getenv("SANDBOX_ARTIFACT_DIR", "/artifacts"))
    artifact_root.mkdir(parents=True, exist_ok=True)
    roles = {str(item.get("alias")): _credential(str(item.get("credential_ref") or "")) for item in contract.get("roles", []) if isinstance(item, dict)}
    evidence: list[dict[str, object]] = []
    console: list[str] = []
    request_ids: list[str] = []
    verdict_signals: list[str] = []
    verdict_reasons: list[str] = []
    started = time.perf_counter()
    try:
        with sync_playwright() as runtime:
            browser = runtime.chromium.launch(headless=True, args=["--disable-dev-shm-usage"])
            sessions: dict[str, tuple[object, object]] = {}

            def session(role: str):  # type: ignore[no-untyped-def]
                key = role or "anonymous"
                if key in sessions:
                    return sessions[key]
                credential = roles.get(role, {})
                headers: dict[str, str] = {}
                if isinstance(credential.get("bearer"), str):
                    headers["Authorization"] = "Bearer " + str(credential["bearer"])
                if isinstance(credential.get("api_key"), str):
                    headers["X-API-Key"] = str(credential["api_key"])
                safe_key = re.sub(r"[^A-Za-z0-9_-]", "_", key)[:40]
                context = browser.new_context(ignore_https_errors=False, extra_http_headers=headers, record_har_path=str(artifact_root / f"network-{safe_key}.har"))
                raw_cookie = credential.get("cookie")
                if isinstance(raw_cookie, str):
                    parsed = urlparse(base)
                    cookies = []
                    for pair in raw_cookie.split(";")[:30]:
                        name, separator, value = pair.strip().partition("=")
                        if separator and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                            cookies.append({"name": name, "value": value, "domain": parsed.hostname, "path": "/", "secure": parsed.scheme == "https", "httpOnly": True})
                    if cookies:
                        context.add_cookies(cookies)
                page = context.new_page()
                page.on("console", lambda message: console.append(_redact_text(message.text)[:1000]))
                page.route(
                    "**/*",
                    lambda route: route.continue_()
                    if route.request.method.upper() in {"GET", "HEAD", "OPTIONS"}
                    and _origin(route.request.url) == _origin(base)
                    and (
                        route.request.resource_type != "document"
                        or _allowed(route.request.url, base, paths)
                        or urlparse(route.request.url).path in {"/login", "/signin", "/users/login", "/auth/login"}
                    )
                    or route.request.method.upper() == "POST"
                    and _origin(route.request.url) == _origin(base)
                    and (
                        _allowed(route.request.url, base, paths)
                        or urlparse(route.request.url).path in {"/login", "/signin", "/users/login", "/auth/login"}
                    )
                    else route.abort("blockedbyclient"),
                )
                sessions[key] = (context, page)
                return context, page

            for index, step in enumerate(steps, start=1):
                role = str(step.get("role") or "")
                context, page = session(role)
                request_id = str(step.get("request_id") or "")
                request_ids.append(request_id)
                if step.get("kind") == "sandbox_probe" and step.get("probe") == "csrf":
                    result = _execute_csrf_probe(context, page, step, base, paths, artifact_root, index, roles.get(role, {}))
                    evidence.extend(list(result.get("evidence") or []))
                    verdict_signals.append(str(result.get("verdict_signal") or "uncertain"))
                    verdict_reasons.append(str(result.get("verdict_reason") or ""))
                    continue
                if step.get("kind") == "sandbox_probe" and step.get("probe") == "xss":
                    result = _execute_xss_probe(context, page, step, base, paths, artifact_root, index, roles.get(role, {}), console)
                    evidence.extend(list(result.get("evidence") or []))
                    verdict_signals.append(str(result.get("verdict_signal") or "uncertain"))
                    verdict_reasons.append(str(result.get("verdict_reason") or ""))
                    continue
                if step.get("kind") == "sandbox_probe" and step.get("probe") == "access_control_mutation":
                    owner_role = str(step.get("owner_role") or "resource_owner")
                    owner_context, owner_page = session(owner_role)
                    result = _execute_access_control_mutation_probe(
                        owner_context, owner_page, context, page, step, base, paths, artifact_root, index,
                        roles.get(owner_role, {}), roles.get(role, {}),
                    )
                    evidence.extend(list(result.get("evidence") or []))
                    verdict_signals.append(str(result.get("verdict_signal") or "uncertain"))
                    verdict_reasons.append(str(result.get("verdict_reason") or ""))
                    continue
                action = str(step.get("action") or "navigate").lower()
                if action not in SAFE_ACTIONS:
                    raise ValueError(f"browser action {action!r} is not allowlisted")
                requested = str(step.get("url") or page.url or base)
                url = urljoin(base.rstrip("/") + "/", requested)
                if action in {"navigate", "goto"}:
                    if not _allowed(url, base, paths):
                        raise ValueError("browser navigation left the approved origin/path scope")
                    page.goto(url, wait_until="networkidle", timeout=15_000)
                elif action == "click":
                    page.locator(str(step.get("selector") or "")).click(timeout=8_000)
                elif action == "fill":
                    page.locator(str(step.get("selector") or "")).fill(str(step.get("value") or ""), timeout=8_000)
                elif action == "select":
                    page.locator(str(step.get("selector") or "")).select_option(str(step.get("value") or ""), timeout=8_000)
                elif action == "wait":
                    page.wait_for_timeout(min(max(int(step.get("milliseconds") or 250), 0), 3_000))
                elif action == "assert_text":
                    expected = str(step.get("text") or "")
                    actual = page.locator(str(step.get("selector") or "body")).inner_text(timeout=8_000)
                    if expected not in actual:
                        raise AssertionError("approved browser text assertion did not match")
                    evidence.append({"evidence_id": str(uuid4()), "type": "browser", "request_id": request_id, "confirmed": True, "facts": "Approved browser text assertion matched.", "complete": True})
                shot = artifact_root / f"step-{index:02d}.png"
                page.screenshot(path=str(shot), full_page=True)
                evidence.append(_artifact(shot, "screenshot", request_id, f"Browser step {index} screenshot captured at approved origin."))
            for context, _ in sessions.values():
                context.close()
            browser.close()
        for har in artifact_root.glob("network-*.har"):
            _redact_har(har)
            evidence.append(_artifact(har, "har", request_ids[-1] if request_ids else "", "Same-origin browser HAR captured and indexed."))
        if console:
            console_path = artifact_root / "console.json"
            console_path.write_text(json.dumps(console[:200], ensure_ascii=False), encoding="utf-8")
            evidence.append(_artifact(console_path, "console", request_ids[-1] if request_ids else "", "Redacted browser console messages captured."))
        if any(step.get("kind") == "browser_action" for step in steps):
            evidence.append({"evidence_id": str(uuid4()), "type": "coverage", "request_id": request_ids[-1] if request_ids else "", "confirmed": False, "facts": "All approved browser steps completed.", "complete": True, "probe_count": len(steps), "duration_ms": round((time.perf_counter() - started) * 1000, 2)})
        signal = "exploitable" if "exploitable" in verdict_signals else "not_exploitable" if verdict_signals and all(item == "not_exploitable" for item in verdict_signals) else "uncertain"
        reason = " ".join(item for item in verdict_reasons if item) or "浏览器步骤与同源取证已完成；是否可利用仍由 DAST 依据明确断言和证据规则裁决。"
        return {"status": "completed", "evidence": evidence, "verdict_signal": signal, "verdict_reason": reason}
    except Exception as exc:  # bounded executor must return a structured failure
        return {"status": "failed", "error": _redact_text(exc)[:1000], "evidence": evidence, "verdict_signal": "uncertain"}


def main() -> int:
    try:
        contract = json.load(sys.stdin)
        result = execute(contract if isinstance(contract, dict) else {})
    except Exception as exc:
        result = {"status": "failed", "error": _redact_text(exc)[:1000], "evidence": []}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("status") == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
