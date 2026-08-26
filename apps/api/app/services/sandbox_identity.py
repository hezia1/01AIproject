"""Project-scoped, ephemeral test identities for DAST/SANDBOX execution.

The vault deliberately keeps credential values in process memory.  API models,
database records and logs only receive the redacted readiness summary.  Docker
targets may be bootstrapped through conventional HTML registration forms;
external/production targets are never mutated automatically.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from html.parser import HTMLParser
from http.cookiejar import CookieJar
import json
import os
import re
from secrets import token_hex
from threading import RLock
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, Request, build_opener


AUTO_REF_PREFIX = "sandbox:auto:"
ROLE_ENV_FALLBACKS = {
    "authenticated_user": "DAST_FLOW_AUTHENTICATED_USER",
    "resource_owner": "DAST_FLOW_USER_A",
    "peer_user": "DAST_FLOW_USER_B",
    "reset_test_account": "DAST_FLOW_RESET_TEST_ACCOUNT",
}


@dataclass
class Form:
    action: str = ""
    method: str = "GET"
    inputs: dict[str, tuple[str, str]] = field(default_factory=dict)


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[Form] = []
        self._current: Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "form":
            self._current = Form(action=values.get("action", ""), method=values.get("method", "GET").upper())
            self.forms.append(self._current)
        elif tag.lower() == "input" and self._current is not None and values.get("name"):
            self._current.inputs[values["name"]] = (values.get("type", "text").lower(), values.get("value", ""))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current = None


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


_lock = RLock()
_vault: dict[str, dict[str, dict[str, object]]] = {}
_target_projects: dict[str, str] = {}


def automatic_ref(alias: str) -> str:
    return AUTO_REF_PREFIX + alias


def _parse_env_value(value: str) -> dict[str, object]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {"token": value}
    return parsed if isinstance(parsed, dict) else {"token": value}


def resolve_credential(project_id: object, ref_or_alias: str) -> dict[str, object] | None:
    project_key = str(project_id or "")
    alias = ref_or_alias[len(AUTO_REF_PREFIX):] if ref_or_alias.startswith(AUTO_REF_PREFIX) else ref_or_alias
    with _lock:
        value = (_vault.get(project_key) or {}).get(alias)
        if value:
            return dict(value)
    env_name = ROLE_ENV_FALLBACKS.get(alias)
    env_value = os.getenv(env_name or "") if env_name else None
    return _parse_env_value(env_value) if env_value else None


def roles_ready(project_id: object, aliases: list[str]) -> bool:
    return all(resolve_credential(project_id, alias) for alias in aliases)


def forget_target(target_id: object) -> None:
    target_key = str(target_id)
    with _lock:
        project_key = _target_projects.pop(target_key, None)
        if project_key and project_key not in _target_projects.values():
            _vault.pop(project_key, None)


def identity_summary(project_id: object) -> dict[str, object]:
    project_key = str(project_id)
    with _lock:
        roles = sorted((_vault.get(project_key) or {}).keys())
    return {
        "status": "ready" if roles else "not_initialized",
        "roles": roles,
        "role_count": len(roles),
        "secret_values_exposed": False,
    }


def _read_forms(opener: Any, url: str) -> list[Form]:
    try:
        response = opener.open(Request(url, headers={"User-Agent": "AI-Security-Sandbox/1.0"}), timeout=5)
        content_type = str(response.headers.get("Content-Type") or "")
        if "html" not in content_type.lower():
            return []
        body = response.read(512_000).decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        return []
    parser = FormParser()
    parser.feed(body)
    for form in parser.forms:
        form.action = urljoin(url, form.action or url)
    return parser.forms


def _registration_form(opener: Any, base_url: str) -> Form | None:
    candidates = ("/register", "/signup", "/users/register", "/auth/register", "/api/register")
    for path in candidates:
        forms = _read_forms(opener, urljoin(base_url.rstrip("/") + "/", path.lstrip("/")))
        for form in forms:
            names = {name.lower() for name in form.inputs}
            has_password = any("password" in name or name in {"passwd", "pwd"} for name in names)
            has_identity = any(name in names for name in {"username", "login", "email", "user", "name"})
            if form.method == "POST" and has_password and has_identity:
                return form
    return None


def _field_value(name: str, input_type: str, current: str, identity: dict[str, str]) -> str:
    lowered = name.lower()
    if input_type == "hidden":
        return current
    if lowered in {"username", "login", "user", "userid", "user_name"}:
        return identity["username"]
    if lowered in {"email", "email_address", "mail"} or "email" in lowered:
        return identity["email"]
    if lowered in {"name", "fullname", "full_name", "displayname", "display_name"}:
        return identity["display_name"]
    if "password" in lowered or lowered in {"passwd", "pwd", "cpassword", "password_confirmation", "confirm_password"}:
        return identity["password"]
    return current


def _cookie_header(jar: CookieJar) -> str:
    return "; ".join(f"{cookie.name}={cookie.value}" for cookie in jar)


def _login_form(opener: Any, base_url: str) -> Form | None:
    candidates = ("/login", "/signin", "/users/login", "/auth/login")
    for path in candidates:
        forms = _read_forms(opener, urljoin(base_url.rstrip("/") + "/", path.lstrip("/")))
        for form in forms:
            names = {name.lower() for name in form.inputs}
            has_password = any("password" in name or name in {"passwd", "pwd"} for name in names)
            has_identity = any(name in names for name in {"username", "login", "email", "user", "name"})
            if form.method == "POST" and has_password and has_identity:
                return form
    return None


def _login_identity(base_url: str, identity: dict[str, str]) -> str | None:
    """Obtain a fresh application session without exposing the credentials."""
    jar = CookieJar()
    opener = build_opener(NoRedirect(), HTTPCookieProcessor(jar))
    form = _login_form(opener, base_url)
    if form is None:
        return None
    payload = {
        name: _field_value(name, input_type, current, identity)
        for name, (input_type, current) in form.inputs.items()
        if input_type not in {"submit", "button", "image", "file"}
    }
    request = Request(
        form.action,
        data=urlencode(payload).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "AI-Security-Sandbox/1.0"},
        method="POST",
    )
    try:
        response = opener.open(request, timeout=5)
        response.read(64_000)
    except HTTPError as exc:
        if exc.code >= 400:
            return None
    except (URLError, TimeoutError, OSError, ValueError):
        return None
    return _cookie_header(jar) or None


def _create_identity(base_url: str, sequence: int) -> dict[str, object] | None:
    jar = CookieJar()
    opener = build_opener(NoRedirect(), HTTPCookieProcessor(jar))
    form = _registration_form(opener, base_url)
    if form is None:
        return None
    suffix = token_hex(6)
    identity = {
        "username": f"dast_user_{sequence}_{suffix}",
        "email": f"dast_{sequence}_{suffix}@example.invalid",
        "display_name": f"DAST Test User {sequence}",
        "password": f"Dast!{token_hex(12)}aA1",
    }
    payload = {
        name: _field_value(name, input_type, current, identity)
        for name, (input_type, current) in form.inputs.items()
        if input_type not in {"submit", "button", "image", "file"}
    }
    if not payload or not any(value == identity["password"] for value in payload.values()):
        return None
    request = Request(
        form.action,
        data=urlencode(payload).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "AI-Security-Sandbox/1.0"},
        method="POST",
    )
    try:
        response = opener.open(request, timeout=4)
        response.read(64_000)
    except HTTPError as exc:
        if exc.code >= 500:
            return None
    except (URLError, TimeoutError, OSError, ValueError):
        # Some deliberately vulnerable training apps complete registration and
        # set the session cookie before their redirect/template rendering stalls.
        # The cookie is the authoritative session artifact; do not discard it
        # merely because the post-registration page timed out.
        if not _cookie_header(jar):
            return None
    cookie = _cookie_header(jar)
    if not cookie:
        return None
    # Registration redirects are inconsistent across training applications.
    # Prefer a deliberate login so the stored cookie is known to represent an
    # authenticated session; retain the registration session only when the app
    # has no conventional login adapter.
    return {"cookie": _login_identity(base_url, identity) or cookie, **identity}


def bootstrap_target_identities(target: Any) -> dict[str, object]:
    """Create two disposable users for a healthy Docker target when possible."""
    project_key, target_key = str(target.project_id), str(target.id)
    if str(getattr(target, "mode", "")) != "docker":
        return {
            "status": "manual_secret_required",
            "roles": [],
            "detail": "已上线目标不会被自动注册账号；请由管理员接入项目级密钥引用。",
            "secret_values_exposed": False,
        }
    if str(getattr(target, "status", "")) != "running":
        return {"status": "waiting_target", "roles": [], "detail": "目标健康后再初始化测试身份。", "secret_values_exposed": False}
    with _lock:
        existing = _vault.get(project_key)
        if existing and {"authenticated_user", "resource_owner", "peer_user", "reset_test_account"}.issubset(existing):
            _target_projects[target_key] = project_key
            return {**identity_summary(project_key), "detail": "项目级临时测试身份已就绪并可供 DAST 自动复用。", "source": "sandbox-form-bootstrap"}
    first = _create_identity(str(target.runtime_url), 1)
    second = _create_identity(str(target.runtime_url), 2)
    if not first or not second:
        return {
            "status": "adapter_required",
            "roles": [],
            "role_count": 0,
            "detail": "未能通过常见注册表单安全创建测试身份；项目需要登录适配器或管理员密钥引用。",
            "secret_values_exposed": False,
        }
    with _lock:
        _vault[project_key] = {
            "authenticated_user": dict(first),
            "resource_owner": dict(first),
            "peer_user": dict(second),
            "reset_test_account": dict(first),
        }
        _target_projects[target_key] = project_key
    return {**identity_summary(project_key), "detail": "已自动创建两名一次性测试用户；Cookie/密码仅保存在后端内存，不写入页面、数据库或日志。", "source": "sandbox-form-bootstrap", "initialized_at": datetime.utcnow().isoformat()}
