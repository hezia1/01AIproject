from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from time import perf_counter
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse
from urllib.request import HTTPCookieProcessor, Request, build_opener
from uuid import uuid4
import json
import os
import re


API_PATTERN = re.compile(r"(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*['\"]([^'\"]+)", re.IGNORECASE)


@dataclass
class PageAssets:
    links: list[str] = field(default_factory=list)
    forms: list[dict[str, object]] = field(default_factory=list)
    api_paths: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)


class AssetParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.assets = PageAssets()
        self._form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "a" and values.get("href"):
            self.assets.links.append(urljoin(self.base_url, values["href"]))
        elif tag.lower() == "script" and values.get("src"):
            self.assets.scripts.append(urljoin(self.base_url, values["src"]))
        elif tag.lower() == "form":
            self._form = {
                "action": urljoin(self.base_url, values.get("action") or self.base_url),
                "method": (values.get("method") or "GET").upper(),
                "parameters": [],
            }
            self.assets.forms.append(self._form)
        elif tag.lower() in {"input", "select", "textarea", "button"} and self._form is not None and values.get("name"):
            parameters = self._form["parameters"] if isinstance(self._form.get("parameters"), list) else []
            parameters.append({"name": values["name"], "location": "body" if self._form.get("method") != "GET" else "query", "type": values.get("type") or tag.lower()})
            self._form["parameters"] = parameters

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        self.assets.api_paths.extend(API_PATTERN.findall(data))


def discover_assets(target_url: str, *, max_pages: int = 12, timeout_seconds: int = 8, credential_ref: str | None = None, allowed_paths: list[str] | None = None) -> dict[str, object]:
    task_id = str(uuid4())
    target_origin = _origin(target_url)
    if target_origin is None:
        raise ValueError("target_url must be a valid HTTP or HTTPS URL")
    opener = build_opener(HTTPCookieProcessor(CookieJar()))
    request_headers = _credential_headers(credential_ref)
    queue: deque[str] = deque([_canonical(target_url)])
    for common_spec in ("/openapi.json", "/swagger.json", "/api/openapi.json"):
        candidate = _canonical(urljoin(target_url, common_spec))
        if _path_allowed(urlparse(candidate).path, allowed_paths or []):
            queue.append(candidate)
    visited: set[str] = set()
    forms: list[dict[str, object]] = []
    api_urls: list[str] = []
    request_logs: list[dict[str, object]] = []
    parameters: list[dict[str, object]] = []
    environment: dict[str, object] = {}
    errors: list[str] = []
    while queue and len(visited) < max(1, min(max_pages, 30)):
        url = queue.popleft()
        if url in visited or _origin(url) != target_origin or not _path_allowed(urlparse(url).path, allowed_paths or []):
            continue
        visited.add(url)
        request_id = str(uuid4())
        started = perf_counter()
        try:
            response = opener.open(Request(url, headers={"User-Agent": "ai-security-platform/dast-discovery", **request_headers}, method="GET"), timeout=max(1, min(timeout_seconds, 20)))
            raw = response.read(512_000)
            status = int(getattr(response, "status", 200))
            content_type = str(response.headers.get("Content-Type") or "")
            headers = {str(key): str(value) for key, value in response.headers.items()}
            if not environment:
                environment = _environment(headers)
            request_logs.append({"request_id": request_id, "method": "GET", "url": url, "status_code": status, "duration_ms": round((perf_counter() - started) * 1000), "response_bytes": len(raw)})
            for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
                parameters.append({"name": key, "location": "query", "source_url": url})
            if "html" not in content_type.lower():
                decoded = raw.decode("utf-8", errors="replace")
                if "json" in content_type.lower() or urlparse(url).path.endswith(".json"):
                    api_urls.append(url)
                    try:
                        document = json.loads(decoded)
                    except json.JSONDecodeError:
                        document = None
                    if isinstance(document, dict) and isinstance(document.get("paths"), dict):
                        for path, operations in document["paths"].items():
                            api_url = urljoin(target_url, str(path))
                            if _origin(api_url) == target_origin and _path_allowed(urlparse(api_url).path, allowed_paths or []):
                                api_urls.append(api_url)
                                if isinstance(operations, dict):
                                    for operation in operations.values():
                                        if not isinstance(operation, dict):
                                            continue
                                        for parameter in operation.get("parameters", []) if isinstance(operation.get("parameters"), list) else []:
                                            if isinstance(parameter, dict) and parameter.get("name"):
                                                parameters.append({"name": str(parameter["name"]), "location": str(parameter.get("in") or "unknown"), "source_url": api_url})
                elif "javascript" in content_type.lower() or urlparse(url).path.endswith((".js", ".mjs")):
                    for path in API_PATTERN.findall(decoded):
                        candidate = urljoin(url, path)
                        if _origin(candidate) == target_origin and _path_allowed(urlparse(candidate).path, allowed_paths or []):
                            api_urls.append(candidate)
                continue
            parser = AssetParser(url)
            parser.feed(raw.decode("utf-8", errors="replace"))
            for link in parser.assets.links:
                canonical = _canonical(link)
                if _origin(canonical) == target_origin and _path_allowed(urlparse(canonical).path, allowed_paths or []) and canonical not in visited:
                    queue.append(canonical)
            for script in parser.assets.scripts:
                canonical = _canonical(script)
                if _origin(canonical) == target_origin and _path_allowed(urlparse(canonical).path, allowed_paths or []) and canonical not in visited:
                    queue.append(canonical)
            for form in parser.assets.forms:
                if _origin(str(form.get("action") or "")) == target_origin:
                    forms.append({**form, "source_url": url, "form_id": str(uuid4())})
                    for item in form.get("parameters") if isinstance(form.get("parameters"), list) else []:
                        parameters.append({**item, "source_url": str(form.get("action"))})
            for path in parser.assets.api_paths:
                candidate = urljoin(url, path)
                if _origin(candidate) == target_origin:
                    api_urls.append(candidate)
        except HTTPError as exc:
            request_logs.append({"request_id": request_id, "method": "GET", "url": url, "status_code": int(exc.code), "duration_ms": round((perf_counter() - started) * 1000), "response_bytes": 0})
        except (URLError, TimeoutError, OSError) as exc:
            errors.append(f"{url}: {type(exc).__name__}")
            request_logs.append({"request_id": request_id, "method": "GET", "url": url, "status": "failed", "duration_ms": round((perf_counter() - started) * 1000), "response_bytes": 0})
    return {
        "task_id": task_id,
        "status": "completed" if visited else "failed",
        "target_url": target_url,
        "urls": sorted(visited),
        "forms": _dedupe_dicts(forms, ("action", "method")),
        "api_urls": sorted(set(api_urls)),
        "parameters": _dedupe_dicts(parameters, ("name", "location", "source_url")),
        "request_logs": request_logs,
        "environment": environment,
        "errors": errors,
        "scope": {"same_origin_only": True, "allowed_paths": allowed_paths or [], "max_pages": max(1, min(max_pages, 30)), "methods": ["GET"], "deduplicated": True, "authenticated_session": bool(credential_ref)},
    }


def _origin(value: str) -> tuple[str, str, int] | None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        return None
    return parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)


def _canonical(value: str) -> str:
    parsed = urlparse(value)
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", parsed.query, ""))


def _environment(headers: dict[str, str]) -> dict[str, object]:
    lowered = {key.lower(): value for key, value in headers.items()}
    waf_markers = " ".join(f"{key}:{value}" for key, value in lowered.items()).lower()
    waf = next((name for name in ("cloudflare", "akamai", "imperva", "sucuri", "aws") if name in waf_markers), None)
    return {
        "server": lowered.get("server"),
        "powered_by": lowered.get("x-powered-by"),
        "waf_hint": waf,
        "security_headers": [name for name in ("content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options") if name in lowered],
    }


def _dedupe_dicts(values: list[dict[str, object]], keys: tuple[str, ...]) -> list[dict[str, object]]:
    seen: set[tuple[str, ...]] = set()
    result: list[dict[str, object]] = []
    for value in values:
        marker = tuple(str(value.get(key) or "") for key in keys)
        if marker not in seen:
            seen.add(marker)
            result.append(value)
    return result


def _path_allowed(path: str, allowed_paths: list[str]) -> bool:
    if not allowed_paths:
        return True
    normalized = path or "/"
    return any(normalized == item or normalized.startswith(item.rstrip("/") + "/") for item in allowed_paths if item.startswith("/"))


def _credential_headers(credential_ref: str | None) -> dict[str, str]:
    if not credential_ref:
        return {}
    if not credential_ref.startswith("env:"):
        raise ValueError("credential_ref must use an env: reference")
    value = os.getenv(credential_ref[4:], "")
    if not value:
        raise ValueError("the referenced DAST discovery credential is not configured")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {"Authorization": f"Bearer {value}"}
    if not isinstance(parsed, dict):
        raise ValueError("the referenced DAST credential must be a token or JSON object")
    headers = parsed.get("headers") if isinstance(parsed.get("headers"), dict) else {}
    result = {str(key): str(item) for key, item in headers.items()}
    if parsed.get("token") and "Authorization" not in result:
        result["Authorization"] = f"Bearer {parsed['token']}"
    if parsed.get("cookie") and "Cookie" not in result:
        result["Cookie"] = str(parsed["cookie"])
    return result
