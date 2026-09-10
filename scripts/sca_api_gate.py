"""Authenticate to the platform and enforce one stored SCA gate result."""
from __future__ import annotations

import argparse
from http.cookiejar import CookieJar
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPCookieProcessor, Request, build_opener
from uuid import UUID


ERROR_EXIT = 3


class GateClientError(RuntimeError):
    pass


def validate_base_url(value: str, *, allow_insecure_http: bool = False) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlsplit(normalized)
    allowed_schemes = {"https"} | ({"http"} if allow_insecure_http else set())
    if parsed.scheme not in allowed_schemes or not parsed.hostname or parsed.username or parsed.password:
        expected = "HTTPS" if not allow_insecure_http else "HTTP(S)"
        raise GateClientError(f"SCA_API_BASE must be an absolute {expected} URL without embedded credentials")
    if parsed.query or parsed.fragment:
        raise GateClientError("SCA_API_BASE must not contain a query or fragment")
    return normalized


def validate_uuid(value: str, label: str) -> str:
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise GateClientError(f"{label} must be a UUID") from exc


def request_json(opener, url: str, *, method: str = "GET", payload: dict[str, str] | None = None, timeout: int = 30) -> dict[str, object]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(
        url,
        data=body,
        method=method,
        headers={"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "ai-security-sca-ci/1"},
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
    except HTTPError as exc:
        detail = _safe_error_detail(exc)
        raise GateClientError(f"HTTP {exc.code} from {urlsplit(url).path}: {detail}") from exc
    except URLError as exc:
        raise GateClientError(f"Unable to reach SCA API: {type(exc.reason).__name__}") from exc
    try:
        result = json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        raise GateClientError(f"Invalid JSON from {urlsplit(url).path}") from exc
    if not isinstance(result, dict):
        raise GateClientError(f"Expected a JSON object from {urlsplit(url).path}")
    return result


def run_api_gate(
    base_url: str,
    project_id: str,
    scan_task_id: str,
    username: str,
    password: str,
    *,
    timeout: int = 30,
    allow_insecure_http: bool = False,
) -> tuple[int, dict[str, object]]:
    base = validate_base_url(base_url, allow_insecure_http=allow_insecure_http)
    project = validate_uuid(project_id, "project_id")
    scan = validate_uuid(scan_task_id, "scan_task_id")
    if not username.strip() or not password:
        raise GateClientError("SCA_CI_USERNAME and SCA_CI_PASSWORD are required")
    opener = build_opener(HTTPCookieProcessor(CookieJar()))
    logged_in = False
    try:
        request_json(opener, f"{base}/api/auth/login", method="POST", payload={"username": username, "password": password}, timeout=timeout)
        logged_in = True
        gate = request_json(
            opener,
            f"{base}/api/sca/projects/{quote(project, safe='')}/gate?scan_task_id={quote(scan, safe='')}",
            timeout=timeout,
        )
        decision = gate.get("decision")
        exit_code = gate.get("exit_code")
        scan_status = gate.get("scan_status")
        if decision not in {"pass", "block"} or exit_code not in {0, 2}:
            raise GateClientError("SCA gate returned an invalid decision contract")
        if decision == "pass" and (exit_code != 0 or scan_status != "succeeded" or gate.get("result_complete") is not True):
            raise GateClientError("SCA gate attempted to pass without a complete succeeded scan")
        if decision == "block" and exit_code != 2:
            raise GateClientError("SCA gate returned inconsistent block and exit_code values")
        return int(exit_code), gate
    finally:
        if logged_in:
            try:
                request_json(opener, f"{base}/api/auth/logout", method="POST", timeout=timeout)
            except GateClientError:
                pass


def _safe_error_detail(error: HTTPError) -> str:
    try:
        payload = json.loads(error.read().decode("utf-8"))
        detail = payload.get("detail") if isinstance(payload, dict) else None
        return str(detail)[:300] if detail else "request rejected"
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "request rejected"


def main() -> int:
    parser = argparse.ArgumentParser(description="Authenticated AI Security Platform SCA gate")
    parser.add_argument("--base-url", default=os.getenv("SCA_API_BASE", ""))
    parser.add_argument("--project-id", default=os.getenv("PROJECT_ID", ""))
    parser.add_argument("--scan-task-id", default=os.getenv("SCAN_TASK_ID", ""))
    parser.add_argument("--allow-insecure-http", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        timeout = max(1, min(int(os.getenv("SCA_CI_TIMEOUT_SECONDS", "30")), 120))
        exit_code, gate = run_api_gate(
            args.base_url,
            args.project_id,
            args.scan_task_id,
            os.getenv("SCA_CI_USERNAME", ""),
            os.getenv("SCA_CI_PASSWORD", ""),
            timeout=timeout,
            allow_insecure_http=args.allow_insecure_http,
        )
        print(json.dumps(gate, ensure_ascii=False))
        return exit_code
    except (GateClientError, ValueError) as exc:
        print(json.dumps({"decision": "error", "exit_code": ERROR_EXIT, "detail": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return ERROR_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
