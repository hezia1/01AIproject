from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from app.models import DastVerdict


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]


@dataclass(frozen=True)
class DastProbeResult:
    target_url: str
    verdict: DastVerdict
    evidence_summary: str
    request_summary: str
    response_summary: str
    reproduction_steps: str
    remediation_hint: str


def probe_target_url(target_url: str, timeout_seconds: float = 8.0) -> DastProbeResult:
    parsed_url = urlparse(target_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError("target_url must be a valid http or https URL")

    started_at = time.perf_counter()
    request = Request(
        target_url,
        headers={
            "User-Agent": "AI-Security-Platform-DAST/0.1",
            "Accept": "text/html,application/json,*/*",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            elapsed_ms = int((time.perf_counter() - started_at) * 1000)
            status_code = response.status
            headers = {key: value for key, value in response.headers.items()}
            return build_probe_result(target_url, parsed_url.scheme, status_code, elapsed_ms, headers, None)
    except HTTPError as exc:
        elapsed_ms = int((time.perf_counter() - started_at) * 1000)
        headers = {key: value for key, value in exc.headers.items()} if exc.headers else {}
        return build_probe_result(target_url, parsed_url.scheme, exc.code, elapsed_ms, headers, None)
    except URLError as exc:
        elapsed_ms = int((time.perf_counter() - started_at) * 1000)
        reason = str(exc.reason) if hasattr(exc, "reason") else str(exc)
        return DastProbeResult(
            target_url=target_url,
            verdict=DastVerdict.uncertain,
            evidence_summary=f"目标访问失败，耗时 {elapsed_ms} ms，错误：{reason}",
            request_summary=f"GET {target_url} timeout={timeout_seconds}s",
            response_summary="未获得有效 HTTP 响应。",
            reproduction_steps=f"从平台 DAST 模块对 {target_url} 发起 GET 请求，观察连接失败或超时。",
            remediation_hint="确认目标 URL、网络可达性、DNS、TLS 证书和访问控制策略；如果目标仅内网可达，需要在可访问网络中部署验证节点。",
        )


def build_probe_result(
    target_url: str,
    scheme: str,
    status_code: int,
    elapsed_ms: int,
    headers: dict[str, str],
    error: str | None,
) -> DastProbeResult:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    missing_headers = [header for header in SECURITY_HEADERS if header.lower() not in normalized_headers]
    present_headers = [header for header in SECURITY_HEADERS if header.lower() in normalized_headers]
    server_header = headers.get("Server") or headers.get("server") or "-"
    content_type = headers.get("Content-Type") or headers.get("content-type") or "-"

    risk_points = 0
    if scheme != "https":
        risk_points += 2
    if len(missing_headers) >= 3:
        risk_points += 2
    elif missing_headers:
        risk_points += 1
    if server_header != "-":
        risk_points += 1
    if status_code >= 500:
        risk_points += 1

    if error:
        verdict = DastVerdict.uncertain
    elif risk_points >= 4:
        verdict = DastVerdict.exploitable
    elif risk_points >= 1:
        verdict = DastVerdict.uncertain
    else:
        verdict = DastVerdict.not_exploitable

    evidence_parts = [
        f"状态码 {status_code}",
        f"响应时间 {elapsed_ms} ms",
        f"协议 {scheme.upper()}",
        f"Server={server_header}",
        f"Content-Type={content_type}",
        f"缺失安全头：{', '.join(missing_headers) if missing_headers else '无'}",
    ]
    request_summary = f"GET {target_url} User-Agent=AI-Security-Platform-DAST/0.1"
    response_summary = (
        f"HTTP {status_code}; elapsed={elapsed_ms}ms; present_headers={', '.join(present_headers) or 'none'}; "
        f"missing_headers={', '.join(missing_headers) or 'none'}; server={server_header}; content_type={content_type}"
    )

    remediation = build_remediation(scheme, missing_headers, server_header)
    return DastProbeResult(
        target_url=target_url,
        verdict=verdict,
        evidence_summary="；".join(evidence_parts),
        request_summary=request_summary,
        response_summary=response_summary,
        reproduction_steps=f"访问 {target_url}，记录状态码、响应头和安全头缺失情况，并按三色裁决规则生成结论。",
        remediation_hint=remediation,
    )


def build_remediation(scheme: str, missing_headers: list[str], server_header: str) -> str:
    hints: list[str] = []
    if scheme != "https":
        hints.append("启用 HTTPS，并将 HTTP 请求重定向到 HTTPS。")
    if missing_headers:
        hints.append(f"补充安全响应头：{', '.join(missing_headers)}。")
    if server_header != "-":
        hints.append("减少 Server Header 中的服务指纹暴露。")
    if not hints:
        hints.append("当前基础响应头检查未发现明显问题，建议结合业务认证、授权和输入验证继续测试。")
    return " ".join(hints)
