"""DeepSeek-assisted, non-executing DAST business-flow draft generation."""
from __future__ import annotations

import json
import os
from urllib.parse import urlparse

from app.services.deepseek_client import DeepSeekClient, DeepSeekSettings, DeepSeekUnavailable, bounded_int, environment_bool


def dast_deepseek_settings() -> DeepSeekSettings:
    base_url = os.getenv("DAST_DEEPSEEK_BASE_URL", "https://api.deepseek.com").strip().rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
        raise DeepSeekUnavailable("DAST_DEEPSEEK_BASE_URL 必须是没有查询参数的 HTTPS 地址")
    model = os.getenv("DAST_DEEPSEEK_MODEL", "deepseek-v4-flash").strip() or "deepseek-v4-flash"
    return DeepSeekSettings(
        api_key=os.getenv("DAST_DEEPSEEK_API_KEY", "").strip(), base_url=base_url, model=model, review_model=model,
        timeout_seconds=bounded_int(os.getenv("DAST_DEEPSEEK_TIMEOUT_SECONDS"), 60, 10, 180),
        max_retries=bounded_int(os.getenv("DAST_DEEPSEEK_MAX_RETRIES"), 1, 0, 3),
        thinking_enabled=environment_bool(os.getenv("DAST_DEEPSEEK_THINKING_ENABLED"), False),
    )


def dast_deepseek_health() -> dict[str, object]:
    try:
        settings = dast_deepseek_settings()
    except DeepSeekUnavailable as exc:
        return {"configured": False, "provider": "deepseek", "status": "invalid_configuration", "detail": str(exc)}
    parsed = urlparse(settings.base_url)
    return {
        "configured": settings.configured, "provider": "deepseek",
        "status": "configured" if settings.configured else "missing_api_key",
        "base_url": f"{parsed.scheme}://{parsed.netloc}", "model": settings.model,
        "api_key_location": "apps/api/.env (DAST_DEEPSEEK_API_KEY)",
        "data_boundary": "Only caller-provided, redacted domain/path/API/business descriptions are sent. Credentials, cookies, tokens, raw responses, screenshots, and personal data are excluded.",
    }


def generate_business_flow_draft(candidate: dict[str, object], business_description: str, target_description: str) -> dict[str, object]:
    settings = dast_deepseek_settings()
    if not settings.configured:
        raise DeepSeekUnavailable("未配置 DAST_DEEPSEEK_API_KEY")
    system = (
        "You create a non-executing, security-reviewed business-flow verification draft. "
        "Return strict JSON only. Never include passwords, tokens, cookies, destructive operations, file uploads, payment, email, deletion, or modifications to real business data. "
        "Use only generic role aliases and env: credential references. Do not claim exploitability."
    )
    user = json.dumps({
        "candidate": candidate,
        "allowed_target_description": target_description,
        "business_description": business_description,
        "required_schema": {
            "name": "string", "flow_mode": "api|browser|hybrid", "roles": [{"alias": "string", "credential_ref": "env:NAME", "description": "string"}],
            "steps": [{"id": "string", "kind": "http_request|login|extract|assert|switch_identity|browser_action", "role": "string"}],
            "sufficiency_criteria": {"required_assertions": ["string"], "notes": "string"}, "safety_notes": ["string"], "missing_information": ["string"],
        },
    }, ensure_ascii=False)
    result = DeepSeekClient(settings=settings, user_agent="ai-security-platform/dast-draft").complete_json(
        role="dast_business_flow_drafter", system_prompt=system, user_prompt=user, max_tokens=2800,
        required_keys=("name", "flow_mode", "roles", "steps", "sufficiency_criteria", "safety_notes", "missing_information"),
    )
    return {"draft": result.content, "model": result.model, "latency_ms": result.latency_ms, "prompt_tokens": result.prompt_tokens, "completion_tokens": result.completion_tokens}
