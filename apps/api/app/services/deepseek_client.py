from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import time
from typing import Callable
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from dotenv import load_dotenv


API_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(API_ROOT / ".env", override=False)


class DeepSeekUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class DeepSeekSettings:
    api_key: str
    base_url: str
    model: str
    review_model: str
    timeout_seconds: int
    max_retries: int
    thinking_enabled: bool = False

    @classmethod
    def from_env(cls) -> "DeepSeekSettings":
        base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").strip().rstrip("/")
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            raise DeepSeekUnavailable("DEEPSEEK_BASE_URL 必须是没有查询参数的 HTTPS 地址")
        model = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash").strip() or "deepseek-v4-flash"
        review_model = os.getenv("DEEPSEEK_REVIEW_MODEL", "").strip() or model
        return cls(
            api_key=os.getenv("DEEPSEEK_API_KEY", "").strip(),
            base_url=base_url,
            model=model,
            review_model=review_model,
            timeout_seconds=bounded_int(os.getenv("DEEPSEEK_TIMEOUT_SECONDS"), 90, 10, 300),
            max_retries=bounded_int(os.getenv("DEEPSEEK_MAX_RETRIES"), 2, 0, 5),
            thinking_enabled=environment_bool(os.getenv("DEEPSEEK_THINKING_ENABLED"), False),
        )

    @property
    def configured(self) -> bool:
        return bool(self.api_key)


@dataclass(frozen=True)
class DeepSeekCallResult:
    content: dict[str, object]
    model: str
    prompt_tokens: int
    completion_tokens: int
    cache_hit_tokens: int
    latency_ms: int
    finish_reason: str


class DeepSeekClient:
    def __init__(
        self,
        settings: DeepSeekSettings | None = None,
        opener: Callable[..., object] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        user_agent: str = "ai-security-platform/1.0",
    ) -> None:
        self.settings = settings or DeepSeekSettings.from_env()
        self._opener = opener or urlopen
        self._sleep = sleep
        self._user_agent = user_agent[:160] or "ai-security-platform/1.0"

    def complete_json(
        self,
        *,
        role: str,
        system_prompt: str,
        user_prompt: str,
        review: bool = False,
        max_tokens: int = 2200,
        required_keys: tuple[str, ...] = (),
        max_retries: int | None = None,
        thinking_enabled: bool | None = None,
    ) -> DeepSeekCallResult:
        if not self.settings.configured:
            raise DeepSeekUnavailable("未配置 DEEPSEEK_API_KEY")
        model = self.settings.review_model if review else self.settings.model
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.0,
            "max_tokens": max(256, min(max_tokens, 8000)),
            "stream": False,
            "thinking": {"type": "enabled" if (self.settings.thinking_enabled if thinking_enabled is None else thinking_enabled) else "disabled"},
        }
        last_error = "DeepSeek 请求失败"
        retries = self.settings.max_retries if max_retries is None else max(0, min(int(max_retries), 5))
        for attempt in range(retries + 1):
            attempt_payload = dict(payload)
            if attempt:
                attempt_payload["max_tokens"] = min(8000, int(payload["max_tokens"]) * (attempt + 1))
                attempt_payload["messages"] = [
                    payload["messages"][0],
                    {
                        "role": "user",
                        "content": (
                            f"{user_prompt}\n\n这是第 {attempt + 1} 次结构化输出尝试。"
                            "请缩短说明，立即返回完整、非空、可由标准 JSON 解析器读取的 JSON 对象；不要输出 Markdown。"
                        ),
                    },
                ]
            body = json.dumps(attempt_payload, ensure_ascii=False).encode("utf-8")
            started = time.perf_counter()
            request = Request(
                f"{self.settings.base_url}/chat/completions",
                data=body,
                headers={
                    "Authorization": f"Bearer {self.settings.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": self._user_agent,
                },
                method="POST",
            )
            try:
                response = self._opener(request, timeout=self.settings.timeout_seconds)
                raw = response.read().decode("utf-8", errors="replace")
                status = int(getattr(response, "status", 200))
                if status >= 400:
                    raise DeepSeekUnavailable(f"DeepSeek HTTP {status}")
                result = parse_chat_completion(raw, int((time.perf_counter() - started) * 1000))
                if not result.content:
                    raise DeepSeekUnavailable("DeepSeek 返回了空 JSON 内容")
                missing = [key for key in required_keys if key not in result.content]
                if missing:
                    raise DeepSeekUnavailable("DeepSeek JSON 缺少必需字段：" + ", ".join(missing))
                return result
            except HTTPError as exc:
                last_error = readable_http_error(exc)
                retryable = exc.code == 429 or exc.code >= 500
            except (URLError, TimeoutError, OSError) as exc:
                last_error = f"DeepSeek 网络错误：{safe_error(exc)}"
                retryable = True
            except (json.JSONDecodeError, KeyError, TypeError, ValueError, DeepSeekUnavailable) as exc:
                last_error = safe_error(exc)
                retryable = True
            if attempt >= retries or not retryable:
                break
            self._sleep(min(0.5 * (2 ** attempt), 4.0))
        raise DeepSeekUnavailable(last_error)


def parse_chat_completion(raw: str, latency_ms: int) -> DeepSeekCallResult:
    payload = json.loads(raw)
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise DeepSeekUnavailable("DeepSeek 响应缺少 choices")
    choice = choices[0]
    message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
    content_text = str(message.get("content") or "").strip()
    if not content_text:
        raise DeepSeekUnavailable("DeepSeek 返回了空内容")
    if str(choice.get("finish_reason") or "").lower() in {"length", "max_tokens"}:
        raise DeepSeekUnavailable("DeepSeek JSON 因输出长度限制被截断")
    # JSON mode responses can still contain an unescaped control character in a
    # generated string (most often a newline in a patch draft).  The outer API
    # envelope is valid JSON, so accepting those characters here is safe and
    # avoids discarding an otherwise structured response.
    content = parse_json_object(strip_code_fence(content_text))
    if not isinstance(content, dict):
        raise DeepSeekUnavailable("DeepSeek JSON 输出必须是对象")
    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
    details = usage.get("prompt_tokens_details") if isinstance(usage.get("prompt_tokens_details"), dict) else {}
    return DeepSeekCallResult(
        content=content,
        model=str(payload.get("model") or "unknown"),
        prompt_tokens=safe_int(usage.get("prompt_tokens")),
        completion_tokens=safe_int(usage.get("completion_tokens")),
        cache_hit_tokens=safe_int(usage.get("prompt_cache_hit_tokens") or details.get("cached_tokens")),
        latency_ms=latency_ms,
        finish_reason=str(choice.get("finish_reason") or "unknown"),
    )


def deepseek_health() -> dict[str, object]:
    try:
        settings = DeepSeekSettings.from_env()
    except DeepSeekUnavailable as exc:
        return {"configured": False, "provider": "deepseek", "status": "invalid_configuration", "detail": str(exc)}
    parsed = urlparse(settings.base_url)
    return {
        "configured": settings.configured,
        "provider": "deepseek",
        "status": "configured" if settings.configured else "missing_api_key",
        "base_url": f"{parsed.scheme}://{parsed.netloc}",
        "model": settings.model,
        "review_model": settings.review_model,
        "thinking_enabled": settings.thinking_enabled,
        "timeout_seconds": settings.timeout_seconds,
        "max_retries": settings.max_retries,
        "api_key_location": str(API_ROOT / ".env"),
    }


def estimate_cost_usd(model: str, prompt_tokens: int, completion_tokens: int, cache_hit_tokens: int = 0) -> float | None:
    prices = {
        "deepseek-v4-flash": (0.14, 0.0028, 0.28),
        "deepseek-v4-pro": (0.435, 0.003625, 0.87),
    }
    if model not in prices:
        return None
    input_miss, input_hit, output = prices[model]
    hit = max(0, min(cache_hit_tokens, prompt_tokens))
    miss = max(0, prompt_tokens - hit)
    return round((miss * input_miss + hit * input_hit + completion_tokens * output) / 1_000_000, 8)


def strip_code_fence(value: str) -> str:
    text = value.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return text


def parse_json_object(value: str) -> dict[str, object]:
    """Parse a complete object while tolerating harmless model formatting.

    We may remove a code fence, surrounding prose and trailing commas, but we
    never synthesize missing quotes/braces from a truncated response.
    """
    candidates = [value.strip()]
    start = value.find("{")
    end = value.rfind("}")
    if start >= 0 and end > start:
        candidates.append(value[start : end + 1].strip())
    last_error: json.JSONDecodeError | None = None
    for candidate in dict.fromkeys(candidates):
        for normalized in (candidate, re.sub(r",\s*([}\]])", r"\1", candidate)):
            try:
                parsed = json.loads(normalized, strict=False)
            except json.JSONDecodeError as exc:
                last_error = exc
                continue
            if isinstance(parsed, dict):
                return parsed
            raise DeepSeekUnavailable("DeepSeek JSON 输出必须是对象")
    if last_error is not None:
        raise last_error
    raise DeepSeekUnavailable("DeepSeek 返回的内容不包含完整 JSON 对象")


def readable_http_error(exc: HTTPError) -> str:
    detail = ""
    try:
        payload = json.loads(exc.read().decode("utf-8", errors="replace"))
        error = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(error, dict):
            detail = str(error.get("message") or error.get("type") or "")
    except Exception:
        detail = ""
    suffix = f"：{detail[:300]}" if detail else ""
    return f"DeepSeek HTTP {exc.code}{suffix}"


def safe_error(exc: object) -> str:
    text = str(exc).replace("\r", " ").replace("\n", " ").strip()
    return text[:500] or type(exc).__name__


def safe_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value) if value not in {None, ""} else default
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def environment_bool(value: object, default: bool) -> bool:
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default
