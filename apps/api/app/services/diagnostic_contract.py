from __future__ import annotations

from datetime import datetime, timezone
import os


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: object) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def bounded_positive_int(name: str, default: int, minimum: int = 1, maximum: int = 8760) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return max(minimum, min(value, maximum))


def freshness(
    observed_at: object,
    *,
    max_age_hours: int,
    now: datetime | None = None,
) -> dict[str, object]:
    parsed = parse_timestamp(observed_at)
    if parsed is None:
        return {
            "status": "unknown",
            "observed_at": None,
            "age_hours": None,
            "max_age_hours": max_age_hours,
            "detail": "没有可解析的更新时间，不能证明数据仍在时效范围内。",
        }
    age_hours = max(0.0, ((now or utc_now()) - parsed).total_seconds() / 3600)
    status = "current" if age_hours <= max_age_hours else "stale"
    return {
        "status": status,
        "observed_at": parsed.isoformat(),
        "age_hours": round(age_hours, 2),
        "max_age_hours": max_age_hours,
        "detail": (
            f"数据年龄 {age_hours:.1f} 小时，处于 {max_age_hours} 小时时效范围内。"
            if status == "current"
            else f"数据年龄 {age_hours:.1f} 小时，超过 {max_age_hours} 小时时效上限。"
        ),
    }
