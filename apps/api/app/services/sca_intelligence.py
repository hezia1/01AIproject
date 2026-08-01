from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Iterable


def intelligence_path() -> Path:
    configured = os.getenv("SCA_INTELLIGENCE_PATH")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[4] / "artifacts" / "sca-offline" / "intelligence.json"


def intelligence_status(path: Path | None = None) -> dict[str, object]:
    target = path or intelligence_path()
    if not target.is_file():
        return {"status": "not_configured", "path": str(target), "advisory_count": 0, "updated_at": None}
    try:
        payload = load_intelligence(target)
    except ValueError as exc:
        return {"status": "invalid", "path": str(target), "advisory_count": 0, "updated_at": None, "detail": str(exc)}
    return {
        "status": "available",
        "path": str(target),
        "advisory_count": len(payload["advisories"]),
        "updated_at": payload.get("updated_at"),
        "sources": payload.get("sources", []),
    }


def import_intelligence_entries(
    entries: Iterable[object],
    source: str | None = None,
    path: Path | None = None,
) -> dict[str, object]:
    target = path or intelligence_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    existing = load_intelligence(target) if target.is_file() else {"advisories": {}, "sources": []}
    advisories = dict(existing["advisories"])
    for item in entries:
        if not isinstance(item, dict):
            continue
        normalized = normalize_advisory(item, source)
        identifier = normalized["id"]
        advisories[identifier] = {**advisories.get(identifier, {}), **normalized}
    if not advisories:
        raise ValueError("intelligence import requires at least one advisory with id or cve")
    sources = list(existing.get("sources", []))
    if source and source not in sources:
        sources.append(source)
    payload = {
        "schema": "ai-security-platform.sca-intelligence/v1",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "sources": sources,
        "advisories": advisories,
    }
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    load_intelligence.cache_clear()
    return intelligence_status(target)


def assess_vulnerability_intelligence(vulnerability_ids: Iterable[str], path: Path | None = None) -> dict[str, object]:
    identifiers = [str(item).strip() for item in vulnerability_ids if str(item).strip()]
    if not identifiers:
        return {"advisories": [], "risk_score": 0, "kev": False, "max_epss": None, "fixed_versions": []}
    try:
        advisories = load_intelligence(path or intelligence_path())["advisories"]
    except ValueError:
        advisories = {}
    matched = [advisories[item] for item in identifiers if item in advisories]
    scores = [risk_score(item) for item in matched]
    fixed_versions = list(dict.fromkeys(str(item["fixed_version"]) for item in matched if item.get("fixed_version")))
    epss_values = [float(item["epss"]) for item in matched if item.get("epss") is not None]
    return {
        "advisories": matched,
        "risk_score": max(scores, default=0),
        "kev": any(bool(item.get("kev")) for item in matched),
        "known_exploited": any(bool(item.get("known_exploited")) for item in matched),
        "max_epss": max(epss_values, default=None),
        "fixed_versions": fixed_versions,
    }


@lru_cache(maxsize=4)
def load_intelligence(path: Path) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"无法读取 SCA 情报镜像：{exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"SCA 情报镜像不是有效 JSON：{exc.msg}") from exc
    records = raw.get("advisories") if isinstance(raw, dict) else raw
    if isinstance(records, dict):
        normalized = {str(key): normalize_advisory({"id": key, **value}) for key, value in records.items() if isinstance(value, dict)}
    elif isinstance(records, list):
        normalized = {item["id"]: item for item in (normalize_advisory(value) for value in records if isinstance(value, dict))}
    else:
        raise ValueError("SCA 情报镜像必须包含 advisories 数组或对象")
    return {
        "advisories": normalized,
        "sources": raw.get("sources", []) if isinstance(raw, dict) else [],
        "updated_at": raw.get("updated_at") if isinstance(raw, dict) else None,
    }


def normalize_advisory(item: dict[str, object], source: str | None = None) -> dict[str, object]:
    identifier = str(item.get("id") or item.get("cve") or item.get("vulnerability_id") or "").strip()
    if not identifier:
        raise ValueError("intelligence advisory requires id or cve")
    cvss = number(item.get("cvss_score", item.get("cvss")), minimum=0, maximum=10)
    epss = number(item.get("epss"), minimum=0, maximum=1)
    references = item.get("references", [])
    return {
        "id": identifier,
        "cvss_score": cvss,
        "cvss_vector": string_or_none(item.get("cvss_vector")),
        "epss": epss,
        "kev": bool(item.get("kev") or item.get("cisa_kev")),
        "known_exploited": bool(item.get("known_exploited") or item.get("exploited")),
        "fixed_version": string_or_none(item.get("fixed_version") or item.get("fixed")),
        "published_at": string_or_none(item.get("published_at")),
        "source": string_or_none(item.get("source")) or source or "manual-import",
        "references": [str(value) for value in references if str(value).strip()] if isinstance(references, list) else [],
    }


def risk_score(advisory: dict[str, object]) -> int:
    cvss = float(advisory.get("cvss_score") or 0)
    epss = float(advisory.get("epss") or 0)
    score = round((cvss / 10 * 65) + (epss * 20) + (15 if advisory.get("kev") else 0) + (5 if advisory.get("known_exploited") else 0))
    return max(0, min(score, 100))


def number(value: object, minimum: float, maximum: float) -> float | None:
    if value is None or value == "":
        return None
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("intelligence score values must be numeric") from exc
    if result < minimum or result > maximum:
        raise ValueError(f"intelligence score must be between {minimum} and {maximum}")
    return result


def string_or_none(value: object) -> str | None:
    result = str(value or "").strip()
    return result or None
