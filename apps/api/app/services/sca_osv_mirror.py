from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from app.services.osv_client import OsvVulnerability, extract_severity
from app.services.sca_vulnerability_rules import version_matches_range


def osv_mirror_path() -> Path:
    configured = os.getenv("SCA_OSV_MIRROR_PATH")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[4] / "artifacts" / "sca-offline" / "osv-mirror.json"


def osv_mirror_status(path: Path | None = None) -> dict[str, object]:
    target = path or osv_mirror_path()
    if not target.is_file():
        return {"status": "not_configured", "path": str(target), "entry_count": 0, "updated_at": None, "detail": "未找到本地 OSV 镜像；扫描会尝试在线 OSV，再在失败时降级到本地规则。"}
    try:
        payload = load_osv_mirror(target)
    except ValueError as exc:
        return {"status": "invalid", "path": str(target), "entry_count": 0, "updated_at": None, "detail": str(exc)}
    return {
        "status": "available",
        "path": str(target),
        "entry_count": len(payload["entries"]),
        "updated_at": payload.get("updated_at"),
        "detail": f"本地 OSV 镜像包含 {len(payload['entries'])} 条组件版本记录。",
    }


def import_osv_mirror(entries: Iterable[object], source: str | None = None, path: Path | None = None) -> dict[str, object]:
    normalized = [normalize_entry(item) for item in entries if isinstance(item, dict)]
    if not normalized:
        raise ValueError("OSV mirror import requires at least one valid entry")
    target = path or osv_mirror_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "ai-security-platform.osv-mirror/v1",
        "source": source or "manual-import",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "entries": normalized,
    }
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    load_osv_mirror.cache_clear()
    return osv_mirror_status(target)


def lookup_osv_mirror(
    ecosystem: str,
    package: str,
    version: str | None,
    path: Path | None = None,
) -> tuple[list[OsvVulnerability], bool]:
    if not version:
        return [], False
    try:
        payload = load_osv_mirror(path or osv_mirror_path())
    except ValueError:
        return [], False
    matches = [entry for entry in payload["entries"] if entry_matches(entry, ecosystem, package, version)]
    if not matches:
        return [], False
    vulnerabilities: list[OsvVulnerability] = []
    for entry in matches:
        for item in entry["vulnerabilities"]:
            vulnerabilities.append(
                OsvVulnerability(
                    vulnerability_id=str(item["id"]),
                    severity=extract_severity(item),
                    summary=str(item.get("summary") or "本地 OSV 镜像命中漏洞。"),
                )
            )
    unique = {item.vulnerability_id: item for item in vulnerabilities}
    return list(unique.values()), True


@lru_cache(maxsize=4)
def load_osv_mirror(path: Path) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"无法读取本地 OSV 镜像：{exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"本地 OSV 镜像不是有效 JSON：{exc.msg}") from exc
    entries = raw.get("entries") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ValueError("本地 OSV 镜像必须包含 entries 数组")
    return {"entries": [normalize_entry(item) for item in entries if isinstance(item, dict)], "updated_at": raw.get("updated_at") if isinstance(raw, dict) else None}


def normalize_entry(item: dict[str, object]) -> dict[str, object]:
    ecosystem = str(item.get("ecosystem") or "").strip().lower()
    package = str(item.get("package") or item.get("name") or "").strip()
    version = str(item.get("version") or "").strip() or None
    affected = str(item.get("affected") or "").strip() or None
    raw_vulnerabilities = item.get("vulnerabilities") or item.get("vulns") or []
    if not ecosystem or not package or not (version or affected) or not isinstance(raw_vulnerabilities, list):
        raise ValueError("OSV mirror entry requires ecosystem, package, version or affected, and vulnerabilities")
    vulnerabilities = []
    for vulnerability in raw_vulnerabilities:
        if not isinstance(vulnerability, dict) or not str(vulnerability.get("id") or "").strip():
            continue
        vulnerabilities.append(dict(vulnerability))
    return {"ecosystem": ecosystem, "package": package, "version": version, "affected": affected, "vulnerabilities": vulnerabilities}


def entry_matches(entry: dict[str, object], ecosystem: str, package: str, version: str) -> bool:
    if str(entry["ecosystem"]).lower() != ecosystem.lower() or str(entry["package"]).lower() != package.lower():
        return False
    if entry.get("version"):
        return str(entry["version"]) == version
    affected = entry.get("affected")
    return bool(affected and version_matches_range(version, str(affected)))
