from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from functools import lru_cache

from app.models import Severity


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "go": "Go",
}


@dataclass(frozen=True)
class OsvVulnerability:
    vulnerability_id: str
    severity: Severity
    summary: str


class OsvLookupError(RuntimeError):
    pass


def query_osv(ecosystem: str, name: str, version: str | None, timeout_seconds: int = 8) -> list[OsvVulnerability]:
    osv_ecosystem = OSV_ECOSYSTEMS.get(ecosystem)
    normalized_version = normalize_version(version)
    if not osv_ecosystem or not name or not normalized_version:
        return []
    return _cached_query(osv_ecosystem, name, normalized_version, timeout_seconds)


def supports_osv(ecosystem: str) -> bool:
    return ecosystem in OSV_ECOSYSTEMS


@lru_cache(maxsize=512)
def _cached_query(osv_ecosystem: str, name: str, version: str, timeout_seconds: int) -> list[OsvVulnerability]:
    payload = json.dumps(
        {
            "package": {
                "name": name,
                "ecosystem": osv_ecosystem,
            },
            "version": version,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        OSV_QUERY_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "ai-security-platform-sca/0.1"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise OsvLookupError(str(exc)) from exc

    vulnerabilities: list[OsvVulnerability] = []
    for item in data.get("vulns", []):
        if not isinstance(item, dict):
            continue
        vulnerability_id = str(item.get("id") or "").strip()
        if not vulnerability_id:
            continue
        vulnerabilities.append(
            OsvVulnerability(
                vulnerability_id=vulnerability_id,
                severity=extract_severity(item),
                summary=str(item.get("summary") or item.get("details") or "OSV vulnerability matched")[:500],
            )
        )
    return vulnerabilities


def normalize_version(version: str | None) -> str | None:
    if not version:
        return None
    match = re.search(r"\d+(?:\.\d+){0,4}(?:[-+][A-Za-z0-9_.-]+)?", version)
    return match.group(0) if match else None


def extract_severity(vulnerability: dict) -> Severity:
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict):
        severity = str(database_specific.get("severity") or "").lower()
        mapped = map_severity_label(severity)
        if mapped:
            return mapped

    severities = vulnerability.get("severity")
    if isinstance(severities, list):
        for item in severities:
            if not isinstance(item, dict):
                continue
            score = str(item.get("score") or "")
            mapped = severity_from_cvss(score)
            if mapped:
                return mapped
    return Severity.medium


def map_severity_label(label: str) -> Severity | None:
    if "critical" in label:
        return Severity.critical
    if "high" in label:
        return Severity.high
    if "moderate" in label or "medium" in label:
        return Severity.medium
    if "low" in label:
        return Severity.low
    return None


def severity_from_cvss(score: str) -> Severity | None:
    match = re.search(r"CVSS:\d\.\d/.*", score)
    if not match:
        return None
    metrics = dict(part.split(":", 1) for part in match.group(0).split("/")[1:] if ":" in part)
    if metrics.get("AV") == "N" and metrics.get("PR") == "N" and metrics.get("UI") == "N":
        return Severity.critical
    if metrics.get("AV") == "N":
        return Severity.high
    return Severity.medium
