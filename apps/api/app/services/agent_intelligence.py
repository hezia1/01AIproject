from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from app.models import Severity
from app.services.agent_scanner import AgentAsset, AgentFinding, AgentProvenance, build_finding
from app.services.osv_client import extract_severity
from app.services.sca_osv_mirror import load_osv_mirror, osv_mirror_path
from app.services.sca_vulnerability_rules import (
    RULES_PATH,
    VulnerabilityRule,
    load_vulnerability_rules,
    matches_vulnerability_rule,
    version_matches_range,
)


@dataclass(frozen=True)
class AgentIntelligenceOutput:
    findings: list[AgentFinding]
    report: dict[str, object]


def agent_threat_intelligence_path() -> Path:
    configured = os.getenv("AGENT_THREAT_INTELLIGENCE_PATH")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[4] / "artifacts" / "agent-offline" / "threat-intelligence.json"


def analyze_agent_intelligence(
    assets: list[AgentAsset],
    *,
    threat_path: Path | None = None,
    mirror_path: Path | None = None,
) -> AgentIntelligenceOutput:
    selected_threat_path = threat_path or agent_threat_intelligence_path()
    selected_mirror_path = mirror_path or osv_mirror_path()
    local_rules = [item for item in load_vulnerability_rules() if item.enabled]
    mirror, mirror_status = load_optional_osv_mirror(selected_mirror_path)
    threat, threat_status = load_optional_threat_intelligence(selected_threat_path)
    sources = {
        "builtin_rules": file_source_status(RULES_PATH, len(local_rules), "available"),
        "osv_mirror": mirror_status,
        "threat_intelligence": threat_status,
    }

    package_results: list[dict[str, object]] = []
    findings: list[AgentFinding] = []
    for asset in assets:
        for provenance in asset.provenance:
            package = package_coordinate(provenance)
            if package is None:
                continue
            result, result_findings = assess_package(
                asset.path,
                provenance,
                package,
                local_rules,
                mirror,
                threat,
            )
            package_results.append(result)
            findings.extend(result_findings)

    vulnerability_count = sum(len(item["vulnerabilities"]) for item in package_results)
    malicious_count = sum(len(item["threats"]) for item in package_results)
    confusion_count = sum(len(item["confusion_signals"]) for item in package_results)
    covered_count = sum(item["lookup_status"] in {"vulnerable", "checked_no_match"} for item in package_results)
    report = {
        "mode": "offline-only",
        "generated_at": utc_now(),
        "sources": sources,
        "summary": {
            "coordinate_count": len(package_results),
            "version_resolved_count": sum(bool(item.get("version_resolved")) for item in package_results),
            "covered_count": covered_count,
            "not_covered_count": sum(item["lookup_status"] == "not_covered" for item in package_results),
            "version_unresolved_count": sum(item["lookup_status"] == "version_unresolved" for item in package_results),
            "unsupported_count": sum(item["lookup_status"] == "unsupported_ecosystem" for item in package_results),
            "vulnerable_package_count": sum(bool(item["vulnerabilities"]) for item in package_results),
            "vulnerability_count": vulnerability_count,
            "malicious_match_count": malicious_count,
            "package_confusion_count": confusion_count,
        },
        "packages": package_results,
        "limitations": [
            "Only bundled local rules and an explicitly configured local OSV mirror are queried; no network request is made.",
            "A checked-no-match result means only that the configured local sources did not match the exact version; it is not proof that the package is vulnerability-free.",
            "Malicious-package and protected-name checks require a local threat-intelligence file; no package is labelled malicious without a matching local record.",
        ],
    }
    return AgentIntelligenceOutput(findings=dedupe_intelligence_findings(findings), report=report)


def package_coordinate(provenance: AgentProvenance) -> dict[str, object] | None:
    name = str(provenance.package_name or "").strip()
    if not name:
        return None
    ecosystem = provenance_ecosystem(provenance)
    version = str(provenance.package_version or "").strip() or None
    resolved = provenance.version_status in {"locked", "tagged"} and bool(version)
    purl = None
    if ecosystem in {"npm", "pypi"}:
        encoded_name = "/".join(quote(part, safe="") for part in name.split("/"))
        purl = f"pkg:{ecosystem}/{encoded_name}{('@' + quote(version, safe='.-+')) if version else ''}"
    return {
        "ecosystem": ecosystem,
        "package_name": name,
        "package_version": version,
        "version_status": provenance.version_status,
        "version_resolved": resolved,
        "purl": purl,
    }


def provenance_ecosystem(provenance: AgentProvenance) -> str:
    source_ref = str(provenance.source_ref or "").lower()
    method = provenance.installation_method.lower()
    if source_ref.startswith("npm:") or method in {"npm", "npx", "pnpm", "pnpx", "yarn", "bunx"}:
        return "npm"
    if source_ref.startswith("pypi:") or method in {"pip", "pipx", "uvx"}:
        return "pypi"
    if provenance.source_type == "container":
        return "oci"
    if provenance.source_type == "git":
        return "git"
    return "unknown"


def assess_package(
    asset_path: str,
    provenance: AgentProvenance,
    package: dict[str, object],
    local_rules: list[VulnerabilityRule],
    mirror: dict[str, object] | None,
    threat: dict[str, object] | None,
) -> tuple[dict[str, object], list[AgentFinding]]:
    ecosystem = str(package["ecosystem"])
    name = str(package["package_name"])
    version = str(package.get("package_version") or "") or None
    version_resolved = bool(package.get("version_resolved"))
    vulnerabilities: list[dict[str, object]] = []
    coverage_sources: list[str] = []
    findings: list[AgentFinding] = []

    applicable_rules = [
        item for item in local_rules
        if item.ecosystem == ecosystem and normalize_package_name(ecosystem, item.package) == normalize_package_name(ecosystem, name)
    ]
    if applicable_rules:
        coverage_sources.append("builtin-local-rules")
    if version_resolved:
        for rule in applicable_rules:
            if matches_vulnerability_rule(ecosystem, name, version, rule):
                vulnerabilities.append(vulnerability_from_rule(rule))

    mirror_entries = mirror.get("entries", []) if isinstance(mirror, dict) else []
    package_mirror_entries = [
        item for item in mirror_entries if isinstance(item, dict)
        and str(item.get("ecosystem") or "").lower() == ecosystem
        and normalize_package_name(ecosystem, str(item.get("package") or "")) == normalize_package_name(ecosystem, name)
    ]
    if package_mirror_entries:
        coverage_sources.append("local-osv-mirror")
    if version_resolved and version:
        for entry in package_mirror_entries:
            if mirror_entry_matches_version(entry, version):
                vulnerabilities.extend(vulnerabilities_from_mirror_entry(entry))

    vulnerabilities = dedupe_vulnerabilities(vulnerabilities)
    threats = match_threat_entries(threat, ecosystem, name, version, version_resolved)
    confusion = match_protected_names(threat, ecosystem, name)
    for vulnerability in vulnerabilities:
        findings.append(vulnerability_finding(asset_path, provenance, package, vulnerability))
    for threat_match in threats:
        findings.append(threat_finding(asset_path, provenance, package, threat_match))
    for confusion_match in confusion:
        findings.append(confusion_finding(asset_path, provenance, package, confusion_match))

    if ecosystem not in {"npm", "pypi"}:
        lookup_status = "unsupported_ecosystem"
    elif not version_resolved:
        lookup_status = "version_unresolved"
    elif vulnerabilities:
        lookup_status = "vulnerable"
    elif coverage_sources:
        lookup_status = "checked_no_match"
    else:
        lookup_status = "not_covered"
    result = {
        "asset_path": asset_path,
        "subject": provenance.subject,
        **package,
        "lookup_status": lookup_status,
        "coverage_sources": coverage_sources,
        "vulnerabilities": vulnerabilities,
        "threats": threats,
        "confusion_signals": confusion,
    }
    return result, findings


def vulnerability_from_rule(rule: VulnerabilityRule) -> dict[str, object]:
    return {
        "id": rule.vulnerability_id,
        "severity": rule.severity.value,
        "summary": rule.summary,
        "affected": rule.affected,
        "fixed_version": rule.fixed_version or None,
        "source": "builtin-local-rules",
        "references": list(rule.references),
    }


def vulnerabilities_from_mirror_entry(entry: dict[str, object]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for raw in entry.get("vulnerabilities", []):
        if not isinstance(raw, dict) or not str(raw.get("id") or "").strip():
            continue
        result.append({
            "id": str(raw["id"]),
            "severity": extract_severity(raw).value,
            "summary": str(raw.get("summary") or raw.get("details") or "Local OSV mirror match")[:500],
            "affected": entry.get("affected") or entry.get("version"),
            "fixed_version": extract_fixed_version(raw),
            "source": "local-osv-mirror",
            "references": extract_references(raw),
        })
    return result


def mirror_entry_matches_version(entry: dict[str, object], version: str) -> bool:
    if entry.get("version"):
        return str(entry["version"]) == version
    affected = str(entry.get("affected") or "")
    return bool(affected and version_matches_range(version, affected))


def extract_fixed_version(item: dict[str, object]) -> str | None:
    database = item.get("database_specific")
    if isinstance(database, dict) and database.get("fixed_version"):
        return str(database["fixed_version"])
    fixed = item.get("fixed_version") or item.get("fixed")
    return str(fixed) if fixed else None


def extract_references(item: dict[str, object]) -> list[str]:
    references = item.get("references")
    if not isinstance(references, list):
        return []
    result: list[str] = []
    for value in references:
        if isinstance(value, dict) and value.get("url"):
            result.append(str(value["url"]))
        elif isinstance(value, str):
            result.append(value)
    return result[:20]


def match_threat_entries(
    threat: dict[str, object] | None,
    ecosystem: str,
    package: str,
    version: str | None,
    version_resolved: bool,
) -> list[dict[str, object]]:
    if not threat:
        return []
    matches: list[dict[str, object]] = []
    for entry in threat.get("entries", []):
        if not isinstance(entry, dict) or not entry.get("enabled", True):
            continue
        if str(entry.get("ecosystem") or "").lower() != ecosystem:
            continue
        if normalize_package_name(ecosystem, str(entry.get("package") or "")) != normalize_package_name(ecosystem, package):
            continue
        affected = str(entry.get("affected") or "").strip()
        if affected and (not version_resolved or not version or not version_matches_range(version, affected)):
            continue
        matches.append({
            "id": str(entry.get("id")),
            "kind": str(entry.get("kind") or "malicious-package"),
            "severity": str(entry.get("severity") or "critical"),
            "summary": str(entry.get("summary") or "Local threat-intelligence match")[:500],
            "affected": affected or None,
            "source": str(entry.get("source") or "local-threat-intelligence"),
            "references": list(entry.get("references") or [])[:20],
        })
    return matches


def match_protected_names(threat: dict[str, object] | None, ecosystem: str, package: str) -> list[dict[str, object]]:
    if not threat:
        return []
    normalized = normalize_package_name(ecosystem, package)
    if len(normalized) < 5:
        return []
    signals: list[dict[str, object]] = []
    for item in threat.get("protected_packages", []):
        if not isinstance(item, dict) or str(item.get("ecosystem") or "").lower() != ecosystem:
            continue
        protected = normalize_package_name(ecosystem, str(item.get("package") or ""))
        if not protected or protected == normalized:
            continue
        distance = edit_distance(normalized, protected, limit=1)
        if distance <= 1:
            signals.append({
                "protected_package": str(item.get("package")),
                "distance": distance,
                "source": str(item.get("source") or "local-threat-intelligence"),
            })
    return signals


def vulnerability_finding(
    asset_path: str,
    provenance: AgentProvenance,
    package: dict[str, object],
    vulnerability: dict[str, object],
) -> AgentFinding:
    del provenance
    severity = severity_value(vulnerability.get("severity"))
    return build_finding(
        "AGENT.INTEL.KNOWN_VULNERABILITY",
        f"Agent dependency matches {vulnerability['id']}",
        severity,
        "agent-vulnerability-intelligence",
        asset_path,
        1,
        f"package={package['package_name']}; version={package.get('package_version') or 'unknown'}; advisory={vulnerability['id']}; source={vulnerability['source']}",
        str(vulnerability.get("summary") or "The exact dependency version matched a configured local advisory."),
        f"Upgrade to {vulnerability.get('fixed_version') or 'a verified fixed version'} and regenerate source and integrity evidence.",
        "Trust is reduced because the declared Agent implementation has a locally matched known vulnerability.",
    )


def threat_finding(
    asset_path: str,
    provenance: AgentProvenance,
    package: dict[str, object],
    threat: dict[str, object],
) -> AgentFinding:
    del provenance
    return build_finding(
        "AGENT.INTEL.MALICIOUS_PACKAGE",
        "Agent dependency matches local malicious-package intelligence",
        severity_value(threat.get("severity"), Severity.critical),
        "agent-threat-intelligence",
        asset_path,
        1,
        f"package={package['package_name']}; version={package.get('package_version') or 'unknown'}; intelligence={threat['id']}",
        str(threat.get("summary") or "The package matched an explicitly configured local threat-intelligence record."),
        "Do not execute the package; verify the intelligence record, isolate affected assets, and replace the dependency from a trusted source.",
        "Trust is critically reduced because local threat intelligence identifies the dependency as malicious or compromised.",
    )


def confusion_finding(
    asset_path: str,
    provenance: AgentProvenance,
    package: dict[str, object],
    signal: dict[str, object],
) -> AgentFinding:
    del provenance
    return build_finding(
        "AGENT.INTEL.PACKAGE_CONFUSION",
        "Agent dependency resembles a protected package name",
        Severity.high,
        "agent-threat-intelligence",
        asset_path,
        1,
        f"package={package['package_name']}; protected_package={signal['protected_package']}; edit_distance={signal['distance']}",
        "The declared package name is one edit away from a protected name in the configured local intelligence file.",
        "Verify the exact package identity, publisher, registry namespace, version, and artifact digest before installation.",
        "Trust is reduced because the dependency may be a typo-squatting or package-confusion candidate.",
    )


def load_optional_osv_mirror(path: Path) -> tuple[dict[str, object] | None, dict[str, object]]:
    if not path.is_file():
        return None, {"status": "not_configured", "path": str(path), "entry_count": 0, "updated_at": None, "age_days": None}
    try:
        payload = load_osv_mirror(path)
    except ValueError as exc:
        return None, {"status": "invalid", "path": str(path), "entry_count": 0, "updated_at": None, "age_days": None, "detail": str(exc)}
    updated_at = payload.get("updated_at")
    return payload, {
        "status": "available", "path": str(path), "entry_count": len(payload["entries"]),
        "updated_at": updated_at, "age_days": age_days(updated_at),
    }


def load_optional_threat_intelligence(path: Path) -> tuple[dict[str, object] | None, dict[str, object]]:
    if not path.is_file():
        return None, {"status": "not_configured", "path": str(path), "entry_count": 0, "protected_package_count": 0, "updated_at": None, "age_days": None}
    try:
        payload = load_agent_threat_intelligence(path)
    except ValueError as exc:
        return None, {"status": "invalid", "path": str(path), "entry_count": 0, "protected_package_count": 0, "updated_at": None, "age_days": None, "detail": str(exc)}
    updated_at = payload.get("updated_at")
    return payload, {
        "status": "available", "path": str(path), "entry_count": len(payload["entries"]),
        "protected_package_count": len(payload["protected_packages"]), "updated_at": updated_at,
        "age_days": age_days(updated_at), "sources": payload.get("sources", []),
    }


@lru_cache(maxsize=4)
def load_agent_threat_intelligence(path: Path) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Unable to read AGENT threat intelligence: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"AGENT threat intelligence is not valid JSON: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise ValueError("AGENT threat intelligence must be a JSON object")
    entries = raw.get("entries", [])
    protected = raw.get("protected_packages", [])
    if not isinstance(entries, list) or not isinstance(protected, list):
        raise ValueError("AGENT threat intelligence entries and protected_packages must be lists")
    normalized_entries = [normalize_threat_entry(item) for item in entries if isinstance(item, dict)]
    normalized_protected = [normalize_protected_package(item) for item in protected if isinstance(item, dict)]
    return {
        "schema": raw.get("schema"),
        "updated_at": raw.get("updated_at"),
        "sources": raw.get("sources", []) if isinstance(raw.get("sources"), list) else [],
        "entries": normalized_entries,
        "protected_packages": normalized_protected,
    }


def normalize_threat_entry(item: dict[str, object]) -> dict[str, object]:
    identifier = str(item.get("id") or "").strip()
    ecosystem = str(item.get("ecosystem") or "").strip().lower()
    package = str(item.get("package") or item.get("name") or "").strip()
    if not identifier or ecosystem not in {"npm", "pypi"} or not package:
        raise ValueError("Threat entries require id, npm or pypi ecosystem, and package")
    severity = severity_value(item.get("severity"), Severity.critical).value
    references = item.get("references", [])
    return {
        "id": identifier,
        "kind": str(item.get("kind") or "malicious-package"),
        "ecosystem": ecosystem,
        "package": package,
        "affected": str(item.get("affected") or "").strip() or None,
        "severity": severity,
        "summary": str(item.get("summary") or "Local threat-intelligence match")[:500],
        "source": str(item.get("source") or "local-threat-intelligence")[:200],
        "references": [str(value) for value in references if str(value).strip()][:20] if isinstance(references, list) else [],
        "enabled": bool(item.get("enabled", True)),
    }


def normalize_protected_package(item: dict[str, object]) -> dict[str, object]:
    ecosystem = str(item.get("ecosystem") or "").strip().lower()
    package = str(item.get("package") or item.get("name") or "").strip()
    if ecosystem not in {"npm", "pypi"} or not package:
        raise ValueError("Protected packages require npm or pypi ecosystem and package")
    return {"ecosystem": ecosystem, "package": package, "source": str(item.get("source") or "local-threat-intelligence")[:200]}


def file_source_status(path: Path, entry_count: int, status: str) -> dict[str, object]:
    updated_at = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat() if path.is_file() else None
    return {"status": status, "path": str(path), "entry_count": entry_count, "updated_at": updated_at, "age_days": age_days(updated_at)}


def age_days(value: object) -> int | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).days)


def normalize_package_name(ecosystem: str, name: str) -> str:
    normalized = name.strip().lower()
    return normalized.replace("_", "-") if ecosystem == "pypi" else normalized


def dedupe_vulnerabilities(items: list[dict[str, object]]) -> list[dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for item in items:
        identifier = str(item.get("id") or "")
        if identifier and identifier not in result:
            result[identifier] = item
    return list(result.values())


def dedupe_intelligence_findings(items: list[AgentFinding]) -> list[AgentFinding]:
    result: dict[tuple[str, str, str], AgentFinding] = {}
    for item in items:
        result[(item.rule_id, item.file_path, item.evidence)] = item
    return list(result.values())


def severity_value(value: object, default: Severity = Severity.medium) -> Severity:
    try:
        return Severity(str(value or default.value).lower())
    except ValueError:
        return default


def edit_distance(left: str, right: str, limit: int) -> int:
    if abs(len(left) - len(right)) > limit:
        return limit + 1
    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        row_min = current[0]
        for right_index, right_char in enumerate(right, start=1):
            current.append(min(
                current[-1] + 1,
                previous[right_index] + 1,
                previous[right_index - 1] + (left_char != right_char),
            ))
            row_min = min(row_min, current[-1])
        if row_min > limit:
            return limit + 1
        previous = current
    return previous[-1]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
