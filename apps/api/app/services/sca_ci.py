from __future__ import annotations

from dataclasses import asdict

from app.services.sca_artifacts import collect_artifact_hashes, source_fingerprint
from app.services.sca_gate_policy import DEFAULT_GATE_POLICY
from app.services.sca_parser import dedupe_components, parse_dependency_tree
from app.services.sca_python_environment import inspect_python_environment
from app.services.sca_risk_analyzer import analyze_components


def run_local_sca(source_path: str, policy: dict[str, object] | None = None) -> dict[str, object]:
    parsed = parse_dependency_tree(source_path)
    environment = inspect_python_environment(source_path)
    components = analyze_components(dedupe_components([*parsed.components, *environment.components]))
    effective_policy = {**DEFAULT_GATE_POLICY, **(policy or {})}
    gate = evaluate_local_gate(components, effective_policy)
    return {
        "source_path": source_path,
        "scanned_files": parsed.scanned_files,
        "source_fingerprint": source_fingerprint(source_path),
        "artifact_hashes": collect_artifact_hashes(source_path, components),
        "python_environment": {"status": "available" if environment.available else "unavailable", "interpreter": environment.interpreter, "error": environment.error},
        "components": [asdict(component) for component in components],
        "gate": gate,
        "sarif": build_sarif(components),
    }


def evaluate_local_gate(components, policy: dict[str, object]) -> dict[str, object]:
    blocked = []
    for component in components:
        if component.risk_status in {"accepted-risk", "not_affected", "fixed"}:
            continue
        metadata = component.risk_metadata or {}
        reasons = []
        if component.severity in set(policy.get("block_severities", [])):
            reasons.append(f"severity:{component.severity}")
        if component.license_risk in set(policy.get("block_license_policies", [])):
            reasons.append(f"license:{component.license_risk}")
        if int(metadata.get("risk_score") or 0) >= int(policy.get("min_risk_score", 0)) > 0:
            reasons.append(f"risk_score:{metadata.get('risk_score')}")
        if policy.get("block_kev") and metadata.get("kev"):
            reasons.append("kev")
        if reasons:
            blocked.append({"name": component.name, "version": component.version, "ecosystem": component.ecosystem, "vulnerability_ids": component.vulnerability_ids or [], "reasons": reasons})
    if not policy.get("enabled", True):
        blocked = []
    return {"decision": "block" if blocked else "pass", "exit_code": 2 if blocked else 0, "policy": policy, "blocked_components": blocked}


def build_sarif(components) -> dict[str, object]:
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for component in components:
        for vulnerability_id in component.vulnerability_ids or []:
            rule_id = f"SCA:{vulnerability_id}"
            rules.setdefault(rule_id, {"id": rule_id, "name": vulnerability_id, "shortDescription": {"text": f"SCA vulnerability {vulnerability_id}"}})
            results.append({"ruleId": rule_id, "level": sarif_level(component.severity), "message": {"text": f"{component.ecosystem}/{component.name}@{component.version or 'unknown'}: {component.risk_summary or vulnerability_id}"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": component.source_file}}}], "properties": {"ecosystem": component.ecosystem, "component": component.name, "version": component.version, "risk_metadata": component.risk_metadata or {}}})
        if component.license_risk in {"restricted", "review_required", "unknown"}:
            rule_id = f"SCA-LICENSE:{component.license_risk}"
            rules.setdefault(rule_id, {"id": rule_id, "name": rule_id, "shortDescription": {"text": "SCA license policy finding"}})
            results.append({"ruleId": rule_id, "level": "warning", "message": {"text": f"{component.name}: license policy {component.license_risk}"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": component.source_file}}}]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "AI Security Platform SCA", "rules": list(rules.values())}}, "results": results}]}


def sarif_level(severity: str | None) -> str:
    return "error" if severity in {"critical", "high"} else "warning" if severity == "medium" else "note"
