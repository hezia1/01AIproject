"""Run the versioned, deterministic security quality and DAST replay benchmark."""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
API_ROOT = ROOT / "apps" / "api"
BENCHMARK_ROOT = ROOT / "benchmarks" / "security" / "v1"
sys.path.insert(0, str(API_ROOT))

from app.models import DastSandboxResult  # noqa: E402
from app.routers.dast import _adjudicate_sandbox_result  # noqa: E402
from app.services.agent_scanner import scan_agent_tree  # noqa: E402
from app.services.sast_scanner import canonical_issue_key, scan_source_tree  # noqa: E402
from app.services.sca_parser import parse_dependency_tree  # noqa: E402
from app.services.sca_risk_analyzer import analyze_components  # noqa: E402


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 1.0


def evaluate_sast(config: dict[str, object]) -> dict[str, object]:
    universe = {canonical_issue_key(str(item)) for item in config.get("rule_universe", [])}
    totals = Counter(tp=0, fp=0, fn=0, tn=0)
    sample_results: list[dict[str, object]] = []
    for sample in config.get("samples", []):
        fixture = BENCHMARK_ROOT / str(sample["path"])
        with TemporaryDirectory(prefix="security-benchmark-sast-") as temporary:
            scan_file = Path(temporary) / str(sample["scan_filename"])
            scan_file.write_bytes(fixture.read_bytes())
            output = scan_source_tree(temporary, include_paths=[scan_file.name])
        observed_raw = sorted({item.rule_id for item in output.findings})
        observed = {canonical_issue_key(item) for item in observed_raw}
        expected_raw = {str(item) for item in sample.get("expected_rule_ids", [])}
        expected = {canonical_issue_key(item) for item in expected_raw}
        for rule_id in universe:
            if rule_id in expected and rule_id in observed:
                totals["tp"] += 1
            elif rule_id in expected:
                totals["fn"] += 1
            elif rule_id in observed:
                totals["fp"] += 1
            else:
                totals["tn"] += 1
        extras = observed - universe
        totals["fp"] += len(extras)
        sample_results.append({
            "id": sample["id"], "expected_rule_ids": sorted(expected_raw),
            "observed_rule_ids": observed_raw,
            "missing_rule_ids": sorted(expected - observed),
            "unexpected_rule_ids": sorted(extras | (observed - expected if not expected else set())),
        })
    precision = ratio(totals["tp"], totals["tp"] + totals["fp"])
    recall = ratio(totals["tp"], totals["tp"] + totals["fn"])
    false_positive_rate = ratio(totals["fp"], totals["fp"] + totals["tn"])
    return {
        "status": "complete", "samples": sample_results, "confusion": dict(totals),
        "precision": precision, "recall": recall, "false_positive_rate": false_positive_rate,
        "limitations": "Metrics cover only the labelled JavaScript rules and fixtures in this benchmark version.",
    }


def evaluate_agent(config: dict[str, object]) -> dict[str, object]:
    universe = {str(item) for item in config.get("rule_universe", [])}
    totals = Counter(tp=0, fp=0, fn=0, tn=0)
    sample_results: list[dict[str, object]] = []
    for sample in config.get("samples", []):
        fixture = BENCHMARK_ROOT / str(sample["path"])
        with TemporaryDirectory(prefix="security-benchmark-agent-") as temporary:
            (Path(temporary) / str(sample["scan_filename"])).write_bytes(fixture.read_bytes())
            output = scan_agent_tree(temporary)
        observed = {item.rule_id for item in output.findings}
        expected = {str(item) for item in sample.get("expected_rule_ids", [])}
        for rule_id in universe:
            if rule_id in expected and rule_id in observed:
                totals["tp"] += 1
            elif rule_id in expected:
                totals["fn"] += 1
            elif rule_id in observed:
                totals["fp"] += 1
            else:
                totals["tn"] += 1
        extras = observed - universe
        totals["fp"] += len(extras)
        sample_results.append({
            "id": sample["id"], "expected_rule_ids": sorted(expected),
            "observed_rule_ids": sorted(observed), "missing_rule_ids": sorted(expected - observed),
            "unexpected_rule_ids": sorted(extras | (observed - expected if not expected else set())),
        })
    return {
        "status": "complete", "samples": sample_results, "confusion": dict(totals),
        "precision": ratio(totals["tp"], totals["tp"] + totals["fp"]),
        "recall": ratio(totals["tp"], totals["tp"] + totals["fn"]),
        "false_positive_rate": ratio(totals["fp"], totals["fp"] + totals["tn"]),
        "limitations": "Metrics cover only labelled instruction rules; they do not test an AGENT runtime or the acceptance project.",
    }


def component_key(component) -> str:
    return f"{component.ecosystem}:{component.name}@{component.version or 'unknown'}"


def evaluate_sca(config: dict[str, object]) -> dict[str, object]:
    component_tp = component_expected = vulnerability_tp = vulnerability_fp = vulnerability_fn = 0
    sample_results: list[dict[str, object]] = []
    for sample in config.get("samples", []):
        fixture = BENCHMARK_ROOT / str(sample["path"])
        with TemporaryDirectory(prefix="security-benchmark-sca-") as temporary:
            (Path(temporary) / str(sample["scan_filename"])).write_bytes(fixture.read_bytes())
            parsed = parse_dependency_tree(temporary)
        analyzed = analyze_components(parsed.components, offline_only=True)
        observed_components = {component_key(item) for item in analyzed}
        observed_vulnerabilities = {value for item in analyzed for value in (item.vulnerability_ids or [])}
        expected_components = {str(item) for item in sample.get("expected_components", [])}
        expected_vulnerabilities = {str(item) for item in sample.get("expected_vulnerability_ids", [])}
        component_tp += len(expected_components & observed_components)
        component_expected += len(expected_components)
        vulnerability_tp += len(expected_vulnerabilities & observed_vulnerabilities)
        vulnerability_fn += len(expected_vulnerabilities - observed_vulnerabilities)
        vulnerability_fp += len(observed_vulnerabilities - expected_vulnerabilities)
        sample_results.append({
            "id": sample["id"], "expected_components": sorted(expected_components),
            "observed_components": sorted(observed_components),
            "expected_vulnerability_ids": sorted(expected_vulnerabilities),
            "observed_vulnerability_ids": sorted(observed_vulnerabilities),
        })
    return {
        "status": "complete", "samples": sample_results,
        "component_recall": ratio(component_tp, component_expected),
        "vulnerability_precision": ratio(vulnerability_tp, vulnerability_tp + vulnerability_fp),
        "vulnerability_recall": ratio(vulnerability_tp, vulnerability_tp + vulnerability_fn),
        "limitations": "Known-vulnerability metrics cover bundled deterministic rules only, not OSV or container-tool coverage.",
    }


def evidence_has_keys(evidence: list[dict[str, object]], required: set[str]) -> bool:
    return not required or any(required <= set(item) for item in evidence)


def evaluate_dast(config: dict[str, object]) -> dict[str, object]:
    repeat_count = int(config.get("repeat_count") or 1)
    correct = consistent = complete = decisive = 0
    sample_results: list[dict[str, object]] = []
    for sample in config.get("samples", []):
        raw = dict(sample["payload"])
        payload = DastSandboxResult(
            task_id=uuid4(), strategy_id=uuid4(), callback_token="benchmark-callback-token-00000001",
            execution_id=f"benchmark-{sample['id']}", **raw,
        )
        verdicts = [_adjudicate_sandbox_result(payload)[0] for _ in range(repeat_count)]
        expected = str(sample["expected_verdict"])
        is_correct = all(item == expected for item in verdicts)
        is_consistent = len(set(verdicts)) == 1
        required = {str(item) for item in sample.get("required_evidence_keys", [])}
        evidence_complete = evidence_has_keys(payload.evidence, required)
        correct += int(is_correct)
        consistent += int(is_consistent)
        if required:
            decisive += 1
            complete += int(evidence_complete)
        sample_results.append({
            "id": sample["id"], "expected_bucket": sample["expected_bucket"],
            "expected_verdict": expected, "observed_verdicts": verdicts,
            "consistent": is_consistent, "required_evidence_complete": evidence_complete,
        })
    count = len(sample_results)
    return {
        "status": "complete", "repeat_count": repeat_count, "samples": sample_results,
        "verdict_accuracy": ratio(correct, count),
        "replay_consistency": ratio(consistent, count),
        "evidence_completeness": ratio(complete, decisive),
        "limitations": "This replays adjudication contracts without starting a target or making network requests.",
    }


def verify_external_source(source: Path, config: dict[str, object]) -> dict[str, str]:
    source_config = config["source"]
    if not source.is_dir():
        raise ValueError("external source must be an existing directory")
    commit = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(source), "status", "--porcelain"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    remote = subprocess.run(
        ["git", "-C", str(source), "remote", "get-url", "origin"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    expected_commit = str(source_config["commit"])
    expected_remote = str(source_config["repository"]).removesuffix(".git").lower()
    manifest = source / str(source_config["official_manifest"])
    manifest_hash = file_sha256(manifest)
    expected_hash = str(source_config["official_manifest_sha256"]).lower()
    if dirty or commit != expected_commit or manifest_hash != expected_hash or remote.removesuffix(".git").lower() != expected_remote:
        raise ValueError(
            f"external benchmark identity mismatch: commit={commit}, manifest_sha256={manifest_hash}, clean={not bool(dirty)}"
        )
    return {"commit": commit, "official_manifest_sha256": manifest_hash, "repository": remote, "worktree": "clean"}


def evaluate_external(source: Path, config: dict[str, object]) -> dict[str, object]:
    identity = verify_external_source(source, config)
    findings = scan_source_tree(str(source)).findings
    observed_by_path: dict[str, set[str]] = {}
    for finding in findings:
        observed_by_path.setdefault(finding.file_path, set()).add(finding.rule_id)
    components = parse_dependency_tree(str(source)).components
    component_keys = {component_key(item) for item in components}
    issue_results = []
    by_class: dict[str, Counter] = {}
    for issue in config.get("issues", []):
        expected_rules = {str(item) for item in issue.get("expected_rule_ids", [])}
        observed_rules = observed_by_path.get(str(issue["path"]), set())
        matched_rules = sorted(expected_rules & observed_rules)
        detected = bool(matched_rules)
        issue_class = str(issue["class"])
        by_class.setdefault(issue_class, Counter(total=0, detected=0))
        by_class[issue_class]["total"] += 1
        by_class[issue_class]["detected"] += int(detected)
        issue_results.append({
            "id": issue["id"], "title": issue["title"], "class": issue_class,
            "module": issue["module"], "path": issue["path"], "detected": detected,
            "matched_rule_ids": matched_rules,
            "component_observed": str(issue.get("component")) in component_keys if issue.get("component") else None,
            "uncovered_reason": None if detected else issue.get("uncovered_reason") or "Expected detector did not produce evidence",
        })
    total = len(issue_results)
    detected_count = sum(int(item["detected"]) for item in issue_results)
    security_scope = [item for item in issue_results if item["class"] != "code_quality"]
    return {
        "status": "partial" if detected_count < total else "complete",
        "identity": identity,
        "official_issue_count": total,
        "detected_issue_count": detected_count,
        "official_list_coverage": ratio(detected_count, total),
        "security_scope_issue_count": len(security_scope),
        "security_scope_coverage": ratio(sum(int(item["detected"]) for item in security_scope), len(security_scope)),
        "by_class": {
            key: {"total": value["total"], "detected": value["detected"], "coverage": ratio(value["detected"], value["total"])}
            for key, value in sorted(by_class.items())
        },
        "issues": issue_results,
        "limitations": "Coverage is a mapping of this fixed official list, not general precision/recall or runtime exploitability.",
    }


def threshold_failures(results: dict[str, object], thresholds: dict[str, object]) -> list[str]:
    actual = {
        "sast_precision": results["sast"]["precision"],
        "sast_recall": results["sast"]["recall"],
        "sast_false_positive_rate": results["sast"]["false_positive_rate"],
        "agent_precision": results["agent"]["precision"],
        "agent_recall": results["agent"]["recall"],
        "agent_false_positive_rate": results["agent"]["false_positive_rate"],
        "sca_component_recall": results["sca"]["component_recall"],
        "sca_vulnerability_precision": results["sca"]["vulnerability_precision"],
        "sca_vulnerability_recall": results["sca"]["vulnerability_recall"],
        "dast_verdict_accuracy": results["dast"]["verdict_accuracy"],
        "dast_replay_consistency": results["dast"]["replay_consistency"],
        "dast_evidence_completeness": results["dast"]["evidence_completeness"],
    }
    failures = []
    for name, expected_value in thresholds.items():
        expected = float(expected_value)
        value = float(actual[name])
        failed = value > expected if name.endswith("false_positive_rate") else value < expected
        if failed:
            failures.append(f"{name}: expected {'<=' if name.endswith('false_positive_rate') else '>='}{expected}, got {value}")
    return failures


def run_benchmark(external_source: Path | None = None) -> dict[str, object]:
    manifest_path = BENCHMARK_ROOT / "manifest.json"
    manifest = load_json(manifest_path)
    results: dict[str, object] = {
        "schema_version": manifest["schema_version"], "benchmark_id": manifest["benchmark_id"],
        "input_hashes": {"manifest.json": file_sha256(manifest_path)},
        "agent": evaluate_agent(manifest["agent"]),
        "sast": evaluate_sast(manifest["sast"]),
        "sca": evaluate_sca(manifest["sca"]),
        "dast": evaluate_dast(manifest["dast"]),
    }
    results["threshold_failures"] = threshold_failures(results, manifest["thresholds"])
    results["status"] = "failed" if results["threshold_failures"] else "passed"
    if external_source is not None:
        external_path = BENCHMARK_ROOT / "external-testproject.json"
        external = load_json(external_path)
        results["input_hashes"]["external-testproject.json"] = file_sha256(external_path)
        results["external"] = evaluate_external(external_source.resolve(), external)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Versioned security quality and DAST replay benchmark")
    parser.add_argument("--external-source", type=Path, help="Optional checkout matching external-testproject.json")
    parser.add_argument("--json", type=Path, help="Write the deterministic report to this path")
    args = parser.parse_args()
    try:
        result = run_benchmark(args.external_source)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "error", "detail": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False), file=sys.stderr)
        return 3
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_bytes(payload.encode("utf-8"))
        print(json.dumps({"status": result["status"], "report": str(args.json), "sha256": file_sha256(args.json)}, ensure_ascii=False))
    else:
        print(payload, end="")
    return 2 if result["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
