"""Run the project SAST profile in CI and write JSON/SARIF evidence."""
from __future__ import annotations

import argparse
from fnmatch import fnmatchcase
import json
import os
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.services.sast_sarif import build_sast_sarif_from_parsed  # noqa: E402
from app.services.sast_git import collect_git_context, git_history_secret_findings  # noqa: E402
from app.services.sast_governance import apply_suppressions, effective_sast_profile  # noqa: E402
from app.services.sast_scanner import SastScanOutput, dedupe_findings  # noqa: E402
from app.routers.sast import run_sast_engines  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Local AI Security Platform SAST scan")
    parser.add_argument("--source", default=".", help="Repository directory to scan")
    parser.add_argument("--json", dest="json_path", default="sast-result.json")
    parser.add_argument("--sarif", dest="sarif_path", default="sast-result.sarif")
    parser.add_argument("--profile", default="", help="Exported SAST CI config or raw project profile JSON")
    parser.add_argument("--offline", action="store_true", help="Record an offline-only run; local rules do not need network access")
    parser.add_argument("--baseline", default="", help="Optional local Git baseline revision for changed-file scanning")
    parser.add_argument("--changed-files-only", action="store_true", help="Scan only files changed from --baseline")
    parser.add_argument("--no-history-secret-scan", action="store_true", help="Do not inspect Git diff history for secret-like identifiers")
    parser.add_argument("--branch", default="", help="Branch name used by the project quality gate")
    parser.add_argument("--fail-on", choices=["none", "critical", "high", "medium", "low", "info"], default=None, help="Override only the project gate threshold")
    args = parser.parse_args()
    if args.offline:
        os.environ["SAST_OFFLINE_ONLY"] = "true"

    source = Path(args.source).resolve()
    try:
        profile = load_profile(args.profile)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    baseline = args.baseline or str(profile.get("git_baseline_ref") or "")
    gate = dict(profile.get("quality_gate") or {})
    changed_files_only = bool(args.changed_files_only or profile.get("changed_files_only"))
    if gate.get("block_new_only") and not baseline:
        parser.error("project quality_gate.block_new_only requires --baseline or profile.git_baseline_ref in standalone CI")
    if gate.get("block_new_only") and baseline:
        changed_files_only = True
    scan_history = bool(profile.get("scan_git_history_secrets", True)) and not args.no_history_secret_scan
    git_context = collect_git_context(str(source), baseline, scan_history)
    changed_files = git_context.get("changed_files") if changed_files_only else None
    if changed_files_only and not changed_files:
        parser.error("changed-files-only scanning requires a baseline that resolves to at least one changed file")
    result = run_sast_engines(str(source), profile, changed_files if isinstance(changed_files, list) else None)
    result = SastScanOutput(
        findings=dedupe_findings([*result.findings, *git_history_secret_findings(git_context)]),
        scanned_files=result.scanned_files,
        engine_status=result.engine_status,
    )
    findings, suppressed = apply_suppressions(result.findings, profile.get("suppressions"))
    branch = args.branch or os.getenv("GITHUB_HEAD_REF") or os.getenv("GITHUB_REF_NAME") or "default"
    gate_result = evaluate_quality_gate(findings, profile, branch, args.fail_on)
    payload = {
        "source_path": str(source),
        "offline": args.offline,
        "profile": profile,
        "engine_status": result.engine_status,
        "git": git_context,
        "scanned_files": result.scanned_files,
        "finding_count": len(findings),
        "suppressed_count": len(suppressed),
        "suppressed_findings": suppressed,
        "quality_gate": gate_result,
        "findings": [
            {
                "rule_id": item.rule_id,
                "title": item.title,
                "severity": item.severity.value,
                "file_path": item.file_path,
                "line_start": item.line_start,
                "line_end": item.line_end,
                "evidence": item.evidence,
                "category": item.category,
                "cwe": item.cwe,
                "owasp": item.owasp,
                "remediation": item.remediation,
            }
            for item in findings
        ],
    }
    Path(args.json_path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    Path(args.sarif_path).write_text(json.dumps(build_sast_sarif_from_parsed(findings), ensure_ascii=False, indent=2), encoding="utf-8")
    should_fail = gate_result["status"] == "block"
    print(json.dumps({"finding_count": len(findings), "suppressed_count": len(suppressed), "quality_gate": gate_result, "failed": should_fail, "git_baseline": git_context.get("baseline_ref")}, ensure_ascii=False))
    return 2 if should_fail else 0


def load_profile(path: str) -> dict[str, object]:
    if not path:
        return effective_sast_profile({})
    profile_path = Path(path).expanduser().resolve()
    if not profile_path.is_file():
        raise ValueError(f"SAST profile file does not exist: {profile_path}")
    payload = json.loads(profile_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("SAST profile JSON must be an object")
    raw_profile: Any = payload.get("profile", payload)
    if not isinstance(raw_profile, dict):
        raise ValueError("SAST profile JSON does not contain a valid profile object")
    return effective_sast_profile({"sast_profile": raw_profile})


def evaluate_quality_gate(findings: list, profile: dict[str, object], branch: str, threshold_override: str | None = None) -> dict[str, object]:
    gate = dict(profile.get("quality_gate") or {})
    threshold = threshold_override or str(gate.get("threshold") or "high")
    enabled = bool(gate.get("enabled", True))
    patterns = gate.get("branch_patterns") if isinstance(gate.get("branch_patterns"), list) else ["*"]
    applies_to_branch = any(fnmatchcase(branch, str(pattern)) for pattern in patterns)
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 99}
    excluded = {str(item) for item in gate.get("excluded_rule_ids", [])} if isinstance(gate.get("excluded_rule_ids"), list) else set()
    blocking = [item for item in findings if item.rule_id not in excluded and ranks.get(item.severity.value, 99) <= ranks.get(threshold, 1)]
    maximum = max(0, int(gate.get("max_blocking_findings") or 0))
    breached = len(blocking) > maximum if maximum > 0 else bool(blocking)
    blocked = enabled and applies_to_branch and threshold != "none" and breached
    return {
        "status": "block" if blocked else "pass",
        "enabled": enabled,
        "threshold": threshold,
        "branch": branch,
        "branch_patterns": patterns,
        "block_new_only": bool(gate.get("block_new_only", False)),
        "excluded_rule_ids": sorted(excluded),
        "max_blocking_findings": maximum,
        "blocking_finding_count": len(blocking),
        "blocking_rule_ids": sorted({item.rule_id for item in blocking}),
    }


if __name__ == "__main__":
    raise SystemExit(main())
