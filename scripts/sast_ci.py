"""Run the local SAST rules in CI and write JSON/SARIF evidence without a platform server."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.services.sast_sarif import build_sast_sarif_from_parsed  # noqa: E402
from app.services.sast_git import collect_git_context, git_history_secret_findings  # noqa: E402
from app.services.sast_scanner import scan_source_tree  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Local AI Security Platform SAST scan")
    parser.add_argument("--source", default=".", help="Repository directory to scan")
    parser.add_argument("--json", dest="json_path", default="sast-result.json")
    parser.add_argument("--sarif", dest="sarif_path", default="sast-result.sarif")
    parser.add_argument("--offline", action="store_true", help="Record an offline-only run; local rules do not need network access")
    parser.add_argument("--baseline", default="", help="Optional local Git baseline revision for changed-file scanning")
    parser.add_argument("--changed-files-only", action="store_true", help="Scan only files changed from --baseline")
    parser.add_argument("--no-history-secret-scan", action="store_true", help="Do not inspect Git diff history for secret-like identifiers")
    parser.add_argument("--fail-on", choices=["none", "critical", "high", "medium", "low"], default="none")
    args = parser.parse_args()
    if args.offline:
        os.environ["SAST_OFFLINE_ONLY"] = "true"

    source = Path(args.source).resolve()
    git_context = collect_git_context(str(source), args.baseline, not args.no_history_secret_scan)
    changed_files = git_context.get("changed_files") if args.changed_files_only else None
    if args.changed_files_only and not changed_files:
        parser.error("--changed-files-only requires --baseline that resolves to at least one changed file")
    result = scan_source_tree(str(source), include_paths=changed_files if isinstance(changed_files, list) else None)
    result.findings.extend(git_history_secret_findings(git_context))
    payload = {
        "source_path": str(source),
        "offline": args.offline,
        "engine": "local_rules",
        "git": git_context,
        "scanned_files": result.scanned_files,
        "finding_count": len(result.findings),
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
            for item in result.findings
        ],
    }
    Path(args.json_path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    Path(args.sarif_path).write_text(json.dumps(build_sast_sarif_from_parsed(result.findings), ensure_ascii=False, indent=2), encoding="utf-8")
    severity_order = {"none": 99, "critical": 0, "high": 1, "medium": 2, "low": 3}
    threshold = severity_order[args.fail_on]
    should_fail = args.fail_on != "none" and any(severity_order.get(item.severity.value, 99) <= threshold for item in result.findings)
    print(json.dumps({"finding_count": len(result.findings), "fail_on": args.fail_on, "failed": should_fail, "git_baseline": git_context.get("baseline_ref")}, ensure_ascii=False))
    return 2 if should_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
