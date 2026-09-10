"""Run SCA locally in CI and write JSON/SARIF evidence without a platform server."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.services.sca_ci import run_local_sca  # noqa: E402


ERROR_EXIT = 3


def main() -> int:
    parser = argparse.ArgumentParser(description="Local AI Security Platform SCA scan")
    parser.add_argument("--source", default=".", help="Repository directory to scan")
    parser.add_argument("--json", dest="json_path", default="sca-result.json")
    parser.add_argument("--sarif", dest="sarif_path", default="sca-result.sarif")
    parser.add_argument("--policy", help="Optional gate policy JSON file")
    parser.add_argument("--offline", action="store_true", help="Do not call online OSV; use local mirrors/rules only")
    parser.add_argument("--fail-on-block", action="store_true")
    args = parser.parse_args()
    if args.offline:
        os.environ["SCA_OFFLINE_ONLY"] = "true"
    try:
        policy = json.loads(Path(args.policy).read_text(encoding="utf-8")) if args.policy else None
        if policy is not None and not isinstance(policy, dict):
            raise ValueError("--policy must contain a JSON object")
        result = run_local_sca(str(Path(args.source).resolve()), policy)
    except Exception as exc:
        detail = f"{type(exc).__name__}: {str(exc)[:500]}"
        result = {
            "source_path": str(Path(args.source).resolve()),
            "scanned_files": [],
            "components": [],
            "assurance": {"status": "failed", "reasons": [detail]},
            "gate": {
                "decision": "error", "exit_code": ERROR_EXIT, "scan_status": "failed",
                "result_complete": False, "operational_reasons": [detail],
                "reason": "本地 SCA 执行或配置失败，不能形成门禁结论",
            },
            "sarif": failed_sarif(detail),
        }
    Path(args.json_path).write_text(json.dumps({key: value for key, value in result.items() if key != "sarif"}, ensure_ascii=False, indent=2), encoding="utf-8")
    Path(args.sarif_path).write_text(json.dumps(result["sarif"], ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result["gate"], ensure_ascii=False))
    if result["gate"]["exit_code"] == ERROR_EXIT:
        return ERROR_EXIT
    return int(result["gate"]["exit_code"]) if args.fail_on_block else 0


def failed_sarif(detail: str) -> dict[str, object]:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "AI Security Platform SCA"}},
            "invocations": [{
                "executionSuccessful": False,
                "toolExecutionNotifications": [{"level": "error", "message": {"text": detail}}],
            }],
            "results": [],
        }],
    }


if __name__ == "__main__":
    raise SystemExit(main())
