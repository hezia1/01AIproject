"""Validate the versioned acceptance baseline without inventing missing metrics."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


ALLOWED_STATUSES = {"verified", "partially_verified", "not_baselined"}
REQUIRED_FIELDS = {
    "id",
    "category",
    "metric",
    "status",
    "target",
    "current",
    "evidence",
    "limitations",
    "required_for",
}
DEFAULT_MANIFEST = Path(__file__).resolve().parents[1] / "acceptance" / "criteria.json"


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("acceptance manifest must be a JSON object")
    return payload


def validate_manifest(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    checks = payload.get("checks")
    definitions = payload.get("status_definitions")
    if payload.get("schema_version") != "1.0":
        errors.append("schema_version must be 1.0")
    if not isinstance(payload.get("baseline_id"), str) or not payload["baseline_id"].strip():
        errors.append("baseline_id must be a non-empty string")
    if not isinstance(definitions, dict) or set(definitions) != ALLOWED_STATUSES:
        errors.append("status_definitions must define exactly the allowed statuses")
    if not isinstance(checks, list) or not checks:
        errors.append("checks must be a non-empty list")
        return errors

    seen_ids: set[str] = set()
    for index, check in enumerate(checks):
        label = f"checks[{index}]"
        if not isinstance(check, dict):
            errors.append(f"{label} must be an object")
            continue
        missing = REQUIRED_FIELDS - set(check)
        if missing:
            errors.append(f"{label} missing fields: {', '.join(sorted(missing))}")
            continue
        check_id = check["id"]
        if not isinstance(check_id, str) or not check_id.strip():
            errors.append(f"{label}.id must be a non-empty string")
        elif check_id in seen_ids:
            errors.append(f"duplicate check id: {check_id}")
        else:
            seen_ids.add(check_id)
        status = check["status"]
        if status not in ALLOWED_STATUSES:
            errors.append(f"{check_id}: unsupported status {status!r}")
        evidence = check["evidence"]
        required_for = check["required_for"]
        if not isinstance(evidence, list) or not all(isinstance(item, str) and item for item in evidence):
            errors.append(f"{check_id}: evidence must be a list of non-empty strings")
        if not isinstance(required_for, list) or not all(item in {"p0", "production"} for item in required_for):
            errors.append(f"{check_id}: required_for contains an unsupported profile")
        if status == "verified" and (check["current"] is None or not evidence):
            errors.append(f"{check_id}: verified checks require a current value and evidence")
        if status == "not_baselined" and check["current"] is not None:
            errors.append(f"{check_id}: not_baselined checks must keep current=null")
    return errors


def profile_failures(payload: dict[str, Any], profile: str) -> list[str]:
    if profile == "baseline":
        return []
    return [
        check["id"]
        for check in payload["checks"]
        if profile in check["required_for"] and check["status"] != "verified"
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--profile", choices=("baseline", "p0", "production"), default="baseline")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()

    try:
        payload = load_manifest(args.manifest)
        errors = validate_manifest(payload)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        errors = [str(exc)]
        payload = {"checks": []}

    failures = profile_failures(payload, args.profile) if not errors else []
    statuses = Counter(check["status"] for check in payload.get("checks", []) if isinstance(check, dict))
    result = {
        "baseline_id": payload.get("baseline_id"),
        "profile": args.profile,
        "valid": not errors,
        "gate_passed": not errors and not failures,
        "status_counts": dict(sorted(statuses.items())),
        "validation_errors": errors,
        "failed_checks": failures,
    }
    if args.json_output:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Baseline: {result['baseline_id'] or 'unknown'}")
        print(f"Profile: {args.profile}")
        print("Statuses: " + ", ".join(f"{key}={value}" for key, value in result["status_counts"].items()))
        if errors:
            print("Manifest errors: " + "; ".join(errors))
        if failures:
            print("Unmet profile checks: " + ", ".join(failures))
        print("Result: PASS" if result["gate_passed"] else "Result: FAIL")
    return 0 if result["gate_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
