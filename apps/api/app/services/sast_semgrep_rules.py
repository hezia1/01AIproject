"""Project-scoped Semgrep YAML rule packs stored in module configuration.

The platform stores the YAML with its version and checksum, then materializes
enabled packs only under artifacts/sast-offline/runtime-rules at scan time.
No rule is fetched from a registry by this service.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable


BUILTIN_CONFIG = "builtin/offline-default.yml"
_RULES_ROOT = Path(__file__).resolve().parents[1] / "rules" / "sast"
_OFFLINE_ROOT = Path(os.getenv("SAST_OFFLINE_DIR", r"D:\project\PYproject\AI网安项目\artifacts\sast-offline"))


def builtin_rule_pack_path() -> Path:
    return _RULES_ROOT / "offline-default.yml"


def validate_semgrep_yaml(content: object) -> dict[str, object]:
    text = str(content or "").replace("\r\n", "\n").strip()
    if len(text) < 24 or len(text) > 200_000:
        raise ValueError("Semgrep YAML content must be between 24 and 200000 characters")
    if not re.search(r"(?m)^rules\s*:\s*$", text):
        raise ValueError("Semgrep YAML must have a top-level 'rules:' key")
    rule_ids = re.findall(r"(?m)^\s*-\s+id\s*:\s*([A-Za-z0-9_.:-]+)\s*$|^\s+id\s*:\s*([A-Za-z0-9_.:-]+)\s*$", text)
    flattened_ids = [first or second for first, second in rule_ids]
    if not flattened_ids:
        raise ValueError("Semgrep YAML must define at least one rule id")
    if len(set(flattened_ids)) != len(flattened_ids):
        raise ValueError("Semgrep YAML rule ids must be unique within a pack")
    if not re.search(r"(?m)^\s+languages\s*:", text):
        raise ValueError("Semgrep YAML rules must declare languages")
    if not re.search(r"(?m)^\s+(pattern|patterns|pattern-either|mode)\s*:", text):
        raise ValueError("Semgrep YAML rules need pattern(s) or a taint mode")
    if re.search(r"(?im)https?://|\bregistry\b", text):
        raise ValueError("Semgrep YAML packs may not reference remote rule sources")
    return {
        "valid": True,
        "rule_ids": flattened_ids,
        "rule_count": len(flattened_ids),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "message": "YAML structure is ready for local Semgrep execution; an installed CLI or preloaded image is still required to compile it fully.",
    }


def materialize_semgrep_rule_packs(rules: Iterable[dict[str, object]]) -> list[Path]:
    target = _OFFLINE_ROOT / "runtime-rules"
    target.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for rule in rules:
        if not rule.get("enabled", True) or rule.get("status", "published") != "published":
            continue
        content = str(rule.get("content") or "")
        result = validate_semgrep_yaml(content)
        digest = str(result["sha256"])
        rule_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(rule.get("id") or "custom"))[:80]
        path = target / f"{rule_id}-{digest[:16]}.yml"
        if not path.exists() or path.read_text(encoding="utf-8", errors="ignore") != content:
            path.write_text(content, encoding="utf-8")
        paths.append(path)
    return paths


def semgrep_rule_preflight(content: object) -> dict[str, object]:
    """Run the installed local/preloaded Semgrep validator when available."""
    structural = validate_semgrep_yaml(content)
    target = _OFFLINE_ROOT / "runtime-rules"
    target.mkdir(parents=True, exist_ok=True)
    path = target / f"preflight-{str(structural['sha256'])[:16]}.yml"
    path.write_text(str(content).replace("\r\n", "\n").strip(), encoding="utf-8")
    semgrep = shutil.which("semgrep")
    docker = shutil.which("docker")
    if semgrep:
        command = [semgrep, "validate", "--config", str(path)]
    elif docker:
        # `docker run` pulls by default when the image is absent. Preflight must
        # remain offline and must never fetch an image behind the user's back.
        try:
            image_check = subprocess.run([docker, "image", "inspect", DEFAULT_IMAGE_FOR_PREFLIGHT], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=12)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {**structural, "engine_checked": False, "engine_status": "unavailable", "detail": str(exc)[:500]}
        if image_check.returncode != 0:
            return {**structural, "engine_checked": False, "engine_status": "unavailable", "detail": f"Preloaded Docker image {DEFAULT_IMAGE_FOR_PREFLIGHT} is unavailable; structural YAML validation completed only."}
        command = [docker, "run", "--rm", "-v", f"{path.parent}:/rules:ro", DEFAULT_IMAGE_FOR_PREFLIGHT, "semgrep", "validate", "--config", f"/rules/{path.name}"]
    else:
        return {**structural, "engine_checked": False, "engine_status": "unavailable", "detail": "Semgrep CLI or Docker is unavailable; structural YAML validation completed only."}
    try:
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {**structural, "engine_checked": False, "engine_status": "unavailable", "detail": str(exc)[:500]}
    if completed.returncode != 0:
        raise ValueError((completed.stderr or completed.stdout or "Semgrep validation failed").strip()[:1000])
    return {**structural, "engine_checked": True, "engine_status": "passed", "detail": (completed.stderr or completed.stdout or "Semgrep validation passed").strip()[:500]}


DEFAULT_IMAGE_FOR_PREFLIGHT = os.getenv("SAST_SEMGREP_IMAGE", "semgrep/semgrep:1.95.0")
