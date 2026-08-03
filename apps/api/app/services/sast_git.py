"""Bounded Git metadata collection for SAST baselines and history secrets."""
from __future__ import annotations

import re
import subprocess
import math
from pathlib import Path

from app.models import Severity
from app.services.sast_scanner import ParsedFinding


SECRET_DIFF_PATTERN = r"(api[_-]?key|secret|token|password|passwd|aws_access_key_id)"
HIGH_ENTROPY_VALUE = re.compile(r"(?i)(?:api[_-]?key|secret|token|password|passwd|private[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_+/=.-]{20,})")


def collect_git_context(source_path: str, baseline_ref: str = "", include_history_secrets: bool = True) -> dict[str, object]:
    root = Path(source_path).resolve()
    repository = _git(root, "rev-parse", "--show-toplevel")
    if repository is None:
        return {"available": False, "reason": "source path is not inside a readable Git repository", "changed_files": [], "history_secret_files": []}
    repo = Path(repository)
    head = _git(repo, "rev-parse", "HEAD")
    baseline = baseline_ref or ""
    changed_files: list[str] = []
    baseline_resolved = _git(repo, "rev-parse", "--verify", baseline) if baseline else None
    if baseline and baseline_resolved:
        output = _git(repo, "diff", "--name-only", "--diff-filter=ACMR", f"{baseline}...HEAD") or ""
        changed_files = _safe_relative_paths(output.splitlines(), repo)
    history_secret_files: list[str] = []
    history_secret_evidence: list[dict[str, str]] = []
    if include_history_secrets:
        # -G searches changed diff lines. We return paths only, never historical secret values.
        output = _git(repo, "log", "-i", "--all", "-G", SECRET_DIFF_PATTERN, "--format=", "--name-only", "--max-count=200") or ""
        history_secret_files = _safe_relative_paths(output.splitlines(), repo)
        history_secret_evidence = _history_entropy_evidence(repo)
        history_secret_files = sorted({*history_secret_files, *(item["file_path"] for item in history_secret_evidence)})
    return {
        "available": True,
        "repository": str(repo),
        "head": head,
        "baseline_ref": baseline or None,
        "baseline_resolved": baseline_resolved,
        "changed_files": changed_files,
        "history_secret_files": history_secret_files,
        "history_secret_count": len(history_secret_files),
        "history_secret_evidence": history_secret_evidence,
        "history_secret_note": "Only file paths are retained; historical credential values are never stored in scan metadata.",
    }


def git_history_secret_findings(context: dict[str, object]) -> list[ParsedFinding]:
    paths = context.get("history_secret_files")
    if not isinstance(paths, list):
        return []
    return [
        ParsedFinding(
            rule_id="SAST.GIT.HISTORY_SECRET", title="Potential credential material in Git history",
            severity=Severity.high, file_path=str(path), line_start=1, line_end=1,
            evidence="Historical diff matched a secret-like identifier; value intentionally withheld.",
            category="secret", cwe="CWE-798", owasp="A02:2021 Cryptographic Failures",
            description="A Git diff history search found a changed line with a secret-like identifier. This does not disclose or retain the value; verify history and rotate any exposed credential.",
            remediation="Inspect the affected historical revision with authorized tooling, rotate the credential, remove it from current code, and follow the repository's history-remediation process.",
            language="Git history",
        )
        for path in paths[:200]
        if isinstance(path, str)
    ]


def _git(root: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=12)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _safe_relative_paths(values: list[str], root: Path) -> list[str]:
    paths: set[str] = set()
    for value in values:
        candidate = value.strip().replace("\\", "/")
        if not candidate or candidate.startswith("/") or ".." in Path(candidate).parts:
            continue
        if re.fullmatch(r"[0-9a-f]{40}", candidate):
            continue
        paths.add(candidate)
    return sorted(paths)


def _history_entropy_evidence(root: Path) -> list[dict[str, str]]:
    """Detect likely high-entropy credential assignments without retaining values."""
    output = _git(root, "log", "--all", "-p", "--max-count=200") or ""
    current_path = ""
    evidence: list[dict[str, str]] = []
    for line in output.splitlines():
        if line.startswith("+++ b/"):
            current_path = line[6:].strip()
            continue
        if not current_path or not line.startswith("+") or line.startswith("+++"):
            continue
        match = HIGH_ENTROPY_VALUE.search(line[1:])
        if match and _shannon_entropy(match.group(1)) >= 3.5:
            item = {"file_path": current_path, "signal": "high_entropy_credential_assignment"}
            if item not in evidence:
                evidence.append(item)
        if len(evidence) >= 200:
            break
    return evidence


def _shannon_entropy(value: str) -> float:
    length = len(value)
    if not length:
        return 0.0
    return -sum((count / length) * math.log2(count / length) for count in {char: value.count(char) for char in set(value)}.values())
