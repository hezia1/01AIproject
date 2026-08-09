"""Bounded Git metadata collection for SAST baselines and history secrets."""
from __future__ import annotations

import re
import subprocess
import math
from pathlib import Path

from app.models import Severity
from app.services.sast_scanner import ParsedFinding
from app.services.sast_noise import is_noise_path


HIGH_ENTROPY_VALUE = re.compile(r"(?i)(?:api[_-]?key|secret|token|password|passwd|private[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_+/=.-]{20,})")
KNOWN_TOKEN_VALUE = re.compile(r"(?i)\b(sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,})\b")
PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
HISTORY_IGNORED_SUFFIXES = {".md", ".rst", ".txt", ".lock", ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif"}
PLACEHOLDER_MARKERS = ("example", "placeholder", "changeme", "change-me", "your_", "your-", "dummy", "sample", "xxxx")


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
        history_secret_evidence = _history_entropy_evidence(repo)
        history_secret_files = sorted({item["file_path"] for item in history_secret_evidence})
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
    evidence_items = context.get("history_secret_evidence")
    if not isinstance(evidence_items, list):
        return []
    findings: list[ParsedFinding] = []
    for item in evidence_items[:200]:
        if not isinstance(item, dict) or not isinstance(item.get("file_path"), str):
            continue
        signal = str(item.get("signal") or "high_confidence_secret")
        findings.append(ParsedFinding(
            rule_id="SAST.GIT.HISTORY_SECRET", title="Potential credential material in Git history",
            severity=Severity.high, file_path=str(item["file_path"]), line_start=1, line_end=1,
            evidence=f"Historical added line matched {signal}; credential value intentionally withheld.",
            category="secret", cwe="CWE-798", owasp="A02:2021 Cryptographic Failures",
            description="A Git historical added line contains a high-confidence credential signal. Identifier-only changes, documentation mentions and low-entropy placeholders are excluded; the value is never retained.",
            remediation="Inspect the affected historical revision with authorized tooling, rotate the credential, remove it from current code, and follow the repository's history-remediation process.",
            language="Git history",
        ))
    return findings


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
    current_commit = ""
    evidence: list[dict[str, str]] = []
    for line in output.splitlines():
        if line.startswith("commit ") and re.fullmatch(r"commit [0-9a-fA-F]{7,64}", line):
            current_commit = line.split(None, 1)[1][:12]
            continue
        if line.startswith("+++ b/"):
            current_path = line[6:].strip()
            continue
        if not current_path or not _history_path_allowed(current_path) or not line.startswith("+") or line.startswith("+++"):
            continue
        added = line[1:]
        match = HIGH_ENTROPY_VALUE.search(added)
        signal = ""
        if match and not _looks_like_placeholder(match.group(1)) and _shannon_entropy(match.group(1)) >= 3.5:
            signal = "high_entropy_credential_assignment"
        elif KNOWN_TOKEN_VALUE.search(added):
            signal = "provider_credential_format"
        elif PRIVATE_KEY_HEADER.search(added):
            signal = "private_key_material"
        if signal:
            item = {"file_path": current_path, "signal": signal, "commit": current_commit}
            if item not in evidence:
                evidence.append(item)
        if len(evidence) >= 200:
            break
    return evidence


def _history_path_allowed(path: str) -> bool:
    normalized = path.replace("\\", "/")
    if is_noise_path(normalized):
        return False
    return Path(normalized).suffix.lower() not in HISTORY_IGNORED_SUFFIXES


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS) or len(set(value)) < 6


def _shannon_entropy(value: str) -> float:
    length = len(value)
    if not length:
        return 0.0
    return -sum((count / length) * math.log2(count / length) for count in {char: value.count(char) for char in set(value)}.values())
