"""Explicitly managed local mirror of Semgrep Community Edition rules.

Updates are operator-triggered. Scans never contact GitHub or the Semgrep
Registry: they only consume the active, revision-pinned local snapshot.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from threading import Lock
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen
from uuid import uuid4
from zipfile import BadZipFile, ZipFile


SOURCE_REPOSITORY = "https://github.com/semgrep/semgrep-rules"
SOURCE_GIT_REPOSITORY = "https://github.com/semgrep/semgrep-rules.git"
SOURCE_API = "https://api.github.com/repos/semgrep/semgrep-rules/commits/{ref}"
SOURCE_ARCHIVE = "https://codeload.github.com/semgrep/semgrep-rules/zip/{revision}"
RULES_LICENSE_URL = "https://semgrep.dev/legal/rules-license/"
DEFAULT_SOURCE_REF = os.getenv("SAST_SEMGREP_COMMUNITY_REF", "develop")
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_BYTES = 250 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 20_000

_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
COMMUNITY_RULES_ROOT = Path(
    os.getenv(
        "SAST_SEMGREP_COMMUNITY_DIR",
        str(_REPOSITORY_ROOT / "artifacts" / "sast-offline" / "community-rules"),
    )
)
_UPDATE_LOCK = Lock()
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
_RULE_DOCUMENT = re.compile(r"(?m)^rules\s*:\s*$")
_RULE_ID = re.compile(r"(?m)^\s*-\s+id\s*:\s*[^#\s]+")

SUPPORTED_ROOTS = {
    "bash",
    "c",
    "csharp",
    "dockerfile",
    "generic",
    "go",
    "html",
    "java",
    "javascript",
    "json",
    "kotlin",
    "php",
    "problem-based-packs",
    "python",
    "ruby",
    "rust",
    "scala",
    "swift",
    "terraform",
    "typescript",
    "yaml",
}
SECURITY_PATH_MARKERS = {"audit", "owasp", "secret", "secrets", "security", "vuln", "vulnerability"}

EXTENSION_TECHNOLOGIES = {
    ".bash": "bash",
    ".c": "c",
    ".cs": "csharp",
    ".go": "go",
    ".htm": "html",
    ".html": "html",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".json": "json",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".scala": "scala",
    ".sh": "bash",
    ".swift": "swift",
    ".tf": "terraform",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".yaml": "yaml",
    ".yml": "yaml",
}


class CommunityRulesUnavailable(RuntimeError):
    pass


def community_rules_status() -> dict[str, Any]:
    pointer = _read_json(COMMUNITY_RULES_ROOT / "current.json")
    revision = str(pointer.get("revision") or "") if pointer else ""
    valid_revision = bool(re.fullmatch(r"[0-9a-f]{40}", revision))
    manifest = _read_json(COMMUNITY_RULES_ROOT / revision / "manifest.json") if valid_revision else None
    installed = bool(manifest and (COMMUNITY_RULES_ROOT / revision / "rules").is_dir())
    if not installed:
        return {
            "installed": False,
            "source": SOURCE_REPOSITORY,
            "source_ref": DEFAULT_SOURCE_REF,
            "license_url": RULES_LICENSE_URL,
            "update_mode": "manual_only",
            "root": str(COMMUNITY_RULES_ROOT),
            "revision": None,
            "updated_at": None,
            "rule_count": 0,
            "rule_file_count": 0,
            "inventory": {},
        }
    return {
        "installed": True,
        "source": SOURCE_REPOSITORY,
        "source_ref": manifest.get("source_ref"),
        "license_url": RULES_LICENSE_URL,
        "update_mode": "manual_only",
        "root": str(COMMUNITY_RULES_ROOT),
        "revision": revision,
        "updated_at": manifest.get("updated_at"),
        "rule_count": int(manifest.get("rule_count") or 0),
        "rule_file_count": int(manifest.get("rule_file_count") or 0),
        "inventory": manifest.get("inventory") if isinstance(manifest.get("inventory"), dict) else {},
        "archive_sha256": manifest.get("archive_sha256"),
    }


def update_community_rules(*, source_ref: str = DEFAULT_SOURCE_REF, license_accepted: bool = False) -> dict[str, Any]:
    from app.services.platform_policy import require_download
    require_download("semgrep_download_allowed")
    if not license_accepted:
        raise ValueError("必须先确认 Semgrep Rules License，平台才会下载社区规则")
    ref = source_ref.strip()
    if not _SAFE_REF.fullmatch(ref) or ".." in ref or ref.startswith("/") or ref.endswith("/"):
        raise ValueError("社区规则版本只能是安全的分支、标签或提交 SHA")

    with _UPDATE_LOCK:
        revision = _resolve_revision(ref)
        archive = _fetch_bytes(SOURCE_ARCHIVE.format(revision=revision), MAX_ARCHIVE_BYTES)
        archive_sha256 = hashlib.sha256(archive).hexdigest()
        target = COMMUNITY_RULES_ROOT / revision
        if not (target / "manifest.json").is_file():
            _install_archive(archive, target, ref, revision, archive_sha256)
        _write_json_atomic(COMMUNITY_RULES_ROOT / "current.json", {"revision": revision})
        return community_rules_status()


def selected_community_configs(source_path: str, *, enabled: bool = True) -> tuple[list[Path], dict[str, Any]]:
    status = community_rules_status()
    if not enabled:
        return [], {**status, "status": "disabled", "selected_technologies": [], "selected_config_count": 0}
    if not status["installed"]:
        return [], {**status, "status": "not_installed", "selected_technologies": [], "selected_config_count": 0}

    root = Path(source_path).expanduser().resolve()
    technologies = detect_project_technologies(root)
    rules_root = COMMUNITY_RULES_ROOT / str(status["revision"]) / "rules"
    configs = select_rule_directories(rules_root, technologies, project_dependency_signals(root))
    return configs, {
        **status,
        "status": "selected" if configs else "no_matching_rules",
        "selected_technologies": [path.relative_to(rules_root).as_posix() for path in configs],
        "selected_config_count": len(configs),
    }


def detect_project_technologies(root: Path) -> list[str]:
    technologies: set[str] = {"generic", "problem-based-packs"}
    if not root.is_dir():
        return []
    inspected = 0
    for path in root.rglob("*"):
        if not path.is_file() or any(part in {".git", "node_modules", "vendor", "dist", "build", "coverage"} for part in path.parts):
            continue
        inspected += 1
        technology = EXTENSION_TECHNOLOGIES.get(path.suffix.lower())
        if technology:
            technologies.add(technology)
        if path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile."):
            technologies.add("dockerfile")
        if inspected >= 5000:
            break
    return sorted(technologies)


def project_dependency_signals(root: Path) -> str:
    names = {
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "requirements.txt", "requirements-dev.txt", "pyproject.toml", "poetry.lock",
        "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "gemfile",
        "composer.json", "cargo.toml",
    }
    chunks: list[str] = []
    if not root.is_dir():
        return ""
    for path in root.rglob("*"):
        if (
            not path.is_file()
            or path.name.lower() not in names
            or any(part in {".git", "node_modules", "vendor", "dist", "build", "coverage"} for part in path.parts)
        ):
            continue
        try:
            if path.stat().st_size <= 2 * 1024 * 1024:
                chunks.append(path.read_text(encoding="utf-8", errors="ignore").lower())
        except OSError:
            continue
    return "\n".join(chunks).replace("_", "-")


def select_rule_directories(rules_root: Path, technologies: list[str], dependency_signals: str) -> list[Path]:
    selected: list[Path] = []
    for technology in technologies:
        technology_root = rules_root / technology
        if not technology_root.is_dir():
            continue
        if technology in {"generic", "problem-based-packs"}:
            selected.append(technology_root)
            continue
        base_candidates = [technology_root / "lang" / "security", technology_root / "audit", technology_root / "security"]
        bases = [candidate for candidate in base_candidates if candidate.is_dir()]
        selected.extend(bases)
        reserved = {"audit", "correctness", "lang", "security"}
        for candidate in technology_root.iterdir():
            if not candidate.is_dir() or candidate.name.lower() in reserved:
                continue
            if _framework_signal_present(candidate.name.lower(), dependency_signals):
                selected.append(candidate)
        if not bases and not any(path.parent == technology_root for path in selected):
            selected.append(technology_root)
    return sorted(dict.fromkeys(selected), key=lambda path: path.as_posix())


def _framework_signal_present(framework: str, signals: str) -> bool:
    aliases = {
        "angular": ("@angular/", "angular"),
        "apollo": ("@apollo/", "apollo-"),
        "aws-lambda": ("aws-lambda", "aws-sdk", "boto3"),
        "node-crypto": ("node:crypto",),
        "nestjs": ("@nestjs/",),
        "react": ("react", "next"),
    }
    markers = aliases.get(framework, (framework,))
    return any(re.search(rf"(?<![a-z0-9]){re.escape(marker)}(?![a-z0-9])", signals) for marker in markers)


def _resolve_revision(ref: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]{40}", ref):
        return ref.lower()
    git = shutil.which("git")
    if git:
        patterns = [ref] if ref.startswith("refs/") else [f"refs/heads/{ref}", f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"]
        environment = dict(os.environ)
        environment["GIT_TERMINAL_PROMPT"] = "0"
        environment["GIT_LFS_SKIP_SMUDGE"] = "1"
        try:
            completed = subprocess.run(
                [git, "ls-remote", SOURCE_GIT_REPOSITORY, *patterns],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=45,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired):
            completed = None
        if completed is not None and completed.returncode == 0:
            candidates = [line.split("\t", 1)[0].lower() for line in completed.stdout.splitlines() if "\t" in line]
            revision = next((value for value in reversed(candidates) if re.fullmatch(r"[0-9a-f]{40}", value)), "")
            if revision:
                return revision

    try:
        revision_payload = json.loads(_fetch_bytes(SOURCE_API.format(ref=quote(ref, safe="")), 2 * 1024 * 1024).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CommunityRulesUnavailable("Semgrep 社区规则源返回了无效的版本信息") from exc
    if not isinstance(revision_payload, dict):
        raise CommunityRulesUnavailable("Semgrep 社区规则源返回了无效的版本信息")
    revision = str(revision_payload.get("sha") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise CommunityRulesUnavailable("Semgrep 社区规则源没有返回有效提交 SHA")
    return revision


def _install_archive(archive: bytes, target: Path, source_ref: str, revision: str, archive_sha256: str) -> None:
    COMMUNITY_RULES_ROOT.mkdir(parents=True, exist_ok=True)
    if target.parent.resolve() != COMMUNITY_RULES_ROOT.resolve() or target.name != revision or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise CommunityRulesUnavailable("Semgrep 社区规则安装目标不安全")
    if target.exists():
        shutil.rmtree(target)
    staging = COMMUNITY_RULES_ROOT / f".staging-{uuid4().hex}"
    rules_target = staging / "rules"
    inventory: dict[str, dict[str, int]] = {}
    extracted_bytes = 0
    rule_count = 0
    rule_file_count = 0
    try:
        rules_target.mkdir(parents=True)
        with ZipFile(io.BytesIO(archive)) as bundle:
            infos = bundle.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                raise CommunityRulesUnavailable("Semgrep 社区规则压缩包文件数量超过安全上限")
            for info in infos:
                relative = _archive_relative_path(info.filename)
                if relative is None or info.is_dir():
                    continue
                if relative.name == "LICENSE" and len(relative.parts) == 1:
                    if info.file_size < 0 or info.file_size > 1024 * 1024:
                        raise CommunityRulesUnavailable("Semgrep 社区规则许可证文件超过安全上限")
                    (staging / "LICENSE").write_bytes(bundle.read(info))
                    continue
                if relative.suffix.lower() not in {".yml", ".yaml"} or relative.parts[0] not in SUPPORTED_ROOTS:
                    continue
                if not _security_rule_path(relative):
                    continue
                if info.file_size < 0 or extracted_bytes + info.file_size > MAX_EXTRACTED_BYTES:
                    raise CommunityRulesUnavailable("Semgrep 社区规则解压内容超过安全上限")
                content = bundle.read(info)
                extracted_bytes += len(content)
                text = content.decode("utf-8", errors="ignore")
                if not _RULE_DOCUMENT.search(text):
                    continue
                destination = rules_target.joinpath(*relative.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
                count = len(_RULE_ID.findall(text))
                channel = relative.parts[0]
                bucket = inventory.setdefault(channel, {"rule_files": 0, "rules": 0})
                bucket["rule_files"] += 1
                bucket["rules"] += count
                rule_file_count += 1
                rule_count += count
        if rule_file_count == 0 or rule_count == 0:
            raise CommunityRulesUnavailable("下载内容中没有识别到可执行的 Semgrep 安全规则")
        manifest = {
            "schema_version": 1,
            "source": SOURCE_REPOSITORY,
            "source_ref": source_ref,
            "revision": revision,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "license_url": RULES_LICENSE_URL,
            "archive_sha256": archive_sha256,
            "rule_file_count": rule_file_count,
            "rule_count": rule_count,
            "inventory": inventory,
            "selection": "security YAML only; scans select detected language/config roots",
        }
        _write_json_atomic(staging / "manifest.json", manifest)
        if os.name == "nt":
            # Renaming a large freshly extracted directory can be denied by
            # Windows file-indexing/antivirus handles. The active pointer is
            # still written only after this full copy completes.
            shutil.copytree(staging, target)
        else:
            staging.replace(target)
    except (BadZipFile, OSError) as exc:
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        raise CommunityRulesUnavailable(f"Semgrep 社区规则安装失败：{exc}") from exc
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _archive_relative_path(name: str) -> Path | None:
    normalized = name.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part]
    if len(parts) < 2 or any(part in {".", ".."} for part in parts):
        return None
    relative = Path(*parts[1:])
    if relative.is_absolute():
        return None
    return relative


def _security_rule_path(path: Path) -> bool:
    if path.parts[0] == "problem-based-packs":
        return True
    lowered = {part.lower() for part in path.parts[1:-1]}
    filename = path.stem.lower()
    return bool(lowered & SECURITY_PATH_MARKERS) or any(marker in filename for marker in SECURITY_PATH_MARKERS)


def _fetch_bytes(url: str, limit: int) -> bytes:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "ai-security-platform-community-rules/1"}
    github_token = os.getenv("GITHUB_TOKEN", "").strip()
    if github_token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {github_token}"
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=120) as response:
            try:
                declared = int(response.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                declared = 0
            if declared > limit:
                raise CommunityRulesUnavailable("Semgrep 社区规则下载超过大小上限")
            payload = response.read(limit + 1)
    except HTTPError as exc:
        if exc.code == 403 and "api.github.com" in url:
            raise CommunityRulesUnavailable("GitHub API 请求受限；请确认本机 Git 可用，或设置 GITHUB_TOKEN 后重试") from exc
        raise CommunityRulesUnavailable(f"无法连接 Semgrep 社区规则源：{exc}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise CommunityRulesUnavailable(f"无法连接 Semgrep 社区规则源：{exc}") from exc
    if len(payload) > limit:
        raise CommunityRulesUnavailable("Semgrep 社区规则下载超过大小上限")
    return payload


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)
