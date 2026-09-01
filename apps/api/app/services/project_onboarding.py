from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4
from zipfile import BadZipFile, ZipFile

from app.services.agent_scanner import classify_agent_asset
from app.services.sca_parser import is_dependency_file


IGNORED_DIRECTORIES = {
    ".git", "node_modules", ".venv", "venv", "dist", "build", "coverage",
    "__pycache__", ".pytest_cache", ".cache", "artifacts", "outputs", "target",
}
SOURCE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".cs", ".php",
    ".rb", ".rs", ".kt", ".swift",
}
MAX_INVENTORY_FILES = 10_000
MAX_INVENTORY_BYTES = 512 * 1024 * 1024
MAX_ZIP_BYTES = 500 * 1024 * 1024
MAX_ZIP_FILES = 20_000
MAX_ZIP_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_ZIP_ENTRY_BYTES = 256 * 1024 * 1024


class ProjectOnboardingError(ValueError):
    pass


@dataclass
class ProjectAssetInventory:
    source_path: str | None
    path_exists: bool = False
    sca_files: list[str] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    agent_files: list[str] = field(default_factory=list)
    dependency_file_count: int = 0
    source_file_count: int = 0
    agent_file_count: int = 0
    inspected_file_count: int = 0
    inspected_bytes: int = 0
    truncated: bool = False
    message: str = "当前项目未配置本地源码路径"

    @property
    def recommended_tasks(self) -> list[str]:
        tasks: list[str] = []
        if self.dependency_file_count:
            tasks.append("sca")
        if self.source_file_count:
            tasks.append("sast")
        if self.agent_file_count:
            tasks.append("agent")
        return tasks


def inspect_project_assets(source_path: str | None) -> ProjectAssetInventory:
    if not source_path:
        return ProjectAssetInventory(source_path=None)
    root = Path(source_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        return ProjectAssetInventory(source_path=str(root), message="本地源码路径不存在或不是目录")

    inventory = ProjectAssetInventory(source_path=str(root), path_exists=True, message="已完成本地源码路径探测")
    for path in root.rglob("*"):
        try:
            relative_path = path.relative_to(root)
        except ValueError:
            continue
        if any(part in IGNORED_DIRECTORIES for part in relative_path.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        inventory.inspected_file_count += 1
        inventory.inspected_bytes += size
        relative = relative_path.as_posix()
        if is_dependency_file(path):
            inventory.dependency_file_count += 1
            if len(inventory.sca_files) < 20:
                inventory.sca_files.append(relative)
        if path.suffix.lower() in SOURCE_SUFFIXES:
            inventory.source_file_count += 1
            if len(inventory.source_files) < 20:
                inventory.source_files.append(relative)
        if classify_agent_asset(path, root) is not None:
            inventory.agent_file_count += 1
            if len(inventory.agent_files) < 20:
                inventory.agent_files.append(relative)
        if inventory.inspected_file_count >= MAX_INVENTORY_FILES or inventory.inspected_bytes >= MAX_INVENTORY_BYTES:
            inventory.truncated = True
            inventory.message = "源码规模超过快速盘点上限，已返回有界资产画像"
            break
    return inventory


def build_project_readiness(project: Any, inventory: ProjectAssetInventory) -> dict[str, object]:
    checks: list[dict[str, str]] = []

    def add(key: str, title: str, status: str, detail: str, remediation: str = "") -> None:
        checks.append({"key": key, "title": title, "status": status, "detail": detail, "remediation": remediation})

    if inventory.path_exists:
        add("source", "源码目录", "ready", f"目录可访问，已盘点 {inventory.inspected_file_count} 个文件。")
    else:
        add("source", "源码目录", "blocked", inventory.message, "选择本机源码文件夹、上传 ZIP，或使用 HTTP(S) Git 地址导入。")

    if inventory.dependency_file_count:
        add("sca", "SCA 依赖识别", "ready", f"识别到 {inventory.dependency_file_count} 个依赖清单或锁文件。")
    else:
        add("sca", "SCA 依赖识别", "warning", "未识别到受支持的依赖清单；SCA 将不会成为推荐任务。", "确认项目是否包含锁文件、清单文件或已安装 Python 环境。")

    if inventory.source_file_count:
        add("sast", "SAST 源码识别", "ready", f"识别到 {inventory.source_file_count} 个可扫描源码文件。")
    else:
        add("sast", "SAST 源码识别", "warning", "未识别到受支持的源码文件。", "确认提供的是源码根目录，而不是构建产物目录。")

    if inventory.agent_file_count:
        add("agent", "Agent / MCP 资产", "ready", f"识别到 {inventory.agent_file_count} 个 Agent、MCP 或插件配置。")
    else:
        add("agent", "Agent / MCP 资产", "optional", "当前项目没有识别到 Agent / MCP 配置，无需启用 AGENT 扫描。")

    if inventory.truncated:
        add("quick_scope", "快速扫描范围", "warning", "资产盘点已达到文件数或体积上限；快速扫描会限制范围并明确标记部分覆盖。", "需要完整覆盖时改用深度扫描。")
    else:
        add("quick_scope", "快速扫描范围", "ready", "项目规模处于快速盘点上限内；快速扫描将使用本地规则和离线情报。")

    runtime_url = str(getattr(project, "runtime_url", None) or getattr(project, "api_base_url", None) or "")
    if runtime_url:
        add("dast", "DAST 运行目标", "ready", "已配置项目运行地址；执行前仍需核对同源目标并授权。")
    else:
        add("dast", "DAST 运行目标", "optional", "未配置运行地址，静态扫描不受影响；DAST 将保持等待状态。", "只有导师提供可授权运行目标时才配置。")

    sandbox_ready = bool(getattr(project, "sandbox_command", None) and getattr(project, "sandbox_image", None))
    if sandbox_ready:
        add("sandbox", "SANDBOX 启动参数", "ready", "已配置隔离目标镜像和启动命令；仍需通过 DAST 审批后执行。")
    else:
        add("sandbox", "SANDBOX 启动参数", "optional", "未配置隔离目标启动参数，源码静态检测不受影响。", "需要动态证据时再选择模板或填写镜像与命令。")

    has_static_task = bool(set(inventory.recommended_tasks) & {"sca", "sast", "agent"})
    overall_status = "blocked" if not inventory.path_exists or not has_static_task else "warning" if inventory.truncated else "ready"
    return {
        "project_id": str(project.id),
        "overall_status": overall_status,
        "recommended_tasks": inventory.recommended_tasks,
        "inventory": {
            "source_path": inventory.source_path,
            "path_exists": inventory.path_exists,
            "dependency_file_count": inventory.dependency_file_count,
            "source_file_count": inventory.source_file_count,
            "agent_file_count": inventory.agent_file_count,
            "inspected_file_count": inventory.inspected_file_count,
            "inspected_bytes": inventory.inspected_bytes,
            "truncated": inventory.truncated,
        },
        "quick_scan": {
            "available": inventory.path_exists and has_static_task,
            "mode": "local_bounded",
            "limits": {
                "inventory_files": MAX_INVENTORY_FILES,
                "inventory_bytes": MAX_INVENTORY_BYTES,
                "dependency_files": 200,
                "components": 3000,
                "source_files": 1200,
                "source_bytes": 60 * 1024 * 1024,
                "module_deadline_seconds": 45,
            },
            "statement": "快速模式保留在线 OSV，并在网络失败时回退人工准备的本地镜像；Git 历史密钥和外部 AI 仍关闭，基础扫描范围仍受限。用户明确勾选的 SCA 容器增强和项目已启用的 Semgrep 会真实执行并记录状态；超过上限时保留部分结果并明确标记。",
        },
        "checks": checks,
    }


def managed_import_root() -> Path:
    configured = os.getenv("PROJECT_IMPORT_ROOT", "").strip()
    root = Path(configured).expanduser() if configured else Path(__file__).resolve().parents[4] / "artifacts" / "project-imports"
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def import_local_directory(source: str) -> Path:
    root = Path(source).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ProjectOnboardingError("本地源码路径不存在或不是目录")
    return root


def clone_git_repository(repository_url: str, branch: str = "main", timeout_seconds: int = 120) -> Path:
    validate_git_url(repository_url)
    validate_git_branch(branch)
    destination = new_import_destination(repository_url)
    command = ["git", "clone", "--depth", "1", "--single-branch", "--branch", branch, "--", repository_url, str(destination)]
    environment = os.environ.copy()
    environment.update({"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_OPTIONAL_LOCKS": "0"})
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds, env=environment, check=False)
    except FileNotFoundError as exc:
        raise ProjectOnboardingError("当前环境未安装 Git，无法导入仓库") from exc
    except subprocess.TimeoutExpired as exc:
        cleanup_managed_destination(destination)
        raise ProjectOnboardingError(f"Git 导入超过 {timeout_seconds} 秒，已停止并清理临时目录") from exc
    if completed.returncode != 0:
        cleanup_managed_destination(destination)
        detail = (completed.stderr or completed.stdout or "Git clone failed").strip()[-800:]
        raise ProjectOnboardingError(f"Git 导入失败：{detail}")
    return destination.resolve()


def extract_zip_archive(archive_path: Path, display_name: str = "project") -> Path:
    archive = archive_path.resolve()
    if not archive.exists() or not archive.is_file():
        raise ProjectOnboardingError("ZIP 文件不存在")
    if archive.stat().st_size > MAX_ZIP_BYTES:
        raise ProjectOnboardingError("ZIP 文件超过 500 MiB 接入上限")
    destination = new_import_destination(display_name)
    destination.mkdir(parents=True, exist_ok=False)
    try:
        with ZipFile(archive) as bundle:
            members = bundle.infolist()
            if not members:
                raise ProjectOnboardingError("ZIP 文件为空")
            if len(members) > MAX_ZIP_FILES:
                raise ProjectOnboardingError("ZIP 文件条目超过 20000 个")
            expanded_bytes = sum(item.file_size for item in members)
            if expanded_bytes > MAX_ZIP_EXPANDED_BYTES:
                raise ProjectOnboardingError("ZIP 解压后体积超过 1 GiB")
            for item in members:
                target = safe_zip_target(destination, item.filename)
                if item.file_size > MAX_ZIP_ENTRY_BYTES:
                    raise ProjectOnboardingError(f"ZIP 单个文件超过 256 MiB：{item.filename}")
                unix_mode = item.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    raise ProjectOnboardingError(f"ZIP 不允许符号链接：{item.filename}")
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(item) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
    except BadZipFile as exc:
        cleanup_managed_destination(destination)
        raise ProjectOnboardingError("上传内容不是有效 ZIP 文件") from exc
    except Exception:
        cleanup_managed_destination(destination)
        raise
    return collapse_single_root(destination)


def validate_git_url(repository_url: str) -> None:
    parsed = urlsplit(repository_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ProjectOnboardingError("Git 导入仅允许明确的 HTTP(S) 仓库地址")
    if parsed.password:
        raise ProjectOnboardingError("仓库地址不得包含明文密码或访问令牌")


def validate_git_branch(branch: str) -> None:
    if not branch or len(branch) > 200 or branch.startswith("-") or ".." in branch or not re.fullmatch(r"[A-Za-z0-9._/-]+", branch):
        raise ProjectOnboardingError("Git 分支名称不合法")


def new_import_destination(label: str) -> Path:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(label.rstrip("/")).stem).strip("-.")[:50] or "project"
    return managed_import_root() / f"{slug}-{uuid4().hex[:12]}"


def safe_zip_target(destination: Path, member_name: str) -> Path:
    normalized = member_name.replace("\\", "/")
    member = PurePosixPath(normalized)
    if member.is_absolute() or any(part in {"", ".", ".."} for part in member.parts):
        raise ProjectOnboardingError(f"ZIP 包含不安全路径：{member_name}")
    target = destination.joinpath(*member.parts).resolve()
    if not target.is_relative_to(destination.resolve()):
        raise ProjectOnboardingError(f"ZIP 路径越界：{member_name}")
    return target


def collapse_single_root(destination: Path) -> Path:
    children = list(destination.iterdir())
    if len(children) == 1 and children[0].is_dir():
        return children[0].resolve()
    return destination.resolve()


def cleanup_managed_destination(destination: Path) -> None:
    target = destination.resolve()
    root = managed_import_root()
    if target == root or not target.is_relative_to(root):
        return
    relative = target.relative_to(root)
    allocation = root / relative.parts[0]
    if allocation.exists():
        shutil.rmtree(allocation, onexc=_remove_readonly_entry)


def _remove_readonly_entry(function: Any, path: str, error: BaseException | tuple[Any, BaseException, Any]) -> None:
    """Retry managed-source cleanup for read-only Git objects on Windows."""
    exception = error if isinstance(error, BaseException) else error[1]
    if not isinstance(exception, PermissionError):
        raise exception
    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
    function(path)
