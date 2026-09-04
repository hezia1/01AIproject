"""Administrator-owned maintenance policy; defaults preserve existing behavior."""
from copy import deepcopy
import os
import re

from app.db import SessionLocal
from app.db_models import PlatformPolicyRecord

DEFAULT_POLICY = {
    "grype_download_allowed": True,
    "sca_dependency_resolution_allowed": True,
    "semgrep_download_allowed": True,
    "sandbox_image_download_allowed": True,
    "sandbox_dependency_download_allowed": True,
    "sandbox_image_repositories": ["node", "python", "golang", "maven", "gradle", "eclipse-temurin", "php", "ruby", "rust", "alpine", "postgres", "redis"],
}
DOWNLOAD_FIELDS = tuple(key for key in DEFAULT_POLICY if key.endswith("_allowed"))


def validate_policy(value: dict) -> dict:
    if set(value) != set(DEFAULT_POLICY):
        raise ValueError("配置字段不完整或包含不支持的字段")
    for key in DOWNLOAD_FIELDS:
        if type(value[key]) is not bool:
            raise ValueError(f"{key} 必须为布尔值")
    repositories = value["sandbox_image_repositories"]
    if not isinstance(repositories, list) or len(repositories) > 100:
        raise ValueError("镜像仓库白名单必须为不超过 100 项的数组")
    for name in repositories:
        # Docker Hub repositories only; no registry hosts, wildcards, shell or tags.
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)?", name):
            raise ValueError("仓库名须为 node 或 organization/image 形式；不接受通配符、标签或注册表地址")
        namespace = name.split("/", 1)[0]
        if len(name) > 200 or ("/" in name and ("." in namespace or namespace == "localhost")):
            raise ValueError("仅支持 Docker Hub 仓库名，不能使用注册表主机地址或超长名称")
    if len(set(repositories)) != len(repositories):
        raise ValueError("镜像仓库白名单不能重复")
    return deepcopy(value)


def current_policy() -> dict:
    # Do not cache: API and background workers must see saved changes.
    # Database failure is deliberately not converted to permissive defaults.
    with SessionLocal() as db:
        record = db.get(PlatformPolicyRecord, "maintenance")
        return validate_policy({**DEFAULT_POLICY, **record.config}) if record else deepcopy(DEFAULT_POLICY)


def require_download(field: str) -> None:
    if os.getenv("PLATFORM_OFFLINE_ONLY", "").lower() in {"1", "true", "yes"} or (field in {"grype_download_allowed", "sca_dependency_resolution_allowed"} and os.getenv("SCA_OFFLINE_ONLY", "").lower() in {"1", "true", "yes"}):
        raise ValueError("显式离线模式禁止联网下载；管理员配置不能覆盖离线限制。")
    if not current_policy()[field]:
        raise ValueError("管理员已禁止此类联网下载；已有本地资源仍可使用。请联系管理员修改下载策略。")


def dependency_download_allowed() -> bool:
    return current_policy()["sandbox_dependency_download_allowed"] and os.getenv("PLATFORM_OFFLINE_ONLY", "").lower() not in {"1", "true", "yes"}


def image_repository_allowed(image: str) -> bool:
    match = re.fullmatch(r"([a-z0-9._/-]+)(?::[A-Za-z0-9_.-]+|@sha256:[a-f0-9]{64})", image.strip())
    return bool(match and match.group(1) in current_policy()["sandbox_image_repositories"])
