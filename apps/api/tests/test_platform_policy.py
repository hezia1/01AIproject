from copy import deepcopy
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.services import platform_policy as policy
from app.services.auth import Identity
from app.routers.platform_policy import save_policy
from app.services import sandbox_orchestrator as sandbox
from app.services.sast_community_rules import update_community_rules
from app.services.sca_tool_scanner import update_grype_database, isolated_dependency_scan_root


@pytest.fixture
def config(monkeypatch):
    value = deepcopy(policy.DEFAULT_POLICY)
    monkeypatch.setattr(policy, "current_policy", lambda: value)
    monkeypatch.delenv("PLATFORM_OFFLINE_ONLY", raising=False)
    monkeypatch.delenv("SCA_OFFLINE_ONLY", raising=False)
    return value


@pytest.mark.parametrize("image", ["node:22-alpine", "python:3.12", "node@sha256:" + "a" * 64])
def test_default_image_allowlist(config, image):
    assert policy.image_repository_allowed(image)


@pytest.mark.parametrize("image", ["node", "node:22;id", "evil/node:22", "node.evil:22", "registry.example/node:22"])
def test_allowlist_rejects_ambiguous_or_unlisted_images(config, image):
    assert not policy.image_repository_allowed(image)


def test_admin_repository_changes_are_consumed(config):
    config["sandbox_image_repositories"] = ["example/runtime"]
    assert policy.image_repository_allowed("example/runtime:1.2")
    assert not policy.image_repository_allowed("node:22")


@pytest.mark.parametrize("repositories", [["*"], ["node;id"], ["node:22"], ["node", "node"], ["registry:5000/node"], ["registry.example/node"], ["localhost/node"], "node"])
def test_validate_repository_input(config, repositories):
    config["sandbox_image_repositories"] = repositories
    with pytest.raises(ValueError):
        policy.validate_policy(config)


def test_blocked_semgrep_never_resolves_or_downloads(config, monkeypatch):
    config["semgrep_download_allowed"] = False
    monkeypatch.setattr("app.services.sast_community_rules._resolve_revision", lambda *args: pytest.fail("network called"))
    with pytest.raises(ValueError, match="管理员已禁止"):
        update_community_rules(license_accepted=True)


def test_blocked_grype_never_runs_update(config, monkeypatch):
    config["grype_download_allowed"] = False
    monkeypatch.setattr("app.services.sca_tool_scanner.grype_database_status", lambda: "unchanged-local-status")
    monkeypatch.setattr("app.services.sca_tool_scanner.run_database_command", lambda *args: pytest.fail("download called"))
    updated, message, status = update_grype_database()
    assert not updated and "管理员已禁止" in message
    assert status == "unchanged-local-status"


def test_blocked_sandbox_does_not_pull_and_keeps_local_images(config, monkeypatch):
    config["sandbox_image_download_allowed"] = False
    monkeypatch.setattr(sandbox, "_image_exists", lambda image: False)
    monkeypatch.setattr(sandbox, "_run_docker", lambda *args, **kwargs: pytest.fail("docker pull called"))
    with pytest.raises(sandbox.SandboxOrchestrationError, match="管理员已禁止"):
        sandbox._ensure_runtime_image("node:22")
    monkeypatch.setattr(sandbox, "_image_exists", lambda image: True)
    sandbox._ensure_runtime_image("node:22")


def test_explicit_offline_wins(config, monkeypatch):
    monkeypatch.setenv("PLATFORM_OFFLINE_ONLY", "true")
    with pytest.raises(ValueError, match="显式离线"):
        policy.require_download("semgrep_download_allowed")
    assert not policy.dependency_download_allowed()


def test_sca_resolution_blocked_before_copy_or_docker(config, monkeypatch, tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"example":"^1.0.0"}}')
    config["sca_dependency_resolution_allowed"] = False
    monkeypatch.setattr("app.services.sca_tool_scanner.subprocess.run", lambda *args, **kwargs: pytest.fail("network called"))
    with isolated_dependency_scan_root(tmp_path) as (root, status, detail):
        assert root == tmp_path and status == "blocked"
        assert "不能声明完整依赖覆盖" in detail


def test_sca_existing_lock_does_not_require_network_permission(config, tmp_path):
    (tmp_path / "package.json").write_text('{}')
    (tmp_path / "package-lock.json").write_text('{}')
    config["sca_dependency_resolution_allowed"] = False
    with isolated_dependency_scan_root(tmp_path) as (_, status, _):
        assert status == "not_needed"


def test_ordinary_user_cannot_save_even_with_forged_actor(config):
    request = Request({"type": "http"})
    request.state.identity = Identity("u", "t", "ordinary", "user")
    with pytest.raises(HTTPException) as error:
        save_policy({"config": config, "version": 0, "actor": "admin"}, request, None)
    assert error.value.status_code == 403


def test_database_failure_does_not_become_permissive_defaults(monkeypatch):
    def unavailable():
        raise RuntimeError("database unavailable")
    monkeypatch.setattr(policy, "SessionLocal", unavailable)
    with pytest.raises(RuntimeError, match="database unavailable"):
        policy.current_policy()
