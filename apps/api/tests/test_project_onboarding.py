from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
from zipfile import ZipFile

import pytest

from app.models import SastScanRequest
from app.db_models import ProjectRecord
from app.routers.projects import delete_project
from app.routers.sast import resolved_scan_profile
from app.services.project_onboarding import (
    ProjectOnboardingError,
    build_project_readiness,
    cleanup_managed_destination,
    extract_zip_archive,
    inspect_project_assets,
    validate_git_url,
)
from app.services.sast_scanner import scan_source_tree
from app.services.sca_parser import parse_dependency_tree


def test_asset_probe_recognizes_every_supported_dependency_family(tmp_path: Path) -> None:
    fixtures = {
        "package-lock.json": '{"name":"demo","lockfileVersion":3,"packages":{}}',
        "poetry.lock": "",
        "Pipfile.lock": '{"default":{}}',
        "Gemfile.lock": "GEM\n  specs:\n",
        "composer.lock": '{"packages":[]}',
        "Cargo.lock": "",
        "packages.lock.json": '{"dependencies":{}}',
        "demo.csproj": "<Project />",
    }
    for name, content in fixtures.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    (tmp_path / "app.rs").write_text("fn main() {}", encoding="utf-8")

    inventory = inspect_project_assets(str(tmp_path))

    assert inventory.path_exists is True
    assert inventory.dependency_file_count == len(fixtures)
    assert "sca" in inventory.recommended_tasks
    assert "sast" in inventory.recommended_tasks


def test_zip_import_extracts_a_single_safe_project_root(tmp_path: Path, monkeypatch) -> None:
    managed = tmp_path / "managed"
    monkeypatch.setenv("PROJECT_IMPORT_ROOT", str(managed))
    archive = tmp_path / "project.zip"
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("demo/package.json", '{"dependencies":{"left-pad":"1.3.0"}}')
        bundle.writestr("demo/src/app.js", "const password = 'not-a-real-secret';")

    source = extract_zip_archive(archive, "demo")

    assert source.parent.parent == managed
    assert (source / "package.json").is_file()
    assert (source / "src" / "app.js").is_file()


def test_zip_import_rejects_path_traversal(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PROJECT_IMPORT_ROOT", str(tmp_path / "managed"))
    archive = tmp_path / "unsafe.zip"
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("../outside.txt", "blocked")

    with pytest.raises(ProjectOnboardingError, match="不安全路径"):
        extract_zip_archive(archive, "unsafe")
    assert not (tmp_path / "outside.txt").exists()


def test_git_import_only_accepts_token_free_http_urls() -> None:
    validate_git_url("https://github.com/example/demo.git")
    with pytest.raises(ProjectOnboardingError):
        validate_git_url("file:///tmp/demo")
    with pytest.raises(ProjectOnboardingError, match="明文密码"):
        validate_git_url("https://user:secret@example.com/demo.git")


def test_managed_git_cleanup_removes_readonly_files_on_windows(tmp_path: Path, monkeypatch) -> None:
    managed = tmp_path / "managed"
    monkeypatch.setenv("PROJECT_IMPORT_ROOT", str(managed))
    source = managed / "demo-123" / ".git" / "objects" / "pack"
    source.mkdir(parents=True)
    readonly_file = source / "pack.idx"
    readonly_file.write_bytes(b"git-object")
    readonly_file.chmod(0o444)

    cleanup_managed_destination(source.parents[2])

    assert not (managed / "demo-123").exists()


def test_readiness_separates_static_ready_from_optional_runtime(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    project = SimpleNamespace(id=uuid4(), runtime_url=None, api_base_url=None, sandbox_command=None, sandbox_image=None)

    readiness = build_project_readiness(project, inspect_project_assets(str(tmp_path)))

    assert readiness["overall_status"] == "ready"
    assert readiness["recommended_tasks"] == ["sca", "sast"]
    checks = {item["key"]: item for item in readiness["checks"]}
    assert checks["source"]["status"] == "ready"
    assert checks["dast"]["status"] == "optional"
    assert checks["sandbox"]["status"] == "optional"


def test_quick_scanners_return_bounded_results(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\nflask==3.0.0\n", encoding="utf-8")
    for index in range(3):
        (tmp_path / f"app_{index}.py").write_text(f"password = 'secret-{index}-value'\n", encoding="utf-8")

    dependencies = parse_dependency_tree(str(tmp_path), max_components=1)
    source = scan_source_tree(str(tmp_path), max_files=1)

    assert dependencies.truncated is True
    assert len(dependencies.components) == 1
    assert source.truncated is True
    assert len(source.scanned_files) == 1


def test_quick_sast_profile_disables_external_and_history_engines() -> None:
    payload = SastScanRequest(project_id=uuid4(), source_path="C:/demo", quick_mode=True)

    profile = resolved_scan_profile(None, payload)

    assert profile["semgrep_enabled"] is False
    assert profile["include_local_rules"] is True
    assert profile["scan_git_history_secrets"] is False
    assert profile["ai_enabled"] is False


def test_project_delete_removes_dependents_before_findings_components_and_scans(tmp_path: Path) -> None:
    project_id = uuid4()
    project = ProjectRecord(id=str(project_id), tenant_id=str(uuid4()), name="delete-order", source_path=str(tmp_path), default_branch="main")

    class RecordingSession:
        def __init__(self) -> None:
            self.tables: list[str] = []
            self.deleted = None

        def get(self, _model, _key):
            return project

        def execute(self, statement):
            self.tables.append(statement.table.name)

        def delete(self, record):
            self.deleted = record

        def commit(self):
            return None

    session = RecordingSession()
    delete_project(project_id, session)  # type: ignore[arg-type]

    assert session.tables.index("sandbox_task_events") < session.tables.index("sandbox_tasks")
    assert session.tables.index("knowledge_entry_versions") < session.tables.index("knowledge_entries")
    assert session.tables.index("findings") < session.tables.index("components") < session.tables.index("scan_tasks")
    assert session.deleted is project
