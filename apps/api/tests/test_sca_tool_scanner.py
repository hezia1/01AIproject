from app.models import ScaScanRequest
from app.services.sca_parser import ParsedComponent
from app.services.sca_tool_scanner import (
    build_platform_cyclonedx,
    isolated_dependency_scan_root,
    offline_assets_dir,
    temporary_sbom_file,
)
from types import SimpleNamespace


def test_default_offline_assets_directory_is_under_repository_root() -> None:
    path = offline_assets_dir()

    assert path.name == "sca-offline"
    assert path.parent.name == "artifacts"
    assert path.parent.parent.name == "AI网安项目"


def test_enhanced_sca_scan_is_enabled_by_default() -> None:
    request = ScaScanRequest(project_id="8a1d6309-0459-4083-9d9b-b8d51dc4173d", source_path="D:/project")

    assert request.enable_tool_scan is True


def test_platform_cyclonedx_fallback_contains_manifest_components() -> None:
    payload = build_platform_cyclonedx([
        ParsedComponent(
            ecosystem="npm",
            name="express",
            version="4.18.2",
            dependency_type="runtime",
            source_file="package.json",
            package_manager="npm",
        )
    ])

    assert payload["components"] == [
        {
            "type": "library",
            "name": "express",
            "bom-ref": "pkg:npm:express:4.18.2",
            "properties": [
                {"name": "sca:source", "value": "platform-parser"},
                {"name": "sca:dependency_type", "value": "runtime"},
            ],
            "version": "4.18.2",
            "purl": "pkg:npm/express@4.18.2",
        }
    ]


def test_temporary_sbom_file_stays_under_sca_offline_assets_and_is_removed() -> None:
    with temporary_sbom_file() as path:
        path.write_text("{}", encoding="utf-8")
        assert path.parent == offline_assets_dir() / "grype-cache" / "runtime"
        assert path.name.startswith("sca-sbom-")
        assert path.is_file()
    assert not path.exists()


def test_npm_dependency_resolution_uses_temporary_copy_without_mutating_source(monkeypatch, tmp_path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies":{"express":"4.18.2"}}', encoding="utf-8")

    def fake_run(command, **kwargs):
        prepared = kwargs["cwd"]
        from pathlib import Path
        Path(prepared, "package-lock.json").write_text('{"lockfileVersion":3,"packages":{}}', encoding="utf-8")
        assert "--ignore-scripts" in command
        assert "--pull=never" in command
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("app.services.sca_tool_scanner.subprocess.run", fake_run)
    with isolated_dependency_scan_root(tmp_path) as (scan_root, status, detail):
        assert status == "success"
        assert scan_root != tmp_path
        assert (scan_root / "package-lock.json").is_file()
        assert "原项目未被修改" in detail

    assert not (tmp_path / "package-lock.json").exists()
