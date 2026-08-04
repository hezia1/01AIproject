from app.models import ScaScanRequest
from app.services.sca_parser import ParsedComponent
from app.services.sca_tool_scanner import (
    build_platform_cyclonedx,
    offline_assets_dir,
    temporary_sbom_file,
)


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
