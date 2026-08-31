from app.models import ScaScanRequest
from app.services.sca_parser import ParsedComponent
from app.services.sca_tool_scanner import (
    SYFT_IMAGE,
    ToolVulnerability,
    build_platform_cyclonedx,
    ensure_grype_database,
    isolated_dependency_scan_root,
    offline_assets_dir,
    parse_trivy_security_findings,
    scan_with_syft_grype,
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
    (tmp_path / "Dockerfile").write_text("FROM node:20\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.js").write_text("console.log('scan me')\n", encoding="utf-8")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "ignored.js").write_text("ignored\n", encoding="utf-8")

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
        assert (scan_root / "Dockerfile").is_file()
        assert (scan_root / "src" / "app.js").is_file()
        assert not (scan_root / "dist").exists()
        assert "原项目未被修改" in detail

    assert not (tmp_path / "package-lock.json").exists()


def test_stale_grype_database_is_not_reimported_on_every_scan(monkeypatch, tmp_path) -> None:
    database = tmp_path / "grype" / "db" / "6" / "vulnerability.db"
    database.parent.mkdir(parents=True)
    database.write_bytes(b"stale")
    calls: list[list[str]] = []

    monkeypatch.setattr("app.services.sca_tool_scanner.grype_cache_dir", lambda: tmp_path)

    def fake_health(command, timeout=20):
        calls.append(command)
        return 1, "database is too old"

    monkeypatch.setattr("app.services.sca_tool_scanner.run_health_command", fake_health)

    error = ensure_grype_database()

    assert "database is too old" in str(error)
    assert len(calls) == 1
    assert "import" not in calls[0]


def test_trivy_security_parser_never_persists_secret_match() -> None:
    payload = {
        "Results": [{
            "Target": "Dockerfile",
            "Misconfigurations": [{"ID": "DS002", "AVDID": "AVD-DS-0002", "Title": "Root user", "Severity": "HIGH", "Message": "No USER", "CauseMetadata": {"StartLine": 3}}],
            "Secrets": [{"RuleID": "github-pat", "Category": "GitHub", "Title": "GitHub token", "Severity": "CRITICAL", "StartLine": 9, "Match": "ghp_do-not-store-this"}],
        }]
    }

    findings = parse_trivy_security_findings(payload)

    assert [(item.kind, item.rule_id, item.line) for item in findings] == [
        ("misconfiguration", "AVD-DS-0002", 3),
        ("secret", "github-pat", 9),
    ]
    assert "ghp_do-not-store-this" not in repr(findings)


def test_grype_unavailable_routes_vulnerabilities_to_single_trivy_fallback(monkeypatch, tmp_path) -> None:
    syft_payload = {
        "components": [{"type": "npm", "name": "express", "version": "4.17.1", "purl": "pkg:npm/express@4.17.1"}]
    }
    trivy_calls: list[bool] = []

    monkeypatch.setattr("app.services.sca_tool_scanner.shutil.which", lambda _name: "docker")
    monkeypatch.setattr("app.services.sca_tool_scanner.ensure_grype_database", lambda: "database expired")
    monkeypatch.setattr(
        "app.services.sca_tool_scanner.run_tool_json",
        lambda _root, image, _args, **_kwargs: (syft_payload, None) if image == SYFT_IMAGE else ({}, None),
    )

    def fake_trivy(_root, include_vulnerabilities=False):
        trivy_calls.append(include_vulnerabilities)
        return ({
            "Results": [{
                "Target": "package-lock.json",
                "Vulnerabilities": [{"PkgName": "express", "InstalledVersion": "4.17.1", "VulnerabilityID": "CVE-TEST", "Severity": "HIGH"}],
                "Misconfigurations": [{"ID": "DS002", "Title": "Root user", "Severity": "HIGH"}],
            }]
        }, None, include_vulnerabilities, None)

    monkeypatch.setattr("app.services.sca_tool_scanner.run_trivy", fake_trivy)

    result = scan_with_syft_grype(str(tmp_path))

    assert trivy_calls == [True]
    assert result.grype_status == "failed"
    assert result.trivy_status == "success"
    assert result.trivy_vulnerability_fallback is True
    assert result.vulnerabilities == [ToolVulnerability("npm", "express", "4.17.1", "CVE-TEST", "high", None, None, tool="trivy")]
    assert result.trivy_misconfiguration_count == 1


def test_healthy_grype_reuses_sbom_while_trivy_skips_vulnerability_scan(monkeypatch, tmp_path) -> None:
    syft_payload = {
        "components": [{"type": "npm", "name": "express", "version": "4.17.1", "purl": "pkg:npm/express@4.17.1"}]
    }
    trivy_calls: list[bool] = []

    monkeypatch.setattr("app.services.sca_tool_scanner.shutil.which", lambda _name: "docker")
    monkeypatch.setattr("app.services.sca_tool_scanner.ensure_grype_database", lambda: None)
    monkeypatch.setattr(
        "app.services.sca_tool_scanner.run_tool_json",
        lambda _root, image, _args, **_kwargs: (syft_payload, None) if image == SYFT_IMAGE else ({}, None),
    )
    monkeypatch.setattr(
        "app.services.sca_tool_scanner.run_grype",
        lambda _root, _sbom, input_name: ({"matches": []}, None, input_name),
    )

    def fake_trivy(_root, include_vulnerabilities=False):
        trivy_calls.append(include_vulnerabilities)
        return ({"Results": []}, None, include_vulnerabilities, None)

    monkeypatch.setattr("app.services.sca_tool_scanner.run_trivy", fake_trivy)

    result = scan_with_syft_grype(str(tmp_path))

    assert trivy_calls == [False]
    assert result.grype_status == "success"
    assert result.trivy_status == "success"
    assert result.trivy_vulnerability_fallback is False
    assert result.trivy_vulnerabilities == 0


def test_failed_late_vulnerability_fallback_keeps_trivy_security_results(monkeypatch, tmp_path) -> None:
    syft_payload = {
        "components": [{"type": "npm", "name": "express", "version": "4.17.1", "purl": "pkg:npm/express@4.17.1"}]
    }
    trivy_calls: list[bool] = []

    monkeypatch.setattr("app.services.sca_tool_scanner.shutil.which", lambda _name: "docker")
    monkeypatch.setattr("app.services.sca_tool_scanner.ensure_grype_database", lambda: None)
    monkeypatch.setattr(
        "app.services.sca_tool_scanner.run_tool_json",
        lambda _root, image, _args, **_kwargs: (syft_payload, None) if image == SYFT_IMAGE else ({}, None),
    )
    monkeypatch.setattr(
        "app.services.sca_tool_scanner.run_grype",
        lambda _root, _sbom, input_name: (None, "unexpected Grype failure", input_name),
    )

    def fake_trivy(_root, include_vulnerabilities=False):
        trivy_calls.append(include_vulnerabilities)
        if include_vulnerabilities:
            return None, "fallback container failed", False, None
        return ({"Results": [{"Target": "Dockerfile", "Misconfigurations": [{"ID": "DS002", "Severity": "HIGH"}]}]}, None, False, None)

    monkeypatch.setattr("app.services.sca_tool_scanner.run_trivy", fake_trivy)

    result = scan_with_syft_grype(str(tmp_path))

    assert trivy_calls == [False, True]
    assert result.grype_status == "failed"
    assert result.trivy_status == "success"
    assert result.trivy_misconfiguration_count == 1
    assert any("漏洞回退失败" in error for error in result.errors)
