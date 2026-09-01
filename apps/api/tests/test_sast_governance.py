from datetime import datetime
import io
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
from zipfile import ZipFile

import pytest

from app.db_models import FindingRecord
from app.models import SastScanRequest
from app.services.sast_governance import add_custom_rule, add_suppression, apply_suppressions, effective_sast_profile, update_sast_profile, validate_custom_rule_payload
from app.services.sast_community_rules import _framework_signal_present, _resolve_revision, community_rules_status, selected_community_configs, update_community_rules
from app.services.sast_sarif import build_sast_sarif
from app.services.sast_scanner import scan_source_tree
from app.services.sast_semgrep_rules import BUILTIN_CONFIG, builtin_rule_pack_path
from app.services.semgrep_scanner import DEFAULT_SEMGREP_IMAGE, SemgrepUnavailable, build_semgrep_command, scan_with_semgrep
from app.routers.sast import sast_quality_gate, serialize_sast_job_payload


def test_sast_profile_keeps_a_valid_engine_enabled():
    profile = update_sast_profile({}, {"semgrep_enabled": False, "include_local_rules": True, "semgrep_config": "rules/security.yml"})

    assert profile["semgrep_enabled"] is False
    assert profile["semgrep_config"] == "rules/security.yml"
    with pytest.raises(ValueError, match="At least one SAST engine"):
        update_sast_profile({}, {"semgrep_enabled": False, "include_local_rules": False})


def test_sast_suppression_filters_matching_rule_and_path(tmp_path):
    source = tmp_path / "service.py"
    source.write_text('password = "super-secret"\n', encoding="utf-8")
    finding = scan_source_tree(str(tmp_path)).findings[0]
    profile = add_suppression({}, {"rule_id": finding.rule_id, "path_pattern": "*.py", "reason": "test-only secret"})

    kept, applied = apply_suppressions([finding], profile["suppressions"])

    assert kept == []
    assert applied[0]["rule_id"] == finding.rule_id


def test_sast_sarif_contains_location_and_rule():
    finding = FindingRecord(
        id="a0000000-0000-0000-0000-000000000001",
        project_id="a0000000-0000-0000-0000-000000000002",
        scan_task_id="a0000000-0000-0000-0000-000000000003",
        source="SAST",
        rule_id="SAST.TEST.RULE",
        title="Test finding",
        severity="high",
        file_path="src/app.py",
        line_start=12,
        line_end=12,
        evidence="dangerous call",
        ai_review={"remediation": "Use a safe API."},
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )

    sarif = build_sast_sarif([finding], str(finding.scan_task_id))
    run = sarif["runs"][0]

    assert run["tool"]["driver"]["rules"][0]["id"] == "SAST.TEST.RULE"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"


def test_default_profile_is_safe_and_normalized():
    profile = effective_sast_profile({"sast_profile": {"semgrep_config": "p/default", "suppressions": "invalid"}})

    assert profile["include_local_rules"] is True
    assert profile["community_rules_enabled"] is True
    assert profile["semgrep_config"] == BUILTIN_CONFIG
    assert profile["suppressions"] == []


def test_community_rules_profile_can_be_disabled():
    profile = update_sast_profile({}, {"community_rules_enabled": False})

    assert profile["semgrep_enabled"] is True
    assert profile["community_rules_enabled"] is False


def test_quality_gate_profile_supports_branch_and_new_finding_policies():
    profile = update_sast_profile({}, {"quality_gate": {"enabled": True, "threshold": "medium", "block_new_only": True, "max_blocking_findings": 2, "branch_patterns": ["main", "release/*"], "excluded_rule_ids": ["SAST.TEST.EXCLUDED"]}})

    assert profile["quality_gate"]["threshold"] == "medium"
    assert profile["quality_gate"]["branch_patterns"] == ["main", "release/*"]
    assert profile["quality_gate"]["block_new_only"] is True


def test_quality_gate_honors_branch_and_maximum_blocking_findings():
    finding = FindingRecord(rule_id="SAST.TEST.RULE", severity="high", file_path="app.py", line_start=1)
    profile = update_sast_profile({}, {"quality_gate": {"enabled": True, "threshold": "high", "max_blocking_findings": 2, "branch_patterns": ["main"]}})

    outside = sast_quality_gate([finding], profile, "feature/demo")
    within_allowance = sast_quality_gate([finding, finding], profile, "main")
    over_allowance = sast_quality_gate([finding, finding, finding], profile, "main")

    assert outside["status"] == "pass"
    assert within_allowance["status"] == "pass"
    assert over_allowance["status"] == "block"


def test_custom_rule_is_validated_and_runs_in_local_scanner(tmp_path):
    payload = {
        "rule_id": "CUSTOM.PROJECT.UNSAFE_LOG",
        "title": "Unsafe debug log",
        "severity": "medium",
        "category": "logging",
        "pattern": r"logger\.debug\(",
        "file_extensions": [".py"],
        "test_sample": "logger.debug('token=%s', token)",
    }
    validation = validate_custom_rule_payload(payload)
    profile = add_custom_rule({}, payload)
    source = tmp_path / "service.py"
    source.write_text("logger.debug('token=%s', token)\n", encoding="utf-8")

    result = scan_source_tree(str(tmp_path), custom_rules=profile["custom_rules"])

    assert validation["test_sample_matched"] is True
    assert [item.rule_id for item in result.findings] == ["CUSTOM.PROJECT.UNSAFE_LOG"]


def test_semgrep_docker_image_is_pinned():
    assert DEFAULT_SEMGREP_IMAGE.startswith("semgrep/semgrep:")
    assert not DEFAULT_SEMGREP_IMAGE.endswith(":latest")


def test_queued_sast_payload_does_not_persist_request_defaults():
    payload = SastScanRequest(project_id=uuid4(), source_path="D:/source")

    stored = serialize_sast_job_payload(payload, "D:\\source")

    assert stored["source_path"] == "D:\\source"
    assert "semgrep_config" not in stored
    assert "include_local_rules" not in stored
    explicit = SastScanRequest(project_id=payload.project_id, source_path="D:/source", include_local_rules=False)
    assert serialize_sast_job_payload(explicit, "D:\\source")["include_local_rules"] is False


def test_semgrep_docker_command_never_pulls(monkeypatch, tmp_path):
    calls: list[list[str]] = []

    monkeypatch.setattr("app.services.semgrep_scanner.shutil.which", lambda name: None if name == "semgrep" else "docker")

    def fake_run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("app.services.semgrep_scanner.subprocess.run", fake_run)
    command = build_semgrep_command(tmp_path, [builtin_rule_pack_path()])

    assert calls[0][:3] == ["docker", "image", "inspect"]
    assert command is not None
    assert "--pull=never" in command
    assert f"{tmp_path.resolve()}:/src:ro" in command
    assert "--metrics=off" in command


def test_semgrep_docker_command_mounts_local_rule_directory(monkeypatch, tmp_path):
    rules = tmp_path / "community" / "javascript"
    rules.mkdir(parents=True)
    (rules / "rule.yml").write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr("app.services.semgrep_scanner.shutil.which", lambda name: None if name == "semgrep" else "docker")
    monkeypatch.setattr("app.services.semgrep_scanner.subprocess.run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0))

    command = build_semgrep_command(tmp_path, [rules])

    assert command is not None
    assert f"{rules.resolve()}:/sast-config/0:ro" in command
    config_index = command.index("--config")
    assert command[config_index + 1] == "/sast-config/0"


def test_community_rules_update_is_explicit_pinned_and_language_selected(monkeypatch, tmp_path):
    revision = "a" * 40
    archive_buffer = io.BytesIO()
    with ZipFile(archive_buffer, "w") as bundle:
        bundle.writestr("semgrep-rules/LICENSE", "Semgrep Rules License v1.0")
        bundle.writestr(
            "semgrep-rules/javascript/lang/security/dangerous-eval.yml",
            "rules:\n  - id: community.javascript.dangerous-eval\n    languages: [javascript]\n    severity: ERROR\n    message: avoid eval\n    pattern: eval(...)\n",
        )
        bundle.writestr(
            "semgrep-rules/javascript/lang/correctness/style.yml",
            "rules:\n  - id: community.javascript.style\n    languages: [javascript]\n    severity: INFO\n    message: style\n    pattern: foo(...)\n",
        )
        bundle.writestr("semgrep-rules/javascript/lang/security/test.yml", "const value = eval(input)\n")
        bundle.writestr(
            "semgrep-rules/python/lang/security/exec.yml",
            "rules:\n  - id: community.python.exec\n    languages: [python]\n    severity: ERROR\n    message: avoid exec\n    pattern: exec(...)\n",
        )
        bundle.writestr(
            "semgrep-rules/javascript/express/security/open-redirect.yml",
            "rules:\n  - id: community.javascript.express.open-redirect\n    languages: [javascript]\n    severity: ERROR\n    message: validate redirects\n    pattern: $RES.redirect($REQ.query.$FIELD)\n",
        )
    archive = archive_buffer.getvalue()

    def fake_fetch(_url, _limit):
        return archive

    monkeypatch.setattr("app.services.sast_community_rules.COMMUNITY_RULES_ROOT", tmp_path / "rules-cache")
    monkeypatch.setattr("app.services.sast_community_rules._resolve_revision", lambda _ref: revision)
    monkeypatch.setattr("app.services.sast_community_rules._fetch_bytes", fake_fetch)
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.js").write_text("eval(input)\n", encoding="utf-8")
    (source / "package.json").write_text('{"dependencies":{"express":"4.21.0"}}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="Rules License"):
        update_community_rules(license_accepted=False)
    installed = update_community_rules(source_ref="develop", license_accepted=True)
    configs, selection = selected_community_configs(str(source))

    assert installed["revision"] == revision
    assert installed["rule_count"] == 3
    assert installed["rule_file_count"] == 3
    assert community_rules_status()["update_mode"] == "manual_only"
    assert [path.relative_to(tmp_path / "rules-cache" / revision / "rules").as_posix() for path in configs] == ["javascript/express", "javascript/lang/security"]
    assert selection["selected_technologies"] == ["javascript/express", "javascript/lang/security"]
    assert not (tmp_path / "rules-cache" / revision / "rules" / "javascript" / "lang" / "correctness").exists()
    (tmp_path / "rules-cache" / "current.json").write_text('{"revision":"../../outside"}', encoding="utf-8")
    assert community_rules_status()["installed"] is False


def test_community_rule_revision_prefers_git_without_github_api(monkeypatch):
    revision = "b" * 40
    monkeypatch.setattr("app.services.sast_community_rules.shutil.which", lambda name: "git" if name == "git" else None)
    monkeypatch.setattr(
        "app.services.sast_community_rules.subprocess.run",
        lambda command, **_kwargs: SimpleNamespace(returncode=0, stdout=f"{revision}\trefs/heads/develop\n", stderr=""),
    )
    monkeypatch.setattr("app.services.sast_community_rules._fetch_bytes", lambda *_args: pytest.fail("GitHub API should not be called"))

    assert _resolve_revision("develop") == revision


def test_framework_detection_uses_dependency_name_boundaries():
    signals = '{"dependencies":{"express":"4.21.0"}}'

    assert _framework_signal_present("express", signals) is True
    assert _framework_signal_present("ci", signals) is False


def test_semgrep_missing_image_degrades_without_docker_run(monkeypatch, tmp_path):
    monkeypatch.setattr("app.services.semgrep_scanner.shutil.which", lambda name: None if name == "semgrep" else "docker")
    monkeypatch.setattr("app.services.semgrep_scanner.subprocess.run", lambda *_args, **_kwargs: SimpleNamespace(returncode=1))

    with pytest.raises(SemgrepUnavailable, match="不会自动联网拉取"):
        build_semgrep_command(Path(tmp_path), [builtin_rule_pack_path()])


def test_semgrep_nonzero_json_error_is_not_reported_as_completed(monkeypatch, tmp_path):
    monkeypatch.setattr("app.services.semgrep_scanner.build_semgrep_command", lambda *_args, **_kwargs: ["semgrep"])
    monkeypatch.setattr(
        "app.services.semgrep_scanner.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=7, stdout='{"results":[],"errors":[{"message":"invalid rule"}]}', stderr=""),
    )

    with pytest.raises(SemgrepUnavailable, match="exit 7"):
        scan_with_semgrep(str(tmp_path))
