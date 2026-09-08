from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.security_skill_models import SecuritySkillManifest
from app.services.security_skill_registry import execute_manifest
from app.middleware.auth import is_admin_operation


def finding(**overrides):
    values = dict(id="11111111-1111-1111-1111-111111111111", source="SAST",
        rule_id="python.sql-injection", title="SQL injection", severity="high",
        status="open", file_path="app/views.py", line_start=42,
        evidence="cursor.execute(user_input)", ai_review={"category": "Injection"})
    values.update(overrides)
    return SimpleNamespace(**values)


def test_manifest_rejects_empty_selector_and_arbitrary_action():
    with pytest.raises(ValidationError):
        SecuritySkillManifest.model_validate({"selectors": {}})
    with pytest.raises(ValidationError):
        SecuritySkillManifest.model_validate({"action": "run_shell", "selectors": {"sources": ["SAST"]}})


def test_manifest_matches_existing_finding_and_keeps_evidence_references():
    manifest = SecuritySkillManifest.model_validate({
        "selectors": {"sources": ["SAST"], "categories": ["injection"], "severities": ["high"]},
        "evidence_required": ["finding_location", "finding_evidence", "ai_review"],
    })
    result = execute_manifest(manifest, [finding(), finding(id="22222222-2222-2222-2222-222222222222", severity="low")])
    assert result["current_finding_count"] == 2
    assert result["matched_count"] == 1
    assert result["matched_findings"][0]["id"] == "11111111-1111-1111-1111-111111111111"
    assert all(result["matched_findings"][0]["evidence_refs"].values())
    assert "不会重新运行" in result["limitations"][0]


def test_manifest_reports_evidence_exclusion_without_claiming_no_vulnerability():
    manifest = SecuritySkillManifest.model_validate({
        "selectors": {"rule_ids": ["python.sql-injection"]},
        "evidence_required": ["ai_review"],
    })
    result = execute_manifest(manifest, [finding(ai_review=None)])
    assert result["selector_match_count"] == 1
    assert result["matched_count"] == 0
    assert result["evidence_excluded_count"] == 1
    assert any("零命中不代表项目无漏洞" in item for item in result["limitations"])


def test_skill_governance_writes_are_admin_only_but_project_run_is_not():
    assert is_admin_operation("POST", "/api/security-skills")
    assert is_admin_operation("POST", "/api/security-skills/11111111-1111-1111-1111-111111111111/versions")
    assert is_admin_operation("POST", "/api/security-skills/11111111-1111-1111-1111-111111111111/versions/1/publish")
    assert not is_admin_operation("POST", "/api/security-skills/11111111-1111-1111-1111-111111111111/projects/22222222-2222-2222-2222-222222222222/run")
