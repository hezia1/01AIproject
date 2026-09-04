from copy import deepcopy

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.middleware.auth import is_admin_operation
from app.services.auth import Identity
from app.services.configuration_access import USER_SAST_PROFILE_FIELDS, merge_module_configuration, require_configuration_access, require_scan_configuration_access


def request_as(role):
    request = Request({"type": "http", "method": "PATCH", "path": "/"})
    request.state.identity = Identity("user-id", "tenant-id", "test", role)
    return request


@pytest.mark.parametrize("field", ["sast_profile", "agent_profile", "quality_gate", "suppressions", "custom_rules", "semgrep_rules", "unknown_future_config"])
def test_generic_module_configuration_is_not_writable_by_user(field):
    with pytest.raises(HTTPException) as raised:
        require_configuration_access(request_as("user"), {field: {}})
    assert raised.value.status_code == 403


def test_admin_can_write_configuration_and_user_can_toggle_module():
    require_configuration_access(request_as("admin"), {"agent_profile": {}})
    require_configuration_access(request_as("user"), {})


def test_user_can_manage_semgrep_runtime_resources_but_not_other_profile_fields():
    require_configuration_access(request_as("user"), {"semgrep_enabled": True, "community_rules_enabled": False}, user_fields=USER_SAST_PROFILE_FIELDS)
    for field in ("quality_gate", "git_baseline_ref", "include_local_rules", "ai_enabled", "custom_rules", "semgrep_config"):
        with pytest.raises(HTTPException) as raised:
            require_configuration_access(request_as("user"), {"semgrep_enabled": True, field: {}}, user_fields=USER_SAST_PROFILE_FIELDS)
        assert raised.value.status_code == 403


def test_reenable_preserves_nested_policies_without_mutating_defaults():
    defaults = {"scan_depth": "standard"}
    saved = {"scan_depth": "deep", "sast_profile": {"suppressions": [{"reason": "reviewed"}], "quality_gate": {"threshold": "critical"}}}
    before = deepcopy(saved)
    assert merge_module_configuration(defaults, saved, {}) == saved
    assert saved == before
    assert defaults == {"scan_depth": "standard"}
    assert merge_module_configuration(defaults, None, {}) == defaults


def test_scan_options_cannot_replace_administrator_rule_source():
    profile = {"semgrep_config": "builtin/offline-default.yml", "include_local_rules": True}
    require_scan_configuration_access(request_as("user"), {"quick_mode": True, "semgrep_enabled": False}, profile)
    require_scan_configuration_access(request_as("user"), profile, profile)
    for options in ({"semgrep_config": "other.yml"}, {"include_local_rules": False}):
        with pytest.raises(HTTPException) as raised:
            require_scan_configuration_access(request_as("user"), options, profile)
        assert raised.value.status_code == 403
        require_scan_configuration_access(request_as("admin"), options, profile)


@pytest.mark.parametrize("method,path", [
    ("POST", "/api/sast/projects/project/suppressions"),
    ("PATCH", "/api/sast/projects/project/suppressions/rule"),
    ("POST", "/api/sca/projects/project/vex"),
    ("PATCH", "/api/sca/vex/statement"),
    ("PATCH", "/api/sca/exceptions/exception"),
    ("PATCH", "/api/agent/projects/project/profile"),
])
def test_administrative_policy_writes_require_admin(method, path):
    assert is_admin_operation(method, path)


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/sca/projects/project/vex"),
    ("POST", "/api/sca/projects/project/exceptions"),
    ("POST", "/api/agent/projects/project/exceptions"),
    ("POST", "/api/sca/grype-database/update"),
    ("POST", "/api/sast/community-rules/update"),
    ("PATCH", "/api/dast/plans/plan"),
    ("PATCH", "/api/dast/business-flows/flow"),
    ("POST", "/api/dast/plans/plan/runs"),
])
def test_user_operations_and_dast_confirmation_remain_available(method, path):
    assert not is_admin_operation(method, path)
