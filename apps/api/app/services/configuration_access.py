"""Field-level boundaries for existing project configuration APIs."""
from fastapi import HTTPException, Request

from app.services.auth import current_identity


USER_SAST_PROFILE_FIELDS = frozenset({"semgrep_enabled", "community_rules_enabled"})


def require_configuration_access(request: Request, payload: dict, *, user_fields: frozenset[str] = frozenset()) -> None:
    identity = current_identity(request)
    restricted = set(payload) - user_fields
    if restricted and not identity.is_admin:
        raise HTTPException(status_code=403, detail="以下配置只能由管理员修改：" + ", ".join(sorted(restricted)))


def merge_module_configuration(defaults: dict, saved: dict | None, supplied: dict | None) -> dict:
    # Re-enabling a module must never erase its rules, exceptions or gate settings.
    return {**defaults, **(saved or {}), **(supplied or {})}


def require_scan_configuration_access(request: Request, supplied: dict, profile: dict) -> None:
    changes = {key: value for key, value in supplied.items() if key in {"semgrep_config", "include_local_rules"} and value != profile.get(key)}
    require_configuration_access(request, changes)
