from pathlib import Path

from app.services.sca_license_policy import load_license_policies
from app.services.sca_osv_mirror import import_osv_mirror, lookup_osv_mirror, osv_mirror_status
from app.services.sca_policy_overrides import effective_license_policies, effective_vulnerability_rules
from app.services.sca_vulnerability_rules import load_vulnerability_rules


def test_project_override_can_disable_packaged_vulnerability_rule() -> None:
    default = load_vulnerability_rules()[0]
    effective = effective_vulnerability_rules(
        (default,),
        [{"policy_kind": "vulnerability", "policy_id": default.vulnerability_id, "enabled": False, "config": {}}],
    )

    assert effective[0].vulnerability_id == default.vulnerability_id
    assert effective[0].enabled is False


def test_project_override_can_disable_packaged_license_policy() -> None:
    default = load_license_policies()[0]
    effective = effective_license_policies(
        (default,),
        [{"policy_kind": "license", "policy_id": default.policy_id, "enabled": False, "config": {}}],
    )

    assert effective[0].policy_id == default.policy_id
    assert effective[0].keywords == ()


def test_local_osv_mirror_matches_exact_component_version(tmp_path: Path) -> None:
    path = tmp_path / "osv-mirror.json"
    status = import_osv_mirror(
        [{
            "ecosystem": "pypi",
            "package": "demo-lib",
            "version": "1.2.3",
            "vulnerabilities": [{"id": "CVE-2026-1000", "severity": "high", "summary": "demo advisory"}],
        }],
        source="unit-test",
        path=path,
    )
    vulnerabilities, matched = lookup_osv_mirror("pypi", "demo-lib", "1.2.3", path=path)

    assert status["status"] == "available"
    assert status["updated_at"]
    assert osv_mirror_status(path)["entry_count"] == 1
    assert matched is True
    assert vulnerabilities[0].vulnerability_id == "CVE-2026-1000"
