from pathlib import Path
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.db_models import ComponentRecord, ScanTaskRecord
from app.routers.sca import build_sca_gate_result
from app.services.sca_gate_policy import effective_gate_policy
from app.services.sca_license_policy import load_license_policies
from app.services.sca_osv_mirror import import_osv_mirror, lookup_osv_mirror, osv_mirror_status
from app.services.sca_policy_overrides import effective_license_policies, effective_vulnerability_rules
from app.services.sca_vulnerability_rules import load_vulnerability_rules
from app.services.sca_intelligence import assess_vulnerability_intelligence, import_intelligence_entries
from app.services.sca_ci import evaluate_local_gate


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


def test_offline_intelligence_enriches_cvss_epss_kev_and_fixed_version(tmp_path: Path) -> None:
    path = tmp_path / "intelligence.json"
    status = import_intelligence_entries(
        [{"cve": "CVE-2026-1000", "cvss": 9.8, "epss": 0.91, "kev": True, "fixed_version": "2.0.1"}],
        source="unit-test",
        path=path,
    )
    assessment = assess_vulnerability_intelligence(["CVE-2026-1000"], path=path)

    assert status["status"] == "available"
    assert assessment["risk_score"] >= 95
    assert assessment["kev"] is True
    assert assessment["fixed_versions"] == ["2.0.1"]


def test_effective_gate_policy_and_kev_blocking_are_machine_readable() -> None:
    project_id = uuid4()
    component = ComponentRecord(
        id=str(uuid4()), project_id=str(project_id), ecosystem="pypi", name="demo", version="1.0.0",
        dependency_type="runtime", source_file="requirements.txt", risk_status="vulnerable", vulnerability_ids=["CVE-2026-1000"],
        severity="medium", risk_metadata={"risk_score": 98, "kev": True},
    )
    scan = ScanTaskRecord(id=str(uuid4()), project_id=str(project_id), scan_type="sca", status="completed", finished_at=datetime.now())
    policy = effective_gate_policy([{"policy_kind": "gate", "policy_id": "default", "enabled": True, "config": {"min_risk_score": 90, "block_severities": []}}])

    result = build_sca_gate_result(project_id, uuid4(), [component], scan, policy)

    assert result["decision"] == "block"
    assert result["exit_code"] == 2
    assert set(result["blocked_components"][0]["reasons"]) >= {"risk_score:98", "kev"}


def gate_scan(project_id, status="completed", *, metadata=None, age_hours=1, scan_type="sca", scan_project_id=None):
    observed_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=age_hours)
    return ScanTaskRecord(
        id=str(uuid4()), project_id=str(scan_project_id or project_id), scan_type=scan_type, status=status,
        scan_metadata=metadata or {}, finished_at=observed_at, created_at=observed_at,
    )


def test_platform_gate_pass_requires_complete_current_successful_scan() -> None:
    project_id = uuid4()
    policy = {**effective_gate_policy([]), "block_severities": [], "min_risk_score": 0, "block_kev": False}
    scan = gate_scan(project_id, metadata={"assurance": {"status": "complete"}})

    result = build_sca_gate_result(project_id, uuid4(), [], scan, policy)

    assert result["decision"] == "pass"
    assert result["scan_status"] == "succeeded"
    assert result["result_complete"] is True


def test_platform_gate_blocks_every_non_successful_scan_state() -> None:
    project_id = uuid4()
    policy = {**effective_gate_policy([]), "enabled": False, "max_scan_age_hours": 168}
    cases = {
        "missing": None,
        "queued": gate_scan(project_id, "queued"),
        "running": gate_scan(project_id, "running"),
        "failed": gate_scan(project_id, "failed", metadata={"error": "scanner failed"}),
        "cancelled": gate_scan(project_id, "cancelled"),
        "partial": gate_scan(project_id, metadata={"assurance": {"status": "partial", "reasons": ["情报不完整"]}}),
        "stale": gate_scan(project_id, metadata={"assurance": {"status": "complete"}}, age_hours=169),
    }

    for expected, scan in cases.items():
        result = build_sca_gate_result(project_id, uuid4() if scan else None, [], scan, policy)
        assert result["decision"] == "block", expected
        assert result["exit_code"] == 2, expected
        assert result["scan_status"] == ("not_run" if expected == "missing" else expected)
        assert result["operational_reasons"], expected

    pending = build_sca_gate_result(project_id, uuid4(), [], gate_scan(project_id, "pending"), policy)
    assert pending["decision"] == "block"
    assert pending["scan_status"] == "queued"


def test_platform_gate_rejects_cross_project_and_non_sca_tasks() -> None:
    project_id = uuid4()
    policy = effective_gate_policy([])

    wrong_project = build_sca_gate_result(project_id, uuid4(), [], gate_scan(project_id, scan_project_id=uuid4()), policy)
    wrong_type = build_sca_gate_result(project_id, uuid4(), [], gate_scan(project_id, scan_type="sast"), policy)

    assert wrong_project["scan_status"] == "invalid"
    assert wrong_type["scan_status"] == "invalid"
    assert wrong_project["decision"] == wrong_type["decision"] == "block"


def test_local_gate_blocks_partial_assurance_even_when_risk_policy_is_disabled() -> None:
    result = evaluate_local_gate([], {**effective_gate_policy([]), "enabled": False}, {
        "status": "partial", "reasons": ["未发现受支持的依赖清单或锁文件"],
    })

    assert result["decision"] == "block"
    assert result["scan_status"] == "partial"
    assert result["result_complete"] is False
    assert result["blocked_components"] == []
