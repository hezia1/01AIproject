from datetime import datetime, timedelta
from uuid import uuid4

from app.db_models import DastBusinessFlowRecord, DastBusinessRunRecord, DastBusinessSnapshotRecord
from app.models import DastBusinessCandidate
from app.routers.dast import enrich_business_candidates_with_validation, unique_business_candidates


def candidate(finding_id, title="SQL injection") -> DastBusinessCandidate:
    return DastBusinessCandidate(
        id=finding_id,
        source="SAST",
        rule_id="SAST-SQLI-001",
        title=title,
        severity="high",
        vulnerability_type="sql_injection",
        attack_surface={"urls": ["http://target.test/api/items"], "methods": ["GET"], "parameters": ["id"]},
    )


def flow(project_id, finding_id) -> DastBusinessFlowRecord:
    now = datetime.utcnow()
    return DastBusinessFlowRecord(
        id=str(uuid4()),
        project_id=str(project_id),
        finding_id=str(finding_id),
        name="SQLi differential",
        target_url="http://target.test/api/items",
        flow_mode="api",
        strategy_source="template",
        authorized_scope="test",
        allowed_paths=["/api/items"],
        roles=[],
        steps=[],
        sufficiency_criteria={},
        requester="test",
        status="approved",
        created_at=now,
        updated_at=now,
    )


def test_candidate_is_verified_only_with_complete_sandbox_evidence():
    project_id, finding_id = uuid4(), uuid4()
    current_flow = flow(project_id, finding_id)
    completed_at = datetime.utcnow()
    dry_run = DastBusinessRunRecord(
        id=str(uuid4()), project_id=str(project_id), flow_id=current_flow.id,
        status="completed", execution_mode="dry_run", operator="test",
        verdict="uncertain", verdict_reason="dry run", created_at=completed_at - timedelta(minutes=1),
        updated_at=completed_at - timedelta(minutes=1), completed_at=completed_at - timedelta(minutes=1),
    )
    sandbox_run = DastBusinessRunRecord(
        id=str(uuid4()), project_id=str(project_id), flow_id=current_flow.id,
        status="completed", execution_mode="sandbox_handoff", operator="test",
        verdict="exploitable", verdict_reason="differential confirmed", created_at=completed_at,
        updated_at=completed_at, completed_at=completed_at,
    )
    evidence = DastBusinessSnapshotRecord(
        id=str(uuid4()), project_id=str(project_id), flow_id=current_flow.id, run_id=sandbox_run.id,
        step_id="sandbox-evidence-1", step_kind="sandbox_evidence", status="confirmed",
        detail={"complete": True, "request_id": "request-1", "evidence_type": "differential"},
        evidence_hash="a" * 64, created_at=completed_at,
    )

    result = enrich_business_candidates_with_validation(
        [candidate(finding_id)], [current_flow], [dry_run, sandbox_run], [evidence]
    )[0]

    assert result.validation_status == "verified"
    assert result.validation_count == 1
    assert str(result.latest_run_id) == sandbox_run.id
    assert str(result.latest_flow_id) == current_flow.id
    assert result.latest_verdict == "exploitable"
    assert result.latest_verdict_reason == "differential confirmed"
    assert result.latest_verified_at == completed_at


def test_deduplication_preserves_the_candidate_with_a_persisted_verdict():
    first, second = candidate(uuid4(), "new duplicate"), candidate(uuid4(), "verified duplicate")
    second = second.model_copy(update={"validation_status": "verified", "latest_verdict": "not_exploitable"})

    result = unique_business_candidates([first, second])

    assert len(result) == 1
    assert result[0].id == second.id
    assert result[0].latest_verdict == "not_exploitable"
