from datetime import datetime
from uuid import UUID, uuid4

from app.db_models import ComponentRecord, DastValidationRecord, FindingRecord, SandboxEvidenceRecord
from app.services.aspm_evidence_graph import build_attack_chains_v2, build_evidence_graph


PROJECT_ID = UUID("11111111-1111-1111-1111-111111111111")


def component() -> ComponentRecord:
    return ComponentRecord(
        id=str(uuid4()),
        project_id=str(PROJECT_ID),
        ecosystem="PyPI",
        name="demo-package",
        version="1.0.0",
        dependency_type="direct",
        source_file="requirements.txt",
        risk_status="vulnerable",
        vulnerability_ids=["CVE-2026-0001"],
        severity="high",
        risk_summary="Known vulnerable component.",
        created_at=datetime(2026, 7, 26, 9, 0, 0),
    )


def finding(component_record: ComponentRecord) -> FindingRecord:
    return FindingRecord(
        id=str(uuid4()),
        project_id=str(PROJECT_ID),
        component_id=str(component_record.id),
        source="SCA",
        rule_id="SCA:PyPI:demo-package:CVE-2026-0001",
        title="Vulnerable dependency",
        severity="high",
        status="open",
        evidence="CVE-2026-0001 affects 1.0.0",
        created_at=datetime(2026, 7, 26, 9, 1, 0),
        updated_at=datetime(2026, 7, 26, 9, 1, 0),
    )


def validation(
    finding_record: FindingRecord | None,
    component_record: ComponentRecord | None,
) -> DastValidationRecord:
    return DastValidationRecord(
        id=str(uuid4()),
        project_id=str(PROJECT_ID),
        finding_id=str(finding_record.id) if finding_record else None,
        component_id=str(component_record.id) if component_record else None,
        link_source="explicit-selection" if finding_record or component_record else "unlinked",
        link_confidence=100 if finding_record or component_record else 0,
        target_url="https://example.test",
        verdict="exploitable",
        evidence_summary="Target is reachable and validation reproduced the risk.",
        created_at=datetime(2026, 7, 26, 9, 2, 0),
        updated_at=datetime(2026, 7, 26, 9, 2, 0),
    )


def sandbox_evidence(
    finding_record: FindingRecord,
    component_record: ComponentRecord,
    validation_record: DastValidationRecord,
) -> SandboxEvidenceRecord:
    return SandboxEvidenceRecord(
        id=str(uuid4()),
        project_id=str(PROJECT_ID),
        finding_id=str(finding_record.id),
        component_id=str(component_record.id),
        validation_id=str(validation_record.id),
        link_source="explicit-selection",
        link_confidence=95,
        run_command="python reproduce.py",
        network_policy="docker-network-none",
        filesystem_policy="readonly-source-mount",
        observed_files=[],
        observed_network=[],
        observed_processes=[],
        observed_tool_calls=[],
        evidence_summary="Sandbox execution reproduced the behavior.",
        created_at=datetime(2026, 7, 26, 9, 3, 0),
        updated_at=datetime(2026, 7, 26, 9, 3, 0),
    )


def test_unlinked_records_do_not_generate_attack_chains() -> None:
    validation_record = validation(None, None)

    chains = build_attack_chains_v2([], [], [validation_record], [])

    assert chains == []


def test_explicit_links_generate_traceable_graph_and_chain() -> None:
    component_record = component()
    finding_record = finding(component_record)
    validation_record = validation(finding_record, component_record)
    evidence_record = sandbox_evidence(finding_record, component_record, validation_record)

    graph = build_evidence_graph(
        PROJECT_ID,
        "Demo project",
        [finding_record],
        [component_record],
        [validation_record],
        [evidence_record],
    )
    chains = build_attack_chains_v2(
        [finding_record],
        [component_record],
        [validation_record],
        [evidence_record],
    )

    relation_types = {edge.relation_type for edge in graph.edges}
    assert {"reported_by", "validated_by", "observed_by"} <= relation_types
    assert graph.summary["linked_validation_count"] == 1
    assert graph.summary["linked_evidence_count"] == 1
    assert graph.summary["unlinked_validation_count"] == 0
    assert len(chains) == 1
    assert chains[0].confidence == 95
    assert chains[0].modules == ["SCA", "DAST", "SANDBOX"]
    assert chains[0].id == f"validation-chain:{validation_record.id}"
    assert all(step.node_id for step in chains[0].steps)


def test_component_only_link_is_valid_and_explainable() -> None:
    component_record = component()
    validation_record = validation(None, component_record)

    chains = build_attack_chains_v2([], [component_record], [validation_record], [])

    assert len(chains) == 1
    assert chains[0].name == "供应链组件动态验证证据链"
    assert chains[0].correlation_basis == ["explicit-selection"]
    assert chains[0].confidence == 100
