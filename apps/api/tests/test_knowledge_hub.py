from uuid import uuid4

from app.db_models import DastValidationRecord, FindingRecord, KnowledgeEntryRecord, ProjectRecord, SandboxEvidenceRecord
from app.services.knowledge_hub import (
    build_applicability,
    build_evidence_refs,
    entry_publish_ready,
    infer_knowledge_type,
    recommendation_score,
)


def make_project(name: str = "source") -> ProjectRecord:
    return ProjectRecord(id=str(uuid4()), tenant_id=str(uuid4()), name=name, default_branch="main")


def make_finding(project: ProjectRecord, *, rule_id: str = "SAST.ACCESS", status: str = "open") -> FindingRecord:
    return FindingRecord(
        id=str(uuid4()), project_id=project.id, source="SAST", rule_id=rule_id,
        title="Missing authorization", severity="high", file_path="src/routes.ts",
        evidence="Route has no role guard", status=status, ai_review={"category": "access_control"},
    )


def make_entry(project: ProjectRecord, finding: FindingRecord) -> KnowledgeEntryRecord:
    return KnowledgeEntryRecord(
        id=str(uuid4()), tenant_id=project.tenant_id, source_project_id=project.id,
        source_finding_id=finding.id, knowledge_type="vulnerability_pattern", title=finding.title,
        summary="Role guard is absent", rule_id=finding.rule_id, source_module=finding.source,
        severity=finding.severity, category="access_control", status="pending_review",
        applicability=build_applicability(project, finding), evidence_refs=[], tags=[], version=1,
        submitted_by="tester",
    )


def test_raw_finding_is_not_publish_ready() -> None:
    project = make_project()
    finding = make_finding(project)
    entry = make_entry(project, finding)
    entry.evidence_refs = build_evidence_refs(finding, [], [])

    assert infer_knowledge_type(finding, []) == "vulnerability_pattern"
    assert entry_publish_ready(entry) is False


def test_dynamic_evidence_makes_candidate_publish_ready() -> None:
    project = make_project()
    finding = make_finding(project)
    validation = DastValidationRecord(
        id=str(uuid4()), project_id=project.id, finding_id=finding.id,
        target_url="https://example.test/admin", verdict="exploitable", evidence_summary="403 bypassed",
    )
    evidence = SandboxEvidenceRecord(
        id=str(uuid4()), project_id=project.id, finding_id=finding.id, validation_id=validation.id,
        run_command="fixed-probe", network_policy="restricted", filesystem_policy="readonly",
        observed_files=[], observed_network=[], observed_processes=[], observed_tool_calls=[],
        evidence_summary="Unauthorized response reproduced",
    )
    entry = make_entry(project, finding)
    entry.knowledge_type = infer_knowledge_type(finding, [validation])
    entry.evidence_refs = build_evidence_refs(finding, [validation], [evidence])

    assert entry.knowledge_type == "validation_playbook"
    assert entry_publish_ready(entry) is True


def test_published_knowledge_recommends_only_on_meaningful_match() -> None:
    source = make_project("source")
    source_finding = make_finding(source)
    entry = make_entry(source, source_finding)
    entry.status = "published"

    target = make_project("target")
    exact = make_finding(target)
    score, reasons, matched = recommendation_score(entry, [exact])
    assert score == 100
    assert "命中相同检测规则" in reasons
    assert matched == [exact.id]

    unrelated = make_finding(target, rule_id="SAST.OTHER")
    unrelated.ai_review = {"category": "cryptography"}
    score, reasons, matched = recommendation_score(entry, [unrelated])
    assert score == 0
    assert reasons == []
    assert matched == []
