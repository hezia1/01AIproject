from uuid import UUID

from app.db_models import ComponentRecord, DastValidationRecord, FindingRecord, ProjectModuleRecord, ProjectRecord, SandboxEvidenceRecord, ScanTaskRecord
from app.models import AiReview, Component, DastValidation, Finding, ModuleKey, Project, ProjectModule, SandboxEvidence, ScanTask


def project_to_schema(record: ProjectRecord) -> Project:
    return Project(
        id=UUID(str(record.id)),
        name=record.name,
        business_owner=record.business_owner,
        security_owner=record.security_owner,
        repository_url=record.repository_url,
        source_path=record.source_path,
        runtime_url=record.runtime_url,
        api_base_url=record.api_base_url,
        sandbox_command=record.sandbox_command,
        sandbox_image=record.sandbox_image,
        default_branch=record.default_branch,
        risk_score=record.risk_score,
        created_at=record.created_at,
    )


def project_module_to_schema(record: ProjectModuleRecord) -> ProjectModule:
    return ProjectModule(
        project_id=UUID(str(record.project_id)),
        module_key=ModuleKey(record.module_key),
        enabled=record.enabled,
        config=record.config,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def scan_to_schema(record: ScanTaskRecord) -> ScanTask:
    return ScanTask(
        id=UUID(str(record.id)),
        project_id=UUID(str(record.project_id)),
        scan_type=record.scan_type,
        status=record.status,
        commit_hash=record.commit_hash,
        started_at=record.started_at,
        finished_at=record.finished_at,
        created_at=record.created_at,
    )


def finding_to_schema(record: FindingRecord) -> Finding:
    ai_review = AiReview(**record.ai_review) if record.ai_review else None
    return Finding(
        id=UUID(str(record.id)),
        project_id=UUID(str(record.project_id)),
        scan_task_id=UUID(str(record.scan_task_id)) if record.scan_task_id else None,
        source=record.source,
        rule_id=record.rule_id,
        title=record.title,
        severity=record.severity,
        file_path=record.file_path,
        line_start=record.line_start,
        line_end=record.line_end,
        evidence=record.evidence,
        status=record.status,
        ai_review=ai_review,
        remediation_owner=record.remediation_owner,
        remediation_note=record.remediation_note,
        remediation_due_at=record.remediation_due_at,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def component_to_schema(record: ComponentRecord) -> Component:
    return Component(
        id=UUID(str(record.id)),
        project_id=UUID(str(record.project_id)),
        scan_task_id=UUID(str(record.scan_task_id)) if record.scan_task_id else None,
        ecosystem=record.ecosystem,
        name=record.name,
        version=record.version,
        dependency_type=record.dependency_type,
        source_file=record.source_file,
        package_manager=record.package_manager,
        license=record.license,
        risk_status=record.risk_status,
        vulnerability_ids=record.vulnerability_ids or [],
        severity=record.severity,
        risk_summary=record.risk_summary,
        remediation=record.remediation,
        license_risk=record.license_risk,
        risk_source=record.risk_source,
        osv_checked=record.osv_checked,
        osv_error=record.osv_error,
        created_at=record.created_at,
    )

def dast_validation_to_schema(record: DastValidationRecord) -> DastValidation:
    return DastValidation(
        id=UUID(str(record.id)),
        project_id=UUID(str(record.project_id)),
        finding_id=UUID(str(record.finding_id)) if record.finding_id else None,
        target_url=record.target_url,
        verdict=record.verdict,
        validator=record.validator,
        evidence_summary=record.evidence_summary,
        request_summary=record.request_summary,
        response_summary=record.response_summary,
        reproduction_steps=record.reproduction_steps,
        remediation_hint=record.remediation_hint,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )

def sandbox_evidence_to_schema(record: SandboxEvidenceRecord) -> SandboxEvidence:
    return SandboxEvidence(
        id=UUID(str(record.id)),
        project_id=UUID(str(record.project_id)),
        finding_id=UUID(str(record.finding_id)) if record.finding_id else None,
        run_command=record.run_command,
        runtime_profile=record.runtime_profile,
        network_policy=record.network_policy,
        filesystem_policy=record.filesystem_policy,
        observed_files=record.observed_files,
        observed_network=record.observed_network,
        observed_processes=record.observed_processes,
        observed_tool_calls=record.observed_tool_calls,
        evidence_summary=record.evidence_summary,
        operator=record.operator,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )



