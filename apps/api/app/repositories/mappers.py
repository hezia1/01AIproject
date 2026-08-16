from uuid import UUID

from app.db_models import ComponentRecord, DastBusinessFlowRecord, DastBusinessRunRecord, DastBusinessSnapshotRecord, DastRunEvidenceRecord, DastValidationRecord, DastVerificationPlanRecord, DastVerificationRunRecord, FindingRecord, ProjectModuleRecord, ProjectRecord, SandboxEvidenceRecord, ScanTaskRecord
from app.models import AiReview, Component, DastBusinessFlow, DastBusinessRun, DastBusinessSnapshot, DastRunEvidence, DastValidation, DastVerificationPlan, DastVerificationRun, Finding, ModuleKey, Project, ProjectModule, SandboxEvidence, ScanTask


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
    metadata = record.scan_metadata or {}
    events = metadata.get("events") if isinstance(metadata.get("events"), list) else []
    return ScanTask(
        id=UUID(str(record.id)),
        project_id=UUID(str(record.project_id)),
        scan_type=record.scan_type,
        metadata=metadata,
        status=record.status,
        commit_hash=record.commit_hash,
        started_at=record.started_at,
        finished_at=record.finished_at,
        created_at=record.created_at,
        progress=int(metadata.get("progress") or (100 if record.status == "completed" else 0)),
        stage=str(metadata.get("stage")) if metadata.get("stage") else None,
        attempt=max(1, int(metadata.get("attempt") or 1)),
        queue_position=metadata.get("queue_position") if isinstance(metadata.get("queue_position"), int) else None,
        error=str(metadata.get("error")) if metadata.get("error") else None,
    )


def finding_to_schema(record: FindingRecord) -> Finding:
    ai_review = AiReview(**record.ai_review) if record.ai_review else None
    return Finding(
        id=UUID(str(record.id)),
        project_id=UUID(str(record.project_id)),
        scan_task_id=UUID(str(record.scan_task_id)) if record.scan_task_id else None,
        component_id=UUID(str(record.component_id)) if record.component_id else None,
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
        risk_metadata=record.risk_metadata or {},
        created_at=record.created_at,
    )

def dast_validation_to_schema(record: DastValidationRecord) -> DastValidation:
    return DastValidation(
        id=UUID(str(record.id)),
        project_id=UUID(str(record.project_id)),
        finding_id=UUID(str(record.finding_id)) if record.finding_id else None,
        component_id=UUID(str(record.component_id)) if record.component_id else None,
        link_source=record.link_source,
        link_confidence=record.link_confidence,
        target_url=record.target_url,
        verdict=record.verdict,
        validator=record.validator,
        strategy_id=record.strategy_id,
        strategy_name=record.strategy_name,
        scope_summary=record.scope_summary,
        limitations=record.limitations,
        evidence_summary=record.evidence_summary,
        request_summary=record.request_summary,
        response_summary=record.response_summary,
        reproduction_steps=record.reproduction_steps,
        remediation_hint=record.remediation_hint,
        created_at=record.created_at,
        updated_at=record.updated_at,
        validation_mode=record.validation_mode,
        connection_confirmed=record.connection_confirmed,
    )


def dast_plan_to_schema(record: DastVerificationPlanRecord) -> DastVerificationPlan:
    return DastVerificationPlan(
        id=UUID(str(record.id)), project_id=UUID(str(record.project_id)),
        finding_id=UUID(str(record.finding_id)) if record.finding_id else None,
        component_id=UUID(str(record.component_id)) if record.component_id else None,
        title=record.title, target_url=record.target_url, authorized_scope=record.authorized_scope,
        allowed_paths=record.allowed_paths, allowed_methods=record.allowed_methods,
        strategy_id=record.strategy_id, strategy_name=record.strategy_name,
        limitations=record.limitations, requester=record.requester,
        approval_status=record.approval_status, approval_reference=record.approval_reference,
        approved_by=record.approved_by, approved_at=record.approved_at,
        created_at=record.created_at, updated_at=record.updated_at,
    )


def dast_run_to_schema(record: DastVerificationRunRecord) -> DastVerificationRun:
    return DastVerificationRun(
        id=UUID(str(record.id)), project_id=UUID(str(record.project_id)), plan_id=UUID(str(record.plan_id)),
        validation_id=UUID(str(record.validation_id)) if record.validation_id else None,
        status=record.status, execution_mode=record.execution_mode, operator=record.operator,
        purpose=record.purpose, started_at=record.started_at, completed_at=record.completed_at,
        created_at=record.created_at, updated_at=record.updated_at,
    )


def dast_run_evidence_to_schema(record: DastRunEvidenceRecord) -> DastRunEvidence:
    return DastRunEvidence(
        id=UUID(str(record.id)), project_id=UUID(str(record.project_id)), plan_id=UUID(str(record.plan_id)),
        run_id=UUID(str(record.run_id)), evidence_type=record.evidence_type,
        content_summary=record.content_summary, content_hash=record.content_hash,
        source_reference=record.source_reference, collected_by=record.collected_by,
        redaction_applied=record.redaction_applied, created_at=record.created_at,
    )


def dast_business_flow_to_schema(record: DastBusinessFlowRecord) -> DastBusinessFlow:
    return DastBusinessFlow(
        id=UUID(str(record.id)), project_id=UUID(str(record.project_id)),
        finding_id=UUID(str(record.finding_id)) if record.finding_id else None,
        name=record.name, target_url=record.target_url, flow_mode=record.flow_mode,
        strategy_source=record.strategy_source, authorized_scope=record.authorized_scope,
        allowed_paths=record.allowed_paths, roles=record.roles, steps=record.steps,
        sufficiency_criteria=record.sufficiency_criteria, requester=record.requester,
        status=record.status, approval_reference=record.approval_reference,
        approved_by=record.approved_by, approved_at=record.approved_at,
        created_at=record.created_at, updated_at=record.updated_at,
    )


def dast_business_run_to_schema(record: DastBusinessRunRecord) -> DastBusinessRun:
    return DastBusinessRun(
        id=UUID(str(record.id)), project_id=UUID(str(record.project_id)), flow_id=UUID(str(record.flow_id)),
        status=record.status, execution_mode=record.execution_mode, operator=record.operator,
        verdict=record.verdict, verdict_reason=record.verdict_reason,
        started_at=record.started_at, completed_at=record.completed_at,
        created_at=record.created_at, updated_at=record.updated_at,
    )


def dast_business_snapshot_to_schema(record: DastBusinessSnapshotRecord) -> DastBusinessSnapshot:
    return DastBusinessSnapshot(
        id=UUID(str(record.id)), project_id=UUID(str(record.project_id)), flow_id=UUID(str(record.flow_id)),
        run_id=UUID(str(record.run_id)), step_id=record.step_id, step_kind=record.step_kind,
        role_alias=record.role_alias, status=record.status, request_summary=record.request_summary,
        response_summary=record.response_summary, detail=record.detail, evidence_hash=record.evidence_hash,
        created_at=record.created_at,
    )

def sandbox_evidence_to_schema(record: SandboxEvidenceRecord) -> SandboxEvidence:
    return SandboxEvidence(
        id=UUID(str(record.id)),
        project_id=UUID(str(record.project_id)),
        finding_id=UUID(str(record.finding_id)) if record.finding_id else None,
        component_id=UUID(str(record.component_id)) if record.component_id else None,
        validation_id=UUID(str(record.validation_id)) if record.validation_id else None,
        link_source=record.link_source,
        link_confidence=record.link_confidence,
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
        strategy_name=record.strategy_name,
        purpose=record.purpose,
        limitations=record.limitations,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )



