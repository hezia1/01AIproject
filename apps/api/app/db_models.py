from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class TenantRecord(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class UserRecord(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "username", name="uq_user_tenant_username"),)

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("tenants.id"), nullable=False)
    username: Mapped[str] = mapped_column(String(120), nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(40), nullable=False, default="viewer")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class ProjectMembershipRecord(Base):
    __tablename__ = "project_memberships"
    __table_args__ = (UniqueConstraint("project_id", "user_id", name="uq_project_member"),)

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=False)
    role: Mapped[str] = mapped_column(String(40), nullable=False, default="viewer")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class AuditRecord(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("tenants.id"), nullable=False)
    user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id"))
    project_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"))
    action: Mapped[str] = mapped_column(String(160), nullable=False)
    outcome: Mapped[str] = mapped_column(String(40), nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class ProjectRecord(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    business_owner: Mapped[str | None] = mapped_column(String(120))
    security_owner: Mapped[str | None] = mapped_column(String(120))
    repository_url: Mapped[str | None] = mapped_column(String(500))
    source_path: Mapped[str | None] = mapped_column(String(1000))
    runtime_url: Mapped[str | None] = mapped_column(String(1000))
    api_base_url: Mapped[str | None] = mapped_column(String(1000))
    sandbox_command: Mapped[str | None] = mapped_column(String(1000))
    sandbox_image: Mapped[str | None] = mapped_column(String(300))
    default_branch: Mapped[str] = mapped_column(String(120), nullable=False, default="main")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    modules: Mapped[list["ProjectModuleRecord"]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
    )


class ProjectModuleRecord(Base):
    __tablename__ = "project_modules"
    __table_args__ = (UniqueConstraint("project_id", "module_key", name="uq_project_module"),)

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    module_key: Mapped[str] = mapped_column(String(40), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    project: Mapped[ProjectRecord] = relationship(back_populates="modules")


class ScanTaskRecord(Base):
    __tablename__ = "scan_tasks"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(80), nullable=False, default="full")
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="queued")
    commit_hash: Mapped[str | None] = mapped_column(String(80))
    scan_metadata: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    scan_task_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("scan_tasks.id"))
    component_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("components.id"))
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(300), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(800))
    line_start: Mapped[int | None] = mapped_column(Integer)
    line_end: Mapped[int | None] = mapped_column(Integer)
    evidence: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="open")
    ai_review: Mapped[dict | None] = mapped_column(JSONB)
    remediation_owner: Mapped[str | None] = mapped_column(String(120))
    remediation_note: Mapped[str | None] = mapped_column(Text)
    remediation_due_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class KnowledgeEntryRecord(Base):
    __tablename__ = "knowledge_entries"
    __table_args__ = (
        UniqueConstraint("tenant_id", "source_finding_id", name="uq_knowledge_tenant_finding"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("tenants.id"), nullable=False)
    source_project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    source_finding_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("findings.id"), nullable=False)
    knowledge_type: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(300), nullable=False)
    source_module: Mapped[str] = mapped_column(String(80), nullable=False)
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    category: Mapped[str | None] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="pending_review")
    applicability: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    evidence_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    submitted_by: Mapped[str] = mapped_column(String(120), nullable=False)
    reviewer: Mapped[str | None] = mapped_column(String(120))
    review_note: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime)
    published_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class KnowledgeEntryVersionRecord(Base):
    __tablename__ = "knowledge_entry_versions"
    __table_args__ = (
        UniqueConstraint("entry_id", "version", name="uq_knowledge_entry_version"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    entry_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("knowledge_entries.id"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    change_action: Mapped[str] = mapped_column(String(40), nullable=False)
    changed_by: Mapped[str] = mapped_column(String(120), nullable=False)
    change_note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class SastAgentRunRecord(Base):
    """Auditable DeepSeek multi-agent execution without storing credentials or raw headers."""

    __tablename__ = "sast_agent_runs"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    scan_task_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("scan_tasks.id"))
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="running")
    provider: Mapped[str] = mapped_column(String(80), nullable=False, default="deepseek")
    model: Mapped[str] = mapped_column(String(160), nullable=False)
    review_model: Mapped[str] = mapped_column(String(160), nullable=False)
    trigger: Mapped[str] = mapped_column(String(40), nullable=False, default="scan")
    agent_steps: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    result_summary: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    token_usage: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class ComponentRecord(Base):
    __tablename__ = "components"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    scan_task_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("scan_tasks.id"))
    ecosystem: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    version: Mapped[str | None] = mapped_column(String(160))
    dependency_type: Mapped[str] = mapped_column(String(80), nullable=False, default="direct")
    source_file: Mapped[str] = mapped_column(String(800), nullable=False)
    package_manager: Mapped[str | None] = mapped_column(String(80))
    license: Mapped[str | None] = mapped_column(String(120))
    risk_status: Mapped[str] = mapped_column(String(80), nullable=False, default="not_checked")
    vulnerability_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    severity: Mapped[str | None] = mapped_column(String(40))
    risk_summary: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    license_risk: Mapped[str | None] = mapped_column(String(40))
    risk_source: Mapped[str | None] = mapped_column(String(80))
    osv_checked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    osv_error: Mapped[str | None] = mapped_column(Text)
    risk_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class ScaPolicyExceptionRecord(Base):
    __tablename__ = "sca_policy_exceptions"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(40), nullable=False)
    package_name: Mapped[str] = mapped_column(String(300), nullable=False)
    package_version: Mapped[str | None] = mapped_column(String(160))
    exception_type: Mapped[str] = mapped_column(String(80), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="pending")
    requester: Mapped[str | None] = mapped_column(String(120))
    requester_role: Mapped[str | None] = mapped_column(String(40))
    approver: Mapped[str | None] = mapped_column(String(120))
    approver_role: Mapped[str | None] = mapped_column(String(40))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    approval_note: Mapped[str | None] = mapped_column(Text)
    approval_history: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class ScaPolicyOverrideRecord(Base):
    """Persist platform or project scoped SCA policy changes without mutating packaged defaults."""

    __tablename__ = "sca_policy_overrides"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"))
    policy_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(160), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    actor: Mapped[str | None] = mapped_column(String(120))
    change_note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class ScaPolicyAuditRecord(Base):
    """Append-only local audit trail for SCA policy governance operations."""

    __tablename__ = "sca_policy_audit"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"))
    policy_override_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(120))
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class ScaVexStatementRecord(Base):
    """A component-level VEX conclusion retained alongside vulnerability evidence."""

    __tablename__ = "sca_vex_statements"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(40), nullable=False)
    package_name: Mapped[str] = mapped_column(String(300), nullable=False)
    package_version: Mapped[str | None] = mapped_column(String(160))
    vulnerability_id: Mapped[str] = mapped_column(String(160), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="under_investigation")
    justification: Mapped[str | None] = mapped_column(Text)
    action_statement: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    actor: Mapped[str | None] = mapped_column(String(120))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

class DastValidationRecord(Base):
    __tablename__ = "dast_validations"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    finding_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("findings.id"))
    component_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("components.id"))
    link_source: Mapped[str] = mapped_column(String(40), nullable=False, default="unlinked")
    link_confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    target_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    verdict: Mapped[str] = mapped_column(String(40), nullable=False)
    validator: Mapped[str | None] = mapped_column(String(120))
    strategy_id: Mapped[str] = mapped_column(String(80), nullable=False, default="web-baseline")
    strategy_name: Mapped[str | None] = mapped_column(String(160))
    scope_summary: Mapped[str | None] = mapped_column(Text)
    limitations: Mapped[str | None] = mapped_column(Text)
    evidence_summary: Mapped[str | None] = mapped_column(Text)
    request_summary: Mapped[str | None] = mapped_column(Text)
    response_summary: Mapped[str | None] = mapped_column(Text)
    reproduction_steps: Mapped[str | None] = mapped_column(Text)
    remediation_hint: Mapped[str | None] = mapped_column(Text)
    validation_mode: Mapped[str] = mapped_column(String(80), nullable=False, default="manual_validation")
    connection_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

class DastVerificationPlanRecord(Base):
    __tablename__ = "dast_verification_plans"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    finding_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("findings.id"))
    component_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("components.id"))
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    target_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    authorized_scope: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_paths: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    allowed_methods: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    strategy_id: Mapped[str] = mapped_column(String(80), nullable=False)
    strategy_name: Mapped[str | None] = mapped_column(String(160))
    limitations: Mapped[str | None] = mapped_column(Text)
    requester: Mapped[str] = mapped_column(String(120), nullable=False)
    approval_status: Mapped[str] = mapped_column(String(40), nullable=False, default="draft")
    approval_reference: Mapped[str | None] = mapped_column(String(240))
    approved_by: Mapped[str | None] = mapped_column(String(120))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class DastVerificationRunRecord(Base):
    __tablename__ = "dast_verification_runs"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    plan_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("dast_verification_plans.id"), nullable=False)
    validation_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("dast_validations.id"))
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="prepared")
    execution_mode: Mapped[str] = mapped_column(String(80), nullable=False, default="documentation_only")
    operator: Mapped[str] = mapped_column(String(120), nullable=False)
    purpose: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class DastRunEvidenceRecord(Base):
    __tablename__ = "dast_run_evidence"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    plan_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("dast_verification_plans.id"), nullable=False)
    run_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("dast_verification_runs.id"), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(80), nullable=False)
    content_summary: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_reference: Mapped[str | None] = mapped_column(String(1000))
    collected_by: Mapped[str | None] = mapped_column(String(120))
    redaction_applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class DastBusinessFlowRecord(Base):
    __tablename__ = "dast_business_flows"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    finding_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("findings.id"))
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    target_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    flow_mode: Mapped[str] = mapped_column(String(40), nullable=False, default="hybrid")
    strategy_source: Mapped[str] = mapped_column(String(40), nullable=False, default="manual")
    authorized_scope: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_paths: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    roles: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    steps: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    sufficiency_criteria: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="draft")
    requester: Mapped[str] = mapped_column(String(120), nullable=False)
    approval_reference: Mapped[str | None] = mapped_column(String(240))
    approved_by: Mapped[str | None] = mapped_column(String(120))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class DastBusinessRunRecord(Base):
    __tablename__ = "dast_business_runs"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    flow_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("dast_business_flows.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="queued")
    execution_mode: Mapped[str] = mapped_column(String(40), nullable=False, default="dry_run")
    operator: Mapped[str] = mapped_column(String(120), nullable=False)
    verdict: Mapped[str | None] = mapped_column(String(40))
    verdict_reason: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class DastBusinessSnapshotRecord(Base):
    __tablename__ = "dast_business_snapshots"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    flow_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("dast_business_flows.id"), nullable=False)
    run_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("dast_business_runs.id"), nullable=False)
    step_id: Mapped[str] = mapped_column(String(120), nullable=False)
    step_kind: Mapped[str] = mapped_column(String(80), nullable=False)
    role_alias: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    request_summary: Mapped[str | None] = mapped_column(Text)
    response_summary: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class DastAssetDiscoveryRecord(Base):
    __tablename__ = "dast_asset_discoveries"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    target_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    result: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class SandboxEvidenceRecord(Base):
    __tablename__ = "sandbox_evidence"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    finding_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("findings.id"))
    component_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("components.id"))
    validation_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("dast_validations.id"))
    link_source: Mapped[str] = mapped_column(String(40), nullable=False, default="unlinked")
    link_confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    run_command: Mapped[str] = mapped_column(String(1000), nullable=False)
    runtime_profile: Mapped[str | None] = mapped_column(String(160))
    network_policy: Mapped[str] = mapped_column(String(80), nullable=False, default="restricted")
    filesystem_policy: Mapped[str] = mapped_column(String(80), nullable=False, default="readonly")
    observed_files: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    observed_network: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    observed_processes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    observed_tool_calls: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence_summary: Mapped[str | None] = mapped_column(Text)
    operator: Mapped[str | None] = mapped_column(String(120))
    strategy_name: Mapped[str | None] = mapped_column(String(160))
    purpose: Mapped[str | None] = mapped_column(Text)
    limitations: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class SandboxTargetInstanceRecord(Base):
    __tablename__ = "sandbox_target_instances"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    mode: Mapped[str] = mapped_column(String(40), nullable=False, default="external")
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="pending")
    runtime_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    internal_url: Mapped[str | None] = mapped_column(String(1000))
    image: Mapped[str | None] = mapped_column(String(300))
    command: Mapped[str | None] = mapped_column(String(1000))
    container_id: Mapped[str | None] = mapped_column(String(160))
    container_name: Mapped[str | None] = mapped_column(String(160))
    network_name: Mapped[str | None] = mapped_column(String(160))
    container_port: Mapped[int | None] = mapped_column(Integer)
    health_path: Mapped[str] = mapped_column(String(300), nullable=False, default="/")
    health_detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    policy: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    operator: Mapped[str] = mapped_column(String(120), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class SandboxTaskRecord(Base):
    __tablename__ = "sandbox_tasks"
    __table_args__ = (UniqueConstraint("source_module", "source_task_id", name="uq_sandbox_source_task"),)

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    target_instance_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("sandbox_target_instances.id"))
    source_module: Mapped[str] = mapped_column(String(40), nullable=False)
    source_task_id: Mapped[str] = mapped_column(String(160), nullable=False)
    strategy_id: Mapped[str] = mapped_column(String(160), nullable=False)
    finding_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("findings.id"))
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="queued")
    required_capabilities: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    contract: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    callback_token: Mapped[str] = mapped_column(String(200), nullable=False)
    execution_id: Mapped[str | None] = mapped_column(String(200))
    evidence: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    result_summary: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    operator: Mapped[str | None] = mapped_column(String(120))
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class SandboxTaskEventRecord(Base):
    __tablename__ = "sandbox_task_events"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    task_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("sandbox_tasks.id"), nullable=False)
    state: Mapped[str] = mapped_column(String(60), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)



