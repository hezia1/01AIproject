from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class ProjectRecord(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
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
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

class DastValidationRecord(Base):
    __tablename__ = "dast_validations"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    finding_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("findings.id"))
    target_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    verdict: Mapped[str] = mapped_column(String(40), nullable=False)
    validator: Mapped[str | None] = mapped_column(String(120))
    evidence_summary: Mapped[str | None] = mapped_column(Text)
    request_summary: Mapped[str | None] = mapped_column(Text)
    response_summary: Mapped[str | None] = mapped_column(Text)
    reproduction_steps: Mapped[str | None] = mapped_column(Text)
    remediation_hint: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

class SandboxEvidenceRecord(Base):
    __tablename__ = "sandbox_evidence"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    finding_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("findings.id"))
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
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)



