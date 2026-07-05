from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class FindingStatus(str, Enum):
    open = "open"
    pending = "pending"
    confirmed = "confirmed"
    fixing = "fixing"
    fixed = "fixed"
    accepted_risk = "accepted_risk"
    retest = "retest"
    closed = "closed"
    false_positive = "false_positive"


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    business_owner: str | None = None
    security_owner: str | None = None
    repository_url: str | None = None
    source_path: str | None = None
    runtime_url: str | None = None
    api_base_url: str | None = None
    sandbox_command: str | None = None
    sandbox_image: str | None = None
    default_branch: str = "main"


class Project(ProjectCreate):
    id: UUID = Field(default_factory=uuid4)
    risk_score: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    business_owner: str | None = None
    security_owner: str | None = None
    repository_url: str | None = None
    source_path: str | None = None
    runtime_url: str | None = None
    api_base_url: str | None = None
    sandbox_command: str | None = None
    sandbox_image: str | None = None
    default_branch: str | None = None


class ProjectAssetProbe(BaseModel):
    project_id: UUID
    source_path: str | None = None
    path_exists: bool = False
    sca_files: list[str] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
    agent_files: list[str] = Field(default_factory=list)
    recommended_tasks: list[str] = Field(default_factory=list)
    message: str


class ScanCreate(BaseModel):
    project_id: UUID
    scan_type: str = "full"


class ScanTask(ScanCreate):
    id: UUID = Field(default_factory=uuid4)
    status: ScanStatus = ScanStatus.queued
    commit_hash: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FindingCreate(BaseModel):
    project_id: UUID
    scan_task_id: UUID | None = None
    source: str
    rule_id: str
    title: str
    severity: Severity
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    evidence: str | None = None


class AiReview(BaseModel):
    summary: str
    false_positive_likelihood: str
    remediation: str
    category: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    language: str | None = None
    description: str | None = None
    trust_impact: str | None = None
    agent_pipeline: list[str] = Field(default_factory=list)
    review_verdict: str | None = None
    evidence_summary: str | None = None
    fix_strategy: str | None = None
    priority: str | None = None


class Finding(FindingCreate):
    id: UUID = Field(default_factory=uuid4)
    status: FindingStatus = FindingStatus.open
    ai_review: AiReview | None = None
    remediation_owner: str | None = None
    remediation_note: str | None = None
    remediation_due_at: datetime | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


class FindingGovernanceUpdate(BaseModel):
    status: FindingStatus | None = None
    remediation_owner: str | None = None
    remediation_note: str | None = None
    remediation_due_at: datetime | None = None


class ModuleKey(str, Enum):
    sast = "sast"
    sca = "sca"
    agent = "agent"
    dast = "dast"
    sandbox = "sandbox"
    aspm = "aspm"


class ModuleCategory(str, Enum):
    detection = "detection"
    validation = "validation"
    governance = "governance"
    evidence = "evidence"


class ModuleCapability(BaseModel):
    title: str
    description: str


class SecurityModule(BaseModel):
    key: ModuleKey
    code: str
    name: str
    subtitle: str
    category: ModuleCategory
    description: str
    capabilities: list[ModuleCapability]
    default_config: dict[str, object] = Field(default_factory=dict)
    dependencies: list[ModuleKey] = Field(default_factory=list)


class ProjectModuleCreate(BaseModel):
    module_key: ModuleKey
    enabled: bool = True
    config: dict[str, object] = Field(default_factory=dict)


class ProjectModule(ProjectModuleCreate):
    project_id: UUID
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ProjectModuleUpdate(BaseModel):
    enabled: bool | None = None
    config: dict[str, object] | None = None


class Component(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    project_id: UUID
    scan_task_id: UUID | None = None
    ecosystem: str
    name: str
    version: str | None = None
    dependency_type: str = "direct"
    source_file: str
    package_manager: str | None = None
    license: str | None = None
    risk_status: str = "not_checked"
    vulnerability_ids: list[str] = Field(default_factory=list)
    severity: Severity | None = None
    risk_summary: str | None = None
    remediation: str | None = None
    license_risk: str | None = None
    risk_source: str | None = None
    osv_checked: bool = False
    osv_error: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ComponentCreate(BaseModel):
    ecosystem: str
    name: str
    version: str | None = None
    dependency_type: str = "direct"
    source_file: str
    package_manager: str | None = None
    license: str | None = None
    risk_status: str = "not_checked"
    vulnerability_ids: list[str] = Field(default_factory=list)
    severity: Severity | None = None
    risk_summary: str | None = None
    remediation: str | None = None
    license_risk: str | None = None
    risk_source: str | None = None
    osv_checked: bool = False
    osv_error: str | None = None


class ScaScanRequest(BaseModel):
    project_id: UUID
    source_path: str = Field(min_length=1)
    clear_previous: bool = True


class ScaScanResult(BaseModel):
    project_id: UUID
    scan_task_id: UUID
    source_path: str
    scanned_files: list[str]
    component_count: int
    components: list[Component]


class SastScanRequest(BaseModel):
    project_id: UUID
    source_path: str = Field(min_length=1)
    clear_previous: bool = True
    semgrep_config: str = "p/default"
    include_local_rules: bool = True


class SastScanResult(BaseModel):
    project_id: UUID
    scan_task_id: UUID
    source_path: str
    scanned_files: list[str]
    finding_count: int
    findings: list[Finding]

class AgentScanRequest(BaseModel):
    project_id: UUID
    source_path: str = Field(min_length=1)
    clear_previous: bool = True


class AgentScanResult(BaseModel):
    project_id: UUID
    scan_task_id: UUID
    source_path: str
    scanned_files: list[str]
    finding_count: int
    findings: list[Finding]

class DastVerdict(str, Enum):
    exploitable = "exploitable"
    uncertain = "uncertain"
    not_exploitable = "not_exploitable"


class DastValidationCreate(BaseModel):
    project_id: UUID
    target_url: str = Field(min_length=1, max_length=1000)
    verdict: DastVerdict
    finding_id: UUID | None = None
    validator: str | None = None
    evidence_summary: str | None = None
    request_summary: str | None = None
    response_summary: str | None = None
    reproduction_steps: str | None = None
    remediation_hint: str | None = None


class DastProbeRequest(BaseModel):
    project_id: UUID
    target_url: str = Field(min_length=1, max_length=1000)
    finding_id: UUID | None = None
    validator: str | None = "auto-dast"


class DastValidation(DastValidationCreate):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class DastValidationUpdate(BaseModel):
    verdict: DastVerdict | None = None
    validator: str | None = None
    evidence_summary: str | None = None
    request_summary: str | None = None
    response_summary: str | None = None
    reproduction_steps: str | None = None
    remediation_hint: str | None = None

class SandboxEvidenceCreate(BaseModel):
    project_id: UUID
    run_command: str = Field(min_length=1, max_length=1000)
    finding_id: UUID | None = None
    runtime_profile: str | None = None
    network_policy: str = "restricted"
    filesystem_policy: str = "readonly"
    observed_files: list[dict[str, object]] = Field(default_factory=list)
    observed_network: list[dict[str, object]] = Field(default_factory=list)
    observed_processes: list[dict[str, object]] = Field(default_factory=list)
    observed_tool_calls: list[dict[str, object]] = Field(default_factory=list)
    evidence_summary: str | None = None
    operator: str | None = None


class SandboxRunRequest(BaseModel):
    project_id: UUID
    run_command: str = Field(min_length=1, max_length=1000)
    finding_id: UUID | None = None
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    operator: str | None = "sandbox-runner"
    image: str | None = None


class SandboxEvidence(SandboxEvidenceCreate):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class SandboxEvidenceUpdate(BaseModel):
    runtime_profile: str | None = None
    network_policy: str | None = None
    filesystem_policy: str | None = None
    observed_files: list[dict[str, object]] | None = None
    observed_network: list[dict[str, object]] | None = None
    observed_processes: list[dict[str, object]] | None = None
    observed_tool_calls: list[dict[str, object]] | None = None
    evidence_summary: str | None = None
    operator: str | None = None


class SandboxCommandTemplate(BaseModel):
    name: str
    command: str
    command_type: str
    image: str
    risk_level: str
    description: str


class AttackChainStep(BaseModel):
    module: str
    title: str
    evidence: str | None = None


class AttackChain(BaseModel):
    id: str
    name: str
    severity: Severity
    modules: list[str]
    evidence_count: int
    summary: str
    recommended_action: str
    steps: list[AttackChainStep] = Field(default_factory=list)


class AspmProjectSummary(BaseModel):
    project_id: UUID
    project_name: str
    enabled_modules: list[ModuleKey]
    risk_score: int
    component_count: int
    finding_count: int
    dast_validation_count: int
    sandbox_evidence_count: int
    scan_task_count: int
    findings_by_source: dict[str, int]
    findings_by_severity: dict[str, int]
    findings_by_status: dict[str, int]
    dast_by_verdict: dict[str, int]
    attack_chains: list[AttackChain] = Field(default_factory=list)




