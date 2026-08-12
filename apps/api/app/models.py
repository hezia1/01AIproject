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
    cancelled = "cancelled"


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
    metadata: dict[str, object] = Field(default_factory=dict)


class ScanTask(ScanCreate):
    id: UUID = Field(default_factory=uuid4)
    status: ScanStatus = ScanStatus.queued
    commit_hash: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    progress: int = Field(default=0, ge=0, le=100)
    stage: str | None = None
    attempt: int = 1
    queue_position: int | None = None
    error: str | None = None


class ScanProgressUpdate(BaseModel):
    progress: int = Field(ge=0, le=100)
    stage: str = Field(min_length=1, max_length=160)
    detail: str | None = Field(default=None, max_length=1000)


class FindingCreate(BaseModel):
    project_id: UUID
    scan_task_id: UUID | None = None
    component_id: UUID | None = None
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
    review_status: str | None = None
    analysis_source: str | None = None
    agent_pipeline: list[str] = Field(default_factory=list)
    review_verdict: str | None = None
    evidence_summary: str | None = None
    fix_strategy: str | None = None
    priority: str | None = None
    ai_provider: str | None = None
    ai_confidence: int | None = Field(default=None, ge=0, le=100)
    ai_review_source: str | None = None
    ai_candidate_id: str | None = None
    evidence_analysis: dict[str, object] | None = None
    knowledge: dict[str, object] | None = None
    fix_draft: dict[str, object] | None = None
    independent_review: dict[str, object] | None = None
    ai_discovery_candidates: list[dict[str, object]] = Field(default_factory=list)


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


class FindingRetestItem(BaseModel):
    identity: str
    result: str
    title: str
    file_path: str | None = None
    previous_line_start: int | None = None
    current_line_start: int | None = None
    previous_severity: Severity | None = None
    current_severity: Severity | None = None
    previous_finding_id: UUID | None = None
    current_finding_id: UUID | None = None


class FindingRetestComparison(BaseModel):
    project_id: UUID
    source: str
    has_comparison: bool = False
    previous_scan_id: UUID | None = None
    current_scan_id: UUID | None = None
    previous_scan_at: datetime | None = None
    current_scan_at: datetime | None = None
    still_present_count: int = 0
    resolved_count: int = 0
    new_count: int = 0
    changed_count: int = 0
    items: list[FindingRetestItem] = Field(default_factory=list)


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
    risk_metadata: dict[str, object] = Field(default_factory=dict)
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
    risk_metadata: dict[str, object] = Field(default_factory=dict)


class ScaScanRequest(BaseModel):
    project_id: UUID
    source_path: str = Field(min_length=1)
    clear_previous: bool = True
    enable_tool_scan: bool = True


class ScaToolStatus(BaseModel):
    enabled: bool = False
    status: str = "disabled"
    syft_component_count: int = 0
    grype_vulnerability_count: int = 0
    grype_input: str | None = None
    trivy_vulnerability_count: int = 0
    syft_status: str = "not_run"
    syft_detail: str | None = None
    grype_status: str = "not_run"
    grype_detail: str | None = None
    trivy_status: str = "not_run"
    trivy_detail: str | None = None
    errors: list[str] = Field(default_factory=list)


class ScaToolHealthCheck(BaseModel):
    name: str
    status: str
    detail: str | None = None
    remediation: str | None = None


class ScaToolHealth(BaseModel):
    status: str
    recommended_grype_input: str
    checks: list[ScaToolHealthCheck] = Field(default_factory=list)


class ScaScanResult(BaseModel):
    project_id: UUID
    scan_task_id: UUID
    source_path: str
    scanned_files: list[str]
    component_count: int
    components: list[Component]
    tool_status: ScaToolStatus | None = None
    assurance: dict[str, object] = Field(default_factory=dict)


class ScaScanHistoryItem(BaseModel):
    scan_task_id: UUID
    status: ScanStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    component_count: int = 0
    direct_dependency_count: int = 0
    transitive_dependency_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    vulnerable_count: int = 0
    license_risk_count: int = 0
    tool_status: ScaToolStatus | None = None
    osv_status: str = "not_checked"
    osv_error_count: int = 0
    assurance: dict[str, object] = Field(default_factory=dict)


class ScaScanDiffItem(BaseModel):
    ecosystem: str
    name: str
    change_type: str
    base_version: str | None = None
    target_version: str | None = None
    base_risk_status: str | None = None
    target_risk_status: str | None = None
    base_severity: Severity | None = None
    target_severity: Severity | None = None
    base_license_risk: str | None = None
    target_license_risk: str | None = None
    base_vulnerability_ids: list[str] = Field(default_factory=list)
    target_vulnerability_ids: list[str] = Field(default_factory=list)
    summary: str


class ScaScanDiffSummary(BaseModel):
    added_components: int = 0
    removed_components: int = 0
    version_changes: int = 0
    risk_added: int = 0
    risk_removed: int = 0
    license_risk_changes: int = 0
    total_changes: int = 0


class ScaScanDiffResult(BaseModel):
    project_id: UUID
    base_scan_id: UUID | None = None
    target_scan_id: UUID
    has_comparison: bool = False
    summary: ScaScanDiffSummary = Field(default_factory=ScaScanDiffSummary)
    changes: list[ScaScanDiffItem] = Field(default_factory=list)


class ScaReportComponent(BaseModel):
    ecosystem: str
    name: str
    version: str | None = None
    dependency_type: str
    risk_status: str
    severity: Severity | None = None
    vulnerability_ids: list[str] = Field(default_factory=list)
    license: str | None = None
    license_risk: str | None = None
    risk_source: str | None = None
    remediation: str | None = None


class ScaReport(BaseModel):
    project: dict[str, object | None]
    scan: dict[str, object | None]
    tool_status: ScaToolStatus | None = None
    summary: dict[str, object]
    distributions: dict[str, dict[str, int]]
    top_risk_components: list[ScaReportComponent] = Field(default_factory=list)
    trend: ScaScanDiffResult | None = None
    recommendations: list[str] = Field(default_factory=list)
    evidence: dict[str, object] = Field(default_factory=dict)


class SastScanRequest(BaseModel):
    project_id: UUID
    source_path: str = Field(min_length=1)
    clear_previous: bool = True
    semgrep_config: str = "builtin/offline-default.yml"
    include_local_rules: bool = True
    branch: str | None = Field(default=None, max_length=200)


class SastScanResult(BaseModel):
    project_id: UUID
    scan_task_id: UUID
    source_path: str
    scanned_files: list[str]
    finding_count: int
    findings: list[Finding]
    engine_status: dict[str, dict[str, object]] = Field(default_factory=dict)
    suppressed_count: int = 0

class AgentScanRequest(BaseModel):
    project_id: UUID
    source_path: str = Field(min_length=1)
    clear_previous: bool = True


class AgentRuntimePreflightRequest(BaseModel):
    command: str | None = Field(default=None, max_length=1000)
    image: str | None = Field(default=None, max_length=300)
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    operator_confirmed: bool = False


class AgentStagingBuildRequest(BaseModel):
    command: str | None = Field(default=None, max_length=1000)
    image: str | None = Field(default=None, max_length=300)
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    plan_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    operator_confirmed: bool = False


class AgentFixtureRuntimeRequest(BaseModel):
    image: str = Field(min_length=1, max_length=300)
    timeout_seconds: int = Field(default=5, ge=1, le=15)
    operator_confirmed: bool = False


class AgentTargetRuntimeRequest(BaseModel):
    command: str = Field(min_length=1, max_length=1000)
    image: str = Field(min_length=1, max_length=300)
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    plan_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    staging_build_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    staging_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    manifest_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    authorization_phrase: str = Field(min_length=1, max_length=100)
    operator_confirmed: bool = False


class AgentPermissionResult(BaseModel):
    asset_path: str
    subject: str
    capability: str
    access: str
    resource_type: str
    scope: str
    approval: str = "unknown"
    risk_level: str = "info"
    source: str


class AgentProvenanceResult(BaseModel):
    subject: str
    package_name: str | None = None
    package_version: str | None = None
    source_type: str
    source_ref: str | None = None
    installation_method: str
    version_status: str
    publisher_claim: str | None = None
    publisher_status: str
    issues: list[str] = Field(default_factory=list)


class AgentAssetResult(BaseModel):
    path: str
    asset_type: str
    format: str
    parser: str
    status: str
    checks: list[str] = Field(default_factory=list)
    finding_count: int = 0
    detail: str | None = None
    name: str | None = None
    version: str | None = None
    publisher: str | None = None
    transport: str | None = None
    entrypoint: str | None = None
    declared_tools: list[str] = Field(default_factory=list)
    declared_resources: list[str] = Field(default_factory=list)
    declared_prompts: list[str] = Field(default_factory=list)
    permission_count: int = 0
    provenance: list[AgentProvenanceResult] = Field(default_factory=list)
    file_sha256: str | None = None
    directory_sha256: str | None = None
    integrity_status: str = "unavailable"
    integrity_issues: list[str] = Field(default_factory=list)
    metadata: dict[str, object] = Field(default_factory=dict)


class AgentScanCoverage(BaseModel):
    discovered_asset_count: int = 0
    parsed_asset_count: int = 0
    failed_asset_count: int = 0
    skipped_file_count: int = 0
    findings_by_asset_type: dict[str, int] = Field(default_factory=dict)
    asset_types: dict[str, int] = Field(default_factory=dict)


class AgentScanResult(BaseModel):
    project_id: UUID
    scan_task_id: UUID
    source_path: str
    scanned_files: list[str]
    finding_count: int
    findings: list[Finding]
    assets: list[AgentAssetResult] = Field(default_factory=list)
    permissions: list[AgentPermissionResult] = Field(default_factory=list)
    coverage: AgentScanCoverage = Field(default_factory=AgentScanCoverage)
    rule_version: str
    suppressed_count: int = 0
    quality_gate: dict[str, object] = Field(default_factory=dict)
    intelligence: dict[str, object] = Field(default_factory=dict)
    dataflow: dict[str, object] = Field(default_factory=dict)
    runtime_validation: dict[str, object] = Field(default_factory=dict)
    trust_score: dict[str, object] = Field(default_factory=dict)


class AgentScanHistoryItem(BaseModel):
    scan_task_id: UUID
    status: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    source_path: str | None = None
    finding_count: int = 0
    rule_version: str | None = None
    coverage: AgentScanCoverage = Field(default_factory=AgentScanCoverage)
    gate_decision: str | None = None


class AgentScanSnapshot(BaseModel):
    project_id: UUID
    scan_task_id: UUID
    created_at: datetime
    source_path: str | None = None
    rule_version: str | None = None
    assets: list[AgentAssetResult] = Field(default_factory=list)
    permissions: list[AgentPermissionResult] = Field(default_factory=list)
    skipped_files: list[dict[str, str]] = Field(default_factory=list)
    quality_gate: dict[str, object] = Field(default_factory=dict)
    intelligence: dict[str, object] = Field(default_factory=dict)
    dataflow: dict[str, object] = Field(default_factory=dict)
    runtime_validation: dict[str, object] = Field(default_factory=dict)
    trust_score: dict[str, object] = Field(default_factory=dict)


class AgentAssetDiffItem(BaseModel):
    identity: str
    change_type: str
    path: str
    asset_type: str
    changes: list[str] = Field(default_factory=list)


class AgentPermissionDiffItem(BaseModel):
    identity: str
    change_type: str
    direction: str
    permission: AgentPermissionResult


class AgentScanDiffSummary(BaseModel):
    assets_added: int = 0
    assets_removed: int = 0
    assets_changed: int = 0
    permissions_added: int = 0
    permissions_removed: int = 0
    permissions_changed: int = 0
    source_changes: int = 0
    integrity_changes: int = 0


class AgentScanDiff(BaseModel):
    project_id: UUID
    target_scan_id: UUID
    base_scan_id: UUID | None = None
    has_comparison: bool = False
    summary: AgentScanDiffSummary = Field(default_factory=AgentScanDiffSummary)
    assets: list[AgentAssetDiffItem] = Field(default_factory=list)
    permissions: list[AgentPermissionDiffItem] = Field(default_factory=list)

class DastVerdict(str, Enum):
    exploitable = "exploitable"
    uncertain = "uncertain"
    not_exploitable = "not_exploitable"


class LinkSuggestion(BaseModel):
    finding_id: UUID | None = None
    component_id: UUID | None = None
    validation_id: UUID | None = None
    confidence: int = Field(ge=0, le=100)
    confidence_level: str
    reasons: list[str] = Field(default_factory=list)
    label: str
    source: str = "rule-engine-v1"


class DastLinkSuggestionRequest(BaseModel):
    project_id: UUID
    target_url: str = Field(min_length=1, max_length=1000)


class DastVerificationStrategy(BaseModel):
    id: str
    name: str
    description: str
    scope_summary: str
    check_items: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class SandboxLinkSuggestionRequest(BaseModel):
    project_id: UUID
    run_command: str = Field(min_length=1, max_length=1000)
    finding_id: UUID | None = None
    component_id: UUID | None = None


class DastValidationCreate(BaseModel):
    project_id: UUID
    target_url: str = Field(min_length=1, max_length=1000)
    verdict: DastVerdict
    finding_id: UUID | None = None
    component_id: UUID | None = None
    link_source: str = "unlinked"
    link_confidence: int = Field(default=0, ge=0, le=100)
    validator: str | None = None
    strategy_id: str = "web-baseline"
    strategy_name: str | None = None
    scope_summary: str | None = None
    limitations: str | None = None
    evidence_summary: str | None = None
    request_summary: str | None = None
    response_summary: str | None = None
    reproduction_steps: str | None = None
    remediation_hint: str | None = None


class DastProbeRequest(BaseModel):
    project_id: UUID
    target_url: str = Field(min_length=1, max_length=1000)
    finding_id: UUID | None = None
    component_id: UUID | None = None
    link_source: str = "unlinked"
    link_confidence: int = Field(default=0, ge=0, le=100)
    validator: str | None = "auto-dast"
    strategy_id: str = "web-baseline"


class DastValidation(DastValidationCreate):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class DastValidationUpdate(BaseModel):
    finding_id: UUID | None = None
    component_id: UUID | None = None
    link_source: str | None = None
    link_confidence: int | None = Field(default=None, ge=0, le=100)
    verdict: DastVerdict | None = None
    validator: str | None = None
    strategy_id: str | None = None
    strategy_name: str | None = None
    scope_summary: str | None = None
    limitations: str | None = None
    evidence_summary: str | None = None
    request_summary: str | None = None
    response_summary: str | None = None
    reproduction_steps: str | None = None
    remediation_hint: str | None = None

class SandboxEvidenceCreate(BaseModel):
    project_id: UUID
    run_command: str = Field(min_length=1, max_length=1000)
    finding_id: UUID | None = None
    component_id: UUID | None = None
    validation_id: UUID | None = None
    link_source: str = "unlinked"
    link_confidence: int = Field(default=0, ge=0, le=100)
    runtime_profile: str | None = None
    network_policy: str = "restricted"
    filesystem_policy: str = "readonly"
    observed_files: list[dict[str, object]] = Field(default_factory=list)
    observed_network: list[dict[str, object]] = Field(default_factory=list)
    observed_processes: list[dict[str, object]] = Field(default_factory=list)
    observed_tool_calls: list[dict[str, object]] = Field(default_factory=list)
    evidence_summary: str | None = None
    operator: str | None = None
    strategy_name: str | None = None
    purpose: str | None = None
    limitations: str | None = None


class SandboxRunRequest(BaseModel):
    project_id: UUID
    run_command: str = Field(min_length=1, max_length=1000)
    finding_id: UUID | None = None
    component_id: UUID | None = None
    validation_id: UUID | None = None
    link_source: str = "unlinked"
    link_confidence: int = Field(default=0, ge=0, le=100)
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    operator: str | None = "sandbox-runner"
    image: str | None = None
    strategy_name: str | None = None
    purpose: str | None = None
    limitations: str | None = None


class SandboxEvidence(SandboxEvidenceCreate):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class SandboxEvidenceUpdate(BaseModel):
    finding_id: UUID | None = None
    component_id: UUID | None = None
    validation_id: UUID | None = None
    link_source: str | None = None
    link_confidence: int | None = Field(default=None, ge=0, le=100)
    runtime_profile: str | None = None
    network_policy: str | None = None
    filesystem_policy: str | None = None
    observed_files: list[dict[str, object]] | None = None
    observed_network: list[dict[str, object]] | None = None
    observed_processes: list[dict[str, object]] | None = None
    observed_tool_calls: list[dict[str, object]] | None = None
    evidence_summary: str | None = None
    operator: str | None = None
    strategy_name: str | None = None
    purpose: str | None = None
    limitations: str | None = None


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
    node_id: str | None = None
    relation_type: str | None = None
    confidence: int | None = None
    created_at: datetime | None = None


class AttackChain(BaseModel):
    id: str
    name: str
    severity: Severity
    modules: list[str]
    evidence_count: int
    confidence: int
    correlation_basis: list[str] = Field(default_factory=list)
    summary: str
    recommended_action: str
    steps: list[AttackChainStep] = Field(default_factory=list)


class EvidenceGraphNode(BaseModel):
    id: str
    kind: str
    module: str
    label: str
    severity: Severity | None = None
    status: str | None = None
    detail: str | None = None
    created_at: datetime | None = None


class EvidenceGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relation_type: str
    basis: str
    confidence: int = Field(ge=0, le=100)
    created_at: datetime | None = None


class EvidenceGraph(BaseModel):
    project_id: UUID
    nodes: list[EvidenceGraphNode] = Field(default_factory=list)
    edges: list[EvidenceGraphEdge] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)


class ScaGovernanceComponent(BaseModel):
    ecosystem: str
    name: str
    version: str | None = None
    risk_status: str
    severity: str | None = None
    vulnerability_count: int = 0
    license_risk: str | None = None
    risk_source: str | None = None
    remediation: str | None = None


class ScaGovernanceSummary(BaseModel):
    latest_scan_id: UUID | None = None
    latest_scan_status: str | None = None
    latest_scan_finished_at: datetime | None = None
    component_count: int = 0
    risky_component_count: int = 0
    vulnerable_component_count: int = 0
    critical_high_component_count: int = 0
    total_finding_count: int = 0
    latest_scan_finding_count: int = 0
    vulnerability_finding_count: int = 0
    license_finding_count: int = 0
    version_review_finding_count: int = 0
    tool_status: ScaToolStatus | None = None
    top_components: list[ScaGovernanceComponent] = Field(default_factory=list)


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
    sca_governance: ScaGovernanceSummary = Field(default_factory=ScaGovernanceSummary)
    attack_chains: list[AttackChain] = Field(default_factory=list)


class ProjectSecurityReport(BaseModel):
    """Project-level delivery snapshot assembled from persisted module results."""

    generated_at: datetime = Field(default_factory=datetime.utcnow)
    project: Project
    summary: AspmProjectSummary
    components: list[Component] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    validations: list[DastValidation] = Field(default_factory=list)
    sandbox_evidence: list[SandboxEvidence] = Field(default_factory=list)
    dependency_graph: dict[str, object] = Field(default_factory=dict)
    evidence_graph: EvidenceGraph
    retest_comparisons: dict[str, FindingRetestComparison] = Field(default_factory=dict)
    capability_boundaries: dict[str, list[str]] = Field(default_factory=dict)




