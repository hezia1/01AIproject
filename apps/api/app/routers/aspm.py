from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import (
    ComponentRecord,
    DastValidationRecord,
    FindingRecord,
    ProjectModuleRecord,
    ProjectRecord,
    SandboxEvidenceRecord,
    ScanTaskRecord,
)
from app.models import (
    AspmProjectSummary,
    ProjectSecurityReport,
    EvidenceGraph,
    ModuleKey,
    ScaGovernanceComponent,
    ScaGovernanceSummary,
    ScaToolStatus,
)
from app.repositories.mappers import (
    component_to_schema,
    dast_validation_to_schema,
    finding_to_schema,
    project_to_schema,
    sandbox_evidence_to_schema,
)
from app.services.aspm_evidence_graph import build_attack_chains_v2, build_evidence_graph
from app.services.finding_retest import build_finding_retest_comparison, current_finding_records
from app.services.sca_dependency_graph import build_dependency_graph

router = APIRouter()


@router.get("/projects/{project_id}/summary", response_model=AspmProjectSummary)
def get_project_summary(project_id: UUID, db: Session = Depends(get_db)) -> AspmProjectSummary:
    project = db.get(ProjectRecord, str(project_id))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    enabled_modules = [
        ModuleKey(record.module_key)
        for record in db.scalars(
            select(ProjectModuleRecord).where(
                ProjectModuleRecord.project_id == str(project_id),
                ProjectModuleRecord.enabled.is_(True),
            )
        ).all()
    ]

    component_count = count_rows(db, ComponentRecord, project_id)
    dast_validation_count = count_rows(db, DastValidationRecord, project_id)
    sandbox_evidence_count = count_rows(db, SandboxEvidenceRecord, project_id)
    scan_task_count = count_rows(db, ScanTaskRecord, project_id)

    dast_by_verdict = grouped_counts(db, DastValidationRecord.verdict, DastValidationRecord.project_id, project_id)
    all_findings = list(db.scalars(
        select(FindingRecord).where(FindingRecord.project_id == str(project_id)).order_by(FindingRecord.created_at.desc())
    ).all())
    findings = current_finding_records(db, project_id, all_findings)
    finding_count = len(findings)
    findings_by_source = record_counts(findings, "source")
    findings_by_severity = record_counts(findings, "severity")
    findings_by_status = record_counts(findings, "status")
    components = db.scalars(
        select(ComponentRecord)
        .where(ComponentRecord.project_id == str(project_id))
        .order_by(ComponentRecord.created_at.desc())
    ).all()
    validations = db.scalars(
        select(DastValidationRecord)
        .where(DastValidationRecord.project_id == str(project_id))
        .order_by(DastValidationRecord.created_at.desc())
    ).all()
    sandbox_evidence = db.scalars(
        select(SandboxEvidenceRecord)
        .where(SandboxEvidenceRecord.project_id == str(project_id))
        .order_by(SandboxEvidenceRecord.created_at.desc())
    ).all()

    risk_score = calculate_risk_score(
        findings_by_severity=findings_by_severity,
        dast_by_verdict=dast_by_verdict,
        sandbox_evidence_count=sandbox_evidence_count,
    )

    return AspmProjectSummary(
        project_id=project_id,
        project_name=project.name,
        enabled_modules=enabled_modules,
        risk_score=risk_score,
        component_count=component_count,
        finding_count=finding_count,
        dast_validation_count=dast_validation_count,
        sandbox_evidence_count=sandbox_evidence_count,
        scan_task_count=scan_task_count,
        findings_by_source=findings_by_source,
        findings_by_severity=findings_by_severity,
        findings_by_status=findings_by_status,
        dast_by_verdict=dast_by_verdict,
        sca_governance=build_sca_governance_summary(db, project_id),
        attack_chains=build_attack_chains_v2(all_findings, components, validations, sandbox_evidence),
    )


@router.get("/projects/{project_id}/report", response_model=ProjectSecurityReport)
def get_project_security_report(project_id: UUID, db: Session = Depends(get_db)) -> ProjectSecurityReport:
    """Return an export-ready, traceable snapshot of all currently relevant project results."""
    project = db.get(ProjectRecord, str(project_id))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    all_findings = list(
        db.scalars(
            select(FindingRecord)
            .where(FindingRecord.project_id == str(project_id))
            .order_by(FindingRecord.created_at.desc())
        ).all()
    )
    findings = current_finding_records(db, project_id, all_findings)
    components = list(
        db.scalars(
            select(ComponentRecord)
            .where(ComponentRecord.project_id == str(project_id))
            .order_by(ComponentRecord.created_at.desc())
        ).all()
    )
    validations = list(
        db.scalars(
            select(DastValidationRecord)
            .where(DastValidationRecord.project_id == str(project_id))
            .order_by(DastValidationRecord.created_at.desc())
        ).all()
    )
    evidence_records = list(
        db.scalars(
            select(SandboxEvidenceRecord)
            .where(SandboxEvidenceRecord.project_id == str(project_id))
            .order_by(SandboxEvidenceRecord.created_at.desc())
        ).all()
    )

    return ProjectSecurityReport(
        project=project_to_schema(project),
        summary=get_project_summary(project_id, db),
        components=[component_to_schema(item) for item in components],
        findings=[finding_to_schema(item) for item in findings],
        validations=[dast_validation_to_schema(item) for item in validations],
        sandbox_evidence=[sandbox_evidence_to_schema(item) for item in evidence_records],
        dependency_graph=build_dependency_graph(project, components),
        evidence_graph=build_evidence_graph(
            project_id, project.name, all_findings, components, validations, evidence_records
        ),
        retest_comparisons={
            source.lower(): build_finding_retest_comparison(db, project_id, source)
            for source in ("SCA", "SAST", "AGENT")
        },
        capability_boundaries=project_report_capability_boundaries(),
    )


@router.get("/projects/{project_id}/evidence-graph", response_model=EvidenceGraph)
def get_project_evidence_graph(project_id: UUID, db: Session = Depends(get_db)) -> EvidenceGraph:
    project = db.get(ProjectRecord, str(project_id))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    findings = db.scalars(
        select(FindingRecord)
        .where(FindingRecord.project_id == str(project_id))
        .order_by(FindingRecord.created_at.desc())
    ).all()
    components = db.scalars(
        select(ComponentRecord)
        .where(ComponentRecord.project_id == str(project_id))
        .order_by(ComponentRecord.created_at.desc())
    ).all()
    validations = db.scalars(
        select(DastValidationRecord)
        .where(DastValidationRecord.project_id == str(project_id))
        .order_by(DastValidationRecord.created_at.desc())
    ).all()
    evidence_records = db.scalars(
        select(SandboxEvidenceRecord)
        .where(SandboxEvidenceRecord.project_id == str(project_id))
        .order_by(SandboxEvidenceRecord.created_at.desc())
    ).all()
    return build_evidence_graph(
        project_id,
        project.name,
        findings,
        components,
        validations,
        evidence_records,
    )


def count_rows(db: Session, model, project_id: UUID) -> int:
    return int(
        db.scalar(select(func.count()).select_from(model).where(model.project_id == str(project_id)))
        or 0
    )


def record_counts(records: list, field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        value = str(getattr(record, field))
        counts[value] = counts.get(value, 0) + 1
    return counts


def grouped_counts(db: Session, group_column, project_column, project_id: UUID) -> dict[str, int]:
    rows = db.execute(
        select(group_column, func.count()).where(project_column == str(project_id)).group_by(group_column)
    ).all()
    return {str(key): int(count) for key, count in rows if key is not None}


def calculate_risk_score(
    findings_by_severity: dict[str, int],
    dast_by_verdict: dict[str, int],
    sandbox_evidence_count: int,
) -> int:
    score = 0
    score += findings_by_severity.get("critical", 0) * 12
    score += findings_by_severity.get("high", 0) * 8
    score += findings_by_severity.get("medium", 0) * 4
    score += findings_by_severity.get("low", 0) * 1
    score += dast_by_verdict.get("exploitable", 0) * 10
    score += dast_by_verdict.get("uncertain", 0) * 3
    score += min(sandbox_evidence_count * 2, 10)
    return min(score, 100)


def project_report_capability_boundaries() -> dict[str, list[str]]:
    """Keep the report explicit about demonstrated capability versus future scope."""
    return {
        "SCA": [
            "当前报告汇总已执行批次的组件、漏洞、许可证和依赖关系结果。",
            "不等同于所有包管理器的完整原生依赖树或实时漏洞情报。",
        ],
        "SAST / AGENT": [
            "当前结果来自本地规则、Semgrep（可用时）和规则化复核流程。",
            "不表示已经接入外部大模型、真实 Agent 执行或完整数据流分析。",
        ],
        "DAST": [
            "当前动态验证是安全的 Web 基础检查，并保留选择的风险、策略和证据摘要。",
            "基础检查的异常信号不等同于 SQL 注入、鉴权绕过等业务漏洞已被真实利用。",
        ],
        "SANDBOX": [
            "当前记录隔离执行策略、命令输出摘要和结构化运行账本。",
            "不是 eBPF、Sysmon 或恶意样本级行为探针，默认隔离策略禁止网络。",
        ],
        "ASPM / 证据链": [
            "攻击链和证据图谱只使用显式关联的 Finding、组件、DAST 与 SANDBOX 记录。",
            "尚未提供 CVSS/EPSS 风险模型、SLA、工单、审批、租户权限或跨项目图推理。",
        ],
    }


def build_sca_governance_summary(db: Session, project_id: UUID) -> ScaGovernanceSummary:
    latest_scan = latest_sca_scan(db, project_id)
    components: list[ComponentRecord] = []
    latest_findings: list[FindingRecord] = []
    if latest_scan is not None:
        components = db.scalars(
            select(ComponentRecord)
            .where(ComponentRecord.project_id == str(project_id))
            .where(ComponentRecord.scan_task_id == latest_scan.id)
        ).all()
        latest_findings = db.scalars(
            select(FindingRecord)
            .where(FindingRecord.project_id == str(project_id))
            .where(FindingRecord.scan_task_id == latest_scan.id)
            .where(FindingRecord.source == "SCA")
        ).all()

    total_sca_finding_count = int(
        db.scalar(
            select(func.count())
            .select_from(FindingRecord)
            .where(FindingRecord.project_id == str(project_id))
            .where(FindingRecord.source == "SCA")
        )
        or 0
    )

    return ScaGovernanceSummary(
        latest_scan_id=latest_scan.id if latest_scan else None,
        latest_scan_status=latest_scan.status if latest_scan else None,
        latest_scan_finished_at=latest_scan.finished_at if latest_scan else None,
        component_count=len(components),
        risky_component_count=sum(1 for component in components if is_sca_risky_component(component)),
        vulnerable_component_count=sum(1 for component in components if component.risk_status == "vulnerable"),
        critical_high_component_count=sum(1 for component in components if component.severity in {"critical", "high"}),
        total_finding_count=total_sca_finding_count,
        latest_scan_finding_count=len(latest_findings),
        vulnerability_finding_count=count_sca_findings(latest_findings, "SCA:"),
        license_finding_count=count_sca_findings(latest_findings, "SCA-LICENSE:"),
        version_review_finding_count=count_sca_findings(latest_findings, "SCA-VERSION:"),
        tool_status=sca_tool_status(latest_scan),
        top_components=top_sca_components(components),
    )


def latest_sca_scan(db: Session, project_id: UUID) -> ScanTaskRecord | None:
    return db.scalars(
        select(ScanTaskRecord)
        .where(ScanTaskRecord.project_id == str(project_id))
        .where(ScanTaskRecord.scan_type == "sca")
        .order_by(ScanTaskRecord.created_at.desc())
    ).first()


def sca_tool_status(scan: ScanTaskRecord | None) -> ScaToolStatus | None:
    if scan is None:
        return None
    metadata = scan.scan_metadata or {}
    value = metadata.get("sca_tool_scan") if isinstance(metadata, dict) else None
    if not isinstance(value, dict):
        return None
    return ScaToolStatus(**value)


def count_sca_findings(findings: list[FindingRecord], prefix: str) -> int:
    return sum(1 for finding in findings if finding.rule_id.startswith(prefix))


def is_sca_risky_component(component: ComponentRecord) -> bool:
    return (
        component.risk_status in {"vulnerable", "license-risk", "review-required"}
        or bool(component.vulnerability_ids)
        or component.severity in {"critical", "high"}
        or component.license_risk in {"restricted", "review_required", "unknown"}
    )


def top_sca_components(components: list[ComponentRecord]) -> list[ScaGovernanceComponent]:
    risky_components = [component for component in components if is_sca_risky_component(component)]
    ranked = sorted(risky_components, key=sca_component_rank, reverse=True)
    return [
        ScaGovernanceComponent(
            ecosystem=component.ecosystem,
            name=component.name,
            version=component.version,
            risk_status=component.risk_status,
            severity=component.severity,
            vulnerability_count=len(component.vulnerability_ids or []),
            license_risk=component.license_risk,
            risk_source=component.risk_source,
            remediation=component.remediation,
        )
        for component in ranked[:5]
    ]


def sca_component_rank(component: ComponentRecord) -> tuple[int, int, int]:
    severity_score = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(component.severity or "", 0)
    vulnerability_score = len(component.vulnerability_ids or [])
    license_score = 1 if component.license_risk in {"restricted", "review_required", "unknown"} else 0
    return severity_score, vulnerability_score, license_score
