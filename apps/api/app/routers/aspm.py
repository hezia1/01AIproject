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
    AttackChain,
    AttackChainStep,
    ModuleKey,
    ScaGovernanceComponent,
    ScaGovernanceSummary,
    ScaToolStatus,
    Severity,
)

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
    finding_count = count_rows(db, FindingRecord, project_id)
    dast_validation_count = count_rows(db, DastValidationRecord, project_id)
    sandbox_evidence_count = count_rows(db, SandboxEvidenceRecord, project_id)
    scan_task_count = count_rows(db, ScanTaskRecord, project_id)

    findings_by_source = grouped_counts(db, FindingRecord.source, FindingRecord.project_id, project_id)
    findings_by_severity = grouped_counts(db, FindingRecord.severity, FindingRecord.project_id, project_id)
    findings_by_status = grouped_counts(db, FindingRecord.status, FindingRecord.project_id, project_id)
    dast_by_verdict = grouped_counts(db, DastValidationRecord.verdict, DastValidationRecord.project_id, project_id)
    findings = db.scalars(
        select(FindingRecord).where(FindingRecord.project_id == str(project_id)).order_by(FindingRecord.created_at.desc())
    ).all()
    risky_components = db.scalars(
        select(ComponentRecord)
        .where(ComponentRecord.project_id == str(project_id))
        .where(ComponentRecord.risk_status.in_(["vulnerable", "review-required", "license-risk"]))
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
        attack_chains=build_attack_chains(findings, risky_components, validations, sandbox_evidence),
    )


def count_rows(db: Session, model, project_id: UUID) -> int:
    return int(
        db.scalar(select(func.count()).select_from(model).where(model.project_id == str(project_id)))
        or 0
    )


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


def build_attack_chains(
    findings: list[FindingRecord],
    risky_components: list[ComponentRecord],
    validations: list[DastValidationRecord],
    sandbox_evidence: list[SandboxEvidenceRecord],
) -> list[AttackChain]:
    chains: list[AttackChain] = []
    high_sast = first_finding(findings, "SAST", {"critical", "high"})
    high_agent = first_finding(findings, "AGENT", {"critical", "high", "medium"})
    exploitable_dast = next((item for item in validations if item.verdict == "exploitable"), None)
    uncertain_dast = next((item for item in validations if item.verdict == "uncertain"), None)
    sandbox = sandbox_evidence[0] if sandbox_evidence else None
    risky_component = risky_components[0] if risky_components else None

    if high_sast and (exploitable_dast or uncertain_dast):
        dast = exploitable_dast or uncertain_dast
        steps = [
            finding_step("SAST", high_sast),
            AttackChainStep(module="DAST", title=f"动态验证目标：{dast.target_url}", evidence=dast.evidence_summary),
        ]
        if sandbox:
            steps.append(AttackChainStep(module="SANDBOX", title=f"运行时证据：{sandbox.run_command}", evidence=sandbox.evidence_summary))
        chains.append(
            AttackChain(
                id="external-code-risk-chain",
                name="外部可达代码风险链",
                severity=Severity.critical if exploitable_dast and high_sast.severity in {"critical", "high"} else Severity.high,
                modules=unique_modules(steps),
                evidence_count=len(steps),
                summary="静态高危代码风险已与动态验证结果关联，具备更高处置优先级。",
                recommended_action="优先确认入口可达性，修复代码风险，并在 DAST 与 SANDBOX 中复测。",
                steps=steps,
            )
        )

    if high_agent and sandbox:
        steps = [
            finding_step("AGENT", high_agent),
            AttackChainStep(module="SANDBOX", title=f"受控执行证据：{sandbox.run_command}", evidence=sandbox.evidence_summary),
        ]
        chains.append(
            AttackChain(
                id="agent-runtime-behavior-chain",
                name="Agent 权限与运行时行为链",
                severity=Severity.high if high_agent.severity in {"critical", "high"} else Severity.medium,
                modules=unique_modules(steps),
                evidence_count=len(steps),
                summary="Agent 配置或工具权限风险已与运行时执行证据关联。",
                recommended_action="收敛 Agent 工具权限，限制文件/网络/命令能力，并保留沙箱复测证据。",
                steps=steps,
            )
        )

    if risky_component and (exploitable_dast or uncertain_dast):
        dast = exploitable_dast or uncertain_dast
        steps = [
            AttackChainStep(
                module="SCA",
                title=f"{risky_component.name} {risky_component.version or ''}".strip(),
                evidence=risky_component.risk_summary or risky_component.remediation,
            ),
            AttackChainStep(module="DAST", title=f"动态验证目标：{dast.target_url}", evidence=dast.evidence_summary),
        ]
        chains.append(
            AttackChain(
                id="supply-chain-exposure-chain",
                name="供应链风险暴露链",
                severity=Severity.high if risky_component.severity in {"critical", "high"} or exploitable_dast else Severity.medium,
                modules=unique_modules(steps),
                evidence_count=len(steps),
                summary="供应链组件风险已与动态目标验证结果关联，可能影响外部暴露面。",
                recommended_action="优先升级或替换风险组件，并对暴露入口执行回归验证。",
                steps=steps,
            )
        )

    return chains


def first_finding(findings: list[FindingRecord], source: str, severities: set[str]) -> FindingRecord | None:
    return next((item for item in findings if item.source == source and item.severity in severities), None)


def finding_step(module: str, finding: FindingRecord) -> AttackChainStep:
    location = f"{finding.file_path or '-'}:{finding.line_start or '-'}"
    return AttackChainStep(module=module, title=finding.title, evidence=f"{location} · {finding.evidence or finding.rule_id}")


def unique_modules(steps: list[AttackChainStep]) -> list[str]:
    modules: list[str] = []
    for step in steps:
        if step.module not in modules:
            modules.append(step.module)
    return modules
