from app.services.sca_assurance import build_sca_assurance, component_resolution
from app.services.sca_parser import ParsedComponent, dedupe_components
from app.services.sca_risk_analyzer import analyze_component
from app.services.sca_license_policy import load_license_policies
from app.services.sca_tool_scanner import ToolScanResult, ToolVulnerability, TrivySecurityFinding
from app.routers.sca import apply_tool_vulnerabilities, build_tool_status


def test_lockfile_exact_version_wins_over_manifest_constraint(monkeypatch):
    manifest = ParsedComponent("npm", "demo", "^1.0.0", "runtime", "package.json", "npm", license="MIT")
    lock = ParsedComponent("npm", "demo", "1.2.3", "runtime", "package-lock.json", "npm", license="MIT")
    resolved = dedupe_components([manifest, lock])[0]

    assert resolved.version == "1.2.3"
    assert resolved.source_file == "package-lock.json"
    assert component_resolution(resolved)["status"] == "resolved"

    monkeypatch.setattr("app.services.sca_risk_analyzer.lookup_osv_mirror", lambda *_args: ([], True))
    analyzed = analyze_component(resolved, vulnerability_rules=(), license_policies=load_license_policies())
    assert analyzed.risk_status == "clean"
    assert analyzed.osv_checked is True


def test_manifest_range_is_never_reported_clean_when_unverified(monkeypatch):
    component = ParsedComponent("npm", "demo", "^1.0.0", "runtime", "package.json", "npm", license="MIT")
    monkeypatch.setenv("SCA_OFFLINE_ONLY", "true")

    analyzed = analyze_component(component, vulnerability_rules=(), license_policies=load_license_policies())
    assurance = build_sca_assurance([analyzed], ["package.json"])

    assert analyzed.risk_status == "review-required"
    assert analyzed.risk_metadata["vulnerability_verification"] == "unverified"
    assert assurance["status"] == "partial"
    assert assurance["constraint_component_count"] == 1


def test_constraint_match_is_still_unverified_without_installed_version():
    component = ParsedComponent(
        "npm",
        "demo",
        "^1.0.0",
        "runtime",
        "package.json",
        "npm",
        vulnerability_ids=["LOCAL-RULE"],
        risk_metadata={"vulnerability_verification": "matched"},
    )

    assurance = build_sca_assurance([component], ["package.json"])

    assert assurance["verified_component_count"] == 0
    assert assurance["unverified_component_count"] == 1


def test_tool_vulnerability_requires_an_exact_component_version_match():
    component = ParsedComponent(
        "npm",
        "demo",
        "1.2.3",
        "runtime",
        "package-lock.json",
        "npm",
        license="MIT",
        license_risk="allowed",
        risk_status="review-required",
        risk_metadata={"vulnerability_verification": "unverified"},
    )
    tool_scan = ToolScanResult(
        components=[],
        vulnerabilities=[ToolVulnerability("npm", "demo", "9.9.9", "CVE-WRONG-VERSION", "critical", None, None)],
        errors=[],
        grype_status="success",
    )

    analyzed = apply_tool_vulnerabilities([component], tool_scan)[0]

    assert not analyzed.vulnerability_ids
    assert analyzed.risk_status == "clean"
    assert analyzed.risk_metadata["vulnerability_verification"] == "verified_no_match"


def test_trivy_fallback_does_not_claim_an_unmatched_component_is_clean():
    component = ParsedComponent(
        "npm", "demo", "1.2.3", "runtime", "package-lock.json", "npm",
        license="MIT", license_risk="allowed", risk_status="review-required",
        risk_metadata={"vulnerability_verification": "unverified"},
    )
    tool_scan = ToolScanResult(
        components=[], vulnerabilities=[], errors=["Grype failed: database expired"],
        grype_status="failed", trivy_status="success", trivy_vulnerability_fallback=True,
    )

    analyzed = apply_tool_vulnerabilities([component], tool_scan)[0]

    assert analyzed.risk_status == "review-required"
    assert analyzed.risk_source is None
    assert analyzed.risk_metadata["tool_coverage"]["vulnerability_engine"] == "trivy"
    assert analyzed.risk_metadata["tool_coverage"]["verified"] is False


def test_completed_trivy_fallback_is_persisted_separately_from_component_vulnerabilities():
    tool_scan = ToolScanResult(
        components=[], vulnerabilities=[], errors=["Grype failed: database expired"],
        syft_status="success", grype_status="failed", trivy_status="success",
        trivy_vulnerability_fallback=True, trivy_secret_count=1,
        trivy_security_findings=(
            TrivySecurityFinding("secret", "demo-token", "high", "Demo token", "src/app.js", 4),
        ),
    )

    status = build_tool_status(True, tool_scan)

    assert status.status == "fallback"
    assert status.trivy_vulnerability_count == 0
    assert status.trivy_secret_count == 1
    assert status.security_findings[0].rule_id == "demo-token"
