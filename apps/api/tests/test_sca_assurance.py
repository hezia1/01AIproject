from app.services.sca_assurance import build_sca_assurance, component_resolution
from app.services.sca_parser import ParsedComponent, dedupe_components
from app.models import Severity
from app.services.osv_client import OsvLookupError, OsvVulnerability
from app.services.sca_risk_analyzer import analyze_component, analyze_components
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

    monkeypatch.setattr("app.services.sca_risk_analyzer.query_osv", lambda *_args: [])
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


def test_online_osv_is_preferred_when_the_api_is_available(monkeypatch):
    component = ParsedComponent("npm", "demo-online", "1.2.3", "runtime", "package-lock.json", "npm", license="MIT")
    online = OsvVulnerability("GHSA-ONLINE", Severity.high, "online match")
    mirror_calls: list[tuple] = []

    monkeypatch.delenv("SCA_OFFLINE_ONLY", raising=False)
    monkeypatch.setattr("app.services.sca_risk_analyzer.query_osv", lambda *_args: [online])
    monkeypatch.setattr("app.services.sca_risk_analyzer.lookup_osv_mirror", lambda *args: (mirror_calls.append(args) or [], False))

    analyzed = analyze_component(component, vulnerability_rules=(), license_policies=load_license_policies())

    assert analyzed.vulnerability_ids == ["GHSA-ONLINE"]
    assert analyzed.risk_source == "osv"
    assert analyzed.osv_error is None
    assert mirror_calls == []


def test_online_osv_failure_falls_back_to_the_local_mirror(monkeypatch):
    component = ParsedComponent("npm", "demo-offline", "1.2.3", "runtime", "package-lock.json", "npm", license="MIT")
    mirrored = OsvVulnerability("GHSA-MIRROR", Severity.medium, "mirror match")

    monkeypatch.delenv("SCA_OFFLINE_ONLY", raising=False)
    monkeypatch.setattr("app.services.sca_risk_analyzer.query_osv", lambda *_args: (_ for _ in ()).throw(OsvLookupError("network unavailable")))
    monkeypatch.setattr("app.services.sca_risk_analyzer.lookup_osv_mirror", lambda *_args: ([mirrored], True))

    analyzed = analyze_component(component, vulnerability_rules=(), license_policies=load_license_policies())

    assert analyzed.vulnerability_ids == ["GHSA-MIRROR"]
    assert analyzed.risk_source == "osv_mirror"
    assert analyzed.osv_checked is True
    assert "已使用本地 OSV 镜像" in str(analyzed.osv_error)


def test_network_failure_uses_one_probe_before_offline_fallback(monkeypatch):
    components = [
        ParsedComponent("npm", f"demo-{index}", "1.2.3", "runtime", "package-lock.json", "npm", license="MIT")
        for index in range(3)
    ]
    calls: list[str] = []

    monkeypatch.delenv("SCA_OFFLINE_ONLY", raising=False)

    def unavailable(_ecosystem, name, _version):
        calls.append(name)
        raise OsvLookupError("network unavailable")

    monkeypatch.setattr("app.services.sca_risk_analyzer.query_osv", unavailable)
    monkeypatch.setattr("app.services.sca_risk_analyzer.lookup_osv_mirror", lambda *_args: ([], False))

    analyzed = analyze_components(components, vulnerability_rules=(), license_policies=load_license_policies())

    assert calls == ["demo-0"]
    assert all(item.risk_status == "review-required" for item in analyzed)
    assert all("本地 OSV 镜像没有匹配记录" in str(item.osv_error) for item in analyzed)


def test_reachable_online_osv_queries_each_exact_component_once(monkeypatch):
    components = [
        ParsedComponent("npm", f"online-{index}", "1.2.3", "runtime", "package-lock.json", "npm", license="MIT")
        for index in range(3)
    ]
    calls: list[str] = []

    monkeypatch.delenv("SCA_OFFLINE_ONLY", raising=False)

    def available(_ecosystem, name, _version):
        calls.append(name)
        return [OsvVulnerability("GHSA-ONLINE-1", Severity.high, "online match")] if name == "online-1" else []

    monkeypatch.setattr("app.services.sca_risk_analyzer.query_osv", available)
    monkeypatch.setattr("app.services.sca_risk_analyzer.lookup_osv_mirror", lambda *_args: (_ for _ in ()).throw(AssertionError("mirror must not run")))

    analyzed = analyze_components(components, vulnerability_rules=(), license_policies=load_license_policies())

    assert sorted(calls) == ["online-0", "online-1", "online-2"]
    assert analyzed[0].risk_status == "clean"
    assert analyzed[1].vulnerability_ids == ["GHSA-ONLINE-1"]
    assert analyzed[2].risk_status == "clean"


def test_explicit_offline_mode_never_calls_online_osv(monkeypatch):
    component = ParsedComponent("npm", "demo-explicit-offline", "1.2.3", "runtime", "package-lock.json", "npm", license="MIT")
    mirrored = OsvVulnerability("GHSA-OFFLINE", Severity.low, "offline match")

    monkeypatch.setenv("SCA_OFFLINE_ONLY", "true")
    monkeypatch.setattr("app.services.sca_risk_analyzer.query_osv", lambda *_args: (_ for _ in ()).throw(AssertionError("online query must not run")))
    monkeypatch.setattr("app.services.sca_risk_analyzer.lookup_osv_mirror", lambda *_args: ([mirrored], True))

    analyzed = analyze_components([component], vulnerability_rules=(), license_policies=load_license_policies())[0]

    assert analyzed.vulnerability_ids == ["GHSA-OFFLINE"]
    assert analyzed.risk_source == "osv_mirror"
