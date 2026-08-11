import json
from pathlib import Path

from app.services.agent_governance import effective_agent_profile, evaluate_agent_quality_gate
from app.services.agent_intelligence import analyze_agent_intelligence, load_agent_threat_intelligence
from app.services.agent_scanner import AgentAsset, AgentProvenance
from app.services.sca_osv_mirror import load_osv_mirror


def package_asset(
    package: str,
    version: str | None,
    *,
    version_status: str = "locked",
    installation_method: str = "npx",
) -> AgentAsset:
    return AgentAsset(
        path=f"agents/{package}.json",
        asset_type="mcp-config",
        format="json",
        parser="test",
        status="parsed",
        checks=[],
        provenance=[AgentProvenance(
            subject=f"server:{package}",
            package_name=package,
            package_version=version,
            source_type="registry",
            source_ref=f"npm:{package}",
            installation_method=installation_method,
            version_status=version_status,
            publisher_claim=None,
            publisher_status="not-declared",
        )],
    )


def test_bundled_rules_distinguish_match_no_match_and_no_coverage(tmp_path: Path) -> None:
    output = analyze_agent_intelligence(
        [
            package_asset("minimist", "1.2.0"),
            package_asset("lodash", "4.17.21"),
            package_asset("package-without-local-rule", "1.0.0"),
            package_asset("minimist", None, version_status="missing"),
        ],
        mirror_path=tmp_path / "missing-osv.json",
        threat_path=tmp_path / "missing-threat.json",
    )

    packages = {f"{item['package_name']}@{item.get('package_version')}": item for item in output.report["packages"]}
    assert packages["minimist@1.2.0"]["lookup_status"] == "vulnerable"
    assert packages["minimist@1.2.0"]["purl"] == "pkg:npm/minimist@1.2.0"
    assert packages["lodash@4.17.21"]["lookup_status"] == "checked_no_match"
    assert packages["package-without-local-rule@1.0.0"]["lookup_status"] == "not_covered"
    assert packages["minimist@None"]["lookup_status"] == "version_unresolved"
    assert [item.rule_id for item in output.findings] == ["AGENT.INTEL.KNOWN_VULNERABILITY"]
    assert output.report["sources"]["osv_mirror"]["status"] == "not_configured"
    assert output.report["sources"]["threat_intelligence"]["status"] == "not_configured"


def test_local_osv_mirror_matches_exact_agent_package_version(tmp_path: Path) -> None:
    mirror_path = tmp_path / "osv-mirror.json"
    mirror_path.write_text(json.dumps({
        "updated_at": "2026-08-10T00:00:00+00:00",
        "entries": [{
            "ecosystem": "npm",
            "package": "mirror-only-package",
            "version": "2.0.0",
            "vulnerabilities": [{
                "id": "CVE-2026-12345",
                "summary": "Test mirror advisory",
                "database_specific": {"severity": "HIGH", "fixed_version": "2.0.1"},
            }],
        }],
    }), encoding="utf-8")
    load_osv_mirror.cache_clear()

    output = analyze_agent_intelligence(
        [package_asset("mirror-only-package", "2.0.0")],
        mirror_path=mirror_path,
        threat_path=tmp_path / "missing-threat.json",
    )

    package = output.report["packages"][0]
    assert package["lookup_status"] == "vulnerable"
    assert package["coverage_sources"] == ["local-osv-mirror"]
    assert package["vulnerabilities"][0]["id"] == "CVE-2026-12345"
    assert output.report["sources"]["osv_mirror"]["status"] == "available"


def test_local_threat_file_drives_malicious_and_protected_name_findings(tmp_path: Path) -> None:
    threat_path = tmp_path / "threat-intelligence.json"
    threat_path.write_text(json.dumps({
        "schema": "ai-security-platform.agent-threat-intelligence/v1",
        "updated_at": "2026-08-10T00:00:00+00:00",
        "sources": ["test-fixture"],
        "entries": [{
            "id": "MAL-TEST-1",
            "ecosystem": "npm",
            "package": "evil-agent-package",
            "severity": "critical",
            "summary": "Fixture malicious package",
            "source": "test-fixture",
        }],
        "protected_packages": [{
            "ecosystem": "npm",
            "package": "trusted-agent",
            "source": "test-fixture",
        }],
    }), encoding="utf-8")
    load_agent_threat_intelligence.cache_clear()

    output = analyze_agent_intelligence(
        [package_asset("evil-agent-package", "1.0.0"), package_asset("trusted-agentt", "1.0.0")],
        mirror_path=tmp_path / "missing-osv.json",
        threat_path=threat_path,
    )

    rule_ids = {item.rule_id for item in output.findings}
    assert rule_ids == {"AGENT.INTEL.MALICIOUS_PACKAGE", "AGENT.INTEL.PACKAGE_CONFUSION"}
    assert output.report["summary"]["malicious_match_count"] == 1
    assert output.report["summary"]["package_confusion_count"] == 1
    assert output.report["sources"]["threat_intelligence"]["status"] == "available"


def test_intelligence_gate_blocks_matches_but_not_accepted_risk(tmp_path: Path) -> None:
    output = analyze_agent_intelligence(
        [package_asset("minimist", "1.2.0")],
        mirror_path=tmp_path / "missing-osv.json",
        threat_path=tmp_path / "missing-threat.json",
    )
    finding = output.findings[0]
    payload = {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "status": "open",
    }
    profile = effective_agent_profile({})
    gate = evaluate_agent_quality_gate(
        findings=[payload], permissions=[], coverage={}, profile=profile,
        intelligence=output.report,
    )
    assert gate["decision"] == "block"
    assert gate["blocking_intelligence_count"] == 1

    accepted = evaluate_agent_quality_gate(
        findings=[{**payload, "status": "accepted_risk"}], permissions=[], coverage={}, profile=profile,
        intelligence=output.report,
    )
    assert accepted["blocking_intelligence_count"] == 0
