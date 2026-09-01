import pytest
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace
from uuid import uuid4

from fastapi import HTTPException

from app.routers.dast import _adjudicate_sandbox_result, build_dast_report, business_flow_for_runtime, business_flow_target_confirmation, confirm_probe_target, eligible_dast_candidate_records, ensure_manual_validation_record, project_with_active_sandbox_target, redact_evidence_summary, visible_business_flow_records
from app.models import DastSandboxResult, DastVerdict
from app.services.dast_probe import build_probe_result
from app.services.dast_business_flow import dry_run, execute_api_flow, execute_api_flow_result
from app.services.dast_candidate_adapter import TEMPLATES, build_flow_blueprint, normalize_candidate
from app.services.dast_sandbox_contract import build_sandbox_handoff, execution_preflight, required_capabilities, step_adapter, validate_flow_policy
from app.services.verification_strategies import recommended_dast_strategies, resolve_dast_strategy


def test_sca_risk_prefers_component_exposure_strategy() -> None:
    strategies = recommended_dast_strategies(SimpleNamespace(source="SCA"))

    assert strategies[0].id == "component-exposure"
    assert "组件漏洞" in " ".join(strategies[0].limitations)


def test_dast_business_queue_only_keeps_actionable_sast_and_agent_findings() -> None:
    records = [
        SimpleNamespace(source="SAST", status="open", id="sast-open"),
        SimpleNamespace(source="AGENT", status="confirmed", id="agent-confirmed"),
        SimpleNamespace(source="SCA", status="open", id="sca-open"),
        SimpleNamespace(source="SAST", status="resolved", id="sast-resolved"),
    ]

    result = eligible_dast_candidate_records(records)

    assert [item.id for item in result] == ["sast-open", "agent-confirmed"]


def test_dast_queue_excludes_static_secret_even_when_ai_review_mislabels_it_xss() -> None:
    secret = SimpleNamespace(
        source="SAST", status="open", id="history-secret",
        rule_id="SAST.GIT.HISTORY_SECRET", title="Potential credential material in Git history",
        ai_review={"category": "xss", "cwe": "CWE-798"},
    )

    assert eligible_dast_candidate_records([secret]) == []


def test_dast_queue_excludes_generated_identifier_dom_cell_without_input_flow() -> None:
    finding = SimpleNamespace(
        source="SAST", status="open", id="dom-id", rule_id="SAST.XSS.DOM_INNERHTML",
        title="不可信数据写入 DOM innerHTML", ai_review={"cwe": "CWE-79"},
        evidence="c_id.innerHTML = users[i].id;", file_path="views/app/adminusers.ejs",
    )

    assert eligible_dast_candidate_records([finding]) == []


def test_dast_workbench_hides_historical_flows_not_in_current_queue() -> None:
    records = [
        SimpleNamespace(id="current-flow", finding_id="current-finding"),
        SimpleNamespace(id="stale-flow", finding_id="old-secret-finding"),
        SimpleNamespace(id="manual-flow", finding_id=None),
    ]

    visible = visible_business_flow_records(records, {"current-finding"})

    assert [record.id for record in visible] == ["current-flow", "manual-flow"]


def test_dast_uses_running_sandbox_target_when_project_has_no_runtime_url() -> None:
    project = SimpleNamespace(
        id=str(uuid4()), runtime_url=None, api_base_url=None, source_path="/source",
        sandbox_image=None, sandbox_command=None,
    )
    target = SimpleNamespace(
        runtime_url="http://127.0.0.1:49152", image="demo:local", command="npm start",
    )
    db = SimpleNamespace(scalar=lambda _statement: target)

    enriched = project_with_active_sandbox_target(project, db)

    assert enriched.runtime_url == "http://127.0.0.1:49152"
    assert enriched.sandbox_image == "demo:local"
    assert enriched.sandbox_command == "npm start"


def test_unknown_strategy_is_rejected() -> None:
    try:
        resolve_dast_strategy("payload-scan")
    except ValueError as exc:
        assert "Unknown DAST" in str(exc)
    else:
        raise AssertionError("unknown strategy should be rejected")


def test_header_risk_is_reported_as_baseline_attention_not_exploitability() -> None:
    result = build_probe_result(
        "http://example.test/login",
        "http",
        200,
        25,
        {"Server": "example"},
        None,
    )

    assert result.verdict == DastVerdict.baseline_attention
    assert "不构成漏洞可利用性" in result.reproduction_steps


def test_clean_headers_are_reported_as_baseline_clear_not_non_exploitable() -> None:
    result = build_probe_result(
        "https://example.test/health",
        "https",
        200,
        25,
        {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "same-origin",
        },
        None,
    )

    assert result.verdict == DastVerdict.baseline_clear
    assert result.verdict != DastVerdict.not_exploitable


def test_probe_target_requires_configured_origin_and_exact_confirmation() -> None:
    project = SimpleNamespace(runtime_url="https://example.test/app", api_base_url=None)
    target = "https://example.test/login"

    confirm_probe_target(project, target, "DAST_WEB_BASELINE:https://example.test/login")

    with pytest.raises(HTTPException, match="exact confirmation phrase"):
        confirm_probe_target(project, target, "confirm")
    with pytest.raises(HTTPException, match="same origin"):
        confirm_probe_target(project, "https://unapproved.example/login", "DAST_WEB_BASELINE:https://unapproved.example/login")


def test_automated_baseline_observation_is_read_only() -> None:
    automated_record = SimpleNamespace(validation_mode="automated_web_baseline")

    with pytest.raises(HTTPException, match="read-only"):
        ensure_manual_validation_record(automated_record)


def test_dast_report_summarizes_stored_records_without_new_probe() -> None:
    project_id = uuid4()
    now = datetime.utcnow()

    def record(*, verdict: str, mode: str, finding_id: str | None) -> SimpleNamespace:
        return SimpleNamespace(
            id=uuid4(),
            project_id=project_id,
            finding_id=finding_id,
            component_id=None,
            link_source="explicit-selection" if finding_id else "unlinked",
            link_confidence=100 if finding_id else 0,
            target_url="https://example.test/login",
            verdict=verdict,
            validator="reviewer",
            strategy_id="web-baseline",
            strategy_name="Web baseline",
            scope_summary="stored record only",
            limitations="limited scope",
            evidence_summary="stored evidence",
            request_summary="no new request",
            response_summary="stored response",
            reproduction_steps="stored reproduction steps",
            remediation_hint="stored remediation",
            validation_mode=mode,
            connection_confirmed=mode == "automated_web_baseline",
            created_at=now,
            updated_at=now,
        )

    report = build_dast_report(
        project_id,
        [
            record(verdict="baseline_clear", mode="automated_web_baseline", finding_id=None),
            record(verdict="uncertain", mode="manual_validation", finding_id=str(uuid4())),
        ],
    )

    assert report["schema"] == "ai-security-platform.dast-report/v1"
    assert report["summary"]["record_count"] == 2
    assert report["summary"]["automated_baseline_count"] == 1
    assert report["summary"]["manual_validation_count"] == 1
    assert report["summary"]["linked_record_count"] == 1
    assert report["summary"]["by_verdict"] == {
        "exploitable": 0,
        "uncertain": 1,
        "not_exploitable": 0,
        "baseline_attention": 0,
        "baseline_clear": 1,
    }
    assert report["summary"]["verification_plan_count"] == 0
    assert report["summary"]["evidence_item_count"] == 0
    assert len(report["records"]) == 2
    assert any("does not connect to targets" in item for item in report["capability_boundaries"])


def test_dast_evidence_summary_redacts_common_secret_values() -> None:
    result = redact_evidence_summary("Authorization: Bearer abc123 token=def456 password=secret")

    assert "abc123" not in result
    assert "def456" not in result
    assert "secret" not in result
    assert result.count("[REDACTED]") == 3


def test_business_flow_dry_run_validates_roles_without_connecting() -> None:
    flow = SimpleNamespace(
        roles=[{"alias": "user_a", "credential_ref": "env:DAST_FLOW_USER_A"}],
        steps=[{"id": "list", "kind": "http_request", "role": "user_a", "method": "GET", "url": "https://example.test/items"}],
    )

    snapshots, errors = dry_run(flow)

    assert errors == []
    assert snapshots[0]["status"] == "ready"


def test_business_flow_browser_step_is_blocked_without_connecting() -> None:
    flow = SimpleNamespace(
        roles=[{"alias": "user_a", "credential_ref": "env:DAST_FLOW_USER_A"}],
        steps=[{"id": "page", "kind": "browser_action", "role": "user_a", "action": "click"}],
        target_url="https://example.test",
        allowed_paths=[],
    )

    snapshots, verdict, reason = execute_api_flow(flow)

    assert verdict == "uncertain"
    assert "预执行校验" in reason
    assert snapshots[0]["status"] == "blocked"


def test_dast_candidate_adapter_reuses_project_target_and_runtime_parameter() -> None:
    finding = SimpleNamespace(
        source="SAST", rule_id="python.sql-injection", title="SQL query is built from request input",
        ai_review={"category": "sql_injection", "cwe": "CWE-89"},
        evidence="GET /api/orders parameter=id", file_path="app/orders.py",
    )
    project = SimpleNamespace(runtime_url="https://example.test/app", api_base_url="https://example.test/api")

    candidate = normalize_candidate(finding, project)

    assert candidate["recommended_strategy_id"] == "sql-injection-differential"
    assert candidate["attack_surface"]["urls"] == ["https://example.test/api/orders"]
    assert candidate["attack_surface"]["methods"] == ["GET"]
    assert candidate["attack_surface"]["parameters"] == ["id"]
    assert candidate["readiness"] == "ready"
    assert candidate["missing"] == []


def test_dast_candidate_ignores_dynamic_source_url_with_template_port() -> None:
    finding = SimpleNamespace(
        source="SAST", rule_id="SAST.TAINT.JAVASCRIPT.SQL", title="SQL injection",
        ai_review={"category": "sql_injection", "cwe": "CWE-89"},
        evidence="console.log(`http://localhost:${PORT}`); GET /api/users parameter=id",
        file_path="app.js", line_start=1,
    )
    project = SimpleNamespace(
        runtime_url="http://127.0.0.1:54108", api_base_url=None, source_path="",
    )

    candidate = normalize_candidate(finding, project)

    assert candidate["attack_surface"]["urls"] == ["http://127.0.0.1:54108/api/users"]
    assert candidate["attack_surface"]["parameters"] == ["id"]
    assert candidate["readiness"] == "ready"

    without_target = normalize_candidate(
        finding,
        SimpleNamespace(runtime_url=None, api_base_url=None, source_path=""),
    )
    assert without_target["attack_surface"]["urls"] == []


def test_dast_candidate_adapter_reports_only_real_blockers() -> None:
    finding = SimpleNamespace(
        source="AGENT", rule_id="agent.prompt-context", title="Prompt context reaches sensitive capability",
        ai_review={"category": "prompt_injection"}, evidence="Agent tool chain", file_path="agent.yaml",
    )
    project = SimpleNamespace(runtime_url=None, api_base_url=None)

    candidate = normalize_candidate(finding, project)

    assert candidate["recommended_strategy_id"] == "agent-capability-boundary"
    assert candidate["missing"] == ["项目运行地址或 API 地址"]
    assert candidate["readiness"] == "blocked"


def test_dast_candidate_extracts_express_body_parameter_and_method() -> None:
    finding = SimpleNamespace(
        source="SAST", rule_id="SAST.TAINT.JAVASCRIPT.COMMAND", title="Command execution receives request-controlled data",
        ai_review={"cwe": "CWE-78"}, evidence="exec('ping ' + req.body.address)", file_path="core/appHandler.js",
    )
    project = SimpleNamespace(runtime_url="https://example.test", api_base_url=None)

    candidate = normalize_candidate(finding, project)

    assert candidate["attack_surface"]["parameters"] == ["address"]
    assert candidate["attack_surface"]["injection_points"] == [{"name": "address", "location": "json"}]
    assert candidate["attack_surface"]["methods"] == ["POST"]
    assert candidate["missing"] == []


def test_dast_candidate_maps_express_body_to_form_when_app_is_urlencoded(tmp_path) -> None:
    (tmp_path / "server.js").write_text(
        "const bodyParser = require('body-parser');\n"
        "app.use(bodyParser.urlencoded({ extended: true }));\n",
        encoding="utf-8",
    )
    finding = SimpleNamespace(
        source="SAST", rule_id="SAST.TAINT.JAVASCRIPT.COMMAND", title="Command execution receives request-controlled data",
        ai_review={"cwe": "CWE-78"}, evidence="exec('ping ' + req.body.address)", file_path="core/appHandler.js",
    )
    project = SimpleNamespace(runtime_url="https://example.test", api_base_url=None, source_path=str(tmp_path))

    candidate = normalize_candidate(finding, project)

    assert candidate["attack_surface"]["injection_points"] == [{"name": "address", "location": "form_field"}]


def test_dast_candidate_maps_express_handler_to_protected_runtime_route(tmp_path) -> None:
    (tmp_path / "core").mkdir()
    (tmp_path / "routes").mkdir()
    (tmp_path / "core" / "appHandler.js").write_text(
        "module.exports.ping = function (req, res) {\n"
        "  const address = req.body.address;\n"
        "  return res.send(address);\n"
        "};\n",
        encoding="utf-8",
    )
    (tmp_path / "routes" / "app.js").write_text(
        "router.post('/ping', authHandler.isAuthenticated, appHandler.ping);\n",
        encoding="utf-8",
    )
    (tmp_path / "server.js").write_text(
        "app.use('/app', require('./routes/app')());\n",
        encoding="utf-8",
    )
    finding = SimpleNamespace(
        source="SAST", rule_id="CWE-78", title="Command injection", ai_review={},
        evidence="exec(address)", file_path="core/appHandler.js", line_start=2,
    )
    project = SimpleNamespace(
        runtime_url="https://example.test", api_base_url=None, source_path=str(tmp_path),
    )

    candidate = normalize_candidate(finding, project)

    assert candidate["attack_surface"]["urls"] == ["https://example.test/app/ping"]
    assert candidate["attack_surface"]["methods"] == ["POST"]
    assert candidate["attack_surface"]["parameters"] == ["address"]
    assert candidate["preconditions"]["required_roles"] == ["authenticated_user"]
    assert candidate["missing"] == ["项目测试身份"]
    assert "源码路由映射" in candidate["auto_filled"]


def test_dast_candidate_maps_route_rule_to_handler_inputs(tmp_path) -> None:
    (tmp_path / "core").mkdir()
    (tmp_path / "routes").mkdir()
    (tmp_path / "core" / "appHandler.js").write_text(
        "module.exports.userEditSubmit = function(req, res) {\n"
        "  return update(req.body.id, req.body.name);\n"
        "};\n",
        encoding="utf-8",
    )
    (tmp_path / "routes" / "app.js").write_text(
        "router.post('/useredit', authHandler.isAuthenticated, appHandler.userEditSubmit);\n",
        encoding="utf-8",
    )
    (tmp_path / "server.js").write_text("app.use('/app', require('./routes/app')());\n", encoding="utf-8")
    finding = SimpleNamespace(
        source="SAST", rule_id="SAST.CSRF.STATE_CHANGE_WITHOUT_TOKEN", title="CSRF",
        ai_review={"category": "csrf", "cwe": "CWE-352"}, evidence="router.post('/useredit')",
        file_path="routes/app.js", line_start=1,
    )
    project = SimpleNamespace(runtime_url="https://example.test", api_base_url=None, source_path=str(tmp_path))

    candidate = normalize_candidate(finding, project)

    assert candidate["vulnerability_type"] == "csrf"
    assert candidate["attack_surface"]["urls"] == ["https://example.test/app/useredit"]
    assert candidate["attack_surface"]["methods"] == ["POST"]
    assert candidate["attack_surface"]["parameters"] == ["id", "name"]
    assert candidate["preconditions"]["required_roles"] == ["authenticated_user"]


def test_dast_candidate_backtracks_ejs_output_to_rendering_handler(tmp_path) -> None:
    (tmp_path / "core").mkdir()
    (tmp_path / "routes").mkdir()
    (tmp_path / "views" / "app").mkdir(parents=True)
    (tmp_path / "views" / "app" / "products.ejs").write_text("<%- output.searchTerm %>\n", encoding="utf-8")
    (tmp_path / "core" / "appHandler.js").write_text(
        "module.exports.productSearch = function(req, res) {\n"
        "  const output = {searchTerm: req.body.name};\n"
        "  return res.render('app/products', {output: output});\n"
        "};\n",
        encoding="utf-8",
    )
    (tmp_path / "routes" / "app.js").write_text(
        "router.post('/products', authHandler.isAuthenticated, appHandler.productSearch);\n",
        encoding="utf-8",
    )
    (tmp_path / "server.js").write_text("app.use('/app', require('./routes/app')());\n", encoding="utf-8")
    finding = SimpleNamespace(
        source="SAST", rule_id="SAST.XSS.EJS_UNESCAPED_OUTPUT", title="EJS unescaped output",
        ai_review={"category": "xss", "cwe": "CWE-79"}, evidence="<%- output.searchTerm %>",
        file_path="views/app/products.ejs", line_start=1,
    )
    project = SimpleNamespace(runtime_url="https://example.test", api_base_url=None, source_path=str(tmp_path))

    candidate = normalize_candidate(finding, project)

    assert candidate["attack_surface"]["urls"] == ["https://example.test/app/products"]
    assert candidate["attack_surface"]["methods"] == ["POST"]
    assert candidate["attack_surface"]["parameters"] == ["name"]


def test_dast_candidate_maps_stored_dom_sink_to_unique_writer(tmp_path) -> None:
    (tmp_path / "core").mkdir()
    (tmp_path / "routes").mkdir()
    (tmp_path / "views" / "app").mkdir(parents=True)
    (tmp_path / "views" / "app" / "adminusers.ejs").write_text(
        "<script>\n"
        "c_email.innerHTML = users[i].email;\n"
        "</script>\n",
        encoding="utf-8",
    )
    (tmp_path / "core" / "appHandler.js").write_text(
        "module.exports.adminUsers = function(req, res) {\n"
        "  return res.render('app/adminusers', { users: [] });\n"
        "};\n"
        "module.exports.userEditSubmit = function(req, res) {\n"
        "  const user = {};\n"
        "  user.email = req.body.email;\n"
        "  return res.send('ok');\n"
        "};\n"
        "module.exports.productEdit = function(req, res) {\n"
        "  const product = {};\n"
        "  product.email = req.body.email;\n"
        "  return res.send('ok');\n"
        "};\n",
        encoding="utf-8",
    )
    (tmp_path / "routes" / "app.js").write_text(
        "router.get('/admin/users', isAuthenticated, appHandler.adminUsers);\n"
        "router.post('/useredit', isAuthenticated, appHandler.userEditSubmit);\n"
        "router.post('/productedit', isAuthenticated, appHandler.productEdit);\n",
        encoding="utf-8",
    )
    (tmp_path / "server.js").write_text("app.use('/app', require('./routes/app'));\n", encoding="utf-8")
    finding = SimpleNamespace(
        source="SAST", rule_id="SAST.XSS.DOM_INNERHTML", title="DOM XSS",
        ai_review={"cwe": "CWE-79"}, evidence="c_email.innerHTML = users[i].email;",
        file_path="views/app/adminusers.ejs", line_start=2,
    )
    project = SimpleNamespace(id=str(uuid4()), runtime_url="https://example.test", api_base_url=None, source_path=str(tmp_path))

    candidate = normalize_candidate(finding, project)
    blueprint = build_flow_blueprint({**candidate, "title": finding.title}, finding_id="stored-xss")

    assert candidate["attack_surface"]["urls"] == ["https://example.test/app/useredit", "https://example.test/app/admin/users"]
    assert candidate["attack_surface"]["methods"] == ["POST"]
    assert candidate["attack_surface"]["parameters"] == ["email"]
    assert candidate["attack_surface"]["injection_points"] == [{"name": "email", "location": "form_field"}]
    assert "可映射的运行时参数" not in candidate["missing"]
    assert "持久化数据流映射" in candidate["auto_filled"]
    assert blueprint["allowed_paths"] == ["/app/useredit", "/app/admin/users"]
    assert blueprint["steps"][0]["setup_url"] == "https://example.test/app/useredit"
    assert blueprint["steps"][0]["url"] == "https://example.test/app/admin/users"


def test_dast_candidate_treats_nested_file_member_as_single_upload_parameter() -> None:
    finding = SimpleNamespace(
        source="SAST", rule_id="CWE-611", title="XXE", ai_review={},
        evidence="parser.toJson(req.files.products.data.toString())", file_path="handler.js", line_start=1,
    )
    project = SimpleNamespace(runtime_url="https://example.test", api_base_url=None, source_path=None)

    candidate = normalize_candidate(finding, project)

    assert candidate["attack_surface"]["parameters"] == ["products"]
    assert candidate["attack_surface"]["injection_points"] == [{"name": "products", "location": "form"}]


def test_dast_candidate_uses_unique_discovered_endpoint_for_source_parameter() -> None:
    finding = SimpleNamespace(
        source="SAST", rule_id="SAST.SQL.STRING_CONCAT", title="SQL query receives request input",
        ai_review={"cwe": "CWE-89"}, evidence="query += req.body.login", file_path="core/appHandler.js",
    )
    project = SimpleNamespace(runtime_url="https://example.test", api_base_url=None)
    discovery = {
        "parameters": [{"name": "login", "location": "body", "source_url": "https://example.test/forgotpw"}],
        "forms": [{"action": "https://example.test/forgotpw", "method": "POST", "parameters": []}],
    }

    candidate = normalize_candidate(finding, project, discovery=discovery)

    assert candidate["attack_surface"]["urls"] == ["https://example.test/forgotpw"]
    assert candidate["attack_surface"]["methods"] == ["POST"]
    assert candidate["attack_surface"]["parameters"] == ["login"]
    assert "运行资产映射" in candidate["auto_filled"]


def test_dast_refuses_to_materialize_parameterized_strategy_without_input_point() -> None:
    with pytest.raises(ValueError, match="唯一定位输入点"):
        build_flow_blueprint({
            "title": "XSS sink", "vulnerability_type": "xss",
            "recommended_strategy_id": "xss-browser-evidence", "evidence_requirements": [], "missing": ["可映射的运行时参数"],
            "attack_surface": {"urls": ["https://example.test/"], "methods": ["GET"], "parameters": [], "injection_points": []},
        }, finding_id="finding-xss")


def test_materialized_access_control_flow_has_isolated_sessions_and_ids() -> None:
    blueprint = build_flow_blueprint({
        "title": "Order IDOR", "vulnerability_type": "access_control",
        "recommended_strategy_id": "access-control-read", "evidence_requirements": ["双身份响应"],
        "missing": ["项目测试身份"],
        "attack_surface": {"urls": ["https://example.test/api/orders/TEST-1"], "methods": ["GET"], "parameters": []},
    }, finding_id="finding-1")

    assert blueprint["strategy_source"] == "template"
    assert blueprint["sufficiency_criteria"]["adapter_version"] == 4
    assert len(blueprint["sufficiency_criteria"]["mapping_fingerprint"]) == 64
    assert [role["credential_ref"] for role in blueprint["roles"]] == ["sandbox:auto:resource_owner", "sandbox:auto:peer_user"]
    assert blueprint["allowed_paths"] == ["/api/orders/TEST-1"]
    assert blueprint["sufficiency_criteria"]["strategy_id"] == "access-control-read"


def test_materialized_access_control_mutation_uses_browser_probe() -> None:
    blueprint = build_flow_blueprint({
        "title": "Profile IDOR", "vulnerability_type": "access_control",
        "recommended_strategy_id": "access-control-read", "evidence_requirements": ["双身份状态变更"],
        "missing": [],
        "attack_surface": {
            "urls": ["https://example.test/app/useredit"], "methods": ["POST"],
            "parameters": ["id", "name"], "injection_points": [{"name": "id", "location": "form_field"}, {"name": "name", "location": "form_field"}],
            "access_model": "resource_mutation",
        },
    }, finding_id="finding-idor-post")

    assert blueprint["roles"] == [
        {"alias": "resource_owner", "credential_ref": "sandbox:auto:resource_owner", "description": "SANDBOX 自动创建的测试资源所属者"},
        {"alias": "peer_user", "credential_ref": "sandbox:auto:peer_user", "description": "SANDBOX 自动创建的另一普通测试用户"},
    ]
    assert blueprint["steps"] == [{
        "id": "authorization-mutation-proof", "kind": "sandbox_probe", "capability": "browser",
        "probe": "access_control_mutation", "role": "peer_user", "owner_role": "resource_owner",
        "method": "POST", "url": "https://example.test/app/useredit", "parameters": ["id", "name"],
        "location": "form_field", "evidence": ["双身份状态变更"],
    }]


@pytest.mark.parametrize(
    "vulnerability_type",
    [
        "access_control", "sql_injection", "xss", "ssrf", "command_injection",
        "path_traversal", "template_injection", "xxe", "open_redirect", "cors",
        "file_upload", "broken_authentication", "csrf", "sensitive_data_exposure",
        "security_misconfiguration", "unsafe_deserialization", "code_injection",
        "agent_capability", "prompt_injection", "dependency_risk", "unclassified",
    ],
)
def test_every_generated_web_strategy_step_has_a_sandbox_adapter(vulnerability_type: str) -> None:
    template = next(item for item in TEMPLATES if vulnerability_type in item.vulnerability_types)
    candidate = {
        "title": vulnerability_type,
        "vulnerability_type": vulnerability_type,
        "recommended_strategy_id": template.id,
        "evidence_requirements": list(template.evidence_requirements),
        "required_capabilities": list(template.required_capabilities),
        "missing": [],
        "preconditions": {"required_roles": []},
        "attack_surface": {
            "urls": ["https://example.test/probe"],
            "methods": [template.methods[0]],
            "parameters": ["q"],
            "injection_points": [{"name": "q", "location": "query"}],
            "observer_urls": [],
        },
    }

    blueprint = build_flow_blueprint(candidate, finding_id=f"finding-{vulnerability_type}")
    flow = SimpleNamespace(**blueprint)

    assert blueprint["steps"]
    assert all(step_adapter(step) in {"http", "browser", "agent"} for step in blueprint["steps"])
    assert required_capabilities(flow)
    assert validate_flow_policy(flow) == []


def test_local_access_control_contract_is_handoff_ready_for_sandbox() -> None:
    project = SimpleNamespace(runtime_url="https://example.test", api_base_url=None, sandbox_image=None, sandbox_command=None)
    flow = SimpleNamespace(
        id=uuid4(), project_id=uuid4(), finding_id=uuid4(), target_url="https://example.test/orders/1",
        status="approved", approval_reference="AUTH-1", approved_by="security", approved_at=datetime.utcnow(),
        allowed_paths=["/orders/1"], roles=[{"alias": "owner"}, {"alias": "peer"}],
        steps=[
            {"id": "owner-read", "kind": "http_request", "role": "owner", "method": "GET", "url": "https://example.test/orders/1"},
            {"id": "peer-read", "kind": "http_request", "role": "peer", "method": "GET", "url": "https://example.test/orders/1"},
            {"id": "authorization-differential", "kind": "assert_compare", "mode": "access_control", "left": "owner-read", "right": "peer-read"},
        ],
        sufficiency_criteria={"required_capabilities": []},
    )

    preflight = execution_preflight(project, flow)

    assert preflight["status"] == "waiting_sandbox"
    assert preflight["can_handoff_sandbox"] is True
    assert preflight["required_capabilities"] == ["isolated_http"]


def test_business_executor_archives_redacted_http_error_as_verdict_evidence() -> None:
    class ForbiddenHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(403)
            self.send_header("Set-Cookie", "session=secret-value")
            self.end_headers()
            self.wfile.write(b"access denied")

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), ForbiddenHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_port}/protected"
    flow = SimpleNamespace(
        target_url=target, allowed_paths=["/protected"],
        roles=[{"alias": "peer"}],
        steps=[
            {"id": "peer-read", "kind": "http_request", "role": "peer", "method": "GET", "url": target},
            {"id": "blocked", "kind": "assert", "status_in": [401, 403, 404], "verdict_on_pass": "not_exploitable"},
        ],
    )
    try:
        snapshots, verdict, _ = execute_api_flow(flow)
    finally:
        server.shutdown()
        server.server_close()

    assert verdict == "not_exploitable"
    assert snapshots[0]["detail"]["status_code"] == 403
    assert snapshots[0]["detail"]["exchange"]["response"]["headers"]["Set-Cookie"] == "[REDACTED]"
    assert snapshots[0]["detail"]["exchange"]["response"]["body"] == "access denied"


def test_business_executor_treats_empty_root_url_path_as_approved_root() -> None:
    class RootHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ready")

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), RootHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    target_without_path = f"http://127.0.0.1:{server.server_port}"
    flow = SimpleNamespace(
        target_url=f"{target_without_path}/", allowed_paths=["/"],
        roles=[{"alias": "anonymous"}],
        steps=[
            {"id": "root", "kind": "http_request", "role": "anonymous", "method": "GET", "url": target_without_path},
            {"id": "available", "kind": "assert", "status_in": [200], "verdict_on_pass": "uncertain"},
        ],
    )
    try:
        result = execute_api_flow_result(flow, task_id="task-root")
    finally:
        server.shutdown()
        server.server_close()

    assert result.terminal_status == "completed"
    assert result.snapshots[0]["status"] == "completed"
    assert result.snapshots[0]["detail"]["status_code"] == 200


def test_business_flow_retargets_to_restarted_project_sandbox_origin() -> None:
    flow_id = uuid4()
    flow = SimpleNamespace(
        id=flow_id, project_id=uuid4(), finding_id=uuid4(),
        target_url="http://127.0.0.1:54739/", allowed_paths=["/"],
        roles=[{"alias": "anonymous"}], sufficiency_criteria={},
        steps=[
            {"id": "root", "kind": "http_request", "method": "GET", "url": "http://127.0.0.1:54739"},
            {"id": "external", "kind": "http_request", "method": "GET", "url": "https://outside.invalid/"},
        ],
    )
    project = SimpleNamespace(
        runtime_url="http://127.0.0.1:51777", api_base_url=None,
        sandbox_image="example/image", sandbox_command="start-app",
    )

    business_flow_target_confirmation(project, flow, f"DAST_BUSINESS_FLOW:{flow_id}:{flow.target_url}")
    runtime_flow = business_flow_for_runtime(project, flow)

    assert runtime_flow.target_url == "http://127.0.0.1:51777/"
    assert runtime_flow.steps[0]["url"] == "http://127.0.0.1:51777"
    assert runtime_flow.steps[1]["url"] == "https://outside.invalid/"
    assert runtime_flow.allowed_paths == ["/"]


def test_sql_strategy_uses_repeated_baseline_and_true_false_differential() -> None:
    blueprint = build_flow_blueprint({
        "title": "SQL injection", "vulnerability_type": "sql_injection",
        "recommended_strategy_id": "sql-injection-differential", "evidence_requirements": [], "missing": [],
        "attack_surface": {"urls": ["https://example.test/api/search"], "methods": ["GET"], "parameters": ["q"]},
    }, finding_id="finding-sql")

    assert [step["id"] for step in blueprint["steps"]] == ["baseline-1", "baseline-2", "boolean-true", "boolean-false", "sql-differential"]
    assert blueprint["steps"][-1]["kind"] == "assert_compare"


def test_sql_differential_requires_a_stable_specific_signal() -> None:
    class StableHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"items":[]}')

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), StableHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{server.server_port}/search"
    blueprint = build_flow_blueprint({
        "title": "SQL injection", "vulnerability_type": "sql_injection",
        "recommended_strategy_id": "sql-injection-differential", "evidence_requirements": [], "missing": [],
        "attack_surface": {"urls": [target], "methods": ["GET"], "parameters": ["q"]},
    }, finding_id="finding-sql")
    flow = SimpleNamespace(**blueprint)
    try:
        result = execute_api_flow_result(flow, task_id="task-sql")
    finally:
        server.shutdown()
        server.server_close()

    assert result.terminal_status == "completed"
    assert result.verdict == "not_exploitable"
    assert any(item["step_kind"] == "assert_compare" for item in result.snapshots)


def test_target_network_failure_is_unverified_instead_of_uncertain() -> None:
    flow = SimpleNamespace(
        target_url="http://127.0.0.1:1/health", allowed_paths=["/health"],
        roles=[{"alias": "anonymous"}],
        steps=[{"id": "health", "kind": "http_request", "role": "anonymous", "method": "GET", "url": "http://127.0.0.1:1/health"}],
    )

    result = execute_api_flow_result(flow, timeout_seconds=1, task_id="task-1")

    assert result.terminal_status == "failed"
    assert result.verdict is None
    assert "未验证" in result.reason


def test_sandbox_preflight_separates_runtime_capability_from_human_fields() -> None:
    project = SimpleNamespace(runtime_url="https://example.test", api_base_url=None)
    flow = SimpleNamespace(
        id=uuid4(), project_id=uuid4(), finding_id=uuid4(), target_url="https://example.test/account",
        status="approved", approval_reference="AUTH-1", approved_by="security", approved_at=datetime.utcnow(),
        allowed_paths=["/account"], roles=[{"alias": "user"}],
        steps=[{"id": "csrf", "kind": "sandbox_probe", "capability": "browser", "probe": "csrf", "role": "user", "method": "POST", "url": "https://example.test/account", "parameters": ["display_name"]}],
        sufficiency_criteria={"required_capabilities": ["browser"], "evidence_requirements": ["differential", "rollback"]},
    )

    preflight = execution_preflight(project, flow)
    handoff = build_sandbox_handoff(project, flow, "task-1", "dast_" + "a" * 64)

    assert preflight["status"] == "waiting_sandbox"
    assert preflight["can_handoff_sandbox"] is True
    assert handoff["required_capabilities"] == ["browser"]
    assert handoff["limits"]["destructive_actions"] is False


def test_dast_tri_color_counts_only_current_findings_with_completed_runtime_evidence() -> None:
    project_id, finding_id, flow_id = uuid4(), uuid4(), uuid4()
    now = datetime.utcnow()
    finding = SimpleNamespace(id=finding_id, ai_review={})
    flow = SimpleNamespace(id=flow_id, finding_id=str(finding_id), name="CSRF proof", target_url="https://example.test/account")
    run = SimpleNamespace(
        id=uuid4(), flow_id=str(flow_id), status="completed", verdict="exploitable",
        verdict_reason="should not count without evidence", execution_mode="sandbox_handoff",
        created_at=now, started_at=now, completed_at=now,
    )

    without_evidence = build_dast_report(
        project_id, [], business_flows=[flow], business_runs=[run], findings=[finding],
    )

    assert without_evidence["summary"]["tri_color"]["total"] == 0
    assert without_evidence["summary"]["unverified_count"] == 1

    snapshot = SimpleNamespace(
        run_id=str(run.id), step_kind="sandbox_evidence", step_id="evidence-1",
        detail={"complete": True, "request_id": "request-1", "evidence_type": "differential"},
        request_summary=None, response_summary="bound fact", evidence_hash="a" * 64,
    )
    with_evidence = build_dast_report(
        project_id, [], business_flows=[flow], business_runs=[run], business_snapshots=[snapshot], findings=[finding],
    )

    assert with_evidence["summary"]["tri_color"] == {"total": 1, "exploitable": 1, "uncertain": 0, "not_exploitable": 0}
    assert with_evidence["summary"]["unverified_count"] == 0


def test_sandbox_handoff_blocks_destructive_browser_actions() -> None:
    project = SimpleNamespace(runtime_url="https://example.test", api_base_url=None)
    flow = SimpleNamespace(
        id=uuid4(), project_id=uuid4(), finding_id=uuid4(), target_url="https://example.test/account",
        status="approved", approval_reference="AUTH-1", approved_by="security", approved_at=datetime.utcnow(),
        allowed_paths=["/account"], roles=[{"alias": "user"}],
        steps=[{"id": "danger", "kind": "browser_action", "role": "user", "action": "payment", "url": "https://example.test/account"}],
        sufficiency_criteria={"required_capabilities": ["browser"]},
    )

    preflight = execution_preflight(project, flow)

    assert preflight["status"] == "blocked"
    assert any(item["code"] == "policy" and item["status"] == "blocked" for item in preflight["checks"])


def test_dast_requires_strong_sandbox_fact_before_exploitable_verdict() -> None:
    weak = DastSandboxResult(
        task_id=uuid4(), strategy_id=uuid4(), callback_token="x" * 32, execution_id="exec-1",
        status="completed", verdict_signal="exploitable", evidence=[{"type": "environment", "confirmed": True}],
    )
    strong = weak.model_copy(update={"evidence": [{"type": "browser", "confirmed": True, "request_id": "request-1", "facts": "unique marker executed"}]})

    assert _adjudicate_sandbox_result(weak)[0] == "uncertain"
    assert _adjudicate_sandbox_result(strong)[0] == "exploitable"


def test_dast_accepts_only_complete_repeated_timing_as_strong_fact() -> None:
    base = DastSandboxResult(
        task_id=uuid4(), strategy_id=uuid4(), callback_token="x" * 32, execution_id="exec-timing",
        status="completed", verdict_signal="exploitable",
        evidence=[{
            "type": "timing", "confirmed": True, "complete": True, "request_id": "request-timing",
            "probe_count": 6, "expected_probe_count": 6,
            "timing": {"samples_ms": [12, 15, 11, 2020, 2012, 2030]},
        }],
    )
    weak = base.model_copy(update={"evidence": [{
        "type": "timing", "confirmed": True, "complete": True, "request_id": "request-timing",
        "probe_count": 2, "expected_probe_count": 2, "timing": {"samples_ms": [10, 2010]},
    }]})

    assert _adjudicate_sandbox_result(weak)[0] == "uncertain"
    assert _adjudicate_sandbox_result(base)[0] == "exploitable"


def test_dast_requires_complete_negative_coverage_before_green_verdict() -> None:
    weak = DastSandboxResult(
        task_id=uuid4(), strategy_id=uuid4(), callback_token="x" * 32, execution_id="exec-1",
        status="completed", verdict_signal="not_exploitable",
        evidence=[{"type": "coverage", "complete": True, "probe_count": 0, "expected_probe_count": 0, "negative_conclusion_supported": True}],
    )
    strong = weak.model_copy(update={"evidence": [{"type": "coverage", "complete": True, "probe_count": 3, "expected_probe_count": 3, "negative_conclusion_supported": True, "request_id": "request-1"}]})

    assert _adjudicate_sandbox_result(weak)[0] == "uncertain"
    assert _adjudicate_sandbox_result(strong)[0] == "not_exploitable"
