from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
from threading import Thread
from uuid import uuid4

import pytest


SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "sca_api_gate.py"
SPEC = importlib.util.spec_from_file_location("sca_api_gate_script", SCRIPT)
assert SPEC and SPEC.loader
sca_api_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sca_api_gate)


class GateHandler(BaseHTTPRequestHandler):
    gate_status = 200
    gate_payload = {"decision": "pass", "exit_code": 0, "scan_status": "succeeded", "result_complete": True}
    logout_count = 0

    def do_POST(self):
        if self.path == "/api/auth/login":
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
            if body != {"username": "ci-user", "password": "ci-secret"}:
                return self.respond(401, {"detail": "Invalid username or password"})
            return self.respond(200, {"role": "user"}, cookie="ai_security_session=test-session; Path=/; HttpOnly")
        if self.path == "/api/auth/logout":
            type(self).logout_count += 1
            return self.respond(200, {})
        self.respond(404, {"detail": "not found"})

    def do_GET(self):
        if self.path.startswith("/api/sca/projects/"):
            if "ai_security_session=test-session" not in str(self.headers.get("Cookie") or ""):
                return self.respond(401, {"detail": "Authentication required"})
            return self.respond(type(self).gate_status, type(self).gate_payload)
        self.respond(404, {"detail": "not found"})

    def respond(self, status, payload, cookie=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return None


@pytest.fixture
def gate_server():
    GateHandler.gate_status = 200
    GateHandler.gate_payload = {"decision": "pass", "exit_code": 0, "scan_status": "succeeded", "result_complete": True}
    GateHandler.logout_count = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), GateHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def invoke(base_url):
    return sca_api_gate.run_api_gate(
        base_url, str(uuid4()), str(uuid4()), "ci-user", "ci-secret", allow_insecure_http=True,
    )


def test_authenticated_client_carries_cookie_and_logs_out(gate_server) -> None:
    exit_code, result = invoke(gate_server)

    assert exit_code == 0
    assert result["scan_status"] == "succeeded"
    assert GateHandler.logout_count == 1


def test_authenticated_client_propagates_gate_block(gate_server) -> None:
    GateHandler.gate_payload = {"decision": "block", "exit_code": 2, "scan_status": "stale", "result_complete": False}

    exit_code, _ = invoke(gate_server)

    assert exit_code == 2
    assert GateHandler.logout_count == 1


@pytest.mark.parametrize("status", [401, 403])
def test_authenticated_client_fails_closed_when_gate_rejects_session(gate_server, status) -> None:
    GateHandler.gate_status = status
    GateHandler.gate_payload = {"detail": "Authentication required" if status == 401 else "Permission denied"}

    with pytest.raises(sca_api_gate.GateClientError, match=f"HTTP {status}"):
        invoke(gate_server)

    assert GateHandler.logout_count == 1


def test_authenticated_client_rejects_invalid_credentials(gate_server) -> None:
    with pytest.raises(sca_api_gate.GateClientError, match="HTTP 401"):
        sca_api_gate.run_api_gate(
            gate_server, str(uuid4()), str(uuid4()), "ci-user", "wrong", allow_insecure_http=True,
        )

    assert GateHandler.logout_count == 0


def test_authenticated_client_rejects_false_pass_contract(gate_server) -> None:
    GateHandler.gate_payload = {"decision": "pass", "exit_code": 0, "scan_status": "partial", "result_complete": False}

    with pytest.raises(sca_api_gate.GateClientError, match="without a complete succeeded scan"):
        invoke(gate_server)


def test_client_requires_https_unless_explicit_test_override() -> None:
    with pytest.raises(sca_api_gate.GateClientError, match="HTTPS"):
        sca_api_gate.validate_base_url("http://security.example.test")


def test_workflow_uses_secret_credentials_without_auth_bypass() -> None:
    workflow = (Path(__file__).resolve().parents[3] / ".github" / "workflows" / "sca-gate.yml").read_text(encoding="utf-8")

    assert "SCA_CI_USERNAME" in workflow
    assert "SCA_CI_PASSWORD" in workflow
    assert "scripts/sca_api_gate.py" in workflow
    assert "AUTH_DISABLED" not in workflow


def test_local_cli_writes_failed_evidence_and_returns_distinct_error(tmp_path, monkeypatch) -> None:
    local_spec = importlib.util.spec_from_file_location("sca_local_cli_script", Path(__file__).resolve().parents[3] / "scripts" / "sca_ci.py")
    assert local_spec and local_spec.loader
    local_cli = importlib.util.module_from_spec(local_spec)
    local_spec.loader.exec_module(local_cli)
    invalid_policy = tmp_path / "invalid-policy.json"
    invalid_policy.write_text("[]", encoding="utf-8")
    output = tmp_path / "result.json"
    sarif = tmp_path / "result.sarif"
    monkeypatch.setattr("sys.argv", [
        "sca_ci.py", "--source", str(tmp_path), "--policy", str(invalid_policy),
        "--json", str(output), "--sarif", str(sarif), "--fail-on-block",
    ])

    assert local_cli.main() == 3
    result = json.loads(output.read_text(encoding="utf-8"))
    sarif_result = json.loads(sarif.read_text(encoding="utf-8"))
    assert result["gate"]["decision"] == "error"
    assert result["gate"]["scan_status"] == "failed"
    assert sarif_result["runs"][0]["invocations"][0]["executionSuccessful"] is False
