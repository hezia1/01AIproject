from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace
from uuid import uuid4

from app.services.sandbox_identity import bootstrap_target_identities, forget_target, resolve_credential, roles_ready


class RegistrationHandler(BaseHTTPRequestHandler):
    registrations: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/register":
            self.send_response(404)
            self.end_headers()
            return
        body = b"""<html><form method='post' action='/register'>
        <input name='username'><input name='email'><input type='password' name='password'>
        <input type='password' name='cpassword'><input type='submit'></form></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8")
        self.__class__.registrations.append(body)
        self.send_response(302)
        self.send_header("Location", "/welcome")
        self.send_header("Set-Cookie", f"session=test-{len(self.registrations)}; Path=/; HttpOnly")
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        return


class JsonIdentityHandler(BaseHTTPRequestHandler):
    users: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {}
        if self.path == "/api/register":
            username, password = str(payload.get("username") or ""), str(payload.get("password") or "")
            if not username or not password:
                return self._json(400, {"error": "missing credentials"})
            self.__class__.users[username] = password
            return self._json(201, {"message": "created"})
        if self.path == "/api/login":
            username, password = str(payload.get("username") or ""), str(payload.get("password") or "")
            if self.users.get(username) != password:
                return self._json(401, {"error": "invalid credentials"})
            return self._json(200, {"token": f"token-{username}"}, cookie=f"session={username}")
        return self._json(404, {"error": "not found"})

    def _json(self, status: int, payload: dict[str, str], cookie: str | None = None) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", f"{cookie}; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def test_docker_target_bootstraps_project_scoped_identities_without_exposing_values() -> None:
    RegistrationHandler.registrations = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), RegistrationHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    project_id, target_id = str(uuid4()), str(uuid4())
    target = SimpleNamespace(
        id=target_id, project_id=project_id, mode="docker", status="running",
        runtime_url=f"http://127.0.0.1:{server.server_port}",
    )
    try:
        summary = bootstrap_target_identities(target)
    finally:
        server.shutdown()

    assert summary["status"] == "ready"
    assert summary["role_count"] == 4
    assert summary["secret_values_exposed"] is False
    assert "cookie" not in summary
    assert roles_ready(project_id, ["authenticated_user", "resource_owner", "peer_user", "reset_test_account"])
    assert resolve_credential(project_id, "sandbox:auto:resource_owner")["cookie"].startswith("session=test-")
    assert len(RegistrationHandler.registrations) == 2
    forget_target(target_id)
    assert not roles_ready(project_id, ["authenticated_user"])


def test_external_target_is_never_mutated_by_identity_bootstrap() -> None:
    target = SimpleNamespace(
        id=str(uuid4()), project_id=str(uuid4()), mode="external", status="running",
        runtime_url="https://example.test",
    )

    summary = bootstrap_target_identities(target)

    assert summary["status"] == "manual_secret_required"
    assert summary["roles"] == []


def test_docker_target_bootstraps_identities_through_conventional_json_api() -> None:
    JsonIdentityHandler.users = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), JsonIdentityHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    project_id, target_id = str(uuid4()), str(uuid4())
    target = SimpleNamespace(
        id=target_id, project_id=project_id, mode="docker", status="running",
        runtime_url=f"http://127.0.0.1:{server.server_port}",
    )
    try:
        summary = bootstrap_target_identities(target)
    finally:
        server.shutdown()

    assert summary["status"] == "ready"
    assert summary["role_count"] == 4
    assert len(JsonIdentityHandler.users) == 2
    credential = resolve_credential(project_id, "sandbox:auto:resource_owner")
    assert credential is not None and str(credential["cookie"]).startswith("session=dast_user_1_")
    assert "cookie" not in summary and "token" not in summary
    forget_target(target_id)
