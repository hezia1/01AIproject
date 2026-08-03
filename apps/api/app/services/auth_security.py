"""Local identity primitives with no third-party authentication dependency."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any


VALID_ROLES = {"admin", "security_engineer", "developer", "viewer"}
JWT_ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = max(300, int(os.getenv("AI_SECURITY_TOKEN_TTL_SECONDS", "28800")))
_SECRET = os.getenv("AI_SECURITY_AUTH_SECRET", "ai-security-local-development-secret-change-before-production").encode("utf-8")


class AuthenticationError(ValueError):
    pass


@dataclass(frozen=True)
class Identity:
    user_id: str
    tenant_id: str
    username: str
    role: str


def hash_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    salt = secrets.token_bytes(16)
    iterations = 310_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "$".join(("pbkdf2-sha256", str(iterations), _b64url(salt), _b64url(digest)))


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, raw_iterations, raw_salt, raw_digest = encoded.split("$", 3)
        if algorithm != "pbkdf2-sha256":
            return False
        iterations = int(raw_iterations)
        expected = _unb64url(raw_digest)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), _unb64url(raw_salt), iterations)
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError):
        return False


def issue_token(identity: Identity) -> tuple[str, int]:
    now = int(time.time())
    expires_at = now + TOKEN_TTL_SECONDS
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    payload = {
        "sub": identity.user_id,
        "tenant_id": identity.tenant_id,
        "username": identity.username,
        "role": identity.role,
        "iat": now,
        "exp": expires_at,
    }
    signing_input = f"{_b64json(header)}.{_b64json(payload)}".encode("ascii")
    signature = hmac.new(_SECRET, signing_input, hashlib.sha256).digest()
    return f"{signing_input.decode('ascii')}.{_b64url(signature)}", expires_at


def parse_token(token: str) -> Identity:
    try:
        header_part, payload_part, signature_part = token.split(".")
        signing_input = f"{header_part}.{payload_part}".encode("ascii")
        expected = hmac.new(_SECRET, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64url(signature_part)):
            raise AuthenticationError("invalid token signature")
        header = json.loads(_unb64url(header_part))
        payload: dict[str, Any] = json.loads(_unb64url(payload_part))
        if header.get("alg") != JWT_ALGORITHM or int(payload.get("exp") or 0) <= int(time.time()):
            raise AuthenticationError("token is expired or invalid")
        role = str(payload.get("role") or "")
        if role not in VALID_ROLES:
            raise AuthenticationError("invalid token role")
        return Identity(
            user_id=str(payload["sub"]), tenant_id=str(payload["tenant_id"]),
            username=str(payload["username"]), role=role,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, AuthenticationError):
            raise
        raise AuthenticationError("invalid access token") from exc


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64json(value: dict[str, Any]) -> str:
    return _b64url(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))
