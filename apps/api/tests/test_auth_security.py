from app.services.auth_security import Identity, AuthenticationError, hash_password, issue_token, parse_token, verify_password


def test_local_password_hash_and_signed_token_round_trip():
    encoded = hash_password("safe-local-password")

    assert verify_password("safe-local-password", encoded)
    assert not verify_password("wrong-password", encoded)

    token, expires_at = issue_token(Identity(
        user_id="00000000-0000-0000-0000-000000000002",
        tenant_id="00000000-0000-0000-0000-000000000001",
        username="security-admin",
        role="admin",
    ))
    identity = parse_token(token)

    assert expires_at > 0
    assert identity.username == "security-admin"
    assert identity.role == "admin"


def test_signed_token_rejects_tampering():
    token, _ = issue_token(Identity(
        user_id="00000000-0000-0000-0000-000000000002",
        tenant_id="00000000-0000-0000-0000-000000000001",
        username="security-admin",
        role="admin",
    ))
    tampered = f"{'A' if token[0] != 'A' else 'B'}{token[1:]}"

    try:
        parse_token(tampered)
    except AuthenticationError:
        pass
    else:
        raise AssertionError("Tampered token must not validate")
