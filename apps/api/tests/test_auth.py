from app.middleware.auth import is_admin_operation
from app.services.auth import hash_password, normalize_role, verify_password


def test_password_hash_uses_scrypt_and_verifies_without_storing_plaintext() -> None:
    encoded = hash_password("correct horse battery staple")
    assert encoded.startswith("scrypt$")
    assert "correct horse" not in encoded
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong password", encoded)


def test_password_hash_rejects_short_passwords() -> None:
    try:
        hash_password("short")
    except ValueError as exc:
        assert "10" in str(exc)
    else:
        raise AssertionError("short passwords must be rejected")


def test_roles_are_limited_to_user_and_admin() -> None:
    assert normalize_role("admin") == "admin"
    assert normalize_role("security") == "user"
    assert normalize_role("viewer") == "user"


def test_admin_routes_do_not_capture_user_managed_updates() -> None:
    assert is_admin_operation("POST", "/api/sast/projects/abc/rules")
    assert is_admin_operation("PATCH", "/api/sca/exceptions/abc")
    assert is_admin_operation("POST", "/api/knowledge/entries/abc/review")
    assert not is_admin_operation("POST", "/api/sca/grype-database/update")
    assert not is_admin_operation("POST", "/api/sast/community-rules/update")
    assert not is_admin_operation("POST", "/api/projects/import")
