import jwt
import pytest

from app.core.security import (
    Permission,
    Role,
    create_access_token,
    decode_token,
    decrypt_secret,
    encrypt_secret,
    has_permission,
    hash_password,
    mask_secret,
    verify_password,
)


def test_password_hash_roundtrip():
    hashed = hash_password("S3cret!pass")
    assert hashed != "S3cret!pass"
    assert verify_password("S3cret!pass", hashed)
    assert not verify_password("wrong", hashed)
    assert not verify_password("x", "not-a-bcrypt-hash")


def test_jwt_roundtrip_and_tamper_detection():
    token = create_access_token("usr_1", "analyst")
    payload = decode_token(token)
    assert payload["sub"] == "usr_1"
    assert payload["role"] == "analyst"
    assert payload["type"] == "access"
    with pytest.raises(jwt.PyJWTError):
        decode_token(token[:-2] + ("AA" if token[-2:] != "AA" else "BB"))


def test_secret_encryption():
    enc = encrypt_secret("api-key-123")
    assert "api-key-123" not in enc
    assert decrypt_secret(enc) == "api-key-123"
    assert decrypt_secret("garbage") is None


@pytest.mark.parametrize(
    ("value", "masked"),
    [(None, None), ("", None), ("abcd", "****"), ("abcdefghijkl", "abcd****ijkl")],
)
def test_mask_secret(value, masked):
    assert mask_secret(value) == masked


def test_rbac_matrix():
    assert has_permission(Role.ADMIN, Permission.USER_ADMIN)
    assert has_permission(Role.ANALYST, Permission.INVESTIGATION_WRITE)
    assert not has_permission(Role.ANALYST, Permission.PROVIDER_ADMIN)
    assert has_permission(Role.VIEWER, Permission.INVESTIGATION_READ)
    assert not has_permission(Role.VIEWER, Permission.INVESTIGATION_WRITE)
    assert not has_permission("nobody", Permission.INVESTIGATION_READ)
