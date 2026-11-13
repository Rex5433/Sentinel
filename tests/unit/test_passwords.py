import secrets

import pytest

from app.auth import hash_password, verify_password, validate_password, token_hash


def test_random_salts_exact_password_and_no_parameter_downgrade():
    password = "Test-only unicode passphrase å " + secrets.token_urlsafe(16) + "  "
    first, second = hash_password(password), hash_password(password)
    assert first != second
    assert verify_password(password, first)
    assert not verify_password(password.strip(), first)
    assert not verify_password(password + "wrong", first)
    assert not verify_password(password, first.replace("131072", "1"))
    assert not verify_password(password, "not-a-hash")


@pytest.mark.parametrize("password", ["short", " " * 20, "x" * 129, "a" * 15 + "\x00", "a" * 15 + "\ud800"])
def test_password_policy_rejects_invalid_inputs(password):
    with pytest.raises(ValueError):
        validate_password(password)


def test_session_token_hash_requires_full_random_token_format():
    assert token_hash(None) is None
    assert token_hash("admin") is None
    token = secrets.token_urlsafe(32)
    assert len(token_hash(token)) == 64 and token_hash(token) != token
