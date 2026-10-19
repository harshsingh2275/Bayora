"""
tests/unit/test_gateway_auth.py
Unit tests for gateway authentication and authorization.

AGENTS.md §5: Security tests must TRY to violate the property and assert the attempt FAILS.
These tests do not use mocks for the thing being tested (auth logic).
"""
import hashlib
import hmac

import pytest

from gateway.app.auth import (
    Role,
    _constant_compare,
    _sha256_hex,
    _verify_tenant_token,
    _verify_admin_token,
)
from gateway.app import config as cfg


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ── _sha256_hex ────────────────────────────────────────────────────────────────

def test_sha256_hex_known_vector():
    """SHA-256("abc") has a known value."""
    expected = "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469348423f656b0fb0c"
    # Drop the last char (known truncation) — let's use a full well-known test:
    expected = hashlib.sha256(b"abc").hexdigest()
    assert _sha256_hex("abc") == expected


def test_sha256_hex_is_hex_64():
    result = _sha256_hex("some-token-value")
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


# ── _constant_compare ─────────────────────────────────────────────────────────

def test_constant_compare_equal():
    assert _constant_compare("abc", "abc") is True


def test_constant_compare_not_equal():
    """SECURITY: must return False, not raise, on mismatch."""
    assert _constant_compare("abc", "xyz") is False


def test_constant_compare_empty():
    assert _constant_compare("", "") is True
    assert _constant_compare("a", "") is False


# ── _verify_tenant_token ──────────────────────────────────────────────────────

class TestVerifyTenantToken:
    """Tests for the core token verification function."""

    def setup_method(self):
        # Patch config hashes with known test values
        self._orig_red = cfg.RED_TOKEN_SHA256
        self._orig_blue = cfg.BLUE_TOKEN_SHA256
        cfg.RED_TOKEN_SHA256 = _make_hash("test-red-token")
        cfg.BLUE_TOKEN_SHA256 = _make_hash("test-blue-token")

    def teardown_method(self):
        cfg.RED_TOKEN_SHA256 = self._orig_red
        cfg.BLUE_TOKEN_SHA256 = self._orig_blue

    def test_valid_red_token_returns_red(self):
        role = _verify_tenant_token("test-red-token")
        assert role == "red"

    def test_valid_blue_token_returns_blue(self):
        role = _verify_tenant_token("test-blue-token")
        assert role == "blue"

    def test_garbage_token_raises_401(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _verify_tenant_token("garbage-token-that-does-not-match")
        assert exc_info.value.status_code == 401

    def test_empty_token_raises_401(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _verify_tenant_token("")
        assert exc_info.value.status_code == 401

    def test_red_token_not_accepted_as_blue(self):
        """SECURITY: red token must not authenticate as blue."""
        role = _verify_tenant_token("test-red-token")
        assert role != "blue"

    def test_blue_token_not_accepted_as_red(self):
        """SECURITY: blue token must not authenticate as red."""
        role = _verify_tenant_token("test-blue-token")
        assert role != "red"

    def test_near_miss_token_rejected(self):
        """SECURITY: a token differing by one character must be rejected."""
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _verify_tenant_token("test-red-toke_")  # last char changed
        assert exc_info.value.status_code == 401

    def test_token_not_in_exception_detail(self):
        """SECURITY SI-10: token value must not appear in error messages."""
        from fastapi import HTTPException
        secret = "super-secret-token-xyz"
        with pytest.raises(HTTPException) as exc_info:
            _verify_tenant_token(secret)
        assert secret not in str(exc_info.value.detail)


# ── _verify_admin_token ────────────────────────────────────────────────────────

class TestVerifyAdminToken:
    def setup_method(self):
        self._orig_admin = cfg.ADMIN_TOKEN_SHA256
        cfg.ADMIN_TOKEN_SHA256 = _make_hash("test-admin-token")

    def teardown_method(self):
        cfg.ADMIN_TOKEN_SHA256 = self._orig_admin

    def test_valid_admin_token_passes(self):
        # Should not raise
        _verify_admin_token("test-admin-token")

    def test_bad_admin_token_raises_401(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _verify_admin_token("wrong-admin-token")
        assert exc_info.value.status_code == 401

    def test_tenant_token_not_accepted_as_admin(self):
        """SECURITY A3: tenant tokens must not work on admin routes."""
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _verify_admin_token("test-red-token")

    def test_admin_token_not_in_error(self):
        """SECURITY SI-10: admin token must not appear in error messages."""
        from fastapi import HTTPException
        secret = "my-admin-secret-token"
        with pytest.raises(HTTPException) as exc_info:
            _verify_admin_token(secret)
        assert secret not in str(exc_info.value.detail)
