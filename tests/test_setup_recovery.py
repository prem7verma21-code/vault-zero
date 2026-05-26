"""
Tests for the /auth/setup and /auth/recover endpoints.

Covers:
  - setup: happy path, 409 conflict, password too short
  - recover: happy path (re-keys DB and rotates all credentials),
             wrong recovery code, password too short, no vault
  - _generate_recovery_code: format contract
"""

import gc
import json
import os
import shutil
from pathlib import Path

import pytest
from fastapi import HTTPException

from backend.api.routes.auth import (
    RecoverRequest,
    SetupRequest,
    _generate_recovery_code,
    recover,
    setup,
    unlock,
    UnlockRequest,
)


# ---------------------------------------------------------------------------
# SHARED TEST HELPERS
# ---------------------------------------------------------------------------

def get_mock_request() -> object:
    """Creates a real Starlette Request with a minimal HTTP scope.

    slowapi's rate-limiter inspects the request object's type, so we need
    a real Request instance (not a Mock) or the limiter decorator will fail.
    """
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/auth/setup",
        "headers": [],
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope=scope)


# ---------------------------------------------------------------------------
# FIXTURES
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_db(monkeypatch, tmp_path):
    """Give every test its own temporary DB path, cleaned up after.

    We monkeypatch get_db_path() so all the endpoints in auth.py resolve
    to the temp directory rather than the real AppData vault.
    """
    temp_db = str(tmp_path / "vault_test.db")
    monkeypatch.setattr("backend.api.routes.auth.get_db_path", lambda: temp_db)
    yield temp_db
    gc.collect()
    # tmp_path is cleaned up automatically by pytest


# ---------------------------------------------------------------------------
# _generate_recovery_code
# ---------------------------------------------------------------------------

def test_recovery_code_format():
    """Recovery code must match VAULT-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX."""
    code = _generate_recovery_code()
    parts = code.split("-")
    # VAULT + 6 hex groups = 7 parts
    assert parts[0] == "VAULT", f"Expected VAULT prefix, got {parts[0]!r}"
    assert len(parts) == 7, f"Expected 7 dash-separated parts, got {len(parts)}"
    for group in parts[1:]:
        assert len(group) == 4, f"Expected 4-char hex group, got {group!r}"
        assert all(c in "0123456789ABCDEF" for c in group), f"Non-hex char in {group!r}"


def test_recovery_code_is_random():
    """Two consecutive codes must not be equal (with overwhelming probability)."""
    codes = {_generate_recovery_code() for _ in range(20)}
    assert len(codes) == 20, "Recovery codes must be unique across calls"


# ---------------------------------------------------------------------------
# POST /auth/setup — happy path
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_setup_creates_vault_and_returns_token(isolated_db):
    """First-time setup must create the DB and return a session token + recovery code."""
    req = get_mock_request()
    body = SetupRequest(password="StrongPass1")

    response = await setup(req, body)

    assert response.session_token, "Expected a non-empty session token"
    assert response.recovery_code.startswith("VAULT-"), "Recovery code must start with VAULT-"

    db_path = isolated_db
    assert Path(db_path).exists(), "vault.db must be created"
    assert Path(db_path).with_suffix(".salt").exists(), ".salt file must be created"
    assert Path(db_path).with_suffix(".recovery.salt").exists(), ".recovery.salt must be created"
    assert Path(db_path).with_suffix(".keyblob").exists(), ".keyblob must be created"


@pytest.mark.anyio
async def test_setup_recovery_code_never_equals_another(isolated_db):
    """Each /setup call must produce a unique recovery code (probabilistic guarantee)."""
    # We can't call setup twice on the same DB (it would 409), so we test
    # the generator directly — which is the source of the code.
    codes = {_generate_recovery_code() for _ in range(50)}
    assert len(codes) == 50


# ---------------------------------------------------------------------------
# POST /auth/setup — error cases
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_setup_password_too_short_returns_400(isolated_db):
    """setup must reject passwords shorter than 8 characters with HTTP 400."""
    req = get_mock_request()
    body = SetupRequest(password="short")  # 5 chars

    with pytest.raises(HTTPException) as exc_info:
        await setup(req, body)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "password_too_short"


@pytest.mark.anyio
async def test_setup_exactly_8_chars_is_accepted(isolated_db):
    """An 8-character password is exactly at the minimum — must succeed."""
    req = get_mock_request()
    body = SetupRequest(password="12345678")  # exactly 8 chars

    response = await setup(req, body)
    assert response.session_token


@pytest.mark.anyio
async def test_setup_twice_returns_409(isolated_db):
    """Calling /setup when the vault is already initialized must return HTTP 409."""
    req = get_mock_request()
    # First setup — should succeed
    await setup(req, SetupRequest(password="InitialPass1"))

    # Second setup — must 409
    with pytest.raises(HTTPException) as exc_info:
        await setup(req, SetupRequest(password="AnotherPass1"))

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "vault_already_initialized"


# ---------------------------------------------------------------------------
# POST /auth/recover — happy path
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_recover_success_changes_password_and_rotates_code(isolated_db):
    """Recovery must re-key the vault and return a new session + new recovery code."""
    req = get_mock_request()

    # 1. Initialize the vault
    setup_response = await setup(req, SetupRequest(password="OldPassword1"))
    old_recovery_code = setup_response.recovery_code
    old_token = setup_response.session_token

    # 2. Recover with the recovery code and a new password
    recover_response = await recover(
        req,
        RecoverRequest(recovery_code=old_recovery_code, new_password="NewPassword1"),
    )

    assert recover_response.session_token, "Expected a new session token"
    assert recover_response.new_recovery_code, "Expected a new recovery code"
    assert recover_response.new_recovery_code != old_recovery_code, (
        "New recovery code must differ from the old one"
    )
    assert recover_response.new_recovery_code.startswith("VAULT-")

    # 3. The old token should now be stale (not re-usable — that's a session layer concern)
    # 4. Verify the new password unlocks the vault
    unlock_response = await unlock(req, UnlockRequest(password="NewPassword1"))
    assert unlock_response.session_token


@pytest.mark.anyio
async def test_recover_old_password_no_longer_works(isolated_db):
    """After recovery, the old master password must be rejected by /unlock."""
    req = get_mock_request()

    setup_response = await setup(req, SetupRequest(password="OldPassword1"))
    old_rc = setup_response.recovery_code

    await recover(req, RecoverRequest(recovery_code=old_rc, new_password="NewPassword1"))

    # The old password must now be rejected
    with pytest.raises(HTTPException) as exc_info:
        await unlock(req, UnlockRequest(password="OldPassword1"))

    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# POST /auth/recover — error cases
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_recover_wrong_code_returns_401(isolated_db):
    """A wrong recovery code must be rejected with HTTP 401."""
    req = get_mock_request()
    await setup(req, SetupRequest(password="SomePassword1"))

    wrong_code = "VAULT-0000-0000-0000-0000-0000-0000"
    with pytest.raises(HTTPException) as exc_info:
        await recover(req, RecoverRequest(recovery_code=wrong_code, new_password="NewPassword1"))

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "invalid_recovery_code"


@pytest.mark.anyio
async def test_recover_password_too_short_returns_400(isolated_db):
    """Recovery must reject a new_password shorter than 8 chars with HTTP 400."""
    req = get_mock_request()
    setup_response = await setup(req, SetupRequest(password="OldPassword1"))
    old_rc = setup_response.recovery_code

    with pytest.raises(HTTPException) as exc_info:
        await recover(req, RecoverRequest(recovery_code=old_rc, new_password="short"))

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "password_too_short"


@pytest.mark.anyio
async def test_recover_no_vault_returns_401(isolated_db):
    """Recovery must return 401 if no vault exists at all."""
    req = get_mock_request()

    with pytest.raises(HTTPException) as exc_info:
        await recover(
            req,
            RecoverRequest(
                recovery_code="VAULT-0000-0000-0000-0000-0000-0000",
                new_password="NewPassword1",
            ),
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "invalid_recovery_code"


@pytest.mark.anyio
async def test_recover_rotates_keyblob_and_salt(isolated_db):
    """After recovery, the .keyblob and .recovery.salt files must change."""
    req = get_mock_request()
    db_path = isolated_db

    setup_response = await setup(req, SetupRequest(password="OldPassword1"))
    old_rc = setup_response.recovery_code

    keyblob_path = Path(db_path).with_suffix(".keyblob")
    recovery_salt_path = Path(db_path).with_suffix(".recovery.salt")

    old_keyblob = keyblob_path.read_text()
    old_recovery_salt = recovery_salt_path.read_bytes()

    await recover(req, RecoverRequest(recovery_code=old_rc, new_password="NewPassword1"))

    new_keyblob = keyblob_path.read_text()
    new_recovery_salt = recovery_salt_path.read_bytes()

    assert new_keyblob != old_keyblob, ".keyblob must be rotated after recovery"
    assert new_recovery_salt != old_recovery_salt, ".recovery.salt must be rotated after recovery"


# ---------------------------------------------------------------------------
# DEVICE BINDING (Step 1.12)
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_unlock_rejects_different_device(isolated_db, monkeypatch):
    """Copying the vault to another machine must produce a clear 403 device_mismatch.

    Setup runs under the conftest's pinned fingerprint. Then we re-pin the
    fingerprint to a different value to simulate the vault being copied to a
    new machine, and assert /unlock rejects it before even hitting the KDF.
    """
    req = get_mock_request()
    await setup(req, SetupRequest(password="OriginalPass1"))

    # The vault was bound to TEST_DEVICE_FINGERPRINT during setup.
    # Now switch fingerprint as if the files were copied to a different box.
    different = "different-device-" + "f" * 47  # still 64 chars, not the conftest constant
    monkeypatch.setattr(
        "backend.api.routes.auth.get_device_fingerprint",
        lambda: different,
    )

    with pytest.raises(HTTPException) as exc_info:
        await unlock(req, UnlockRequest(password="OriginalPass1"))

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "device_mismatch"


@pytest.mark.anyio
async def test_recover_rotates_device_binding(isolated_db, monkeypatch):
    """Recovery is the deliberate "I'm on a new machine" path.

    Setup on machine A → simulate transferring the files to machine B (no
    physical copy in the test, just a fingerprint swap) → /unlock fails with
    device_mismatch → /recover succeeds and rebinds to B → /unlock now works
    on B with the new password, and an attempt with the *original* fingerprint
    would now fail (vault is bound to B).
    """
    req = get_mock_request()
    db_path = isolated_db
    device_hash_path = Path(db_path).with_suffix(".device.hash")

    # Set up on "machine A" (default conftest fingerprint).
    setup_response = await setup(req, SetupRequest(password="OldPassword1"))
    old_rc = setup_response.recovery_code
    a_device_hash = device_hash_path.read_text()

    # Simulate moving the files to "machine B".
    machine_b = "machine-b-fingerprint-" + "b" * 42  # 64 chars
    monkeypatch.setattr(
        "backend.api.routes.auth.get_device_fingerprint",
        lambda: machine_b,
    )

    # Direct /unlock fails on B before recovery.
    with pytest.raises(HTTPException) as exc_info:
        await unlock(req, UnlockRequest(password="OldPassword1"))
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "device_mismatch"

    # Recover with the recovery code → rebinds to B.
    await recover(
        req,
        RecoverRequest(recovery_code=old_rc, new_password="NewPassword1"),
    )

    b_device_hash = device_hash_path.read_text()
    assert b_device_hash != a_device_hash, ".device.hash must rotate on recovery"

    # /unlock now works on B with the new password.
    unlock_response = await unlock(req, UnlockRequest(password="NewPassword1"))
    assert unlock_response.session_token

    # If we then "go back to A", it should fail — the vault is now bound to B.
    monkeypatch.setattr(
        "backend.api.routes.auth.get_device_fingerprint",
        lambda: "test-device-" + "0" * 52,  # the original conftest constant
    )
    with pytest.raises(HTTPException) as exc_info:
        await unlock(req, UnlockRequest(password="NewPassword1"))
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "device_mismatch"
