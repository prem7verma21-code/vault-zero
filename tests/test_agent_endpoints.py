"""
Tests for agent API endpoints — Step 1.6 checkpoint.
Written for the Opus security rewrite.

Tests:
   1. register_agent — returns card_id + hmac_secret + valid_until
   2. register_agent with non-existent label — returns 404
   3. request_key — full happy path: register, add item, request key → decrypted value
   4. request_key with wrong HMAC signature — returns 403
   5. request_key with replayed nonce — returns 400
   6. request_key for label not in permissions — returns 403
   7. request_key with expired timestamp — returns 403
   8. revoke_card — card is removed and subsequent request_key returns 403
   9. get_pending_permissions — returns empty list initially
  10. respond_permission for unknown request_id — returns 404
  11. HMAC secret is zeroed from memory after card revocation
  12. invalid nonce format (not UUID4) — returns 400
  13. invalid signature format (not 64 hex chars) — returns 422

All tests use an isolated temporary database and unlock the vault first.
"""

import gc
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

TEST_PASSWORD = "agent-step1-6-test-password"


def _make_user_headers(token: str) -> dict:
    """Headers for user (session token) requests."""
    return {"Authorization": f"Bearer {token}"}


def _make_agent_headers(vault_api_key: str) -> dict:
    """Headers for agent (capability card) requests."""
    return {"Authorization": f"Bearer {vault_api_key}"}


def _sign_request(
    vault_api_key: str,
    msg_type: str,
    label: str,
    timestamp: int,
    nonce: str,
) -> str:
    """Produces the HMAC-SHA256 signature an agent must include with every request.

    This mirrors the exact signing logic in agent.py's _verify_hmac_signature().
    The message format is: card_id:type:label:timestamp:nonce
    Any mismatch → the signature won't verify → 403.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"vault-zero-hmac-v1",
    )
    secret = hkdf.derive(vault_api_key.encode("utf-8"))
    message = f"{vault_api_key}:{msg_type}:{label}:{timestamp}:{nonce}"
    return hmac.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# FIXTURES
# ---------------------------------------------------------------------------

@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    """Isolated temporary database for each test.

    Patches get_db_path in ALL route modules so they all use the same temp file.
    """
    db_path = str(tmp_path / "vault_agent_test.db")
    salt_path = str(Path(db_path).with_suffix(".salt"))

    monkeypatch.setattr("backend.api.routes.auth.get_db_path", lambda: db_path)
    monkeypatch.setattr("backend.api.routes.vault.get_db_path", lambda: db_path)
    monkeypatch.setattr("backend.api.routes.agent.get_db_path", lambda: db_path)
    monkeypatch.setattr("backend.database.models.get_db_path", lambda: db_path)

    yield db_path

    gc.collect()
    for p in (db_path, salt_path):
        if Path(p).exists():
            try:
                os.remove(p)
            except Exception:
                pass


@pytest.fixture()
def client(temp_db):
    """TestClient wired to the isolated temp database."""
    # Clear the in-memory stores between tests to prevent state leakage
    from backend.api.routes.agent import _used_nonces, _agent_hmac_secrets, _pending_permissions
    _used_nonces.clear()
    _agent_hmac_secrets.clear()
    _pending_permissions.clear()

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def auth_token(client):
    """Unlocks the vault and returns the user session token."""
    response = client.post(
        "/api/v1/auth/unlock",
        json={"password": TEST_PASSWORD},
    )
    assert response.status_code == 200, f"Unlock failed: {response.text}"
    return response.json()["session_token"]


@pytest.fixture()
def vault_item(client, auth_token):
    """Adds a test vault item and returns its metadata."""
    headers = _make_user_headers(auth_token)
    resp = client.post(
        "/api/v1/vault/items",
        json={"category": "api_key", "label": "OpenAI Key", "value": "sk-test-secret-value"},
        headers=headers,
    )
    assert resp.status_code == 201, f"Add item failed: {resp.text}"
    return resp.json()


@pytest.fixture()
def registered_agent(client, auth_token, vault_item):
    """Registers an agent with permission to access 'OpenAI Key'.

    Returns: { "vault_api_key": ..., "valid_until": ... }
    """
    headers = _make_user_headers(auth_token)
    resp = client.post(
        "/api/v1/agent/register",
        json={
            "agent_id": "test-cursor-agent",
            "permissions": ["OpenAI Key"],
            "ttl_hours": 1,
        },
        headers=headers,
    )
    assert resp.status_code == 201, f"Register agent failed: {resp.text}"
    data = resp.json()
    assert "vault_api_key" in data
    assert "valid_until" in data
    return data


# ---------------------------------------------------------------------------
# TEST 1 — register_agent: happy path
# ---------------------------------------------------------------------------

def test_register_agent_returns_vault_api_key(client, auth_token, vault_item):
    """register_agent must return vault_api_key and valid_until."""
    headers = _make_user_headers(auth_token)

    resp = client.post(
        "/api/v1/agent/register",
        json={
            "agent_id": "cursor",
            "permissions": ["OpenAI Key"],
            "ttl_hours": 1,
        },
        headers=headers,
    )

    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"
    data = resp.json()

    # vault_api_key starts with "vzk_" and is 68 chars total
    assert "vault_api_key" in data
    assert data["vault_api_key"].startswith("vzk_")
    assert len(data["vault_api_key"]) == 68

    # valid_until is a future Unix timestamp
    assert "valid_until" in data
    assert data["valid_until"] > int(time.time())


# ---------------------------------------------------------------------------
# TEST 2 — register_agent with non-existent label → 404
# ---------------------------------------------------------------------------

def test_register_agent_nonexistent_label_returns_404(client, auth_token):
    """register_agent must return 404 if any requested label doesn't exist."""
    headers = _make_user_headers(auth_token)

    resp = client.post(
        "/api/v1/agent/register",
        json={
            "agent_id": "bad-agent",
            "permissions": ["Label That Does Not Exist"],
            "ttl_hours": 1,
        },
        headers=headers,
    )

    assert resp.status_code == 404, (
        f"Expected 404 for non-existent label, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TEST 3 — request_key: full happy path → plaintext value returned
# ---------------------------------------------------------------------------

def test_request_key_returns_decrypted_value(client, auth_token, registered_agent):
    """Full happy path: register → request_key with valid signature → get plaintext.

    Verifies:
    - The key is correctly decrypted from the double-encrypted storage
    - The correct plaintext value is returned
    - The response does NOT contain the encrypted_payload
    """
    vault_api_key = registered_agent["vault_api_key"]

    nonce = str(uuid.uuid4())
    timestamp = int(time.time())
    label = "OpenAI Key"
    signature = _sign_request(vault_api_key, "request_key", label, timestamp, nonce)

    resp = client.post(
        "/api/v1/agent/request_key",
        json={
            "label": label,
            "nonce": nonce,
            "timestamp": timestamp,
            "signature": signature,
        },
        headers=_make_agent_headers(vault_api_key),
    )

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()

    assert data["label"] == label
    assert data["value"] == "sk-test-secret-value"  # Must match what was stored


# ---------------------------------------------------------------------------
# TEST 4 — request_key with wrong HMAC signature → 403
# ---------------------------------------------------------------------------

def test_request_key_wrong_signature_returns_403(client, auth_token, registered_agent):
    """request_key with a tampered/wrong signature must be rejected with 403.

    Tests Layer 2: request signing. Even with a valid card, a wrong
    signature means the payload was tampered or the secret is wrong.
    """
    vault_api_key = registered_agent["vault_api_key"]

    nonce = str(uuid.uuid4())
    timestamp = int(time.time())
    label = "OpenAI Key"

    # 64 hex chars but completely wrong — a valid format but invalid signature
    wrong_signature = "a" * 64

    resp = client.post(
        "/api/v1/agent/request_key",
        json={
            "label": label,
            "nonce": nonce,
            "timestamp": timestamp,
            "signature": wrong_signature,
        },
        headers=_make_agent_headers(vault_api_key),
    )

    assert resp.status_code == 403, (
        f"Expected 403 for wrong signature, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TEST 5 — request_key with replayed nonce → 400
# ---------------------------------------------------------------------------

def test_request_key_replayed_nonce_returns_400(client, auth_token, registered_agent):
    """Sending the same nonce twice must be rejected on the second request.

    Tests Layer 1: nonce binding. The first request succeeds (200);
    the second with the same nonce returns 400 replay_detected.
    """
    vault_api_key = registered_agent["vault_api_key"]

    nonce = str(uuid.uuid4())
    label = "OpenAI Key"

    # First request — should succeed (200)
    timestamp = int(time.time())
    sig = _sign_request(vault_api_key, "request_key", label, timestamp, nonce)
    r1 = client.post(
        "/api/v1/agent/request_key",
        json={"label": label, "nonce": nonce, "timestamp": timestamp, "signature": sig},
        headers=_make_agent_headers(vault_api_key),
    )
    assert r1.status_code == 200, f"First request failed: {r1.text}"

    # Second request with SAME nonce — must be rejected as replay
    timestamp2 = int(time.time())
    sig2 = _sign_request(vault_api_key, "request_key", label, timestamp2, nonce)
    r2 = client.post(
        "/api/v1/agent/request_key",
        json={"label": label, "nonce": nonce, "timestamp": timestamp2, "signature": sig2},
        headers=_make_agent_headers(vault_api_key),
    )
    assert r2.status_code == 400, (
        f"Expected 400 for replayed nonce, got {r2.status_code}: {r2.text}"
    )
    assert "replay" in r2.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# TEST 6 — request_key for label not in permissions → 403
# ---------------------------------------------------------------------------

def test_request_key_unpermitted_label_returns_403(client, auth_token, registered_agent):
    """An agent requesting a label NOT in its permissions list must get 403.

    We add a second vault item the agent doesn't have permission for,
    then try to access it with a card only granted access to "OpenAI Key".
    """
    headers_user = _make_user_headers(auth_token)

    # Add a second vault item the agent doesn't have permission for
    client.post(
        "/api/v1/vault/items",
        json={"category": "password", "label": "Secret Password", "value": "hunter2"},
        headers=headers_user,
    )

    vault_api_key = registered_agent["vault_api_key"]

    nonce = str(uuid.uuid4())
    timestamp = int(time.time())
    label = "Secret Password"  # NOT in this card's permissions
    sig = _sign_request(vault_api_key, "request_key", label, timestamp, nonce)

    resp = client.post(
        "/api/v1/agent/request_key",
        json={"label": label, "nonce": nonce, "timestamp": timestamp, "signature": sig},
        headers=_make_agent_headers(vault_api_key),
    )

    assert resp.status_code == 403, (
        f"Expected 403 for unpermitted label, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TEST 7 — request_key with stale timestamp → 403
# ---------------------------------------------------------------------------

def test_request_key_stale_timestamp_returns_403(client, auth_token, registered_agent):
    """A request with a timestamp more than 5 minutes old must be rejected with 403.

    This prevents an attacker from capturing a valid signed request and
    replaying it long after the original.
    """
    vault_api_key = registered_agent["vault_api_key"]

    nonce = str(uuid.uuid4())
    # Timestamp 10 minutes in the past — well outside the ±5 minute window
    timestamp = int(time.time()) - 600
    label = "OpenAI Key"
    sig = _sign_request(vault_api_key, "request_key", label, timestamp, nonce)

    resp = client.post(
        "/api/v1/agent/request_key",
        json={"label": label, "nonce": nonce, "timestamp": timestamp, "signature": sig},
        headers=_make_agent_headers(vault_api_key),
    )

    assert resp.status_code == 403, (
        f"Expected 403 for stale timestamp, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TEST 8 — revoke_card → subsequent request_key returns 403
# ---------------------------------------------------------------------------

def test_revoke_card_blocks_subsequent_requests(client, auth_token, registered_agent):
    """After revoking a card, the agent must receive 403 on any subsequent request."""
    vault_api_key = registered_agent["vault_api_key"]
    hashed_key = hashlib.sha256(vault_api_key.encode("utf-8")).hexdigest()
    headers_user = _make_user_headers(auth_token)

    # Revoke the card using the hashed key (ID)
    revoke_resp = client.delete(f"/api/v1/agent/cards/{hashed_key}", headers=headers_user)
    assert revoke_resp.status_code == 200, f"Revoke failed: {revoke_resp.text}"
    assert revoke_resp.json()["revoked"] is True

    # Try to use the revoked card — must fail
    nonce = str(uuid.uuid4())
    timestamp = int(time.time())
    label = "OpenAI Key"
    sig = _sign_request(vault_api_key, "request_key", label, timestamp, nonce)

    resp = client.post(
        "/api/v1/agent/request_key",
        json={"label": label, "nonce": nonce, "timestamp": timestamp, "signature": sig},
        headers=_make_agent_headers(vault_api_key),
    )

    assert resp.status_code == 403, (
        f"Expected 403 after revocation, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TEST 9 — get_pending_permissions: empty initially
# ---------------------------------------------------------------------------

def test_get_pending_permissions_empty_initially(client, auth_token):
    """GET /agent/pending_permissions should return an empty list when nothing is pending."""
    headers = _make_user_headers(auth_token)

    resp = client.get("/api/v1/agent/pending_permissions", headers=headers)

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert resp.json()["pending"] == []


# ---------------------------------------------------------------------------
# TEST 10 — respond_permission for unknown request_id → 404
# ---------------------------------------------------------------------------

def test_respond_permission_unknown_id_returns_404(client, auth_token):
    """Responding to a permission request that doesn't exist must return 404."""
    headers = _make_user_headers(auth_token)

    resp = client.post(
        "/api/v1/agent/respond_permission",
        json={"request_id": "nonexistent-request-id", "approved": True},
        headers=headers,
    )

    assert resp.status_code == 404, (
        f"Expected 404 for unknown request_id, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TEST 11 — vault_api_key is never stored plaintext in database
# ---------------------------------------------------------------------------

def test_vault_api_key_never_stored_plaintext(client, auth_token, registered_agent):
    """Verify that the raw vault_api_key is never stored in the database.

    This ensures that even if the database file is compromised, no agent credentials
    are leaked in plaintext.
    """
    vault_api_key = registered_agent["vault_api_key"]
    from backend.database.models import get_connection, get_db_path
    from backend.core.security import get_any_session_key

    db_path = get_db_path()
    session_key = get_any_session_key()
    assert session_key is not None

    with get_connection(db_path, session_key) as conn:
        rows = conn.execute("SELECT id, permissions FROM capability_cards").fetchall()
        for row in rows:
            card_id_in_db = row[0]
            # The card_id in the DB must be the SHA-256 hash of the vault_api_key, not the key itself
            assert card_id_in_db != vault_api_key
            assert card_id_in_db == hashlib.sha256(vault_api_key.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# TEST 12 — invalid nonce format (not UUID4) → 400
# ---------------------------------------------------------------------------

def test_request_key_invalid_nonce_format_returns_400(client, auth_token, registered_agent):
    """A nonce that is not a valid UUID4 must be rejected before any processing.

    This prevents memory abuse from extremely long nonces and ensures the
    nonce store stays efficient.
    """
    vault_api_key = registered_agent["vault_api_key"]

    bad_nonce = "not-a-valid-uuid-at-all"
    timestamp = int(time.time())
    label = "OpenAI Key"
    sig = _sign_request(vault_api_key, "request_key", label, timestamp, bad_nonce)

    resp = client.post(
        "/api/v1/agent/request_key",
        json={"label": label, "nonce": bad_nonce, "timestamp": timestamp, "signature": sig},
        headers=_make_agent_headers(vault_api_key),
    )

    assert resp.status_code == 400, (
        f"Expected 400 for invalid nonce format, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TEST 13 — invalid signature format (not 64 hex chars) → 422 (Pydantic)
# ---------------------------------------------------------------------------

def test_request_key_invalid_signature_format_returns_422(client, auth_token, registered_agent):
    """A signature that is not exactly 64 hex characters must be rejected at validation."""
    vault_api_key = registered_agent["vault_api_key"]

    nonce = str(uuid.uuid4())
    timestamp = int(time.time())
    label = "OpenAI Key"

    # Too short — not 64 chars
    bad_signature = "abc123"

    resp = client.post(
        "/api/v1/agent/request_key",
        json={"label": label, "nonce": nonce, "timestamp": timestamp, "signature": bad_signature},
        headers=_make_agent_headers(vault_api_key),
    )

    assert resp.status_code == 422, (
        f"Expected 422 for invalid signature format, got {resp.status_code}: {resp.text}"
    )
