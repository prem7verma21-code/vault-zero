"""
Tests for agent API endpoints — Step 1.6 checkpoint.
Single bearer token auth (no HMAC). Same auth model as OpenAI/Anthropic/Groq.

Tests:
   1. register_agent — returns vault_api_key + valid_until
   2. register_agent with non-existent label — returns 404
   3. request_key — full happy path: register, add item, request key → decrypted value
   4. request_key with replayed nonce — returns 403
   5. request_key for label not in permissions — returns 403
   6. request_key with expired timestamp — returns 403
   7. revoke_card — card is removed and subsequent request_key returns 403
   8. get_pending_permissions — returns empty list initially
   9. respond_permission for unknown request_id — returns 404
  10. vault_api_key is never stored plaintext in database
  11. invalid nonce format (not UUID4) — returns 400
  12. request_key missing nonce — returns 422
  13. request_key missing timestamp — returns 422

All tests use an isolated temporary database and unlock the vault first.
"""

import gc
import hashlib
import json
import os
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


def _make_payload(label: str, *, nonce: str | None = None, timestamp: int | None = None) -> dict:
    """Builds the JSON body an agent sends to /request_key.

    Single bearer token auth — no signing. Just label + nonce + timestamp.
    Caller can override nonce/timestamp; otherwise we generate fresh ones.
    """
    return {
        "label": label,
        "nonce": nonce if nonce is not None else str(uuid.uuid4()),
        "timestamp": timestamp if timestamp is not None else int(time.time()),
    }


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
    from backend.api.routes.agent import _used_nonces, _pending_permissions
    _used_nonces.clear()
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

    # No second secret — single bearer token, same as OpenAI/Anthropic/Groq
    assert "hmac_secret" not in data

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
    """Full happy path: register → request_key → get plaintext."""
    vault_api_key = registered_agent["vault_api_key"]

    resp = client.post(
        "/api/v1/agent/request_key",
        json=_make_payload("OpenAI Key"),
        headers=_make_agent_headers(vault_api_key),
    )

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["label"] == "OpenAI Key"
    assert data["value"] == "sk-test-secret-value"


# ---------------------------------------------------------------------------
# TEST 4 — request_key with replayed nonce → 403
# ---------------------------------------------------------------------------

def test_request_key_replayed_nonce_returns_403(client, auth_token, registered_agent):
    """Sending the same nonce twice must be rejected on the second request.

    Tests Layer 1: nonce binding. The first request succeeds (200);
    the second with the same nonce returns 403 (opaque, never reveal why).
    """
    vault_api_key = registered_agent["vault_api_key"]
    nonce = str(uuid.uuid4())

    r1 = client.post(
        "/api/v1/agent/request_key",
        json=_make_payload("OpenAI Key", nonce=nonce),
        headers=_make_agent_headers(vault_api_key),
    )
    assert r1.status_code == 200, f"First request failed: {r1.text}"

    r2 = client.post(
        "/api/v1/agent/request_key",
        json=_make_payload("OpenAI Key", nonce=nonce),
        headers=_make_agent_headers(vault_api_key),
    )
    assert r2.status_code == 403, (
        f"Expected 403 for replayed nonce, got {r2.status_code}: {r2.text}"
    )


# ---------------------------------------------------------------------------
# TEST 5 — request_key for label not in permissions → 403
# ---------------------------------------------------------------------------

def test_request_key_unpermitted_label_returns_403(client, auth_token, registered_agent):
    """An agent requesting a label NOT in its permissions list must get 403."""
    headers_user = _make_user_headers(auth_token)

    client.post(
        "/api/v1/vault/items",
        json={"category": "password", "label": "Secret Password", "value": "hunter2"},
        headers=headers_user,
    )

    vault_api_key = registered_agent["vault_api_key"]

    resp = client.post(
        "/api/v1/agent/request_key",
        json=_make_payload("Secret Password"),  # NOT in card permissions
        headers=_make_agent_headers(vault_api_key),
    )
    assert resp.status_code == 403, (
        f"Expected 403 for unpermitted label, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TEST 6 — request_key with stale timestamp → 403
# ---------------------------------------------------------------------------

def test_request_key_stale_timestamp_returns_403(client, auth_token, registered_agent):
    """A request with a timestamp more than 5 minutes old must be rejected with 403."""
    vault_api_key = registered_agent["vault_api_key"]
    stale = int(time.time()) - 600  # 10 minutes old

    resp = client.post(
        "/api/v1/agent/request_key",
        json=_make_payload("OpenAI Key", timestamp=stale),
        headers=_make_agent_headers(vault_api_key),
    )
    assert resp.status_code == 403, (
        f"Expected 403 for stale timestamp, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TEST 7 — revoke_card → subsequent request_key returns 403
# ---------------------------------------------------------------------------

def test_revoke_card_blocks_subsequent_requests(client, auth_token, registered_agent):
    """After revoking a card, the agent must receive 403 on any subsequent request."""
    vault_api_key = registered_agent["vault_api_key"]
    hashed_key = hashlib.sha256(vault_api_key.encode("utf-8")).hexdigest()
    headers_user = _make_user_headers(auth_token)

    revoke_resp = client.delete(f"/api/v1/agent/cards/{hashed_key}", headers=headers_user)
    assert revoke_resp.status_code == 200, f"Revoke failed: {revoke_resp.text}"
    assert revoke_resp.json()["revoked"] is True

    resp = client.post(
        "/api/v1/agent/request_key",
        json=_make_payload("OpenAI Key"),
        headers=_make_agent_headers(vault_api_key),
    )
    assert resp.status_code == 403, (
        f"Expected 403 after revocation, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TEST 8 — get_pending_permissions: empty initially
# ---------------------------------------------------------------------------

def test_get_pending_permissions_empty_initially(client, auth_token):
    """GET /agent/pending_permissions should return an empty list when nothing is pending."""
    headers = _make_user_headers(auth_token)

    resp = client.get("/api/v1/agent/pending_permissions", headers=headers)

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert resp.json()["pending"] == []


# ---------------------------------------------------------------------------
# TEST 9 — respond_permission for unknown request_id → 404
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
# TEST 10 — vault_api_key is never stored plaintext in database
# ---------------------------------------------------------------------------

def test_vault_api_key_never_stored_plaintext(client, auth_token, registered_agent):
    """Verify that the raw vault_api_key is never stored in the database."""
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
            assert card_id_in_db != vault_api_key
            assert card_id_in_db == hashlib.sha256(vault_api_key.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# TEST 11 — invalid nonce format (not UUID4) → 400
# ---------------------------------------------------------------------------

def test_request_key_invalid_nonce_format_returns_400(client, auth_token, registered_agent):
    """A nonce that is not a valid UUID4 must be rejected before any processing.

    Prevents memory abuse from extremely long nonces and keeps the nonce store efficient.
    """
    vault_api_key = registered_agent["vault_api_key"]

    resp = client.post(
        "/api/v1/agent/request_key",
        json=_make_payload("OpenAI Key", nonce="not-a-valid-uuid-at-all"),
        headers=_make_agent_headers(vault_api_key),
    )
    assert resp.status_code == 400, (
        f"Expected 400 for invalid nonce format, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TEST 12 — request_key missing nonce → 422
# ---------------------------------------------------------------------------

def test_request_key_missing_nonce_returns_422(client, auth_token, registered_agent):
    """A request without a nonce must be rejected at validation (Pydantic 422)."""
    vault_api_key = registered_agent["vault_api_key"]

    resp = client.post(
        "/api/v1/agent/request_key",
        json={"label": "OpenAI Key", "timestamp": int(time.time())},
        headers=_make_agent_headers(vault_api_key),
    )
    assert resp.status_code == 422, (
        f"Expected 422 for missing nonce, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TEST 13 — request_key missing timestamp → 422
# ---------------------------------------------------------------------------

def test_request_key_missing_timestamp_returns_422(client, auth_token, registered_agent):
    """A request without a timestamp must be rejected at validation (Pydantic 422)."""
    vault_api_key = registered_agent["vault_api_key"]

    resp = client.post(
        "/api/v1/agent/request_key",
        json={"label": "OpenAI Key", "nonce": str(uuid.uuid4())},
        headers=_make_agent_headers(vault_api_key),
    )
    assert resp.status_code == 422, (
        f"Expected 422 for missing timestamp, got {resp.status_code}: {resp.text}"
    )
