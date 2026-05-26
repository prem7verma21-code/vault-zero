"""
Tests for agent management (list and revoke endpoints) — Step 1.11.
Single bearer token auth (no HMAC).
"""

import gc
import hashlib
import os
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.core.crypto import derive_key, zero_memory
from backend.database.models import initialize_database

TEST_PASSWORD = "mgmt-test-password"


def _make_user_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _make_agent_headers(vault_api_key: str) -> dict:
    return {"Authorization": f"Bearer {vault_api_key}"}


def _make_payload(label: str, *, nonce: str | None = None, timestamp: int | None = None) -> dict:
    """Builds the JSON body an agent sends to /request_key.

    Single bearer token auth — no signing. label + nonce + timestamp.
    """
    return {
        "label": label,
        "nonce": nonce if nonce is not None else str(uuid.uuid4()),
        "timestamp": timestamp if timestamp is not None else int(time.time()),
    }


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "vault_mgmt_test.db")
    salt_path = str(Path(db_path).with_suffix(".salt"))

    # Derive a key using the same device-bound password the API uses, so the
    # DB this fixture pre-creates can be opened by /unlock with TEST_PASSWORD.
    from tests.conftest import TEST_DEVICE_FINGERPRINT
    bound_password = f"{TEST_PASSWORD}:{TEST_DEVICE_FINGERPRINT}"
    key, salt = derive_key(bound_password)

    # Save the salt alongside the database
    with open(salt_path, "wb") as f:
        f.write(salt)

    # Initialize all tables in the temp db
    initialize_database(db_path, key)
    zero_memory(key)

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
    from backend.api.routes.agent import _used_nonces, _pending_permissions
    _used_nonces.clear()
    _pending_permissions.clear()

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def auth_token(client):
    response = client.post(
        "/api/v1/auth/unlock",
        json={"password": TEST_PASSWORD},
    )
    assert response.status_code == 200, f"Unlock failed: {response.text}"
    return response.json()["session_token"]


@pytest.fixture()
def vault_item(client, auth_token):
    headers = _make_user_headers(auth_token)
    resp = client.post(
        "/api/v1/vault/items",
        json={"category": "api_key", "label": "OpenAI Key", "value": "sk-test-mgmt-value"},
        headers=headers,
    )
    assert resp.status_code == 201
    return resp.json()


def test_register_and_list_agent(client, auth_token, vault_item):
    """Test 1: Register an agent → call list → verify it is included in the output list."""
    headers = _make_user_headers(auth_token)

    # Register
    reg_resp = client.post(
        "/api/v1/agent/register",
        json={
            "agent_id": "test-agent-1",
            "permissions": ["OpenAI Key"],
            "ttl_hours": 2,
        },
        headers=headers,
    )
    assert reg_resp.status_code == 201
    reg_data = reg_resp.json()
    vault_api_key = reg_data["vault_api_key"]

    # List
    list_resp = client.get("/api/v1/agent/list", headers=headers)
    assert list_resp.status_code == 200
    list_data = list_resp.json()

    assert len(list_data) == 1
    agent = list_data[0]
    assert agent["agent_name"] == "test-agent-1"
    assert agent["allowed_labels"] == ["OpenAI Key"]
    assert agent["is_expired"] is False
    # The card_id listed must be the SHA-256 hash of the vault_api_key
    expected_card_id = hashlib.sha256(vault_api_key.encode("utf-8")).hexdigest()
    assert agent["card_id"] == expected_card_id


def test_revoke_agent(client, auth_token, vault_item):
    """Test 2: Revoke an agent → call list → verify it is no longer listed."""
    headers = _make_user_headers(auth_token)

    # Register
    reg_resp = client.post(
        "/api/v1/agent/register",
        json={
            "agent_id": "test-agent-2",
            "permissions": ["OpenAI Key"],
            "ttl_hours": 1,
        },
        headers=headers,
    )
    assert reg_resp.status_code == 201
    reg_data = reg_resp.json()
    vault_api_key = reg_data["vault_api_key"]
    hashed_key = hashlib.sha256(vault_api_key.encode("utf-8")).hexdigest()

    # Revoke
    revoke_resp = client.delete(f"/api/v1/agent/revoke/{hashed_key}", headers=headers)
    assert revoke_resp.status_code == 200
    assert revoke_resp.json() == {"revoked": True, "card_id": hashed_key}

    # List
    list_resp = client.get("/api/v1/agent/list", headers=headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 0


def test_revoke_non_existent_card_returns_404(client, auth_token):
    """Test 3: Revoke non-existent card_id → expect HTTP 404."""
    headers = _make_user_headers(auth_token)
    bad_card_id = "a" * 64
    resp = client.delete(f"/api/v1/agent/revoke/{bad_card_id}", headers=headers)
    assert resp.status_code == 404


def test_revoke_agent_blocks_requests(client, auth_token, vault_item):
    """Test 4: Revoke agent → attempt to request_key with the revoked agent's token → expect HTTP 403."""
    headers = _make_user_headers(auth_token)

    # Register
    reg_resp = client.post(
        "/api/v1/agent/register",
        json={
            "agent_id": "test-agent-4",
            "permissions": ["OpenAI Key"],
            "ttl_hours": 1,
        },
        headers=headers,
    )
    assert reg_resp.status_code == 201
    reg_data = reg_resp.json()
    vault_api_key = reg_data["vault_api_key"]
    hashed_key = hashlib.sha256(vault_api_key.encode("utf-8")).hexdigest()

    # First verify request_key works
    resp = client.post(
        "/api/v1/agent/request_key",
        json=_make_payload("OpenAI Key"),
        headers=_make_agent_headers(vault_api_key),
    )
    assert resp.status_code == 200

    # Revoke
    revoke_resp = client.delete(f"/api/v1/agent/revoke/{hashed_key}", headers=headers)
    assert revoke_resp.status_code == 200

    # Try requesting again — must return 403
    resp2 = client.post(
        "/api/v1/agent/request_key",
        json=_make_payload("OpenAI Key"),
        headers=_make_agent_headers(vault_api_key),
    )
    assert resp2.status_code == 403


def test_list_requires_user_session_token(client, auth_token, vault_item):
    """Test 5: Confirm list endpoint requires user session token (not agent token)."""
    headers = _make_user_headers(auth_token)

    # Register an agent
    reg_resp = client.post(
        "/api/v1/agent/register",
        json={
            "agent_id": "test-agent-5",
            "permissions": ["OpenAI Key"],
            "ttl_hours": 1,
        },
        headers=headers,
    )
    assert reg_resp.status_code == 201
    vault_api_key = reg_resp.json()["vault_api_key"]

    # Try listing without any authorization header -> 401 Unauthorized
    resp_no_auth = client.get("/api/v1/agent/list")
    assert resp_no_auth.status_code == 401

    # Try listing with the agent's key -> 401 (since agent token is not a valid user JWT)
    resp_agent_auth = client.get("/api/v1/agent/list", headers=_make_agent_headers(vault_api_key))
    assert resp_agent_auth.status_code == 401


def test_register_never_expire_agent(client, auth_token, vault_item):
    """Test: Register with ttl_hours=None -> card has valid_until=None"""
    headers = _make_user_headers(auth_token)
    reg_resp = client.post(
        "/api/v1/agent/register",
        json={
            "agent_id": "never-expire-agent",
            "permissions": ["OpenAI Key"],
            "ttl_hours": None,
        },
        headers=headers,
    )
    assert reg_resp.status_code == 201
    reg_data = reg_resp.json()
    assert reg_data["valid_until"] is None

    # Retrieve from list endpoint and verify valid_until is None and is_expired is False
    list_resp = client.get("/api/v1/agent/list", headers=headers)
    assert list_resp.status_code == 200
    agents = list_resp.json()
    never_expire_agent = next(a for a in agents if a["agent_name"] == "never-expire-agent")
    assert never_expire_agent["valid_until"] is None
    assert never_expire_agent["is_expired"] is False


def test_never_expire_card_request_key_works_after_time_advance(client, auth_token, vault_item, monkeypatch):
    """Test: Never-expire card -> request_key still works after simulated time advance"""
    headers = _make_user_headers(auth_token)
    reg_resp = client.post(
        "/api/v1/agent/register",
        json={
            "agent_id": "never-expire-time-agent",
            "permissions": ["OpenAI Key"],
            "ttl_hours": None,
        },
        headers=headers,
    )
    assert reg_resp.status_code == 201
    vault_api_key = reg_resp.json()["vault_api_key"]

    # Advance time by 10 years (10 * 365 * 24 * 3600 seconds)
    future_time = int(time.time()) + 10 * 365 * 24 * 3600
    monkeypatch.setattr(time, "time", lambda: float(future_time))

    resp = client.post(
        "/api/v1/agent/request_key",
        json=_make_payload("OpenAI Key", timestamp=future_time),
        headers=_make_agent_headers(vault_api_key),
    )
    assert resp.status_code == 200
    assert resp.json()["value"] == "sk-test-mgmt-value"


def test_register_agent_with_ttl_zero_returns_400(client, auth_token, vault_item):
    """Test: Register with ttl_hours=0 -> 400 error"""
    headers = _make_user_headers(auth_token)
    reg_resp = client.post(
        "/api/v1/agent/register",
        json={
            "agent_id": "bad-agent",
            "permissions": ["OpenAI Key"],
            "ttl_hours": 0,
        },
        headers=headers,
    )
    assert reg_resp.status_code == 400
    assert "ttl_hours must be positive" in reg_resp.text
