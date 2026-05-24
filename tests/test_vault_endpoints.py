"""
Tests for vault CRUD endpoints — Step 1.5 checkpoint.

Tests:
  1. Add item, GET items → response contains label but NOT encrypted_payload
  2. Add two items, GET items → list has 2 items
  3. DELETE a real item → 200 response with {deleted: true}
  4. DELETE a non-existent UUID → 404 response
  5. Add item with duplicate label → 409 response

All tests use a temporary isolated database and unlock the vault first,
matching exactly the pattern from test_auth.py.
"""

import gc
import json
import os
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

# ── bring the backend package onto sys.path (conftest.py does this) ──────────

from backend.api.main import app
from backend.api.routes.auth import unlock, UnlockRequest
from backend.core.security import create_session, get_session_key


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

TEST_PASSWORD = "vault-step1-5-test-password"


def _make_auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# FIXTURES
# ---------------------------------------------------------------------------

@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    """Create an isolated temporary database for each test.

    Monkeypatches get_db_path in BOTH the auth and vault route modules
    so they both read from the same temp file.
    """
    db_path = str(tmp_path / "vault_test.db")
    salt_path = str(Path(db_path).with_suffix(".salt"))

    monkeypatch.setattr("backend.api.routes.auth.get_db_path", lambda: db_path)
    monkeypatch.setattr("backend.api.routes.vault.get_db_path", lambda: db_path)

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
    """Returns a TestClient that uses the isolated temp database."""
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def auth_token(client):
    """Unlocks the vault with the test password and returns the session token."""
    response = client.post(
        "/api/v1/auth/unlock",
        json={"password": TEST_PASSWORD},
    )
    assert response.status_code == 200, f"Unlock failed: {response.text}"
    return response.json()["session_token"]


# ---------------------------------------------------------------------------
# TEST 1 — Add item, GET items → label present, encrypted_payload absent
# ---------------------------------------------------------------------------

def test_add_item_then_list_no_payload(client, auth_token):
    """After adding an item, GET /vault/items must return the label but NEVER
    the encrypted_payload field.

    This is the most critical security rule in Step 1.5: the API surface must
    never expose raw encrypted (or decrypted) payloads to the UI.
    """
    headers = _make_auth_headers(auth_token)

    # Add a new item
    add_resp = client.post(
        "/api/v1/vault/items",
        json={"category": "api_key", "label": "OpenAI Key", "value": "sk-test-123"},
        headers=headers,
    )
    assert add_resp.status_code == 201, f"Add failed: {add_resp.text}"

    # List all items
    list_resp = client.get("/api/v1/vault/items", headers=headers)
    assert list_resp.status_code == 200, f"List failed: {list_resp.text}"

    items = list_resp.json()["items"]
    assert len(items) == 1

    item = items[0]
    # Label must be present
    assert item["label"] == "OpenAI Key"
    assert item["category"] == "api_key"
    # encrypted_payload must NEVER appear in the response
    assert "encrypted_payload" not in item, (
        "SECURITY VIOLATION: encrypted_payload was returned in the list response!"
    )
    # Decrypted value must not appear
    assert "value" not in item


# ---------------------------------------------------------------------------
# TEST 2 — Add two items, GET items → list has exactly 2 items
# ---------------------------------------------------------------------------

def test_add_two_items_list_returns_both(client, auth_token):
    """Two separate POST /vault/items calls should produce a list of 2 items."""
    headers = _make_auth_headers(auth_token)

    r1 = client.post(
        "/api/v1/vault/items",
        json={"category": "api_key", "label": "Key One", "value": "sk-value-1"},
        headers=headers,
    )
    assert r1.status_code == 201

    r2 = client.post(
        "/api/v1/vault/items",
        json={"category": "token", "label": "Key Two", "value": "token-value-2"},
        headers=headers,
    )
    assert r2.status_code == 201

    list_resp = client.get("/api/v1/vault/items", headers=headers)
    assert list_resp.status_code == 200

    items = list_resp.json()["items"]
    assert len(items) == 2

    labels = {item["label"] for item in items}
    assert labels == {"Key One", "Key Two"}


# ---------------------------------------------------------------------------
# TEST 3 — DELETE a real item → 200 with {deleted: true}
# ---------------------------------------------------------------------------

def test_delete_existing_item(client, auth_token):
    """Deleting an item that exists must return 200 with deleted=true,
    and a subsequent GET must show an empty list.
    """
    headers = _make_auth_headers(auth_token)

    # Add an item
    add_resp = client.post(
        "/api/v1/vault/items",
        json={"category": "password", "label": "GitHub Token", "value": "ghp-secret"},
        headers=headers,
    )
    assert add_resp.status_code == 201
    item_id = add_resp.json()["id"]

    # Delete it
    del_resp = client.delete(f"/api/v1/vault/items/{item_id}", headers=headers)
    assert del_resp.status_code == 200, f"Delete failed: {del_resp.text}"

    body = del_resp.json()
    assert body["deleted"] is True
    assert body["id"] == item_id

    # Verify the vault is now empty
    list_resp = client.get("/api/v1/vault/items", headers=headers)
    assert list_resp.status_code == 200
    assert list_resp.json()["items"] == []


# ---------------------------------------------------------------------------
# TEST 4 — DELETE a non-existent UUID → 404
# ---------------------------------------------------------------------------

def test_delete_nonexistent_item_returns_404(client, auth_token):
    """Attempting to delete an item ID that does not exist must return 404."""
    headers = _make_auth_headers(auth_token)
    fake_id = "00000000-0000-0000-0000-000000000000"

    del_resp = client.delete(f"/api/v1/vault/items/{fake_id}", headers=headers)
    assert del_resp.status_code == 404, (
        f"Expected 404 for non-existent ID, got {del_resp.status_code}"
    )


# ---------------------------------------------------------------------------
# TEST 5 — Add item with duplicate label → 409 Conflict
# ---------------------------------------------------------------------------

def test_duplicate_label_returns_409(client, auth_token):
    """Adding a second item with the same label must return 409 Conflict.

    Labels must be unique within a vault — this prevents accidental overwrites
    and makes it unambiguous which item an agent is requesting.
    """
    headers = _make_auth_headers(auth_token)

    # First add — should succeed
    r1 = client.post(
        "/api/v1/vault/items",
        json={"category": "api_key", "label": "Duplicate Label", "value": "first-value"},
        headers=headers,
    )
    assert r1.status_code == 201

    # Second add with same label — must fail with 409
    r2 = client.post(
        "/api/v1/vault/items",
        json={"category": "api_key", "label": "Duplicate Label", "value": "second-value"},
        headers=headers,
    )
    assert r2.status_code == 409, (
        f"Expected 409 for duplicate label, got {r2.status_code}: {r2.text}"
    )


# ---------------------------------------------------------------------------
# BONUS — invalid category returns 422 (Pydantic validation)
# ---------------------------------------------------------------------------

def test_invalid_category_returns_422(client, auth_token):
    """An empty category must be rejected at validation time (422).

    The backend accepts any non-empty category string — the frontend dropdown
    enforces the three UI options (API KEY / URL / ID), but the backend
    never restricts storage.  An empty string is the only truly invalid value.
    """
    headers = _make_auth_headers(auth_token)

    resp = client.post(
        "/api/v1/vault/items",
        json={"category": "", "label": "Test", "value": "val"},
        headers=headers,
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# BONUS — unauthenticated requests return 401 / 403
# ---------------------------------------------------------------------------

def test_get_items_requires_auth(client):
    """GET /vault/items without a token must be rejected."""
    resp = client.get("/api/v1/vault/items")
    # FastAPI HTTPBearer returns 403 when no credentials are provided
    assert resp.status_code in (401, 403)


def test_post_item_requires_auth(client):
    """POST /vault/items without a token must be rejected."""
    resp = client.post(
        "/api/v1/vault/items",
        json={"category": "api_key", "label": "X", "value": "y"},
    )
    assert resp.status_code in (401, 403)
