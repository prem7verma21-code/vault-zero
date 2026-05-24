"""
Tests for the binary WebSocket tunnel — Step 1.7 checkpoint.

Tests:
   1. Handshake → encrypted "connected" confirmation
   2. key_request for valid label → decrypted plaintext secret
   3. key_request for invalid label → "access denied"
   4. Corrupted encryption → connection closes with code 4002
   5. ping → pong with matching msg_id

Each test:
  - Creates an isolated temporary SQLCipher database
  - Unlocks the vault with a test password (stores session key)
  - Registers an agent via the REST API to get a valid card_id + HMAC secret
  - Adds a vault item for key_request tests
  - Starts the WebSocket tunnel server on a random port
  - Connects with the `websockets` library and exercises the protocol
  - Tears everything down cleanly

SECURITY NOTE: These tests use the REAL crypto stack (AES-256-GCM + Argon2id).
No crypto is mocked. This verifies the tunnel works end-to-end with production
encryption, exactly as it will run in the real app.
"""

import asyncio
import gc
import hashlib
import hmac as hmac_mod
import json
import os
import time
import uuid
from pathlib import Path

import msgpack
import pytest
import pytest_asyncio
import websockets

from backend.core.crypto import encrypt, decrypt, derive_key, zero_memory
from backend.core.security import create_session, get_any_session_key, destroy_all_sessions
from backend.database.models import (
    get_connection,
    initialize_database,
    insert_vault_item,
)
from backend.api.routes.agent import (
    _register_hmac_secret,
    _used_nonces,
    _agent_hmac_secrets,
    _pending_permissions,
    destroy_all_agent_secrets,
)
from backend.database.models import insert_capability_card
from backend.tunnel.ws_handler import start_tunnel_server, stop_tunnel_server


# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

TEST_PASSWORD = "tunnel-step-1-7-test-password"
TEST_LABEL = "Tunnel Test Key"
TEST_SECRET_VALUE = "sk-tunnel-test-secret-12345"

# Tell pytest-asyncio to treat all async tests in this module as asyncio tests
pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _sign_request(
    hmac_secret_hex: str,
    card_id: str,
    msg_type: str,
    label: str,
    timestamp: int,
    nonce: str,
) -> str:
    """Produces the HMAC-SHA256 signature matching agent.py's _verify_hmac_signature().

    Message format: card_id:type:label:timestamp:nonce
    """
    secret = bytes.fromhex(hmac_secret_hex)
    message = f"{card_id}:{msg_type}:{label}:{timestamp}:{nonce}"
    return hmac_mod.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()


def _encrypt_outbound(message: dict, session_key: bytearray) -> bytes:
    """Encrypts a message dict for sending to the tunnel server (client side).

    Mirrors the server's _encrypt_outbound logic:
      1. MsgPack-serialize the message dict
      2. AES-256-GCM encrypt the raw bytes
      3. MsgPack-serialize the encryption bundle
    """
    raw = msgpack.packb(message, use_bin_type=True)
    bundle = encrypt(raw, session_key)
    return msgpack.packb(bundle, use_bin_type=True)


def _decrypt_inbound(frame: bytes, session_key: bytearray) -> dict:
    """Decrypts a binary frame received from the tunnel server (client side).

    Mirrors the server's _decrypt_inbound logic:
      1. MsgPack-unpack the outer layer → {nonce, ciphertext}
      2. AES-256-GCM decrypt → raw MsgPack bytes
      3. MsgPack-unpack the inner layer → message dict
    """
    bundle = msgpack.unpackb(frame, raw=False)
    raw = decrypt(bundle, session_key)
    return msgpack.unpackb(bytes(raw), raw=False)


# ---------------------------------------------------------------------------
# FIXTURES
# ---------------------------------------------------------------------------

@pytest.fixture()
def temp_db(tmp_path):
    """Creates an isolated temporary SQLCipher database with all tables."""
    db_path = str(tmp_path / "vault_tunnel_test.db")

    # Derive a key from the test password
    key, salt = derive_key(TEST_PASSWORD)

    # Save the salt alongside the database (same convention as auth.py)
    salt_path = str(Path(db_path).with_suffix(".salt"))
    with open(salt_path, "wb") as f:
        f.write(salt)

    # Create all tables
    initialize_database(db_path, key)

    yield db_path, key

    # Cleanup: zero the key and remove files
    zero_memory(key)
    gc.collect()
    for p in (db_path, salt_path):
        if Path(p).exists():
            try:
                os.remove(p)
            except Exception:
                pass


@pytest.fixture()
def unlocked_vault(temp_db, monkeypatch):
    """Unlocks the vault by storing the derived key in a session.

    Also patches get_db_path in the tunnel's import chain so all modules
    use the same temporary database.
    """
    db_path, key = temp_db

    # Patch get_db_path everywhere it's imported
    monkeypatch.setattr("backend.database.models.get_db_path", lambda: db_path)
    monkeypatch.setattr("backend.api.routes.auth.get_db_path", lambda: db_path)
    monkeypatch.setattr("backend.api.routes.vault.get_db_path", lambda: db_path)
    monkeypatch.setattr("backend.api.routes.agent.get_db_path", lambda: db_path)
    monkeypatch.setattr("backend.tunnel.ws_handler.get_db_path", lambda: db_path)

    # Destroy any stale sessions left by previous test modules.
    # Without this, get_any_session_key() might return a zeroed-out key
    # from a prior test instead of our fresh one.
    destroy_all_sessions()
    destroy_all_agent_secrets()

    # Clear any leftover in-memory state from previous tests
    _used_nonces.clear()
    _agent_hmac_secrets.clear()
    _pending_permissions.clear()

    # Create a session so get_any_session_key() returns our key
    session_token = create_session(key)

    yield db_path, key, session_token

    # Teardown: destroy sessions and agent secrets
    destroy_all_sessions()
    destroy_all_agent_secrets()


@pytest.fixture()
def vault_with_item(unlocked_vault):
    """Adds a test vault item and returns everything needed for tunnel tests."""
    db_path, key, session_token = unlocked_vault

    # Encrypt the test secret value and store it
    encrypted_payload = encrypt(TEST_SECRET_VALUE.encode("utf-8"), key)
    payload_json = json.dumps(encrypted_payload)

    with get_connection(db_path, key) as conn:
        item_id = insert_vault_item(conn, "api_key", TEST_LABEL, payload_json)

    yield db_path, key, session_token, item_id


@pytest.fixture()
def registered_agent(vault_with_item):
    """Registers an agent with permission to access the test vault item.

    Creates the capability card directly in the database — exactly what
    the REST /register endpoint does.
    """
    db_path, key, session_token, item_id = vault_with_item

    # Generate the single Vault API Key: "vzk_" + 64 hex characters (256-bit entropy)
    import secrets
    vault_api_key = "vzk_" + secrets.token_hex(32)
    hashed_key = hashlib.sha256(vault_api_key.encode("utf-8")).hexdigest()

    # Derive the HMAC secret server-side from vault_api_key
    from backend.api.routes.agent import _derive_hmac_secret
    from backend.core.crypto import zero_memory
    hmac_secret = _derive_hmac_secret(vault_api_key)
    hmac_secret_hex = hmac_secret.hex()
    zero_memory(hmac_secret)

    # Permissions: JSON array of allowed labels
    permissions_json = json.dumps([TEST_LABEL])
    valid_until = int(time.time()) + 3600  # 1 hour from now

    with get_connection(db_path, key) as conn:
        insert_capability_card(
            conn,
            agent_id="tunnel-test-agent",
            permissions=permissions_json,
            valid_until=valid_until,
            card_id=hashed_key,
        )

    yield {
        "db_path": db_path,
        "key": key,
        "session_token": session_token,
        "item_id": item_id,
        "card_id": vault_api_key,  # The tests expect "card_id" to be the token they send in handshake/signing
        "hmac_secret_hex": hmac_secret_hex,
        "valid_until": valid_until,
    }


@pytest_asyncio.fixture()
async def tunnel_server(registered_agent):
    """Starts the WebSocket tunnel server on a random available port.

    Uses port 0 to let the OS assign an available port, avoiding conflicts
    with any running production instance on port 47291.
    """
    # Start on port 0 → OS assigns a free port
    server = await start_tunnel_server(host="127.0.0.1", port=0)

    # Extract the actual port assigned by the OS
    sockets = server.sockets
    actual_port = sockets[0].getsockname()[1]

    yield actual_port, registered_agent

    # Teardown: stop the tunnel server
    server.close()
    await server.wait_closed()


# ---------------------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tunnel_handshake(tunnel_server):
    """Test 1: Connect and complete handshake → receive encrypted 'connected' confirmation.

    The handshake is the ONLY unencrypted message in the tunnel protocol.
    The agent sends {agent_token: card_id, nonce: uuid} as MsgPack binary.
    The server validates the card and responds with an encrypted confirmation.
    """
    port, agent_info = tunnel_server
    card_id = agent_info["card_id"]
    key = agent_info["key"]

    uri = f"ws://127.0.0.1:{port}/agent"

    async with websockets.connect(uri) as ws:
        # Send unencrypted handshake (MsgPack binary)
        handshake = msgpack.packb(
            {"agent_token": card_id, "nonce": str(uuid.uuid4())},
            use_bin_type=True,
        )
        await ws.send(handshake)

        # Receive the encrypted confirmation
        response_frame = await asyncio.wait_for(ws.recv(), timeout=5.0)

        # Decrypt it — must be a valid encrypted MsgPack message
        response = _decrypt_inbound(response_frame, key)

        assert response["type"] == "connected", (
            f"Expected 'connected', got '{response.get('type')}'"
        )
        assert response["agent_id"] == "tunnel-test-agent", (
            f"Expected agent_id 'tunnel-test-agent', got '{response.get('agent_id')}'"
        )


@pytest.mark.asyncio
async def test_tunnel_key_request_valid(tunnel_server):
    """Test 2: Send key_request for a permitted label → receive decrypted value.

    Full security chain is exercised:
      - Timestamp freshness (±5 minutes)
      - Nonce uniqueness (Layer 1)
      - HMAC signature verification (Layer 2)
      - Permission check (label in card's allowed list)
      - Decryption of vault item → plaintext returned
    """
    port, agent_info = tunnel_server
    card_id = agent_info["card_id"]
    key = agent_info["key"]
    hmac_secret_hex = agent_info["hmac_secret_hex"]

    uri = f"ws://127.0.0.1:{port}/agent"

    async with websockets.connect(uri) as ws:
        # --- Handshake ---
        handshake = msgpack.packb(
            {"agent_token": card_id, "nonce": str(uuid.uuid4())},
            use_bin_type=True,
        )
        await ws.send(handshake)
        confirmation = await asyncio.wait_for(ws.recv(), timeout=5.0)
        confirm_msg = _decrypt_inbound(confirmation, key)
        assert confirm_msg["type"] == "connected"

        # --- key_request ---
        nonce = str(uuid.uuid4())
        timestamp = int(time.time())
        signature = _sign_request(
            hmac_secret_hex, card_id, "request_key", TEST_LABEL, timestamp, nonce,
        )

        request_msg = {
            "type": "key_request",
            "msg_id": str(uuid.uuid4()),
            "payload": {
                "label": TEST_LABEL,
                "nonce": nonce,
                "timestamp": timestamp,
                "signature": signature,
            },
        }

        # Encrypt and send the request
        encrypted_request = _encrypt_outbound(request_msg, key)
        await ws.send(encrypted_request)

        # Receive and decrypt the response
        response_frame = await asyncio.wait_for(ws.recv(), timeout=5.0)
        response = _decrypt_inbound(response_frame, key)

        assert response["type"] == "key_response", (
            f"Expected 'key_response', got '{response.get('type')}': {response}"
        )
        assert response["label"] == TEST_LABEL
        assert response["value"] == TEST_SECRET_VALUE, (
            f"Expected decrypted value '{TEST_SECRET_VALUE}', got '{response.get('value')}'"
        )
        assert response["msg_id"] == request_msg["msg_id"], (
            "msg_id must be echoed back so the agent can match responses to requests"
        )


@pytest.mark.asyncio
async def test_tunnel_key_request_invalid_label(tunnel_server):
    """Test 3: Send key_request for a label NOT in the card's permissions → 'access denied'.

    The agent has permission for TEST_LABEL only.
    Requesting a different label must be rejected with no information leak.
    """
    port, agent_info = tunnel_server
    card_id = agent_info["card_id"]
    key = agent_info["key"]
    hmac_secret_hex = agent_info["hmac_secret_hex"]

    uri = f"ws://127.0.0.1:{port}/agent"

    async with websockets.connect(uri) as ws:
        # --- Handshake ---
        handshake = msgpack.packb(
            {"agent_token": card_id, "nonce": str(uuid.uuid4())},
            use_bin_type=True,
        )
        await ws.send(handshake)
        confirmation = await asyncio.wait_for(ws.recv(), timeout=5.0)
        confirm_msg = _decrypt_inbound(confirmation, key)
        assert confirm_msg["type"] == "connected"

        # --- key_request for a label the agent does NOT have permission for ---
        wrong_label = "Non-Existent Key"
        nonce = str(uuid.uuid4())
        timestamp = int(time.time())
        signature = _sign_request(
            hmac_secret_hex, card_id, "request_key", wrong_label, timestamp, nonce,
        )

        request_msg = {
            "type": "key_request",
            "msg_id": str(uuid.uuid4()),
            "payload": {
                "label": wrong_label,
                "nonce": nonce,
                "timestamp": timestamp,
                "signature": signature,
            },
        }

        encrypted_request = _encrypt_outbound(request_msg, key)
        await ws.send(encrypted_request)

        response_frame = await asyncio.wait_for(ws.recv(), timeout=5.0)
        response = _decrypt_inbound(response_frame, key)

        assert response["type"] == "error", (
            f"Expected 'error', got '{response.get('type')}'"
        )
        assert response["reason"] == "access denied", (
            f"Expected 'access denied', got '{response.get('reason')}'"
        )
        assert response["msg_id"] == request_msg["msg_id"]


@pytest.mark.asyncio
async def test_tunnel_corrupted_encryption(tunnel_server):
    """Test 4: Send a frame with corrupted ciphertext → connection closes with code 4002.

    AES-256-GCM detects any tampering via its authentication tag.
    Corrupted data must cause the server to close the connection with
    CLOSE_CRYPTO_ERROR (4002), not return an error message.
    """
    port, agent_info = tunnel_server
    card_id = agent_info["card_id"]
    key = agent_info["key"]

    uri = f"ws://127.0.0.1:{port}/agent"

    async with websockets.connect(uri) as ws:
        # --- Handshake (must succeed first) ---
        handshake = msgpack.packb(
            {"agent_token": card_id, "nonce": str(uuid.uuid4())},
            use_bin_type=True,
        )
        await ws.send(handshake)
        confirmation = await asyncio.wait_for(ws.recv(), timeout=5.0)
        confirm_msg = _decrypt_inbound(confirmation, key)
        assert confirm_msg["type"] == "connected"

        # --- Send corrupted encrypted data ---
        # Create a valid-looking MsgPack bundle with garbage ciphertext.
        # The nonce is real but the ciphertext is corrupted → GCM tag check fails.
        corrupted_bundle = {
            "nonce": "AAAAAAAAAAAAAAAA",     # 12 bytes in base64
            "ciphertext": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        }
        corrupted_frame = msgpack.packb(corrupted_bundle, use_bin_type=True)
        await ws.send(corrupted_frame)

        # The server should close the connection with code 4002
        try:
            # Try to receive — the server should have closed the connection
            await asyncio.wait_for(ws.recv(), timeout=5.0)
            # If we got a message instead of a close, that's a failure
            pytest.fail("Expected connection close (4002), but received a message")
        except websockets.ConnectionClosedError as e:
            assert e.rcvd.code == 4002, (
                f"Expected close code 4002, got {e.rcvd.code}"
            )
        except websockets.ConnectionClosed as e:
            assert e.rcvd.code == 4002, (
                f"Expected close code 4002, got {e.rcvd.code}"
            )


@pytest.mark.asyncio
async def test_tunnel_ping_pong(tunnel_server):
    """Test 5: Send encrypted ping → receive encrypted pong with matching msg_id.

    Ping/pong is the simplest message type — used by agents to check if the
    tunnel is alive. The msg_id must be echoed back so the agent can match
    the response to its request.
    """
    port, agent_info = tunnel_server
    card_id = agent_info["card_id"]
    key = agent_info["key"]

    uri = f"ws://127.0.0.1:{port}/agent"

    async with websockets.connect(uri) as ws:
        # --- Handshake ---
        handshake = msgpack.packb(
            {"agent_token": card_id, "nonce": str(uuid.uuid4())},
            use_bin_type=True,
        )
        await ws.send(handshake)
        confirmation = await asyncio.wait_for(ws.recv(), timeout=5.0)
        confirm_msg = _decrypt_inbound(confirmation, key)
        assert confirm_msg["type"] == "connected"

        # --- Ping ---
        ping_msg_id = str(uuid.uuid4())
        ping_msg = {
            "type": "ping",
            "msg_id": ping_msg_id,
            "payload": {},
        }

        encrypted_ping = _encrypt_outbound(ping_msg, key)
        await ws.send(encrypted_ping)

        # --- Pong ---
        response_frame = await asyncio.wait_for(ws.recv(), timeout=5.0)
        response = _decrypt_inbound(response_frame, key)

        assert response["type"] == "pong", (
            f"Expected 'pong', got '{response.get('type')}'"
        )
        assert response["msg_id"] == ping_msg_id, (
            f"Expected msg_id '{ping_msg_id}', got '{response.get('msg_id')}'"
        )
