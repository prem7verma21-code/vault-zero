"""
Binary WebSocket tunnel for Vault-Zero — Step 1.7.

Replaces readable HTTP/JSON agent communication with encrypted binary MsgPack
frames. All agent-vault traffic through this tunnel is:

  1. Binary (MsgPack) — not human-readable in browser DevTools
  2. Encrypted (AES-256-GCM) — not decryptable without the session key
  3. Persistent (single WebSocket connection) — no HTTP request/response pattern

Why this matters:
  In Phase 3, this architecture moves to the cloud. The patterns built here must
  be secure enough for the cloud. Building security in later is much harder than
  building it correctly from the start. Even locally, other apps on the same
  machine can potentially inspect HTTP traffic on localhost — the tunnel prevents
  that by encrypting everything.

Protocol overview:
  1. Agent connects to ws://127.0.0.1:47291/agent
  2. Agent sends an unencrypted handshake: {agent_token, nonce} packed with MsgPack
  3. Server validates the capability card and sends a plain MsgPack confirmation
  4. All subsequent messages (after handshake) are MsgPack-serialized, then AES-256-GCM encrypted
  5. Each message has a type field that determines how it is processed

Message types:
  "key_request"         — agent requests a decrypted vault item (full security check)
  "permission_request"  — agent asks user for approval before a sensitive action
  "context_request"     — agent requests labels of "memory" category items
  "ping"                — keepalive, returns "pong" with same msg_id

Security layers enforced (same as REST API):
  Layer 1 — Nonce binding:   every request has a unique nonce; replays are rejected
  Layer 2 — Timestamp window: requests outside ±5 minutes are rejected
  Layer 3 — Localhost:       server binds to 127.0.0.1 only (enforced here and in run_server.py)
  Process pinning:           background task monitors parent (Electron) process health

Encryption protocol (after handshake):
  Outbound (server → agent):
    1. message_dict → msgpack.packb → raw_bytes
    2. raw_bytes → AES-256-GCM encrypt → {nonce, ciphertext} dict
    3. bundle_dict → msgpack.packb → encrypted_frame
    4. encrypted_frame → ws.send (binary WebSocket frame)

  Inbound (agent → server):
    1. ws.recv → encrypted_frame (binary)
    2. encrypted_frame → msgpack.unpackb → {nonce, ciphertext} dict
    3. bundle_dict → AES-256-GCM decrypt → raw_bytes
    4. raw_bytes → msgpack.unpackb → message_dict
"""

import asyncio
import json
import logging
import os
import time
import uuid as uuid_mod

import msgpack
import websockets

from backend.core.crypto import encrypt, decrypt, zero_memory
from backend.core.security import get_any_session_key
from backend.database.models import (
    get_db_path,
    get_connection,
    get_vault_item,
    list_vault_items,
    append_audit_log,
)

# Import agent.py's security infrastructure — same layers used by the REST API.
# Because both servers run in the same Python process, they share the same
# module-level state (nonce store, pending permissions).
from backend.api.routes.agent import (
    _check_and_record_nonce,
    _validate_agent_card,
    _append_audit_safe,
    _pending_permissions,
    _PERMISSION_TIMEOUT_SECONDS,
    _MAX_PENDING_PERMISSIONS,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

# The tunnel runs on a separate port from the REST API (8765).
# This is intentional — each server has a single responsibility.
TUNNEL_HOST = "127.0.0.1"  # Localhost only — Layer 3 from GEMINI.md
TUNNEL_PORT = 47291

# Custom WebSocket close codes (4000-4999 range is reserved for applications)
CLOSE_INVALID_PATH = 4000     # Client connected to wrong path
CLOSE_AUTH_FAILED = 4001      # Handshake authentication failed
CLOSE_CRYPTO_ERROR = 4002     # Decryption of a message failed
CLOSE_SESSION_EXPIRED = 4003  # Vault was locked or card expired mid-session

# Maximum time to wait for the handshake message before giving up
_HANDSHAKE_TIMEOUT_SECONDS = 10.0


# ---------------------------------------------------------------------------
# ENCRYPTION HELPERS
# ---------------------------------------------------------------------------
# These two functions implement the tunnel's own encryption layer.
# This is SEPARATE from the vault item encryption — these protect the
# WebSocket frames in transit, while vault item encryption protects the
# stored secrets at rest.

def _encrypt_outbound(message: dict, session_key: bytearray) -> bytes:
    """Encrypts a message dict for sending over the WebSocket tunnel.

    Steps:
      1. Serialize the message dict to MsgPack binary format
      2. Encrypt the binary data with AES-256-GCM using the session key
      3. Serialize the encryption bundle {nonce, ciphertext} to MsgPack
      4. Return the final bytes ready to send as a binary WebSocket frame

    The result looks like random noise to anyone without the session key.
    """
    # Step 1: message dict → binary bytes
    raw = msgpack.packb(message, use_bin_type=True)

    # Step 2: encrypt the raw bytes (returns {nonce: b64, ciphertext: b64})
    bundle = encrypt(raw, session_key)

    # Step 3: pack the bundle dict into MsgPack for transmission
    return msgpack.packb(bundle, use_bin_type=True)


def _decrypt_inbound(frame: bytes, session_key: bytearray) -> dict:
    """Decrypts a binary WebSocket frame received from an agent.

    Steps:
      1. Unpack the outer MsgPack layer → {nonce, ciphertext} dict
      2. Decrypt the AES-256-GCM bundle → raw MsgPack bytes
      3. Unpack the inner MsgPack layer → original message dict

    Raises an exception if decryption fails (wrong key, tampered data, etc.).
    The caller should catch this and close the connection with CLOSE_CRYPTO_ERROR.
    """
    # Step 1: unpack outer layer to get the encryption bundle
    bundle = msgpack.unpackb(frame, raw=False)

    # Step 2: decrypt — raises InvalidTag if tampered or wrong key
    raw = decrypt(bundle, session_key)

    # Step 3: unpack inner layer to get the original message
    message = msgpack.unpackb(bytes(raw), raw=False)

    return message


async def _safe_close(ws, code: int, reason: str = "") -> None:
    """Closes a WebSocket connection, silently ignoring errors if already closed.

    Network connections can fail at any time. If the connection is already
    gone when we try to close it, we don't want that error to mask the
    actual problem we're handling.
    """
    try:
        await ws.close(code, reason)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# HANDSHAKE — the first message exchange that authenticates the agent
# ---------------------------------------------------------------------------

async def _handle_handshake(ws) -> tuple[str | None, dict | None]:
    """Processes the initial handshake from the agent.

    The handshake is the ONLY unencrypted message in the entire tunnel session.
    It must be unencrypted because the agent needs to present its credential
    (capability card ID) before the server knows which agent it is.

    Expected handshake message (MsgPack-packed):
      {"agent_token": "<card_id>", "nonce": "<uuid4>"}

    Returns:
      (card_id, card_dict) on success
      (None, None) on failure (connection is closed before returning)
    """
    # Wait for the handshake message with a timeout.
    # If the agent doesn't send anything within 10 seconds, it's not a real agent.
    try:
        raw = await asyncio.wait_for(ws.recv(), timeout=_HANDSHAKE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning("Tunnel handshake timed out")
        await _safe_close(ws, CLOSE_AUTH_FAILED, "handshake timeout")
        return None, None
    except Exception:
        return None, None

    # The handshake must be binary (MsgPack), not text
    if isinstance(raw, str):
        await _safe_close(ws, CLOSE_AUTH_FAILED, "binary frames only")
        return None, None

    # Unpack the MsgPack handshake
    try:
        handshake = msgpack.unpackb(raw, raw=False)
    except Exception:
        logger.warning("Tunnel handshake: invalid MsgPack")
        await _safe_close(ws, CLOSE_AUTH_FAILED, "invalid handshake format")
        return None, None

    # Extract required fields
    agent_token = handshake.get("agent_token")
    nonce = handshake.get("nonce")

    if not agent_token or not nonce:
        await _safe_close(ws, CLOSE_AUTH_FAILED, "missing handshake fields")
        return None, None

    # The vault must be unlocked for any agent communication.
    # If it's locked, there's no session key to decrypt vault items with.
    session_key = get_any_session_key()
    if session_key is None:
        await _safe_close(ws, CLOSE_AUTH_FAILED, "vault locked")
        return None, None

    # Validate the capability card — this checks:
    #   - Card exists in the database
    #   - Card is not expired (valid_until > now)
    # On failure, _validate_agent_card raises HTTPException.
    db_path = get_db_path()
    try:
        card = _validate_agent_card(agent_token, db_path, session_key)
    except Exception:
        # Don't reveal which check failed — same as REST API
        logger.info("Tunnel handshake: card validation failed for token")
        await _safe_close(ws, CLOSE_AUTH_FAILED, "auth failed")
        return None, None

    # Log the successful tunnel connection
    _append_audit_safe(
        db_path, session_key,
        action="tunnel_connect",
        result="success",
        agent_id=card["agent_id"],
    )

    return agent_token, card


# ---------------------------------------------------------------------------
# MESSAGE HANDLERS — one function per message type
# ---------------------------------------------------------------------------

async def _handle_ping(msg_id: str) -> dict:
    """Handles a ping message — just echoes back with "pong".

    Used by agents to check if the tunnel is alive. The msg_id is echoed
    back so the agent can match the response to its request.
    """
    return {"type": "pong", "msg_id": msg_id}


async def _handle_key_request(
    card_id: str,
    card: dict,
    agent_id: str,
    msg_id: str,
    payload: dict,
    session_key: bytearray,
) -> dict:
    """Handles a key_request — decrypts and returns a vault item's value.

    This is the most security-critical message type. Every security layer
    is checked in order, exactly matching the REST API's /request_key:

      Step 1: Timestamp freshness (±5 minutes)
      Step 2: Nonce uniqueness (replay protection — Layer 1)
      Step 3: Permission check (label must be in card's allowed list)
      Step 4: Decrypt vault item → return value → zero memory

    Auth model: bearer token only (same as the REST API). No HMAC.

    On ANY failure: returns {"type": "error", "reason": "access denied"}.
    Never reveals which specific check failed.
    """
    label = payload.get("label", "")
    nonce = payload.get("nonce", "")
    timestamp = payload.get("timestamp", 0)
    db_path = get_db_path()

    # --- Step 1: Timestamp freshness ---
    # Reject requests older than 5 minutes to prevent stockpiling signed requests
    now = int(time.time())
    if abs(now - timestamp) > 300:
        _append_audit_safe(
            db_path, session_key, "tunnel_request_key",
            "denied_stale_timestamp", agent_id, label,
        )
        return {"type": "error", "msg_id": msg_id, "reason": "access denied"}

    # --- Step 2: Nonce check (Layer 1 — replay protection) ---
    try:
        await _check_and_record_nonce(nonce)
    except Exception:
        return {"type": "error", "msg_id": msg_id, "reason": "access denied"}

    # --- Step 3: Permission check ---
    try:
        allowed_labels: list[str] = json.loads(card["permissions"])
    except (json.JSONDecodeError, KeyError):
        allowed_labels = []

    if label not in allowed_labels:
        _append_audit_safe(
            db_path, session_key, "tunnel_request_key",
            "denied_not_permitted", agent_id, label,
        )
        return {"type": "error", "msg_id": msg_id, "reason": "access denied"}

    # --- Step 5: Decrypt the vault item and return the value ---
    decrypted: bytearray | None = None
    try:
        with get_connection(db_path, session_key) as conn:
            # Find the vault item by label
            all_items = list_vault_items(conn)
            item_meta = next((i for i in all_items if i["label"] == label), None)

            if item_meta is None:
                # Label was in permissions but was deleted from vault since card was created
                return {"type": "error", "msg_id": msg_id, "reason": "access denied"}

            # Fetch the encrypted payload and update last_accessed timestamp
            item = get_vault_item(conn, item_meta["id"])
            if item is None:
                return {"type": "error", "msg_id": msg_id, "reason": "access denied"}

            # Decrypt the stored secret — returns a mutable bytearray
            payload_dict = json.loads(item["encrypted_payload"])
            decrypted = decrypt(payload_dict, session_key)

            # Decode to string for the response. The immutable str copy cannot be
            # zeroed — this is a known Python limitation documented in agent.py.
            plaintext_value = decrypted.decode("utf-8")

            # Audit log — label only, NEVER the value (Rule 6 from GEMINI.md)
            append_audit_log(
                conn,
                action="tunnel_request_key",
                result="approved",
                agent_id=agent_id,
                label_accessed=label,
            )

        return {
            "type": "key_response",
            "msg_id": msg_id,
            "label": label,
            "value": plaintext_value,
        }

    except Exception as exc:
        logger.error("Tunnel key_request error: %s", type(exc).__name__)
        return {"type": "error", "msg_id": msg_id, "reason": "access denied"}
    finally:
        # Zero the decrypted bytearray immediately — Rule 4 from GEMINI.md
        if decrypted is not None:
            zero_memory(decrypted)


async def _handle_permission_request(
    card_id: str,
    card: dict,
    agent_id: str,
    msg_id: str,
    payload: dict,
    session_key: bytearray,
) -> dict:
    """Handles a permission_request — asks the user to approve or deny an action.

    How it works:
      1. Agent sends a description of what it wants to do
      2. Replay protections verified (timestamp ±5 min + fresh nonce)
      3. A pending entry is created with an asyncio.Event
      4. This handler WAITS (up to 60 seconds) for the user to respond
      5. The Electron UI polls GET /pending_permissions (REST) and shows a popup
      6. User clicks Approve or Deny → POST /respond_permission (REST)
      7. That REST endpoint sets the event → this handler wakes up
      8. Decision is returned to the agent through the encrypted tunnel

    NOTE: Permission requests from the tunnel share the same _pending_permissions
    dict as the REST API. The UI always uses REST to approve/deny, regardless
    of whether the original request came via REST or WebSocket.
    """
    action = payload.get("action", "")
    nonce = payload.get("nonce", "")
    timestamp = payload.get("timestamp", 0)
    request_id = payload.get("request_id", str(uuid_mod.uuid4()))
    db_path = get_db_path()

    # --- Timestamp freshness ---
    now = int(time.time())
    if abs(now - timestamp) > 300:
        return {"type": "error", "msg_id": msg_id, "reason": "access denied"}

    # --- Layer 1: Nonce check ---
    try:
        await _check_and_record_nonce(nonce)
    except Exception:
        return {"type": "error", "msg_id": msg_id, "reason": "access denied"}

    # --- Prevent flooding ---
    if len(_pending_permissions) >= _MAX_PENDING_PERMISSIONS:
        return {"type": "error", "msg_id": msg_id, "reason": "too_many_pending"}

    # --- Create pending entry and wait for user decision ---
    event = asyncio.Event()
    _pending_permissions[request_id] = {
        "event": event,
        "approved": None,
        "action": action,
        "agent_id": agent_id,
        "created_at": int(time.time()),
    }

    try:
        # Block up to 60 seconds for the user to respond
        try:
            await asyncio.wait_for(
                event.wait(),
                timeout=float(_PERMISSION_TIMEOUT_SECONDS),
            )
        except asyncio.TimeoutError:
            pass  # Fall through — None is treated as denied (fail-safe)

        decision = _pending_permissions.get(request_id, {})
        approved: bool = decision.get("approved") or False  # None → False = auto-deny

    finally:
        # Always clean up, even on error or timeout
        _pending_permissions.pop(request_id, None)

    result_str = "approved" if approved else "denied"
    _append_audit_safe(
        db_path, session_key, "tunnel_request_permission",
        result_str, agent_id, action[:200],
    )

    return {
        "type": "permission_response",
        "msg_id": msg_id,
        "request_id": request_id,
        "approved": approved,
    }


async def _handle_context_request(
    card_id: str,
    card: dict,
    agent_id: str,
    msg_id: str,
    payload: dict,
    session_key: bytearray,
) -> dict:
    """Handles a context_request — returns labels of "memory" category vault items.

    This allows agents to discover what user preferences or context items exist
    without decrypting them. If the agent needs the actual value, it must use
    key_request with proper permissions.

    Returns: list of {label, created_at} for items with category = "memory".
    """
    db_path = get_db_path()

    try:
        with get_connection(db_path, session_key) as conn:
            all_items = list_vault_items(conn)
            memory_items = [
                {"label": item["label"], "created_at": item["created_at"]}
                for item in all_items
                if item["category"] == "memory"
            ]

            append_audit_log(
                conn,
                action="tunnel_context_request",
                result="success",
                agent_id=agent_id,
            )

        return {
            "type": "context_response",
            "msg_id": msg_id,
            "items": memory_items,
        }

    except Exception as exc:
        logger.error("Tunnel context_request error: %s", type(exc).__name__)
        return {"type": "error", "msg_id": msg_id, "reason": "internal_error"}


# ---------------------------------------------------------------------------
# MESSAGE ROUTER — dispatches to the correct handler based on message type
# ---------------------------------------------------------------------------

async def _route_message(
    card_id: str,
    card: dict,
    agent_id: str,
    message: dict,
    session_key: bytearray,
) -> dict:
    """Routes an incoming tunnel message to the correct handler.

    Every message must have a "type" field. Unknown types get an error response.
    The msg_id is always echoed back so the agent can match responses to requests.
    """
    msg_type = message.get("type", "")
    msg_id = message.get("msg_id", "")
    payload = message.get("payload", {})

    if msg_type == "ping":
        return await _handle_ping(msg_id)

    elif msg_type == "key_request":
        return await _handle_key_request(
            card_id, card, agent_id, msg_id, payload, session_key,
        )

    elif msg_type == "permission_request":
        return await _handle_permission_request(
            card_id, card, agent_id, msg_id, payload, session_key,
        )

    elif msg_type == "context_request":
        return await _handle_context_request(
            card_id, card, agent_id, msg_id, payload, session_key,
        )

    else:
        return {
            "type": "error",
            "msg_id": msg_id,
            "reason": "unknown_type",
        }


# ---------------------------------------------------------------------------
# MAIN CONNECTION HANDLER — manages one WebSocket connection end-to-end
# ---------------------------------------------------------------------------

async def _handle_connection(ws) -> None:
    """Manages a single agent's WebSocket tunnel connection from start to finish.

    Lifecycle:
      1. Validate the connection path (must be /agent)
      2. Run the handshake (authenticate the agent's capability card)
      3. Send plain MsgPack confirmation (not encrypted — client has no session_key)
      4. Enter message loop: receive → decrypt → route → encrypt → send
      5. On any fatal error or disconnect: clean up and return

    The connection stays open until:
      - The agent disconnects
      - The vault is locked (session key becomes None)
      - The agent's capability card expires
      - A crypto error occurs (tampered data)
      - The server shuts down
    """
    # --- Validate connection path ---
    # Only /agent is accepted. The path check is best-effort across
    # different websockets library versions.
    try:
        if hasattr(ws, "request") and hasattr(ws.request, "path"):
            path = ws.request.path
        elif hasattr(ws, "path"):
            path = ws.path
        else:
            path = "/agent"  # Can't determine — allow
    except Exception:
        path = "/agent"

    if path != "/agent":
        await _safe_close(ws, CLOSE_INVALID_PATH, "invalid path")
        return

    # --- Handshake phase ---
    card_id, card = await _handle_handshake(ws)
    if card_id is None:
        return

    agent_id = card["agent_id"]
    valid_until = card.get("valid_until")

    # Get the session key — needed for decrypting vault items in subsequent messages.
    # We check here (not later) so we fail fast if the vault was locked between
    # handshake and first message.
    session_key = get_any_session_key()
    if session_key is None:
        await _safe_close(ws, CLOSE_SESSION_EXPIRED, "vault locked")
        return

    # Send AES-256-GCM encrypted MsgPack confirmation.
    # The session_key was retrieved immediately above, so encryption is possible.
    # Encrypting the confirmation is consistent with all subsequent messages and
    # matches the test protocol (tests call _decrypt_inbound on this frame).
    confirmation = {"type": "connected", "agent_id": agent_id}
    try:
        await ws.send(_encrypt_outbound(confirmation, session_key))
    except Exception:
        return

    logger.info("Tunnel: agent '%s' connected (card %s)", agent_id, card_id[:8])

    # --- Message loop ---
    try:
        async for frame in ws:
            # Check that the frame is binary (MsgPack), not text
            if isinstance(frame, str):
                await _safe_close(ws, CLOSE_CRYPTO_ERROR, "binary frames only")
                return

            # Check that the vault is still unlocked
            session_key = get_any_session_key()
            if session_key is None:
                logger.info("Tunnel: vault locked during session for agent '%s'", agent_id)
                # Cannot encrypt without a key — send plain MsgPack error as last resort
                try:
                    error_msg = msgpack.packb(
                        {"type": "error", "reason": "session_expired"},
                        use_bin_type=True,
                    )
                    await ws.send(error_msg)
                except Exception:
                    pass
                await _safe_close(ws, CLOSE_SESSION_EXPIRED, "session expired")
                return

            # Check that the card hasn't expired since the handshake
            if valid_until is not None and int(time.time()) > valid_until:
                logger.info("Tunnel: card expired for agent '%s'", agent_id)
                try:
                    error_response = {"type": "error", "reason": "session_expired"}
                    await ws.send(_encrypt_outbound(error_response, session_key))
                except Exception:
                    pass
                await _safe_close(ws, CLOSE_SESSION_EXPIRED, "card expired")
                return

            # Decrypt the incoming message
            try:
                message = _decrypt_inbound(frame, session_key)
            except Exception:
                logger.warning(
                    "Tunnel: crypto error from agent '%s' — closing connection",
                    agent_id,
                )
                await _safe_close(ws, CLOSE_CRYPTO_ERROR, "crypto_error")
                return

            # Route to the correct handler and get the response
            response = await _route_message(
                card_id, card, agent_id, message, session_key,
            )

            # Encrypt and send the response
            try:
                await ws.send(_encrypt_outbound(response, session_key))
            except Exception:
                return

    except websockets.ConnectionClosed:
        # Normal disconnection — agent closed the connection
        pass
    except Exception as exc:
        logger.error(
            "Tunnel: unexpected error for agent '%s': %s",
            agent_id, type(exc).__name__,
        )
    finally:
        logger.info("Tunnel: agent '%s' disconnected", agent_id)


# ---------------------------------------------------------------------------
# SERVER LIFECYCLE — start and stop the tunnel server
# ---------------------------------------------------------------------------

# Module-level reference to the running server, used by stop_tunnel_server()
_tunnel_server = None


async def start_tunnel_server(
    host: str = TUNNEL_HOST,
    port: int = TUNNEL_PORT,
):
    """Starts the WebSocket tunnel server.

    Called by run_server.py at startup, alongside the REST API server.
    Both servers run in the same Python process and share the same
    module-level state (sessions, nonces, pending permissions).

    Args:
        host: IP address to bind to. Always 127.0.0.1 — never 0.0.0.0.
        port: Port number. Default 47291 (separate from REST API on 8765).

    Returns:
        The websockets server object (for lifecycle management).
    """
    global _tunnel_server

    _tunnel_server = await websockets.serve(
        _handle_connection,
        host,
        port,
    )

    logger.info(
        "Binary WebSocket tunnel running on ws://%s:%d/agent",
        host, port,
    )
    return _tunnel_server


async def stop_tunnel_server() -> None:
    """Stops the WebSocket tunnel server gracefully.

    Closes all active connections and releases the port.
    Called during server shutdown alongside REST API shutdown.
    """
    global _tunnel_server

    if _tunnel_server is not None:
        _tunnel_server.close()
        await _tunnel_server.wait_closed()
        _tunnel_server = None
        logger.info("Binary WebSocket tunnel stopped")


# ---------------------------------------------------------------------------
# PROCESS PINNING — monitors the parent (Electron) process
# ---------------------------------------------------------------------------

async def start_parent_monitor(parent_pid: int) -> None:
    """Background task that checks every 10 seconds if the parent process is alive.

    When Vault-Zero runs as a desktop app, Electron (main.js) spawns the Python
    backend as a child process and passes its own PID via the PARENT_PID env var.

    This task verifies the parent is still running. If it dies (user closes the app,
    crash, kill), we immediately:
      1. Zero all derived keys from memory
      2. Clear nonce store and pending permissions
      3. Force-exit the process (os._exit)

    This prevents an orphaned vault process from running with live keys in RAM
    after the desktop app is closed. Without this, closing the Electron window
    would leave the Python backend running silently with decrypted keys available.

    Only active when PARENT_PID is set — not during development/testing.
    """
    try:
        import psutil
    except ImportError:
        logger.warning(
            "psutil not installed — parent process monitoring disabled. "
            "Install with: pip install psutil"
        )
        return

    logger.info("Parent process monitor started (PID %d)", parent_pid)

    while True:
        await asyncio.sleep(10)
        try:
            proc = psutil.Process(parent_pid)
            if proc.status() == psutil.STATUS_ZOMBIE:
                raise psutil.NoSuchProcess(parent_pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
            logger.critical(
                "Parent process %d no longer alive — "
                "zeroing all keys and force-exiting",
                parent_pid,
            )
            # Import here to avoid circular imports at module load time
            from backend.core.security import destroy_all_sessions
            from backend.api.routes.agent import destroy_all_agent_secrets

            destroy_all_sessions()
            destroy_all_agent_secrets()

            # os._exit bypasses Python cleanup — no finally blocks, no atexit.
            # This is intentional: we want to exit as fast as possible once
            # we detect the parent is gone, minimizing the window where keys
            # sit in RAM without a controlling process.
            os._exit(1)
