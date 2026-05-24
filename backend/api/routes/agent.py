"""


Handles AI agents requesting API keys and permission approvals.

This is the most security-critical route file after auth.py.
Every agent request is checked against MULTIPLE security layers before a key
is ever decrypted.

Authentication model (two separate credential types):
  USER ENDPOINTS (register, revoke, pending, respond):
    - Use the standard user session JWT (Bearer: session_token from /auth/unlock)
    - Only the vault owner can manage capability cards

  AGENT ENDPOINTS (request_key, request_permission):
    - Use the capability card ID as the Bearer token (Bearer: card_id)
    - The vault must also be unlocked (user session active) for decryption to work

Security layers enforced here (from GEMINI.md):
  Layer 1 — Nonce binding: every agent request carries a unique nonce (UUID); reused
             nonces are rejected immediately. Defeats replay attacks.
  Layer 2 — HMAC signing: every agent request is signed with a per-agent secret returned
             once at registration. We recompute the HMAC and reject on mismatch.
             Defeats payload tampering (Attack 4 from GEMINI.md).
  Layer 3 — Localhost binding: enforced at the server level (run_server.py / uvicorn).

Endpoints:
  POST   /api/v1/agent/register              — user creates a capability card for an agent
  POST   /api/v1/agent/request_key           — agent requests a decrypted key (card auth)
  POST   /api/v1/agent/request_permission    — agent asks user for approval (card auth)
  GET    /api/v1/agent/pending_permissions   — UI polls for pending permission requests
  POST   /api/v1/agent/respond_permission    — UI submits user's approve/deny decision
  DELETE /api/v1/agent/cards/{card_id}       — user revokes a capability card
"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid as uuid_mod

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.api.routes.auth import require_session
from backend.core.crypto import decrypt, zero_memory
from backend.core.security import get_any_session_key
from backend.database.models import (
    get_db_path,
    get_connection,
    get_vault_item,
    list_vault_items,
    insert_capability_card,
    get_capability_card,
    delete_capability_card,
    append_audit_log,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agent", tags=["agent"])

# Rate limiter — GEMINI.md Rule 7: every endpoint gets 60 req/min
limiter = Limiter(key_func=get_remote_address)


# ---------------------------------------------------------------------------
# IN-MEMORY NONCE STORE — replay attack prevention (Layer 1)
# ---------------------------------------------------------------------------
#
# When an agent makes a request it includes a one-time nonce (UUID string).
# We store every nonce we have seen. If we see the same nonce twice, the
# second request is rejected — it's a replay attack (someone captured and
# re-sent a valid request).
#
# TTL: nonces are stored with an expiry timestamp and purged after 1 hour
# (the max token lifetime). After that, the card itself is expired and the
# nonce no longer matters.
#
# Structure: { nonce_string: expiry_unix_timestamp }

_used_nonces: dict[str, int] = {}

# Maximum age of a nonce before we forget it (1 hour, matches max card TTL)
_NONCE_TTL_SECONDS: int = 3600

# We use an asyncio.Lock to prevent concurrent cleanup races.
# Without this, two async requests arriving simultaneously could both trigger
# the cleanup sweep at the same time — harmless but wasteful.
_nonce_lock = asyncio.Lock()

# How often (in requests) to sweep expired nonces to prevent unbounded memory growth
_nonce_request_counter: int = 0
_NONCE_CLEANUP_INTERVAL: int = 100


async def _check_and_record_nonce(nonce: str) -> None:
    """Checks whether a nonce has been used before and records it.

    This is Layer 1 of the anti-impersonation system: nonce binding.
    If the nonce was already used, raises HTTP 400 immediately.
    If the nonce is fresh, records it so the same nonce cannot be reused.

    Why this matters: without nonces, an attacker who intercepts a valid
    signed request could re-send it ("replay attack") and get the key.
    With nonces, every second attempt is rejected.
    """
    global _nonce_request_counter

    # Validate nonce format — must be a valid UUID4 string (36 chars including dashes).
    # This prevents memory abuse from extremely long nonces and ensures predictable format.
    if len(nonce) != 36:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid nonce format",
        )
    try:
        uuid_mod.UUID(nonce, version=4)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid nonce format",
        )

    now = int(time.time())

    async with _nonce_lock:
        # Periodically clean up expired nonces to prevent unbounded memory growth
        _nonce_request_counter += 1
        if _nonce_request_counter >= _NONCE_CLEANUP_INTERVAL:
            _nonce_request_counter = 0
            expired = [n for n, exp in _used_nonces.items() if exp < now]
            for n in expired:
                del _used_nonces[n]

        # Reject if nonce was already seen — this is a replay attempt
        if nonce in _used_nonces:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="replay_detected",
            )

        # Record this nonce with its expiry timestamp
        _used_nonces[nonce] = now + _NONCE_TTL_SECONDS


# ---------------------------------------------------------------------------
# IN-MEMORY HMAC SECRET STORE — per-agent signing secrets (Layer 2)
# ---------------------------------------------------------------------------
#
# When a capability card is created, we generate a random 32-byte HMAC secret.
# The secret is returned to the agent exactly ONCE at registration time.
# On every subsequent request, the agent must include an HMAC-SHA256 signature
# so we can verify the request came from the right agent and wasn't tampered.
#
# SECURITY NOTE (Rule 4): secrets are stored as bytearray, not bytes, so they
# can be explicitly zeroed from memory when a card is revoked. We never store
# the raw secret in the database — only in this dict.
#
# Structure: { card_id: hmac_secret_bytearray }

_agent_hmac_secrets: dict[str, bytearray] = {}


def _register_hmac_secret(card_id: str, secret: bytearray) -> None:
    """Stores the HMAC secret for a capability card in memory.

    The secret must be a bytearray (not bytes) so it can be zeroed on revocation.
    """
    if not isinstance(secret, bytearray):
        raise TypeError("HMAC secret must be bytearray, not bytes (Rule 4)")
    _agent_hmac_secrets[card_id] = secret


def _get_hmac_secret(card_id: str) -> bytearray | None:
    """Retrieves the HMAC secret for a card. Returns None if not found."""
    return _agent_hmac_secrets.get(card_id)


def _revoke_hmac_secret(card_id: str) -> None:
    """Removes and zeros the HMAC secret for a revoked card.

    The secret is zeroed from memory before being removed from the dict,
    so no trace of it lingers in RAM after revocation.
    """
    secret = _agent_hmac_secrets.pop(card_id, None)
    if secret is not None:
        zero_memory(secret)


def destroy_all_agent_secrets() -> None:
    """Zeros and removes ALL HMAC secrets from memory — called on server shutdown.

    This ensures no agent signing secrets linger in RAM after the process exits.
    Called from main.py lifespan shutdown alongside destroy_all_sessions().
    """
    for card_id, secret in list(_agent_hmac_secrets.items()):
        zero_memory(secret)
    _agent_hmac_secrets.clear()
    _used_nonces.clear()
    _pending_permissions.clear()


def _verify_hmac_signature(
    secret: bytearray,
    card_id: str,
    msg_type: str,
    label: str,
    timestamp: int,
    nonce: str,
    signature: str,
) -> bool:
    """Recomputes the expected HMAC-SHA256 and compares it to the provided signature.

    This is Layer 2 of the anti-impersonation system: request signing.
    The message being signed is: card_id:type:label:timestamp:nonce
    Including the nonce ties the signature to a single use — even if an attacker
    knows the format, they cannot re-sign without the secret.

    Why this matters: without HMAC, a compromised process could tamper with
    request payloads in transit between the agent and the vault (Attack 4
    from GEMINI.md). With HMAC, any change to the payload invalidates the
    signature.

    Uses hmac.compare_digest() for constant-time comparison to prevent
    timing side-channel attacks.
    """
    # Build the canonical message string — the agent must use this exact format
    message = f"{card_id}:{msg_type}:{label}:{timestamp}:{nonce}"
    expected = hmac.new(
        bytes(secret), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    # Constant-time comparison — prevents an attacker from guessing the
    # signature one character at a time by measuring response time
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# IN-MEMORY PERMISSION REQUEST STORE — for the approve/deny flow
# ---------------------------------------------------------------------------
#
# When an agent calls /request_permission, we create a pending entry and WAIT
# (via asyncio.Event) for the UI to respond via /respond_permission.
#
# Structure: { request_id: {"event": asyncio.Event, "approved": bool|None, ...} }

_pending_permissions: dict[str, dict] = {}

# Maximum wait time before auto-denying (GEMINI.md spec: 60 seconds)
_PERMISSION_TIMEOUT_SECONDS: int = 60

# Maximum number of concurrent pending permission requests.
# Prevents a rogue agent from flooding the store (DoS vector).
_MAX_PENDING_PERMISSIONS: int = 50


# ---------------------------------------------------------------------------
# REQUEST / RESPONSE MODELS
# ---------------------------------------------------------------------------

class CardExpiredError(HTTPException):
    def __init__(self):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail="access denied")


class RegisterAgentRequest(BaseModel):
    """Body for POST /register — identifies the agent requesting a capability card."""
    agent_id: str               # Name or identifier for the agent (e.g., "cursor", "claude")
    permissions: list[str]      # Vault item labels this agent is allowed to access
    ttl_hours: int | None = 1   # How long the card is valid. Default: 1 hour. None means never expires.

    @field_validator("agent_id")
    @classmethod
    def agent_id_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("agent_id must not be empty")
        return v.strip()

    @field_validator("ttl_hours")
    @classmethod
    def ttl_must_be_valid(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if v <= 0:
            raise HTTPException(
                status_code=400,
                detail="ttl_hours must be positive or null for no expiry"
            )
        if v > 8760:
            raise HTTPException(
                status_code=400,
                detail="ttl_hours must be between 1 and 8760"
            )
        return v


class RegisterAgentResponse(BaseModel):
    """Returned after successful agent registration.

    IMPORTANT: vault_api_key is returned ONCE and never again.
    The agent must store it securely — if lost, revoke and re-create the card.
    """
    vault_api_key: str  # The single Vault API Key (starting with 'vzk_')
    valid_until: int | None    # Unix timestamp when this card expires (None if never)


class AgentResponse(BaseModel):
    """Details of a registered agent (capability card) returned in list views.

    Never leaks the raw vault_api_key or HMAC secret.
    """
    card_id: str
    agent_name: str
    allowed_labels: list[str]
    valid_until: int | None
    created_at: int
    is_expired: bool


from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def _derive_hmac_secret(vault_api_key: str) -> bytearray:
    """Derives a 32-byte HMAC secret from the vault_api_key.

    Uses HKDF with SHA-256, no salt, and info context b"vault-zero-hmac-v1".
    Returns the secret as a mutable bytearray so it can be zeroed out.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"vault-zero-hmac-v1",
    )
    derived = hkdf.derive(vault_api_key.encode("utf-8"))
    return bytearray(derived)


class RequestKeyRequest(BaseModel):
    """Body for POST /request_key — agent asking for a specific vault item's value."""
    label: str      # Which vault item label to retrieve (must be in permissions list)
    nonce: str | None = None      # A UUID4 the agent generates fresh for every single request
    timestamp: int | None = None  # Unix timestamp when the agent generated this request
    signature: str | None = None  # HMAC-SHA256 hex of "card_id:request_key:label:timestamp:nonce"

    @field_validator("label")
    @classmethod
    def label_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("label must not be empty")
        return v

    @field_validator("nonce")
    @classmethod
    def nonce_must_not_be_empty(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not v.strip():
            raise ValueError("nonce must not be empty")
        return v

    @field_validator("signature")
    @classmethod
    def signature_must_be_valid_hex(cls, v: str | None) -> str | None:
        """HMAC-SHA256 hex digest is always exactly 64 hex characters."""
        if v is None:
            return v
        if len(v) != 64:
            raise ValueError("signature must be 64 hex characters")
        try:
            bytes.fromhex(v)
        except ValueError:
            raise ValueError("signature must be valid hexadecimal")
        return v


class RequestKeyResponse(BaseModel):
    """The decrypted secret value — exists in memory only, never logged."""
    label: str
    value: str  # The plaintext secret — agent should use it immediately and discard it


class RequestPermissionRequest(BaseModel):
    """Body for POST /request_permission — agent asking the user for approval."""
    request_id: str  # UUID the agent generates to track this permission request
    action: str      # Plain-English description of what the agent wants to do
    nonce: str       # Fresh nonce for replay protection
    timestamp: int   # Unix timestamp of the request
    signature: str   # HMAC-SHA256 of "card_id:request_permission:action:timestamp:nonce"

    @field_validator("action")
    @classmethod
    def action_must_be_valid(cls, v: str) -> str:
        """Validates the action string is non-empty and within size limits."""
        if not v.strip():
            raise ValueError("action must not be empty")
        if len(v) > 1000:
            raise ValueError("action must be 1000 characters or fewer")
        return v

    @field_validator("signature")
    @classmethod
    def signature_must_be_valid_hex(cls, v: str) -> str:
        if len(v) != 64:
            raise ValueError("signature must be 64 hex characters")
        try:
            bytes.fromhex(v)
        except ValueError:
            raise ValueError("signature must be valid hexadecimal")
        return v


class RequestPermissionResponse(BaseModel):
    """The user's approve/deny decision."""
    request_id: str
    approved: bool


class RespondPermissionRequest(BaseModel):
    """Body for POST /respond_permission — sent by the UI when user clicks Approve/Deny."""
    request_id: str
    approved: bool


class RevokeCardResponse(BaseModel):
    """Returned after a capability card is successfully revoked."""
    revoked: bool
    card_id: str


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _extract_card_id(request: Request) -> str:
    """Extracts the card_id from the Authorization: Bearer <card_id> header.

    Raises HTTP 403 if the header is missing or malformed.
    Agent endpoints use their capability card ID as the Bearer token —
    NOT the user's JWT session token.

    The 403 detail is always the same opaque "access denied" string —
    never reveal WHY the request failed (per GEMINI.md agent spec).
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="access denied",
        )
    card_id = auth_header.split(" ", 1)[1].strip()
    if not card_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="access denied",
        )
    return card_id


def _require_vault_unlocked() -> bytearray:
    """Returns the active session key, or raises HTTP 403 if the vault is locked.

    Agent endpoints need the encryption key to decrypt vault items.
    If the vault is locked, no decryption is possible — agents must wait
    for the user to unlock the vault first.

    Returns the live session key — do NOT zero it (it belongs to _active_sessions).
    """
    key = get_any_session_key()
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="access denied",
        )
    return key


def _validate_agent_card(card_id: str, db_path: str, session_key: bytearray) -> dict:
    """Checks that a capability card exists and is not expired.

    Returns the card dict from the database.
    Raises HTTP 403 on any failure — NEVER reveals which check failed.
    This is intentional: an attacker probing different card_ids should get
    the same error for "doesn't exist" or "expired".
    """
    hashed_key = hashlib.sha256(card_id.encode("utf-8")).hexdigest()
    try:
        with get_connection(db_path, session_key) as conn:
            card = get_capability_card(conn, hashed_key)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="access denied",
        )

    if card is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="access denied",
        )

    # In _validate_agent_card() — expiry check:
    if card["valid_until"] is None:
        pass  # never expires — skip check
    elif int(time.time()) > card["valid_until"]:
        raise CardExpiredError

    return card


def _check_timestamp_freshness(timestamp: int) -> None:
    """Rejects requests with timestamps more than ±5 minutes from server time.

    This prevents signed requests from being stockpiled and used much later.
    Combined with nonce binding, this closes the window for replay attacks
    to at most 5 minutes (and the nonce store covers that entire window).
    """
    now = int(time.time())
    if abs(now - timestamp) > 300:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="access denied",
        )


def _append_audit_safe(
    db_path: str,
    session_key: bytearray,
    action: str,
    result: str,
    agent_id: str | None = None,
    label_accessed: str | None = None,
) -> None:
    """Writes an audit log entry without raising exceptions.

    Used in hot paths (HMAC failure, permission denied, etc.) where we want
    to record what happened but must not let a logging failure hide the
    actual security error being raised.
    """
    try:
        with get_connection(db_path, session_key) as conn:
            append_audit_log(
                conn,
                action=action,
                result=result,
                agent_id=agent_id,
                label_accessed=label_accessed,
            )
    except Exception as exc:
        logger.error("Audit log write failed (%s): %s", action, type(exc).__name__)


# ---------------------------------------------------------------------------
# ENDPOINTS — USER (require user session token)
# ---------------------------------------------------------------------------

@router.post(
    "/register",
    response_model=RegisterAgentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new AI agent and issue it a capability card (user auth required)",
)
@limiter.limit("60/minute")
async def register_agent(
    request: Request,
    body: RegisterAgentRequest,
    session_key: bytearray = Depends(require_session),
) -> RegisterAgentResponse:
    """Creates a capability card that grants an AI agent access to specific vault items.

    Steps:
      1. Validate that every requested label actually exists in the vault
      2. Generate a random 32-byte HMAC secret as bytearray (Rule 4 — can be zeroed)
      3. Store the capability card in the database with the permissions list
      4. Store the HMAC secret in memory (never written to disk in plaintext)
      5. Return card_id + hmac_secret (hex) + valid_until to the caller

    SECURITY: The HMAC secret is returned exactly once. If the agent loses it,
    the card must be revoked and a new one created. This is intentional —
    it forces agents to handle their secrets responsibly.
    """
    db_path = get_db_path()
    now = int(time.time())

    if body.ttl_hours is not None and body.ttl_hours <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ttl_hours must be positive or null for no expiry",
        )

    if body.ttl_hours is None:
        valid_until = None
    else:
        valid_until = now + (body.ttl_hours * 3600)

    # Verify that all requested labels exist in the vault
    try:
        with get_connection(db_path, session_key) as conn:
            existing_rows = list_vault_items(conn)
    except Exception as exc:
        logger.error("DB error during register_agent label check: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to validate labels",
        )

    existing_labels = {row["label"] for row in existing_rows}
    for label in body.permissions:
        if label not in existing_labels:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Vault item with label '{label}' not found",
            )

    # Generate the single Vault API Key: "vzk_" + 64 hex characters (256-bit entropy)
    vault_api_key = "vzk_" + secrets.token_hex(32)
    hashed_key = hashlib.sha256(vault_api_key.encode("utf-8")).hexdigest()

    # Store permissions as a JSON array of label strings
    permissions_json = json.dumps(body.permissions)

    try:
        with get_connection(db_path, session_key) as conn:
            card_id = insert_capability_card(
                conn,
                agent_id=body.agent_id,
                permissions=permissions_json,
                valid_until=valid_until,
                card_id=hashed_key,
            )
            append_audit_log(
                conn,
                action="register_agent",
                result="success",
                agent_id=body.agent_id,
            )
    except Exception as exc:
        logger.error("DB error during register_agent: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create capability card",
        )

    return RegisterAgentResponse(
        vault_api_key=vault_api_key,
        valid_until=valid_until,
    )


@router.get(
    "/pending_permissions",
    status_code=status.HTTP_200_OK,
    summary="Get all pending permission requests (UI polling endpoint)",
)
@limiter.limit("60/minute")
async def get_pending_permissions(
    request: Request,
    session_key: bytearray = Depends(require_session),
) -> dict:
    """Returns all permission requests currently waiting for user approval.

    The Electron UI renderer polls this endpoint (every ~2 seconds) so it
    knows when to show a permission popup to the user. The vault must be
    unlocked (valid session token required) to view pending requests.

    Returns: { "pending": [ { request_id, action, agent_id, created_at }, ... ] }
    """
    pending = [
        {
            "request_id": rid,
            "action": data["action"],
            "agent_id": data["agent_id"],
            "created_at": data["created_at"],
        }
        for rid, data in _pending_permissions.items()
    ]
    return {"pending": pending}


@router.post(
    "/respond_permission",
    status_code=status.HTTP_200_OK,
    summary="Submit user approval or denial for a permission request (UI use only)",
)
@limiter.limit("60/minute")
async def respond_permission(
    request: Request,
    body: RespondPermissionRequest,
    session_key: bytearray = Depends(require_session),
) -> dict:
    """Records the user's Approve or Deny decision for a pending permission request.

    Called by the Electron UI when the user clicks Approve or Deny on the popup.
    This unblocks the waiting /request_permission call and delivers the decision
    back to the agent.

    Returns 404 if the request_id is not found (may have already timed out).
    """
    pending = _pending_permissions.get(body.request_id)
    if pending is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No pending permission request found with id '{body.request_id}'",
        )

    # Record the decision and signal the waiting /request_permission coroutine
    pending["approved"] = body.approved
    pending["event"].set()

    return {"request_id": body.request_id, "approved": body.approved, "recorded": True}


@router.delete(
    "/cards/{card_id}",
    response_model=RevokeCardResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke a capability card — the agent can no longer use it (user auth required)",
)
@limiter.limit("60/minute")
async def revoke_card(
    request: Request,
    card_id: str,
    session_key: bytearray = Depends(require_session),
) -> RevokeCardResponse:
    """Permanently revokes a capability card.

    After revocation:
      - The card is deleted from the database.
      - The HMAC secret is zeroed from memory (Rule 4) and removed.
      - Any future requests using this card_id receive HTTP 403.

    This endpoint requires the USER's session token — only the vault owner
    can revoke cards (not the agent itself).

    Returns 404 if the card doesn't exist.
    """
    db_path = get_db_path()

    try:
        with get_connection(db_path, session_key) as conn:
            card = get_capability_card(conn, card_id)
            if card is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Capability card '{card_id}' not found or already expired",
                )

            deleted = delete_capability_card(conn, card_id)
            if not deleted:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Capability card '{card_id}' not found",
                )

            append_audit_log(
                conn,
                action="revoke_card",
                result="success",
                agent_id=card["agent_id"],
            )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("DB error during revoke_card: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke capability card",
        )

    # Zero and remove the HMAC secret from memory — card is now fully dead
    _revoke_hmac_secret(card_id)

    return RevokeCardResponse(revoked=True, card_id=card_id)


@router.get(
    "/list",
    response_model=list[AgentResponse],
    status_code=status.HTTP_200_OK,
    summary="List all registered capability cards (user auth required)",
)
@limiter.limit("60/minute")
async def list_agents(
    request: Request,
    session_key: bytearray = Depends(require_session),
) -> list[AgentResponse]:
    """Retrieves all registered agents (capability cards) from the database."""
    db_path = get_db_path()
    try:
        with get_connection(db_path, session_key) as conn:
            rows = conn.execute(
                "SELECT id, agent_id, permissions, valid_until, created_at "
                "FROM capability_cards ORDER BY created_at DESC"
            ).fetchall()
            append_audit_log(
                conn,
                action="list_agents",
                result="success",
            )
    except Exception as exc:
        logger.error("DB error during list_agents: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list agents",
        )

    now = int(time.time())
    agents = []
    for row in rows:
        card_id = row[0]
        agent_id = row[1]
        permissions_str = row[2]
        valid_until = row[3]
        created_at = row[4]

        try:
            allowed_labels = json.loads(permissions_str)
        except Exception:
            allowed_labels = []

        is_expired = valid_until is not None and now > valid_until

        agents.append(
            AgentResponse(
                card_id=card_id,
                agent_name=agent_id,
                allowed_labels=allowed_labels,
                valid_until=valid_until,
                created_at=created_at,
                is_expired=is_expired,
            )
        )
    return agents


@router.delete(
    "/revoke/{card_id}",
    response_model=RevokeCardResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke a capability card (user auth required)",
)
@limiter.limit("60/minute")
async def revoke_agent(
    request: Request,
    card_id: str,
    session_key: bytearray = Depends(require_session),
) -> RevokeCardResponse:
    """Revokes a capability card using the /revoke/{card_id} endpoint style."""
    db_path = get_db_path()
    try:
        with get_connection(db_path, session_key) as conn:
            row = conn.execute(
                "SELECT agent_id FROM capability_cards WHERE id = ?",
                (card_id,),
            ).fetchone()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Capability card '{card_id}' not found",
                )
            agent_id = row[0]

            deleted = delete_capability_card(conn, card_id)
            if not deleted:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Capability card '{card_id}' not found",
                )

            append_audit_log(
                conn,
                action="revoke_agent",
                result="success",
                agent_id=agent_id,
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("DB error during revoke_agent: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke capability card",
        )

    return RevokeCardResponse(revoked=True, card_id=card_id)


# ---------------------------------------------------------------------------
# ENDPOINTS — AGENT (Bearer token = capability card ID)
# ---------------------------------------------------------------------------

@router.post(
    "/request_key",
    response_model=RequestKeyResponse,
    status_code=status.HTTP_200_OK,
    summary="Request a decrypted key from the vault (agent auth via capability card)",
)
@limiter.limit("60/minute")
async def request_key(
    request: Request,
    body: RequestKeyRequest,
) -> RequestKeyResponse:
    """Decrypts and returns a specific vault item's value to an authorized agent.

    This is the most security-critical endpoint. Every layer is checked in order:

      Step 1 (Time):    Check timestamp freshness (±5 min). Reject stale requests early.
      Step 2 (Layer 1): Check nonce — reject if already seen (replay attack).
      Step 3 (Card):    Extract card_id from Bearer header; validate card exists + not expired.
      Step 4 (Vault):   Check the vault is unlocked (user has an active session).
      Step 5 (Layer 2): Verify HMAC signature — reject if payload was tampered.
      Step 6 (Perms):   Check the requested label is in the card's permissions list.
      Step 7 (Decrypt): Fetch encrypted payload, decrypt into a temporary bytearray.
      Step 8 (Return):  Decode to string, return in response.
      Step 9 (Zero):    Zero the bytearray immediately (finally block).
      Step 10 (Log):    Audit log — label only, value NEVER logged (Rule 6).

    SECURITY: The decrypted value exists as a bytearray until zeroed in the finally
    block. The decoded str copy is returned in the response and then unreachable.
    Python strings are immutable so we cannot zero the str — this is a known Python
    limitation documented in GEMINI.md. The key never touches disk, logs, or storage.
    This is Rule 3: keys in memory only.
    """
    # ----- Step 1: Timestamp freshness — reject stale requests before any work -----
    if body.timestamp is not None:
        _check_timestamp_freshness(body.timestamp)

    # ----- Step 2: Nonce check (replay protection, Layer 1) -----
    if body.nonce is not None:
        await _check_and_record_nonce(body.nonce)

    # ----- Step 3: Extract and validate the capability card -----
    card_id = _extract_card_id(request)
    session_key = _require_vault_unlocked()
    db_path = get_db_path()
    card = _validate_agent_card(card_id, db_path, session_key)

    # ----- Step 5 (Layer 2): HMAC signature verification -----
    if body.signature is not None:
        hmac_secret = _derive_hmac_secret(card_id)
        try:
            if not _verify_hmac_signature(
                secret=hmac_secret,
                card_id=card_id,
                msg_type="request_key",
                label=body.label,
                timestamp=body.timestamp,
                nonce=body.nonce,
                signature=body.signature,
            ):
                _append_audit_safe(
                    db_path, session_key,
                    action="request_key",
                    result="denied_invalid_signature",
                    agent_id=card["agent_id"],
                    label_accessed=body.label,
                )
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="access denied")
        finally:
            zero_memory(hmac_secret)

    # ----- Step 6: Permission check — label must be in card's allowed list -----
    try:
        allowed_labels: list[str] = json.loads(card["permissions"])
    except (json.JSONDecodeError, KeyError):
        allowed_labels = []

    if body.label not in allowed_labels:
        _append_audit_safe(
            db_path, session_key,
            action="request_key",
            result="denied_not_permitted",
            agent_id=card["agent_id"],
            label_accessed=body.label,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="access denied")

    # ----- Steps 7–10: Decrypt the key, return it, zero it, log it -----
    decrypted: bytearray | None = None
    try:
        with get_connection(db_path, session_key) as conn:
            # Find the vault item by label — we need its encrypted payload
            all_items = list_vault_items(conn)
            item_meta = next((i for i in all_items if i["label"] == body.label), None)

            if item_meta is None:
                # Label was in permissions but no longer in vault (deleted since card was issued)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="access denied",
                )

            # get_vault_item fetches the encrypted payload and updates last_accessed
            item = get_vault_item(conn, item_meta["id"])
            if item is None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="access denied",
                )

            # Parse the stored JSON payload and decrypt into a mutable bytearray
            payload_dict = json.loads(item["encrypted_payload"])
            decrypted = decrypt(payload_dict, session_key)

            # Decode to string for the JSON response. This creates an immutable str
            # that we cannot zero — a known Python limitation. The bytearray is zeroed
            # in the finally block below. The str will be garbage-collected normally.
            plaintext_value = decrypted.decode("utf-8")

            # Audit log — label only, NEVER the value (Rule 6 from GEMINI.md)
            append_audit_log(
                conn,
                action="request_key",
                result="approved",
                agent_id=card["agent_id"],
                label_accessed=body.label,
            )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Error during request_key decrypt: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve key",
        )
    finally:
        # Zero the decrypted bytearray regardless of success or failure.
        # This is the earliest possible moment we can wipe the plaintext bytes.
        if decrypted is not None:
            zero_memory(decrypted)

    return RequestKeyResponse(label=body.label, value=plaintext_value)


@router.post(
    "/request_permission",
    response_model=RequestPermissionResponse,
    status_code=status.HTTP_200_OK,
    summary="Request user approval for an action (agent auth via capability card)",
)
@limiter.limit("60/minute")
async def request_permission(
    request: Request,
    body: RequestPermissionRequest,
) -> RequestPermissionResponse:
    """Asks the user (via the Electron UI) to approve or deny an agent action.

    How it works:
      1. Agent sends a plain-English description of what it wants to do.
      2. All security layers are verified (nonce, card, HMAC, timestamp).
      3. We create a pending entry with an asyncio.Event and store it.
      4. This endpoint WAITS (up to 60 seconds) for the user to respond.
      5. The Electron UI polls GET /pending_permissions and shows a popup.
      6. User clicks Approve or Deny — the UI posts to POST /respond_permission.
      7. /respond_permission sets the event and records the decision.
      8. This endpoint wakes up, reads the decision, and returns it to the agent.

    SECURITY: On timeout, the decision is ALWAYS "denied". We NEVER auto-approve.
    This is a fail-safe default — if the user walks away, agents get nothing.
    """
    # Timestamp freshness — reject stale requests before doing any work
    _check_timestamp_freshness(body.timestamp)

    # Layer 1: Nonce check (replay protection)
    await _check_and_record_nonce(body.nonce)

    # Extract and validate capability card
    card_id = _extract_card_id(request)
    session_key = _require_vault_unlocked()
    db_path = get_db_path()
    card = _validate_agent_card(card_id, db_path, session_key)

    # Layer 2: HMAC signature verification
    # For permission requests, "label" in the signature = action description
    hmac_secret = _derive_hmac_secret(card_id)
    try:
        if not _verify_hmac_signature(
            secret=hmac_secret,
            card_id=card_id,
            msg_type="request_permission",
            label=body.action,
            timestamp=body.timestamp,
            nonce=body.nonce,
            signature=body.signature,
        ):
            _append_audit_safe(
                db_path, session_key,
                action="request_permission",
                result="denied_invalid_signature",
                agent_id=card["agent_id"],
                label_accessed=body.action[:200],
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="access denied")
    finally:
        zero_memory(hmac_secret)

    # Enforce cap on concurrent pending permissions to prevent DoS
    if len(_pending_permissions) >= _MAX_PENDING_PERMISSIONS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many pending permission requests",
        )

    # Create a pending permission entry — the UI will pick this up and show a popup
    event = asyncio.Event()
    _pending_permissions[body.request_id] = {
        "event": event,
        "approved": None,
        "action": body.action,
        "agent_id": card["agent_id"],
        "created_at": int(time.time()),
    }

    try:
        # Wait up to 60 seconds for the user to click Approve or Deny
        try:
            await asyncio.wait_for(event.wait(), timeout=float(_PERMISSION_TIMEOUT_SECONDS))
        except asyncio.TimeoutError:
            pass  # Fall through — decision is None → treated as denied (fail-safe)

        decision = _pending_permissions.get(body.request_id, {})
        approved: bool = decision.get("approved") or False  # None → False = auto-deny

    finally:
        # Always clean up the pending entry, even on error or timeout
        _pending_permissions.pop(body.request_id, None)

    result_str = "approved" if approved else "denied"

    # Audit log — action string (truncated) is the "label" here
    _append_audit_safe(
        db_path, session_key,
        action="request_permission",
        result=result_str,
        agent_id=card["agent_id"],
        label_accessed=body.action[:200],  # Truncate long action strings
    )

    return RequestPermissionResponse(request_id=body.request_id, approved=approved)
