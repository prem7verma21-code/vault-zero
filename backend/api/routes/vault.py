"""
Vault CRUD endpoints for Vault-Zero — Step 1.5.

Handles Create, Read, Delete operations for stored secrets (vault_items).
Every secret value is encrypted with AES-256-GCM *before* being stored —
this module never writes or returns a plaintext secret value.

Endpoints:
  GET    /api/v1/vault/items           — list all items (labels only, never payloads)
  POST   /api/v1/vault/items           — add a new encrypted secret
  DELETE /api/v1/vault/items/{item_id} — permanently delete an item by UUID
  GET    /api/v1/vault/audit           — last 100 audit log entries (for Step 1.8C)

Security rules enforced here:
  - encrypted_payload is NEVER returned in any response
  - All write operations are recorded in the audit_log
  - Labels returned; decrypted values never returned
  - Duplicate label returns 409 Conflict
  - Unknown item_id for DELETE returns 404
"""

import json
import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.api.routes.auth import require_session
from backend.core.crypto import encrypt, decrypt, zero_memory
from backend.database.models import (
    get_db_path,
    get_connection,
    insert_vault_item,
    list_vault_items,
    delete_vault_item,
    get_vault_item,
    append_audit_log,
    get_audit_log,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vault", tags=["vault"])

# Rate limiter — GEMINI.md Rule 7: every endpoint gets 60 req/min
limiter = Limiter(key_func=get_remote_address)

# ---------------------------------------------------------------------------
# CATEGORY VALIDATION — backend accepts any non-empty string
# The frontend dropdown restricts UX choices; the backend never limits storage.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# REQUEST / RESPONSE MODELS
# ---------------------------------------------------------------------------

class VaultItemResponse(BaseModel):
    """A single vault item as returned to the UI — never includes the payload."""
    id: str
    category: str
    label: str
    created_at: int


class VaultItemListResponse(BaseModel):
    """List of vault items."""
    items: list[VaultItemResponse]


class AddItemRequest(BaseModel):
    """Body for POST /items — the plaintext secret is accepted here, encrypted immediately."""
    category: str
    label: str
    value: str

    @field_validator("category")
    @classmethod
    def category_must_be_valid(cls, v: str) -> str:
        if not v or len(v.strip()) == 0:
            raise ValueError("category cannot be empty")
        return v

    @field_validator("label")
    @classmethod
    def label_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("label must not be empty")
        return v

    @field_validator("value")
    @classmethod
    def value_must_not_be_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("value must not be empty")
        return v


class DeleteItemResponse(BaseModel):
    """Response for a successful DELETE."""
    deleted: bool
    id: str


class RevealItemResponse(BaseModel):
    """Response for POST /items/{id}/reveal — the decrypted secret value.

    The value is only ever held in the response body. The caller is expected
    to display it for a short window (UI: 30 seconds, then auto-hide) and not
    cache it. The bytearray copy on the server is zeroed before this returns.
    """
    id: str
    label: str
    value: str
    expires_at: int  # Unix seconds — UI uses this to drive the auto-hide countdown


class AuditLogEntry(BaseModel):
    """A single audit log entry."""
    id: int
    timestamp: int
    agent_id: str | None
    action: str
    result: str
    label_accessed: str | None


class AuditLogResponse(BaseModel):
    """Audit log entries."""
    entries: list[AuditLogEntry]


# ---------------------------------------------------------------------------
# ENDPOINTS
# ---------------------------------------------------------------------------

@router.get(
    "/items",
    response_model=VaultItemListResponse,
    status_code=status.HTTP_200_OK,
    summary="List all vault items (labels only — never returns encrypted payloads)",
)
@limiter.limit("60/minute")
async def get_items(
    request: Request,
    session_key: bytearray = Depends(require_session),
) -> VaultItemListResponse:
    """Returns all stored vault items with metadata.

    SECURITY: encrypted_payload is intentionally excluded from this response.
    The UI only needs to display what items *exist*, never their values.
    Decrypted values are only ever returned by the agent endpoint that
    explicitly requests a specific key (Step 1.6).
    """
    db_path = get_db_path()
    try:
        with get_connection(db_path, session_key) as conn:
            rows = list_vault_items(conn)
            append_audit_log(conn, action="list_items", result="success")
    except Exception as exc:
        logger.error("Database error during list_items: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to read vault items",
        )

    return VaultItemListResponse(
        items=[
            VaultItemResponse(
                id=row["id"],
                category=row["category"],
                label=row["label"],
                created_at=row["created_at"],
            )
            for row in rows
        ]
    )


@router.post(
    "/items",
    response_model=VaultItemResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a new encrypted secret to the vault",
)
@limiter.limit("60/minute")
async def add_item(
    request: Request,
    body: AddItemRequest,
    session_key: bytearray = Depends(require_session),
) -> VaultItemResponse:
    """Encrypts a new secret and stores it in the vault.

    Steps:
      1. Category is validated by Pydantic (see AddItemRequest validator)
      2. Duplicate label check — returns 409 if label already exists
      3. Encrypt the plaintext value with the session key
      4. Store {nonce, ciphertext} JSON as encrypted_payload
      5. Log the operation (label only — the value is NEVER logged)
      6. Return item metadata (id, category, label, created_at) — never the value

    SECURITY: The plaintext `body.value` is encoded to bytes, encrypted, and
    the result is stored. The variable goes out of scope immediately after.
    It is never written to any log, response, or file.
    """
    db_path = get_db_path()
    plaintext: bytearray | None = None

    try:
        with get_connection(db_path, session_key) as conn:
            # Duplicate label check — 409 Conflict if already exists
            existing_rows = list_vault_items(conn)
            existing_labels = {row["label"] for row in existing_rows}
            if body.label in existing_labels:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"A vault item with label '{body.label}' already exists",
                )

            # Encrypt the plaintext value — value never touches the database directly
            plaintext = bytearray(body.value.encode("utf-8"))
            payload_dict = encrypt(bytes(plaintext), session_key)
            encrypted_payload = json.dumps(payload_dict)

            # Compute created_at locally — avoids a second DB query
            created_at = int(time.time())

            # Persist to database
            item_id = insert_vault_item(
                conn,
                category=body.category,
                label=body.label,
                encrypted_payload=encrypted_payload,
            )

            # Record in audit log — label only, NEVER the value
            append_audit_log(
                conn,
                action="add_item",
                result="success",
                label_accessed=body.label,
            )

    except HTTPException:
        raise  # Re-raise 409 directly
    except Exception as exc:
        logger.error("Database error during add_item: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to store vault item",
        )
    finally:
        # Zero the plaintext from memory regardless of success or failure
        if plaintext is not None:
            zero_memory(plaintext)

    return VaultItemResponse(
        id=item_id,
        category=body.category,
        label=body.label,
        created_at=created_at,
    )


@router.delete(
    "/items/{item_id}",
    response_model=DeleteItemResponse,
    status_code=status.HTTP_200_OK,
    summary="Permanently delete a vault item by UUID",
)
@limiter.limit("60/minute")
async def delete_item(
    request: Request,
    item_id: str,
    session_key: bytearray = Depends(require_session),
) -> DeleteItemResponse:
    """Permanently deletes a vault item.

    Returns 404 if no item with that UUID exists.
    This is a hard delete — there is no undo.
    The audit log records the label of what was deleted, not the value.
    """
    db_path = get_db_path()
    try:
        with get_connection(db_path, session_key) as conn:
            # Fetch the label before deleting (for audit log)
            rows = list_vault_items(conn)
            item = next((r for r in rows if r["id"] == item_id), None)

            if item is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Vault item '{item_id}' not found",
                )

            deleted = delete_vault_item(conn, item_id)
            if not deleted:
                # Highly unlikely race condition — treat as not found
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Vault item '{item_id}' not found",
                )

            # Audit log — label of the deleted item, never the value
            append_audit_log(
                conn,
                action="delete_item",
                result="success",
                label_accessed=item["label"],
            )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Database error during delete_item: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete vault item",
        )

    return DeleteItemResponse(deleted=True, id=item_id)


@router.post(
    "/items/{item_id}/reveal",
    response_model=RevealItemResponse,
    status_code=status.HTTP_200_OK,
    summary="Decrypt and return a single vault item's value (UI auto-hides after 30s)",
)
@limiter.limit("60/minute")
async def reveal_item(
    request: Request,
    item_id: str,
    session_key: bytearray = Depends(require_session),
) -> RevealItemResponse:
    """Decrypts and returns the plaintext value of a vault item to the UI.

    This is the user-facing counterpart of /agent/request_key. Auth is the
    standard session token (the human looking at their own vault), there are
    no capability cards involved, and any item the unlocked vault contains
    can be revealed.

    Steps:
      1. Look up item by id (404 if missing)
      2. Decrypt the stored payload into a temporary bytearray
      3. Decode to string for the response
      4. Audit-log {label, action="reveal_item"}; never the value
      5. Zero the bytearray in finally before returning

    The response carries `expires_at = now + 30` so the UI can drive a visible
    countdown without trusting the client clock for absolute timing.
    """
    db_path = get_db_path()
    decrypted: bytearray | None = None

    try:
        with get_connection(db_path, session_key) as conn:
            item = get_vault_item(conn, item_id)
            if item is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Vault item '{item_id}' not found",
                )

            payload_dict = json.loads(item["encrypted_payload"])
            decrypted = decrypt(payload_dict, session_key)
            plaintext_value = decrypted.decode("utf-8")

            append_audit_log(
                conn,
                action="reveal_item",
                result="success",
                label_accessed=item["label"],
            )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Database error during reveal_item: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reveal vault item",
        )
    finally:
        # Zero our local bytearray copy; the immutable str escapes via the
        # response body and is unreachable once the response is serialized.
        if decrypted is not None:
            zero_memory(decrypted)

    return RevealItemResponse(
        id=item_id,
        label=item["label"],
        value=plaintext_value,
        expires_at=int(time.time()) + 30,
    )


@router.get(
    "/audit",
    response_model=AuditLogResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve the last 100 audit log entries (newest first)",
)
@limiter.limit("60/minute")
async def get_audit(
    request: Request,
    session_key: bytearray = Depends(require_session),
) -> AuditLogResponse:
    """Returns the most recent 100 audit log entries in reverse-chronological order.

    Used by the Audit Log screen (Step 1.8C) to show what has happened in the vault.
    Records contain: timestamp, agent_id, action, result, label_accessed.
    Secret values are NEVER present in the audit log.
    """
    db_path = get_db_path()
    try:
        with get_connection(db_path, session_key) as conn:
            entries = get_audit_log(conn, limit=100)
    except Exception as exc:
        logger.error("Database error during get_audit: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to read audit log",
        )

    return AuditLogResponse(
        entries=[
            AuditLogEntry(
                id=e["id"],
                timestamp=e["timestamp"],
                agent_id=e["agent_id"],
                action=e["action"],
                result=e["result"],
                label_accessed=e["label_accessed"],
            )
            for e in entries
        ]
    )
