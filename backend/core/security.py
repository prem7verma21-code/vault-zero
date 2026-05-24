"""
Session token generation and in-memory session management for Vault-Zero.

When the user unlocks the vault, a derived key is created from their password.
That key must live somewhere in memory so vault operations can use it without
asking for the password again. This module manages that.

How sessions work:
  1. User provides master password → auth.py derives a key
  2. This module stores the key in _active_sessions keyed by a session ID
  3. A JWT containing the session ID is returned to the user (never the key itself)
  4. On every vault request, the JWT is verified → session ID → key is looked up
  5. On lock or server restart, all keys are zeroed and sessions are cleared

Security notes:
  - The JWT secret is random bytes generated once at startup — all sessions are
    invalidated if the server restarts (correct behavior for a local vault)
  - Session IDs in JWTs are opaque UUIDs — the key is never in the token
  - Sessions expire after 8 hours by default
  - zero_memory() is called when a session is destroyed
"""

import os
import uuid
import time
from typing import Optional

from jose import JWTError, jwt

from backend.core.crypto import zero_memory


# ---------------------------------------------------------------------------
# SERVER-LIFETIME SECRET — random bytes, never stored, gone on restart
# ---------------------------------------------------------------------------

# This secret is used to sign JWTs. It is generated once when the server starts.
# If the server restarts, all existing JWTs become invalid — this is intentional.
# A local vault should not survive server restarts with open sessions.
_JWT_SECRET: str = os.urandom(32).hex()
_JWT_ALGORITHM: str = "HS256"
_SESSION_TTL_SECONDS: int = 8 * 60 * 60  # 8 hours


# ---------------------------------------------------------------------------
# IN-MEMORY SESSION STORE — maps session ID → derived key
# ---------------------------------------------------------------------------

# This dict holds the derived keys for all active sessions.
# Keys are opaque UUIDs. Values are bytearray (so they can be zeroed on lock).
# This dict is the ONLY place derived keys live — they are never written to disk.
_active_sessions: dict[str, bytearray] = {}


# ---------------------------------------------------------------------------
# PUBLIC API
# ---------------------------------------------------------------------------

def create_session(derived_key: bytearray) -> str:
    """Stores a derived key in memory and returns a signed JWT session token.

    The JWT contains only a session ID — never the key itself.
    The caller (auth.py) should zero derived_key after passing it here;
    this function takes ownership and stores its own copy.

    Returns:
        A signed JWT string the client uses for subsequent requests.
    """
    session_id = str(uuid.uuid4())
    expiry = int(time.time()) + _SESSION_TTL_SECONDS

    # Store a copy of the key — we own this copy now
    _active_sessions[session_id] = bytearray(derived_key)

    payload = {
        "sub": session_id,   # subject — the opaque session identifier
        "exp": expiry,       # expiry — token becomes invalid after this Unix timestamp
        "iat": int(time.time()),  # issued at
    }

    token = jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)
    return token


def get_session_key(token: str) -> Optional[bytearray]:
    """Validates a JWT and returns the derived key for that session.

    Returns None (not an exception) if the token is invalid or expired.
    Callers must treat None as 'not authenticated' and return 401.

    IMPORTANT: The caller must NOT zero the returned bytearray — it is the
    live reference stored in _active_sessions. Zeroing it would destroy the session.
    If you need to use the key temporarily, copy it.
    """
    try:
        payload = jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
        session_id: str = payload.get("sub")
        if session_id is None:
            return None
        return _active_sessions.get(session_id)  # None if session was destroyed
    except JWTError:
        return None


def destroy_session(token: str) -> bool:
    """Zeros the derived key and removes the session — this is the 'lock' operation.

    After this call, the token is permanently invalid. The user must unlock again
    (re-enter their password) to get a new session.

    Returns True if a session was found and destroyed, False if it didn't exist.
    """
    try:
        payload = jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
        session_id: str = payload.get("sub")
        if session_id is None:
            return False
        key = _active_sessions.pop(session_id, None)
        if key is not None:
            zero_memory(key)  # Securely wipe the key from memory
            return True
        return False
    except JWTError:
        return False


def destroy_all_sessions() -> None:
    """Zeros all keys and clears all sessions — called on server shutdown.

    This ensures no derived keys linger in memory after the app closes.
    """
    for session_id, key in list(_active_sessions.items()):
        zero_memory(key)
    _active_sessions.clear()


def is_vault_unlocked() -> bool:
    """Returns True if there is at least one active session (vault is unlocked).

    Used by the UI to show the correct initial screen.
    """
    return len(_active_sessions) > 0


def get_any_session_key() -> Optional[bytearray]:
    """Returns the encryption key from any active session, or None if vault is locked.

    This is used by agent endpoints, which authenticate via capability cards
    (not user JWTs). The agent's card proves identity; this function provides
    the encryption key needed to decrypt vault items.

    Because Vault-Zero is single-user local software, there is at most one
    active session at a time. If the vault is locked, agents cannot access keys.

    IMPORTANT: Do NOT zero the returned bytearray — it is the live reference
    stored in _active_sessions. Zeroing it would destroy the session.
    """
    if not _active_sessions:
        return None
    # Return the first (and normally only) active session key
    return next(iter(_active_sessions.values()))
