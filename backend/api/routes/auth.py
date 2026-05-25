"""
Auth endpoints for Vault-Zero.

Controls vault access: unlock, lock, first-time setup, and password recovery.

Endpoints:
  POST /api/v1/auth/setup    — first-time vault initialization only
  POST /api/v1/auth/unlock   — verify password, return session token
  POST /api/v1/auth/lock     — invalidate session, zero key from memory
  POST /api/v1/auth/recover  — recover access using a recovery code

Rate limit: 60 requests per minute per IP (via slowapi).
This prevents brute-force attacks against all auth endpoints.
"""

import base64
import json
import os
import secrets
import shutil
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from backend.core.crypto import derive_key, zero_memory, encrypt, decrypt
from backend.core.security import create_session, destroy_session, get_session_key
from backend.database.models import (
    get_db_path,
    get_connection,
    initialize_database,
    get_setting,
    set_setting,
)


# ---------------------------------------------------------------------------
# RATE LIMITER — shared with main.py
# ---------------------------------------------------------------------------

# get_remote_address extracts the client IP for per-IP rate limiting
limiter = Limiter(key_func=get_remote_address)

# Router prefix and tags are set here; main.py mounts it at /api/v1/auth
router = APIRouter(prefix="/auth", tags=["auth"])

# Used to parse Bearer tokens from the Authorization header
bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# REQUEST / RESPONSE MODELS
# ---------------------------------------------------------------------------

class UnlockRequest(BaseModel):
    """Body for the unlock endpoint — the master password."""
    password: str

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        """Reject empty / single-char passwords up front (Bug 3 fix).

        Setup already enforces a minimum of 8 chars; mirroring it here
        means an attacker can't even start a derive_key cycle for an
        obviously-too-short input. Returns 422 via Pydantic before the
        rate limiter sees the request.
        """
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        return v


class UnlockResponse(BaseModel):
    """Successful unlock returns only the session token — never the derived key."""
    session_token: str


class LockResponse(BaseModel):
    """Successful lock response."""
    status: str  # always "locked"


class SetupRequest(BaseModel):
    """Body for first-time vault creation — the chosen master password."""
    password: str


class SetupResponse(BaseModel):
    """Returned after vault is first initialized.

    recovery_code is returned EXACTLY ONCE and never stored in plaintext.
    The user must save it — if the master password is forgotten, this is the
    only way to regain access. There is no other recovery path.
    """
    session_token: str
    recovery_code: str  # Format: VZK-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX (6 hex groups)


class RecoverRequest(BaseModel):
    """Body for account recovery — the old recovery code and the desired new password."""
    recovery_code: str
    new_password: str


class RecoverResponse(BaseModel):
    """Returned after a successful recovery.

    A brand-new recovery code is generated. The old one is permanently invalidated.
    new_recovery_code must be saved — it replaces the old one completely.
    """
    session_token: str
    new_recovery_code: str


# ---------------------------------------------------------------------------
# DEPENDENCY — extracts and validates the Bearer token from any request
# ---------------------------------------------------------------------------

def require_session(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> bytearray:
    """FastAPI dependency: validates the Bearer token and returns the live session key.

    Inject this into any endpoint that requires the vault to be unlocked:
        @router.get("/items")
        def get_items(key: bytearray = Depends(require_session)):
            ...

    Raises HTTP 401 if the token is missing, expired, or invalid.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    key = get_session_key(credentials.credentials)
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token. Please unlock the vault.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return key


# ---------------------------------------------------------------------------
# ENDPOINTS
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hashes the master password using Argon2id with standard parameters."""
    salt = os.urandom(16)
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=65536,
    )
    hashed = kdf.derive(password.encode("utf-8"))
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hashed_b64 = base64.b64encode(hashed).decode("ascii")
    return f"argon2id${salt_b64}${hashed_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies the password against the stored Argon2id hash."""
    try:
        parts = stored_hash.split("$")
        if len(parts) != 3 or parts[0] != "argon2id":
            return False
        salt = base64.b64decode(parts[1])
        hashed = base64.b64decode(parts[2])
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            lanes=4,
            memory_cost=65536,
        )
        kdf.verify(password.encode("utf-8"), hashed)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _generate_recovery_code() -> str:
    """Generates a cryptographically random recovery code in VZK-XXXX-XXXX-... format.

    Uses 6 groups of 4 hex characters (2 bytes each) for 96 bits of entropy.
    The "VZK-" prefix makes it clearly identifiable as a Vault-Zero recovery code.

    Example: VZK-A3F9-B2C1-D4E5-F6G7-H8I9-J0K1

    Why generated on the Python side: JavaScript's crypto.getRandomValues() is fine
    for browser contexts, but all security-sensitive operations belong in the Python
    backend, which is compiled with Nuitka. The JS renderer has zero access to this.
    """
    groups = [secrets.token_hex(2).upper() for _ in range(6)]
    return "VAULT-" + "-".join(groups)


@router.post(
    "/unlock",
    response_model=UnlockResponse,
    status_code=status.HTTP_200_OK,
    summary="Unlock the vault with the master password",
)
@limiter.limit("60/minute")
async def unlock(request: Request, body: UnlockRequest) -> UnlockResponse:
    """Derives the encryption key from the master password and opens a session.

    On first unlock ever (no hash stored yet), it initializes the database and 
    saves the password hash. On subsequent unlocks, it compares against the hash
    and returns HTTP 401 on failure.
    """
    db_path = get_db_path()
    salt_path = str(Path(db_path).with_suffix(".salt"))

    db_exists = Path(db_path).exists()
    salt_exists = Path(salt_path).exists()

    # Edge case — salt file exists but database was deleted
    if salt_exists and not db_exists:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid password",
        )

    # Resolve salt if exists
    salt = None
    if salt_exists:
        try:
            with open(salt_path, "rb") as f:
                salt = f.read()
        except Exception:
            pass

    key = None
    try:
        # Derive the key — derive_key() zeros the password bytes internally
        key, salt = derive_key(body.password, salt)

        if not db_exists:
            # FIRST unlock ever: initialize database and store hash
            initialize_database(db_path, key)
            
            # Save the salt companion file
            Path(salt_path).parent.mkdir(parents=True, exist_ok=True)
            with open(salt_path, "wb") as f:
                f.write(salt)

            pw_hash = hash_password(body.password)
            with get_connection(db_path, key) as conn:
                set_setting(conn, "master_password_hash", pw_hash)
        else:
            # Subsequent unlocks: attempt to connect and retrieve/verify hash
            try:
                with get_connection(db_path, key) as conn:
                    stored_hash = get_setting(conn, "master_password_hash")
            except Exception:
                # Any database error (like decryption failure) is a wrong password
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="invalid password",
                )

            if stored_hash is None:
                # Fallback: if database exists but has no hash (edge case), initialize/store it
                pw_hash = hash_password(body.password)
                with get_connection(db_path, key) as conn:
                    set_setting(conn, "master_password_hash", pw_hash)
            elif not verify_password(body.password, stored_hash):
                # Password hash does not match
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="invalid password",
                )

        # Store the key in memory, get back a JWT session token
        token = create_session(key)
        return UnlockResponse(session_token=token)

    finally:
        # Always zero our local reference to the derived key
        if key is not None:
            zero_memory(key)


@router.post(
    "/lock",
    response_model=LockResponse,
    status_code=status.HTTP_200_OK,
    summary="Lock the vault and zero the key from memory",
)
@limiter.limit("60/minute")
async def lock(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> LockResponse:
    """Destroys the session and zeros the derived key from memory.

    After this call, the session token is permanently invalid.
    The user must call /unlock again to regain access.

    This endpoint deliberately does NOT require require_session — a user
    should be able to lock even if their token is about to expire.
    It returns 200 even if the token was already invalid (safe to call multiple times).
    """
    if credentials is not None:
        # Best-effort destroy — don't raise even if session was already gone
        destroy_session(credentials.credentials)

    return LockResponse(status="locked")


# ---------------------------------------------------------------------------
# FIRST-TIME SETUP
# ---------------------------------------------------------------------------

@router.post(
    "/setup",
    response_model=SetupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initialize the vault for the first time with a master password",
)
@limiter.limit("60/minute")
async def setup(request: Request, body: SetupRequest) -> SetupResponse:
    """Creates the vault database and master password on first run.

    This endpoint can only be called ONCE — if the vault is already initialized
    (master_password_hash exists in vault_settings) it returns HTTP 409.

    Why generate the recovery code here (Python) and not in the UI (JS):
    All security-sensitive random generation belongs in the compiled Python backend.
    The renderer has no access to this endpoint's internals.

    Steps:
      1. Reject if vault already initialized (409)
      2. Validate password length >= 8
      3. Generate a cryptographically random recovery code
      4. Derive the 256-bit vault key via Argon2id
      5. Initialize all database tables
      6. Store Argon2id hashes of both password AND recovery code
      7. Create a session, return session_token + recovery_code (once only)
    """
    if len(body.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="password_too_short",
        )

    db_path = get_db_path()
    salt_path = str(Path(db_path).with_suffix(".salt"))

    db_exists = Path(db_path).exists()

    # If the database already exists, check whether it has been initialized.
    # We must open the DB to check vault_settings, but we don't yet have the
    # correct key — so we attempt to derive one and catch failures gracefully.
    if db_exists:
        # The salt file holds the key-derivation salt for the existing vault.
        if Path(salt_path).exists():
            try:
                with open(salt_path, "rb") as f:
                    existing_salt = f.read()
                existing_key, _ = derive_key(body.password, existing_salt)
                try:
                    with get_connection(db_path, existing_key) as conn:
                        existing_hash = get_setting(conn, "master_password_hash")
                    if existing_hash is not None:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="vault_already_initialized",
                        )
                finally:
                    zero_memory(existing_key)
            except HTTPException:
                raise
            except Exception:
                # If we can't open the existing DB with this password, the vault
                # was initialized with a different password — still a 409.
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="vault_already_initialized",
                )
        else:
            # DB exists but no salt — treat as already initialized
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="vault_already_initialized",
            )

    # Generate the recovery code before any key material is created
    recovery_code = _generate_recovery_code()

    key = None
    recovery_key = None
    try:
        # Derive the vault key from the chosen password (fresh Argon2id salt)
        key, salt = derive_key(body.password)

        # Create and encrypt the database with the vault key
        initialize_database(db_path, key)

        # Persist the master Argon2id salt for subsequent /unlock calls
        Path(salt_path).parent.mkdir(parents=True, exist_ok=True)
        with open(salt_path, "wb") as f:
            f.write(salt)

        # Derive a SEPARATE recovery key from the recovery code + its own fresh salt.
        # This key is used ONLY during the /recover flow.
        recovery_key, recovery_salt = derive_key(recovery_code)
        recovery_salt_path = str(Path(db_path).with_suffix(".recovery.salt"))
        with open(recovery_salt_path, "wb") as f:
            f.write(recovery_salt)

        # Encrypt the raw vault key under the recovery key and write it to a
        # .keyblob file OUTSIDE the database. This lets /recover read the blob
        # without needing to open the encrypted DB first — the DB is still keyed
        # with the master password. The blob is AES-256-GCM encrypted, so
        # someone with the .keyblob file alone still cannot open the vault.
        key_bundle = encrypt(bytes(key), recovery_key)
        keyblob_path = str(Path(db_path).with_suffix(".keyblob"))
        with open(keyblob_path, "w") as f:
            f.write(json.dumps(key_bundle))

        # Store hashes of both the password and recovery code inside the DB
        pw_hash = hash_password(body.password)
        rc_hash = hash_password(recovery_code)

        with get_connection(db_path, key) as conn:
            set_setting(conn, "master_password_hash", pw_hash)
            set_setting(conn, "recovery_code_hash", rc_hash)

        # Bug 1 fix — also write the recovery code hash to a side-file so /recover
        # can verify the supplied code BEFORE opening the SQLCipher database. This
        # closes a timing oracle: previously, the DB was opened (Argon2id key
        # derivation + sqlcipher open) prior to the Argon2id hash check, so wrong
        # codes took noticeably longer to fail than malformed ones. Argon2id
        # hashes aren't reversible, so storing the hash next to the DB is safe.
        recovery_hash_path = str(Path(db_path).with_suffix(".recovery.hash"))
        with open(recovery_hash_path, "w") as f:
            f.write(rc_hash)

        # Open a session — same mechanism as /unlock
        token = create_session(key)
        # recovery_code is returned to the caller once and never stored raw
        return SetupResponse(session_token=token, recovery_code=recovery_code)

    finally:
        if recovery_key is not None:
            zero_memory(recovery_key)
        if key is not None:
            zero_memory(key)


# ---------------------------------------------------------------------------
# PASSWORD RECOVERY
# ---------------------------------------------------------------------------

@router.post(
    "/recover",
    response_model=RecoverResponse,
    status_code=status.HTTP_200_OK,
    summary="Recover vault access using the recovery code",
)
@limiter.limit("60/minute")
async def recover(request: Request, body: RecoverRequest) -> RecoverResponse:
    """Re-keys the entire vault when the master password is forgotten.

    This is the nuclear option — use only when the master password is lost.
    After recovery, the old recovery code is permanently invalidated and a
    new one is generated. The user MUST save the new recovery code immediately.

    How the DB is opened without the master password:
      During /setup, the raw vault key is encrypted with a recovery-key derived from
      the recovery code, and the encrypted blob is stored in vault_settings.
      /recover decrypts that blob to get the original vault key, then opens the DB,
      re-encrypts all vault items under a new password-derived key, and uses
      SQLCipher's PRAGMA rekey to re-encrypt the database file itself.

    Steps:
      1. Validate new_password length >= 8
      2. Verify the recovery code's Argon2id hash against the side-file BEFORE
         opening the SQLCipher database (Bug 1 — closes timing oracle)
      3. Load recovery_salt, derive recovery_key = Argon2id(recovery_code, recovery_salt)
      4. Decrypt key_bundle to get old vault_key
      5. Copy DB to temp; open temp with old_key; verify recovery_code_hash
         (defense-in-depth); read all vault items
      6. Decrypt all items with old vault_key
      7. Derive new vault_key from new_password (fresh salt)
      8. Re-encrypt all items with new vault_key
      9. On the temp DB only: update all rows, update settings, PRAGMA rekey
     10. Verify the rekeyed temp DB opens cleanly with new_key
     11. os.replace(temp, db_path) — atomic swap (Bug 2 — no half-rekeyed file)
     12. Write new companion files; create new session; return new recovery code
    """
    if len(body.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="password_too_short",
        )

    db_path = get_db_path()
    salt_path = str(Path(db_path).with_suffix(".salt"))
    recovery_salt_path = str(Path(db_path).with_suffix(".recovery.salt"))
    keyblob_path = str(Path(db_path).with_suffix(".keyblob"))
    recovery_hash_path = str(Path(db_path).with_suffix(".recovery.hash"))

    if not Path(db_path).exists() or not Path(recovery_salt_path).exists() or not Path(keyblob_path).exists():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_recovery_code",
        )

    # Bug 1 fix — verify the Argon2id hash from the side-file BEFORE we touch
    # SQLCipher. The previous flow opened the DB (Argon2id key derivation +
    # sqlcipher_open) before the hash check, leaking timing information about
    # which step rejected. We still re-check inside the DB later as defense-in-depth.
    if Path(recovery_hash_path).exists():
        try:
            with open(recovery_hash_path, "r") as f:
                side_hash = f.read().strip()
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_recovery_code",
            )
        if not verify_password(body.recovery_code, side_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_recovery_code",
            )

    try:
        with open(recovery_salt_path, "rb") as f:
            recovery_salt = f.read()
        with open(keyblob_path, "r") as f:
            key_bundle = json.loads(f.read())
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_recovery_code",
        )

    recovery_key = None
    old_key = None
    new_key = None
    decrypted_items: list[tuple[str, str, str, bytes]] = []

    # Temp DB path lives next to the real one; os.replace is atomic on the same volume.
    temp_db_path = db_path + ".rekey.tmp"

    try:
        # Derive the recovery key from the provided recovery code + stored recovery salt
        recovery_key, _ = derive_key(body.recovery_code, recovery_salt)

        # Decrypt the key bundle to get the original vault key.
        # If the recovery code is wrong, this AES-GCM decrypt will raise an exception.
        try:
            old_key_bytes = decrypt(key_bundle, recovery_key)  # bytearray
            old_key = old_key_bytes
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_recovery_code",
            )

        # Bug 2 fix — work on a copy so an interrupted rekey can't corrupt the
        # live vault. copy2 preserves the SQLCipher header.
        try:
            shutil.copy2(db_path, temp_db_path)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).error(
                "Recovery: temp copy failed: %s", type(exc).__name__
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="recovery_failed",
            )

        # Open the temp DB with the recovered vault key to verify the recovery_code
        # hash (defense-in-depth) and read all vault items
        try:
            with get_connection(temp_db_path, old_key) as conn:
                stored_rc_hash = get_setting(conn, "recovery_code_hash")
                rows = conn.execute(
                    "SELECT id, category, label, encrypted_payload FROM vault_items"
                ).fetchall()
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_recovery_code",
            )

        # Defense-in-depth: re-verify the Argon2id hash inside the DB itself.
        # Catches the case where someone tampered with the side-file but not
        # the encrypted vault_settings row.
        if stored_rc_hash is None or not verify_password(body.recovery_code, stored_rc_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_recovery_code",
            )

        # Decrypt every vault item with the old vault key
        for row in rows:
            item_id, category, label, encrypted_payload_json = row
            payload_dict = json.loads(encrypted_payload_json)
            plaintext_ba = decrypt(payload_dict, old_key)
            decrypted_items.append((item_id, category, label, bytes(plaintext_ba)))
            zero_memory(plaintext_ba)

        # Derive new vault key from the new master password (fresh random salt)
        new_key, new_salt = derive_key(body.new_password)

        # Re-encrypt every item under the new vault key
        reencrypted: list[tuple[str, str]] = []
        for item_id, _category, _label, plaintext_bytes in decrypted_items:
            new_payload = encrypt(plaintext_bytes, new_key)
            reencrypted.append((item_id, json.dumps(new_payload)))

        # Derive a new recovery key for the new recovery code
        new_recovery_code = _generate_recovery_code()
        new_recovery_key, new_recovery_salt = derive_key(new_recovery_code)

        # Encrypt the new vault key under the new recovery key for the .keyblob
        new_key_bundle = encrypt(bytes(new_key), new_recovery_key)
        zero_memory(new_recovery_key)

        new_pw_hash = hash_password(body.new_password)
        new_rc_hash = hash_password(new_recovery_code)

        # Re-key the TEMP database file using PRAGMA rekey. The original is
        # untouched until we os.replace at the end. If we crash anywhere in
        # this block, the temp file is removed and the user can still recover
        # by re-running with the same code.
        try:
            from sqlcipher3 import dbapi2 as sqlcipher

            conn_raw = sqlcipher.connect(temp_db_path)
            old_key_hex = bytes(old_key).hex()
            new_key_hex = bytes(new_key).hex()

            conn_raw.execute(f"PRAGMA key = \"x'{old_key_hex}'\";")
            conn_raw.execute("PRAGMA cipher_page_size = 4096;")
            conn_raw.execute("PRAGMA kdf_iter = 256000;")
            conn_raw.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512;")
            conn_raw.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;")
            conn_raw.execute("PRAGMA journal_mode = WAL;")

            # Update all vault items with their newly re-encrypted payloads
            for item_id, new_payload_json in reencrypted:
                conn_raw.execute(
                    "UPDATE vault_items SET encrypted_payload = ? WHERE id = ?",
                    (new_payload_json, item_id),
                )

            # Update vault settings with new hashes (key bundle is now in .keyblob, not DB)
            conn_raw.execute(
                "INSERT OR REPLACE INTO vault_settings (key, value) VALUES (?, ?)",
                ("master_password_hash", new_pw_hash),
            )
            conn_raw.execute(
                "INSERT OR REPLACE INTO vault_settings (key, value) VALUES (?, ?)",
                ("recovery_code_hash", new_rc_hash),
            )

            conn_raw.commit()

            # Re-encrypt the database file with the new vault key
            conn_raw.execute(f"PRAGMA rekey = \"x'{new_key_hex}'\";")
            conn_raw.commit()
            conn_raw.close()

            # Verify by opening the rekeyed temp file fresh with the new key.
            # If this round-trip fails, the rekey didn't actually take and we
            # must NOT replace the original.
            with get_connection(temp_db_path, new_key) as verify_conn:
                verify_hash = get_setting(verify_conn, "master_password_hash")
            if verify_hash != new_pw_hash:
                raise RuntimeError("rekey verification mismatch")

        except Exception as exc:
            import logging
            logging.getLogger(__name__).error(
                "Recovery re-keying failed: %s", type(exc).__name__
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="recovery_failed",
            )

        # The temp DB is now rekeyed and verified. Atomic swap into place.
        try:
            os.replace(temp_db_path, db_path)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).error(
                "Recovery: atomic replace failed: %s", type(exc).__name__
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="recovery_failed",
            )

        # Overwrite companion files. Order: salt first (needed for any future
        # /unlock), then keyblob, then recovery salt + recovery hash.
        with open(salt_path, "wb") as f:
            f.write(new_salt)
        with open(keyblob_path, "w") as f:
            f.write(json.dumps(new_key_bundle))
        with open(recovery_salt_path, "wb") as f:
            f.write(new_recovery_salt)
        with open(recovery_hash_path, "w") as f:
            f.write(new_rc_hash)

        # Open a new session under the new key
        token = create_session(new_key)
        return RecoverResponse(session_token=token, new_recovery_code=new_recovery_code)

    finally:
        # Clean up the temp file in any failure path. os.replace already
        # consumed it on the success path, so missing-file is fine.
        if Path(temp_db_path).exists():
            try:
                os.remove(temp_db_path)
            except Exception:
                pass
        if recovery_key is not None:
            zero_memory(recovery_key)
        if old_key is not None:
            zero_memory(old_key)
        if new_key is not None:
            zero_memory(new_key)
        # bytes objects are immutable — plaintext_bytes copies cannot be zeroed;
        # they will be collected by the GC. The bytearray copies were zeroed above.
