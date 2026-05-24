"""
Defines the SQLCipher database schema and connection management for Vault-Zero.

SQLCipher is SQLite with AES-256 encryption at the file level. This means the
entire .db file on disk is encrypted — even if someone steals the file, it's
unreadable without the key.

IMPORTANT: This module works together with the double-encryption strategy:
  - SQLCipher encrypts the entire database FILE (this module)
  - crypto.py encrypts individual secret VALUES before storage (Rule 8 from GEMINI.md)
  - Two independent encryption layers = much stronger protection

Tables:
  - vault_items      — encrypted API keys and other secrets
  - capability_cards — permission grants for AI agents
  - audit_log        — record of every action taken (labels only, never secret values)
"""

import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

# Import sqlcipher3 which is a drop-in replacement for sqlite3 with encryption.
# It has the same API as sqlite3, so the code looks almost identical.
try:
    from sqlcipher3 import dbapi2 as sqlcipher
except ImportError:
    # This should never happen in production — sqlcipher3 is in requirements.txt
    raise ImportError(
        "sqlcipher3 is not installed. Run: pip install sqlcipher3"
    )


# ---------------------------------------------------------------------------
# DATABASE SCHEMA — Exact from GEMINI.md, do not modify
# ---------------------------------------------------------------------------

# This is the SQL that creates all three tables.
# It uses IF NOT EXISTS so it is safe to run every time the app starts.
_CREATE_VAULT_ITEMS = """
CREATE TABLE IF NOT EXISTS vault_items (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    label TEXT NOT NULL,
    encrypted_payload BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    last_accessed INTEGER
);
"""

_CREATE_CAPABILITY_CARDS = """
CREATE TABLE IF NOT EXISTS capability_cards (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    permissions TEXT NOT NULL,
    valid_until INTEGER,
    created_at INTEGER NOT NULL
);
"""

_CREATE_AUDIT_LOG = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    agent_id TEXT,
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    label_accessed TEXT
);
"""

_CREATE_VAULT_SETTINGS = """
CREATE TABLE IF NOT EXISTS vault_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def get_db_path() -> str:
    """Returns the platform-specific path to the Vault-Zero database file.

    Windows: %APPDATA%/Vault-Zero/vault.db
    macOS: ~/Library/Application Support/Vault-Zero/vault.db
    Linux/Other: ~/.config/Vault-Zero/vault.db
    """
    import os
    import sys
    if os.name == "nt":
        base_dir = os.environ.get("APPDATA")
        if not base_dir:
            base_dir = str(Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base_dir = os.environ.get("HOME")
        if base_dir:
            base_dir = str(Path(base_dir) / "Library" / "Application Support")
        else:
            base_dir = str(Path.home() / "Library" / "Application Support")
    else:
        base_dir = os.environ.get("HOME")
        if base_dir:
            base_dir = str(Path(base_dir) / ".config")
        else:
            base_dir = str(Path.home() / ".config")
            
    return str(Path(base_dir) / "Vault-Zero" / "vault.db")


# ---------------------------------------------------------------------------
# CONNECTION MANAGEMENT
# ---------------------------------------------------------------------------

def _open_connection(db_path: str, key_hex: str) -> sqlcipher.Connection:
    """Opens an encrypted SQLCipher database connection.

    The key_hex is the 256-bit derived key (from Argon2id) formatted as a
    hex string. SQLCipher unlocks the file with this key — without it,
    the file is just random-looking bytes.

    Why raw key via "x'...'" format: this tells SQLCipher the key is raw bytes,
    not a passphrase. We always use the derived key, never the raw password.
    """
    conn = sqlcipher.connect(db_path)
    try:
        # Set the encryption key IMMEDIATELY after opening — before any other query.
        # If this is a new database, SQLCipher encrypts it with this key.
        # If existing, it decrypts it with this key (wrong key = "file is encrypted" error).
        conn.execute(f"PRAGMA key = \"x'{key_hex}'\";")

        # These settings make SQLCipher use the current (v4) cipher defaults:
        # AES-256-CBC with HMAC-SHA512. Do not change these.
        conn.execute("PRAGMA cipher_page_size = 4096;")
        conn.execute("PRAGMA kdf_iter = 256000;")
        conn.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512;")
        conn.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;")

        # Standard SQLite pragmas for reliability
        conn.execute("PRAGMA journal_mode = WAL;")      # Write-Ahead Logging for crash safety
        conn.execute("PRAGMA foreign_keys = ON;")        # Enforce referential integrity

        return conn
    except Exception:
        conn.close()
        raise


@contextmanager
def get_connection(db_path: str, key_bytes: bytes) -> Generator[sqlcipher.Connection, None, None]:
    """Context manager that opens, yields, and safely closes a database connection.

    Usage:
        with get_connection(db_path, key_bytes) as conn:
            conn.execute(...)

    The key_bytes is the raw 32-byte key from crypto.derive_key(). We convert it
    to hex here so it can be passed to SQLCipher's PRAGMA key.

    Always use this context manager — it ensures the connection is closed even
    if something goes wrong, so we never leave an open handle to the encrypted DB.
    """
    key_hex = key_bytes.hex()  # Convert raw bytes to hex string for SQLCipher
    conn = _open_connection(db_path, key_hex)
    try:
        yield conn
        conn.commit()  # Auto-commit on successful exit
    except Exception:
        conn.rollback()  # Roll back any partial changes on error
        raise
    finally:
        conn.close()  # Always close, even if an exception occurred


# ---------------------------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------------------------

def initialize_database(db_path: str, key_bytes: bytes) -> None:
    """Creates all tables in a new (or existing) SQLCipher database.

    Safe to call every time the app starts — IF NOT EXISTS means it won't
    overwrite existing data. If the database file doesn't exist, SQLCipher
    creates and encrypts it. If it exists, it opens and decrypts it.

    Call this once during app startup, right after the user unlocks the vault.
    """
    # Create the directory if it doesn't exist yet
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    with get_connection(db_path, key_bytes) as conn:
        conn.execute(_CREATE_VAULT_ITEMS)
        conn.execute(_CREATE_CAPABILITY_CARDS)
        conn.execute(_CREATE_AUDIT_LOG)
        conn.execute(_CREATE_VAULT_SETTINGS)


# ---------------------------------------------------------------------------
# VAULT ITEMS
# ---------------------------------------------------------------------------

def insert_vault_item(
    conn: sqlcipher.Connection,
    category: str,
    label: str,
    encrypted_payload: str,
) -> str:
    """Stores a new encrypted secret in the vault.

    The encrypted_payload must already be encrypted by crypto.encrypt_item()
    before calling this function — this module never touches plaintext secrets.

    Returns the new item's ID so the caller can reference it later.
    """
    item_id = str(uuid.uuid4())
    now = int(time.time())
    conn.execute(
        """
        INSERT INTO vault_items (id, category, label, encrypted_payload, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (item_id, category, label, encrypted_payload, now),
    )
    return item_id


def get_vault_item(conn: sqlcipher.Connection, item_id: str) -> dict | None:
    """Fetches a single vault item by ID, including its encrypted payload.

    Returns None if the item doesn't exist.
    The caller is responsible for decrypting the payload using crypto.decrypt_item().
    """
    row = conn.execute(
        "SELECT id, category, label, encrypted_payload, created_at, last_accessed "
        "FROM vault_items WHERE id = ?",
        (item_id,),
    ).fetchone()

    if row is None:
        return None

    # Mark the access time so we know when each item was last used
    conn.execute(
        "UPDATE vault_items SET last_accessed = ? WHERE id = ?",
        (int(time.time()), item_id),
    )

    return {
        "id": row[0],
        "category": row[1],
        "label": row[2],
        "encrypted_payload": row[3],
        "created_at": row[4],
        "last_accessed": row[5],
    }


def list_vault_items(conn: sqlcipher.Connection) -> list[dict]:
    """Returns all vault items — labels and metadata ONLY, never the encrypted payloads.

    This is intentional: the UI only needs to show what items exist.
    The actual encrypted data is only fetched when explicitly requested (get_vault_item).
    This follows Rule 3: keys live in memory only — we minimize how often we touch them.
    """
    rows = conn.execute(
        "SELECT id, category, label, created_at, last_accessed "
        "FROM vault_items ORDER BY created_at DESC"
    ).fetchall()

    return [
        {
            "id": row[0],
            "category": row[1],
            "label": row[2],
            "created_at": row[3],
            "last_accessed": row[4],
        }
        for row in rows
    ]


def delete_vault_item(conn: sqlcipher.Connection, item_id: str) -> bool:
    """Permanently deletes a vault item by ID.

    Returns True if an item was deleted, False if the ID didn't exist.
    This is a hard delete — there is no undo. Call only after explicit user confirmation.
    """
    cursor = conn.execute(
        "DELETE FROM vault_items WHERE id = ?",
        (item_id,),
    )
    return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# CAPABILITY CARDS
# ---------------------------------------------------------------------------

def insert_capability_card(
    conn: sqlcipher.Connection,
    agent_id: str,
    permissions: str,
    valid_until: int | None = None,
    card_id: str | None = None,
) -> str:
    """Creates a new capability card granting an agent access to specific vault items.

    permissions is a JSON string describing what the agent is allowed to access.
    valid_until is a Unix timestamp — after this time, the card is expired.
    If valid_until is None, the card never expires (use with caution).

    Returns the new card's ID.
    """
    if card_id is None:
        card_id = str(uuid.uuid4())
    now = int(time.time())
    conn.execute(
        """
        INSERT INTO capability_cards (id, agent_id, permissions, valid_until, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (card_id, agent_id, permissions, valid_until, now),
    )
    return card_id


def get_capability_card(conn: sqlcipher.Connection, card_id: str) -> dict | None:
    """Fetches a capability card by ID.

    Returns None if the card doesn't exist OR if it is expired.
    Callers should treat both cases identically — never reveal which one it is.
    """
    row = conn.execute(
        "SELECT id, agent_id, permissions, valid_until, created_at "
        "FROM capability_cards WHERE id = ?",
        (card_id,),
    ).fetchone()

    if row is None:
        return None

    # Check expiry — expired card is treated as not found
    valid_until = row[3]
    if valid_until is not None and int(time.time()) > valid_until:
        return None

    return {
        "id": row[0],
        "agent_id": row[1],
        "permissions": row[2],
        "valid_until": row[3],
        "created_at": row[4],
    }


def delete_capability_card(conn: sqlcipher.Connection, card_id: str) -> bool:
    """Revokes a capability card. The agent can no longer request keys with this card.

    Returns True if a card was revoked, False if the ID didn't exist.
    """
    cursor = conn.execute(
        "DELETE FROM capability_cards WHERE id = ?",
        (card_id,),
    )
    return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# AUDIT LOG
# ---------------------------------------------------------------------------

def append_audit_log(
    conn: sqlcipher.Connection,
    action: str,
    result: str,
    agent_id: str | None = None,
    label_accessed: str | None = None,
) -> None:
    """Records an action in the audit log.

    CRITICAL: This function ONLY records labels and action descriptions.
    NEVER pass a decrypted key value, password, or any secret content here.
    Rule 6: The audit log never stores secret values — only what happened.

    action       — what was attempted (e.g., "request_key", "unlock", "add_item")
    result       — outcome (e.g., "approved", "denied", "success", "failure")
    agent_id     — which agent made the request (None for user-initiated actions)
    label_accessed — which item's label was accessed (NOT the value)
    """
    conn.execute(
        """
        INSERT INTO audit_log (timestamp, agent_id, action, result, label_accessed)
        VALUES (?, ?, ?, ?, ?)
        """,
        (int(time.time()), agent_id, action, result, label_accessed),
    )


def get_audit_log(conn: sqlcipher.Connection, limit: int = 100) -> list[dict]:
    """Returns the most recent audit log entries, newest first.

    Capped at `limit` entries (default 100) to prevent unbounded queries.
    """
    rows = conn.execute(
        """
        SELECT id, timestamp, agent_id, action, result, label_accessed
        FROM audit_log
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    return [
        {
            "id": row[0],
            "timestamp": row[1],
            "agent_id": row[2],
            "action": row[3],
            "result": row[4],
            "label_accessed": row[5],
        }
        for row in rows
    ]


# ---------------------------------------------------------------------------
# SETTINGS
# ---------------------------------------------------------------------------

def get_setting(conn: sqlcipher.Connection, key: str) -> str | None:
    """Retrieves a setting value by key. Returns None if not found."""
    row = conn.execute(
        "SELECT value FROM vault_settings WHERE key = ?",
        (key,),
    ).fetchone()
    return row[0] if row else None


def set_setting(conn: sqlcipher.Connection, key: str, value: str) -> None:
    """Stores or updates a setting key-value pair."""
    conn.execute(
        "INSERT OR REPLACE INTO vault_settings (key, value) VALUES (?, ?)",
        (key, value),
    )
