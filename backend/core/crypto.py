"""
Handles all encryption and decryption for Vault-Zero using AES-256-GCM + Argon2id.

This module provides four capabilities:
  1. zero_memory  — securely wipes a bytearray so secrets don't linger in RAM
  2. derive_key   — turns a master password into a 256-bit encryption key using Argon2id
  3. encrypt      — encrypts plaintext bytes with AES-256-GCM, returns nonce + ciphertext
  4. decrypt      — reverses encryption given the correct key

Plus two convenience functions that combine derivation + encryption into one call:
  5. encrypt_item — derive key from password, encrypt, return full payload (salt + nonce + ciphertext)
  6. decrypt_item — re-derive key from stored salt, decrypt, return plaintext

This module also exports AESGCMProvider — a class that implements the CryptoProvider
interface from crypto_interface.py. run_server.py uses this class so that the
crypto backend is pluggable in the future.
"""

import os
import base64
import ctypes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from backend.core.crypto_interface import CryptoProvider


# ---------------------------------------------------------------------------
# MEMORY SAFETY
# ---------------------------------------------------------------------------

def zero_memory(b: bytearray) -> None:
    """Overwrites every byte in a bytearray with zeros.

    Why: Python's normal 'bytes' type is immutable — you can't erase it.
    We use 'bytearray' for all secrets so we can zero the memory when done.
    This stops secrets from sitting in RAM after we're finished with them.
    """
    if not isinstance(b, bytearray):
        raise TypeError("zero_memory only works on bytearray — bytes cannot be zeroed")
    if len(b) == 0:
        return
    ctypes.memset(
        ctypes.addressof((ctypes.c_char * len(b)).from_buffer(b)),
        0,
        len(b),
    )


# ---------------------------------------------------------------------------
# KEY DERIVATION
# ---------------------------------------------------------------------------

def derive_key(password: str, salt: bytes = None) -> tuple[bytearray, bytes]:
    """Turns the master password into a 256-bit encryption key using Argon2id.

    How it works:
      - Takes your password (a string) and a random salt (16 bytes)
      - Runs Argon2id, which is deliberately slow and memory-heavy (64 MB)
      - This makes brute-force guessing extremely expensive for attackers
      - Returns the derived key as a bytearray (so it can be zeroed later)

    If no salt is provided, a fresh random one is generated.
    The salt must be stored — you need it to re-derive the same key on next unlock.

    Returns:
      (key, salt) — key is a 32-byte bytearray, salt is 16 bytes
    """
    if salt is None:
        salt = os.urandom(16)

    # Convert password to bytes — Argon2id works on raw bytes, not strings
    password_bytes = bytearray(password.encode("utf-8"))

    try:
        # Exact parameters from the project spec — do not change these
        # NOTE: The GEMINI.md spec says "memory_size" but the cryptography library's
        # actual parameter name is "memory_cost". Same value (65536 KiB = 64 MB).
        kdf = Argon2id(
            salt=salt,
            length=32,            # 256-bit key
            iterations=3,         # time_cost — how many passes over memory
            lanes=4,              # parallelism — how many threads can work at once
            memory_cost=65536,    # 64 MB in KiB — makes each guess cost real resources
        )

        # derive() returns immutable bytes, so we copy into a mutable bytearray
        derived_bytes = kdf.derive(bytes(password_bytes))
        key = bytearray(derived_bytes)

        return key, salt
    finally:
        # Always zero the password bytes, even if derivation fails
        zero_memory(password_bytes)


# ---------------------------------------------------------------------------
# ENCRYPTION
# ---------------------------------------------------------------------------

def encrypt(plaintext: bytes, key: bytearray) -> dict:
    """Encrypts plaintext using AES-256-GCM and returns nonce + ciphertext.

    How it works:
      - Generates a fresh random 12-byte nonce (used only once, ever)
      - Encrypts with AES-256-GCM, which also creates an authentication tag
      - The tag is appended to the ciphertext automatically by the library
      - Returns everything base64-encoded so it can be stored as text in the database

    Security notes:
      - A NEW nonce is generated for every single call — never reuse a nonce with the same key
      - GCM's auth tag means any tampering with the ciphertext will be detected on decrypt

    Returns:
      {"nonce": "<base64>", "ciphertext": "<base64>"}
    """
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes (256 bits)")

    # 96-bit nonce, freshly random for each encryption — NEVER reuse
    nonce = os.urandom(12)

    aesgcm = AESGCM(bytes(key))

    # encrypt() returns ciphertext with GCM authentication tag appended
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


# ---------------------------------------------------------------------------
# DECRYPTION
# ---------------------------------------------------------------------------

def decrypt(encrypted_data: dict, key: bytearray) -> bytearray:
    """Decrypts data that was encrypted by the encrypt() function above.

    How it works:
      - Reads the nonce and ciphertext from the payload (base64-decoded)
      - Decrypts with AES-256-GCM using the same key that encrypted it
      - GCM automatically verifies the authentication tag — if anyone tampered
        with the ciphertext, this raises an exception instead of returning bad data

    Returns:
      The original plaintext as a bytearray (so the caller can zero it after use).

    Raises:
      cryptography.exceptions.InvalidTag — if the key is wrong or data was tampered with.
      This is intentional: we NEVER return partial or corrupted data.
    """
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes (256 bits)")

    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])

    aesgcm = AESGCM(bytes(key))

    # decrypt() verifies the GCM tag — raises InvalidTag if wrong key or tampered data
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)

    # Return as bytearray so the caller can zero it when done
    return bytearray(plaintext_bytes)


# ---------------------------------------------------------------------------
# CONVENIENCE: FULL PIPELINE (derive + encrypt/decrypt in one call)
# ---------------------------------------------------------------------------

def encrypt_item(plaintext: bytes, password: str, salt: bytes = None) -> dict:
    """Full pipeline: derives a key from the password, encrypts, returns a self-contained payload.

    This is a convenience function that combines derive_key() + encrypt().
    Use this when you want a single encrypted item that can be decrypted later
    with just the password — no need to manage the key separately.

    Returns:
      {"salt": "<base64>", "nonce": "<base64>", "ciphertext": "<base64>"}
      This matches the exact storage format from the project spec (GEMINI.md).
    """
    key, used_salt = derive_key(password, salt)

    try:
        result = encrypt(plaintext, key)
        result["salt"] = base64.b64encode(used_salt).decode("ascii")
        return result
    finally:
        # Key was only needed for this operation — zero it immediately
        zero_memory(key)


def decrypt_item(encrypted_data: dict, password: str) -> bytearray:
    """Full pipeline: re-derives the key from the stored salt, then decrypts.

    This is the reverse of encrypt_item(). It reads the salt from the payload,
    re-derives the same key using the password, and decrypts.

    Returns:
      The original plaintext as a bytearray (zero it when you're done with it!).
    """
    salt = base64.b64decode(encrypted_data["salt"])
    key, _ = derive_key(password, salt)

    try:
        return decrypt(encrypted_data, key)
    finally:
        # Zero the re-derived key immediately after use
        zero_memory(key)


# ---------------------------------------------------------------------------
# PLUGGABLE PROVIDER — wraps the module-level functions above into a class
# ---------------------------------------------------------------------------

class AESGCMProvider(CryptoProvider):
    """Concrete implementation of CryptoProvider using AES-256-GCM + Argon2id.

    This class is a thin wrapper around the module-level functions in this file.
    It exists so the rest of the codebase can depend on the CryptoProvider
    interface rather than on this specific implementation.

    To swap in a different crypto backend in the future, create a new class
    that inherits CryptoProvider and pass it to the server instead of this one.
    """

    def zero_memory(self, b: bytearray) -> None:
        """Delegates to the module-level zero_memory() function."""
        zero_memory(b)

    def derive_key(self, password: str, salt: bytes = None) -> tuple[bytearray, bytes]:
        """Delegates to the module-level derive_key() function."""
        return derive_key(password, salt)

    def encrypt(self, plaintext: bytes, key: bytearray) -> dict:
        """Delegates to the module-level encrypt() function."""
        return encrypt(plaintext, key)

    def decrypt(self, encrypted_data: dict, key: bytearray) -> bytearray:
        """Delegates to the module-level decrypt() function."""
        return decrypt(encrypted_data, key)
