"""
Abstract base class (interface) for all cryptographic providers in Vault-Zero.

Why this exists:
  The pluggable provider pattern means the rest of the codebase never imports
  crypto.py directly for type-checking — it imports this interface instead.
  That means in the future, a different crypto backend (e.g. hardware HSM,
  or a FIPS-compliant provider) can be swapped in without touching any
  other file — only crypto.py needs to change.

Any class that inherits from CryptoProvider and implements all abstract
methods is a valid drop-in replacement for the default Argon2id + AES-256-GCM
implementation in crypto.py.
"""

import uuid
from abc import ABC, abstractmethod


class CryptoProvider(ABC):
    """Defines the contract that every crypto backend must fulfill.

    All methods here are abstract — a subclass that skips any of them
    will raise a TypeError at import time, preventing silent bugs.
    """

    @abstractmethod
    def zero_memory(self, b: bytearray) -> None:
        """Securely wipe all bytes in a bytearray to zero.

        Must work in-place on the bytearray.
        Must raise TypeError if given an immutable bytes object.
        """
        ...

    @abstractmethod
    def derive_key(self, password: str, salt: bytes = None) -> tuple[bytearray, bytes]:
        """Derive a 256-bit encryption key from a password using a KDF.

        If salt is None, a fresh random salt must be generated and returned.
        Must return (key, salt) where key is a 32-byte bytearray.
        Must zero the password from memory before returning.
        """
        ...

    @abstractmethod
    def encrypt(self, plaintext: bytes, key: bytearray) -> dict:
        """Encrypt plaintext with a 256-bit key.

        Must generate a fresh random nonce for every call — never reuse.
        Must return at minimum: {"nonce": "<base64>", "ciphertext": "<base64>"}.
        """
        ...

    @abstractmethod
    def decrypt(self, encrypted_data: dict, key: bytearray) -> bytearray:
        """Decrypt data produced by encrypt().

        Must raise an exception (never return bad data) if:
          - The key is wrong
          - The ciphertext has been tampered with
          - The nonce or ciphertext is malformed
        Must return decrypted data as a bytearray (so caller can zero it).
        """
        ...

    def generate_id(self) -> str:
        """Generate a unique identifier for vault items and capability cards.

        Returns a UUID4 string. Not abstract — subclasses may override if
        they need a different ID scheme (e.g. deterministic test IDs),
        but the default implementation is correct for production use.
        """
        return str(uuid.uuid4())


