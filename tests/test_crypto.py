"""
Tests for crypto.py: verifies that the encryption system works correctly and securely.

Three REQUIRED tests from GEMINI.md:
  1. Encrypt then decrypt gives back the original data (round-trip)
  2. Wrong password/key raises an exception — never returns partial or wrong data
  3. Five encryptions of the same data produce five different nonces (no reuse)

Plus additional tests for edge cases and security properties.
"""

import base64

import pytest
from cryptography.exceptions import InvalidTag

from backend.core.crypto import (
    decrypt,
    decrypt_item,
    derive_key,
    encrypt,
    encrypt_item,
    zero_memory,
)


# ---------------------------------------------------------------------------
# zero_memory() tests
# ---------------------------------------------------------------------------

class TestZeroMemory:
    """Tests for the zero_memory() function that wipes sensitive data from RAM."""

    def test_zeros_all_bytes(self):
        """After zeroing, every byte should be 0x00."""
        secret = bytearray(b"super_secret_key_12345")
        original_length = len(secret)
        zero_memory(secret)
        assert secret == bytearray(original_length)

    def test_rejects_immutable_bytes(self):
        """bytes objects can't be zeroed — this must raise TypeError."""
        with pytest.raises(TypeError):
            zero_memory(b"immutable")

    def test_empty_bytearray_is_safe(self):
        """Zeroing an empty bytearray should not crash."""
        empty = bytearray(b"")
        zero_memory(empty)  # should not raise


# ---------------------------------------------------------------------------
# derive_key() tests
# ---------------------------------------------------------------------------

class TestDeriveKey:
    """Tests for the Argon2id key derivation function."""

    def test_returns_32_byte_key(self):
        """The derived key must always be exactly 256 bits (32 bytes)."""
        key, salt = derive_key("test_password")
        assert len(key) == 32
        assert isinstance(key, bytearray)
        zero_memory(key)

    def test_returns_16_byte_salt_when_generated(self):
        """When no salt is provided, a random 16-byte salt is generated."""
        key, salt = derive_key("test_password")
        assert len(salt) == 16
        zero_memory(key)

    def test_same_password_same_salt_same_key(self):
        """Same password + same salt must always produce the same key."""
        key1, salt = derive_key("my_password")
        key2, _ = derive_key("my_password", salt)
        assert key1 == key2
        zero_memory(key1)
        zero_memory(key2)

    def test_different_salt_different_key(self):
        """Same password but different salts must produce different keys."""
        key1, salt1 = derive_key("my_password")
        key2, salt2 = derive_key("my_password")
        # Two random 16-byte salts are virtually guaranteed to differ
        assert salt1 != salt2
        assert key1 != key2
        zero_memory(key1)
        zero_memory(key2)

    def test_key_is_bytearray_not_bytes(self):
        """Key must be bytearray (mutable) so it can be zeroed after use."""
        key, _ = derive_key("password")
        assert type(key) is bytearray
        zero_memory(key)

    def test_uses_provided_salt(self):
        """When a specific salt is provided, it must be used as-is."""
        custom_salt = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        key, returned_salt = derive_key("password", salt=custom_salt)
        assert returned_salt == custom_salt
        zero_memory(key)


# ---------------------------------------------------------------------------
# encrypt() + decrypt() tests
# ---------------------------------------------------------------------------

class TestEncryptDecrypt:
    """Tests for the core encrypt/decrypt round-trip."""

    def test_round_trip(self):
        """REQUIRED TEST 1: Encrypting then decrypting must return the exact original data."""
        key, _ = derive_key("password123")
        original = b"This is my secret API key: sk-1234567890abcdef"

        encrypted = encrypt(original, key)
        decrypted = decrypt(encrypted, key)

        assert bytes(decrypted) == original
        zero_memory(decrypted)
        zero_memory(key)

    def test_wrong_key_raises_invalid_tag(self):
        """REQUIRED TEST 2: Wrong key must raise InvalidTag — never return garbage data."""
        key1, _ = derive_key("correct_password")
        key2, _ = derive_key("wrong_password")

        encrypted = encrypt(b"secret data", key1)

        with pytest.raises(InvalidTag):
            decrypt(encrypted, key2)

        zero_memory(key1)
        zero_memory(key2)

    def test_five_encryptions_five_different_nonces(self):
        """REQUIRED TEST 3: Each encryption must use a unique random nonce."""
        key, _ = derive_key("password")
        plaintext = b"same data every time"

        nonces = set()
        for _ in range(5):
            result = encrypt(plaintext, key)
            nonces.add(result["nonce"])

        assert len(nonces) == 5, "All 5 nonces must be different"
        zero_memory(key)

    def test_five_encryptions_five_different_ciphertexts(self):
        """Different nonces mean different ciphertexts, even for identical plaintext."""
        key, _ = derive_key("password")
        plaintext = b"same data every time"

        ciphertexts = set()
        for _ in range(5):
            result = encrypt(plaintext, key)
            ciphertexts.add(result["ciphertext"])

        assert len(ciphertexts) == 5
        zero_memory(key)

    def test_decrypted_value_is_bytearray(self):
        """Decrypted output must be bytearray so the caller can zero it after use."""
        key, _ = derive_key("password")
        encrypted = encrypt(b"secret", key)
        decrypted = decrypt(encrypted, key)

        assert type(decrypted) is bytearray
        zero_memory(decrypted)
        zero_memory(key)

    def test_tampered_ciphertext_raises_error(self):
        """If someone modifies the encrypted data, decryption must fail — never return corrupted data."""
        key, _ = derive_key("password")
        encrypted = encrypt(b"important data", key)

        # Tamper with the ciphertext by flipping bits in the first byte
        raw = bytearray(base64.b64decode(encrypted["ciphertext"]))
        raw[0] ^= 0xFF
        encrypted["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")

        with pytest.raises(InvalidTag):
            decrypt(encrypted, key)

        zero_memory(key)

    def test_tampered_nonce_raises_error(self):
        """If someone modifies the nonce, decryption must also fail."""
        key, _ = derive_key("password")
        encrypted = encrypt(b"important data", key)

        # Tamper with the nonce
        raw_nonce = bytearray(base64.b64decode(encrypted["nonce"]))
        raw_nonce[0] ^= 0xFF
        encrypted["nonce"] = base64.b64encode(bytes(raw_nonce)).decode("ascii")

        with pytest.raises(InvalidTag):
            decrypt(encrypted, key)

        zero_memory(key)

    def test_empty_plaintext(self):
        """Encrypting and decrypting empty data should work correctly."""
        key, _ = derive_key("password")
        encrypted = encrypt(b"", key)
        decrypted = decrypt(encrypted, key)

        assert bytes(decrypted) == b""
        zero_memory(key)

    def test_large_plaintext(self):
        """Encrypting a larger payload (simulating a long API key or token) works."""
        key, _ = derive_key("password")
        original = b"A" * 4096  # 4 KB of data
        encrypted = encrypt(original, key)
        decrypted = decrypt(encrypted, key)

        assert bytes(decrypted) == original
        zero_memory(decrypted)
        zero_memory(key)

    def test_rejects_wrong_key_length(self):
        """Keys that aren't exactly 32 bytes must be rejected immediately."""
        short_key = bytearray(b"too_short")
        with pytest.raises(ValueError):
            encrypt(b"data", short_key)
        with pytest.raises(ValueError):
            decrypt({"nonce": "", "ciphertext": ""}, short_key)

    def test_output_contains_only_nonce_and_ciphertext(self):
        """encrypt() output must have exactly the keys the spec defines."""
        key, _ = derive_key("password")
        result = encrypt(b"test", key)
        assert set(result.keys()) == {"nonce", "ciphertext"}
        zero_memory(key)

    def test_output_values_are_valid_base64(self):
        """All values in the encrypt output must be valid base64 strings."""
        key, _ = derive_key("password")
        result = encrypt(b"test", key)
        # These should not raise if the values are valid base64
        base64.b64decode(result["nonce"])
        base64.b64decode(result["ciphertext"])
        zero_memory(key)


# ---------------------------------------------------------------------------
# encrypt_item() + decrypt_item() tests (full pipeline)
# ---------------------------------------------------------------------------

class TestItemPipeline:
    """Tests for the full encrypt_item/decrypt_item convenience pipeline."""

    def test_round_trip_with_password(self):
        """encrypt_item → decrypt_item with the same password returns original data."""
        original = b"my-openai-key-sk-abcdefgh1234567890"

        payload = encrypt_item(original, "master_password")

        # Payload must have all three fields from the spec
        assert "salt" in payload
        assert "nonce" in payload
        assert "ciphertext" in payload

        decrypted = decrypt_item(payload, "master_password")
        assert bytes(decrypted) == original
        zero_memory(decrypted)

    def test_wrong_password_raises_error(self):
        """decrypt_item with wrong password must fail, never return wrong data."""
        payload = encrypt_item(b"secret", "right_password")

        with pytest.raises(InvalidTag):
            decrypt_item(payload, "wrong_password")

    def test_payload_matches_spec_format(self):
        """The returned payload must exactly match the storage format from GEMINI.md."""
        payload = encrypt_item(b"test", "password")

        # Must have exactly these three keys
        assert set(payload.keys()) == {"salt", "nonce", "ciphertext"}

        # All values must be valid base64 strings
        salt_bytes = base64.b64decode(payload["salt"])
        nonce_bytes = base64.b64decode(payload["nonce"])
        base64.b64decode(payload["ciphertext"])

        # Salt must be 16 bytes, nonce must be 12 bytes
        assert len(salt_bytes) == 16
        assert len(nonce_bytes) == 12

    def test_same_password_different_payloads(self):
        """Two calls with the same password and plaintext produce different payloads."""
        p1 = encrypt_item(b"same", "password")
        p2 = encrypt_item(b"same", "password")

        # Different salts → different derived keys → completely different output
        assert p1["salt"] != p2["salt"]
        assert p1["nonce"] != p2["nonce"]
        assert p1["ciphertext"] != p2["ciphertext"]
