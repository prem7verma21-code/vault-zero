"""
Vault-Zero Python SDK — request encrypted secrets from a locally-running vault.

Auth model: a single bearer token (VZK_KEY), same as OpenAI / Anthropic / Groq.
Each request also carries a fresh UUID4 nonce and Unix timestamp so the vault
can reject replayed requests; the agent doesn't need a separate signing secret.

Required environment variable:
  VZK_KEY  — the vault_api_key returned at registration (starts with "vzk_")
"""

import os
import time
import uuid

import requests

VAULT_URL = os.getenv("VAULT_URL", "http://127.0.0.1:8765")


class VaultZeroClient:
    def __init__(self, vzk_key: str = None):
        self.vzk_key = vzk_key or os.getenv("VZK_KEY", "")
        if not self.vzk_key:
            raise ValueError("No VZK_KEY found.")

    def get(self, label: str, fallback: str = None) -> str:
        # Fresh nonce + timestamp per request — replay protection without a second secret.
        nonce = str(uuid.uuid4())
        timestamp = int(time.time())

        try:
            response = requests.post(
                f"{VAULT_URL}/api/v1/agent/request_key",
                json={
                    "label": label,
                    "nonce": nonce,
                    "timestamp": timestamp,
                },
                headers={"Authorization": f"Bearer {self.vzk_key}"},
                timeout=5,
            )
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 401:
                raise PermissionError("Invalid VZK key")
            elif response.status_code == 403:
                raise PermissionError(f"Access denied to '{label}'")
            else:
                raise ConnectionError(f"Vault returned {response.status_code}")
        except requests.exceptions.ConnectionError:
            if fallback is not None:
                return fallback
            raise ConnectionError("Vault-Zero is not running")
        except Exception:
            if fallback is not None:
                return fallback
            raise


_default_client = None


def _get_client() -> VaultZeroClient:
    global _default_client
    if _default_client is None:
        _default_client = VaultZeroClient()
    return _default_client


def get(label: str, fallback: str = None) -> str:
    """
    Get a secret from Vault-Zero.
    Usage: from vaultzero import get
           MY_KEY = get("MY_KEY")
    """
    return _get_client().get(label, fallback)
