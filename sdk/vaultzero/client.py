import requests
import os

VAULT_URL = os.getenv("VAULT_URL", "http://127.0.0.1:8765")

class VaultZeroClient:
    def __init__(self, vzk_key: str = None):
        self.vzk_key = vzk_key or os.getenv("VZK_KEY", "")
        if not self.vzk_key:
            raise ValueError("No VZK_KEY found.")

    def get(self, label: str, fallback: str = None) -> str:
        try:
            response = requests.post(
                f"{VAULT_URL}/api/v1/agent/request_key",
                json={"label": label},
                headers={"Authorization": f"Bearer {self.vzk_key}"},
                timeout=5
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
        except Exception as e:
            if fallback is not None:
                return fallback
            raise

# Module-level convenience — works like os.getenv
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
