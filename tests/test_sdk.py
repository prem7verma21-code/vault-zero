import sys
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch
import requests

# Ensure sdk directory is in sys.path
sdk_path = str(Path(__file__).resolve().parent.parent / "sdk")
if sdk_path not in sys.path:
    sys.path.insert(0, sdk_path)

from vaultzero.client import VaultZeroClient, get


class TestVaultZeroClientInit:
    def test_init_with_explicit_key(self):
        client = VaultZeroClient(vzk_key="vzk_test_123")
        assert client.vzk_key == "vzk_test_123"

    def test_init_with_env_var(self, monkeypatch):
        monkeypatch.setenv("VZK_KEY", "vzk_env_456")
        client = VaultZeroClient()
        assert client.vzk_key == "vzk_env_456"

    def test_init_raises_value_error_when_no_key(self, monkeypatch):
        monkeypatch.delenv("VZK_KEY", raising=False)
        with pytest.raises(ValueError, match="No VZK_KEY found."):
            VaultZeroClient()


class TestVaultZeroClientGet:
    @patch("requests.post")
    def test_get_success_200(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"value": "secret_val"}
        mock_post.return_value = mock_response

        client = VaultZeroClient(vzk_key="vzk_test")
        result = client.get("MY_LABEL")

        assert result == "secret_val"
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert kwargs["json"]["label"] == "MY_LABEL"
        assert kwargs["headers"]["Authorization"] == "Bearer vzk_test"

    @patch("requests.post")
    def test_get_http_401_raises_permission_error(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response

        client = VaultZeroClient(vzk_key="vzk_test")
        with pytest.raises(PermissionError, match="Invalid VZK key"):
            client.get("MY_LABEL")

    @patch("requests.post")
    def test_get_http_403_raises_permission_error(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_post.return_value = mock_response

        client = VaultZeroClient(vzk_key="vzk_test")
        with pytest.raises(PermissionError, match="Access denied to 'MY_LABEL'"):
            client.get("MY_LABEL")

    @patch("requests.post")
    def test_get_other_status_code_raises_connection_error(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        client = VaultZeroClient(vzk_key="vzk_test")
        with pytest.raises(ConnectionError, match="Vault returned 500"):
            client.get("MY_LABEL")

    @patch("requests.post")
    def test_get_connection_error_with_fallback(self, mock_post):
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection refused")

        client = VaultZeroClient(vzk_key="vzk_test")
        result = client.get("MY_LABEL", fallback="fallback_value")

        assert result == "fallback_value"

    @patch("requests.post")
    def test_get_connection_error_without_fallback_raises(self, mock_post):
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection refused")

        client = VaultZeroClient(vzk_key="vzk_test")
        with pytest.raises(ConnectionError, match="Vault-Zero is not running"):
            client.get("MY_LABEL")

    @patch("requests.post")
    def test_get_generic_exception_with_fallback(self, mock_post):
        mock_post.side_effect = requests.exceptions.Timeout("Timed out")

        client = VaultZeroClient(vzk_key="vzk_test")
        result = client.get("MY_LABEL", fallback="fallback_value")

        assert result == "fallback_value"

    @patch("requests.post")
    def test_get_generic_exception_without_fallback_raises(self, mock_post):
        mock_post.side_effect = requests.exceptions.Timeout("Timed out")

        client = VaultZeroClient(vzk_key="vzk_test")
        with pytest.raises(requests.exceptions.Timeout):
            client.get("MY_LABEL")


class TestModuleGetHelper:
    @patch("vaultzero.client.VaultZeroClient")
    def test_module_get_function(self, mock_client_cls, monkeypatch):
        mock_instance = MagicMock()
        mock_instance.get.return_value = "helper_secret"
        mock_client_cls.return_value = mock_instance

        monkeypatch.setattr("vaultzero.client._default_client", None)

        result = get("TEST_KEY", fallback="fb")

        assert result == "helper_secret"
        mock_client_cls.assert_called_once()
        mock_instance.get.assert_called_once_with("TEST_KEY", "fb")
