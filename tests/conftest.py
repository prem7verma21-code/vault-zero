import sys
from pathlib import Path

import pytest

# Add root directory to sys.path so pytest can locate 'backend' package
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))


# A fixed fingerprint used by every test unless a specific test overrides it.
# Real Argon2id input is `password + ":" + this_constant`, so test passwords
# stay deterministic and existing 76 tests keep passing without modification.
TEST_DEVICE_FINGERPRINT = "test-device-" + "0" * 52  # 64 chars to match real shape


@pytest.fixture(autouse=True)
def _stub_device_fingerprint(monkeypatch):
    """Pins the device fingerprint to a constant for every test.

    auth.py imports `get_device_fingerprint` directly with `from`, so we patch
    the binding in `backend.api.routes.auth` (where it's actually called),
    not the source module. Tests that need to simulate a different machine
    can call monkeypatch.setattr(...) again with their own value mid-test.
    """
    monkeypatch.setattr(
        "backend.api.routes.auth.get_device_fingerprint",
        lambda: TEST_DEVICE_FINGERPRINT,
    )
    # Also patch the source module so any other importer sees the stub.
    monkeypatch.setattr(
        "backend.core.device.get_device_fingerprint",
        lambda: TEST_DEVICE_FINGERPRINT,
    )
