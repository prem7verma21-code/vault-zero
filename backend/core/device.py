"""
Hardware fingerprint for device binding (Step 1.12).

Mixes a stable per-machine identifier into the Argon2id input at /unlock and
/setup so that copying the encrypted database to a different computer makes
the file cryptographically inert there — even if the master password is
correct. Recovery is the deliberate exit ramp: /recover rebinds to the new
machine.

Sources, in order of preference:
  Windows : HKLM\\SOFTWARE\\Microsoft\\Cryptography  →  MachineGuid
  macOS   : ioreg -d2 -c IOPlatformExpertDevice  →  IOPlatformUUID
  fallback: uuid.getnode() (the primary network-interface MAC)

The returned value is a SHA-256 hex digest of the raw source so the actual
hardware ID never leaves this module — useful when grepping logs or memory
dumps in a leaked-device scenario. The digest is 64 chars of hex.
"""

import hashlib
import logging
import platform
import re
import subprocess
import uuid

logger = logging.getLogger(__name__)


def _read_windows_machine_guid() -> str | None:
    """Reads HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid via winreg.

    Stable across reboots, user account changes, and many Windows reinstalls.
    Returns None on any error (registry missing, access denied, non-Windows).
    """
    try:
        import winreg  # stdlib on Windows; ImportError on other OSes
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            if isinstance(value, str) and value.strip():
                return value.strip()
    except Exception as exc:
        logger.warning("Could not read MachineGuid: %s", type(exc).__name__)
    return None


def _read_macos_platform_uuid() -> str | None:
    """Reads IOPlatformUUID via `ioreg`.

    Stable across reboots and macOS upgrades on the same Mac. Returns None on
    any error (non-macOS, ioreg missing, parse failure).
    """
    try:
        result = subprocess.run(
            ["ioreg", "-d2", "-c", "IOPlatformExpertDevice"],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', result.stdout)
        if match:
            return match.group(1).strip()
    except Exception as exc:
        logger.warning("Could not read IOPlatformUUID: %s", type(exc).__name__)
    return None


def _mac_address_fallback() -> str:
    """Returns the primary MAC address as hex.

    Used when neither the Windows registry nor macOS ioreg path yielded a
    value — for example, on Linux dev machines or in CI. uuid.getnode() will
    invent a random 48-bit value if no real interface is available; that's
    still better than nothing because it's stable for the lifetime of the
    Python process.
    """
    return f"{uuid.getnode():012x}"


def get_device_fingerprint() -> str:
    """Returns a stable 64-char hex SHA-256 of this machine's hardware ID.

    Priority: Windows MachineGuid → macOS IOPlatformUUID → MAC fallback.
    Tests monkeypatch this function (or _raw_device_id below) to a constant
    so they don't depend on the host machine's real fingerprint.
    """
    raw = _raw_device_id()
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _raw_device_id() -> str:
    """Returns the raw (non-hashed) device identifier string.

    Split out so tests can monkeypatch a single seam and exercise the same
    SHA-256 path production uses.
    """
    system = platform.system()
    if system == "Windows":
        guid = _read_windows_machine_guid()
        if guid:
            return f"win:{guid}"
    elif system == "Darwin":
        uuid_str = _read_macos_platform_uuid()
        if uuid_str:
            return f"mac:{uuid_str}"
    # Anything else (Linux dev box, CI, registry access denied, ioreg missing)
    return f"mac-fallback:{_mac_address_fallback()}"
