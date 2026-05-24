"""
Entry point: starts both the FastAPI REST API and the encrypted WebSocket tunnel.

The REST API (port 8765) handles user operations: unlock, lock, vault CRUD, agent
registration, and permission responses.

The WebSocket tunnel (port 47291) handles encrypted binary agent communication:
key requests, permission requests, and context queries.

Both servers run in the same Python process and share the same module-level state
(sessions, nonces, HMAC secrets). This is intentional — it avoids the complexity
of inter-process state synchronization while keeping the two protocols cleanly
separated on different ports.

Run with:
    python -m backend.run_server
    OR
    python backend/run_server.py
"""

import asyncio
import hashlib
import os
import sys
from pathlib import Path

# Add root directory to sys.path so we can import 'backend'
# even when run directly as `python run_server.py` from the backend directory.
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

import uvicorn


# ---------------------------------------------------------------------------
# SHA-256 SELF-INTEGRITY CHECK
# ---------------------------------------------------------------------------
# On first launch: computes SHA-256 of this file and stores it.
# On subsequent launches: recomputes and compares to the stored hash.
# If they differ, the binary may have been tampered with — refuse to start.
#
# Why this matters: if a malicious program replaces the vault binary on the
# user's machine with a modified version that exfiltrates keys, this check
# detects the change and aborts before any secrets are loaded into memory.

def _get_integrity_dir() -> Path:
    """Returns the directory where the integrity hash is stored.

    Same location as vault.db — the user's platform-specific app data folder.
    This keeps the integrity file out of the project folder and out of Git.
    """
    if os.name == "nt":
        base = os.environ.get("APPDATA")
        if not base:
            base = str(Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        home = os.environ.get("HOME", str(Path.home()))
        base = str(Path(home) / "Library" / "Application Support")
    else:
        home = os.environ.get("HOME", str(Path.home()))
        base = str(Path(home) / ".config")
    d = Path(base) / "Vault-Zero"
    d.mkdir(parents=True, exist_ok=True)
    return d


def verify_integrity() -> None:
    """Computes SHA-256 of this file and compares to the stored snapshot.

    First launch: creates the snapshot file — this is the trusted baseline.
    Subsequent launches: if the hash differs, the file was modified after the
    baseline was set. This is a tamper indicator. The server refuses to start.

    To reset the baseline (e.g. after a legitimate update), delete the
    .vault_integrity file from the AppData directory.
    """
    this_file = Path(__file__).resolve()
    integrity_file = _get_integrity_dir() / ".vault_integrity"

    # Compute SHA-256 of the current file contents
    sha256 = hashlib.sha256()
    with open(this_file, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    current_hash = sha256.hexdigest()

    if integrity_file.exists():
        stored_hash = integrity_file.read_text(encoding="utf-8").strip()
        if current_hash != stored_hash:
            print(
                "INTEGRITY CHECK FAILED — binary may be tampered.\n"
                f"Expected:  {stored_hash}\n"
                f"Got:       {current_hash}\n"
                f"File:      {this_file}\n"
                f"Baseline:  {integrity_file}\n"
                "\n"
                "If this is a legitimate update, delete the baseline file:\n"
                f"  del \"{integrity_file}\"\n"
                "Then restart.",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        # First launch — create the trusted baseline
        integrity_file.write_text(current_hash, encoding="utf-8")
        print(f"Integrity baseline created: {integrity_file}")


# Run the integrity check before importing any backend modules.
# This ensures tampered code never loads into memory.
verify_integrity()


# The concrete provider (AES-256-GCM + Argon2id) — swap this class to change
# the entire crypto backend without touching any other file.
from backend.core.crypto import AESGCMProvider as CryptoProvider  # noqa: F401, E402

# crypto_provider is the single shared instance — route handlers will receive
# it via FastAPI dependency injection (wired in backend/api/main.py).
crypto_provider = CryptoProvider()


async def main():
    """Starts both the REST API and WebSocket tunnel servers together.

    Both servers share the same asyncio event loop and the same module-level
    Python state. They run concurrently using asyncio.gather() to prevent
    blocking and ensure both are fully operational.
    """
    import logging
    import sys

    # Configure the backend logger to write to stdout so we can see when
    # the WebSocket tunnel starts. Uvicorn has its own logging configuration
    # but doesn't print standard library logger messages unless configured.
    backend_logger = logging.getLogger("backend")
    backend_logger.setLevel(logging.INFO)
    if not backend_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(levelname)s:     %(message)s"))
        backend_logger.addHandler(handler)

    from backend.tunnel.ws_handler import start_tunnel_server, start_parent_monitor

    # Start parent process monitor if launched by Electron.
    # Electron's main.js sets PARENT_PID to its own process ID when spawning
    # the Python backend. If Electron dies, this monitor zeros all keys and exits.
    parent_pid = os.environ.get("PARENT_PID")
    if parent_pid:
        asyncio.create_task(start_parent_monitor(int(parent_pid)))

    # Configure the REST API server on port 8765.
    # Using uvicorn.Server with an async serve() call in asyncio.gather()
    # ensures that both protocols coexist cleanly in the same event loop.
    config = uvicorn.Config(
        "backend.api.main:app",
        host="127.0.0.1",   # Local only — never expose to network (Layer 3)
        port=8765,
        reload=False,        # No auto-reload in production
        log_level="info",
    )
    server = uvicorn.Server(config)

    tunnel = None

    async def run_tunnel():
        nonlocal tunnel
        # Start the binary WebSocket tunnel on port 47291
        tunnel = await start_tunnel_server()
        try:
            # Keep the tunnel task alive until cancelled
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            # Clean shutdown: close the tunnel when this task is cancelled
            if tunnel:
                tunnel.close()
                await tunnel.wait_closed()

    try:
        # Gather both servers to run concurrently in the same asyncio event loop
        await asyncio.gather(
            server.serve(),
            run_tunnel(),
        )
    except Exception as exc:
        # Ensure cleanup if an error occurs during startup
        if tunnel:
            tunnel.close()
            await tunnel.wait_closed()
        raise exc


if __name__ == "__main__":
    asyncio.run(main())
