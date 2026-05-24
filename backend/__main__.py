"""
Main entry point: starts both the REST API and WebSocket tunnel when run as a module.

Run with:
    python -m backend
"""

import asyncio
import os
import sys
from pathlib import Path

# Add root directory to sys.path so we can import 'backend'
# even when run in environments where the root is not in sys.path.
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

import uvicorn

# Run the SHA-256 self-integrity check on the primary entry point (run_server.py)
# before loading any backend security modules. This ensures both entry points
# (python -m backend AND python -m backend.run_server) verify the same file.
from backend.run_server import verify_integrity  # noqa: E402
verify_integrity()

from backend.core.crypto import AESGCMProvider as CryptoProvider  # noqa: F401, E402

# crypto_provider is the single shared instance — route handlers will receive
# it via FastAPI dependency injection (wired in backend/api/main.py).
crypto_provider = CryptoProvider()


async def main():
    """Starts both the REST API server and the WebSocket tunnel.

    Both servers run concurrently in the same event loop using asyncio.gather().
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

    # Start parent process monitor if launched by Electron
    parent_pid = os.environ.get("PARENT_PID")
    if parent_pid:
        asyncio.create_task(start_parent_monitor(int(parent_pid)))

    # Start the REST API on port 8765
    config = uvicorn.Config(
        "backend.api.main:app",
        host="127.0.0.1",   # Local only — never expose to network
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
