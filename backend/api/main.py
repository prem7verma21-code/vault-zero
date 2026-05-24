"""
Creates the FastAPI application instance and registers all route groups.

This is the central wiring file — it connects:
  - The FastAPI app
  - The slowapi rate limiter (shared with all route files)
  - All routers (auth now; vault and agent in later steps)
  - Global error handlers

Startup and shutdown lifecycle hooks are also here, so we can
zero all session keys from memory when the server stops.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from backend.api.routes.auth import router as auth_router
from backend.api.routes.vault import router as vault_router
from backend.api.routes.agent import router as agent_router
from backend.api.routes.agent import destroy_all_agent_secrets
from backend.core.security import destroy_all_sessions


# ---------------------------------------------------------------------------
# RATE LIMITER — shared instance used by all route files
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)


# ---------------------------------------------------------------------------
# LIFESPAN — startup and shutdown hooks
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Runs setup before the server starts and cleanup when it shuts down.

    On shutdown: zeros all active session keys from memory so no secrets
    linger in RAM after the process exits.
    """
    # Startup — nothing to do yet (database init will be added here later)
    yield
    # Shutdown — wipe all derived keys and agent secrets from memory
    destroy_all_sessions()
    destroy_all_agent_secrets()


# ---------------------------------------------------------------------------
# APP INSTANCE
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Vault-Zero API",
    description=(
        "Local-first encrypted credential vault for AI agents. "
        "Phase 1 — auth, vault CRUD, and agent key/permission API."
    ),
    version="0.1.0",
    # Disable docs in production; enable during development for manual testing
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Attach the rate limiter to the app so slowapi can intercept requests
app.state.limiter = limiter

# Return HTTP 429 when the rate limit is exceeded
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ---------------------------------------------------------------------------
# SECURITY HEADERS — applied to every HTTP response
# ---------------------------------------------------------------------------
# These defend against common web vulnerabilities even though Vault-Zero
# is localhost-only. Defense-in-depth: if any of these headers prevent even
# one attack vector, they are worth the single-digit microseconds of cost.

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Injects hardening headers into every response.

    X-Content-Type-Options: nosniff — prevents MIME-type confusion attacks.
    X-Frame-Options: DENY — prevents the API from being embedded in iframes.
    Cache-Control: no-store — ensures no response body is cached to disk.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------

# Auth endpoints: /api/v1/auth/unlock and /api/v1/auth/lock
app.include_router(auth_router, prefix="/api/v1")

# Vault CRUD endpoints: /api/v1/vault/items and /api/v1/vault/audit (Step 1.5)
app.include_router(vault_router, prefix="/api/v1")

# Agent endpoints: /api/v1/agent/register, /request_key, /request_permission (Step 1.6)
app.include_router(agent_router, prefix="/api/v1")


# ---------------------------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------------------------

@app.get("/health", tags=["system"], summary="Server health check")
async def health(request: Request) -> dict:
    """Returns 200 if the server is running. No auth required."""
    return {"status": "ok", "version": "0.1.0"}
