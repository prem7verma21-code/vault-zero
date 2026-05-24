# Vault-Zero

**A local-first encrypted vault that lets AI agents use your API keys without you ever pasting them into a chat window.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS-lightgrey.svg)]()

---

## The Problem

AI agents need credentials to act — booking flights, calling APIs, pushing code. Today, the only way to give an agent a key is to paste it into a chat window or hard-code it into a script. Neither approach is auditable, revocable, or safe. One leaked conversation and your keys are exposed.

Vault-Zero solves this by keeping your secrets on your machine, encrypted, and giving agents a controlled, time-limited, auditable way to request them — without ever seeing your master password or the raw database.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                        YOUR MACHINE                             │
│                                                                 │
│   ┌──────────────┐   encrypted    ┌─────────────────────────┐  │
│   │   Electron   │◄──WebSocket───►│   Python Backend        │  │
│   │   Frontend   │   (MsgPack +   │   FastAPI + SQLCipher   │  │
│   │   (UI only)  │   AES-256-GCM) │   AES-256-GCM + Argon2  │  │
│   └──────────────┘                └────────────┬────────────┘  │
│                                                │               │
│                                    ┌───────────▼────────────┐  │
│                                    │   vault.db (SQLCipher) │  │
│                                    │   double-encrypted     │  │
│                                    └────────────────────────┘  │
│                                                │               │
│                              ┌─────────────────▼────────────┐  │
│                              │   AI Agent (local process)   │  │
│                              │   requests keys via          │  │
│                              │   capability card token      │  │
│                              └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

- **Secrets never leave your device.** AES-256-GCM encryption at the application layer, stored inside a SQLCipher-encrypted database file.
- **Agents get scoped, time-limited access.** A capability card grants an agent access to specific named secrets for a defined window. Nothing more.
- **You stay in control.** Every agent action is logged. Sensitive operations require your real-time approval via a permission dialog.

---

## Quick Start

### Prerequisites

- Python 3.12+
- Node.js 18+
- Windows or macOS

### Install

```bash
git clone https://github.com/prem7verma21-code/vault-zero
cd vault-zero

# Backend dependencies
pip install -r requirements.txt

# Frontend dependencies
cd frontend && npm install && cd ..
```

### Run

```bash
# Terminal 1 — start the backend
cd backend && python run_server.py

# Terminal 2 — start the Electron UI
cd frontend && npm start
```

The Electron window opens. Set your master password on first launch. The backend API is available at `http://127.0.0.1:8765` — Swagger docs at `/docs`.

### Run Tests

```bash
python -m pytest tests/
```

---

## Agent SDK Usage

Any script or AI agent can request secrets from a running Vault-Zero instance using a capability card token (`vzk_...`).

### 1. Register an agent (in the UI)

Open Vault-Zero → Agents → New Agent. Select which secrets the agent may access and set an expiry. You receive a one-time Agent Token (`vzk_...`).

### 2. Request a key (from your script)

Install the SDK:

```bash
pip install vault-zero-sdk
```

Request a key in 3 lines:

```python
from vaultzero import get

GROQ_KEY = get("GROQ_API_KEY")
```

The SDK reads your token from the `VZK_KEY` environment variable and handles authentication automatically.

**Manual REST integration (without the SDK):**

```http
POST http://127.0.0.1:8765/api/v1/agent/request_key
Authorization: Bearer vzk_your_token_here
Content-Type: application/json

{"label": "GROQ_API_KEY"}
```

### 3. Request user permission before a sensitive action

```python
import requests, uuid, time

def request_permission(action_description: str) -> bool:
    request_id = str(uuid.uuid4())

    requests.post(
        f"{VAULT_URL}/api/v1/agent/request_permission",
        headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
        json={"action": action_description, "request_id": request_id}
    )

    # Poll for user response (up to 60 seconds)
    for _ in range(60):
        time.sleep(1)
        status = requests.get(
            f"{VAULT_URL}/api/v1/agent/permission_status/{request_id}",
            headers={"Authorization": f"Bearer {AGENT_TOKEN}"}
        ).json()["status"]

        if status == "approved":
            return True
        if status in ("denied", "expired"):
            return False

    return False

# Usage
if request_permission("Send email to team@company.com"):
    send_email(...)
```

---

## Security Model

| What is protected | How |
|---|---|
| Secrets at rest | AES-256-GCM (app layer) inside SQLCipher (file layer) |
| Master password | Never stored — used once to derive key via Argon2id, then zeroed from memory |
| Agent access | Scoped capability cards with expiry and HMAC request signing |
| Replay attacks | Per-request nonce tracking; duplicate nonces rejected |
| Audit trail | Every agent action logged (labels only, never secret values) |
| Network exposure | API and WebSocket bind to 127.0.0.1 only |

**What Vault-Zero does not protect against:**
- An attacker with physical access to your unlocked machine
- A compromised OS kernel
- Malware running as the same user with equivalent process privileges

See [SECURITY.md](SECURITY.md) for the full security model and vulnerability reporting policy.

---

## Architecture

```
backend/
├── core/
│   ├── crypto_interface.py   abstract crypto contract (pluggable provider)
│   ├── crypto.py             AES-256-GCM + Argon2id implementation
│   └── security.py           JWT session token generation
├─ tunnel/
│   └── ws_handler.py         binary WebSocket tunnel (MsgPack + AES-256-GCM)
├── api/
│   ├── main.py               FastAPI app instance
│   └── routes/
│       ├── auth.py           unlock / lock endpoints
│       ├── vault.py          CRUD for stored secrets
│       └── agent.py          capability cards, key requests, permissions
├── database/
│   └── models.py             SQLCipher schema
└── run_server.py             starts FastAPI (port 8765) + WebSocket (port 47291)

frontend/
├── main.js                   Electron lifecycle, spawns Python backend
├── preload.js                contextBridge IPC — only bridge to renderer
└── src/
    ├── index.html            UI shell
    ├── renderer.js           UI logic (no Node.js access)
    └── style.css             Gerish Black design system
```

The frontend and backend share no memory. The only connection between them is an encrypted binary WebSocket tunnel. Breaking into the Electron shell does not expose the crypto core.

---

## D-Auth Protocol

Vault-Zero implements the D-Auth protocol — a draft specification for scoped, time-limited, user-auditable AI agent authorization. See [PROTOCOL.md](PROTOCOL.md) for the full specification.

D-Auth is designed to be compatible with OAuth 2.0 and the W3C Verifiable Credentials data model. Feedback and integration proposals are welcome via GitHub Issues.

---

## Contributing

Contributions are welcome. Please open an issue before submitting a pull request for significant changes.

Security vulnerabilities must be reported privately — see [SECURITY.md](SECURITY.md).

For protocol feedback and D-Auth integration proposals, open a GitHub Issue tagged `protocol`.

---

## License

MIT License — see [LICENSE](LICENSE).

---

## Author

**Prem Verma**
JEE Aspirant & Independent Developer, India
GitHub: [github.com/prem7verma21-code](https://github.com/prem7verma21-code)
Email: dotdev@zohomail.com
X: [@premverma_dev](https://x.com/premverma_dev)

---

*Vault-Zero and the D-Auth Protocol are original works by Prem Verma, first published May 24, 2026.*
