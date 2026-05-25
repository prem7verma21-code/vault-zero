# Vault-Zero — Claude Code Context

## Project Overview

**DotID / Vault-Zero** — A local-first desktop app (Windows + macOS) that:
1. Stores API keys and secrets encrypted on the user's machine
2. Lets AI agents request those keys via a local API — user never pastes secrets into chat
3. Shows the user every action the agent takes, with approve/deny control
4. Long-term goal: become the standard authorization protocol for AI agents (DotID Gateway)

**Current phase:** Phase 1 — Local vault only. Nothing cloud. Nothing agentic yet.

**User:** Master Prem — secondary school student, JEE exam January 2027. Does not know Python yet. He is the architect; Claude is the engineer. Respect his decisions, do not simplify the vision. Write plain-English comments above every function.

---

## Tech Stack — DO NOT CHANGE WITHOUT ASKING

| Layer | Choice | Reason |
|---|---|---|
| Backend | Python 3.12+ with FastAPI (async) | Cryptography library ecosystem |
| Encryption | AES-256-GCM + Argon2id | Industry standard, proven |
| Crypto library | `cryptography` (Python) | Never roll your own |
| Database | SQLCipher (sqlcipher3) | SQLite + AES encryption at file level |
| Desktop wrapper | Electron (Node.js) | Cross-platform, frontend only |
| IPC protocol | Binary WebSocket + MsgPack | Silent network profile |
| Compiler | Nuitka | Native binary, no readable bytecode |
| Sensitive value type | `bytearray` not `bytes` | Memory can be explicitly zeroed |

---

## Phase 1 Status

- [x] Step 1.1 — Directory Structure & Project Setup
- [x] Step 1.2 — Crypto Core (crypto_interface.py + crypto.py) — 25/25 tests pass
- [x] Step 1.3 — Encrypted Database (models.py)
- [x] Step 1.4 — Auth Endpoints (auth.py) — unlock + lock live-tested
- [x] Step 1.5 — Vault CRUD Endpoints (vault.py) — 8/8 tests pass
- [x] Step 1.6 — Agent API Endpoints (agent.py) — 13/13 tests pass
- [x] Step 1.7 — Binary WebSocket Tunnel (ws_handler.py) — 5/5 tests pass
- [x] Step 1.8 — Electron Frontend (main.js + UI)
- [x] Step 1.9 — Security Hardening — 55/55 tests pass
- [ ] Step 1.10 — Open Source Launch Prep
- [x] Step 1.11 — Agent Management UI — 60/60 tests pass
- [ ] Step 1.12 — Device Trust / Hardware Binding
- [ ] Step 1.13 — Secret Reveal (30-second auto-hide)

**Next steps:** 1.10 (launch docs), 1.12 (hardware binding), 1.13 (secret reveal)

---

## Security Rules — NON-NEGOTIABLE

1. Master password → never stored anywhere, ever
2. Derived key → memory only, zeroed on app close with `ctypes.memset`
3. Decrypted secrets → passed in memory to agent, never written to disk
4. Audit log → labels only, never secret values
5. Electron: `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true` — permanent
6. Every endpoint: 60 req/min rate limit via `slowapi`
7. All secret values: AES-256-GCM encrypted at application layer BEFORE SQLCipher stores them
8. Never roll your own cryptography — use `cryptography` library only
9. API and WebSocket bind to 127.0.0.1 only — never 0.0.0.0

---

## Crypto Spec — EXACT PARAMETERS, NO DEVIATION

```python
# Key derivation
Argon2id(salt=16_random_bytes, length=32, iterations=3, lanes=4, memory_size=65536)

# Encryption
AESGCM(key).encrypt(nonce=os.urandom(12), data=plaintext, aad=None)

# Storage format per item
{"salt": b64, "nonce": b64, "ciphertext": b64}  # ciphertext includes GCM tag
```

---

## Database Schema — EXACT, DO NOT MODIFY

```sql
vault_items     (id TEXT PK, category TEXT, label TEXT, encrypted_payload BLOB, created_at INT, last_accessed INT)
capability_cards(id TEXT PK, agent_id TEXT, permissions TEXT/JSON, valid_until INT, created_at INT)
audit_log       (id INT PK AUTOINCREMENT, timestamp INT, agent_id TEXT, action TEXT, result TEXT, label_accessed TEXT)
```

---

## Directory Structure

```
Vault-Zero/
├── .gemini/               ← original Gemini AI context files (do not modify)
├── .claude/               ← Claude Code artifacts and memory
├── backend/
│   ├── core/              crypto_interface.py, crypto.py, security.py
│   ├── tunnel/            ws_handler.py (binary WebSocket, port 47291)
│   ├── api/               main.py + routes/ (auth.py, vault.py, agent.py)
│   ├── database/          models.py (SQLCipher schema)
│   └── run_server.py      entry point: FastAPI on 8765 + WebSocket on 47291
├── frontend/
│   ├── main.js            Electron lifecycle + spawns Python backend
│   ├── preload.js         contextBridge IPC (ONLY bridge to renderer)
│   └── src/               index.html, renderer.js, style.css
├── tests/
├── requirements.txt
└── README.md
```

---

## UI Design — EXACT VALUES

```css
--bg:        #0A0A0A;
--text:      #E8E8E8;
--accent:    #4ADE80;
--danger:    #F87171;
--dim:       #6B7280;
--border:    #2A2A2A;
--code-bg:   #111111;
--font-ui:   'Inter', system-ui, sans-serif;
--font-mono: 'JetBrains Mono', monospace;
--transition: 150ms ease;
/* No shadows. No gradients. Only borders and spacing. */
```

5 screens: Unlock · Vault Dashboard · Add Item · Permission Dialog · Audit Log

---

## Model Selection Guide

| Task | Model |
|---|---|
| crypto.py, ws_handler.py, agent.py, any security review | Claude Opus 4.7 Thinking |
| All other backend Python, tests, debugging | Claude Sonnet 4.6 Thinking |
| Frontend, CSS, boilerplate, docs | Gemini 3.5 Flash High |

---

## Key API Endpoints

```
POST /api/v1/auth/unlock          → derives key, creates session, returns JWT
POST /api/v1/auth/lock            → zeros key from memory, invalidates session
GET  /api/v1/vault/items          → labels only, NEVER decrypted values
POST /api/v1/vault/items          → encrypts and stores a new secret
DEL  /api/v1/vault/items/{id}     → deletes an item
GET  /api/v1/vault/audit          → last 100 audit entries, newest first
POST /api/v1/agent/register       → creates capability card for an agent
POST /api/v1/agent/request_key    → agent requests a decrypted secret (403 on any failure)
POST /api/v1/agent/request_permission → agent asks user for permission
GET  /api/v1/agent/permission_status/{id} → agent polls for user response
POST /api/v1/user/respond_permission → user approves or denies agent request
```

---

## Running the Project

```bash
# Backend
cd backend && python run_server.py
# Swagger UI: http://127.0.0.1:8765/docs

# Frontend
cd frontend && npm install && npm start

# Tests
python -m pytest tests/
```

---

## Artifacts

All Claude Code artifacts (plans, notes, outputs) are saved in `C:\Vault-Zero\.claude\`.
