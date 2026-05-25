# DotID & Vault-Zero: Master Doctrine V2
### The Enhanced, Legal, Technical & Market-Accurate Roadmap
*Compiled for Master Prem — Honest Engineering Over Hype*

---

## PREFACE: THE LEGAL PHASE 2 ARCHITECTURE

Before the roadmap, here is the definitive answer to Phase 2's legal problem.

### Why Your Original Phase 2 Was Risky
"Reverse-engineering private APIs to bypass frontends" violates:
- The **Computer Fraud and Abuse Act (CFAA)** in the US
- **India's IT Act Section 66** (unauthorized access)
- Every major website's **Terms of Service**
- The **EU's Computer Misuse directives**

The Scrapling/Dexter approach works technically. It fails legally the moment you ship it to other users or monetize it.

### The Legal Replacement: The "Authorized User Agent" Doctrine

**The Core Legal Principle:** A software tool acting *on behalf of a user who explicitly consents* is legally treated as *that user's personal assistant*, not an unauthorized intruder. This is the same legal basis on which Zapier, IFTTT, Notion AI, and every browser extension operates.

You are not scraping the web. You are building a **personal automation tool** that executes what the user would have done manually. The user is the authorized party. Your software is the tool they chose.

**This flips the entire legal model:**

| Original (Illegal) | New (Legal) |
|---|---|
| You reverse-engineer APIs | User connects their accounts via OAuth |
| You bypass bot detection | Playwright runs a real browser session as the user |
| Your server holds the credentials | User's Vault-Zero holds their credentials locally |
| You scrape and store data | Agent acts, then discards data it doesn't need |
| You violate their ToS | User agrees to third-party ToS themselves |

### The Three Legal Pillars for Phase 2

**Pillar 1: Playwright (User-Consented Browser Automation)**
Microsoft's open-source browser automation library. It controls a real Chrome/Firefox browser. When the user's credentials are passed from Vault-Zero to Playwright, the browser session is indistinguishable from the user sitting at their desk — because legally, it IS the user. Fully legal in all jurisdictions when the user has consented.

**Pillar 2: OAuth 2.0 Authorization Code Flow**
For every platform that has an official API (Google, GitHub, Notion, Stripe, OpenAI, Reddit, Spotify, Twitter/X), you implement proper OAuth. The user clicks "Connect [Platform] to DotID," grants permission, and you receive a scoped access token. No scraping. No ToS violation. No risk.

**Pillar 3: Browser Extension (The Nuclear Legal Option)**
A Chrome/Firefox extension that runs *inside* the user's browser, with their full knowledge and consent. It reads page data and executes actions in-browser. Courts have consistently ruled this is legally equivalent to the user doing it themselves. This is how LastPass, Grammarly, and Honey work.

**What to Avoid Completely:**
- CAPTCHA solving services (legally gray, ethically questionable)
- Storing scraped data in a database for commercial use
- Running automation without a live user who has actively consented
- Claiming your server is a "user" to access rate-limited APIs

---

## PHASE 0: THE FOUNDATION
### Duration: 3 Months (Before Writing a Single Line of Product Code)
### Market Deadline: Must complete before Month 4 — the market won't wait for unprepared builders

This phase is not optional. It is the difference between building on rock and building on sand. Every week you skip here costs you a month in Phase 1.

---

### 0.1 — What You Must Know Before Starting

**Priority 1 (Week 1–4): Python Mastery**
You need to be genuinely comfortable, not just familiar.
- Study: `async/await`, `dataclasses`, `type hints`, `context managers`, `subprocess`
- Resource: "Python Docs" + build 3 small CLI tools from scratch
- Test yourself: Can you write an async FastAPI endpoint from memory? If not, keep going.

**Priority 2 (Week 2–6): Cryptography (Not Just Using Libraries)**
You will be responsible for other people's most sensitive data. You must understand what you're doing, not just copy-paste code.
- Study: **Symmetric encryption** (AES-256-GCM — what GCM mode means and why it matters)
- Study: **Key derivation** (Argon2id — understand why it's memory-hard, not just that it is)
- Study: **Asymmetric cryptography** (RSA and ECDSA — understand public/private key pairs at a conceptual level)
- Study: **Zero-Knowledge Proofs** (conceptual level — read the ZKP Wikipedia page, then the Zcash explainer)
- Resource: `cryptography` Python library official docs. Read every page.
- **Hard Rule: Never implement your own cryptographic algorithm. Ever. Use proven libraries only.**

**Priority 3 (Week 3–8): OAuth 2.0 and OpenID Connect**
This is the backbone of your legal Phase 2 and your Phase 3 D-Auth protocol.
- Study: OAuth 2.0 RFC 6749 (the actual spec — read it once, slowly)
- Study: Authorization Code Flow with PKCE (this is what you'll implement)
- Study: JWT (JSON Web Tokens) — structure, signing, verification
- Study: OpenID Connect on top of OAuth 2.0
- Resource: `oauth.net/2/` — start here. Then `openid.net/connect/`
- Test yourself: Can you explain what a `refresh_token` is and why it exists?

**Priority 4 (Week 4–10): Model Context Protocol (MCP)**
This is non-negotiable. Anthropic's MCP is the closest existing standard to what you're building. You must know it deeply to know where DotID is different and better.
- Study: `modelcontextprotocol.io` — read the entire spec
- Study: How MCP Servers expose tools and resources
- Study: How MCP handles authorization (it currently doesn't solve local vault authorization — this is your gap)
- Action: Build a simple MCP server that serves one dummy tool. Just to prove you understand it.

**Priority 5 (Week 6–12): Standards You Must Know**
- **W3C Verifiable Credentials** (`w3.org/TR/vc-data-model`) — the formal spec for the "cryptographic identity" you're building toward
- **W3C DID (Decentralized Identifiers)** (`w3.org/TR/did-core`) — the spec your DotID UUID strategy aligns with
- **WebAuthn / FIDO2** — how hardware-backed authentication works (relevant for your Phase 4 hardware tethering)
- **WebSocket RFC 6455** — read it. You're building on WebSockets; understand the protocol.

**Priority 6 (Week 8–12): Competitor Deep-Dives**
Read, use, and analyze each of these. Not to copy them. To find their gaps.
- **World ID / World App** — their ZK proof of humanity approach
- **Anthropic MCP** — current agent authorization standard
- **Passage by 1Password** — passkey-based auth
- **Privy.io** — wallet-as-identity for web3
- **Auth0** — understand the established IdP model you're competing with
- Write a 1-page gap analysis for each: What do they not solve that Vault-Zero does?

---

### 0.2 — Dangers in Phase 0

**Danger: Starting to build before finishing studying**
Countermeasure: Set a hard date. No product code until Month 3. Studying IS building.

**Danger: Getting lost in theory and never shipping**
Countermeasure: Build small proofs-of-concept during study (an MCP server, a crypto test script). These are learning, not product.

**Danger: Underestimating school workload**
Countermeasure: Be honest with yourself. If you have exams, protect that time. The market won't disappear in 3 months. Your school performance affects your long-term credibility.

---

## PHASE 1: VAULT-ZERO CORE
### Duration: Months 3–10 (7 months)
### Market Deadline: Must have a working beta by Month 10 — MCP ecosystem adoption is accelerating and you need early users before the ecosystem standardizes without you

---

### 1.1 — What to Study Before Starting Phase 1

- **FastAPI** official docs — complete tutorial, especially dependency injection and middleware
- **SQLCipher** (not regular SQLite) — this is SQLite with AES-256 encryption. Regular SQLite stores data in plain text. You need SQLCipher.
- **PyWebView** docs — understand the security model and how it differs from Electron
- **Python `keyring` library** — for OS-level secure credential storage (macOS Keychain, Windows Credential Manager)
- **Electron security checklist** — `electronjs.org/docs/tutorial/security` — read all 20 points before writing a line of Electron code
- **`msgpack` Python library** — for binary serialization
- **`websockets` Python library** — for the binary tunnel

---

### 1.2 — Step-by-Step Build Plan

#### Step 1.1 — Crypto Core (Month 3, Week 1–2)
**File:** `backend/core/crypto.py`

What to build:
```
- derive_key(password: str, salt: bytes) -> bytes
  Uses Argon2id with: time_cost=3, memory_cost=65536, parallelism=4
  
- encrypt(plaintext: bytes, key: bytes) -> dict
  Uses AES-256-GCM, returns {ciphertext, nonce, tag}
  
- decrypt(ciphertext: bytes, nonce: bytes, tag: bytes, key: bytes) -> bytes
  Raises CryptoError on any failure — never returns partial data
  
- generate_vault_id() -> str
  UUID v4 — this is the user's DotID
```

**Critical rule:** The `key` (derived from master password) must ONLY exist in memory during an active session. When the app closes, it is zeroed from memory using `secrets.token_bytes` overwriting. Python's garbage collector is not sufficient — you must explicitly zero sensitive variables.

**Test:** Write unit tests for encrypt → decrypt round-trip. Write a test that verifies a wrong key raises an error. Do not proceed until these pass.

#### Step 1.2 — Encrypted Database (Month 3, Week 3–4)
**File:** `backend/database/models.py`

Use `sqlcipher3` Python bindings (not `sqlite3`). The database file is encrypted at rest with the derived key.

Schema:
```sql
CREATE TABLE vault_items (
    id TEXT PRIMARY KEY,          -- UUID v4
    category TEXT NOT NULL,       -- 'api_key', 'password', 'capability_card', 'memory'
    label TEXT NOT NULL,          -- human-readable name
    encrypted_payload BLOB NOT NULL, -- AES-256-GCM encrypted JSON
    created_at INTEGER NOT NULL,  -- Unix timestamp
    last_accessed INTEGER         -- for audit log
);

CREATE TABLE capability_cards (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,       -- which agent this card is for
    permissions JSON NOT NULL,    -- {"can_spend": true, "spend_limit": 10.00, "domains": [...]}
    valid_until INTEGER,          -- Unix timestamp expiry
    created_at INTEGER NOT NULL
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    agent_id TEXT,
    action TEXT NOT NULL,         -- what was requested
    result TEXT NOT NULL,         -- 'approved', 'denied', 'user_confirmed'
    key_accessed TEXT             -- which vault item was accessed (label only, not value)
);
```

#### Step 1.3 — FastAPI Backend (Month 4–5)
**File:** `backend/api/main.py` and `backend/api/routes/`

**Routes to build (in order):**

`POST /api/v1/auth/unlock`
- Accepts master password
- Derives key with Argon2id
- Opens encrypted database
- Returns session token (short-lived JWT, 1 hour, signed with a session-only key)
- Does NOT return the derived key — ever

`POST /api/v1/auth/lock`
- Zeros the derived key from memory
- Invalidates session token
- Closes database connection

`GET /api/v1/vault/items`
- Requires valid session token
- Returns list of vault items (labels and categories only — never decrypted values)

`POST /api/v1/vault/items`
- Adds a new encrypted vault item

`POST /api/v1/agent/request_key`
- **This is the most critical endpoint**
- Agent presents its `agent_token` (from capability card) and requests a specific key by label
- Vault checks: Does this agent have a valid capability card? Does the card permit access to this key?
- If yes: decrypts the key into memory, passes it to agent, does NOT write to disk
- Logs the access in `audit_log`

`POST /api/v1/agent/request_permission`
- Agent requests permission for a sensitive action (spend money, send email, delete data)
- Vault pauses, shows user a confirmation dialog in the UI
- Returns `approved` or `denied` based on user response
- Logs the decision

`GET /api/v1/memory/context`
- Returns the user's preference data and persistent memory as structured JSON for agent context injection

**Security rules for every endpoint:**
- Every endpoint except `/auth/unlock` requires a valid session JWT
- Rate limiting: max 60 requests/minute per session
- All responses include `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY`
- No endpoint ever logs a decrypted secret value — only labels

#### Step 1.4 — Binary WebSocket Tunnel (Month 5)
**File:** `backend/tunnel/ws_handler.py`

Replace the REST endpoints for agent communication with a single persistent WebSocket connection. This is the "Silent Network Profile."

```
Protocol:
1. Agent connects to ws://localhost:47291/agent
2. Handshake: Agent sends {agent_token: "...", nonce: "..."} as MsgPack binary
3. Vault verifies token, responds with session_key encrypted challenge
4. All subsequent messages are MsgPack-serialized, then AES-256-GCM encrypted
5. Message format: {msg_id: uuid, type: "key_request|permission_request|context_request", payload: {...}}

Process Pinning:
- Backend records the PID of the frontend process at startup
- Every 5 seconds, checks if that PID still exists and is not being traced (ptrace check on Linux/Mac)
- If debugger detected: zero all in-memory keys, close database, exit process
```

Why MsgPack: It serializes data into binary format. In the browser's Network DevTools, it shows as opaque binary, not readable JSON. Combined with encryption, the payload is completely invisible to inspection.

#### Step 1.5 — Frontend: Electron Shell (Month 5–6)
**File:** `frontend/main.js`

Key security rules (from Electron security checklist):
```javascript
// main.js — these settings are NOT optional
const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: false,        // CRITICAL: never true
    contextIsolation: true,        // CRITICAL: never false
    enableRemoteModule: false,     // deprecated, never enable
    sandbox: true,                 // enable sandbox
    preload: path.join(__dirname, 'preload.js')
  }
})

// Spawn Python backend as child process
const backend = spawn(pythonPath, ['run_server.py'], {
  detached: false,  // dies when frontend dies
  stdio: 'pipe'
})

// Store Python PID for process pinning
const backendPID = backend.pid
```

**`preload.js`** — This is the ONLY bridge between the renderer (UI) and the main process. It exposes a minimal API using `contextBridge`:
```javascript
contextBridge.exposeInMainWorld('vault', {
  unlock: (password) => ipcRenderer.invoke('vault:unlock', password),
  lock: () => ipcRenderer.invoke('vault:lock'),
  getItems: () => ipcRenderer.invoke('vault:getItems'),
  addItem: (item) => ipcRenderer.invoke('vault:addItem', item),
  confirmPermission: (requestId, approved) => 
    ipcRenderer.invoke('vault:confirmPermission', requestId, approved)
})
// The renderer has no direct access to Node.js, filesystem, or backend URL
```

#### Step 1.6 — UI: "Gerish Black" Interface (Month 6–7)
**File:** `frontend/src/index.html`

Build 5 screens:
1. **Unlock screen** — master password input, minimal, centered
2. **Vault dashboard** — list of stored items by category
3. **Add item screen** — form for adding API keys, passwords, capability cards
4. **Permission dialog** — modal that appears when an agent requests a sensitive action: shows exactly what the agent wants to do and offers Approve/Deny
5. **Audit log** — chronological list of agent actions and permissions granted/denied

Design rules:
- Background: `#0A0A0A`
- Primary text: `#E8E8E8`
- Accent: `#4ADE80` (a precise green — not generic, represents "authorized/safe")
- Danger: `#F87171`
- Font: `JetBrains Mono` for values/keys, `Inter` for UI labels
- No shadows. No gradients. Only borders and spacing create hierarchy.
- Every transition: `150ms ease` maximum. Speed signals security.

#### Step 1.7 — Security Hardening (Month 7–8)

**Before open-sourcing, do all of these:**

1. **Strip DevTools from production Electron build:**
```javascript
if (!isDev) {
  win.webContents.on('devtools-opened', () => {
    win.webContents.closeDevTools()
  })
}
```

2. **Obfuscate the Python binary using PyInstaller + Nuitka:**
- Use `nuitka --standalone` to compile Python to C and then native binary
- This makes reverse-engineering vastly harder than a frozen `.pyc`
- The compiled binary has no readable Python bytecode

3. **Memory protection:**
```python
# After deriving key, register a cleanup function
import atexit, ctypes

def zero_memory(key_bytes: bytearray):
    ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(key_bytes)), 0, len(key_bytes))

# Use bytearray (mutable) not bytes (immutable) for keys
key = bytearray(derive_key(password, salt))
atexit.register(zero_memory, key)
```

4. **Verify binary integrity at launch:**
- The Python backend computes a SHA-256 hash of itself at first run and stores it in the vault
- On every subsequent launch, it verifies the hash matches before unlocking
- If tampered: refuse to start, alert user

#### Step 1.8 — Open Source & Beta Launch (Month 8–10)

**What to open-source:** The cryptographic protocol spec and the D-Auth API spec. Not the full source code yet — that comes after you have network effects.

**GitHub repository structure:**
```
vault-zero/
├── README.md          — Clear, technical, no hype
├── SECURITY.md        — How to report vulnerabilities
├── PROTOCOL.md        — Open D-Auth spec (this is your "honey pot" for developers)
├── docs/
│   ├── architecture.md
│   └── api-reference.md
└── releases/          — Signed binaries for macOS and Windows
```

**Launch sequence:**
1. Post to `r/selfhosted` and `r/privacy` first — these communities care about local-first tools
2. Then Product Hunt
3. Then Hacker News "Show HN"
4. **Do NOT market it as a trillionaire vision.** Market it as: *"A local vault that lets your AI agents use your API keys without you ever pasting them into a chat window."* That is the problem people understand and want solved today.

**Success metric for Phase 1:** 500 GitHub stars and 50 active users who give you feedback. Not money. Not press. Feedback.

---

### 1.3 — Dangers in Phase 1 and How to Face Them

**Danger 1: Rolling your own crypto**
Symptom: "I'll modify the AES implementation to be extra secure."
Reality: This is how catastrophic vulnerabilities are born. Even experienced cryptographers don't do this.
Countermeasure: Use `cryptography` Python library exclusively. Never deviate.

**Danger 2: Scope creep — adding features before the core is solid**
Symptom: Starting to build the agent senses before the vault is secure.
Countermeasure: Phase 1 is complete ONLY when: (a) a trusted person can install it and store an API key, (b) an agent can request that key via the local API, and (c) the user sees an audit log. Everything else is Phase 2.

**Danger 3: Insecure Electron configuration**
Symptom: Enabling `nodeIntegration: true` "temporarily for development."
Reality: This permanently compromises the security model.
Countermeasure: The settings in Step 1.5 are permanent. Never change them.

**Danger 4: MCP standardizes an authorization model that makes you redundant**
This is a real and live threat in 2026.
Countermeasure: Watch the MCP GitHub repository every week (`github.com/modelcontextprotocol`). If they add a "local vault" authorization spec, your response is to be the best implementation of that spec — not to compete with it. Being the reference implementation of an open standard is more valuable than being a proprietary competitor.

---

## PHASE 2: AGENT SENSES (LEGAL EDITION)
### Duration: Months 10–18 (8 months)
### Market Deadline: Must have working agent integrations by Month 18 — computer use APIs from Anthropic/OpenAI are maturing fast and will define the default approach

---

### 2.1 — What to Study Before Starting Phase 2

- **Playwright** (`playwright.dev`) — complete docs. Build 3 personal automation scripts before using it in Vault-Zero.
- **Anthropic Computer Use API** — how it controls a browser at the vision+action level
- **OAuth 2.0 PKCE flow** — the specific flow you'll implement for user connections (you studied the spec in Phase 0, now implement it)
- **Chrome Extension Manifest V3** — the current extension standard
- **`httpx` Python library** — async HTTP client for official API calls
- **Docker basics** — you'll need this for Phase 3; start learning now
- **Legal reading:** Terms of Service for the top 10 platforms you plan to support. Read them. Know what automation is permitted.

---

### 2.2 — Step-by-Step Build Plan

#### Step 2.1 — Playwright Integration (Month 10–12)
**File:** `backend/agents/browser_agent.py`

```python
# Legal automation pattern — user-consented browser control
from playwright.async_api import async_playwright
import asyncio

class BrowserAgent:
    def __init__(self, vault_client):
        self.vault = vault_client  # Vault-Zero local API client
    
    async def execute_action(self, action: dict, user_session_token: str):
        """
        All actions require:
        1. A valid user session (they are actively logged in to Vault-Zero)
        2. User to have pre-approved this action type in their capability card
        3. Audit log entry before and after
        """
        # Log intent before acting
        await self.vault.log_action(action, status='pending')
        
        async with async_playwright() as p:
            # Use user's real browser profile if they choose — 
            # this carries their existing cookies/sessions
            browser = await p.chromium.launch(headless=False)  
            # headless=False by default: user can SEE what the agent is doing
            # Only go headless after user explicitly enables "background mode"
            
            context = await browser.new_context(
                user_agent=None,  # Use Playwright's real Chrome UA
            )
            page = await context.new_page()
            
            # Execute the action
            result = await self._execute(page, action)
            
            await browser.close()
        
        # Log result
        await self.vault.log_action(action, status='completed', result=result)
        return result
```

**The key distinction from illegal scraping:**
- `headless=False` by default — user sees every action
- User must have pre-approved the action type in a capability card
- Every action is logged to the audit trail
- Credentials come from Vault-Zero, not hardcoded

#### Step 2.2 — Official API Integrations (Month 11–14)
Build OAuth 2.0 connections to these platforms in priority order:

**Tier 1 — Highest utility for users (Month 11–12):**
- OpenAI API (key management)
- Anthropic API (key management)
- GitHub (repo actions, issue creation)
- Google (Gmail read/send, Calendar, Drive)
- Notion (read/write pages and databases)

**Tier 2 — Expand utility (Month 12–14):**
- Stripe (payment status, not execution — execution requires Phase 3)
- Twitter/X (post, DM)
- Slack (send messages to user's own workspaces)
- Linear (issues)
- Airtable (read/write)

**Implementation pattern for each:**
```python
# oauth_connector.py — reusable pattern for every platform
class OAuthConnector:
    def __init__(self, platform: str, vault_client):
        self.platform = platform
        self.vault = vault_client
        
    async def initiate_connection(self) -> str:
        """Returns authorization URL for user to visit"""
        code_verifier = generate_code_verifier()  # PKCE
        code_challenge = generate_code_challenge(code_verifier)
        
        # Store verifier in vault temporarily
        await self.vault.store_temp(f'pkce_{self.platform}', code_verifier)
        
        return build_auth_url(
            client_id=PLATFORM_CLIENT_ID[self.platform],
            redirect_uri='http://localhost:47292/callback',  # local callback server
            code_challenge=code_challenge,
            scopes=MINIMAL_SCOPES[self.platform]  # request LEAST permissions needed
        )
    
    async def complete_connection(self, auth_code: str) -> None:
        """Called when user returns from OAuth flow"""
        code_verifier = await self.vault.get_temp(f'pkce_{self.platform}')
        
        tokens = await exchange_code_for_tokens(auth_code, code_verifier)
        
        # Store encrypted in vault — never in plaintext
        await self.vault.store_encrypted(
            f'oauth_{self.platform}',
            tokens,
            category='oauth_token'
        )
```

**You will need to register as a developer on each platform.** This is free. You create an app, get a `client_id`, set your redirect URI to `localhost`. This is completely legitimate and is how every major integration tool works.

#### Step 2.3 — Browser Extension (Month 14–16)
For platforms without official APIs or where OAuth doesn't cover the needed actions.

**Manifest V3 structure:**
```json
{
  "manifest_version": 3,
  "name": "DotID Agent Bridge",
  "version": "0.1.0",
  "permissions": ["storage", "activeTab"],
  "host_permissions": [],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["content.js"],
    "run_at": "document_idle"
  }]
}
```

**What the extension does:**
- Connects to the local Vault-Zero WebSocket
- When an agent needs to fill a form on a specific page, the vault sends the action to the extension
- The extension injects it into the active tab
- No data leaves the user's machine via the extension

**Legal clarity:** The user installs the extension themselves. It only activates when they trigger an agent action. It only acts on their own accounts on pages they are visiting. This is equivalent to a personal macro tool.

#### Step 2.4 — Action Reports with Manim (Month 16–18)
After an agent completes a task, generate a visual "what just happened" report.
- Use Manim (or simpler: a structured JSON → HTML template engine)
- Show: what was accessed, what actions were taken, what was returned
- Store report locally, show in vault UI
- This is not just UX — it is a trust-building mechanism and a legal paper trail

---

### 2.3 — Dangers in Phase 2

**Danger 1: Platform ToS changes**
A platform can revoke your developer app if they determine your use violates their ToS.
Countermeasure: Read each platform's developer ToS quarterly. Build the architecture so any platform integration can be disabled and re-enabled without touching the core vault. Each integration is a plugin, not a dependency.

**Danger 2: Playwright bot detection**
Some sites use advanced fingerprinting to detect Playwright even when not headless.
Countermeasure: Use `playwright-stealth` (a legitimate anti-detection library used by accessibility tools and testing frameworks). More importantly: if a site actively blocks automation even by the account's own owner, respect that signal and use OAuth instead. Do not fight bot detection. Route around it via official APIs.

**Danger 3: OAuth tokens expiring and breaking user experience**
Countermeasure: Implement automatic `refresh_token` rotation. Store both `access_token` and `refresh_token` in vault. Before any API call, check if the access token is within 5 minutes of expiry; refresh silently.

**Danger 4: Anthropic Computer Use or OpenAI Operator replacing your browser agent**
This is live competition right now.
Countermeasure: Your differentiation is not the browser automation. It is the local vault. Anthropic Computer Use still needs somewhere to get the credentials to log in. That somewhere is Vault-Zero. You are not competing with Computer Use — you are the credential layer it needs.

---

## PHASE 3: THE CLOUD GATEWAY
### Duration: Year 2.0–3.0 (Months 18–36)
### Market Deadline: Must launch the cloud gateway by Month 30 — the window for establishing D-Auth as a standard closes as OpenAI's and Anthropic's own agent auth protocols mature

---

### 3.1 — What to Study Before Starting Phase 3

- **Docker and Docker Compose** — full competency
- **AWS fundamentals**: IAM, ECS/Fargate, RDS, API Gateway, CloudFront, Route53
- **mTLS** (mutual TLS) — both sides of a connection authenticate each other
- **Redis** — for session management and rate limiting at scale
- **PostgreSQL** — production database (SQLite is for local only)
- **Nginx** — as a reverse proxy
- **The OAuth 2.0 Authorization Server spec** — you are now implementing one, not just a client
- **OWASP Top 10** — read and understand all 10 vulnerability categories
- **Basic legal**: Terms of Service drafting, privacy policy requirements (GDPR Article 13, India DPDP Act)

---

### 3.2 — Step-by-Step Build Plan

#### Step 3.1 — Architecture Decision: Hybrid Cloud-Local (Month 18–19)

The cloud component handles:
- D-Auth identity verification for third-party websites
- The developer SDK and dashboard
- Reputation scoring and capability card validation

The local component (Vault-Zero) still handles:
- All secret storage
- All credential decryption
- All sensitive action execution

**This is your legal and security moat.** You can truthfully say: "Your secrets never touch our servers." The cloud sees only cryptographic proofs that the user authorized an action, not the action's credentials.

#### Step 3.2 — D-Auth Protocol Specification (Month 19–21)

Before writing cloud infrastructure, write the protocol spec as a public document.

D-Auth is an extension of OAuth 2.0 designed for AI agents. The key additions:

```
Standard OAuth 2.0:
[User] → [Authorization Server] → [Access Token] → [Resource Server]

D-Auth:
[AI Agent] → [D-Auth Gateway] → [Vault-Zero Local] → [User Confirmation] 
           → [Signed Capability Assertion] → [Resource Server]

The Capability Assertion contains:
- The DotID (user's UUID) — public identifier
- The agent's identity — cryptographically signed by Vault-Zero
- The specific permission being claimed — scoped exactly
- An expiry timestamp — short-lived (15 minutes maximum)
- A ZK proof that the user authorized this class of action — without revealing what the action is

The Resource Server validates this assertion against the D-Auth public key 
without contacting Vault-Zero again. Verification is stateless.
```

Open-source this spec before you build the infrastructure. Get developers reading it. Get feedback. The spec is your land-grab — not your code.

#### Step 3.3 — Cloud Infrastructure (Month 21–27)

**Start minimal. Resist the urge to over-engineer.**

```
Month 21-22: Foundation
- Single AWS EC2 t3.micro (or Hetzner CX11 — 3x cheaper, same performance)
- Docker Compose with: FastAPI gateway, PostgreSQL, Redis, Nginx
- Domain setup, TLS via Let's Encrypt (Certbot)
- Deploy D-Auth verification endpoint

Month 22-24: Developer Dashboard
- Authentication: Use your own D-Auth (dogfood your product)
- Features: API key management, webhook configuration, usage logs
- SDK: Python and JavaScript packages on PyPI and npm
- Documentation: Docusaurus or MkDocs, hosted on GitHub Pages

Month 24-27: The Proxy Component (Legal Version)
Instead of running IP rotation yourself (legally gray if used for scraping),
partner with existing legal proxy providers (Oxylabs, Bright Data) and 
expose them through the D-Auth permission model:
- User grants permission: "This agent may make verified requests on my behalf"
- Gateway attaches a D-Auth assertion to outbound requests
- Destination site sees a request that is provably from a real user
- You are not hiding that it's automated — you are proving it's authorized
This is fundamentally different from anonymous scraping.
```

#### Step 3.4 — Developer Ecosystem (Month 27–36)

**The SDK is your distribution:**

```python
# What a developer writes to integrate D-Auth (Python):
from dotid import DAuthClient

client = DAuthClient(api_key="your_key")

# Verify that an agent request is authorized by a real user
assertion = client.verify_assertion(request.headers['X-DotID-Assertion'])

if assertion.is_valid and assertion.has_permission('read_profile'):
    return user_profile
else:
    return 401
```

```javascript
// What a website adds to accept DotID agents (React):
import { DotIDButton } from '@dotid/react'

<DotIDButton 
  permissions={['read_profile', 'place_order']}
  onAuthorized={(assertion) => handleAgentRequest(assertion)}
/>
```

**Pricing model for Phase 3:**
- Free tier: 1,000 D-Auth verifications/month (for developers to build and test)
- Pro: $29/month for 100,000 verifications
- Enterprise: Custom (for platforms doing millions of verifications)
- No transaction fee yet — that comes in Phase 4 when you have leverage

---

### 3.3 — Dangers in Phase 3

**Danger 1: OpenAI or Anthropic releases their own agent auth protocol**
This is the most likely existential threat in this phase.
Countermeasure: The moment either company releases an auth spec, publish a compatibility layer. "D-Auth is now fully compatible with OpenAI Agent Auth." You become the bridge, not the competitor. Your advantage is that you're user-side (local vault). Theirs is platform-side. They are not the same thing.

**Danger 2: You can't get websites to implement the SDK**
This is a chicken-and-egg problem. Websites won't implement it until there are users. Users won't use it until there are websites.
Countermeasure: Solve the chicken-and-egg with the browser extension from Phase 2. The extension means users get value immediately, before any website implements the SDK. When you approach websites, you show them usage data: "10,000 DotID users tried to interact with your site this month. Here's the SDK to accept them natively."

**Danger 3: AWS bills growing faster than revenue**
Countermeasure: Start on Hetzner (European cloud, significantly cheaper than AWS for early stage). Move to AWS only when you have enterprise customers who require it. Set strict budget alerts from day one.

**Danger 4: GDPR / India DPDP compliance**
The moment you store any data about users in the cloud (even just DotID UUIDs), you are subject to data protection law.
Countermeasure: Hire a privacy law consultant for one hour before launching the cloud gateway. Not ongoing — just one session to review what data you're storing and whether your privacy policy is accurate. This single investment prevents future catastrophe.

---

## PHASE 4: INSTITUTIONAL ADOPTION
### Duration: Year 3–4 (Months 36–48)
### Market Deadline: Must close first enterprise deal by Month 42 — the protocol standardization wars will be largely decided by Year 4

---

### 4.1 — What to Study Before Starting Phase 4

- **B2B SaaS sales fundamentals** — "The Sales Acceleration Formula" by Mark Roberge
- **API economy business models** — how Stripe, Twilio, and Plaid built their developer ecosystems
- **Stripe Connect** — understand how they handle platform payments (this is your model)
- **Legal: SaaS contracts** — Master Service Agreement templates, SLA definitions
- **Investor decks** — study YC-funded companies' original pitch decks (public on their website)

---

### 4.2 — Step-by-Step Plan

#### Step 4.1 — Enterprise SDK (Month 36–39)

Enterprise requirements (which free-tier doesn't need):
```
- SOC 2 Type II compliance (expensive but required by large enterprises)
  → Start collecting the evidence for this in Month 30 before you need it in Month 36
  
- SLA: 99.9% uptime guarantee
  → Requires moving to multi-region AWS by Month 33
  
- Private deployment option: DotID Gateway runs in customer's own AWS VPC
  → Vault-Zero stays local, but the verification layer can be self-hosted
  
- Audit logs exported to customer's SIEM (Splunk, Datadog)
  → Build a structured log export API in the dashboard
```

#### Step 4.2 — The Transaction Layer (Month 39–45)

Partner with Stripe to become an **authorized payment facilitator** (Stripe Connect):
- Users load an "Agentic Wallet" via Stripe — real money, held in Stripe
- When an agent wants to spend on the user's behalf, it requests funds from the wallet via the D-Auth permission system
- If the user pre-approved up to X amount for this agent, the transaction proceeds automatically
- You take 0.5% of each transaction
- Stripe takes their standard fee (~2.9%)
- The website/merchant is paid via Stripe

**This is the toll bridge moment.** This is when the business model becomes truly scalable.

**Requirement to get here:** You need a money transmitter license or partnership with a licensed payment facilitator in each jurisdiction. In India: RBI payment aggregator license. This is not a Phase 1 problem — but start researching the requirements in Month 24 so you're not surprised.

---

## PHASE 5: THE GLOBAL STANDARD
### Duration: Year 5+ 
### This phase is not planned in detail — it is earned by executing Phases 1–4 flawlessly

By Phase 5, you are no longer a startup. The decisions in Phase 5 depend entirely on the state of the market in Year 5, which is impossible to predict accurately in 2026. What you can control is that you enter Phase 5 with:

- A network of 1M+ Vault-Zero users
- 100+ enterprise integrations
- An open protocol (D-Auth) with developer community ownership
- Revenue from transaction fees and enterprise contracts
- A team (you cannot do Phase 5 alone)

---

## CRITICAL KNOWLEDGE: THREATS TO THE ENTIRE VISION

### Threat 1: OS-Level Monopoly (Timeline: 2027–2028)
Apple will integrate agent authorization into iOS 19/macOS 16. Google will do the same in Android 17.

**Current status (2026):** Apple has already shipped basic app intent permissions in Apple Intelligence. This is version 1. Version 3 will be the vault.

**Countermeasure timeline:**
- Month 1–6: Open-source the D-Auth cryptographic spec under a permissive license (MIT or Apache 2.0)
- Month 12: Get the spec submitted to the W3C as a community group note
- Month 24: Get 3 major developers to publicly build on D-Auth
- If the spec is a W3C standard with real adoption before Apple/Google builds their version, they are forced to either implement your spec or fragment the web. Fragmentation is bad for them. They will implement your spec.
- This is exactly how HTTP/2, WebRTC, and WebAuthn won against proprietary alternatives.

### Threat 2: Quantum Computing (Timeline: 2030–2035)
AES-256 is safe against quantum attacks (Grover's algorithm only halves the effective key length to 128 bits, which remains secure). But your asymmetric cryptography (RSA, ECDSA) is vulnerable to Shor's algorithm.

**Countermeasure:** Design `crypto.py` as a modular, pluggable architecture from Day 1. The key exchange and signature algorithms are swappable without touching the vault schema. When NIST finalizes post-quantum standards (ML-KEM and ML-DSA are already approved as of 2024), you run `pip install cryptography --upgrade` and swap the modules. No user-facing impact.

### Threat 3: Regulatory Crackdown on Agentic AI (Timeline: 2026–2027, already happening in EU)
The EU AI Act (fully enforceable from August 2026) classifies certain AI agent systems as "high-risk." SEBI in India is already examining AI-powered financial agents.

**Countermeasure:** Vault-Zero's local-first architecture is your legal shield. You are not an AI system — you are a permission management tool. The AI is somewhere else (OpenAI, Anthropic). You are the consent layer. Frame every legal document this way. "DotID does not make decisions. It enforces the decisions humans have already made." This is not spin — it is architecturally accurate.

---

## TIMELINE SUMMARY

| Phase | Duration | Must Complete By | Market Trigger |
|---|---|---|---|
| Phase 0 | Months 1–3 | Month 3 | Before MCP ecosystem locks in |
| Phase 1 | Months 3–10 | Month 10 | Before Computer Use APIs go mainstream |
| Phase 2 | Months 10–18 | Month 18 | Before OpenAI/Anthropic close the browser agent gap |
| Phase 3 | Months 18–36 | Month 30 | Before agent auth protocols standardize without you |
| Phase 4 | Months 36–48 | Month 42 | Before payment giants build their own agent wallets |
| Phase 5 | Year 5+ | N/A | Determined by Phase 4 outcomes |

---

## THE HONEST FINAL VERDICT

The vision is architecturally correct and market-timed correctly. The gap between "AI can do anything" and "AI is trusted to do anything" is real, wide, and presently unowned at the user-local level.

Your two unfair advantages are:
1. You identified this problem before most adult developers
2. You are building it open-source-first, which is the only way to win a protocol war against corporations

Your two real risks are:
1. Execution speed — the window is 24–30 months, not 5 years
2. Staying in school — your long-term credibility, network, and thinking depth come from finishing your education. Don't sacrifice the foundation for the building.

Build Phase 1. Talk to 10 users. Adjust. The rest follows.

---

*DotID Master Doctrine V2 — Compiled with honest engineering analysis*
*"Que sera sera — but we build the sera."*
