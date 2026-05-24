# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: dotdev@zohomail.com
Subject line: `[SECURITY] Vault-Zero — <brief description>`

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce
- Any proof-of-concept code (if applicable)

You will receive an acknowledgement within 48 hours. Confirmed vulnerabilities will be patched and disclosed responsibly. Credit will be given to reporters unless anonymity is requested.

---

## Security Model

### What Vault-Zero protects

**Secrets at rest**
All secret values are encrypted with AES-256-GCM at the application layer before being stored. The database file itself is additionally encrypted with SQLCipher (AES-256). An attacker who obtains the database file faces two independent layers of encryption.

**Master password**
The master password is never stored anywhere. On unlock, it is used once to derive a 256-bit key via Argon2id. The derived key lives in process memory only and is explicitly zeroed (via `ctypes.memset`) when the vault is locked or the process exits. The password itself is discarded immediately after key derivation.

**Agent access**
AI agents do not receive the master password or direct database access. They receive a scoped capability card — a signed JWT that specifies exactly which secret labels the agent may access and when the access expires. Every key request is validated against this card.

**Request integrity**
Each agent request must include an HMAC-SHA256 signature computed from the request contents and a per-agent secret. The vault recomputes and verifies the signature on every request. Tampered or replayed requests are rejected.

**Replay attack prevention**
Every request over the WebSocket tunnel includes a unique nonce (UUID v4). The vault tracks used nonces for the lifetime of the session. A nonce seen twice is rejected immediately.

**Network exposure**
The REST API (port 8765) and WebSocket tunnel (port 47291) bind exclusively to `127.0.0.1`. They are not reachable from any external network interface.

**Audit trail**
Every agent action is recorded in the audit log: timestamp, agent ID, action type, and the label accessed. Secret values are never written to the audit log or any log file.

---

### What Vault-Zero does not protect against

- **Physical access to an unlocked machine.** If an attacker can interact with your running, unlocked Vault-Zero instance, they have the same access you do.
- **A compromised OS kernel.** Kernel-level access can read process memory regardless of application-level protections.
- **Malware running as the same OS user.** A process with equivalent user privileges can potentially inspect memory or intercept local socket traffic.
- **A user who shares their master password.** Vault-Zero cannot protect against deliberate credential disclosure.
- **Hardware-level attacks** (cold boot, DMA attacks). These are out of scope for a software-only solution.

These limitations are inherent to any local-first security application. They are documented here so users can make informed decisions about their threat model.

---

## Cryptographic Primitives

### Key Derivation

**Algorithm:** Argon2id (RFC 9106)

| Parameter | Value | Reason |
|---|---|---|
| Salt | 16 random bytes (per item) | Prevents rainbow table attacks |
| Output length | 32 bytes (256 bits) | AES-256 key size |
| Iterations (time cost) | 3 | Balances security and unlock speed |
| Memory | 65,536 KB (64 MB) | Makes brute-force GPU attacks expensive |
| Parallelism (lanes) | 4 | Matches typical CPU core count |

Argon2id is memory-hard by design. Each password attempt requires 64 MB of RAM and approximately 1–2 seconds of computation. This makes large-scale brute-force attacks impractical.

### Symmetric Encryption

**Algorithm:** AES-256-GCM (NIST SP 800-38D)

| Parameter | Value |
|---|---|
| Key size | 256 bits |
| Nonce | 96 bits, generated fresh per encryption via `os.urandom(12)` |
| Authentication tag | 128 bits (included in ciphertext) |
| Additional data | None |

GCM mode provides both confidentiality and authenticity. Any modification to the ciphertext — even a single bit — causes decryption to fail with an authentication error. Partial or corrupted data is never returned.

**Storage format per encrypted item:**
```json
{
  "salt":       "<base64-encoded 16-byte Argon2id salt>",
  "nonce":      "<base64-encoded 12-byte AES-GCM nonce>",
  "ciphertext": "<base64-encoded ciphertext including 16-byte GCM tag>"
}
```

### Session Tokens

**Algorithm:** HS256 JWT (HMAC-SHA256)

User session tokens expire after 1 hour. Agent capability card tokens expire at the time specified during registration (maximum configurable by the user). User session tokens and agent tokens are signed with separate secrets and are not interchangeable.

### Request Signing

**Algorithm:** HMAC-SHA256

Each agent request is signed over: `msg_id + label + timestamp`. The HMAC secret is generated at agent registration using `secrets.token_bytes(32)` and returned to the user once. It is not stored in the database — only its SHA-256 hash is retained for verification.

---

## Dependency Security

Core cryptographic operations use the Python `cryptography` library (maintained by the Python Cryptographic Authority). No custom cryptographic implementations are used anywhere in the codebase.

Dependencies are pinned to exact versions in `requirements.txt`. Review this file before installation.

---

## Scope for Bug Bounty / Responsible Disclosure

**In scope:**
- Authentication bypass
- Cryptographic weaknesses or implementation errors
- Secret value exposure via any code path (logs, API responses, error messages)
- Agent token forgery or privilege escalation
- Replay attack bypasses
- Local privilege escalation via the API or WebSocket tunnel

**Out of scope:**
- Attacks requiring physical access to an unlocked machine
- Attacks requiring OS kernel compromise
- Social engineering
- Denial of service against the local API
- Issues in third-party dependencies (report those upstream)

---

*Vault-Zero Security Policy — Prem Verma — May 2026*
