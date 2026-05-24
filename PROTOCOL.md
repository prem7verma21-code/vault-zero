# D-Auth Protocol — Draft Specification v0.1.0

**Status:** Draft — not yet standardized
**Author:** Prem Verma (dotdev@zohomail.com)
**First published:** May 24, 2026
**Feedback:** GitHub Issues tagged `protocol`

---

## Abstract

D-Auth (Delegated Authorization for Agents) is a protocol for granting AI agents scoped, time-limited, user-auditable access to credentials and sensitive resources. It extends the OAuth 2.0 authorization framework (RFC 6749) with agent-specific capability scoping and is compatible with the W3C Verifiable Credentials data model.

The core problem D-Auth addresses: existing authorization standards were designed for human users and server-to-server communication. They assume a browser redirect flow or a pre-registered client application. AI agents — autonomous processes that act on behalf of users — fit neither model cleanly. D-Auth provides a first-class authorization primitive for agentic use cases.

---

## 1. Motivation

When a user instructs an AI agent to "book a flight" or "push this code to GitHub," the agent needs credentials. Current approaches:

1. **Paste credentials into the chat.** The credentials are now in the LLM provider's logs, the user's chat history, and potentially training data.
2. **Hard-code credentials in a script.** No audit trail, no revocation, no scope limiting.
3. **Give the agent full OAuth access.** The agent can do anything the user can do, with no per-action oversight.

D-Auth introduces a fourth option: the user's vault holds credentials locally, and the agent requests specific credentials via a signed capability card. The user sees every request. Sensitive actions require explicit approval. Access expires automatically.

---

## 2. Concepts

### 2.1 Vault

A local process that stores encrypted credentials and enforces access policy. In the reference implementation, this is Vault-Zero. The vault exposes a local HTTP API and WebSocket tunnel, both bound to `127.0.0.1`.

### 2.2 Capability Card

A signed, time-limited authorization token that grants an agent access to a specific set of named credentials. A capability card is not a credential — it is a permission to request credentials.

Capability cards are created by the user, not the agent. An agent cannot create or extend its own capability card.

### 2.3 Agent

Any process that acts on behalf of a user: an AI assistant, an automation script, a browser extension, or a background service. Agents are identified by a unique `agent_id` (UUID v4) assigned at registration.

### 2.4 Vault API Key (`vzk_` token)

The bearer token an agent uses to authenticate requests to the vault. Format:

```
vzk_<base64url-encoded UUID v4>
```

Example: `vzk_dGhpcyBpcyBhIHRlc3Q`

The `vzk_` prefix distinguishes vault API keys from other token types and prevents accidental use in wrong contexts.

### 2.5 HMAC Secret

A 32-byte random secret generated at agent registration and returned to the user once. The agent uses this secret to sign every request. The vault verifies the signature before processing any request. This prevents request tampering and replay attacks.

---

## 3. Registration Flow

```
User                    Vault UI                  Vault Backend
 │                          │                           │
 │  Open "New Agent" form   │                           │
 │─────────────────────────►│                           │
 │                          │                           │
 │  Submit:                 │  POST /api/v1/agent/register
 │  - agent_name            │──────────────────────────►│
 │  - allowed_labels[]      │                           │ validate labels exist
 │  - ttl_hours             │                           │ generate agent_id (UUID)
 │                          │                           │ generate hmac_secret (32 bytes)
 │                          │                           │ sign capability card JWT
 │                          │                           │ store card in DB
 │                          │◄──────────────────────────│
 │                          │  {                        │
 │                          │    agent_token: "vzk_...",│
 │                          │    hmac_secret: "...",    │
 │                          │    agent_id: "uuid",      │
 │                          │    valid_until: 1234567890│
 │                          │  }                        │
 │◄─────────────────────────│                           │
 │  ONE-TIME display of      │                           │
 │  agent_token + hmac_secret│                           │
```

The `agent_token` and `hmac_secret` are shown to the user exactly once. If lost, the capability card must be revoked and a new one created.

---

## 4. Key Request Flow

### 4.1 REST API

**Endpoint:** `POST /api/v1/agent/request_key`
**Host:** `http://127.0.0.1:8765`
**Authentication:** `Authorization: Bearer <agent_token>`

**Request body:**
```json
{
  "label":     "OpenAI Key",
  "msg_id":    "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "1716556800",
  "hmac_sig":  "<HMAC-SHA256 signature>"
}
```

**Signature computation:**
```
hmac_sig = HMAC-SHA256(hmac_secret, msg_id + label + timestamp)
```

**Success response (200):**
```json
{
  "value": "sk-abc123..."
}
```

**Failure response (403) — all failure cases return the same response:**
```json
{
  "detail": "access denied"
}
```

Failure cases include: expired token, invalid signature, label not in allowed scope, vault locked, duplicate nonce (replay attempt). The specific reason is never disclosed.

### 4.2 Rate Limiting

Key requests are rate-limited to 10 requests per minute per agent token. Exceeding this limit returns HTTP 429.

### 4.3 Nonce Tracking

Each `msg_id` must be a UUID v4 that has not been used in the current session. The vault maintains a set of used nonces for the lifetime of each session. A duplicate `msg_id` returns 403 regardless of other validity.

---

## 5. Permission Request Flow

For actions that require explicit user approval before proceeding.

### 5.1 Submit a permission request

**Endpoint:** `POST /api/v1/agent/request_permission`

```json
{
  "action":     "Send email to team@company.com with subject 'Q2 Report'",
  "request_id": "550e8400-e29b-41d4-a716-446655440001"
}
```

Response:
```json
{
  "status":     "pending",
  "request_id": "550e8400-e29b-41d4-a716-446655440001"
}
```

### 5.2 Poll for user response

**Endpoint:** `GET /api/v1/agent/permission_status/{request_id}`

Response:
```json
{
  "status":     "approved",
  "request_id": "550e8400-e29b-41d4-a716-446655440001"
}
```

Possible status values: `pending`, `approved`, `denied`, `expired`

Requests expire after 60 seconds if the user does not respond. Agents must treat `expired` as equivalent to `denied`.

### 5.3 User response (vault UI)

**Endpoint:** `POST /api/v1/user/respond_permission`
**Authentication:** User session token (not agent token)

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440001",
  "approved":   true
}
```

---

## 6. WebSocket Tunnel (Phase 2)

The WebSocket tunnel provides a persistent, binary-encrypted channel for high-frequency agent communication. It is designed for the cloud phase of D-Auth where the vault may not be on the same machine as the agent.

**Endpoint:** `ws://127.0.0.1:47291/agent`

### 6.1 Message format

All messages are serialized with MessagePack and encrypted with AES-256-GCM using the session key before transmission.

```
Outbound (vault → agent):
  1. Serialize message dict → MsgPack bytes
  2. Encrypt with AES-256-GCM → {salt, nonce, ciphertext}
  3. Serialize bundle → MsgPack bytes
  4. Send as binary WebSocket frame

Inbound (agent → vault):
  1. Receive binary frame
  2. Deserialize outer MsgPack → {salt, nonce, ciphertext}
  3. Decrypt with AES-256-GCM → raw bytes
  4. Deserialize inner MsgPack → message dict
  5. Process by message type
```

### 6.2 Handshake

The first message from the agent is sent unencrypted:

```msgpack
{
  "agent_token": "vzk_...",
  "nonce":       "uuid-v4"
}
```

If the token is valid, the vault responds with a plain MsgPack confirmation (unencrypted). Encryption begins with all subsequent messages after handshake.

```json
{
  "type":     "connected",
  "agent_id": "uuid"
}
```

If invalid, the connection is closed with WebSocket close code `4001`.

### 6.3 Supported message types

| Type | Direction | Description |
|---|---|---|
| `key_request` | agent → vault | Request a decrypted secret by label |
| `permission_request` | agent → vault | Request user approval for an action |
| `context_request` | agent → vault | Request user preferences from memory items |
| `ping` | agent → vault | Keepalive; vault responds with `pong` and same `msg_id` |

### 6.4 Error codes

| Code | Meaning |
|---|---|
| 4001 | Invalid or expired agent token during handshake |
| 4002 | Decryption failure — message integrity check failed |

---

## 7. Capability Card JWT Structure

Capability cards are signed JWTs (HS256) with the following payload:

```json
{
  "agent_id":       "550e8400-e29b-41d4-a716-446655440000",
  "allowed_labels": ["OpenAI Key", "GitHub Token"],
  "valid_until":    1716643200,
  "type":           "agent",
  "iat":            1716556800
}
```

Agent tokens are signed with a secret that is separate from the user session JWT secret. The vault rejects user session tokens presented as agent tokens and vice versa.

---

## 8. Audit Log

Every agent action is recorded:

```json
{
  "timestamp":     1716556800,
  "agent_id":      "550e8400-e29b-41d4-a716-446655440000",
  "action":        "request_key",
  "result":        "approved",
  "label_accessed": "OpenAI Key"
}
```

Secret values are never written to the audit log. The log records what was accessed, not what the value was.

---

## 9. Relationship to Existing Standards

**OAuth 2.0 (RFC 6749):** D-Auth extends OAuth's concept of scoped authorization tokens. Capability cards are analogous to access tokens with explicit resource scoping. D-Auth does not replace OAuth for server-to-server or user-to-service flows — it extends it for agent-to-local-vault flows.

**W3C Verifiable Credentials:** The capability card structure is compatible with the W3C VC data model. A future version of D-Auth may express capability cards as Verifiable Credentials to enable cross-vault and cross-device verification.

**FIDO2 / WebAuthn:** D-Auth's device trust mechanism (Phase 2) is conceptually aligned with FIDO2's authenticator binding model. Hardware binding in D-Auth uses platform-specific hardware identifiers rather than cryptographic authenticators, making it deployable without specialized hardware.

---

## 10. Versioning

This document describes D-Auth v0.1.0.

Version format: `MAJOR.MINOR.PATCH`

- MAJOR: breaking changes to the protocol
- MINOR: new endpoints or message types (backwards compatible)
- PATCH: clarifications, editorial changes

Breaking changes will be announced via GitHub releases with a migration guide.

---

## 11. Status and Roadmap

**v0.1.0 (current):** Local vault, REST API, WebSocket tunnel, capability cards, permission requests.

**v0.2.0 (planned):** OAuth 2.0 integration for cloud services (OpenAI, GitHub, Google). Browser extension support.

**v1.0.0 (target):** W3C Community Group submission when adoption reaches 10+ independent integrations.

---

## 12. Contributing to the Protocol

Protocol feedback is welcome via GitHub Issues tagged `protocol`. Areas of particular interest:

- Cross-platform capability card verification (enabling cloud vaults)
- Post-quantum signature algorithms for capability cards
- Standardized agent identity (DID-based agent_id)
- Multi-vault federation

---

*D-Auth Protocol Draft Specification v0.1.0*
*Prem Verma — May 24, 2026*
*Vault-Zero reference implementation: github.com/prem7verma21-code/vault-zero*
