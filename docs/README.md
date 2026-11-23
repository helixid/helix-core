<p align="center">
  <h1 align="center">HelixID</h1>
  <p align="center"><strong>Cryptographic identity and authorization for AI agents.</strong></p>
  <p align="center">Replace API keys with verifiable, scoped, and auditable agent identity.</p>
</p>

<p align="center">
  <a href="https://github.com/nicedigverse/helixid/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://www.w3.org/TR/vc-data-model-2.0/"><img src="https://img.shields.io/badge/W3C-VC%202.0-green.svg" alt="W3C VC 2.0"></a>
  <a href="https://www.w3.org/TR/did-core/"><img src="https://img.shields.io/badge/W3C-DID%201.0-green.svg" alt="W3C DID 1.0"></a>
</p>

---

## The Problem

AI agents are authenticating with static API keys and bearer tokens — credentials designed for humans clicking through OAuth consent screens, not autonomous software making thousands of cross-boundary decisions per hour.

This breaks in predictable ways:

- **No delegation chain.** When Agent A spawns Agent B to call Service C, there's no standard way to prove B is authorized to act on A's behalf.
- **No scoped authority.** API keys are all-or-nothing. An agent that needs read access to one table gets the same key as one that needs admin access to everything.
- **No cross-org trust.** When your agent calls a third-party service, both sides rely on shared secrets and manual API key exchange. There's no way to verify authority without bilateral integration.
- **No revocation that works.** Revoking a compromised agent means rotating keys across every service it touched.
- **No audit trail.** "Who authorized this agent to do that?" is answered by grepping logs, not cryptographic proof.

HelixID fixes this by giving every AI agent a cryptographic identity — a portable, verifiable, revocable credential that works across organizational boundaries without requiring the parties to know each other in advance.

## What HelixID Does

HelixID is a **5-layer trust stack** for AI agents, not just an identity library:

| Layer              | What It Does                                                                                                     | How                                                   |
| ------------------ | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| **1. Identity**    | Every agent gets a DID (Decentralized Identifier) bound to a cryptographic keypair                               | W3C DID (`did:web` default, `did:key` local) |
| **2. Authority**   | Scoped, time-bound credentials that prove what an agent is allowed to do                                         | W3C Verifiable Credentials with delegation chains     |
| **3. Enforcement** | Runtime verification and authorization checks at execution boundaries                                              | SDK/core verification + verifier-owned policy checks  |
| **4. Audit**       | Operational record of issuance, verification/session bridge, revocation, and lifecycle events                    | KYA-OS typed producer events (AAP-1) in `audit_events` + encrypted evidence vault, with a stdout/file echo |
| **5. Revocation**  | Decentralized, cacheable revocation that works offline                                                           | Bitstring Status List |

## Roles

HelixID is built around three distinct actors. Each has a different relationship with the SDK and the issuer service.

| Role | Who | What they do |
|---|---|---|
| **Platform Operator** | The team building the AI product | Creates issuer DID, mints bootstrap tokens, issues VCs to agents, manages revocation |
| **AI Agent** | The autonomous software process | Onboards with an enrollment token, requests server-signed VPs, presents credentials, delegates authority to sub-agents |
| **Service Provider** | The API or service the agent calls | Verifies incoming VPs, checks scopes, optionally issues a session JWT or caches the result |

### Platform Operator

The operator runs the issuer service (self-hosted `helix-api` or CLI for low volume). They never touch agent private keys — they only control the issuance policy.

```typescript
// Operator: mint a bootstrap token for a new agent (authenticated operator call)
// POST /v1/enrollment-tokens
// { agentName, requestedScopes, maxDelegationDepth, requestedDomains }
// → { bootstrapToken }

// Operator: revoke an agent's credential
// CLI
helix revoke --vc-id <vcId> --status-list ./public/status/1.json --wallet issuer.enc
```

The operator's private key (issuer signing key) never leaves the issuer service. It is the trust anchor for every VC issued in their trust domain.

### AI Agent

The agent signs every tool call itself (KYA-OS story C-C): a per-request holder-of-key proof (`org.kya-os/proof.v1`) bound to the request body and the service, with its delegation chain beside it in `params._meta`. The private key stays wherever the agent's `Signer` keeps it; no request ever carries it. There is no Helix VP, `signVP()` or `verifyVP()`.

```typescript
import { kyaos } from '@helixid/sdk-js'

// the agent's own key, read from HELIX_SIGNING_KEY at each sign() call
const signer = new kyaos.EnvSigner({ did: agentDid })

// one proof per request, for this service only
const request = await kyaos.withRequestProof(
  { name: 'lookup_order', arguments: { orderId: 'ORD-1001' } },
  signer,
  { audience: 'did:web:orders.example.com', chain },
)
// send `request` as the MCP tools/call params (the proof rides params._meta)
```

### Service Provider

The service verifies each call in-process with the local verifier (story F-2): the proof in the §11.2 order, the carried chain, status lists and the agent's Entity Card, from public documents only. The Helix API is never asked.

```typescript
import { helixidMCPMiddleware, createLocalVerifier, RedisNonceStore } from '@helixid/mcp-middleware'

const verifier = createLocalVerifier({
  serviceDid: 'did:web:orders.example.com',
  trustedIssuers: '*',
  nonceStore: new RedisNonceStore({ client: redis }), // replay protection, shared by every instance
  // An agent card's revocation entry is on the Helix issuer's list: bind its exact URL (SPEC-ENTITY-CARD §10.3).
  statusListIssuers: { 'did:web:api.helixid.dev': ['https://api.helixid.dev/v1/status-list/helix-status-list-1'] },
})
const requireHelix = helixidMCPMiddleware({ verifier, toolScopes: { lookup_order: ['read:orders'] } })

await requireHelix({ name, input: args, _meta: request.params._meta, request })
```

Neither session option is required. The verifier can re-verify the VP on every call if preferred. The SDK supports all three paths.

## Architecture

HelixID uses a **hybrid 3-layer architecture** that delivers the trust properties of verifiable credentials with the performance of JWTs:

```
┌─────────────────────────────────────────────────────────────┐
│                     YOUR AI AGENT                           │
│                                                             │
│  ┌─────────────┐   ┌──────────────┐   ┌─────────────────┐  │
│  │  Layer 3    │   │   Layer 2    │   │    Layer 1      │  │
│  │  Ed25519    │   │  Ephemeral   │   │   VC-Based      │  │
│  │  Direct     │   │    JWT       │   │   Identity      │  │
│  │  Signing    │   │  Sessions    │   │                 │  │
│  │             │   │              │   │                 │  │
│  │ • did:key   │   │ • Verify VC  │   │ • DID creation  │  │
│  │ • Local dev │   │   once       │   │ • Delegated VCs │  │
│  │ • MCP tool  │   │ • Issue JWT  │   │ • StatusList    │  │
│  │   auth      │   │   (5-15 min) │   │   revocation    │  │
│  │             │   │ • Hot path   │   │ • Cross-org     │  │
│  │  ~0.1ms     │   │  ~0.1ms/req  │   │   trust          │  │
│  └─────────────┘   └──────────────┘   └─────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │    API audit log (adapter store + stdout/file)       │   │
│  │   Issuance · revocation · session-bridge verification │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Why three layers?** Different trust contexts need different tradeoffs:

- **Layer 1 (VCs):** Use when agents cross organizational boundaries, when delegation chains matter, when you need revocation and audit. This is the foundation.
- **Layer 2 (JWT sessions):** Verify the VC once, issue a short-lived JWT for subsequent calls. Best for high-frequency internal calls where you've already established trust.
- **Layer 3 (Ed25519 direct):** For local development, MCP tool authentication, and internal agent-to-tool calls where both parties share a trust context.

## Quick Start

### Full Demo (self-hosted, Travel Concierge)

See HelixID enforce scoped access, delegation, and revocation against a real
AI travel-booking agent — with a live audit trail of every trust decision.

Prefer a guided walkthrough? **[Try it on our website →](https://dgverse.in/helixid/try-it-out)**
Same demo, no local setup.

To run it yourself:

**Step 1 — Get an LLM API key**

The concierge agent needs access to an LLM. Grab a free key from one of:

- [Anthropic Console](https://console.anthropic.com/settings/keys)
- [OpenAI Platform](https://platform.openai.com/api-keys)

**Step 2 — Get the demo**

Download the demo package:

[helixid-travel-concierge-demo.zip](#) — pre-filled `.env` with working demo defaults (LLM key still manual).

Unzip it, then set your key:

```bash
# --- LLM Provider ---
# Which LLM to use: "anthropic" (default) or "openai".
LLM_PROVIDER=anthropic

# LLM API key obtained from your LLM provider.
LLM_API_KEY=your-llm-api-key
```

**Step 3 — Run it**

```bash
docker-compose up
```

This starts the issuer API (sqlite + in-memory cache + `did:web`), the
**HelixID Console**, the travel-concierge web app, and two pre-provisioned
custodial agents. A one-shot setup service pre-registers the booking backend as
a known service, seeds scopes, pre-onboards the demo agents, and seeds a
status list — fully wired, nothing else to configure.

Open **http://localhost:5173** for the demo. The terminal will also print a
URL for the **Console** — the operator view where you'll revoke credentials
and watch enrollment happen live in Step 4.

**Step 4 — Try the security patterns**

| Scenario | What it shows |
|---|---|
| **Search vs. Book** | The Search Agent can look up flights but its VP is rejected when it tries to book — scope enforcement, not a role flag in a database. |
| **Delegate to a Sub-Agent** | The Concierge Agent delegates a reduced, time-boxed credential to a search sub-agent. The sub-agent can search, but can't book — even though it inherited from an agent that could. |
| **Revoke Mid-Flight** | An operator revokes the Concierge Agent's credential while it's active. Its very next request is rejected — no key rotation, anywhere. |
| **Onboard a New Agent, Live** | From the Console, mint a bootstrap token and watch a brand-new agent enroll and receive its VC in real time — the only scenario that isn't pre-seeded. |

Every action above appears in real time in the **Console's audit panel**, so
you can watch exactly which credential authorized which action, and when.

---
