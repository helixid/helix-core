# KYA-OS alignment

Status: **Not aligned.** Do not claim KYA-OS conformance or "standards-compliant" yet.

Reference: KYA-OS spec v1.0.0 / conformance v1.1.0, pinned at
`decentralized-identity/kya-os-mcp@6160620` — copies in [`references/kya-os/`](references/kya-os/).

## What KYA-OS is

A DIF (Decentralized Identity Foundation) standard from the Trusted AI Agents
Working Group — **not** a Linux Foundation spec. The "ratified" status is
self-reported in the repo; confirm with DIF before citing it externally.
Conformance is claimed per ladder (Core L1–L3, Card L1–L3, AAP-0–4) by passing
the vectors in `conformance/` through a `ConformanceAdapter`.

## Where we already agree

Same building blocks: Ed25519, `did:key`/`did:web`, W3C VCs, delegation chains
rooted at a responsible party, bitstring revocation, nonce + expiry on presentations.

## Gaps

| Area | Helix today | KYA-OS | Level |
|---|---|---|---|
| Canonicalization | Recursive key-sort + `JSON.stringify` (`vp-crypto.ts`) | RFC 8785 JCS | Core L1 |
| Signature format | `Ed25519Signature2020` proof over SHA-256 of canonical JSON | JWS compact, `alg: EdDSA` | Core L1 |
| Discovery | `/.well-known/did.json` only | `/.well-known/mcp`, Entity Card `/card.json` | Core L1 (rec.), Card L1 |
| Wire placement | `_helixVP` inside tool `input` (agent → server) | Detached proof in `_meta` over request/response hashes (server → agent) | Core L2 |
| Session | HS256 session JWT | `kyaos_` handshake, base64url nonce, ≤120s skew | Core L2 |
| Credential type | `HelixAgentCredential` / `DelegationGrantCredential` | `DelegationCredential` (subject = `id` + `delegation` only), CRISP scopes | Core L3 |
| Revocation | `BitstringStatusListEntry` | `StatusList2021Entry` | Core L3 |
| Consent | Grant VC flow | `needs_authorization` result with consent URL | Core L3 |
| Verification locus | Centralized: `/v1/vp/verify` on helix-server | Verifiable locally/offline by the MCP server | Core L3 |
| MCP extension | none | `org.kya-os/decentralized-authority` negotiation | negotiation vectors |

The last row matters most: KYA-OS assumes any server can verify without calling
an authority, which conflicts with [`proposal-sdk-api-only.md`](proposal-sdk-api-only.md).

## Path to alignment

Add a KYA-OS *binding* next to the existing Helix format rather than replacing it.

1. **Conformance adapter first.** Implement `ConformanceAdapter` over our
   verifier and run the pinned vectors in CI. This gives an objective gap list
   and is the only basis for any claim.
2. **Core L1.** Switch canonicalization to RFC 8785 JCS (also fixes the
   cross-SDK risk in `proposal-sdk-api-only.md`); add JWS/EdDSA signing;
   serve `/.well-known/mcp`.
3. **Core L2.** In `@helixid/mcp-middleware`, emit and verify detached proofs
   in `_meta` and implement the handshake/nonce rules.
4. **Core L3.** Issue/accept `DelegationCredential` alongside Helix VCs; accept
   `StatusList2021Entry` (keep Bitstring as ours); return `needs_authorization`.
   Decide whether local verification is allowed — L3 is not reachable otherwise.
5. **Claim narrowly.** Only after vectors pass, e.g. "KYA-OS Core L2 conformant
   (DIF TAAWG, suite vX)".
