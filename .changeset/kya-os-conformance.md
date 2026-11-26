---
"@helixid/core": major
---

KYA-OS conformance. Breaking: VP issuance and verification are removed; agents prove each call with a KYA-OS request proof, and `POST /v1/verify` runs the KYA-OS verifier. The service delegation-grant and agent-scopes routes are removed; the root delegation is signed by the user's did:key at consent (L3-H).

Added: client-generated agent keys and did:web documents (`did:web:<domain>[:<kind>]:<hex>`), identity VC and per-scope attestations, Entity Cards, custody preference (self-custody or custodial, `KeyStore`) with custody audit facts, typed audit events with a recorder and journal, status lists with cascading revocation and signed revocation signals, key rotation and revocation (`reissueHop`), forward delegation with `maxDelegationDepth`, the Helix agent registry ("Make discoverable"), the account DID as each agent DID's `controller`, and Helix refusing to sign for a revoked agent (403 `AGENT_REVOKED`).
