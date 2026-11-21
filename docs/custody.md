# Key custody and DID hosting

KYA-OS story F-3. Every agent, service and owner on Helix makes two choices, independently, in any combination.

| Choice | `self` / `own` | `helix` |
| --- | --- | --- |
| Key custody (`keyCustody`) | The private key is generated and kept on your side. The SDK signs through its Signer. Helix only ever sees the public key. | Helix generates the key, keeps it in its key store, and signs for you when you ask. |
| DID hosting (`didHosting`) | Your did:web lives on your own domain. You publish `did.json` and `card.json` there. | Your did:web lives under the Helix domain. Helix serves the documents. |

## What `custody: helix` means for conformance

The KYA-OS spec (SPEC §4.5) says an implementation that holds an agent's key is not conformant for that agent. So every agent, service or owner whose key Helix holds is labelled `custody: helix`. It is left out of every Core and Card conformance claim. `GET /v1/conformance/report` lists it under `excluded`.

Verifiers still accept its proofs. A key is a key, and the label is about what Helix may claim, not about whether the proofs hold.

Self-custody (`custody: self`) is the conformant tier. Only self-custody subjects appear in the report's `claimSet`.

## Defaults

An account can set a preference, `custody.defaultKeyCustody` and `custody.defaultDidHosting`. New agents and services use it unless they choose otherwise. Existing ones keep their custody. The hosted build stores the preference per account (`GET` / `PUT /v1/account/custody`).

A build without accounts has no preference. Its default is self-custody on Helix hosting.

## Onboarding

Self-custody, with an enrollment token:

1. `POST /v1/agents` with `keyCustody: "self"` returns an enrollment token.
2. `helix init --token <token> --out <dir>` generates the key on your host and registers only the public JWK, with a proof of possession. It writes `did.json`, `card.json`, `signing-key.env` (the private key, mode 0600) and `helix-agent.json` to `<dir>`.
3. With Helix hosting the agent is active at once. With your own domain, publish the two documents, then run `helix activate`. Helix reads them from your domain and activates the agent only when they list the key you registered.

Full custody is one call: `POST /v1/agents` with `keyCustody: "helix"`. The agent signs through `HelixCustodialSigner`, which calls `POST /v1/agents/{did}/sign`. Application code is the same in both modes. Only the line that builds the Signer differs.

Services take the same choice on `POST /v1/services`. Owners, whose keys sign capability attestations, use `POST /v1/owners`.

## Changing custody

`POST /v1/agents/{did}/custody` with the other `keyCustody` is a key rotation:

- the new key is generated in the new place (with `helix custody take` on your host for a change to self);
- the DID document lists both keys during the overlap (default 24 hours), so proofs made before the change still verify;
- the key Helix held is shredded at once when you take custody yourself;
- delegation hops bound to the old key are reissued in story C-E. F-3 calls the reissue seam and reports that it is pending;
- when the overlap ends (`POST .../custody/finalize`), the old key is revoked and leaves the document.

## Where the keys are

Helix-held private keys live in `wrapped_keys`, each wrapped with AES-256-GCM under the key-encryption key `HELIX_KEY_STORE_KEK`, behind the `KeyStore` interface. No code reads a private key from a table directly. A KMS-backed key store is planned for phase 4.

For a self-custody subject, Helix stores no private key at all. Requests that carry private key material are refused.

## Audit

Every custody choice, activation, change, key revocation and shred, and every custodial signature or refused signature, is an audit event naming the actor and the agent, service or owner. A custodial signature is recorded by the digest and length of what was signed, never the bytes.
