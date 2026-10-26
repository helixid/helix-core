---
'@helixid/core': minor
---

Consent grants are bound to their service and to the agent's own scopes.

- `verifyVP`: a grant must be issued by the VP's `targetService` (`CONSENT_GRANT_WRONG_SERVICE`); a grant to a delegating agent with `allowDelegation: false` does not cover its delegates (`CONSENT_GRANT_NOT_DELEGABLE`); a grant to an ancestor is intersected only with the credentials delegated from that ancestor, so a delegate's own onboarding credential no longer widens it.
- Grant issuance refuses scopes outside the agent's own (non-delegated) credential scopes (`CONSENT_GRANT_SCOPE_NOT_ALLOWED`) and grants of only `accept-terms` (`CONSENT_NO_GRANTABLE_SCOPES`), and accepts `allowDelegation`.
- New `GET /v1/service-delegation-grants/agent-scopes?serviceDid=&agentDid=` (authorized as `agentScopes`).
- `signVP` no longer inherits a delegator's grant that has `allowDelegation: false`.
