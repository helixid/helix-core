# @helixid/core

## 3.0.0

### Major Changes

- 1acfcaf: VC creation revamp.

  Breaking:

  - The prepare/finalize flow is gone: `PreparedPayloadService`, `IPreparedPayloadService`, `PreparedPayloadRepository` and `preparedPayloadRoutes` are no longer exported. Grants are issued through `ServiceProviderService` (`serviceProviderRoutes`), which signs server-side.
  - `VPRepository`, `AgentKeyRepository` (`AgentKeyRecord`, `CreateAgentKeyRecordParams`) and `ServiceRegistryRepository` (`ServiceRegistryRecord`) are replaced by `DidKeyRepository`, `AgentRecordRepository` and `ServiceRepository`, with their record types exported alongside.

  Added:

  - `expireAt` is optional when onboarding an agent: without it the agent's credential stays valid until it is revoked.
  - Service delegation grants can cover several agents at once, and `IssueDelegationGrantInput` / `DelegateAuthorityOptions` are exported.
  - `ServiceProviderService.enrollService` / `generateServiceId` for registering services, and `DIDRouteAction` / `DIDRouteOptions` types for the DID routes.
  - Audit events name the service on `VP_VERIFIED` and the claimed agent on `VP_REJECTED`.

### Minor Changes

- 97d8f2f: Consent grants are bound to their service and to the agent's own scopes.

  - `verifyVP`: a grant must be issued by the VP's `targetService` (`CONSENT_GRANT_WRONG_SERVICE`); a grant to a delegating agent with `allowDelegation: false` does not cover its delegates (`CONSENT_GRANT_NOT_DELEGABLE`); a grant to an ancestor is intersected only with the credentials delegated from that ancestor, so a delegate's own onboarding credential no longer widens it.
  - Grant issuance refuses scopes outside the agent's own (non-delegated) credential scopes (`CONSENT_GRANT_SCOPE_NOT_ALLOWED`) and grants of only `accept-terms` (`CONSENT_NO_GRANTABLE_SCOPES`), and accepts `allowDelegation`.
  - New `GET /v1/service-delegation-grants/agent-scopes?serviceDid=&agentDid=` (authorized as `agentScopes`).
  - `signVP` no longer inherits a delegator's grant that has `allowDelegation: false`.

## 2.0.1

### Patch Changes

- 2c98211: Bump dependencies to latest in-range (semver-compatible) versions.

## 2.0.0

### Major Changes

- dc59cf2: Release the changes accumulated on `main` since the last npm publish (1.0.0) that were never pushed to npm:

  - Retire agent self-custody: server-side keygen, DB-held keys, no wallet file — this removes the self-custody API surface, hence the major bump
  - Add custodial agent-to-agent delegation
  - Add `ACCOUNT_AUTH_REQUIRED` / `ACCOUNT_FORBIDDEN` error codes
  - Hold SP-issued consent credentials on the platform
