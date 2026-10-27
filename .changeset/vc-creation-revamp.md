---
'@helixid/core': major
---

VC creation revamp.

Breaking:

- The prepare/finalize flow is gone: `PreparedPayloadService`, `IPreparedPayloadService`, `PreparedPayloadRepository` and `preparedPayloadRoutes` are no longer exported. Grants are issued through `ServiceProviderService` (`serviceProviderRoutes`), which signs server-side.
- `VPRepository`, `AgentKeyRepository` (`AgentKeyRecord`, `CreateAgentKeyRecordParams`) and `ServiceRegistryRepository` (`ServiceRegistryRecord`) are replaced by `DidKeyRepository`, `AgentRecordRepository` and `ServiceRepository`, with their record types exported alongside.

Added:

- `expireAt` is optional when onboarding an agent: without it the agent's credential stays valid until it is revoked.
- Service delegation grants can cover several agents at once, and `IssueDelegationGrantInput` / `DelegateAuthorityOptions` are exported.
- `ServiceProviderService.enrollService` / `generateServiceId` for registering services, and `DIDRouteAction` / `DIDRouteOptions` types for the DID routes.
- Audit events name the service on `VP_VERIFIED` and the claimed agent on `VP_REJECTED`.
