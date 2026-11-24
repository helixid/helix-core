// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Package barrel for @helixid/core. A downstream product (self-hosted OSS
// server, or a hosted/enterprise build layering accounts/multi-tenancy on
// top) imports everything it needs from here — never from sub-paths, so
// this file is the actual, enforced surface of the package.

export * from './core/index.js';

export { errorHandler } from './middleware/errorHandler.js';
export { registerRequestLogger } from './middleware/requestLogger.js';

export * from './audit/index.js';

export type { ICache } from './cache/ICache.js';
export { NoopCache } from './cache/NoopCache.js';
export { InProcessCache } from './cache/InProcessCache.js';
export { RedisCache, type RedisLike } from './cache/RedisCache.js';
export { TwoLayerCache } from './cache/TwoLayerCache.js';
export { createDidCache, createStatusListCache } from './cache/cacheFactory.js';

export { createHederaClient } from './hedera/createHederaClient.js';
export type { IHederaClient } from './hedera/IHederaClient.js';
export { DisabledHederaClient } from './hedera/DisabledHederaClient.js';
export { MockHederaClient } from './hedera/mock/MockHederaClient.js';

export { SqliteStore, sqliteLiteral } from './storage/sqlite.js';
export {
  UnsupportedStorageDriverError,
  type StorageDriverDeps,
  type StorageDriverKind,
} from './storage/driver-registry.js';

export { DidRepository } from './repositories/did.repository.js';
export { VcRepository } from './repositories/vc.repository.js';
export type {
  VCRecord,
  ListVcFilters,
  CreateVcParams,
  StatusListEntryRecord,
} from './repositories/vc.repository.js';
export { AgentRepository } from './repositories/agent.repository.js';
export type {
  EnrollmentTokenRecord,
  ChallengeRecord,
} from './repositories/agent.repository.js';
export { DidKeyRepository } from './repositories/did-key.repository.js';
export type {
  DidKeyRecord,
  DidKeySubjectType,
  CreateDidKeyRecordParams,
} from './repositories/did-key.repository.js';
export { ServiceRepository } from './repositories/service.repository.js';
export type { ServiceRecord, ServiceCreateData } from './repositories/service.repository.js';
export {
  AgentRecordRepository,
  AGENT_VISIBILITIES,
  AGENT_STATUS_FILTERS,
} from './repositories/agent-record.repository.js';
export type {
  AgentRecord,
  AgentCreateData,
  AgentCredentialState,
  AgentVisibility,
  AgentStatus,
  AgentStatusFilter,
  PublicAgentQuery,
  PublicAgentRow,
} from './repositories/agent-record.repository.js';

export { DIDService } from './services/did/did.service.js';
export type { IDIDService } from './services/did/did.service.js';
export { extractEd25519PublicKeyHexFromDIDDocument } from './services/did/publicKey.js';
export { VCService } from './services/vc/vc.service.js';
export type {
  IVCService,
  IssueVCParams,
  IssueVCResult,
  VCDetails,
  ListVCFilters,
  VCSummary,
  RenewVCOptions,
  ReconcileOptions,
  ReconcileResult,
} from './services/vc/vc.service.js';
export { AgentService, mapAgentError, hashToken } from './services/agent/agent.service.js';
export type {
  IAgentService,
  EnrollmentTokenResult,
  ChallengeResult,
  OnboardVerifyResult,
  OnboardWithCustodyResult,
  UserChallengeVerifyResult,
} from './services/agent/IAgentService.js';
export { CredentialService } from './services/credentials/credential.service.js';
// KYA-OS story L3-C: signed per-issuer status lists, revocation and the revocation signal.
export { StatusListPublisher, StatusListService, STATUS_LIST_LENGTH } from './services/status-lists/status-list.service.js';
export type { StatusListPublisherOptions, StatusListRepository, RevocationSignalSink, RevokeContext } from './services/status-lists/status-list.service.js';
export { RevocationService, REVOCATION_REQUEST_TYP } from './services/revocation/revocation.service.js';
export type { RevocationOutcome, RevocationRequestClaims, RevocationServiceOptions } from './services/revocation/revocation.service.js';
export { RevocationSignalPublisher, InProcessSignalBus, RedisSignalBus } from './services/revocation/signal-publisher.js';
export type { RevocationEvent, SignalBus, RedisPubSubLike, RevocationSignalPublisherOptions } from './services/revocation/signal-publisher.js';
export { publicDidResolver } from './services/revocation/public-resolver.js';
export type {
  AgentCredentials,
  CredentialStatus,
  CredentialStatusStore,
  CredentialVcRepository,
  IssueAttestationsInput,
  IssueHopInput,
  IssueIdentityInput,
  IssueRootHopInput,
  StoredCredential,
} from './services/credentials/credential.service.js';
export { CustodySigner } from './services/credentials/custody-signer.js';
export { AesGcmKeyCustody } from './services/key-custody/key-custody.js';
export type { IKeyCustody, EncryptedKeyMaterial } from './services/key-custody/key-custody.js';
export {
  ServiceProviderService,
  generateServiceId,
} from './services/service-provider/service-provider.service.js';
export type {
  IServiceProviderService,
  EnrollServiceInput,
} from './services/service-provider/service-provider.service.js';

export { default as didRoutes } from './routes/did/index.js';
export type { DIDRouteAction, DIDRouteOptions } from './routes/did/index.js';
export { default as didWebRoutes } from './routes/did-web/index.js';
export { default as vcRoutes, type VcRouteOptions } from './routes/vc/index.js';
export { default as statusListRoutes } from './routes/status-list/index.js';
export { default as verifyRoutes, helixStatusListIssuers } from './routes/verify/index.js';
export { default as revocationRoutes } from './routes/revocations/index.js';
export { default as eventRoutes } from './routes/events/index.js';
export type { VerifyRouteOptions } from './routes/verify/index.js';
export { default as agentRoutes, enrollmentOnboardingHandler } from './routes/agent/index.js';
// KYA-OS F-1 credential routes with a host authorize hook (F-3 parity: helix-server-enterprise mounts them account-scoped).
export { default as credentialRoutes, hopDelegate } from './routes/credentials/index.js';
export type { CredentialRouteAction, CredentialRouteOptions } from './routes/credentials/index.js';
export { default as entityCardRoutes, hostedUrls } from './routes/entity-card/index.js';
export type { EntityCardRouteOptions, EntityCardSource, EntityCardRecord } from './routes/entity-card/index.js';
export { createEntityCardSource, assertionKeyOf, attestedCardCapabilities, credentialCardDetails } from './services/entity-card/entity-card.source.js';
export type { EntityCardSourceOptions, EntityCardDetails, ActiveCredentialStore } from './services/entity-card/entity-card.source.js';
// KYA-OS story F-3: custody preference, KeyStore, custodial signing, conformance report.
export { default as custodyRoutes } from './routes/custody/index.js';
export type { CustodyAction, CustodyRouteOptions } from './routes/custody/index.js';
export * from './services/custody/custody.service.js';
export { CustodyRecheckScheduler, custodyRecheckSettings } from './services/custody/custody-recheck.js';
export type { CustodyRecheckSchedulerOptions, CustodyRecheckTarget } from './services/custody/custody-recheck.js';
export { CUSTODIAL_SIGNING_SUBJECTS } from './services/custody/custodial-keys.js';
export type { CustodialKeys, CustodialSigningSubject, CustodialSigningUse } from './services/custody/custodial-keys.js';
export { DbKeyStore, resolveKeyEncryptionKey, DB_KEY_STORE_ALGORITHM } from './services/custody/db-key-store.js';
export type { DbKeyStoreOptions, WrappedKeyTable, KeyEncryptionKeyConfig } from './services/custody/db-key-store.js';
export { CustodyAudit, payloadDigest } from './services/custody/custody-audit.js';
export { CUSTODY_AUDIT_CATEGORY } from './services/custody/custody-audit.js';
export type { CustodyActor, CustodialSigningRefusal, CustodyFactsSink } from './services/custody/custody-audit.js';
export { pendingHopReissuer, HOP_REISSUE_PENDING_NOTE } from './services/custody/hop-reissue.js';
export type { HopReissuer, HopReissueInput, HopReissueResult } from './services/custody/hop-reissue.js';
export { CustodyRepository, WrappedKeyRepository, CUSTODY_STATUSES } from './repositories/custody.repository.js';
export type { CustodyRecordRow, CustodyKeyRow, CustodyStatus, CustodyKeyLocation, CustodyKeyStatus, WrappedKeyRow } from './repositories/custody.repository.js';
export { default as auditLogRoutes, type AuditLogRouteOptions } from './routes/audit-log/index.js';
export { default as auditRoutes, requireAuditOperator, type AuditRouteOptions, type AuditSubmissionAuthorizer } from './routes/audit/index.js';
export { runAuditCli, verifyAuditLedgerExport, type AuditCliIo, type AuditLedgerExport } from './cli/audit.js';
export { default as sessionRoutes } from './routes/sessions/index.js';
export { default as serviceProviderRoutes } from './routes/service-provider/index.js';
export type { ServiceProviderAction, ServiceProviderRouteOptions } from './routes/service-provider/index.js';
// KYA-OS story L3-H: the root delegation signed by the user's did:key at consent.
export { default as consentRoutes, readCookie, type ConsentRouteOptions } from './routes/consent/index.js';
export { ConsentService, readUnsignedGrant, CONSENT_PAGE_COOKIE, DEFAULT_CONSENT_REQUEST_TTL_SECONDS, DEFAULT_MAX_CONSENT_WINDOW_SECONDS } from './services/consent/consent.service.js';
export type {
  ApprovedConsent,
  ConsentPage,
  ConsentRequestResult,
  ConsentRequestState,
  ConsentServiceInfo,
  ConsentServiceOptions,
  CreatedConsentRequest,
  RenewedHop,
  WithdrawnConsent,
} from './services/consent/consent.service.js';
export { UserKeyService, serviceUserRefOf, ORPHAN_USER_KEY_MS } from './services/consent/user-key.service.js';
export type { UserKeyServiceOptions, UserKeyRepository } from './services/consent/user-key.service.js';
export {
  CONSENT_REQUEST_TYP,
  CONSENT_RENEWAL_TYP,
  CONSENT_WITHDRAWAL_TYP,
  SIGNED_REQUEST_SKEW_SECONDS,
  MemoryJtiStore,
  signRequest,
  verifySignedRequest,
} from './services/consent/signed-request.js';
export type { JtiStore, SignedRequestClaims, SignedRequestOptions } from './services/consent/signed-request.js';
export { consentServiceDirectory, consentAgentScopes } from './services/consent/directory.js';
export { actsOnUserConsent } from './services/consent/acts-on-user-consent.js';
export type { ActsOnUserConsentDeps } from './services/consent/acts-on-user-consent.js';
export type { ServiceDirectorySources } from './services/consent/directory.js';
export { ConsentRepository, CONSENT_REQUEST_STATUSES } from './repositories/consent.repository.js';
export type {
  ConsentDisplay,
  ConsentRequestRow,
  ConsentRequestStatus,
  UnsignedRootGrant,
  UserConsentRow,
  UserKeyRow,
} from './repositories/consent.repository.js';
export { CONSENT_SQLITE_DDL } from './repositories/drivers/consent.drivers.js';
export type { CredentialCardOptions } from './services/entity-card/entity-card.source.js';
