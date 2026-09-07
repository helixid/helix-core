import { afterAll, beforeAll, describe, it } from 'vitest';
import {
  resetLiveTestDatabase,
  startLiveApi,
  type LiveApi,
} from '../utils/liveApi.js';

// Agent-to-agent delegation (a "sub-agent") — distinct from the consent-grant
// flow: here the delegator is itself an onboarded agent, delegating a subset
// of its own privilege scopes to another agent it controls.
//
// SKIPPED — known gap from the server-custody migration, not yet a design
// decision: the SDK's delegate() needs the delegator's real private key to
// sign the sub-agent's VC (previously: AgentWallet.load(walletPath, ...)),
// and under server custody there is no wallet file and no local key to load.
// Unlike VP-signing (AgentService.signVP, an agent presenting something),
// this is an agent *issuing* a credential to another agent — a materially
// different, new capability (something like AgentService.signDelegationVC(),
// a KeyCustody-backed VC-issuance path) that hasn't been designed or built.
// Re-enable once that capability exists and this test is rewritten against
// it — the two `it.todo`s below are placeholders, not real coverage.
describe.skip('Agent Delegation Live Integration', () => {
  let api: LiveApi;

  beforeAll(async () => {
    await resetLiveTestDatabase();
    api = await startLiveApi();
  });

  afterAll(async () => {
    await api?.stop();
  });

  it.todo('lets a delegated sub-agent present a VP whose delegationChain shows the parent');

  it.todo("rejects delegation past the parent VC's maxDelegationDepth");
});
