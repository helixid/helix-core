// KYA-OS story L3-H follow-up: which agents act on user consent (their cards
// leave responsibleParty out), now including an agent given a hop forwarded
// under a user's consent.
import { describe, expect, it, vi } from 'vitest';
import { actsOnUserConsent } from '../../../../src/services/consent/acts-on-user-consent.js';
import { AGENT, OTHER_AGENT, consentWorld } from './harness.js';

describe('actsOnUserConsent', () => {
  it('covers the agent a consent request named, and an agent given a hop forwarded under that consent', async () => {
    const world = consentWorld();
    const { approved } = await world.consentTo();
    // AGENT forwards a hop under the user's root to OTHER_AGENT (Helix signs it with AGENT's key).
    world.credentials.attachCustodialKeys({ signerFor: async (did: string) => (did === AGENT.did ? AGENT.signer : undefined) } as never);
    const forwarded = await world.credentials.issueHop(approved.hop.id, { invoker: OTHER_AGENT.did, allowedAction: approved.hop.credentialSubject.allowedAction as string[] }, 'r');
    expect(forwarded.chain[0]!.issuer).toBe(approved.hop.issuer);

    expect(await world.credentials.rootIssuersOfHopsTo(OTHER_AGENT.did)).toEqual([approved.hop.issuer]);
    const acts = actsOnUserConsent({ consents: world.repo, credentials: world.credentials });
    expect(await acts(AGENT.did)).toBe(true);
    expect(await acts(OTHER_AGENT.did)).toBe(true);
    expect(await acts('did:web:helix.example:agents:nobody')).toBe(false);
  });

  it('a chain rooted elsewhere (an organization, or a did:key that is no user key) does not count', async () => {
    const consents = { hasRequestForAgent: vi.fn(async () => false), findUserKey: vi.fn(async () => null) };
    const credentials = { rootIssuersOfHopsTo: vi.fn(async () => ['did:web:accounts.example:accounts:org-a', 'did:key:z6MkOwnerKeyNotAUserKey']) };
    expect(await actsOnUserConsent({ consents, credentials })(AGENT.did)).toBe(false);
    expect(consents.findUserKey).toHaveBeenCalledTimes(1);
    expect(consents.findUserKey).toHaveBeenCalledWith('did:key:z6MkOwnerKeyNotAUserKey');
  });

  it('a root hop given directly counts its issuer once, whatever the number of hops', async () => {
    const world = consentWorld();
    const { approved } = await world.consentTo();
    await world.consent.renewHop(await world.renewalJws({ consentId: approved.consentId }), 'r');
    expect(await world.credentials.rootIssuersOfHopsTo(AGENT.did)).toEqual([approved.hop.issuer]);
  });
});
