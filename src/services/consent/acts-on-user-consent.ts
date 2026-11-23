// KYA-OS story L3-H (follow-up): which agents act on user consent. Their
// Entity Cards leave `responsibleParty` out, so every chain's root is its own
// (Harish 2026-11-23: the responsible party is journey-specific; in a
// user-consent journey the user's pairwise did:key signs the root).
//
// An agent acts on user consent when a consent request ever named it, or when
// it is the invoker of any hop in a chain rooted at a user's did:key: an agent
// that received a hop forwarded under someone's consent acts on that consent
// as much as the agent the user consented to.

export interface ActsOnUserConsentDeps {
  consents: {
    hasRequestForAgent(agentDid: string): Promise<boolean>;
    findUserKey(did: string): Promise<unknown | null>;
  };
  credentials: { rootIssuersOfHopsTo(agentDid: string): Promise<string[]> };
}

export function actsOnUserConsent(deps: ActsOnUserConsentDeps): (agentDid: string) => Promise<boolean> {
  return async (agentDid) => {
    if (await deps.consents.hasRequestForAgent(agentDid)) return true;
    for (const issuer of await deps.credentials.rootIssuersOfHopsTo(agentDid)) {
      // Users get did:key only; a did:key root is a user's when it is one of the consent keys.
      if (issuer.startsWith('did:key:') && (await deps.consents.findUserKey(issuer)) !== null) return true;
    }
    return false;
  };
}
