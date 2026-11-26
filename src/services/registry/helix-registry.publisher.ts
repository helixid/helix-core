// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Registry v3 (2026-11-24): a deployment's side of publishing. When an agent
// onboarded here is discoverable (the "Make discoverable" choice, on by
// default) and active, or is made discoverable later, the deployment
// registers it with the Helix registry; when it is made not discoverable,
// revoked or deactivated, it asks the Helix registry to drop it.
//
// A registration is signed by the agent's own key. A custodial key is held
// here, so the deployment signs. A self-custody key is not: the holder signs
// and sends its own registration with the SDK (kyaos.registry.publish), and
// this logs that it is waiting for that.
//
// Best effort: a failure is logged and never fails the onboarding or change.
// On the Helix-hosted deployment there is nothing to do: it is the Helix
// registry, and lists its own agents itself.

import { base64UrlDecodeStrict, type Signer } from '../../core/index.js';
import { signRegistration } from './registration.js';
import { AGENT_REGISTRY_PATH, originOf } from './registry.js';

export type PublishOutcome = 'published' | 'is_helix_registry' | 'holder_signs' | 'failed';

export interface HelixRegistryPublisherOptions {
  /** This deployment's origin (API_BASE_URL). */
  deployment: string;
  /** The Helix registry's origin: helixRegistryOrigin(). */
  helixOrigin: string;
  /** The signer of a key held here, or undefined (self-custody, unknown). */
  signerFor(did: string): Promise<Signer | undefined>;
  fetch?: ((url: string, init?: RequestInit) => Promise<Response>) | undefined;
  log?: ((message: string) => void) | undefined;
}

/** "header.payload.<16 signature chars>…", decoded, for the log. */
export function describeRegistration(jws: string): string {
  const [header, payload, signature] = jws.split('.');
  const decode = (part: string | undefined): string => {
    const bytes = part === undefined ? undefined : base64UrlDecodeStrict(part);
    return bytes ? Buffer.from(bytes).toString('utf8') : '?';
  };
  return `${decode(header)} ${decode(payload)} signature ${(signature ?? '').slice(0, 16)}…`;
}

export class HelixRegistryPublisher {
  readonly deployment: string;
  readonly helixOrigin: string;
  private readonly fetch: (url: string, init?: RequestInit) => Promise<Response>;
  private readonly log: (message: string) => void;

  constructor(private readonly options: HelixRegistryPublisherOptions) {
    this.deployment = originOf(options.deployment);
    this.helixOrigin = originOf(options.helixOrigin);
    this.fetch = options.fetch ?? ((url, init) => fetch(url, init));
    this.log = options.log ?? ((message: string): void => console.info(`[registry] ${message}`));
  }

  /** True on the Helix-hosted deployment. */
  get isHelixRegistry(): boolean {
    return this.deployment === this.helixOrigin;
  }

  async publish(did: string): Promise<PublishOutcome> {
    if (this.isHelixRegistry) return 'is_helix_registry';
    let signer: Signer | undefined;
    try {
      signer = await this.options.signerFor(did);
    } catch {
      signer = undefined;
    }
    if (!signer) {
      this.log(`agent ${did} is discoverable; its key is not held here, so its holder registers it with the Helix registry (kyaos.registry.publish)`);
      return 'holder_signs';
    }
    try {
      const registration = await signRegistration(signer, { deployment: this.deployment, audience: this.helixOrigin });
      this.log(`registering agent ${did} with the Helix registry ${this.helixOrigin}: ${describeRegistration(registration)}`);
      const response = await this.fetch(`${this.helixOrigin}${AGENT_REGISTRY_PATH}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ registration }),
      });
      if (!response.ok) {
        this.log(`the Helix registry refused agent ${did}: ${response.status} ${await response.text()}`);
        return 'failed';
      }
      this.log(`the Helix registry lists agent ${did}`);
      return 'published';
    } catch (error) {
      this.log(`could not register agent ${did} with the Helix registry: ${error instanceof Error ? error.message : String(error)}`);
      return 'failed';
    }
  }

  /** Asks the Helix registry to drop the entry; it checks with this deployment first. */
  async withdraw(did: string): Promise<boolean> {
    if (this.isHelixRegistry) return false;
    try {
      const response = await this.fetch(`${this.helixOrigin}${AGENT_REGISTRY_PATH}/${encodeURIComponent(did)}`, { method: 'DELETE', headers: { accept: 'application/json' } });
      if (!response.ok) {
        this.log(`the Helix registry kept agent ${did}: ${response.status} ${await response.text()}`);
        return false;
      }
      this.log(`asked the Helix registry to drop agent ${did}`);
      return true;
    } catch (error) {
      this.log(`could not withdraw agent ${did} from the Helix registry: ${error instanceof Error ? error.message : String(error)}`);
      return false;
    }
  }
}
