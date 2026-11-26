---
"@helixid/core": minor
---

Own-hosted agents get their credentials at enrollment. The identity credential and the capability attestations are issued when the agent's key is registered (`helix init`, or creation of a custodial own-hosted agent), not at activation, so the `card.json` returned then is final: the owner publishes it once and never republishes after activation. Activation, by the background re-check or `POST /v1/agents/:did/activate`, reuses those credentials. If issuing fails at enrollment, enrollment still succeeds and activation issues them as before.
