---
"@helixid/core": minor
---

`VP_VERIFIED` audit events now carry `targetService`, and `VP_REJECTED` events carry `attemptedHolderDid` and `attemptedTargetService`, read off the unverified presentation like the existing `attempted*` fields. A rejection could not previously be tied to an agent at all. `GET /v1/audit-log` returns the two new fields.
