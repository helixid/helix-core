---
"@helixid/core": major
---

Release the changes accumulated on `main` since the last npm publish (1.0.0) that were never pushed to npm:

- Retire agent self-custody: server-side keygen, DB-held keys, no wallet file — this removes the self-custody API surface, hence the major bump
- Add custodial agent-to-agent delegation
- Add `ACCOUNT_AUTH_REQUIRED` / `ACCOUNT_FORBIDDEN` error codes
- Hold SP-issued consent credentials on the platform
