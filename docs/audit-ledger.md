# Audit ledger (KYA-OS AAP-2 Chained)

Story A-2 makes the audit log a chained, receipted ledger. Every audit event,
the API's own and every producer's (middleware, SDKs), enters through one
authoritative recorder, which assigns the epoch, the sequence, the predecessor
digest and the service time, and signs a receipt with its own key. Producers
send a frozen event and never choose any of those.

## Pieces

| Piece | Where |
|---|---|
| Recorder (one authority per ledger epoch) | `src/core/audit/recorder.ts` (`AuditRecorderService`) |
| Managed recorder (a ledger per tenant, epochs, transitions) | `src/core/audit/managed-recorder.ts` |
| Journal contract and memory journal | `src/core/audit/journal.ts`, `src/core/audit/contract.ts` |
| PostgreSQL journal and vault | `src/audit/postgres-journal.ts`, `src/audit/postgres-evidence.ts`, migration `20261121120000_audit_recorder_journal` |
| SQLite journal and vault (self-hosted single file) | `src/audit/sqlite-journal.ts`, `src/audit/sqlite-evidence.ts` |
| Retention (legal hold, release, disposal) | `src/core/audit/retention.ts` |
| Verify walk and CLI | `src/core/audit/ledger-verify.ts`, `src/cli/audit.ts` (`helix-audit`) |
| HTTP | `src/routes/audit/index.ts` (`/v1/audit`), `src/routes/audit-log/index.ts` (`/v1/audit-log`) |

## Configuration

| Variable | Meaning |
|---|---|
| `AUDIT_RECORDER_SIGNING_KEY` | The recorder key (Ed25519, hex). Required in production; must differ from `HELIX_SIGNING_KEY`. Unset elsewhere, a per-process key is generated and every restart opens a `key_rotation` epoch. |
| `AUDIT_RECORDER_DID`, `AUDIT_RECORDER_KID` | The recorder's DID and key fragment; default the `did:key` of the recorder key (verifiable offline). |
| `AUDIT_RECORDER_MODE` | `managed` (default): a ledger per tenant that submits. `self-hosted`: only the tenants in `AUDIT_RECORDER_TENANTS` (a JSON array of party references; default this API's own tenant). |
| `AUDIT_RECORDER_WITNESS_PATH` | The restore witness file (default `./data/audit-recorder-witness.json` for a durable journal). Keep it off the database's volume. |
| `AUDIT_RETENTION_MIN_DAYS` | A disposal floor on top of the longest delegation lifetime (default 0). |

## Append-only, enforced twice

There is no update or delete path in code. In the database, triggers refuse
`UPDATE`, `DELETE` and `TRUNCATE` on the journal, refuse an insert that is not
the next entry of an active epoch, let an epoch head only advance by one onto a
stored entry or be sealed once, and let an evidence row change only by having
its ciphertext disposed (never while an object-level hold is active). A
superuser can disable triggers; `helix-audit verify` is what detects that.

## Epochs

Failover, recorder key rotation, retention rollover and restore each seal the
active epoch at its committed head and open a successor whose genesis commits
the previous epoch id and terminal digest. A restore is a transition, never a
rewind: no entry is ever signed again at a receipted sequence.

- Key rotation and restore start on their own when the recorder opens a ledger:
  a recorder key other than the active epoch's opens `key_rotation`; a journal
  behind the restore witness (or holding another digest at the witnessed
  sequence) opens `restore`. A running recorder whose journal answers a head
  below one it committed fails closed with `AUDIT_JOURNAL_FAILURE`.
- Failover and retention rollover are operator commands:
  `POST /v1/audit/ledgers/:ledgerId/epochs {"reason": "failover" | "retention_rollover" | "key_rotation" | "restore"}`.
  A rollover by the same authority closes its epoch with `ledger.epoch.transitioned`.
- The terminal digest is computed from the chain head for now (domain
  `org.kya-os.audit.checkpoint.v1` over `urn:helix:audit:terminal-head:v1`);
  story A-3 replaces it with the signed RFC 9162 checkpoint digest.

## Retention

Retained indefinitely by default: nothing expires on a timer. The only removal
is an explicit disposal (`POST /v1/audit/ledgers/:ledgerId/disposals`), which
removes evidence ciphertext and never the entry or its commitment, so history
still verifies. Disposal is refused under an active legal hold on the ledger,
the entry or the object, and for anything younger than the retention floor (the
longer of `AUDIT_RETENTION_MIN_DAYS` and the longest delegation lifetime;
unbounded while any delegation has no expiry). Holds
(`POST /v1/audit/ledgers/:ledgerId/legal-holds`), releases
(`POST /v1/audit/legal-holds/:holdId/release`), disposals and refused disposals
are all recorded in the ledger.

## Verify command

```bash
pnpm audit:verify --ledger <ledgerId> --database-url "$DATABASE_URL" --trusted-recorder <recorder DID>
```

Sources: `--database-url`, `--sqlite <file>`, `--file <export.json>` (from
`helix-audit export`), or `--api <url> --admin-key <key>` (the API's export
endpoints, verified locally). It walks the ledger epoch by epoch and stops at
the first broken link (sequence and reason). Exit 0: verifies; 1: broken; 2:
usage or input error. Pin recorder keys with `--trusted-recorder`; without
them the receipts are checked against the recorders the ledger names, and a
warning says so.

## Running the tests against PostgreSQL

```bash
pnpm --dir ../e2e-playwright db:up
AUDIT_JOURNAL_DATABASE_URL=postgresql://helix:helix@localhost:5544/helix_e2e_test pnpm vitest run tests/integration/audit
```

Each test migrates its own schema in that database and drops it afterwards.
