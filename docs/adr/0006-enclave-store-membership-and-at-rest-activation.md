# 6. Enclave store membership and at-rest page-encryption activation (#72 CR5)

Date: 2026-11-27

## Status

Accepted (implementation in progress — slice 1 = A/membership, slice 2 = B/default sugar).

## Context

At-rest page encryption (M27, spec 12) is **mechanically complete but inert**. Everything
needed to encrypt a store's pages already exists on `main` (as of `1300e7f`):

- **Page hook** — `pager_seal_page` / `pager_open_page` (`src/cdb_pager.c`) AEAD-encrypt a
  page body on write and authenticate-decrypt on read **iff** `h->domain_id > 0` and an AEAD
  algorithm is configured. A `domain_id == 0` page takes the legacy CRC32C tamper-evident path
  byte-for-byte (the inert path). An enclave page whose tag fails authentication fails closed
  as `CDB_E_SECURITY` (ADR-0002 boundary, PR#84).
- **Key derivation** — `db_attach_enclave_keys` derives every enclave subkey (PAGE, CONTENT_HASH,
  INDEX, SEAL, REPL — the last two from audit #72 CR2) from the enclave's root key; keys are
  zeroized in `db_wipe_crypto`. CR3's `db_enclave_unwrap_stored_key` reads a persisted wrapped key.
- **Enclave lifecycle** — `cdb_db_create_enclave` / `cdb_db_open_enclave` populate the in-memory
  `db->enclaves[]` table (keys resolved from the app's `key_provider` via a `key_ref`; **no key
  material is persisted in the database** — least privilege, keys stay with the app/KMS).
- **Domain resolution** — `store_domain(db, store_id)` already returns a store's encryption
  domain as either **(a)** the store's persisted `cdb_store_info.domain_id` (catalog), or **(b)**
  `store_id` itself when an open enclave has `enclave_id == store_id` (a "self-enclave").
- **Record tagging** — the single central write path tags every record with
  `r.domain_id = store_domain(db, store_id)` (`cdb_db.c:2448`) and resolves the page key. This is
  **store-level, not per-model**: the cross-model "wire `domain_id` through every model's
  page-write path" worry in #72 is **mooted** — document / table / link / time-series / vector
  all flow through this one tagging site. Activation is a store-level setter, not a cross-model edit.

**The one missing link:** `cdb_store_info.domain_id` is persisted and read, but **no public API
sets it** — there is no way to assign a store to an enclave. So `store_domain` always returns `0`
and every page is written in plaintext. This ADR adds that assignment.

## Decision

Add store→enclave **membership** and a per-store **convenience default** layered over it.

### A — explicit enclave membership (the model)

```c
cdb_status cdb_db_store_set_enclave(cdb_db *db, uint64_t store_id, uint64_t enclave_id);
```

Assigns `store_id` to an **open** enclave, persisting `cdb_store_info.domain_id = enclave_id`
through the catalog. After this, `store_domain` path (a) returns the enclave id and new page
writes for that store are AEAD-encrypted. Several stores may share one enclave (one key domain).

**Fail-closed contract:**
- `enclave_id == 0` or `store_id` invalid → `CDB_E_INVALID_ARG`.
- enclave not open (`enclave_index(db, enclave_id) < 0`) → `CDB_E_SECURITY` (never assign a store
  to a domain whose key is not loaded — that would write pages under a key the session can't derive).
- store not found / dropped → `CDB_E_NOT_FOUND`.
- **store is non-empty** (has committed records) → `CDB_E_STATE`. Retroactively joining a store
  that already holds plaintext pages would leave a mixed plaintext/ciphertext store and imply a
  re-encryption pass. This slice **forbids** it (fail-closed, simple, no silent partial
  encryption); an online re-encrypt / crypto-shred pass is **deferred** (future issue). A store is
  joined while empty — at or right after create, before first write.
- when a principal context is active, the call is **RBAC-gated** via
  `cdb_db_check_perm(principal, enclave_id, WRITE/ADMIN)`; single-user embedded use (no principal)
  is allowed.

On reopen the application re-opens the enclave it needs (`cdb_db_open_enclave(enclave_id, key_ref)`)
and `store_domain` path (a) resolves the persisted membership — encryption resumes with no
further call. Keys are never read from the database.

### B — per-store convenience (the default)

```c
cdb_status cdb_db_store_set_encrypted(cdb_db *db, uint64_t store_id, const char *key_ref);
cdb_status cdb_db_store_open_encrypted(cdb_db *db, uint64_t store_id, const char *key_ref);
```

The ergonomic "just encrypt this store" path, implemented **as sugar over A**: `set_encrypted`
creates a **self-enclave** whose `enclave_id == store_id` (`cdb_db_create_enclave(store_id,
key_ref)`) and persists the membership; `open_encrypted` is `cdb_db_open_enclave(store_id,
key_ref)`. `store_domain` already resolves self-enclaves (path b), so a single call turns a store
into an encrypted store with a per-store key. This is the **default** surface callers reach for;
A is for sharing one key domain across several stores.

Same fail-closed contract (empty store, master key present, keys stay app-side).

## Alternatives considered

- **Per-model `domain_id` wiring** (the original #72 framing) — rejected: the central
  `store_domain` tagging already covers every model, so per-model edits are unnecessary churn and
  a larger edit surface for no benefit.
- **Persist the enclave key / key_ref in the DB for automatic reopen** — rejected: keys must stay
  with the app/KMS (least privilege; keys never touch the database file). The app re-supplies
  `key_ref` on open. Persisting
  a non-secret *key reference hint* for ergonomics is a possible future nicety, not this slice.
- **Allow joining a non-empty store with lazy re-encryption** — deferred: correct but needs an
  online re-encrypt / crypto-shred pass with its own fault-injection proof; out of scope here.
  This slice fails closed (`CDB_E_STATE`) instead of silently leaving a half-encrypted store.
- **Leave CR5 inert, close as foundation-complete** — rejected by the owner (the at-rest
  confidentiality is the point).

## Threat model (STRIDE — the store→enclave assignment boundary)

- **Spoofing / Elevation** — only a principal with WRITE/ADMIN on the enclave scope may assign a
  store to it (RBAC-gated when a principal context is active). Assigning to a not-open enclave is
  rejected, so a caller cannot bind a store to a domain whose key it does not hold.
- **Tampering** — an enclave page that fails AEAD authentication fails closed as `CDB_E_SECURITY`
  (existing boundary). Membership lives in the catalog, itself covered by the archive's integrity.
- **Information disclosure** — the whole point: pages of a joined store are AEAD-encrypted at
  rest; keys never touch the database file; plaintext/keys never logged. A non-empty-store join is
  forbidden so no store is left partly in plaintext under a false "encrypted" belief.
- **Repudiation** — the assignment is an ordinary committed catalog change (auditable like any
  schema change).
- **Denial of service** — bounded: the enclave table is fixed-size (`CDB_E_OVERFLOW` when full);
  one membership field per store; no unbounded growth.

Abuse cases become security tests: join-to-unopened-enclave rejected, non-empty-store join
rejected, tampered enclave page → `CDB_E_SECURITY`, inert (`domain_id==0`) store byte-for-byte
unchanged.

## Consequences

- One small, store-level, fail-closed API closes CR5 activation; no per-model edits.
- A store opts into encryption at create time; existing-store migration is explicitly deferred.
- The default (B) gives per-store keys with one call; A enables shared key domains across stores.
- Deferred (tracked as future issues): online re-encrypt / crypto-shred for non-empty stores;
  automatic enclave reopen from a persisted key-reference hint; the CR2 **REPL**-subkey consumer
  (encrypting CRDT replication slices) — the subkey is derived and available, its consumer is a
  separate slice.
