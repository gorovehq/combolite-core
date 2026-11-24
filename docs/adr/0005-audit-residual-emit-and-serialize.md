# ADR-0005: Wire the audit-trail residuals — REVISION/BATON emit sites and single-writer chain serialization

- **Status:** Accepted
- **Date:** 2026-11-24
- **Supersedes / Superseded by:** —

> Relates to issue #54 PART 1 (residuals F2/F3/F4), deferred from #37; design `.sdlc/design.md`.
> Extends the #37 governance-audit guard shape (`db_governance_audit`). Builds on the
> tamper-evident audit chain (`src/cdb_audit.c`) and the coordinator baton (`db->coord`).
> Scope guard: M27 enclave crypto (CR5 page encryption, CR2 SEAL/REPL subkeys, CR3 `unwrap_key`)
> is a separate effort and is explicitly **out of scope** here (see `docs/BACKLOG.md`).

## Context

#37 established a tamper-evident audit chain and wired emit+sign for `KEY_OP`, `SCHEMA`, and
`BATON` (reconcile-hold path only), with verify-on-read fail-closed (`CDB_E_SECURITY`). Three
fail-open residuals survived, each a gap in the **evidence** the chain is supposed to guarantee —
all confirmed reproducible in source:

- **F2 — REVISION defined but never emitted.** `CDB_AUDIT_REVISION` (type 2) and
  `CDB_AUDIT_CUSTOM` (type 6) exist in `cdb_audit.h` but **no** `cdb_audit_log` call emits either.
  Document/table revisions — the most common write — leave no audit record (Repudiation; an
  attribution/Elevation gap mirroring the #37 A09 governance hole).
- **F3 — BATON audited only on one of several acquisition sites.** Only `cdb_db_reconcile` emits
  `BATON`; `db_reclaim_in` and `db_compact_in` take the baton via `reconcile_hold` **silently**, so
  a store-move/reclaim that seizes the single-writer token is unlogged (Repudiation).
- **F4 — chain append not single-writer-serialized.** `cdb_audit_log`'s
  `reload_head → hash → sign → index_put → update-head` sequence is separable; its own comment
  flags that two un-reconciled concurrent writers could interleave appends and **fork/corrupt** the
  hash chain, which verify-on-read would later reject as non-evidence (Tampering/Repudiation).

This alters a security trust boundary (what the audit chain attests) and a concurrency/crash-safety
guarantee (append atomicity against the chain head), which is exactly the ADR-filing bar in
`docs/adr/README.md`.

## Decision

Wire each residual at its **real source site**, reusing the #37 pattern, with no public-API churn.

1. **F2 — one REVISION per committed revisioning transaction, live path only.** Emit in
   `tx_commit_locked` *after* the commit record is durable, gated on a per-tx flag
   `db->tx_has_revision` (reset in `tx_begin`; set at the delta-stage site when a mutated
   `store_id` resolves to a document/table store). Reuse `db_governance_audit(... CDB_AUDIT_REVISION
   ...)` (add `CDB_GOV_SUBOP_REVISION`): emit iff `has_catalog`; principal = real identity **or 0**
   when none (never gate on `has_identity` — that would re-open the #37 governance-no-principal
   hole); best-effort (a failed append never fails or undoes the commit). The **replay/recovery
   apply path is deliberately not a site** (it re-runs → would double-emit).
2. **F2 — CUSTOM is caller-driven.** `CDB_AUDIT_CUSTOM` is reachable through the existing public
   `cdb_audit_log(event_type = CDB_AUDIT_CUSTOM)` as the application-governance/health hook; no
   internal origin site and no new wrapper this run. Documented so the type is not a silent dead
   value.
3. **F3 — BATON on the not-held→held edge at every acquisition site.** In `db_reclaim_in` and
   `db_compact_in`, sample `acquired = !cdb_coord_baton_held(&db->coord)` *before* `reconcile_hold`
   and, on overall success, emit iff `acquired`. A standing-baton (re-entrant) op → `acquired==0` →
   no double-emit.
4. **F4 — serialize the append inside `cdb_audit_log` on the coordinator baton.** Bracket
   reload-head → … → update-head under the single-writer token: if the caller already holds the
   baton (reconcile/reclaim/compact/key-rotation) append directly; else take-around-then-release
   (release only what we took). **Fail-closed:** on token denial (another live coordinator holds the
   baton, or there is no joined coordinator) the append falls back to the existing reload-head floor
   — best-effort, writing only to this writer's private pager, so it **never drops the event and
   never forks the shared chain** (the floor is retained, not removed). No signature change to
   `cdb_audit_log`. **Oracle (honest scope, #40 FR1):** the committed red→green asserts the
   *serialization invariant* — a non-holder's append must **acquire the exclusive baton** (observably
   taken from the prior holder) — not a replayed chain *break*. In the single-writer coordinator
   model every *persistent* append already runs while holding the baton (a sole coordinator holds it
   from open; governance ops hold it mid-committing-session) and un-reconciled overlay appends are
   discarded on reconcile, so a deterministic single-thread *corruption* is unreachable; a genuinely
   simultaneous interleave is only an OS-thread data race (non-deterministic, out of a deterministic
   gate's scope). The baton bracket makes the single-writer discipline **explicit and enforced** at
   the append site so it cannot silently regress.
5. **F5 — verify-on-read unchanged.** Stays fail-closed (`CDB_E_SECURITY`), bound to the reader's
   active key. Per-signer key registry remains a follow-up (BACKLOG).

## Alternatives considered

- **F2 emit per `apply_change` / in the apply path.** Rejected: double-emits on recovery replay and
  multiplies events per batched transaction, breaking the deterministic "exactly one per revision."
- **F2 gate on `has_identity` (skip when no principal).** Rejected: silently un-audits
  governance-mode-without-principal — the precise #37 A09 regression. Principal-0 unattributed emit
  is strictly more evidence.
- **F4 serialize at each caller** (take the baton around every `cdb_audit_log` call site).
  Rejected: churns every caller, easy to miss the baton-less `tx_commit_locked` REVISION site, and
  risks a second take by callers that already hold the baton (deadlock). Serializing *inside*
  `cdb_audit_log` with take-if-not-held covers all sites uniformly and cannot deadlock against
  reconcile/reclaim/compact (they append directly).
- **F4 a dedicated audit mutex** instead of the existing baton. Rejected: introduces a second
  single-writer discipline to reason about and a new lock-ordering hazard against the baton; the
  baton is already the archive's single-writer token and is already held by the heavy writers.

## Consequences

- **Pro.** The chain now records what it was designed to attest (revisions + all baton seizures),
  with correct attribution (real-or-0). Append is atomic against the chain head, so a forked head is
  **unreachable** rather than detected-after-the-fact on read. No public API or on-disk format
  change; `cdb_audit_log`'s signature is stable, so no caller churn. Each fix is a red→green oracle
  (`tests/test_audit_{revision_f2,baton_f3,serialize_f4}.c`): red on the pre-fix merge-base, green
  after the source edit (anti-no-op per #40 FR1).
- **Con / bound.** F4 adds a take-if-not-held baton op on the baton-less append path; on the common
  paths the caller already holds the baton (sole coordinator, or a governance op mid-session) so it
  is a no-op there. On token denial the append uses the reload-head floor (private-pager, best-effort)
  rather than dropping or forking — completeness and integrity preserved on the degraded path. The
  deterministic oracle proves the serialization *invariant* (exclusive-baton acquisition), not a
  flaky chain break; a true simultaneous interleave is an OS-thread race left to a non-deterministic
  stress harness. CUSTOM remains origin-less by design until an application hook needs it.
- **Follow-ups (BACKLOG).** Per-signer key registry for verify-on-read (F5); M27 enclave crypto
  (CR5/CR2/CR3) as its own cross-model effort.
