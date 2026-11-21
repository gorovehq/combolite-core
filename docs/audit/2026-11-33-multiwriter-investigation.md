# Root-cause investigation — #33 "multi-writer DB becomes unopenable (CDB_E_CORRUPT)"

Audit anchor: `cdb_db.c:1762-1766`, 2026-11 completeness audit, triaged
`remediate(investigate)` with **doc symptom / UNDOC root**. This is the record of
the investigation the audit asked for (FR2 / AC4), and the verdict.

## TL;DR

- The design's **primary hypothesis is wrong**: `cursor_open` line 944
  (`c->have && c->unsealed > committed_seq → set_aside`) is **unreachable** — a
  journal's `unsealed_seq` is **never** greater than the archive's
  `committed_seq`, by a monotonicity invariant (proof below). It was observed
  `unsealed == committed` in every constructed state.
- The symptom the issue literally names — a slot carrying `CDB_COORD_JOURNAL`
  whose cursor is **"not `usable` nor `set_aside`"** — is the `!exists` case:
  the in-use journal **file is absent**. The only reachable instance of that is
  **genuine loss** (the journal held committed, un-folded data), which the
  fail-closed `CDB_E_CORRUPT` at `cdb_db.c:1768` and `cdb_db.c:1135` handles
  **correctly**.
- The *recoverable-but-rejected* variant (flag set, journal absent, **but its
  data already folded into a sound archive**) is **prevented by the cleanup
  ordering**: the slot's `CDB_COORD_JOURNAL` flag is cleared / the slot removed
  **durably (synced) before** the journal file is removed. So "flag set +
  journal absent" cannot arise from a crash.
- **Evidence:** 180 adversarial power-cut crash points (DROP_UNSYNCED / TORN /
  REORDER × 60 I/O ops) injected across the exact fold-and-retire reconcile
  produced **zero** false rejects (`tests/test_multiwriter_open.c`, test 4).
- **Verdict (AC14 terminal):** the fail-closed at `cdb_db.c:1762-1766` is
  **correct** for every reachable state; the suspected data-loss defect is **not
  reproducible** through any legitimate multi-writer / crash sequence. Per the
  task's explicit instruction, **no speculative fix is committed** — an
  over-permissive change here would trade a non-existent false-reject for real
  false-accept / silent data loss (ideation §7, the cardinal risk). The
  deliverable is this analysis plus a deterministic regression oracle that goes
  red if the protective ordering ever regresses.

## What the fail-closed site actually is

```c
/* cdb_db.c, non-alone open path (take over a slot while a peer is live) */
if ((s = cursor_open(db, db->coord.me.slot, &c, &usable)) != CDB_OK)
    return s;
if ((db->coord.me.flags & CDB_COORD_JOURNAL) && (!usable || db->set_aside)
    && !(db->cfg.flags & CDB_DB_ACCEPT_LOSS))
    return CDB_E_CORRUPT;                 /* <- 1762-1766 */
```

`cursor_open` reports `usable = 0` in exactly these ways:

| cause in `cursor_open` | `set_aside`? | reachable meaning |
|---|---|---|
| journal file `!exists` (line 925) | no | journal in use but **missing** |
| header corrupt/unsupported/malformed (928) | yes (`.stray`) | unreadable journal |
| `foreign` db_id / slot (937) | yes | another database's journal |
| `c->have && c->unsealed > committed_seq` (944) | yes | journal needs a newer archive |

The issue's phrase "not `usable` **nor** `set_aside`" ⇒ the first row only:
**journal missing**.

## Proof 1 — `unsealed > committed_seq` is unreachable (refutes the design)

A journal's `unsealed_seq` is fixed at creation:

- `start_session` (`cdb_db.c:1278`): `new_journal(..., committed_seq + 1)`, and
  its very next step is `cdb_pager_commit`, which advances the header
  `committed_seq` to exactly that `committed_seq + 1`. So after a *clean* start,
  `unsealed == committed`, and the journal is **empty**.
- `rebase_pages` / `rotate_journal`: `new_journal(..., committed_seq)` — equal by
  construction.

`committed_seq` is **monotonically non-decreasing** on disk (spec 3.2 step 4 is
the only writer of it, and it only ever raises it; a torn step-4 falls back to
the *previous, higher-or-equal* committed copy, never lower than any existing
journal's `unsealed`). Any journal was created when `committed` was some value
`C0`; its `unsealed ≤ C0 ≤ committed_now`. Therefore `unsealed > committed` can
never hold at any later open. Empirically, every reconstructed state showed
`unsealed == committed` (never `>`). Line 944 is effectively dead for the
purpose of this bug.

## Proof 2 — "flag set + journal absent" is prevented by cleanup ordering

A journal file is only removed by `merge_journals` cleanup, and only *after* its
data is folded and its slot is retired durably:

1. Fold: `apply_range` then `cdb_pager_commit` (`cdb_db.c:1194`) — the committed
   transactions and the moved reconciliation mark become durable (spec 3.2).
2. Clear the flag / retire the slot, **synced**:
   - own slot on recovery: `cdb_coord_set_journal(0)` (`cdb_db.c:1206`), whose
     body `set_journal_body` does `write_half` **+ `cdb_storage_sync`**;
   - a dead peer under `holding_all`: `cdb_coord_remove_slot`
     (`cdb_db.c:1229`), whose body removes the slot file **+ `sync_dir`**.
3. Only then remove the journal file (`env_remove`, `cdb_db.c:1222` / `1239`),
   followed by `env_sync_dir`.

Because step 2 is durable before step 3 begins, any crash leaves one of:

- *(after 1, before 2)* flag set **+ journal present** → reopen: `cursor_open`
  reads it, `scan_next` finds nothing above the moved mark (`have = 0`) →
  `usable = 1` → **opens**;
- *(after 2, before/at 3)* flag cleared / slot gone **+ journal maybe-absent** →
  reopen: no in-use flag → **opens**.

"Flag set **and** journal absent" is never a crash outcome. The only way to
manufacture it is to delete the journal by hand while forcing the flag to stay —
a state the system does not produce.

## Proof 3 — empirical, 180 adversarial crash points

`tests/test_multiwriter_open.c::test_fold_then_crash_matrix_no_false_reject`
drives two live writers, commits a transaction on the peer, crashes the peer,
then power-cuts the survivor's fold-and-retire reconcile at **every** I/O op
(1..60) under **all three** loss models (`DROP_UNSYNCED`, `TORN`, `REORDER`).
After each cut it reboots and reopens:

- `false_rejects == 0` — no crash ever left a sound, fully-folded archive that
  reported `CDB_E_CORRUPT` while the data was in fact present;
- crashes actually fired and reopens actually happened (anti-vacuity guards).

This is the **regression oracle**: if a future change removes the sync in
`set_journal_body`/`remove_slot_body`, or reorders the cleanup so the journal is
removed before the flag is cleared, this test turns **red** with exactly the #33
symptom.

## Reproduction attempts that did *not* trigger it (for the record)

All deterministic, hermetic, via `combolite_testing` fault env:

1. Fresh/alone writer commits, peer joins, writer crashes, slot taken over while
   peer live → **opens**, `unsealed == committed == 2`.
2. Overlay (non-fresh) writer commits, crashes, slot taken over → **opens**.
3. Reconcile crashed mid-operation (op 1..60), slot taken over → **opens**.
4. Reconcile *cleanup* crashed (killed-process model, op 1..60) → **opens**.
5. Two writers commit, power-cut both, reopen → **opens**, both values present.
6. Instrumenting the three `CDB_E_CORRUPT` return sites and running the **entire**
   `test_coord` / `test_fault_sweep` / `test_db*` suites: the only site ever hit
   is the merge path on `test_missing_peer_journal_refused` — the *correct*
   genuine-loss case (`usable=0 set_aside=0 have=0`, journal truly missing,
   nothing folded).

The single way `CDB_E_CORRUPT` appeared on a sound archive was by **directly
deleting** an already-folded journal file while leaving its slot flag set — i.e.
reconstructing the unreachable state of Proof 2 by hand. A fix that opened that
state would weaken the genuine-loss guard (`test_missing_in_use_journal_fails_closed`)
with no reachable benefit.

## Why no speculative fix

The only candidate fix is to make open/merge *tolerate* a missing in-use journal
when "the data is already folded." But at open, with the journal gone, there is
**no durable signal** that distinguishes *folded-and-retired* (safe) from
*lost* (unsafe) once the flag is set — the flag being set is itself the "not yet
fully retired" signal. Any heuristic that proceeds risks opening a genuinely
lost database (false-accept → silent data loss), which ideation §7 rates the
worst outcome and says to rate up under uncertainty. **Integrity > permissiveness.**

The protective invariant already lives in the right place (crash-safe cleanup
ordering, Proof 2). The correct remediation for #33's CRITICAL line is therefore
to (a) record that the fail-closed is correct and the suspected loss is
unreachable, and (b) lock the protective ordering behind the regression oracle —
both delivered here. If the project nonetheless wants the ordering made
*explicit and self-documenting* (defense-in-depth), that is a separate, small,
behaviour-preserving change to `merge_journals` comments/asserts; it is **not**
a change to the accept/refuse decision and is out of scope for a bugfix that
must show red→green.

## Files

- `tests/test_multiwriter_open.c` — 4 deterministic, hermetic tests (recoverable
  take-over opens without `ACCEPT_LOSS`; parallel-writer power-cut reopens;
  genuine-loss fails closed; 180-point crash matrix = regression oracle).
- `tests/CMakeLists.txt` — `cdb_add_test(test_multiwriter_open)` wiring.
- `src/*` — **unchanged**: no fix, per the AC14 terminal (do not guess a fix).
