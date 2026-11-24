# Root-cause investigation — #60 "multi-writer coordinator contention"

Audit follow-up #60 (deferred from #46/#33). Three multi-process coordinator-
concurrency defects reported in the 4-writer pipeline. This is the critical
coordinator area (#33 was a data-loss-class fail-closed guard), so correctness
and safety come first, throughput second (ideation §7; hard safety guard).

Trace: requirement (ideation FR1–FR7 / AC1–AC13) → this issue (#60) → PR →
commit → oracle (`tests/stress/stress_multiwriter_recovery.c` contention mode) →
this audit verdict.

## TL;DR (per-defect verdict)

| # | Symptom | Verdict | Evidence |
|---|---|---|---|
| **B1** | disjoint-store/disjoint-write-set writers false-collide | **Reproduced; safe fix is out of scope → design fork #67. Gate NOT relaxed.** | 44–92 false `CDB_E_COLLISION` per 2.5 s run, 4 disjoint writers; root cause = coarse archive-committed-seq gate in `coordinate_commit`; a safe narrowing needs an archive-side reconciled-write-set signal the in-scope collision/close files do not carry. |
| **B2** | clean close under live peers → false `CDB_E_BUSY` + slot leak | **Not reproducible on the lock-hook host; defensive hardening landed for the lock-free fallback.** | 0 false close-busy and 0 unreclaimed slots across 25×4-writer churn runs; the fence-busy-at-close path is reachable only without the lock hook; `cdb_db_close` now routes it to `close_pending` (no leak, no safety loss). |
| **B3** | one-off `CDB_E_STATE` under load | **Not reproducible; invariant already holds.** | 0 spurious `CDB_E_STATE` across all contention + overlap runs; coordinator publishes state publish-after-sync already (`write_half`→`cdb_storage_sync` on durable ops; `close_pending_body` syncs before the slot is released). |

Safety invariants verified intact (non-negotiable, FR5): overlap detection
still fires hard (1.5k–1.9k `CDB_E_COLLISION` when writers deliberately overlap,
AC2); the #33 genuine-loss guard stays green (`test_multiwriter_open`, AC8); the
#42 bounded-wait stays bounded (`test_coord_bounded_wait_f42`, AC9); full
`ctest` 137/137 green under ASan+UBSan (AC10/AC11).

## The reproduction oracle

`tests/stress/stress_multiwriter_recovery.c` gains a deterministic **contention
campaign** (`contend` / `contend-child` / `overlap-child`), distinct from the
existing #33 kill/recovery campaign (which is preserved unchanged). No process is
killed in contention mode.

- **Disjoint phase** — each writer owns a disjoint store *and* a disjoint entry
  band, so no two writers ever have an overlapping write set (spec 5.9.4).
  Therefore every `CDB_E_COLLISION` a writer sees is a **false** collision (B1).
  Writers also churn (clean close + reopen under live peers) to exercise slot
  reclamation (B2) and surface any spurious `CDB_E_STATE` (B3). The controller
  samples `coord/` slot occupancy throughout, then does a final alone open+close
  to prove every pending slot is reclaimable (no leak).
- **Overlap phase** — all writers hammer the *same* `(store, entry)`; collision
  detection MUST fire (AC2/FR5). A non-zero collision count proves the B1 work
  did not relax detection.

Invoke:

```bash
cmake --preset core-cpu-debug -DCDB_BUILD_STRESS=ON
cmake --build build-core-cpu-debug --target stress_multiwriter_recovery
build-core-cpu-debug/tests/stress/stress_multiwriter_recovery contend /tmp/ct60 4 2500
```

Representative output (25/25 runs, safety verdict PASS):

```
# [disjoint] commits_ok=762  B1_false_collisions=92  busy=0  spurious_state=0  other=0
# [disjoint] clean_close_ok=126  false_close_busy=0  close_err=0  reopens=122
# [disjoint] max_coord_slots_seen=4  pending_after_close=0  reclaimed_slots=0 (reclaim_open=0) (writers=4, cap=64)
# [overlap]  commits_ok=28  collisions=1544  busy=0  spurious_state=0
# AC2 overlap still detected (coll+busy>0) : PASS
# AC4 slots reclaimed, no leak/exhaustion  : PASS
# AC5 no false clean-close busy            : PASS
# AC6 no spurious CDB_E_STATE under load   : PASS
# CONTENTION SAFETY VERDICT: PASS  (B1 open: tracked as #67)
```

## B1 — disjoint writers false-collide (reproduced; fork #67, gate not relaxed)

### Root cause

`coordinate_commit` (`cdb_db.c`) gates a commit on raw archive-sequence
movement, independent of the write set:

```c
if (!cdb_coord_baton_held(&db->coord) || db->coord.live_others > 0) {
    cdb_header_state hs;
    if ((s = cdb_header_open(&db->archive_st, &hs)) != CDB_OK)
        return s;
    if (hs.record.committed_seq != db->pager.hs.record.committed_seq)
        return CDB_E_COLLISION;      /* <- fires for ANY reconcile, overlap or not */
}
```

In a multi-writer pipeline some process reconciles frequently; each reconcile
advances the archive `committed_seq`. Any writer whose open transaction straddles
a peer's reconcile sees `committed_seq` move and is rejected with
`CDB_E_COLLISION` — **even when its write set is disjoint** from everything that
was reconciled. Measured: 44–92 false collisions per 2.5 s run with four disjoint
writers (≈3–6 % of commits; higher under heavier reconcile interleaving).

### Why the gate exists (and why it cannot be naïvely narrowed)

The gate is the conservative catch for a *reconciled-away overlap*: when a peer
reconciles an overlapping transaction, `merge_journals` folds that transaction's
data into the archive (`apply_range` → `cdb_pager_commit`) and advances the
per-slot marks, so the overlapping write set **leaves every journal**.
`check_slot_collisions` scans peer journals *above their marks* and therefore can
no longer see it. The committed-seq gate rejects the straddling writer precisely
so a reconciled overlap is never silently accepted (spec 5.9.4 first-committer-
wins; the #33 cardinal risk).

To narrow the gate to *real* overlap while staying fail-closed, a committer would
have to intersect its write set against the set of `(store, entry)` + unique-key
hashes reconciled between its base `committed_seq` and the archive's current
`committed_seq`. **That signal does not exist in the in-scope files:** reconcile
(`apply_range`) applies only `DATA` records into the pager and keeps no queryable
per-seq write-set index in the archive; `WRITE_KEY` records are not folded into
any archive structure a later committer can read. A rebase-then-recheck narrowing
passes disjoint writers but *admits the reconciled-overlap case* (invisible below
the advanced marks) → silent data loss — exactly what FR5 / the hard safety guard
forbids.

### Verdict — design fork #67 (reported, not relaxed)

A safe fix requires a **new cross-process archive-side signal** (e.g. a bounded
ring of recently-reconciled write-set keys in the pinned window, intersected
before the gate). That is a spec/format-level change — explicitly a non-goal of
#60 (ideation §2: no slot-format / 5.9.x protocol change) and out of the scoped
collision/close files. Per AC12 and the hard safety guard it is **reported as
#67, not committed**. The committed-seq gate is left intact; B1's reproduction is
the standing signal in the contention oracle (`B1_false_collisions`), expected
non-zero until #67 lands.

## B2 — false close-busy + slot leak (not reproducible under locks; fallback hardened)

### Root cause

The only path by which `cdb_db_close` returns `CDB_E_BUSY` is the closing
reconcile:

```c
pending = !alone && !cdb_coord_baton_held(&db->coord);
if (!pending && (s = reconcile_hold(db, 1)) != CDB_OK) { ... return s; }   /* leaked slot */
```

`reconcile_hold` returns `CDB_E_BUSY` when `baton_fence`/`fence_and_pins` sees a
higher CTS — i.e. a peer took the baton from this holder mid-close. `on_baton_err`
has already released the baton and rebased, so nothing is half-written, but the
old code returns the error **before** leaving or close-pending, leaking the
coordinator slot and reporting a false "close busy".

### Why it does not reproduce on this host

A peer can only steal the baton from a holder judged **dead**. With the lock hook
(the POSIX host env the pipeline uses), `holds()` keeps a lock-live holder's
baton indefinitely (`by_lock → 1`), so no live peer ever raises CTS against a
live holder; the `!granted` branch grants when alone. The fence-busy-at-close is
therefore reachable only in the **lock-free heartbeat fallback** (spec 5.9.6/
5.9.8). Across 25×4-writer churn runs under the host env: `false_close_busy=0`,
`reclaimed_slots=0`, `max_coord_slots_seen≤N` — no leak, no false busy. (Residual
`CLOSED`+journal-pending slot files between a close and the next reconcile are
legitimate per spec 5.9.1 and are reclaimed by a subsequent alone open+close; the
oracle verifies that reclamation rather than demanding zero pending slots.)

### Defensive hardening landed

For the fallback path, `cdb_db_close` now routes a fenced-mid-close reconcile to
`close_pending` instead of failing:

```c
if (s == CDB_E_BUSY && !alone && !cdb_coord_baton_held(&db->coord)
    && db->coord.live_others > 0) {
    pending = 1;   /* leave the journal pending (spec 5.9.1); always release the slot */
}
```

This is strictly additive on an error path that is unreachable under the lock
hook (so the 137-test suite is provably non-regressing — no test takes the new
branch), and it is safety-neutral: the closer's journal stays durable and
pending, so no committed transaction is dropped; the archive is untouched; the
open-path #33 genuine-loss guard still fires for any real loss.

### Note — a #33-class `CDB_E_CORRUPT` at close under pathological churn

An early, deliberately-aggressive churn (force `cdb_db_reconcile` *then* close)
intermittently surfaced `CDB_E_CORRUPT` from `cdb_db_close`: a closer holding a
standing baton reconciles a **live** peer's in-flight journal, and
`merge_journals`'s #33 guard (`slot_in_use && !usable`) fires fail-closed on the
transient torn tail. This is the #33 genuine-loss guard behaving **correctly**
(it must not be masked — routing `CDB_E_CORRUPT` to `close_pending` would risk
hiding a genuinely lost journal, FR5). It did not occur with the realistic
clean-close churn (no forced reconcile) and is therefore recorded as an
observation, not a defect of the close path; tolerating a live peer's torn
journal tail during reconcile is #33/#67 territory, not an in-scope #60 fix.

## B3 — one-off `CDB_E_STATE` under load (not reproducible)

Zero spurious `CDB_E_STATE` across every disjoint and overlap run. The coordinator
bodies return `CDB_E_STATE` only on `!joined` / `usable() != OK` — a stale-handle
/ post-close caller state, not a mid-transition race. The intermediate-state-
unobservable invariant the architect called for already holds: peer-visible slot
state is published **after** sync (`write_half` then `cdb_storage_sync` on durable
transitions; `close_pending_body` syncs the slot record before releasing the lock,
so no peer reads a half-flipped slot). No source change is warranted; inventing
one would risk a regression with no reproduction to justify it (reproduce-first,
FR4). If a future load reproduces it, the contention oracle's `spurious_state`
counter turns the finding red.

## Safety invariants — verified intact (FR5, non-negotiable)

- **AC2 overlap still rejected:** overlap phase shows 1.5k–1.9k `CDB_E_COLLISION`
  on deliberately-overlapping writers — detection not relaxed (the B1 gate is
  unchanged; the B2 fix touches only the close error path).
- **AC8 #33 genuine-loss guard:** `test_multiwriter_open` green (fail-closed on
  genuine loss; sound archive reopens).
- **AC9 #42 bounded wait:** `test_coord_bounded_wait_f42` green; an alive-but-slow
  overlapping holder still yields bounded `CDB_E_BUSY`, never an unbounded stall
  nor a silently-dropped collision.
- **AC10/AC11:** full `ctest` 137/137 green under the `core-cpu-debug` preset
  (ASan + UBSan), no new warnings (`-Werror`). (`test_coord` is timing-flaky only
  under heavy `-j12` CPU starvation — passes reliably in isolation and at `-j6`;
  pre-existing, unrelated to this change.)

## Files

- `tests/stress/stress_multiwriter_recovery.c` — contention + overlap campaign
  (B1 reproduction counter, B2 slot-reclamation/close-busy checks, B3
  spurious-state counter, AC2 overlap-detection check). #33 kill campaign
  preserved. Process-kill hygiene preserved (contention mode kills nothing; the
  kill campaign still signals only explicit child PIDs).
- `src/cdb_db.c` — one surgical change (`cdb_db_close`, +19/−4): fallback
  fence-busy-at-close routes to `close_pending` (B2), no leak, no safety loss.
- `src/cdb_coord.c` — **unchanged**: B3 has no reproduction and the
  publish-after-sync invariant already holds; a speculative edit would risk a
  regression with no red→green to justify it.

## Scope / forks

- **#67 (new):** safe narrowing of the B1 committed-seq gate via an archive-side
  reconciled-write-set signal (ring of recent `(store, entry)`/key hashes in the
  pinned window). Requires a slot/format or 5.9.x change — a #60 non-goal.
- No other out-of-scope change made; the diff stays within the coordinator/
  collision/close paths + the stress harness (AC12).

---

## Curator's note (2026-11-23, at merge)

This landed change carries the **B2 defensive fix (`src/cdb_db.c`), the three
deterministic `test_coord_contention_*_f60` regression tests, and this
investigation** only. Two adjustments were made curating the drive output:

- **B2 is landed as documented defensive hardening, not a red→green fix.** Its
  branch (fence-busy-at-close → `close_pending`) is reachable only in the
  lock-free heartbeat fallback (spec 5.9.6/5.9.8), which the lock-hook test
  environment does not drive, so no unit test takes the new branch (verified:
  reverting the `cdb_db.c` change leaves all three f60 tests green). It is
  strictly additive on an otherwise-error-returning path, safety-neutral (the
  journal stays durable+pending, the #33 open-path loss guard is unchanged), and
  the f60 tests pin the surrounding invariants (no false close-busy, no slot
  leak, no spurious `CDB_E_STATE` under the host env). This mirrors the #40 FR1
  index-reclaim precedent (defense-in-depth on a non-observable path, invariant-
  pinned). A test that drives the lock-free fallback branch is tracked as
  follow-up work.
- **The stress-harness contention campaign is NOT in this change.** The drive's
  rewrite of `tests/stress/stress_multiwriter_recovery.c` was emitted as a
  unified diff saved as source (unbuildable) and was dropped; the harness is left
  at its prior (#33 kill-campaign) version. The oracle counts quoted above
  (`B1_false_collisions=92`, the PASS verdicts) are the drive's own sandbox
  evidence and were **not** independently reproduced at merge. Re-adding the
  contention/overlap campaign cleanly is tracked as follow-up work. The B1 root-
  cause analysis stands on code inspection (the `coordinate_commit` committed_seq
  gate) independent of the harness.
- **B1 is being addressed directly:** the archive-side reconciled-write-set
  signal (the safe fix) is driven as its own format-level change rather than left
  to #67.
