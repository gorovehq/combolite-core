# ADR-0004: Reconciled-write-set ring to narrow the commit collision gate

- **Status:** Accepted
- **Date:** 2026-11-23
- **Supersedes / Superseded by:** —

> Relates to issue #60 B1 (supersedes fork #67), audit `docs/audit/2026-11-60-coord-contention.md`.
> Guards the #33 no-silent-loss invariant. Builds on ADR-0002 (no heap in the core).

## Context

`coordinate_commit` (`src/cdb_db.c`) rejects a commit with `CDB_E_COLLISION` whenever the
archive `committed_seq` advanced past the transaction's base — **regardless of write-set
overlap** (spec 5.9.4). A peer's frequent reconcile advances `committed_seq`, so a writer with
a **disjoint** write set that merely *straddles* a peer reconcile is falsely rejected
(measured 44–92 false collisions per 2.5 s run with 4 disjoint writers, ≈3–6 % of commits).

The coarse gate is not gratuitous: it is the conservative catch for a *reconciled-away
overlap*. Once `merge_journals` folds a peer's overlapping transaction into the archive, that
write set leaves every journal, and `check_slot_collisions` can no longer see it. A naïve
rebase-then-recheck narrowing passes disjoint writers but **admits the reconciled-overlap
case → silent data loss** (#33 class). Narrowing safely requires a new archive-side signal
that records what reconciliation folded away.

## Decision

Add an archive-side **reconciled-write-set ring** (`src/cdb_wsring.{h,c}`, spec 14.22): a
bounded, append-only, format-versioned structure recording each reconciled transaction's
write-set keys — `(store, entry)` data keys and unique-index key-hash keys — each tagged with
the `committed_seq` at which it was reconciled.

`coordinate_commit`'s blanket "`committed_seq` moved → `CDB_E_COLLISION`" is narrowed to:
when the sequence advanced from the tx's base `B` to the archive's current `C`, **allow** only
if the ring **provably covers** `(B, C]` **and** none of the tx's own write-set keys intersect
a ring entry tagged in `(B, C]`; otherwise **reject**.

### A. State / format & transitions (spec 14.22)

- **Layout.** A 64-byte region header (`WSR1` magic, format version, capacity, live count,
  head index, `floor_seq`, `top_seq`, CRC-32C) followed by fixed 40-byte entries (`seq`,
  store, entry, key-tag, kind, CRC-32C). Each of the header and every entry carries its own
  CRC, so a torn write is detected, not trusted.
- **Versioning / compatibility.** Rooted by a reserved-region anchor (spec 14.1.6) with
  feature index `CDB_REGION_FEATURE_WRITESET_RING = 1`. A binary that predates the index, or
  an archive written before the region, finds no anchor and takes the conservative gate — the
  addition is forward- and backward-compatible.
- **Append (reconcile).** Only on the `merge_journals` fold path; the batch's keys are
  appended tagged with the new `committed_seq`. `top_seq` advances to that seq; the frontier
  only moves forward.
- **Evict (at cap).** Oldest-first; the evicted entry's tag raises `floor_seq`, so any range
  including an evicted seq fails coverage (fail-closed). A batch larger than the cap raises
  `floor_seq` to its own seq.
- **Atomic publish.** The ring is written by the baton holder inside the **same pager commit**
  that raises `committed_seq` (the marks-index pattern, `marks_root`): written and synced
  before the sequence it tags becomes visible. A committer therefore never observes a
  `committed_seq` whose covering ring entry is not yet durable.

### B. Timeouts / bounds (R-B)

- The ring is bounded by the named cap `CDB_WSRING_MAX_ENTRIES` (4096), further bounded by
  what the region holds.
- The intersection scan iterates `count ≤ cap` entries × `nown` own keys — a static upper
  bound, no loop driven by external state.
- **Coverage predicate** (triggers the fail-closed fallback): `decode-clean ∧ current > base
  ∧ floor_seq ≤ base ∧ top_seq ≥ current`. Any failure → reject.

### C. Concurrency model (R-C)

- Multi-process coordination via the mmap'd/file archive + fsync ordering — **not** an async
  event loop; there is no runtime/scheduler to block. The only new CPU work (the bounded scan)
  runs inline.
- The ring is written by the **single** reconciling baton holder and read by committers. The
  read is consistent because of publish-after-sync (A): a committer reads the ring from a
  read-only archive snapshot; a half-published or torn read fails its CRC and takes the
  conservative fallback.

## Fail-closed invariant (non-negotiable, #33)

Every operation defaults to rejection. `cdb_wsring_straddle_disjoint` sets `*allow = 1` only
on a proven covered-and-disjoint decision; incomplete coverage, an absent/old/torn/corrupt
region, an unknown format, a hash kind mismatch, or any error leaves `*allow = 0`. A false
collision is retryable; a silently-admitted reconciled overlap is data loss. The #33 open-path
genuine-loss guard (`merge_journals` `slot_in_use && !usable`) and the #42 bounded wait are
untouched.

## Consequences

- **Pro.** Disjoint-writer false collisions can be eliminated without weakening
  first-committer-wins. The ring module is pure over a caller-provided byte region, so the
  intersection + coverage logic is directly unit-tested
  (`tests/test_coord_writeset_ring_f60.c`, the red→green oracle) independent of the
  multi-process machinery.
- **Con / bound.** A too-small ring leaves coverage frequently incomplete → false collisions
  persist (safe, retryable, never loss). Cap sizing targets the observed reconcile rate.

## Integration status

**Wired (#60 B1).** The ring module, its header-anchor rooting helpers
(`cdb_header_region_find` / `cdb_header_region_set`), the format/version note, the red→green
unit test, **and the live-path wiring** are all landed and green under `core-cpu-debug`
(ASan + UBSan). The two pure-function call sites, plus the one missing primitive, are now in
the engine:

0. **Snapshot region read** (`cdb_pager_read_wsring_region`, `src/cdb_pager.c`, PART 0): reads
   the ring region bytes from the archive at the anchor located by `cdb_header_region_find` on
   the committed snapshot `hs`. The region is one pinned page of the ring's own CRC-protected
   bytes (not wrapped in a page frame), so the read reflects exactly the state `hs` committed
   with no anchor-map walk. Absent/out-of-range/short read → cannot-read → the conservative
   reject; a torn or half-published region fails the ring's own CRC on decode (fail-closed).

1. **Populate** (`merge_journals`, inside the existing `cdb_pager_commit`): each folded
   transaction's write-set keys are collected from `apply_range`'s record walk and appended
   (`cdb_wsring_append(seq = committed_seq + 1)`) into the ring, published to a fresh pinned
   page via `cdb_pager_wsring_publish` and rooted with `cdb_header_region_set` — durable by the
   same commit's step-1 barrier before `committed_seq` is raised (publish-after-sync). A fresh
   ring primes `floor_seq` to inception so it never claims coverage of reconciles that predate
   it (retrofit-safe); an incomplete write set (accumulator overflow) raises `floor_seq` past
   the new seq so no straddle over it is ever admitted.

2. **Consult** (`coordinate_commit`, replacing the blanket reject at the `committed_seq`-moved
   branch): reads the region from the archive snapshot `hs` via PART 0, gathers the tx's own
   write-set keys, and calls `cdb_wsring_straddle_disjoint(base =
   db->pager.hs.record.committed_seq, current = hs.record.committed_seq)`; falls through on
   `*allow`, else `CDB_E_COLLISION`.

The narrowing applies to the plain archive layout only; encrypted (AEAD) and tamper-evident
(governance) layouts take the conservative gate (absent ring) until the ring page is sealed
like every other page — a documented, fail-closed scope limit, no-worse-than-current.

Because the consult is fail-closed (absent/unreadable region → the exact current behavior), the
wiring is provably no-worse-than-current. It was landed only after verification against the full
multi-process `ctest` under ASan+UBSan, with the mandatory red→green on the disjoint straddle
(`tests/test_coord_writeset_ring_e2e_f60.c::test_disjoint_straddle_now_succeeds`;
`tests/test_coord_contention_collision_f60.c` flipped from `CDB_E_COLLISION` to `CDB_OK`) and
overlap / reconciled-overlap / unreadable-region staying rejected — a bug on this critical path
is the #33 data-loss class the signal exists to prevent.
