# Changelog

All notable changes to `combolite-core` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches its first tagged release. No version has been tagged yet, so all
entries live under `[Unreleased]`.

Issue and pull-request numbers refer to the `gorovehq/combolite-core` tracker.

## [Unreleased]

### Fixed

- **Disjoint-writer false collisions eliminated: the reconciled-write-set ring is
  wired into the live commit path (#60 B1) — `#33` DATA-LOSS-CRITICAL gate
  narrowed, not relaxed (`src/cdb_db.c`, `src/cdb_pager.c`/`.h`,
  `tests/test_coord_writeset_ring_e2e_f60.c`, ADR-0004).** `coordinate_commit`
  rejected every commit whose archive `committed_seq` had advanced past the
  transaction's base, **regardless of write-set overlap**, so a peer's frequent
  reconcile made **disjoint** writers that merely straddle it false-collide
  (≈3–6 % of commits). The reconciled-write-set ring (module + format + unit
  tests, #60 B1 / PR#70) is now **populated and consulted** on the live path:
  - **Populate** (`merge_journals`, inside the existing `cdb_pager_commit`):
    each folded transaction's write-set keys (data `(store, entry)` keys and
    unique-index key-hash keys) are collected from `apply_range`'s record walk
    and appended to the header-anchored ring, tagged with the new
    `committed_seq`. The ring is one pinned archive page of the ring's own
    CRC-protected bytes, published by the same pager commit that raises
    `committed_seq` (**publish-after-sync**), so a peer never sees a
    `committed_seq` whose covering ring entry is not yet durable. A fresh ring
    primes its `floor_seq` to inception so it never claims coverage of reconciles
    that predate it (retrofit-safe).
  - **Consult** (`coordinate_commit`): when the sequence advanced, the committer
    reads the ring from the archive snapshot it sees
    (`cdb_pager_read_wsring_region`, PART 0) and calls
    `cdb_wsring_straddle_disjoint`; it **allows** only a straddle the ring
    provably covers **and** that is disjoint from every reconciled key in the
    range, otherwise rejects.
  - **Fail-closed (non-negotiable, #33).** Any absent/torn/old/corrupt or
    half-published region, incomplete coverage, accumulator or own-key overflow,
    or read error leaves the decision `0` → `CDB_E_COLLISION` — exactly today's
    conservative reject, so the wiring is **provably no-worse-than-current**. A
    reconciled-away overlap (the #33 cardinal case) is still rejected; the #33
    open-path genuine-loss guard and the #42 bounded wait are untouched.
  - **Scope.** Narrowing applies to the plain archive layout only; encrypted
    (AEAD) and tamper-evident (governance) archives take the conservative gate
    (absent ring) until the ring page is sealed like every other page.
  - **Proof.** `tests/test_coord_writeset_ring_e2e_f60.c` — a disjoint straddle
    now **SUCCEEDS** (red→green; the prior `CDB_E_COLLISION` assertion in
    `tests/test_coord_contention_collision_f60.c` is flipped to `CDB_OK`), while
    overlap, reconciled-overlap, and an unreadable region stay
    `CDB_E_COLLISION`; full `ctest` green under `core-cpu-debug` (ASan + UBSan).
- **Signed/attributed document revisions keep the original writer's principal
  across crash recovery (#65) — audit follow-up (`src/cdb_doc.c`,
  `src/cdb_journal.c`/`.h`, `src/cdb_db.c`/`.h`, `tests/`).** A document
  revision's delta carried no principal of its own, so when recovery re-applied
  it after a crash, `apply_change` (`src/cdb_doc.c`) attributed the revision to
  the **recovering** session's active identity (or `0`) rather than the original
  writer — silently corrupting the audit trail / non-repudiation for every
  revision recovered after a crash. The writer's `principal_id` is now **captured
  in the journal data record at write time** (`tx_put_in`, `src/cdb_db.c`) and
  **used on replay** so the recovered revision keeps its original attribution.
  - **Record format (versioned, backward-compatible).** A new record flag
    `CDB_RECORD_FLAG_PRINCIPAL` (`0x20`) marks a record that stores the 8-byte
    principal as a suffix of the record **body** — inside the region already
    covered by the trailer CRC (plaintext) or AEAD tag (encrypted), so the stored
    value inherits the record envelope's integrity. `cdb_journal_append_crypto`
    writes it (body grows by 8 when the flag is set); `cdb_journal_read_crypto`
    strips and validates it (length-checked, before the encrypted hidden-target
    varint decode). The flag *is* the version signal: a record written without it
    (an old journal, or a write under no active identity) decodes exactly as
    before. No header, epoch, or record-kind change.
  - **Fail-closed.** A record that claims `FLAG_PRINCIPAL` but whose body is too
    short to hold the 8-byte suffix is rejected `CDB_E_CORRUPT` (never an
    under-read). A record with **no** stored principal (`cdb_delta.has_principal`
    is the explicit tri-state, so a legitimately-attributed `0` stays distinct
    from "absent") falls back to today's documented behavior — the active identity
    or `0` — and never crashes.
  - **Live path unchanged.** On a normal commit the stored principal equals the
    active principal, so the non-recovery hot path attributes exactly as before
    (#40). Cross-identity **re-signing** of a recovered signed revision under the
    original key remains deferred (`docs/BACKLOG.md`): this change carries the
    principal and preserves the original stored envelope signature; it does not
    re-sign under the recovering session.
  - Held to `tests/test_doc_principal_sig_f40.c`: `test_recovery_replay_keeps_original_principal`
    (red→green — write under A, recover under B, recovered principal is A not
    B/0), `test_old_format_record_falls_back` (no stored principal → non-crashing
    fallback), `test_record_principal_roundtrip_versioned` (new- and old-format
    records decode; principal round-trips), and `test_principal_short_body_rejected`
    (DoS edge → `CDB_E_CORRUPT`). The existing #40 roundtrip/no-identity/
    mismatched-signature tests, the #37/#54 audit suites, and the #33 guard stay
    green. **Every other #65 item stays deferred** (see `docs/BACKLOG.md`).

### Added

- **M27 enclave key plumbing (#72 slice 1) — CR3 + CR2.** The in-core keystore
  now reads back a stored wrapped enclave key via a new unwrap caller
  (`db_enclave_unwrap_stored_key`, the counterpart to `cdb_crypto_wrap_key`),
  fail-closed `CDB_E_SECURITY` on a bad tag / wrong master with no key bytes
  written on the failure path (CR3); and the SEAL and REPL subkeys are now
  derived (HKDF) from the enclave key during key setup and held, wiped in
  `db_wipe_crypto` (CR2). **Deferred to later #72 slices:** CR5 (at-rest page
  encryption — wiring `domain_id` through every model's page-write path) and
  the consumer that actually encrypts CRDT replication slices with the REPL
  subkey. Tests: unwrap round-trip + tamper-fails-closed (`tests/test_crypto.c`)
  and the SEAL/REPL HKDF KAT (`tests/test_crypto_kat.c`).
- **General matrix determinant for dim ≥ 4 (#65) — audit follow-up, closing the
  #40 FR5 `cdb_math_mat_det` cap (`src/cdb_math.c`, `tests/`).** `cdb_math_mat_det`
  previously computed the determinant only for 1×1/2×2 (direct) and 3×3 (Rule of
  Sarrus), returning `CDB_E_UNSUPPORTED` for any dimension ≥ 4. It now computes
  the determinant for **dim 4 … `CDB_MATH_MAT_DET_MAX_DIM` (32)** via **LU
  decomposition with partial pivoting** — determinant = permutation sign × the
  product of the pivots, accumulated in `double` (matching `mat_mul`/`mat_vec_mul`).
  A **singular** matrix (a zero/near-zero pivot column) yields a determinant of
  exactly `0.0` with `CDB_OK` — a valid result, not an error. The elimination
  runs **in place on a bounded stack copy** (`double[32*32]`, 8 KiB), so the op
  stays **zero-heap**; the cap is checked **before any dim-derived sizing or
  indexing**, so an over-large `dim` can neither overflow the size computation
  (CWE-190) nor overrun the scratch (CWE-787) — above the cap (and `dim == 0`)
  returns `CDB_E_UNSUPPORTED` (documented cap). The dim 1/2/3 fast paths and the
  existing `float`/error-return conventions are unchanged. Held to a red→green
  regression (`tests/test_math_mat_det_general.c`: known 4×4 = 8, known 5×5 =
  −35, cleanly-singular ⇒ 0, 3×3 Sarrus continuity, above-cap ⇒ `CDB_E_UNSUPPORTED`,
  null ⇒ `CDB_E_INVALID_ARG`); `tests/test_math_mat_det_cap_f40.c` updated so the
  unsupported-boundary assertion moves from 4×4 to `MAX_DIM + 1`. **The remaining
  #65 items stay deferred-with-note** (recovery-replay signed principal, atomic
  table create, order-preserving keys, collation, document rollback-op, FTS
  modes, overflow re-sign, vector tuning — see `docs/BACKLOG.md`).
- **Time-series audit-completeness + retention-on-write (#63) — audit follow-up,
  deferred from #41 (`src/cdb_ts.c`, `tests/`).** Two focused time-series fixes,
  each at its real engine source site with a red→green regression test:
    - **Series-create audit event now always emitted (Item 1).** Creating a
      time-series series (`ts_series_in`) emitted no dedicated `CDB_AUDIT_SCHEMA`
      event, so the create was unaudited. A new `ts_schema_audit()` helper now
      records a redacted `CDB_AUDIT_SCHEMA` (store + new series id only), mirroring
      `db_governance_audit` and the `COLLISION` emit: it fires whenever the audit
      log is persistable (`has_catalog`), attributed to the active principal when
      one is registered and to **principal 0 (unattributed)** otherwise — never
      silently dropped when no identity is active (the same emit-unattributed fix
      as governance #37 and the single-writer path #54 F2; closes an OWASP A09
      audit-completeness gap). Best-effort: a failed audit append never fails or
      undoes the create. (`tests/test_ts_audit_unattributed_63.c`)
    - **Retention auto-enforced on write (Item 2).** Configured retention was
      applied only by an explicit `cdb_ts_apply_retention` maintenance call, so a
      caller that only wrote accumulated over-retention points indefinitely. The
      write path (`ts_append_in`) now applies the configured retention after
      journaling the points, using the trusted server clock (`cdb_db_now`,
      converted to the series' tick precision) — never a client-supplied point
      timestamp — so an over-retention series is trimmed on the next write with no
      explicit maintenance. The trim is **bounded** (removes only points older than
      `now − retention`, never in-window data) and **idempotent** (a no-stale write
      trims nothing), so it is safe to run on every append. Explicit
      `cdb_ts_apply_retention` behaviour is unchanged; it and the write path now
      share the lock-free inner helpers (`ts_get_retention_in` / `ts_drop_before_in`),
      removing a latent re-lock. (`tests/test_ts_retention_on_write_63.c`)
  - **Deferred (recorded, not started):** full **downsample-on-write** (Item 2 ships
    retention-trim-on-write only), **compaction modes**, **predicate pushdown**, and
    **retention-in-transaction** remain follow-ups — see `docs/BACKLOG.md` (→ #63).

- **Blob-store extras (#56) — audit follow-up to #39
  (`src/cdb_blob.{c,h}`, `src/cdb_doc.{c,h}`, `src/cdb_proc.{c,h}`,
  `src/cdb_compiler.c`, `src/cdb_db.h`).** Three declared-but-unwired blob-store
  capabilities are closed at their real engine/compiler source sites, each with a
  red→green regression test:
  - **External-file attachments (FR1, `cdb_blob.c`).** `cdb_blob_store_external_db`
    / `cdb_blob_read_external_db` store and read a blob body in an external
    companion file (the `cdb_blob_ref` flags bit 0 that previously had no code
    path), routed entirely through `cdb_env` file ops — no hardcoded POSIX. The
    file is content-addressed (name from the SHA-256 / enclave HMAC-SHA-256 of the
    body). Reads **fail closed**, returning no bytes, when the external file is
    missing (`CDB_E_NOT_FOUND`), a different size than `ref->total_len`
    (`CDB_E_CORRUPT`, catches truncation/growth), or — by default — does not hash
    to `ref->hash` (`CDB_E_CORRUPT`), reusing #39 verify-on-read for the external
    bytes. Test: `test_blob_external`.
  - **Doc-body compression (FR2, `cdb_doc.c`).** The document write path now
    compresses a body through `cdb_codec` (LZMA2, spec 15.2/15.3) when the new
    opt-in `cdb_db_config.doc_compress` is set, keeping the compressed form only
    when it saves at least 1/8 and **falling back to stored-raw** otherwise; reads
    transparently decompress into a bounded buffer (decompression-bomb guarded).
    A compressible body is stored compressed and reads back byte-identical; an
    incompressible one is stored raw and also reads back identical. Default off,
    so existing callers are unaffected. Test: `test_doc_compress`. **Scope:**
    doc-bodies only — **journal and page compression are deferred** (see
    `docs/BACKLOG.md`), not half-wired.
  - **CMBQL blob create + read opcode (FR3, `cdb_proc.c` + `cdb_compiler.c`).**
    New ISA opcodes `CDB_MUT_BLOB_CREATE` / `CDB_MUT_BLOB_READ` and CMBQL grammar
    forms `create_blob(store, content)` / `read_blob(store, ref)` (and
    `CREATE BLOB … CONTENT …` / `READ BLOB … REF …`), wired to the real
    `cdb_db_blob_*` engine (the query layer could previously only `free_blob`).
    Operands are validated and fail closed on malformed input; the read is a
    capped whole-blob-into-register (bounded resource use). Test:
    `test_proc_blob_opcode`.

### Fixed

- **Coordinator (#67) — measured per-op-kind completion estimate for the
  non-baton busy ops (`src/cdb_coord.c`, `tests/`), closing the #42 storage/coord
  follow-up (spec 5.9.6).** The five non-baton busy op kinds
  (`RECONCILE`/`COMPACT`/`GRAPH`/`RECOVER`/`REBASE`) previously always published
  the flat conservative constant (`CDB_COORD_ESTIMATE_CONSERVATIVE_MS`, 30 s)
  because the measured path in `estimate_of` was gated on holding the baton
  (`issued != 0`). The #42 bounded prepared-tx waiter (`cdb_db.c`
  `check_slot_collisions`, spec 5.9.5) therefore read a fictitious 30 s bound for
  an operation that may be finishing in milliseconds. A new `measured_estimate()`
  now derives the estimate from progress already in the coord record — **basis
  A/B:** the elapsed time since `status_start` scaled by work-left over work-done
  (`x`/`x_total`), the same formula the baton uses, but **without requiring the
  baton** for the five non-baton kinds; **basis C:** when no work counters are
  published, the bare elapsed time since `status_start`, **bounded below** the
  conservative constant. No new stored field: the one-field `cdb_coord.h` option
  was not needed.
  - **Finite + fail-closed (FR2/FR3, spec 5.9.6 security).** A non-baton busy op
    with no measured basis still falls back to the conservative constant (never
    `UNKNOWN`); `COMMIT` without baton progress and unknown op kinds stay
    `UNKNOWN`; idle is 0. All basis math guards divide-by-zero, `x_total < x`,
    and `now_us <= status_start`, and clamps below the `UNKNOWN` sentinel, so a
    corrupt/hostile peer record can at worst push the wait to the waiter's hard
    cap (`CDB_TX_WAIT_HARD_CAP_MS`), never beyond and never to `UNKNOWN`
    (CWE-190/-369 guarded).
  - **holder_outlasts semantics preserved (FR5).** A measurement is kept distinct
    from the constant fallback **by construction** — `measured_estimate` never
    returns exactly `CDB_COORD_ESTIMATE_CONSERVATIVE_MS` (a value landing there is
    nudged down 1 ms) — so `holder_outlasts`'s existing value test still treats a
    constant-fallback estimate as "says nothing" and only a genuine measurement
    may shorten the baton wait, with no stored flag.
  - Red→green regression test `tests/test_coord_measured_estimate_f67.c`
    (deterministic faultenv, virtual clock) proves measured ≠ constant & finite,
    no-basis → constant fallback, the fallback-magnitude collision nudge, and the
    #42 bounded wait still returning `CDB_E_BUSY` within bound against a measured
    non-baton holder — red on the merge-base (non-baton estimate was exactly
    30 000 ms), green under `core-cpu-debug` (ASan + UBSan). #42/#33 guards
    unchanged and green.

- **Executor (#52) — per-model live cursors / scan materialization
  (`src/cdb_exec.c`, `src/cdb_vec.{h,c}`, `src/cdb_link.{h,c}`).** The query
  executor's full-store scan is now complete and live-correct for the vector,
  time-series and link models (relational and document were already correct):
  - **VECTOR scan materializes `$vector`.** The `scan_read`/`scan_load` VECTOR
    path no longer force-zeros the record length after `cdb_vec_get`, so each row
    carries its encoded `$vector` value; large vectors flow through the existing
    host-profile grow path (`CDB_E_OUT_OF_BUDGET` bound preserved).
  - **TIME-SERIES and LINK scans emit real records**, not bare
    `store_id`/`entry_id` rows: the TS branch yields one record per live series
    (its key bytes) by **reusing the #41 `cdb_ts_list` enumeration** (no second
    enumerator added), and the LINK branch yields a serialized link record per
    **live** link via a new whole-store `cdb_link_scan`, which **reuses the
    #40/#60 `state_of()==LIVE` filter** so tombstoned/removed-end links are
    skipped.
  - **Correct live-entry count for an open store.** All three models now
    enumerate their committed **live** entries — vectors via the new
    `cdb_vec_next_live` over the entries index (delete removes from it), TS via
    `cdb_ts_list`, links via `cdb_link_scan` — instead of counting entry IDs up
    to the catalog's block-claimed `next_entry_id`, which lags an open store and
    over/under-counted it.
  - Fail-closed: any enumeration error propagates the model status and emits no
    row. The time-series/link cursor state lives in an arena allocation taken
    only for a live scan, so the other models' query memory budget is unchanged.
  - Red→green regression test `tests/test_exec_live_cursors_f52.c` drives the
    real executor scan site (missing-`$vector` / bare-ID / open-store miscount
    were red on the merge-base), green under `core-cpu-debug` (ASan + UBSan).

### Added

- **Coordinator (#60 B1) — reconciled-write-set ring (`src/cdb_wsring.{h,c}`,
  spec 14.22).** A bounded, append-only, format-versioned archive structure
  recording each reconciled transaction's write-set keys — `(store, entry)` data
  keys and unique-index key hashes — tagged with the `committed_seq` at which
  reconciliation folded them in. It is the archive-side signal that lets
  `coordinate_commit` narrow its blanket "`committed_seq` moved →
  `CDB_E_COLLISION`" gate: a committer whose **disjoint** write set merely
  *straddles* a peer reconcile can be allowed, while a writer whose write set was
  **reconciled away** (and so is no longer in any journal for
  `check_slot_collisions` to see) is still rejected — preserving
  first-committer-wins / no-silent-loss (#33). Every path is **fail-closed**:
  the gate admits only on a proven covered-and-disjoint decision; incomplete
  coverage (oldest-first eviction raising `floor_seq`, or batch overflow), an
  absent / old-format / torn / corrupt region (per-header and per-entry
  CRC-32C), a key-kind mismatch, or any intersecting key → `CDB_E_COLLISION`.
  Rooted by a reserved-region anchor (spec 14.1.6, feature index 1,
  `CDB_REGION_FEATURE_WRITESET_RING`) and published durably by the same pager
  commit that raises `committed_seq`; forward- and backward-compatible (a binary
  or archive predating the feature takes the conservative gate). The intersection
  + coverage logic is a pure function over a caller-provided byte region and is
  held to a committed deterministic red→green oracle
  (`tests/test_coord_writeset_ring_f60.c`): disjoint-allowed / overlap-rejected /
  reconciled-overlap-rejected / incomplete-coverage-rejected /
  torn-CRC-rejected / old-format-conservative, green under `core-cpu-debug`
  (ASan + UBSan). See ADR-0004. The #33 open-path guard
  (`test_multiwriter_open`) and the #42 bounded wait
  (`test_coord_bounded_wait_f42`) are unchanged and green. **This increment adds
  the ring module + format only; `coordinate_commit` and `merge_journals` are not
  yet wired to it, so the blanket gate is still live and #60 B1 stays open until
  the (verified, multi-process) live-path wiring lands — see ADR-0004 "Integration
  status".**

### Security

- **Query engine (DoS, CWE-674)** — bounded the recursive descents over
  **untrusted** precompiled query wire and stored-procedure bytecode
  (`cdb_query_skip_expr` / `cdb_query_skip_node`, and `build_exec_tree`) with an
  explicit recursion-depth cap (`CDB_QUERY_MAX_DEPTH`, 64 — the compiler's maximum
  emitted plan depth, peer of `CDB_VALUE_MAX_DEPTH=32`). Hostile deeply-nested
  wire reaching the public `cdb_exec_open` (directly or via `cdb_proc_exec`) now
  returns the typed error `CDB_E_DEPTH` instead of driving unbounded C recursion
  to a stack overflow (SIGSEGV) in the very code that gates untrusted input — the
  parser now fails **closed**. The depth counters are `size_t`, incremented only
  on the `depth < cap` branch, so they are bounded by the cap and cannot overflow
  (CWE-190). No behaviour change for valid, reasonably-nested wire; no public
  ABI/signature change. Held to a committed regression test
  (`tests/test_cdb_wire_depth.c`, red→green proven under ASan+UBSan).
  (Private security advisory GHSA-rf29-8939-p85v, finding F3)
- Bounded the LZMA2 decoder dictionary against the decompressed-output budget
  **before allocating**, closing a crafted-property-byte memory-exhaustion DoS
  in `cdb_codec_decompress`: a one-byte dictionary property (0..40) could map to
  a dictionary size up to ~4 GiB and drive an unbounded allocation through the
  host environment allocator. The decoder now rejects any dictionary larger than
  a valid stream of the stated output length requires (`CDB_E_CORRUPT`), with no
  change to valid in-budget decode. Held to a committed red→green regression
  test. (F4, GHSA-rf29-8939-p85v)
- Bumped the vendored Mbed TLS submodule from 3.6.2 to **3.6.5**, picking up the
  upstream maintenance and security fixes for the crypto primitives the engine
  relies on (AES-256-GCM, ChaCha20-Poly1305, SHA-256, HMAC, HKDF, ECDSA). (#1)
- **Key-wrap (nonce reuse, CWE-323)** — `cdb_crypto_wrap_key` / `cdb_crypto_unwrap_key`
  previously encrypted every wrapped enclave key under a **fixed** AES-256-GCM nonce, so a
  single master key reused the same `(key, nonce)` pair across wraps and key rotations —
  defeating GCM confidentiality and integrity. The wrap now draws a fresh random nonce per
  wrap and stores it with the ciphertext (`CDB_WRAPPED_KEY_SIZE` grew to nonce ∥ tag ∥
  ciphertext); unwrap reads it back. Held to a committed regression test.
  (GHSA-2xx7-85rc-w3q8)

### Fixed

- **Audit-trail residuals (#54 PART 1, deferred from #37) — three defined-but-unwired
  governance-evidence paths closed (`src/cdb_audit.{c,h}`, `src/cdb_db.{c,h}`; spec 12.5/12.7,
  OWASP A09). ADR-0005.** #37 wired KEY_OP/SCHEMA/BATON emit+sign and verify-on-read; these three
  fail-open gaps remained, each now wired at its real source site with a red→green test (red on the
  pre-fix tree, green after the source edit — anti-no-op, #40 FR1):
  - **F2 — `CDB_AUDIT_REVISION` (type 2) was never emitted.** A committed transaction that mutates a
    document or table store now emits **exactly one** REVISION event in `tx_commit_locked` (gated on
    a per-tx `tx_has_revision` flag set at the delta-stage site for `CDB_MODEL_DOCUMENT`/
    `CDB_MODEL_RELATIONAL` stores, reset in `tx_begin`). Reuses the #37 `db_governance_audit` guard
    shape: emitted when the audit log is persistable (`has_catalog`), attributed to the active
    principal **or principal 0** when none is registered (never gated on `has_identity` — that would
    re-open the #37 governance-no-principal hole); best-effort (a failed append never fails or undoes
    the commit); the recovery/replay apply path is deliberately **not** a site (would double-emit).
    `CDB_AUDIT_CUSTOM` (type 6) is confirmed **caller-driven** via the public
    `cdb_audit_log(CDB_AUDIT_CUSTOM, …)` application-governance hook — no silent dead type.
    (`tests/test_audit_revision_f2.c`.)
  - **F3 — BATON audited only on `cdb_db_reconcile`.** `db_reclaim_in` and `db_compact_in` also take
    the single-writer baton via `reconcile_hold`; they now emit a BATON event on the genuine
    not-held→held handoff (sampled before `reconcile_hold`, emitted on success), so a
    reclaim/store-move that seizes the baton is no longer unlogged. A standing-baton op does not
    double-emit. (`tests/test_audit_baton_f3.c`.)
  - **F4 — the chain append is now serialized under the coordinator baton.** `cdb_audit_log` brackets
    its `reload-head → build → index_put → update-head` sequence under the baton (take-if-not-held,
    append, release only what it took); on token denial it falls back to the existing reload-head
    floor (private-pager, best-effort) so it **never drops the event and never forks the shared
    chain**. Verify-on-read stays fail-closed (`CDB_E_SECURITY`), bound to the reader's active key
    (per-signer registry remains a follow-up). The deterministic oracle asserts the serialization
    *invariant* — a non-holder's append must acquire the exclusive baton — since a true simultaneous
    chain *corruption* is only an OS-thread race (non-deterministic); in the coordinator model every
    persistent append already holds the baton. (`tests/test_audit_serialize_f4.c`.)
  - **Out of scope (own effort):** M27 enclave crypto (CR5 enclave page encryption, CR2 SEAL/REPL
    subkey derivation, CR3 `unwrap_key` caller wiring) and the per-signer audit key registry — left
    untouched here, recorded in `docs/BACKLOG.md`.

- **CRDT replication convergence (silent divergence / data loss)** — multi-master
  replication merged deltas by **arrival order**, not causality, so two peers'
  concurrent writes to the same `(store, entry)` could converge to **different
  values depending on import order**, and the real merge primitives in
  `src/cdb_crdt.c` had **zero callers**. Convergence is now deterministic and
  import-order independent (spec 19.5/19.9):
  - **Real HLC on export** — `crdt_emit` carries the clock stamped at commit from
    the maintained `db->hlc` (each record in a transaction gets a distinct
    sub-tick), not the transaction counter / record sequence it faked before.
  - **Order-independent resolve** — import compares an incoming delta's HLC against
    the target record's stored convergence clock and dispatches by merge class:
    **LWW** (higher HLC wins, stable peer-id tiebreak), **PN-counter** (concurrent
    increments **net** — `+100@A` and `+50@B` converge to `150` either order,
    never last-write-wins, F1), **AWORSet** (link add-wins over a concurrent older
    remove), and **commutative time series** (duplicate points dedup). The merge
    class travels on the wire in the op byte's high nibble (the "merge nibble") and
    may be registered per store with `cdb_db_crdt_set_store_merge`.
  - **Both commit branches stamp** — the normal and the baton-expiry replay paths
    both advance the clock and stamp each record, so a multi-record transaction
    under replication never collapses to equal clocks and drops records on import
    (F2).
  - **Untrusted-delta validation** — imported deltas are validated fail-closed
    (`cdb_crdt_delta_validate`: known op/merge nibble, bounded length CWE-190,
    non-NULL non-empty payload); a malformed delta is rejected with no partial
    apply.
  - **Residuals** — the convergence state (per-record clock, per-peer PN state,
    per-store class) is a bounded in-core, **session-scoped** table like the
    existing `db->hlc` / version vector; record-level (not per-field) granularity;
    durable per-record persistence is deferred (value codecs
    `cdb_crdt_hlc_encode` / `cdb_crdt_pn_encode` provided for a backward-compatible
    side store). The on-disk format is unchanged, so old images open unaffected.
    **CD3** (vector-handshake codec wiring) and **CD4** (P2P gossip / discovery /
    sockets) remain deferred — they need a transport. Held to committed
    deterministic regression tests (`tests/test_crdt.c`:
    `test_convergence_order_independent`, `test_pn_counter_apply_nets`,
    `test_baton_expiry_multirecord_survives`, and per-type/validation tests,
    red→green under ASan+UBSan). (#38)
- **Time-series downsampling (silent wrong result over money, CWE-682)** — SUM,
  MIN, MAX and AVG over a `DECIMAL` field in a downsample recipe previously emitted
  **0 with no error** (the aggregation loop filled only the INT/F32/F64
  accumulators), silently corrupting money/exact data. They are now computed
  **exactly** using a bounded, allocation-free big-integer accumulator
  (`src/cdb_decimal_agg.{c,h}`): scale-aligned SUM, decimal-value MIN/MAX returning
  the exact stored winner, and AVG as `sum / count` at the bucket's maximum input
  scale rounded **half-to-even** (ADR-0003 — the spec left DECIMAL AVG rounding
  unspecified). A numeric aggregate over a non-aggregatable type now **fails closed**
  with `CDB_E_UNSUPPORTED` instead of a silent 0. No `double` round-trip, no
  `__int128`, C99, `no-heap-in-core` preserved; stored bytes are length-checked and
  intermediates fail closed with `CDB_E_OVERFLOW`. COUNT/FIRST/LAST and the
  INT/F32/F64 paths are unchanged. Held to a committed regression test
  (`tests/test_ts_downsample_decimal.c`, red→green proven under ASan+UBSan).
  (DECIMAL-downsample item of #40)
- Resolved three undefined-behaviour bugs caught by UndefinedBehaviorSanitizer,
  each held to a committed regression test (delivered together in #19):
  - **Crypto** — undefined behaviour on the cryptography path. (#15)
  - **Pager** — undefined behaviour in the pager. (#16)
  - **Index** — undefined behaviour in the ordered-index / B+tree path. (#17)
- Repository hygiene cleanups accompanying the UBSan fixes. (#19)

### Added

- **CMBQL-TEXT query-engine front-end** — the eight previously text-unreachable
  operators (`AGGREGATE`, `UNION`, `TRAVERSE`, `TEXT_SEARCH`, `VECTOR_SEARCH`,
  `HYBRID_RANK`, `ASOF_JOIN`, `UNNEST`) now have grammar/parser productions in
  `src/cdb_compiler.c` that compile from CMBQL text to the same CMBQ wire the
  executor consumes — reachable via the pipeline syntax (`… | text_search(…)`,
  `… | aggregate(by: […], n: count(*))`, `… | traverse(…)`, …) and the
  stream-operator constructors (`TextSearch`/`VectorSearch`/`Traverse`/
  `HybridRank`/`AsofJoin`/`Union`). `count(*)` and the aggregate functions parse
  inside `aggregate(…)` (closing the "Unknown function call" / "Unknown pipeline
  stage" backlog items); reserved words are accepted as field names. Malformed
  clauses fail closed with a typed parse error (CWE-20/-674). (#35)
- **Public `cdb_db_query(db, text, …)`** (`src/cdb_db.h`) — compiles CMBQL text
  against the database catalog and opens a streaming execution cursor, with
  caller-owned, no-heap-in-core buffers; fail-closed on parse/exec error. (#35)
- `docs/CHANGELOG.md` — this file. (#20)
- `docs/FAQ.md` — frequently asked questions covering what the engine is, the
  build/toolchain, the data models and CMBQL, cryptography, and coverage posture. (#20)

### Changed

- **Triggers now fire.** `cdb_trigger_dispatch` resolves a trigger's registered
  procedure (new `cdb_trigger_register_proc` / `cdb_db_register_proc` no-heap
  bytecode registry), marshals the mutated row's old/new values as procedure
  parameters, honours the per-trigger depth/cascade limit, and actually executes
  the procedure via the proc VM — fail-closed on a procedure error (it no longer
  `(void)`-discards its arguments and only bumps a counter). The commit path
  (`cdb_tx_commit`) captures matching-store mutations during a transaction and
  dispatches their post-commit triggers once the commit is durable
  (spec 11.6/11.9). (#35)
- Refreshed the `README.md` quickstart into a copy-pasteable
  clone → configure → build → test → coverage sequence against the real
  `CMakePresets.json` presets. (#20)

## Milestone history

The engine was built milestone by milestone (`docs/dev/milestones.md` is the
authoritative record). The arc below is reverse-chronological; statuses mirror
that file exactly — in-progress and planned work is **not** flattened to done.

- **M27–M32 — Enclaves, held logs, joined stores, principals & grants** — *planned.*
  Enclave directory and per-enclave catalogs, stores inside enclaves, the held
  log, joined stores and cross-domain links, moving stores between enclaves, and
  stored procedures / principals / roles / grants as catalog records. These build
  atop the now-corrected key-wrap primitive (per-wrap random nonce, GHSA-2xx7-85rc-w3q8),
  which is where wrapped enclave keys first persist to disk.
- **M26 — Enclave format foundation** — *in progress: format and salts done.*
  Store-ID slot on every page, hidden IDs on encrypted pages and delta records,
  HKDF subkeys with the Section 12.2 labels, and per-session salts (salt table,
  overlay nonce track, budgeted salt scrub). The demo database was rebuilt.
- **M25 — Compute acceleration (layers 1–4)** — *layers 1–4 done; approximate
  search's pending pass still runs on the CPU (BACKLOG).* Accelerator hook in
  `cdb_env`, mirrors, certified exact search, the fake accelerator (layer 1); the
  CUDA backend (layer 2); the Vulkan backend with checked-in SPIR-V (layer 3);
  bulk search and graph-refresh acceleration (layer 4).
- **M24 — Security & authenticated encryption** — *done.* AES-256-GCM and
  ChaCha20-Poly1305, envelope key wrapping, subkey derivation, key rotation,
  tamper-evident governance mode, identities and RBAC authorization.
- **M20–M23 — Parallelism and query** — *done.* Optional thread/mutex environment
  hooks and worker threads (M20); the CMBQL structured operator-tree core and the
  stored-procedure bytecode engine (M21); the human-readable CMBQL text language
  and its grammar/lexer compiling into that core (M22); cross-store atomic
  transactions, triggers, scheduled procedures, and procedure savepoints (M23).
- **M15–M19 — Models completed, transactions and the coordinator** — *done.*
  Links and the environment clock (M15); time series (M16); row-oriented tables
  and nibblets (M17); column-oriented tables and xz/LZMA2 compression (M18); the
  multi-process coordinator with primary/subordinate election, heartbeats, and
  recovery (M19).
- **M9–M14 — Documents, FTS, vectors, overflow** — *done.* Document revision
  chains and patches (M9); write-time document schema validation (M10); BM25
  full-text search (M11); vector collections with exact search (M12); the
  neighbour graph and approximate search (M13); overflow pages (M14).
- **M0–M8 — Foundations** — *done.* Build skeleton, warnings, sanitizers, test
  runner (M0); CRC-32C, varints, byte-order and value encoding (M1); the storage
  backend interface plus host-file and fault-injecting backends (M2); the file
  header (M3); pages, anchor map, and free-space list (M4); delta tracks,
  transactions, reconciliation and recovery (M5); space reuse and compaction (M6);
  the order-preserving B+tree index (M7); and the catalog (M8).

[Unreleased]: https://github.com/gorovehq/combolite-core
