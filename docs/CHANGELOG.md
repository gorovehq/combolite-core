# Changelog

All notable changes to `combolite-core` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches its first tagged release. No version has been tagged yet, so all
entries live under `[Unreleased]`.

Issue and pull-request numbers refer to the `gorovehq/combolite-core` tracker.

## [Unreleased]

### Fixed

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
