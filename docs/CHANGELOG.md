# Changelog

All notable changes to `combolite-core` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches its first tagged release. No version has been tagged yet, so all
entries live under `[Unreleased]`.

Issue and pull-request numbers refer to the `gorovehq/combolite-core` tracker.

## [Unreleased]

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
