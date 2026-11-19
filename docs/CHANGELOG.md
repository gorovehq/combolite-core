# Changelog

All notable changes to `combolite-core` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches its first tagged release. No version has been tagged yet, so all
entries live under `[Unreleased]`.

Issue and pull-request numbers refer to the `gorovehq/combolite-core` tracker.

## [Unreleased]

### Security

- Bumped the vendored Mbed TLS submodule from 3.6.2 to **3.6.5**, picking up the
  upstream maintenance and security fixes for the crypto primitives the engine
  relies on (AES-256-GCM, ChaCha20-Poly1305, SHA-256, HMAC, HKDF, ECDSA). (#1)

### Fixed

- Resolved three undefined-behaviour bugs caught by UndefinedBehaviorSanitizer,
  each held to a committed regression test (delivered together in #19):
  - **Crypto** — undefined behaviour on the cryptography path. (#15)
  - **Pager** — undefined behaviour in the pager. (#16)
  - **Index** — undefined behaviour in the ordered-index / B+tree path. (#17)
- Repository hygiene cleanups accompanying the UBSan fixes. (#19)

### Added

- `docs/CHANGELOG.md` — this file. (#20)
- `docs/FAQ.md` — frequently asked questions covering what the engine is, the
  build/toolchain, the data models and CMBQL, cryptography, and coverage posture. (#20)

### Changed

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
  stored procedures / principals / roles / grants as catalog records. The
  key-wrap nonce fix (see the README "Known Issues") lands first, in M27.
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
