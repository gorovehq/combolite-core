# Frequently Asked Questions

Answers for people evaluating or contributing to `combolite-core`. Everything here
is kept accurate to the current merged tree; where a feature is still in progress or
planned, that is stated rather than glossed over. See the [`README.md`](../README.md)
for the full capability list and the [`CHANGELOG.md`](CHANGELOG.md) for what changed.

---

## 1. What is combolite-core?

`combolite-core` is an embeddable, serverless, multi-model database engine written
in C99. At rest a database is a single archive file (`.cdbarch`); while open it uses
a working directory (`.cdbwork`) for lockfiles, write-ahead journals, slot
coordinators, and transaction overlays.

It is clean-room, strictly crash-safe, and designed with **zero external dynamic
dependencies** and **zero heap allocation in the core** — all scratch space, page
caches, and transaction buffers come from the caller or from optional environment
allocator hooks (`cdb_env_ops`), which is what lets it target resource-constrained
devices as well as servers. Mutations are journaled with write-ahead ordering,
CRC-32C checksums, and torn-write protection, and process liveness is anchored to
OS-level file locks, so an ungraceful crash leaves the archive undamaged.

---

## 2. How do I build it, and what toolchain do I need?

**Prerequisites:** a C99 compiler (`gcc` >= 9 or `clang` >= 11), CMake >= 3.20, and a
POSIX-compliant host (Linux, macOS, FreeBSD). CUDA and Vulkan SDKs are **optional** and
only needed for the accelerator presets.

The crypto, compression, and test-framework dependencies are vendored as git
submodules (Mbed TLS, xz, Unity), so clone with submodules:

```sh
git clone --recurse-submodules https://github.com/gorovehq/combolite-core.git
```

If you already cloned without `--recurse-submodules`, pull them in afterwards:

```sh
git submodule update --init --recursive
```

Then configure, build, and test with the CPU-only debug preset (ASan + UBSan +
tests, no accelerator SDK required):

```sh
cmake --preset core-cpu-debug
cmake --build --preset core-cpu-debug -j
ctest --preset core-cpu-debug --output-on-failure
```

`core-cpu-debug` is the toolchain-light path and the one the README quickstart
uses. The maintainers' long-term profile is `core-both-debug` ("the build to test
in until 1.0"), which additionally needs the CUDA and Vulkan SDKs; `core-cpu-release`
is the optimised, sanitizer-off CPU build. All preset names come straight from
`CMakePresets.json`.

---

## 3. What data models does it support, and what is CMBQL?

The engine natively stores five query-addressable data models in one archive, plus
full-text search and content-addressed blob storage:

- **Document pools** — variable-length JSON documents with revision histories, delta
  patches, write-time schema validation, and **integrated full-text search** (BM25
  ranking).
- **Relational tables** — row- and column-oriented tables with compound keys,
  secondary B-tree indexes, foreign keys, and catalog-driven schema migrations.
- **Vector collections** — dense float32, int8, and 1-bit binary vectors with exact
  distance computation and an HNSW-like navigable small-world neighbour graph for
  approximate nearest-neighbour search.
- **Time series** — append-only temporal metrics with bit-packed columnar blocks,
  millisecond/nanosecond timestamps, late-arrival policies, and downsampling rollups.
- **Graph links** — directed, weighted edges connecting entries across models with
  cardinality constraints, CASCADE / SET NULL delete rules, and bidirectional lookups.

On top of these sits **CMBQL** (Combolite Query Language), the engine's own
human-readable query language. CMBQL has a formal grammar and lexer and compiles
into a structured operator-tree core (Scan / Filter / Project / Join / Sort / Limit /
Union / Aggregate / Traverse / TextSearch / VectorSearch / HybridRank), which also
backs a stored-procedure bytecode engine. Note that some high-level executor
operators (`TEXT_SEARCH`, `VECTOR_SEARCH`, `TRAVERSE`, `HYBRID_RANK`) still have
pipeline-integration work pending — see the README "Provisioned but Not Yet
Implemented" section.

---

## 4. What cryptography does it use?

Authenticated encryption, hashing, key derivation, and identity signing are all
provided through the **vendored Mbed TLS** library (currently 3.6.5), never
hand-rolled:

- **Authenticated encryption (AEAD):** **AES-256-GCM** or **ChaCha20-Poly1305**,
  chosen per file by a header flag. AES-256-GCM is hardware-accelerated on most
  CPUs and on ESP32; ChaCha20-Poly1305 is the choice for chips without AES hardware.
- **Hashing and integrity:** **SHA-256**, and **HMAC-SHA-256** for keyed content
  hashes and keyed page-integrity tags in governance mode.
- **Key derivation:** **HKDF-SHA-256**, deriving a separate subkey per purpose
  (page, hash, index, seal, replication, …) from each domain key, using the job's
  label as the HKDF info so a weakness in one use can't affect another.
- **Identity signing:** **ECDSA on the NIST P-256 (secp256r1) curve**. A principal
  identity is an asymmetric key pair registered in the catalog; by default only
  **audit-series events** are signed (the policy is configurable to sign every
  revision or nothing).

Nonces are **deterministic** (built from a track ID and a sequence number, not an
RNG); per-session random salts keep forks and restored backups from reusing nonces.

**Honest caveat (do not overstate confidentiality):** `cdb_crypto_wrap_key`
currently uses a *fixed* AES-GCM nonce under the master key. No wrapped keys are
written to disk in current milestone builds, and full remediation via AES Key Wrap
(RFC 3394 / NIST SP 800-38F) is scheduled for M27 before encrypted keystores land —
this is tracked in the README "Known Issues" and `docs/BACKLOG.md`. Also note that
RBAC runs inside the application's own process: **confidentiality comes from keys,
not from RBAC** — a hostile process that already holds a key can bypass policy
checks. See [`docs/spec/12-security.md`](spec/12-security.md) for the full model.

---

## 5. What is the test coverage posture?

The suite (Unity + CTest) works toward high **line** and **branch** coverage of
first-party code (`src/**`, excluding `third-party/` and the tests themselves), with
the **critical paths** — cryptography (`cdb_crypto.c`) and the durability/catalog
read-write path — held to the highest bar. The public API is driven end to end by
`test_e2e_lifecycle`, and negative/abuse paths (tampered ciphertext, wrong keys,
buffer-too-small encoders, malformed input) are covered by dedicated edge suites.

Measure coverage with Clang source-based instrumentation via the `CDB_COVERAGE`
option (off by default); see `docs/dev/testing-and-coverage.md` for the full
`llvm-profdata` / `llvm-cov` recipe.

The largest **known gap** is **defensive error branches** — the status checks
guarding every allocation, I/O operation, and downstream crypto call. By design
these are not reachable with ordinary inputs; triggering them means injecting the
underlying failure. The engine already ships a fault-injection harness
(`cdb_faultdev` / `cdb_faultenv`) that the crash-recovery suites use, and closing
the gap is a matter of extending those sweeps across the full operation surface,
asserting each error path returns its typed status and leaves state consistent
(fail-closed, no partial writes).

This is an **interim posture with ongoing work to ratchet coverage up**, tracked in
issue **#18**; there is deliberately **no fabricated coverage percentage** here —
the authoritative, current description lives in
[`docs/dev/testing-and-coverage.md`](dev/testing-and-coverage.md). Contributions
that extend a module's fault sweep (and turn any finding into a committed regression
test) are welcome.
