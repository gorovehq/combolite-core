# combolite-core

`combolite-core` is the embeddable, serverless multi-model database engine in C99. At rest, a database is a single archive file (`.cdbarch`). While open, a working directory (`.cdbwork`) manages lockfiles, write-ahead journals, slot coordinators, and transaction overlays.

The core engine is clean-room, strictly crash-safe, and designed with zero external dynamic dependencies. It natively stores five distinct data models within one engine:
- **Relational Tables**: Row-oriented with compound keys, secondary B-tree indexes, foreign keys, and catalog-driven schema migrations.
- **Document Pools**: Variable-length JSON documents with revision histories, delta patches, schema validation, and integrated full-text search (BM25 ranking).
- **Vector Collections**: Dense float32, int8, and 1-bit binary vectors with exact distance computation and an HNSW-like navigable small-world neighbour graph for sub-linear approximate nearest neighbour (ANN) search.
- **Graph Links**: Directed, weighted edges connecting entries across models with cardinality constraints, CASCADE/SET NULL delete rules, and fast bidirectional edge lookups.
- **Time Series**: Append-only temporal metrics with bit-packed columnar blocks, millisecond/nanosecond timestamps, late-arrival policies, and downsampling rollups.
- **Content-Addressed Blobs**: Streaming zero-copy large object storage backed by incremental SHA-256 / HMAC-SHA-256 chunking across overflow page extents.

---

## Architectural Principles

1. **Zero Heap Allocation in Core**: The engine never invokes `malloc`, `realloc`, or `free`. All execution scratch space, page caches, and transaction buffers are supplied by the caller or through the host environment's optional allocator hooks (`cdb_env_ops`). This enables predictable memory boundaries and compilation for resource-constrained microcontrollers.
2. **Crash-Safe Journaling & Liveness Redesign**: All mutations are journaled with strict write-ahead ordering, CRC-32C checksums, and torn-write protection. Process liveness is strictly anchored to OS-level file locks on coordinator slot files; an ungraceful crash or process kill leaves the archive undamaged, allowing surviving or newly opened processes to safely reconcile or adopt pending journals.
3. **Canonical Binary Serialization**: Every multi-byte integer and float on disk is encoded through explicit endian-neutral macros (`cdb_endian.h`). Validators strictly enforce canonical forms and reject non-canonical encodings.
4. **Single-File Portability**: An idle database is entirely self-contained in a single archive file (`.cdbarch`), easily transferred, archived, or replicated.

---

## Prerequisites

- **C Compiler**: C99-compliant compiler (`gcc` >= 9 or `clang` >= 11).
- **Build System**: CMake >= 3.20.
- **Host OS**: Linux, macOS, FreeBSD, or POSIX-compliant environment.
- **Optional Accelerators**: NVIDIA CUDA Toolkit >= 11.8 or Vulkan SDK 1.3+ (handled via `combolite-accelerator`).

---

## Building

`combolite-core` can be built as part of the umbrella project or standalone:

### Standalone Build

```sh
cd combolite-core
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DCDB_BUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

### Umbrella Presets (from Repository Root)

```sh
# Debug build with ASan and UBSan sanitizers (standard development profile)
cmake --preset core-both-debug
cmake --build --preset core-both-debug -j
ctest --preset core-both-debug -j4

# CPU-only Release build
cmake --preset core-cpu-release
cmake --build --preset core-cpu-release -j
```

---

## Getting Started: C99 API

All public database interfaces are declared in `<combolite/combolite.h>`.

### Minimal Lifecycle Example

```c
#include <stdio.h>
#include <string.h>
#include <combolite/combolite.h>

int main(void)
{
    cdb_status st;
    cdb_db_config cfg;
    cdb_db *db = NULL;

    /* Initialize default configuration */
    cdb_db_config_init(&cfg);
    cfg.page_size = CDB_PAGE_SIZE_4K;

    /* Open or create database archive */
    st = cdb_db_open("my_data.cdbarch", &cfg, &db);
    if (st != CDB_OK) {
        fprintf(stderr, "Failed to open database: %d\n", (int)st);
        return 1;
    }

    /* Begin a read-write transaction */
    cdb_tx *tx = NULL;
    st = cdb_tx_begin(db, CDB_TX_READ_WRITE, &tx);
    if (st == CDB_OK) {
        /* Define a relational table schema */
        cdb_table_def def;
        memset(&def, 0, sizeof(def));
        def.name = "users";
        def.name_len = 5;

        /* Create table in catalog */
        st = cdb_table_create(tx, &def);
        if (st == CDB_OK) {
            /* Commit transaction durably */
            st = cdb_tx_commit(tx);
        } else {
            cdb_tx_rollback(tx);
        }
    }

    /* Close database cleanly (flushes journals and removes coordinator slot) */
    cdb_db_close(db);
    return (st == CDB_OK) ? 0 : 1;
}
```

---

## Features as Built

- **M01–M09 Storage & Pager Foundations**: Variable-size B+Tree pages, leaf rebalancing, overflow chains, nibblet shared tail packing, CRC-32C validation, and dual-copy mirrored catalog headers.
- **M10–M14 Multi-Model Data Stores**:
  - Relational tables with primary keys, composite unique indexes, and column-level default values.
  - Document pools with JSON delta revisions, BM25 tokenizer and full-text index scoring.
  - Vector collections with cosine, Euclidean, and dot-product distances; f32, i8, and 1-bit Hamming binary vectors; incremental neighbour graph construction.
  - Time series blocks with run-length and bit-packed delta timestamps and values.
  - Graph links with token-based traversal and foreign key integrity cascades.
- **M15–M19 Transactions & Concurrency**:
  - ACID transactions with savepoint rollbacks (`cdb_tx_savepoint`, `cdb_tx_rollback_to`).
  - Liveness redesign (steps 1–5, 7): Multi-process coordination with POSIX slot locking (`lock_open`/`lock_close`), crash and kill sweeps (`test_coord`), journal adoption, and background responder threads off `mutex_trylock`.
- **M24 CRDT & Replication Core**:
  - Hybrid Logical Clocks (`cdb_hlc`) with causal total ordering.
  - Peer version vectors (`cdb_crdt_vector`) with dominance testing.
  - Field-level Last-Write-Wins (LWW) document registers, Add-Wins Observed-Remove Sets (AWORSet) for graph links, and PN-Counters.
  - Transport-agnostic binary delta-slice export/import (`cdb_db_crdt_export_slice`, `cdb_db_crdt_import_slice`).
- **M26 Partition Isolation & Encryption**:
  - Store ID slot headers on all pages.
  - Hidden IDs on encrypted delta journal records.
  - HKDF subkey derivation per store and tenant.
  - Session salts, salt tables, and memory scrub routines.
- **Hardware Acceleration Hook**:
  - Zero-overhead C dispatch hook (`cdb_env_ops.accel`) integrating optional CUDA and Vulkan hardware backends via `combolite-accelerator`.

---

## Known Issues

1. **Key-Wrap Fixed Nonce Reuse (`BACKLOG.md`)**: `cdb_crypto_wrap_key` currently utilizes a fixed AES-GCM nonce under the master key. No wrapped keys are stored on disk in current milestone builds; full remediation via AES Key Wrap (RFC 3394 / NIST SP 800-38F) is scheduled for M27 before encrypted keystores land.
2. **Concurrent Database Creation**: If two processes simultaneously attempt to create a non-existent database file at the same instant without an external lock, an archive race can occur prior to slot initialization.
3. **Transaction ID Block Allocation Ceiling**: A single process is currently capped at 21 held ID blocks (21,504 new records) across open stores prior to transaction commit / catalog reconciliation (`CDB_E_OUT_OF_BUDGET`).
4. **Graph Refresh Walk Scalability**: For large vector collections (>15,000 vectors), CPU-bound reachability index walks in `check_entry` scale quadratically without hardware acceleration.

---

## ToDos

- Implement Step 6 dynamic coordinator primary election and dynamic slot count allocation (`coord/primary`).
- Finalize Enclave storage engines (M27–M31: enclave directory, stores, held logs, joined store cross-references).
- Implement catalog-level procedures, principals, and access grants (M32).
- Optimize graph refresh walks via batched index seeks.
- Add ARM64 NEON and CRC32 assembly optimizations to hardware acceleration path.

---

## Provisioned but Not Yet Implemented

The following features, interfaces, or operators are provisioned in headers, specification documents, or executor scaffolds, but are not yet fully implemented:

1. **Executor High-Level Query Operators (`src/cdb_exec.c`)**:
   - `TEXT_SEARCH`: The `text_search_next` executor operator functions as a pass-through scoring filter; integrated streaming query evaluation across BM25 posting lists is stubbed.
   - `VECTOR_SEARCH`: The `vector_search_next` operator executes linear scans; integration with the neighbour graph within the pipelined executor tree is pending.
   - `TRAVERSE`: The `traverse_next` operator emits fixed `$depth` fields; recursive multi-hop path traversal and cycle detection are pending.
   - `HYBRID_RANK`: The `hybrid_next` operator contains stubbed Reciprocal Rank Fusion (RRF); multi-branch pipeline execution is not yet integrated.
2. **Coordinator Primary Election & Dynamic Slots (Step 6)**:
   - Dynamic allocation of coordinator slots beyond the compiled default and primary node designation via `coord/primary` (as outlined in `docs/dev/plan-step6-coord-primary.md`).
3. **Enclave Storage & Keystore (M27–M31)**:
   - Enclave directory and encrypted stores, held log compaction, cross-enclave moves, and joined store queries.
4. **Procedures, Principals, and Catalog Grants (M32)**:
   - Storing user procedures, cryptographic principals, and permission grants as catalog records.
5. **Automated Background P2P Replication Gossip (Spec 19 Draft)**:
   - While binary delta-state CRDT slice codecs and sync methods are implemented, automated background peer discovery and socket gossip are in draft specification.
6. **Prepared Transaction Estimate Wait (Spec 5.9.4)**:
   - The coordinator wait loop on prepared transactions does not yet parse the holder's published duration estimate.
7. **Microcontroller Profiles (MCU Profile)**:
   - Microcontroller build target presets (`noxz`) are paused until post-1.0 release; the code preserves no-heap guarantees to ensure compatibility upon unpausing.

---

## License

MIT: See [`LICENSE`](LICENSE) for complete license text. Third-party components (Mbed TLS, xz) are documented in [`ATTRIBUTIONS.md`](../ATTRIBUTIONS.md).
