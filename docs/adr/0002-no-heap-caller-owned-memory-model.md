# ADR-0002: No heap in the core; caller-owned buffers

- **Status:** Accepted
- **Date:** 2026-11-21
- **Supersedes / Superseded by:** —

> Retroactive record of a foundational, long-standing design choice (backfilled with ADR-0001).

## Context

`combolite-core` targets both host and **microcontroller (MCU)** profiles and must be crash-safe
and predictable under tight, auditable resource bounds. Implicit dynamic allocation in the engine
would make memory use unpredictable, complicate MCU/freestanding targets, widen the attack surface
(allocation-driven DoS, use-after-free), and make deterministic testing harder.

## Decision

The core performs **no heap allocation**. Memory is supplied by the caller:

- Callers size buffers via the `cdb_*_buffers_size()` helpers and pass them in.
- An optional env `alloc`/`free` hook (`cdb_env.h`) is available on the **host** profile only;
  the MCU profile is fully static.
- Readers return **views (pointers) into caller-owned buffers**, not copies. Slot-pointer lifetime
  is bounded (valid until the next open of the same model, outside a tx/op scope — callers wrap
  multi-step work in `cdb_db_op_begin` / `cdb_db_op_end`).
- Reaching a configured limit returns `CDB_E_OUT_OF_BUDGET` rather than growing unbounded.

## Alternatives considered

- **Internal malloc/free** — simplest API, but unpredictable footprint, poor MCU fit, larger
  attack surface, non-deterministic tests. Rejected.
- **A single internal arena owned by the engine** — better than malloc, but still hides sizing
  from the caller and complicates the MCU/static story. Rejected in favor of explicit
  caller-owned buffers + optional host alloc hooks.

## Consequences

- Predictable, auditable memory use; MCU/freestanding support; smaller attack surface; deterministic,
  fault-injectable tests (`cdb_faultdev` / `cdb_faultenv`).
- The API is more demanding: callers compute buffer sizes and must respect **view/slot lifetime**
  (a real use-after-scope hazard — called out in `CONTRIBUTING.md` and the dev docs).
- All size/offset arithmetic on untrusted input must be overflow-guarded before buffer math (see
  the security fixes under advisory GHSA-rf29-8939-p85v).
