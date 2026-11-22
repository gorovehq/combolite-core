# ADR-0003: Exact DECIMAL downsample aggregation and AVG rounding

- **Status:** Accepted
- **Date:** 2026-11-21
- **Supersedes / Superseded by:** —

> Relates to issue #40 (the DECIMAL time-series downsample item). Builds on ADR-0002
> (no heap in the core).

## Context

Time-series downsampling (spec §10.4) reduces a bucket of raw points into one summary point
per aggregate (SUM / MIN / MAX / AVG / COUNT / FIRST / LAST). The aggregation loop in
`src/cdb_ts.c` only populated its integer and floating-point accumulators for
`CDB_TYPE_INT`, `CDB_TYPE_F64` and `CDB_TYPE_F32`. A `CDB_TYPE_DECIMAL` field — combolite's
exact money type — left those accumulators at zero, so SUM / MIN / MAX / AVG over a DECIMAL
column emitted **0 with no error**: silent corruption of financial data. Types that cannot be
numerically aggregated at all (string, binary, object, array, …) were likewise reduced to a
silent 0.

A DECIMAL value is an unscaled integer (shortest big-endian two's complement) and a decimal
scale: `value = unscaled × 10^-scale`. The engine had no decimal arithmetic, no `__int128`,
and must stay C99 and allocation-free (ADR-0002). `double` cannot represent decimal money
exactly, so routing money through it is not acceptable.

## Decision

1. **Exact integer arithmetic.** A fixed-capacity sign-magnitude big integer
   (`src/cdb_decimal_agg.{h,c}`, base-2³² limbs) aggregates DECIMAL fields exactly, with no
   `double` and no `__int128`:
   - **SUM** — scale-aligned exact sum. The running sum is held at the **maximum input scale**
     seen in the bucket; a value at a smaller scale is multiplied up, and the sum is multiplied
     up when a larger scale appears.
   - **MIN / MAX** — the **exact stored DECIMAL** that is the numeric minimum / maximum
     (scale-aware decimal comparison; the winner's bytes and scale are emitted unchanged).
   - **AVG** — `exact_sum / count` at the bucket's maximum input scale, rounded
     **half-to-even** (banker's rounding). Exact when it divides evenly. The spec left the
     DECIMAL AVG rounding mode unspecified; this ADR fixes it as half-to-even, which is
     symmetric, bias-free and the common convention for money.
2. **Fail closed, never silently zero.** A numeric aggregate (SUM / AVG / MIN / MAX) over a
   type that cannot be numerically aggregated returns `CDB_E_UNSUPPORTED` and emits no point,
   rather than a fabricated 0.
3. **Bounded, allocation-free (ADR-0002).** The accumulator is a fixed stack/struct buffer.
   An unscaled integer longer than `CDB_DEC_MAX_BYTES`, or any intermediate that would exceed
   the capacity, fails closed with `CDB_E_OVERFLOW` — never a truncated or wrapped result.
   Stored DECIMAL bytes are treated as untrusted input: every read is length-checked (proven
   under ASan + UBSan).
4. **Scope.** COUNT / FIRST / LAST and the INT / F32 / F64 paths are unchanged; no public API
   or on-disk format change.

## Alternatives considered

- **Accumulate through `double`** — trivial, but loses precision on money; the exact defect
  being fixed. Rejected.
- **A 128-bit (`__int128`) accumulator** — simpler, but not portable C99 and still too small
  for a bucket sum of many 38-digit decimals. Rejected in favour of a fixed-limb big integer.
- **AVG round-half-up or truncate** — biased; half-to-even is the money convention. Rejected.

## Consequences

- DECIMAL SUM / MIN / MAX / AVG are exact; the AVG rounding mode is defined and documented.
- Non-aggregatable types fail closed with a typed error instead of silently emitting 0.
- A new fixed-size accumulator is embedded per field in the downsample state; capacity is
  bounded and documented, and an over-capacity input fails closed rather than corrupting.
- Unrelated pre-existing behaviour (for example FIRST/LAST re-emitting a decimal through the
  generic value path) is **not** changed by this ADR and remains a separate matter.
