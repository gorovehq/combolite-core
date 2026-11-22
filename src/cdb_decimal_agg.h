/* Exact, heap-free aggregation of DECIMAL (money) values for time-series
 * downsampling (spec 10.4, issue #40).
 *
 * A DECIMAL value is an unscaled integer (shortest big-endian two's
 * complement) and a decimal scale: value = unscaled * 10^-scale. Summing or
 * averaging such values through `double` loses precision, so this accumulator
 * does the arithmetic on a fixed-capacity sign-magnitude big integer:
 *
 *   SUM  - scale-aligned exact integer sum.
 *   MIN  - the exact stored DECIMAL that is the numeric minimum of the bucket.
 *   MAX  - the exact stored DECIMAL that is the numeric maximum of the bucket.
 *   AVG  - exact_sum / count at the bucket's maximum input scale, rounded
 *          half-to-even (banker's rounding; see docs/adr/0003). No `double`.
 *
 * Everything is bounded and allocation-free (ADR-0002, no-heap-in-core): an
 * input whose unscaled integer is longer than CDB_DEC_MAX_BYTES, or any
 * intermediate that would exceed the accumulator capacity, fails closed with
 * CDB_E_OVERFLOW rather than truncating or wrapping. Stored DECIMAL bytes are
 * treated as untrusted input: every read is length-checked.
 *
 * A zeroed struct (for example from memset) is a valid empty accumulator;
 * cdb_decimal_agg_reset does the same explicitly. */
#ifndef CDB_DECIMAL_AGG_H
#define CDB_DECIMAL_AGG_H

#include <stddef.h>
#include <stdint.h>

#include "combolite/cdb_common.h"

/* Magnitude capacity in 32-bit limbs: 40 limbs = 1280 bits, enough to sum
 * many 128-byte-input decimals (each <= 1024 bits) with headroom. */
#define CDB_DEC_LIMBS 40u

/* Largest accepted unscaled-integer length, in bytes (also the width used to
 * retain MIN/MAX winners). 128 bytes keeps a parsed magnitude within the limb
 * capacity with room to spare. */
#define CDB_DEC_MAX_BYTES 128u

/* Minimum output-buffer size, in bytes, for a SUM/AVG result emitted by this
 * module (a full-capacity magnitude plus sign room). */
#define CDB_DEC_EMIT_MAX 176u

/* Fixed-size, heap-free DECIMAL accumulator for one downsample field. */
typedef struct cdb_decimal_agg {
    uint32_t sum_mag[CDB_DEC_LIMBS]; /* running SUM magnitude, little-endian limbs */
    int sum_neg;                     /* sign of the running SUM (0 for zero)        */
    uint64_t sum_scale;              /* scale the running SUM is held at (max seen)  */

    uint8_t min_be[CDB_DEC_MAX_BYTES]; /* exact MIN winner, as stored */
    size_t min_len;
    uint64_t min_scale;

    uint8_t max_be[CDB_DEC_MAX_BYTES]; /* exact MAX winner, as stored */
    size_t max_len;
    uint64_t max_scale;

    uint64_t count; /* number of values folded in */
    int have;       /* whether any value has been added */
} cdb_decimal_agg;

/* Returns the accumulator to the empty state. */
void cdb_decimal_agg_reset(cdb_decimal_agg *st);

/* Folds one DECIMAL value (scale + shortest big-endian two's-complement
 * unscaled integer) into the accumulator, updating SUM, MIN, MAX and count.
 * `unscaled_be`/`len` must be a non-empty, length-checked buffer. Returns
 * CDB_E_INVALID_ARG on a null/empty input and CDB_E_OVERFLOW when the value or
 * an intermediate exceeds the fixed capacity. */
cdb_status cdb_decimal_agg_add(cdb_decimal_agg *st, uint64_t scale, const uint8_t *unscaled_be,
                               size_t len);

/* Writes the aggregate result as a canonical shortest big-endian two's
 * complement unscaled integer into out[0..cap) and its scale into *scale.
 * CDB_E_INVALID_ARG if the accumulator is empty; CDB_E_BUFFER_TOO_SMALL if the
 * result does not fit; CDB_E_OVERFLOW on a capacity overflow (AVG round-up). */
cdb_status cdb_decimal_agg_sum(const cdb_decimal_agg *st, uint64_t *scale, uint8_t *out, size_t cap,
                               size_t *out_len);
cdb_status cdb_decimal_agg_min(const cdb_decimal_agg *st, uint64_t *scale, uint8_t *out, size_t cap,
                               size_t *out_len);
cdb_status cdb_decimal_agg_max(const cdb_decimal_agg *st, uint64_t *scale, uint8_t *out, size_t cap,
                               size_t *out_len);
cdb_status cdb_decimal_agg_avg(const cdb_decimal_agg *st, uint64_t *scale, uint8_t *out, size_t cap,
                               size_t *out_len);

#endif /* CDB_DECIMAL_AGG_H */
