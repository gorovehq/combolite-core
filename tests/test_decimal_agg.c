/* Unit + abuse tests for the exact DECIMAL aggregator (src/cdb_decimal_agg.c),
 * the money-exact core behind the issue #40 downsample fix.
 *
 * These are white-box, hermetic unit tests for the big-integer accumulator
 * itself: exact SUM/MIN/MAX/AVG, scale alignment, sign handling and zero
 * cancellation, banker's (round-half-to-even) AVG, and — critically — the
 * fail-closed negative paths (NULL/empty args, over-long input, scale blow-up
 * overflow, buffer-too-small, empty accumulator). The engine-level red->green
 * regression lives in test_ts_downsample_decimal.c; this suite proves the
 * arithmetic kernel never silently produces a wrong number or writes OOB
 * (validated under ASan+UBSan).
 *
 * Correctness is checked against an independent reference encoder (enc_i64):
 * every expected result is produced by a second, simple canonical
 * big-endian two's-complement encoder, so a bug in the module cannot be
 * masked by reusing the module to compute its own oracle. All inputs are
 * fixed and synthetic; no clock, network, or shared state. */

#include <stdint.h>
#include <string.h>

#include "unity.h"
#include "cdb_decimal_agg.h"

/* ---- reference oracle: canonical BE two's complement of an int64 --------- */

/* Independent of the module under test. Emits the shortest big-endian two's
 * complement of v into out (>= 9 bytes); returns the length (>= 1). */
static size_t enc_i64(int64_t v, uint8_t *out)
{
    uint8_t b[8];
    uint64_t u = (uint64_t)v;
    size_t s, len, i;
    for (i = 8; i-- > 0;) {
        b[i] = (uint8_t)(u & 0xFFu);
        u >>= 8;
    }
    s = 0;
    while (8u - s >= 2u) {
        if (b[s] == 0x00u && !(b[s + 1] & 0x80u))
            s++;
        else if (b[s] == 0xFFu && (b[s + 1] & 0x80u))
            s++;
        else
            break;
    }
    len = 8u - s;
    for (i = 0; i < len; i++)
        out[i] = b[s + i];
    return len;
}

/* Folds one int64 value at the given scale into the accumulator. */
static cdb_status add_i64(cdb_decimal_agg *st, int64_t v, uint64_t scale)
{
    uint8_t b[9];
    size_t n = enc_i64(v, b);
    return cdb_decimal_agg_add(st, scale, b, n);
}

typedef cdb_status (*agg_fn)(const cdb_decimal_agg *, uint64_t *, uint8_t *, size_t, size_t *);

/* Asserts an aggregate getter returns exactly want_val at want_scale. */
static void assert_agg_eq(agg_fn fn, const cdb_decimal_agg *st, int64_t want_val, uint64_t want_scale)
{
    uint8_t got[CDB_DEC_EMIT_MAX];
    uint8_t exp[9];
    size_t glen = 0, elen;
    uint64_t gscale = 0xDEAD;
    TEST_ASSERT_EQUAL_INT(CDB_OK, fn(st, &gscale, got, sizeof got, &glen));
    elen = enc_i64(want_val, exp);
    TEST_ASSERT_EQUAL_UINT64(want_scale, gscale);
    TEST_ASSERT_EQUAL_size_t(elen, glen);
    TEST_ASSERT_EQUAL_MEMORY(exp, got, glen);
}

void setUp(void) {}
void tearDown(void) {}

/* ---- happy-path exactness --------------------------------------------- */

/* A single value: SUM/MIN/MAX/AVG all equal it; count is 1. */
static void test_single_value(void)
{
    cdb_decimal_agg st;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 1025, 2)); /* 10.25 */
    TEST_ASSERT_EQUAL_UINT64(1, st.count);
    assert_agg_eq(cdb_decimal_agg_sum, &st, 1025, 2);
    assert_agg_eq(cdb_decimal_agg_min, &st, 1025, 2);
    assert_agg_eq(cdb_decimal_agg_max, &st, 1025, 2);
    assert_agg_eq(cdb_decimal_agg_avg, &st, 1025, 2);
}

/* SUM/MIN/MAX over a money bucket are exact (not 0 — the #40 defect). */
static void test_money_bucket_sum_min_max(void)
{
    cdb_decimal_agg st;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 1025, 2));   /*  10.25 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, -350, 2));   /*  -3.50 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 10000, 2));  /* 100.00 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 75, 2));     /*   0.75 */
    TEST_ASSERT_EQUAL_UINT64(4, st.count);
    assert_agg_eq(cdb_decimal_agg_sum, &st, 10750, 2); /* 107.50 */
    assert_agg_eq(cdb_decimal_agg_min, &st, -350, 2);  /*  -3.50 */
    assert_agg_eq(cdb_decimal_agg_max, &st, 10000, 2); /* 100.00 */
}

/* Mixed-scale SUM aligns to the max scale and stays exact: 1.5 + 2.25 = 3.75. */
static void test_mixed_scale_sum(void)
{
    cdb_decimal_agg st;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 15, 1));  /* 1.5  */
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 225, 2)); /* 2.25 */
    assert_agg_eq(cdb_decimal_agg_sum, &st, 375, 2);     /* 3.75 */
    TEST_ASSERT_EQUAL_UINT64(2, st.count);
}

/* MIN/MAX are scale-aware across different input scales (no byte-only compare).
 * 1.0 (1@0) vs 0.9 (9@1): min is 0.9, max is 1.0 — each emitted with its own
 * exact stored bytes and original scale. */
static void test_min_max_scale_aware(void)
{
    cdb_decimal_agg st;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 1, 0)); /* 1.0 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 9, 1)); /* 0.9 */
    assert_agg_eq(cdb_decimal_agg_min, &st, 9, 1);     /* 0.9 at scale 1 */
    assert_agg_eq(cdb_decimal_agg_max, &st, 1, 0);     /* 1.0 at scale 0 */
}

/* Numerically equal values at different scales compare equal: neither 5 (5@0)
 * nor 5.0 (50@1) displaces the other, so the first-added winner is retained. */
static void test_min_max_cross_scale_equal(void)
{
    cdb_decimal_agg st;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 5, 0));  /* 5   */
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 50, 1)); /* 5.0 */
    assert_agg_eq(cdb_decimal_agg_min, &st, 5, 0);
    assert_agg_eq(cdb_decimal_agg_max, &st, 5, 0);
}

/* Signed addition: opposite signs that cancel yield a canonical zero (single
 * 0x00 byte, non-negative), not a wrapped or sign-tagged value. */
static void test_zero_cancellation(void)
{
    cdb_decimal_agg st;
    uint8_t got[CDB_DEC_EMIT_MAX];
    size_t glen = 0;
    uint64_t gscale = 0;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 350, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, -350, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_decimal_agg_sum(&st, &gscale, got, sizeof got, &glen));
    TEST_ASSERT_EQUAL_UINT64(2, gscale);
    TEST_ASSERT_EQUAL_size_t(1, glen);
    TEST_ASSERT_EQUAL_UINT8(0x00, got[0]);
    assert_agg_eq(cdb_decimal_agg_min, &st, -350, 2);
    assert_agg_eq(cdb_decimal_agg_max, &st, 350, 2);
}

/* A literal zero value folds in cleanly and reads back as canonical zero. */
static void test_zero_value(void)
{
    cdb_decimal_agg st;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 0, 0));
    TEST_ASSERT_EQUAL_UINT64(1, st.count);
    assert_agg_eq(cdb_decimal_agg_sum, &st, 0, 0);
    assert_agg_eq(cdb_decimal_agg_min, &st, 0, 0);
    assert_agg_eq(cdb_decimal_agg_max, &st, 0, 0);
    assert_agg_eq(cdb_decimal_agg_avg, &st, 0, 0);
}

/* Many adds carry correctly: sum of 1..100 at scale 0 is exactly 5050. */
static void test_many_adds_carry(void)
{
    cdb_decimal_agg st;
    int64_t i;
    cdb_decimal_agg_reset(&st);
    for (i = 1; i <= 100; i++)
        TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, i, 0));
    TEST_ASSERT_EQUAL_UINT64(100, st.count);
    assert_agg_eq(cdb_decimal_agg_sum, &st, 5050, 0);
    assert_agg_eq(cdb_decimal_agg_min, &st, 1, 0);
    assert_agg_eq(cdb_decimal_agg_max, &st, 100, 0);
}

/* Property: SUM is order-independent (commutative). Same multiset, two orders,
 * identical result bytes + scale. */
static void test_sum_order_independent(void)
{
    cdb_decimal_agg a, b;
    uint8_t ga[CDB_DEC_EMIT_MAX], gb[CDB_DEC_EMIT_MAX];
    size_t la = 0, lb = 0;
    uint64_t sa = 0, sb = 0;
    cdb_decimal_agg_reset(&a);
    cdb_decimal_agg_reset(&b);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&a, 1025, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&a, -350, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&a, 10000, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&a, 75, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&b, 75, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&b, 10000, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&b, -350, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&b, 1025, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_decimal_agg_sum(&a, &sa, ga, sizeof ga, &la));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_decimal_agg_sum(&b, &sb, gb, sizeof gb, &lb));
    TEST_ASSERT_EQUAL_UINT64(sa, sb);
    TEST_ASSERT_EQUAL_size_t(la, lb);
    TEST_ASSERT_EQUAL_MEMORY(ga, gb, la);
}

/* ---- AVG: round-half-to-even (banker's rounding), ADR-0003 ------------- */

/* Tie rounds DOWN to the even quotient: 10/4 = 2.5 -> 2. */
static void test_avg_half_even_down(void)
{
    cdb_decimal_agg st;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 1, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 1, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 4, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 4, 0));
    assert_agg_eq(cdb_decimal_agg_avg, &st, 2, 0);
}

/* Tie rounds UP to the even quotient: 14/4 = 3.5 -> 4. */
static void test_avg_half_even_up(void)
{
    cdb_decimal_agg st;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 3, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 3, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 4, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 4, 0));
    assert_agg_eq(cdb_decimal_agg_avg, &st, 4, 0);
}

/* Non-tie remainder > half rounds up (odd count): 5/3 = 1.66.. -> 2. */
static void test_avg_round_up_nontie(void)
{
    cdb_decimal_agg st;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 1, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 2, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 2, 0));
    assert_agg_eq(cdb_decimal_agg_avg, &st, 2, 0);
}

/* Exact division: 8/4 = 2, no rounding. */
static void test_avg_exact(void)
{
    cdb_decimal_agg st;
    int i;
    cdb_decimal_agg_reset(&st);
    for (i = 0; i < 4; i++)
        TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 2, 0));
    assert_agg_eq(cdb_decimal_agg_avg, &st, 2, 0);
}

/* Money AVG at the bucket scale: (10.25-3.50+100.00+0.75)/4 = 26.875 ->
 * 26.88 by half-to-even (2687.5 ties up to the even 2688). */
static void test_avg_money_half_even(void)
{
    cdb_decimal_agg st;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 1025, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, -350, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 10000, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 75, 2));
    assert_agg_eq(cdb_decimal_agg_avg, &st, 2688, 2); /* 26.88 */
}

/* Negative AVG rounds symmetrically: sum -107.50 / 4 -> -26.88. */
static void test_avg_negative(void)
{
    cdb_decimal_agg st;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, -1025, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 350, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, -10000, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, -75, 2));
    assert_agg_eq(cdb_decimal_agg_sum, &st, -10750, 2);
    assert_agg_eq(cdb_decimal_agg_avg, &st, -2688, 2); /* -26.88 */
}

/* ---- boundary: largest accepted input length -------------------------- */

/* A full-width (CDB_DEC_MAX_BYTES) positive value is accepted and parsed. */
static void test_max_length_input_accepted(void)
{
    cdb_decimal_agg st;
    uint8_t big[CDB_DEC_MAX_BYTES];
    uint8_t got[CDB_DEC_EMIT_MAX];
    size_t glen = 0;
    uint64_t gscale = 0;
    cdb_decimal_agg_reset(&st);
    memset(big, 0x01, sizeof big);
    big[0] = 0x00; /* keep it positive (clear sign bit) */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_decimal_agg_add(&st, 0, big, sizeof big));
    TEST_ASSERT_EQUAL_UINT64(1, st.count);
    /* Reads back exactly (MIN == MAX == the stored value). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_decimal_agg_min(&st, &gscale, got, sizeof got, &glen));
    TEST_ASSERT_EQUAL_size_t(sizeof big, glen);
    TEST_ASSERT_EQUAL_MEMORY(big, got, glen);
}

/* ---- fail-closed negative / abuse paths ------------------------------- */

/* NULL / empty / over-long inputs are rejected with typed errors, never OOB. */
static void test_add_invalid_args(void)
{
    cdb_decimal_agg st;
    uint8_t one[1] = {0x01};
    uint8_t toolong[CDB_DEC_MAX_BYTES + 1u];
    cdb_decimal_agg_reset(&st);
    memset(toolong, 0x01, sizeof toolong);
    toolong[0] = 0x00;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_decimal_agg_add(NULL, 0, one, 1));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_decimal_agg_add(&st, 0, NULL, 1));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_decimal_agg_add(&st, 0, one, 0));
    /* len > CDB_DEC_MAX_BYTES fails closed with OVERFLOW (not a silent clamp). */
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_decimal_agg_add(&st, 0, toolong, sizeof toolong));
    /* All rejections leave the accumulator empty. */
    TEST_ASSERT_EQUAL_UINT64(0, st.count);
    TEST_ASSERT_EQUAL_INT(0, st.have);
}

/* A scale blow-up that would exceed the fixed capacity fails closed with
 * CDB_E_OVERFLOW rather than wrapping, truncating, or looping unboundedly. */
static void test_scale_overflow_fails_closed(void)
{
    cdb_decimal_agg st;
    uint8_t one[1] = {0x01};
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_decimal_agg_add(&st, 0, one, 1)); /* value 1, scale 0 */
    /* Aligning the running sum to scale 100000 needs *10^100000: overflow. */
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_decimal_agg_add(&st, 100000, one, 1));
    /* After a fail-closed error the module is still usable on a fresh reset. */
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 42, 0));
    assert_agg_eq(cdb_decimal_agg_sum, &st, 42, 0);
}

/* Getters on an empty (reset) accumulator return CDB_E_INVALID_ARG, never a
 * fabricated 0. */
static void test_getters_empty_fail(void)
{
    cdb_decimal_agg st;
    uint8_t got[CDB_DEC_EMIT_MAX];
    size_t glen = 0;
    uint64_t gscale = 0;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_decimal_agg_sum(&st, &gscale, got, sizeof got, &glen));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_decimal_agg_min(&st, &gscale, got, sizeof got, &glen));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_decimal_agg_max(&st, &gscale, got, sizeof got, &glen));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_decimal_agg_avg(&st, &gscale, got, sizeof got, &glen));
}

/* Getters with NULL out-params return CDB_E_INVALID_ARG. */
static void test_getters_null_args(void)
{
    cdb_decimal_agg st;
    uint8_t got[CDB_DEC_EMIT_MAX];
    size_t glen = 0;
    uint64_t gscale = 0;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 1, 0));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_decimal_agg_sum(NULL, &gscale, got, sizeof got, &glen));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_decimal_agg_sum(&st, NULL, got, sizeof got, &glen));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_decimal_agg_sum(&st, &gscale, NULL, sizeof got, &glen));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_decimal_agg_sum(&st, &gscale, got, sizeof got, NULL));
}

/* An output buffer too small for the result fails closed with
 * CDB_E_BUFFER_TOO_SMALL — no partial/overrun write. */
static void test_buffer_too_small(void)
{
    cdb_decimal_agg st;
    uint8_t got[4];
    size_t glen = 0;
    uint64_t gscale = 0;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 1100, 2)); /* needs 2 bytes */
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_decimal_agg_sum(&st, &gscale, got, 1, &glen));
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_decimal_agg_min(&st, &gscale, got, 1, &glen));
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_decimal_agg_max(&st, &gscale, got, 1, &glen));
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_decimal_agg_avg(&st, &gscale, got, 1, &glen));
    /* With adequate room it succeeds. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_decimal_agg_sum(&st, &gscale, got, sizeof got, &glen));
    TEST_ASSERT_EQUAL_size_t(2, glen);
}

/* reset() returns a used accumulator to empty (and NULL is a safe no-op). */
static void test_reset(void)
{
    cdb_decimal_agg st;
    uint8_t got[CDB_DEC_EMIT_MAX];
    size_t glen = 0;
    uint64_t gscale = 0;
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_INT(CDB_OK, add_i64(&st, 999, 2));
    TEST_ASSERT_EQUAL_UINT64(1, st.count);
    cdb_decimal_agg_reset(&st);
    TEST_ASSERT_EQUAL_UINT64(0, st.count);
    TEST_ASSERT_EQUAL_INT(0, st.have);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_decimal_agg_sum(&st, &gscale, got, sizeof got, &glen));
    cdb_decimal_agg_reset(NULL); /* must not crash */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_single_value);
    RUN_TEST(test_money_bucket_sum_min_max);
    RUN_TEST(test_mixed_scale_sum);
    RUN_TEST(test_min_max_scale_aware);
    RUN_TEST(test_min_max_cross_scale_equal);
    RUN_TEST(test_zero_cancellation);
    RUN_TEST(test_zero_value);
    RUN_TEST(test_many_adds_carry);
    RUN_TEST(test_sum_order_independent);
    RUN_TEST(test_avg_half_even_down);
    RUN_TEST(test_avg_half_even_up);
    RUN_TEST(test_avg_round_up_nontie);
    RUN_TEST(test_avg_exact);
    RUN_TEST(test_avg_money_half_even);
    RUN_TEST(test_avg_negative);
    RUN_TEST(test_max_length_input_accepted);
    RUN_TEST(test_add_invalid_args);
    RUN_TEST(test_scale_overflow_fails_closed);
    RUN_TEST(test_getters_empty_fail);
    RUN_TEST(test_getters_null_args);
    RUN_TEST(test_buffer_too_small);
    RUN_TEST(test_reset);
    return UNITY_END();
}
