/* F4 / GHSA-rf29-8939-p85v  (CWE-789/409): the LZMA2 decompressor must bound
 * the decoder *dictionary* against the output budget BEFORE allocating, so a
 * crafted one-byte dictionary property (0..40 -> up to UINT32_MAX ~4 GiB)
 * cannot drive a memory-exhaustion DoS through the host env allocator.
 *
 * The output size is already bounded (plain > cap -> CDB_E_BUFFER_TOO_SMALL);
 * the dictionary allocation was the lone unbounded size reaching an allocator.
 *
 * Red->green regression (fails against the pre-fix code, passes against the
 * fix):
 *   (a) a hostile property byte must be rejected with a typed error (not a
 *       multi-GiB allocation / OOM). A recording host env allocator captures
 *       the largest size ever requested; the fix must keep it within the
 *       cdb_codec_work_size budget. Pre-fix code hands liblzma ~4 GiB here.
 *   (b) a valid, in-budget LZMA2 stream must still round-trip byte-exact
 *       (no behaviour change beyond bounding the dictionary).
 *
 * The recording allocator refuses anything above a safety cap far below
 * ~4 GiB, so the test NEVER actually attempts a multi-gigabyte allocation even
 * when exercising the vulnerable path. C99; every local initialised at
 * declaration; explicit casts; no VLA. */
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "cdb_codec.h"

#define PLAIN_LEN 10000u
/* 10000 encodes as a two-byte varint, so the single LZMA2 property byte that
 * carries the dictionary size is packed[2] (see cdb_codec compressed form). */
#define PROP_INDEX 2u
/* A cap comfortably above any legitimate preset-1 working set, yet far below
 * the ~4 GiB a hostile property byte would demand: large enough that valid
 * decode succeeds, small enough that the attack never really allocates. */
#define ALLOC_CAP (64u * 1024u * 1024u)

/* A host environment allocator that records the largest size ever requested
 * and returns NULL for anything over its cap instead of allocating it. */
typedef struct rec_alloc {
    size_t largest; /* largest size any single request asked for */
    size_t cap;     /* requests above this return NULL, unallocated */
} rec_alloc;

static void *rec_alloc_fn(void *ctx, size_t n)
{
    rec_alloc *r = (rec_alloc *)ctx;
    if (n > r->largest)
        r->largest = n;      /* record the request even when we refuse it */
    if (n > r->cap)
        return NULL;
    return malloc(n);
}

static void rec_free_fn(void *ctx, void *p)
{
    (void)ctx;
    free(p);
}

static cdb_env_ops ops;
static cdb_env env;
static rec_alloc rec;

void setUp(void)
{
    memset(&ops, 0, sizeof ops);
    ops.alloc = rec_alloc_fn;
    ops.free = rec_free_fn;
    memset(&env, 0, sizeof env); /* zero accel hooks too; codec ignores them */
    env.ops = &ops;
    env.ctx = &rec;
    rec.largest = 0;
    rec.cap = ALLOC_CAP;
}

void tearDown(void) {}

#ifdef CDB_WITH_XZ

static uint8_t plainbuf[PLAIN_LEN];
static uint8_t packed[PLAIN_LEN + 1024u];
static uint8_t back[PLAIN_LEN];

/* Repetitive text: compresses to a small, in-budget LZMA2 stream. */
static void fill_text(size_t n)
{
    static const char words[] =
        "the quick brown fox jumps over the lazy dog while the database packs pages ";
    size_t i = 0;
    for (i = 0; i < n; i++)
        plainbuf[i] = (uint8_t)words[(i * 7u + i / 13u) % (sizeof words - 1u)];
}

/* Produce a valid compressed form of PLAIN_LEN bytes; returns its length. */
static size_t make_valid(void)
{
    cdb_codec_mem m;
    size_t clen = 0;
    memset(&m, 0, sizeof m);
    m.env = &env;
    fill_text(PLAIN_LEN);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_codec_compress(&m, CDB_CODEC_LZMA2, plainbuf, PLAIN_LEN, packed,
                                                     sizeof packed, &clen));
    /* The natural property byte a valid stream declares is in range (0..40). */
    TEST_ASSERT_TRUE(clen > PROP_INDEX);
    TEST_ASSERT_TRUE(packed[PROP_INDEX] <= 40u);
    return clen;
}

/* PRIMARY F4 regression: property byte 40 stands for UINT32_MAX (~4 GiB). The
 * fix must reject it with CDB_E_CORRUPT before any allocation; the recording
 * allocator proves nothing over the budget is ever requested. Pre-fix code
 * requests ~4 GiB right here, so BOTH the return code and the largest-alloc
 * assertion fail against the vulnerable code. */
static void test_dict_property_byte40_bounded(void)
{
    cdb_codec_mem m;
    size_t clen = 0;
    size_t blen = 0;
    size_t budget = 0;
    uint8_t saved = 0;

    clen = make_valid();

    budget = cdb_codec_work_size(CDB_CODEC_LZMA2, PLAIN_LEN);
    TEST_ASSERT_TRUE(budget > 0u);
    /* Invariant the test relies on: a legitimate working set fits under the
     * cap (so valid decode allocates), while ~4 GiB does not. */
    TEST_ASSERT_TRUE(budget < rec.cap);

    memset(&m, 0, sizeof m);
    m.env = &env;

    saved = packed[PROP_INDEX];
    packed[PROP_INDEX] = (uint8_t)40u; /* dict_of_prop(40) -> UINT32_MAX */
    rec.largest = 0;
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_codec_decompress(&m, CDB_CODEC_LZMA2, packed, clen, back,
                                                              sizeof back, &blen));
    /* The fix bounds the dictionary: nothing over the budget is requested. */
    TEST_ASSERT_TRUE(rec.largest <= budget);
    packed[PROP_INDEX] = saved;
}

/* Breadth: every over-budget / out-of-range property byte is a typed error and
 * never drives an over-budget allocation. Bytes 5..40 map to dictionaries
 * larger than the 10000-byte output needs (valid declares byte 4); 41/255 are
 * out of range. Pre-fix: large bytes record a huge alloc, mid bytes decode a
 * larger-than-needed dictionary and wrongly return CDB_OK -> red either way. */
static void test_hostile_property_bytes_rejected(void)
{
    static const uint8_t hostile[] = {5u, 8u, 20u, 39u, 40u, 41u, 255u};
    cdb_codec_mem m;
    size_t clen = 0;
    size_t budget = 0;
    uint8_t saved = 0;
    size_t i = 0;

    clen = make_valid();
    budget = cdb_codec_work_size(CDB_CODEC_LZMA2, PLAIN_LEN);
    TEST_ASSERT_TRUE(budget > 0u);
    saved = packed[PROP_INDEX];

    for (i = 0; i < sizeof hostile / sizeof hostile[0]; i++) {
        size_t blen = 0;
        memset(&m, 0, sizeof m);
        m.env = &env;
        packed[PROP_INDEX] = hostile[i];
        rec.largest = 0;
        TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_codec_decompress(&m, CDB_CODEC_LZMA2, packed, clen, back,
                                                                  sizeof back, &blen));
        TEST_ASSERT_TRUE(rec.largest <= budget);
    }
    packed[PROP_INDEX] = saved;
}

/* No regression: a valid, in-budget stream still decompresses byte-exact, and
 * its legitimate working allocations stay within the budget. */
static void test_valid_roundtrip_unaffected(void)
{
    cdb_codec_mem m;
    size_t clen = 0;
    size_t blen = 0;
    size_t budget = 0;

    budget = cdb_codec_work_size(CDB_CODEC_LZMA2, PLAIN_LEN);
    TEST_ASSERT_TRUE(budget > 0u);

    memset(&m, 0, sizeof m);
    m.env = &env;
    fill_text(PLAIN_LEN);
    rec.largest = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_codec_compress(&m, CDB_CODEC_LZMA2, plainbuf, PLAIN_LEN, packed,
                                                     sizeof packed, &clen));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_codec_decompress(&m, CDB_CODEC_LZMA2, packed, clen, back,
                                                       sizeof back, &blen));
    TEST_ASSERT_EQUAL_size_t(PLAIN_LEN, blen);
    TEST_ASSERT_EQUAL_MEMORY(plainbuf, back, PLAIN_LEN);
    TEST_ASSERT_TRUE(rec.largest <= budget);
}

/* The bound must also hold in caller scratch memory (no env allocator): the
 * MCU bump path already fails closed, so the hostile byte is refused without
 * overrunning the fixed work buffer. */
static void test_dict_bound_in_work_memory(void)
{
    static uint8_t work[16u * 1024u * 1024u];
    cdb_codec_mem m;
    size_t need = 0;
    size_t clen = 0;
    size_t blen = 0;
    uint8_t saved = 0;

    need = cdb_codec_work_size(CDB_CODEC_LZMA2, PLAIN_LEN);
    TEST_ASSERT_TRUE(need > 0u && need <= sizeof work);

    memset(&m, 0, sizeof m);
    m.work = work;
    /* Give the whole scratch buffer: cdb_codec_work_size reports the decoder's
     * working set, but the bump allocator's per-block alignment makes the
     * encoder (used below only to build a fixture) want slightly more. The
     * security claim under test is decode-side bounding, not a tight encode
     * budget, so size generously and let both paths run. */
    m.work_size = sizeof work;
    fill_text(PLAIN_LEN);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_codec_compress(&m, CDB_CODEC_LZMA2, plainbuf, PLAIN_LEN, packed,
                                                     sizeof packed, &clen));
    saved = packed[PROP_INDEX];
    packed[PROP_INDEX] = (uint8_t)40u;
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_codec_decompress(&m, CDB_CODEC_LZMA2, packed, clen, back,
                                                              sizeof back, &blen));
    packed[PROP_INDEX] = saved;
    /* And the valid stream still round-trips through scratch memory. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_codec_decompress(&m, CDB_CODEC_LZMA2, packed, clen, back,
                                                       sizeof back, &blen));
    TEST_ASSERT_EQUAL_size_t(PLAIN_LEN, blen);
    TEST_ASSERT_EQUAL_MEMORY(plainbuf, back, PLAIN_LEN);
}

#else /* no codec built in */

/* Without the codec there is no LZMA2 dictionary path to bound; the call is
 * simply unsupported (spec 15.7). */
static void test_unsupported_without_codec(void)
{
    cdb_codec_mem m;
    size_t n = 0;
    uint8_t buf[8] = {0};
    memset(&m, 0, sizeof m);
    m.env = &env;
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED, cdb_codec_decompress(&m, CDB_CODEC_LZMA2, buf, sizeof buf,
                                                                 buf, sizeof buf, &n));
}

#endif

int main(void)
{
    UNITY_BEGIN();
#ifdef CDB_WITH_XZ
    RUN_TEST(test_dict_property_byte40_bounded);
    RUN_TEST(test_hostile_property_bytes_rejected);
    RUN_TEST(test_valid_roundtrip_unaffected);
    RUN_TEST(test_dict_bound_in_work_memory);
#else
    RUN_TEST(test_unsupported_without_codec);
#endif
    return UNITY_END();
}
