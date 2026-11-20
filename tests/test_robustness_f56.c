/* Regression suite for combolite-core #23 (F5/F6 robustness hardening).
 *
 * Scope: defensive / undefined-behaviour hygiene (CWE-476/824 pointer-deref
 * before a NULL guard; CWE-190 size_t overflow). These edges are NOT
 * attacker-reachable across a trust boundary (confirmed in the STRIDE review),
 * so this is a public robustness suite, not the security advisory. Every case
 * tightens a failure mode from UB to a typed error and leaves valid-input
 * behaviour unchanged -- the behaviour-preservation cases below assert exactly
 * that.
 *
 * F5 (CWE-476/824): pointer arithmetic / dereference on a parameter must not
 * precede that parameter's NULL guard.
 *   F5a cdb_crypto_wrap_key  -- formed wrapped_out + offset before the guard.
 *   F5b cdb_value_read       -- formed buf + 1 / buf + len before the guard.
 *   F5c parse_item (colenc)  -- dereferenced p before guarding it; reached
 *                               end-to-end here via the public reader when the
 *                               chunk claims a value but carries no bytes.
 * Under the project's ASan+UBSan build (-fno-sanitize-recover=all) a NULL +
 * non-zero offset, or a NULL dereference, is a hard trap: these cases abort on
 * the pre-fix merge-base (RED) and return the typed CDB_E_INVALID_ARG after the
 * fix (GREEN).
 *
 * F6 (CWE-190): the journal record size is header + payload + trailer. On a
 * 32-bit build size_t is 32 bits, so a payload_len near UINT32_MAX wraps size_t
 * when the fixed overhead is added -- which could let a `size > buf_size` bound
 * check pass on a wrapped-small value. The checked seams cdb_journal_size_add /
 * cdb_journal_record_size reject the overflow deterministically, before any
 * bound/CRC check. The size_add case is keyed on SIZE_MAX, so it demonstrates
 * the guard on any platform width; before the fix the seam did not exist (the
 * suite failed to link == errored gate == RED), after it the overflow is a
 * typed CDB_E_OVERFLOW (GREEN). AC8 permits proving the guard on a 64-bit host.
 *
 * Hermetic: no files, no network, no secrets. All crypto inputs are NULL or
 * synthetic; every local is initialized at its declaration. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "combolite/cdb_common.h"
#include "combolite/cdb_crypto.h"
#include "combolite/cdb_value.h"

#include "cdb_colenc.h"           /* white-box: public reader reaches parse_item (F5c) */
#include "cdb_journal_internal.h" /* white-box: checked size seams (F6) */

void setUp(void) {}
void tearDown(void) {}

/* ======================================================================== *
 * F5a: cdb_crypto_wrap_key NULL guards precede pointer arithmetic          *
 * ======================================================================== */

static void test_wrap_key_null_wrapped_out(void)
{
    uint8_t master[CDB_CRYPTO_KEY_SIZE];
    uint8_t enclave[CDB_CRYPTO_KEY_SIZE];
    cdb_status s = CDB_OK;

    memset(master, 0x11, sizeof master);
    memset(enclave, 0x22, sizeof enclave);

    /* NULL wrapped_out: pre-fix formed wrapped_out + offset -> UBSan trap. */
    s = cdb_crypto_wrap_key(master, enclave, NULL);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, s);
}

static void test_wrap_key_null_master(void)
{
    uint8_t enclave[CDB_CRYPTO_KEY_SIZE];
    uint8_t wrapped[CDB_WRAPPED_KEY_SIZE];
    cdb_status s = CDB_OK;

    memset(enclave, 0x33, sizeof enclave);
    memset(wrapped, 0, sizeof wrapped);

    s = cdb_crypto_wrap_key(NULL, enclave, wrapped);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, s);
}

static void test_wrap_key_null_enclave(void)
{
    uint8_t master[CDB_CRYPTO_KEY_SIZE];
    uint8_t wrapped[CDB_WRAPPED_KEY_SIZE];
    cdb_status s = CDB_OK;

    memset(master, 0x44, sizeof master);
    memset(wrapped, 0, sizeof wrapped);

    s = cdb_crypto_wrap_key(master, NULL, wrapped);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, s);
}

/* Behaviour preservation: the fix only reorders the NULL guard above the
 * offset arithmetic; a fully valid call still wraps and round-trips. This
 * proves the guard move did not disturb the happy path (crypto touches no key
 * byte in this change). */
static void test_wrap_unwrap_roundtrip_preserved(void)
{
    uint8_t master[CDB_CRYPTO_KEY_SIZE];
    uint8_t enclave[CDB_CRYPTO_KEY_SIZE];
    uint8_t wrapped[CDB_WRAPPED_KEY_SIZE];
    uint8_t recovered[CDB_CRYPTO_KEY_SIZE];
    cdb_status s = CDB_OK;

    memset(master, 0x5A, sizeof master);
    memset(enclave, 0xA5, sizeof enclave);
    memset(wrapped, 0, sizeof wrapped);
    memset(recovered, 0, sizeof recovered);

    s = cdb_crypto_wrap_key(master, enclave, wrapped);
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);

    s = cdb_crypto_unwrap_key(master, wrapped, recovered);
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(enclave, recovered, CDB_CRYPTO_KEY_SIZE);
}

/* ======================================================================== *
 * F5b: cdb_value_read NULL/len guards precede buf arithmetic               *
 * ======================================================================== */

static void test_value_read_null_buf(void)
{
    cdb_value out;
    cdb_status s = CDB_OK;

    memset(&out, 0, sizeof out);

    /* NULL buf: pre-fix computed buf + 1 / buf + len -> UBSan trap. */
    s = cdb_value_read(NULL, 4, CDB_ORDER_LITTLE, &out);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, s);
}

static void test_value_read_null_out(void)
{
    uint8_t buf[2] = { 0, 0 };
    cdb_status s = CDB_OK;

    /* NULL out is rejected before the body is touched. */
    s = cdb_value_read(buf, sizeof buf, CDB_ORDER_LITTLE, NULL);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, s);
}

static void test_value_read_null_buf_zero_len(void)
{
    cdb_value out;
    cdb_status s = CDB_OK;

    memset(&out, 0, sizeof out);

    /* Even with len 0, a NULL buf must be rejected as CDB_E_INVALID_ARG,
     * not fall through to the len<1 TRUNCATED path (error ordering). */
    s = cdb_value_read(NULL, 0, CDB_ORDER_LITTLE, &out);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, s);
}

/* Error-ordering companion: a NON-NULL buffer with len 0 takes the len<1
 * branch and returns CDB_E_TRUNCATED -- distinct from the NULL case above.
 * This pins the exact guard order the fix must preserve (NULL beats len). */
static void test_value_read_empty_buf_is_truncated(void)
{
    uint8_t buf[1] = { 0 };
    cdb_value out;
    cdb_status s = CDB_OK;

    memset(&out, 0, sizeof out);

    s = cdb_value_read(buf, 0, CDB_ORDER_LITTLE, &out);
    TEST_ASSERT_EQUAL_INT(CDB_E_TRUNCATED, s);
}

/* Behaviour preservation: a valid encoded value still decodes correctly after
 * the guard reordering -- only the NULL/len edges changed. */
static void test_value_read_valid_roundtrip_preserved(void)
{
    uint8_t buf[32];
    cdb_value_writer w;
    cdb_value out;
    size_t n = 0;
    cdb_status s = CDB_OK;

    memset(buf, 0, sizeof buf);
    memset(&w, 0, sizeof w);
    memset(&out, 0, sizeof out);

    cdb_value_writer_init(&w, buf, sizeof buf, CDB_ORDER_LITTLE, CDB_DECIMAL_UNBOUNDED);
    s = cdb_value_write_int(&w, (int64_t)-12345);
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);
    n = cdb_value_writer_len(&w);
    TEST_ASSERT_TRUE(n > 0);

    s = cdb_value_read(buf, n, CDB_ORDER_LITTLE, &out);
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);
    TEST_ASSERT_EQUAL_INT(CDB_TAG_INT, out.tag);
    TEST_ASSERT_TRUE(out.as.i64 == (int64_t)-12345);
}

/* ======================================================================== *
 * F5c: parse_item NULL guard, reached through the public colenc reader     *
 * ======================================================================== */

/* A plain chunk that declares n=1 value but carries zero bytes (data=NULL,
 * len=0) passes reader_init (its guard only rejects data==NULL with len>0),
 * then cdb_colenc_next calls parse_item(r->data + r->pos == NULL, avail=0).
 * Pre-fix that dereferences a NULL p (ASan/UBSan trap == RED); post-fix the
 * top-of-function NULL guard fails closed with CDB_E_INVALID_ARG (GREEN). */
static void test_colenc_next_null_data_item(void)
{
    cdb_colenc_reader r;
    uint64_t scratch[4] = { 0, 0, 0, 0 };
    const uint8_t *item = NULL;
    size_t item_len = 0;
    int done = 0;
    cdb_status s = CDB_OK;

    memset(&r, 0, sizeof r);

    /* STRING (0x40) is a variable-length tag, so parse_item must inspect the
     * payload bytes -- exactly the path that dereferences p. */
    s = cdb_colenc_reader_init(&r, (uint8_t)CDB_TAG_STRING, CDB_ORDER_LITTLE,
                               CDB_DECIMAL_UNBOUNDED, CDB_COLENC_PLAIN,
                               NULL, (size_t)0u, (size_t)1u, scratch,
                               (size_t)(sizeof scratch / sizeof scratch[0]));
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);

    s = cdb_colenc_next(&r, &item, &item_len, &done);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, s);
}

/* ======================================================================== *
 * F6: journal size arithmetic overflow guards (CWE-190)                    *
 * ======================================================================== */

static void test_size_add_overflow_rejected(void)
{
    size_t out = 0;
    cdb_status s = CDB_OK;

    /* Host-independent: SIZE_MAX + 1 wraps on any width -> CDB_E_OVERFLOW. */
    s = cdb_journal_size_add(SIZE_MAX, (size_t)1u, &out);
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, s);

    /* A non-overflowing add succeeds and yields the sum. */
    out = 0;
    s = cdb_journal_size_add((size_t)100u, (size_t)23u, &out);
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);
    TEST_ASSERT_EQUAL_UINT(123u, out);
}

/* Out is left unchanged on overflow (the seam must not write a wrapped
 * value a caller might then bound-check). */
static void test_size_add_out_untouched_on_overflow(void)
{
    size_t out = 0;
    cdb_status s = CDB_OK;

    out = (size_t)0xDEADu;
    s = cdb_journal_size_add(SIZE_MAX, (size_t)2u, &out);
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, s);
    TEST_ASSERT_TRUE(out == (size_t)0xDEADu);
}

static void test_size_add_null_out(void)
{
    cdb_status s = CDB_OK;

    s = cdb_journal_size_add((size_t)1u, (size_t)2u, NULL);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, s);
}

static void test_size_add_boundary_ok(void)
{
    size_t out = 0;
    cdb_status s = CDB_OK;

    /* Exactly SIZE_MAX is representable (no overflow). */
    s = cdb_journal_size_add(SIZE_MAX - (size_t)1u, (size_t)1u, &out);
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);
    TEST_ASSERT_TRUE(out == SIZE_MAX);
}

static void test_record_size_ok(void)
{
    size_t out = 0;
    cdb_status s = CDB_OK;

    /* A normal payload length sizes without overflow and is behaviour-
     * preserving: header(48) + payload(10) + trailer(16) = 74. */
    s = cdb_journal_record_size((uint32_t)10u, &out);
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);
    TEST_ASSERT_EQUAL_UINT(74u, out);
}

/* No false overflow: the largest uint32 payload_len does not overflow a
 * 64-bit size_t, so on this host the guard must stay out of the way and still
 * return the exact total (overhead 64 + UINT32_MAX). On a 32-bit size_t the
 * same input would legitimately be rejected -- the point of the guard -- but
 * AC8 lets us prove the behaviour-preserving half here. */
static void test_record_size_max_uint32_no_false_overflow(void)
{
    size_t out = 0;
    cdb_status s = CDB_OK;

    if (sizeof(size_t) < 8u) {
        TEST_IGNORE_MESSAGE("32-bit size_t: UINT32_MAX payload legitimately rejected");
        return;
    }

    s = cdb_journal_record_size(UINT32_MAX, &out);
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);
    TEST_ASSERT_TRUE(out == (size_t)64u + (size_t)UINT32_MAX);
}

static void test_record_size_null_out(void)
{
    cdb_status s = CDB_OK;

    s = cdb_journal_record_size((uint32_t)10u, NULL);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, s);
}

int main(void)
{
    UNITY_BEGIN();

    /* F5a */
    RUN_TEST(test_wrap_key_null_wrapped_out);
    RUN_TEST(test_wrap_key_null_master);
    RUN_TEST(test_wrap_key_null_enclave);
    RUN_TEST(test_wrap_unwrap_roundtrip_preserved);

    /* F5b */
    RUN_TEST(test_value_read_null_buf);
    RUN_TEST(test_value_read_null_out);
    RUN_TEST(test_value_read_null_buf_zero_len);
    RUN_TEST(test_value_read_empty_buf_is_truncated);
    RUN_TEST(test_value_read_valid_roundtrip_preserved);

    /* F5c */
    RUN_TEST(test_colenc_next_null_data_item);

    /* F6 */
    RUN_TEST(test_size_add_overflow_rejected);
    RUN_TEST(test_size_add_out_untouched_on_overflow);
    RUN_TEST(test_size_add_null_out);
    RUN_TEST(test_size_add_boundary_ok);
    RUN_TEST(test_record_size_ok);
    RUN_TEST(test_record_size_max_uint32_no_false_overflow);
    RUN_TEST(test_record_size_null_out);

    return UNITY_END();
}
