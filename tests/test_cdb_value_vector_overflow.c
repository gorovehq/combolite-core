/* Regression test for F1 / GHSA-rf29-8939-p85v: the vector decoder accepted
 * an integer-overflow length sentinel. vector_data_len() returns 0 both for a
 * legitimately empty vector (dims == 0) and when the byte length overflows, so
 * a crafted vector with a huge dims and zero trailing bytes slipped past the
 * decoder's only gate (0 != 0) and was accepted with an attacker-chosen dims.
 * validate_vector then iterated on the untrusted dims -> out-of-bounds read and
 * effective non-termination; the BINARY branch indexed d[data_len - 1] with
 * data_len == 0 -> wild read.
 *
 * These abuse-path assertions FAIL (or crash/hang under ASan+UBSan) against the
 * pre-fix code and PASS after the fix. The well-formed cases guard against a
 * regression (no over-rejection of valid vectors, including the empty one). */
#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "cdb_varint.h"
#include "combolite/cdb_value.h"

void setUp(void) {}
void tearDown(void) {}

/* Builds one on-disk VECTOR value: tag, envelope length varint, element-type
 * byte, dims varint, then data_len raw data bytes. Returns the total encoded
 * length, or 0 if it would not fit in out[0..cap). Every local is initialised
 * at its declaration and the one pointer argument is guarded before use. */
static size_t build_vector(uint8_t *out, size_t cap, uint8_t elem_byte, uint64_t dims,
                           const uint8_t *data, size_t data_len)
{
    uint8_t dims_enc[CDB_VARINT_MAX_LEN] = { 0 };
    uint8_t env_enc[CDB_VARINT_MAX_LEN] = { 0 };
    size_t dims_n = 0;
    size_t env_n = 0;
    size_t payload_len = 0;
    size_t total = 0;
    size_t off = 0;

    if (out == NULL || (data == NULL && data_len != 0))
        return 0;

    dims_n = cdb_varint_encode(dims, dims_enc);
    payload_len = (size_t)1u + dims_n + data_len;
    env_n = cdb_varint_encode((uint64_t)payload_len, env_enc);
    total = (size_t)1u + env_n + payload_len;
    if (total > cap)
        return 0;

    out[off++] = (uint8_t)CDB_TAG_VECTOR;
    memcpy(out + off, env_enc, env_n);
    off += env_n;
    out[off++] = elem_byte;
    memcpy(out + off, dims_enc, dims_n);
    off += dims_n;
    if (data_len != 0) {
        memcpy(out + off, data, data_len);
        off += data_len;
    }
    return off;
}

/* AC1/AC2: elem = F32, dims = 2^62, zero data bytes. vector_data_len overflows
 * to the 0 sentinel; the crafted value must be rejected (not accepted with a
 * 2^62 dims) by both the reader and the validator, with no OOB read or hang. */
static void test_f32_overflow_dims_zero_data_is_malformed(void)
{
    uint8_t buf[32] = { 0 };
    cdb_value v;
    size_t n = build_vector(buf, sizeof buf, (uint8_t)CDB_VEC_F32, UINT64_C(1) << 62, NULL, 0);

    memset(&v, 0, sizeof v);
    TEST_ASSERT_NOT_EQUAL(0u, n);

    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_value_read(buf, n, CDB_ORDER_LITTLE, &v));
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED,
                          cdb_value_validate(buf, n, CDB_ORDER_LITTLE, CDB_DECIMAL_UNBOUNDED, 0));
}

/* AC3: elem = BINARY, dims = UINT64_MAX (not a multiple of 8), zero data bytes.
 * The bit-length computation overflows to the 0 sentinel; the value must be
 * rejected and the BINARY path must never index d[data_len - 1] with
 * data_len == 0. */
static void test_binary_overflow_dims_zero_data_is_malformed(void)
{
    uint8_t buf[32] = { 0 };
    cdb_value v;
    size_t n = build_vector(buf, sizeof buf, (uint8_t)CDB_VEC_BINARY, UINT64_MAX, NULL, 0);

    memset(&v, 0, sizeof v);
    TEST_ASSERT_NOT_EQUAL(0u, n);
    TEST_ASSERT_NOT_EQUAL(0u, UINT64_MAX % 8u); /* confirm the abuse precondition */

    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_value_read(buf, n, CDB_ORDER_LITTLE, &v));
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED,
                          cdb_value_validate(buf, n, CDB_ORDER_LITTLE, CDB_DECIMAL_UNBOUNDED, 0));
}

/* A huge F32 dims with a single (insufficient) data byte must also be rejected:
 * the required length is the overflow sentinel 0, which must never be matched
 * against a non-zero remaining length either. */
static void test_f32_overflow_dims_one_data_byte_is_malformed(void)
{
    uint8_t buf[32] = { 0 };
    const uint8_t data[1] = { 0 };
    cdb_value v;
    size_t n = build_vector(buf, sizeof buf, (uint8_t)CDB_VEC_F32, UINT64_C(1) << 62, data, sizeof data);

    memset(&v, 0, sizeof v);
    TEST_ASSERT_NOT_EQUAL(0u, n);

    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_value_read(buf, n, CDB_ORDER_LITTLE, &v));
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED,
                          cdb_value_validate(buf, n, CDB_ORDER_LITTLE, CDB_DECIMAL_UNBOUNDED, 0));
}

/* AC4: a well-formed small F32 vector still decodes and validates exactly as
 * before the fix (no behaviour change / no regression). */
static void test_valid_f32_vector_still_ok(void)
{
    uint8_t wbuf[64];
    cdb_value_writer w;
    const float elems[3] = { 1.0f, -0.0f, 0.5f };
    cdb_value v;
    size_t len = 0;

    memset(wbuf, 0xAA, sizeof wbuf);
    cdb_value_writer_init(&w, wbuf, sizeof wbuf, CDB_ORDER_LITTLE, CDB_DECIMAL_UNBOUNDED);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_write_vector(&w, CDB_VEC_F32, 3, elems));
    len = cdb_value_writer_len(&w);
    TEST_ASSERT_NOT_EQUAL(0u, len);

    memset(&v, 0, sizeof v);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_read(wbuf, len, CDB_ORDER_LITTLE, &v));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_VECTOR, v.type);
    TEST_ASSERT_EQUAL_UINT64(3, v.as.vector.dims);
    TEST_ASSERT_EQUAL_size_t(12, v.as.vector.data_len);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_value_validate(wbuf, len, CDB_ORDER_LITTLE, CDB_DECIMAL_UNBOUNDED, 0));
}

/* AC (no over-rejection): a legitimately empty vector (dims == 0, zero data)
 * must still read and validate OK — the fix distinguishes dims == 0 from the
 * dims != 0 overflow sentinel. */
static void test_valid_empty_vector_still_ok(void)
{
    uint8_t buf[16] = { 0 };
    cdb_value v;
    size_t n = build_vector(buf, sizeof buf, (uint8_t)CDB_VEC_F32, 0, NULL, 0);

    memset(&v, 0, sizeof v);
    TEST_ASSERT_NOT_EQUAL(0u, n);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_read(buf, n, CDB_ORDER_LITTLE, &v));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_VECTOR, v.type);
    TEST_ASSERT_EQUAL_UINT64(0, v.as.vector.dims);
    TEST_ASSERT_EQUAL_size_t(0, v.as.vector.data_len);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_value_validate(buf, n, CDB_ORDER_LITTLE, CDB_DECIMAL_UNBOUNDED, 0));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_f32_overflow_dims_zero_data_is_malformed);
    RUN_TEST(test_binary_overflow_dims_zero_data_is_malformed);
    RUN_TEST(test_f32_overflow_dims_one_data_byte_is_malformed);
    RUN_TEST(test_valid_f32_vector_still_ok);
    RUN_TEST(test_valid_empty_vector_still_ok);
    return UNITY_END();
}
