/* Regression + validation + golden for the extended aggregates FIRST / LAST /
 * STDDEV / VARIANCE (CDB_AGG_FIRST..VARIANCE, 0x06..0x09). Before the fix these
 * four were defined but rejected by the writer/reader bound (fn > CDB_AGG_MAX,
 * 0x05) and defaulted to NULL in the executor, so they were dead/unusable
 * (finding F-Q1, issue #12). This test fails against the pre-fix tree (the
 * writer returns CDB_E_INVALID_ARG) and passes against the fix. */
#include "unity.h"
#include "cdb_exec.h"
#include "cdb_query.h"

#include <string.h>

static uint8_t scratch[32768];
static uint8_t wire[512];

void setUp(void) {}
void tearDown(void) {}

static void make_str_val(cdb_value *out, const char *str, size_t len)
{
    memset(out, 0, sizeof(*out));
    out->type = CDB_TYPE_STRING;
    out->tag = CDB_TAG_STRING;
    out->payload = (const uint8_t *)str;
    out->payload_len = len;
}

/* REGRESSION: the writer + validator now accept the four opcodes. */
static void test_write_validate_accepts_new_aggs(void)
{
    const uint8_t fns[4] = { CDB_AGG_FIRST, CDB_AGG_LAST, CDB_AGG_STDDEV, CDB_AGG_VARIANCE };
    size_t k;
    for (k = 0; k < 4; k++) {
        cdb_query_writer qw;
        cdb_query_writer_init(&qw, wire, sizeof wire);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate(&qw, 1, 1));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "s", 1));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "g", 1));
        /* the previously-rejected call */
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate_output(&qw, "a", 1, fns[k]));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "v", 1));
        TEST_ASSERT_EQUAL_INT(CDB_OK, qw.error);
        /* and the wire validates (reader bound accepts it too) */
        {
            size_t root = 0;
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_validate(wire, cdb_query_writer_len(&qw), &root));
        }
    }
}

/* GOLDEN: the opcode byte for each aggregate is encoded verbatim in the wire. */
static void test_golden_agg_opcode_byte(void)
{
    cdb_query_writer qw;
    size_t len, i;
    int found = 0;
    cdb_query_writer_init(&qw, wire, sizeof wire);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate(&qw, 1, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "s", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "g", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate_output(&qw, "sd", 2, CDB_AGG_STDDEV));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "v", 1));
    len = cdb_query_writer_len(&qw);
    /* the alias "sd" is immediately followed by the fn byte 0x08 */
    for (i = 0; i + 2 < len; i++) {
        if (wire[i] == 's' && wire[i + 1] == 'd' && wire[i + 2] == CDB_AGG_STDDEV) { found = 1; break; }
    }
    TEST_ASSERT_TRUE_MESSAGE(found, "STDDEV opcode 0x08 not found after its alias in the wire");
}

/* Build a one-group aggregate over `amount`, run it over a mock scan. */
static cdb_status run_single_group(uint8_t fn, const int64_t *vals, size_t n,
                                   cdb_value *out, int *has)
{
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row rows[8];
    cdb_exec_row out_row;
    cdb_status s;
    size_t i;
    cdb_eval_make_null(out);
    *has = 0;
    if (n > 8) return CDB_E_INVALID_ARG;
    memset(rows, 0, sizeof rows);
    for (i = 0; i < n; i++) {
        rows[i].n_fields = 2;
        rows[i].fields[0].name = "g"; rows[i].fields[0].name_len = 1;
        make_str_val(&rows[i].fields[0].val, "G", 1);
        rows[i].fields[1].name = "v"; rows[i].fields[1].name_len = 1;
        cdb_eval_make_int(&rows[i].fields[1].val, vals[i]);
    }
    cdb_query_writer_init(&qw, wire, sizeof wire);
    if (cdb_query_writer_begin(&qw) != CDB_OK) return qw.error;
    cdb_query_write_aggregate(&qw, 1, 1);
    cdb_query_write_scan(&qw, "s", 1);
    cdb_query_write_expr_field(&qw, "g", 1);          /* group by g */
    cdb_query_write_aggregate_output(&qw, "a", 1, fn);
    cdb_query_write_expr_field(&qw, "v", 1);          /* over v */
    if (qw.error != CDB_OK) return qw.error;
    if ((s = cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL, 0,
                           scratch, sizeof scratch)) != CDB_OK)
        return s;
    if ((s = cdb_exec_set_mock_scan(&cur, "s", 1, rows, n)) != CDB_OK) { cdb_exec_close(&cur); return s; }
    s = cdb_exec_next(&cur, &out_row, has);
    if (s == CDB_OK && *has && out_row.n_fields >= 2)
        *out = out_row.fields[1].val;   /* field 0 = group key g, field 1 = the aggregate */
    cdb_exec_close(&cur);
    return s;
}

/* VALIDATION: FIRST / LAST return the first / last value in scan order. */
static void test_first_last_values(void)
{
    const int64_t vals[3] = { 100, 50, 200 };
    cdb_value out; int has;
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_single_group(CDB_AGG_FIRST, vals, 3, &out, &has));
    TEST_ASSERT_TRUE(has);
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, out.type);
    TEST_ASSERT_EQUAL_INT64(100, out.as.i64);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_single_group(CDB_AGG_LAST, vals, 3, &out, &has));
    TEST_ASSERT_TRUE(has);
    TEST_ASSERT_EQUAL_INT64(200, out.as.i64);
}

/* VALIDATION: VARIANCE / STDDEV are sample (n-1); vals 2,4,6 -> var 4, stddev 2. */
static void test_variance_stddev_values(void)
{
    const int64_t vals[3] = { 2, 4, 6 };
    const int64_t one[1] = { 42 };
    cdb_value out; int has;
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_single_group(CDB_AGG_VARIANCE, vals, 3, &out, &has));
    TEST_ASSERT_TRUE(has);
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_F64, out.type);
    TEST_ASSERT_DOUBLE_WITHIN(1e-9, 4.0, out.as.f64);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_single_group(CDB_AGG_STDDEV, vals, 3, &out, &has));
    TEST_ASSERT_TRUE(has);
    TEST_ASSERT_DOUBLE_WITHIN(1e-9, 2.0, out.as.f64);
    /* n < 2 -> NULL (sample variance undefined) */
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_single_group(CDB_AGG_VARIANCE, one, 1, &out, &has));
    TEST_ASSERT_TRUE(has);
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_write_validate_accepts_new_aggs);
    RUN_TEST(test_golden_agg_opcode_byte);
    RUN_TEST(test_first_last_values);
    RUN_TEST(test_variance_stddev_values);
    return UNITY_END();
}
