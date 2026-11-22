/* Red->green regression tests for CMBQL executor capacity limits (#36 FR5):
 *   - a projection wider than the old 16-field cap returns all its fields;
 *   - a row that still exceeds the (raised) cap is a typed error, not a
 *     silent field drop;
 *   - ORDER BY ... LIMIT k over a store larger than the sort buffer succeeds
 *     via a no-heap top-N that buffers O(k) rows instead of failing
 *     CDB_E_OUT_OF_BUDGET.
 *
 * Deterministic and hermetic: mock scans, no wall-clock/network/shared state.
 * Each assertion fails on the pre-fix merge-base (16-field cap truncated wide
 * rows; a large ORDER BY exhausted the 256-row buffer).
 */
#include "unity.h"
#include "cdb_exec.h"
#include "cdb_query.h"

#include <string.h>

void setUp(void)
{
}
void tearDown(void)
{
}

/* ---- FR5 (AC9): a 17-field projection returns all 17 fields ---- */
static void test_project_seventeen_fields(void)
{
    uint8_t wire[2048], scratch[65536];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row src;
    cdb_exec_row out_row;
    int has_row = 0;
    int i;

    memset(&src, 0, sizeof(src));
    src.entry_id = 1;
    src.n_fields = 1;
    src.fields[0].name = "v";
    src.fields[0].name_len = 1;
    cdb_eval_make_int(&src.fields[0].val, 42);

    /* Project 17 outputs, each the field v, with distinct aliases c0..c16. */
    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_project(&qw, 0, 17));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "src", 3));
    for (i = 0; i < 17; i++) {
        char alias[8];
        int n = snprintf(alias, sizeof(alias), "c%d", i);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_project_output(&qw, alias, (size_t)n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "v", 1));
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "src", 3, &src, 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_TRUE(has_row);
    TEST_ASSERT_EQUAL_size_t(17, out_row.n_fields); /* all 17, not truncated at 16 */
    for (i = 0; i < 17; i++)
        TEST_ASSERT_EQUAL_INT64(42, out_row.fields[i].val.as.i64);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* ---- FR5 (AC10): too many output columns is a typed error at open ---- */
static void test_project_too_many_columns_errors(void)
{
    uint8_t wire[4096], scratch[65536];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    int i;
    cdb_status st;

    /* CDB_EXEC_MAX_FIELDS + 1 outputs: more than a row can hold. */
    const int n_out = (int)CDB_EXEC_MAX_FIELDS + 1;

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_project(&qw, 0, (size_t)n_out));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "src", 3));
    for (i = 0; i < n_out; i++) {
        char alias[8];
        int n = snprintf(alias, sizeof(alias), "c%d", i);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_project_output(&qw, alias, (size_t)n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "v", 1));
    }

    /* Fail closed: a typed overflow, never a silently truncated projection. */
    st = cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL, 0, scratch,
                       sizeof(scratch));
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, st);
}

/* ---- FR5 (AC10): a passthrough row that overflows the cap errors at next --- */
static void test_project_passthrough_overflow_errors(void)
{
    uint8_t wire[1024], scratch[65536];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row src;
    cdb_exec_row out_row;
    int has_row = 0;
    cdb_status st;
    size_t i;
    const size_t base = CDB_EXEC_MAX_FIELDS - 2; /* nearly full input row */

    memset(&src, 0, sizeof(src));
    src.entry_id = 1;
    src.n_fields = base;
    for (i = 0; i < base; i++) {
        src.fields[i].name = "v";
        src.fields[i].name_len = 1;
        cdb_eval_make_int(&src.fields[i].val, (int64_t)i);
    }

    /* passthrough (base fields) + 5 computed = base + 5 > cap. */
    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_project(&qw, 1, 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "src", 3));
    for (i = 0; i < 5; i++) {
        char alias[8];
        int n = snprintf(alias, sizeof(alias), "e%zu", i);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_project_output(&qw, alias, (size_t)n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "v", 1));
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "src", 3, &src, 1));

    st = cdb_exec_next(&cur, &out_row, &has_row);
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, st); /* no silent field drop */

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

#define TOPN_ROWS 300
static cdb_exec_row g_rows[TOPN_ROWS];

/* ---- FR5 (AC11/AC12): ORDER BY ... LIMIT k over a large store ---- */
static void test_order_by_limit_topn_large(void)
{
    uint8_t wire[256], scratch[65536];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row out_row;
    int has_row = 0;
    int i;

    /* Values are a permutation of 0..299 (97 is coprime to 300), so the five
     * smallest are exactly 0,1,2,3,4 and sorting actually does work. */
    memset(g_rows, 0, sizeof(g_rows));
    for (i = 0; i < TOPN_ROWS; i++) {
        g_rows[i].entry_id = (uint64_t)(i + 1);
        g_rows[i].n_fields = 1;
        g_rows[i].fields[0].name = "v";
        g_rows[i].fields[0].name_len = 1;
        cdb_eval_make_int(&g_rows[i].fields[0].val, (int64_t)((i * 97 + 13) % TOPN_ROWS));
    }

    /* Limit(5, Sort(Scan("big"), v ASC)) */
    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_limit(&qw, 5, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_sort(&qw, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "big", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "v", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_query_write_sort_key_suffix(&qw, CDB_SORT_ASC, CDB_NULLS_LAST));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "big", 3, g_rows, TOPN_ROWS));

    /* The whole store exceeds the sort buffer; pre-fix this fails
     * CDB_E_OUT_OF_BUDGET. The top-N path returns the five smallest. */
    for (i = 0; i < 5; i++) {
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
        TEST_ASSERT_TRUE(has_row);
        TEST_ASSERT_EQUAL_INT64((int64_t)i, out_row.fields[0].val.as.i64);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_FALSE(has_row);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_project_seventeen_fields);
    RUN_TEST(test_project_too_many_columns_errors);
    RUN_TEST(test_project_passthrough_overflow_errors);
    RUN_TEST(test_order_by_limit_topn_large);
    return UNITY_END();
}
