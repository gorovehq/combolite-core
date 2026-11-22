/* QA edge/boundary tests for CMBQL executor capacity limits (#36 FR5).
 *
 * Complements the implementer's test_exec_capacity.c (17-field projection,
 * MAX+1 columns, passthrough overflow, ORDER BY ... LIMIT ASC top-N) with the
 * cases it omits: a DESC top-N over a large store (the descending ordering path
 * of the no-heap top-N), an exact-at-cap wide projection boundary, and an
 * ORDER BY ... LIMIT over a large store that returns the correct window of rows
 * (not merely "does not fail").
 *
 * Deterministic and hermetic: mock scans, no wall-clock/network/shared state.
 * Pre-fix the merge-base capped a row at 16 fields and a Sort at 256 buffered
 * rows, so a wide projection truncated and a large ORDER BY failed
 * CDB_E_OUT_OF_BUDGET.
 */
#include "unity.h"
#include "cdb_exec.h"
#include "cdb_query.h"

#include <stdio.h>
#include <string.h>

void setUp(void)
{
}
void tearDown(void)
{
}

/* ---- FR5: an exactly-at-cap wide projection returns every field ----
 * A projection of CDB_EXEC_MAX_FIELDS outputs is the boundary that must
 * succeed (CDB_EXEC_MAX_FIELDS + 1 is the implementer's error case). */
static void test_project_exact_cap_fields(void)
{
    uint8_t wire[4096], scratch[131072];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row src, out_row;
    int has_row = 0;
    size_t i;
    const size_t n_out = CDB_EXEC_MAX_FIELDS;

    memset(&src, 0, sizeof(src));
    src.entry_id = 1;
    src.n_fields = 1;
    src.fields[0].name = "v";
    src.fields[0].name_len = 1;
    cdb_eval_make_int(&src.fields[0].val, 7);

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_project(&qw, 0, n_out));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "src", 3));
    for (i = 0; i < n_out; i++) {
        char alias[8];
        int n = snprintf(alias, sizeof(alias), "c%zu", i);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_project_output(&qw, alias, (size_t)n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "v", 1));
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "src", 3, &src, 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_TRUE(has_row);
    TEST_ASSERT_EQUAL_size_t(CDB_EXEC_MAX_FIELDS, out_row.n_fields);
    for (i = 0; i < n_out; i++)
        TEST_ASSERT_EQUAL_INT64(7, out_row.fields[i].val.as.i64);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

#define QA_ROWS 400
static cdb_exec_row g_rows[QA_ROWS];

/* Fills g_rows with a permutation of 0..QA_ROWS-1 (step 97 is coprime to 400),
 * so the ascending and descending extremes are exact and sorting does work. */
static void fill_permutation(void)
{
    int i;
    memset(g_rows, 0, sizeof(g_rows));
    for (i = 0; i < QA_ROWS; i++) {
        g_rows[i].entry_id = (uint64_t)(i + 1);
        g_rows[i].n_fields = 1;
        g_rows[i].fields[0].name = "v";
        g_rows[i].fields[0].name_len = 1;
        cdb_eval_make_int(&g_rows[i].fields[0].val, (int64_t)((i * 97 + 29) % QA_ROWS));
    }
}

/* ---- FR5 (AC11/AC12): DESC top-N over a store larger than the sort buffer ----
 * Limit(3, Sort(Scan, v DESC)) over 400 rows (> the 256-row buffer). The three
 * largest are 399, 398, 397. Pre-fix this failed CDB_E_OUT_OF_BUDGET. */
static void test_order_by_desc_limit_topn(void)
{
    uint8_t wire[256], scratch[131072];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row out_row;
    int has_row = 0;
    int i;

    fill_permutation();

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_limit(&qw, 3, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_sort(&qw, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "big", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "v", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_query_write_sort_key_suffix(&qw, CDB_SORT_DESC, CDB_NULLS_LAST));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "big", 3, g_rows, QA_ROWS));

    for (i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
        TEST_ASSERT_TRUE(has_row);
        TEST_ASSERT_EQUAL_INT64((int64_t)(QA_ROWS - 1 - i), out_row.fields[0].val.as.i64);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_FALSE(has_row);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* ---- FR5: ASC top-N over a large store returns the smallest k in order ---- */
static void test_order_by_asc_limit_topn(void)
{
    uint8_t wire[256], scratch[131072];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row out_row;
    int has_row = 0;
    int i;

    fill_permutation();

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_limit(&qw, 4, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_sort(&qw, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "big", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "v", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_query_write_sort_key_suffix(&qw, CDB_SORT_ASC, CDB_NULLS_LAST));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "big", 3, g_rows, QA_ROWS));

    for (i = 0; i < 4; i++) {
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
    RUN_TEST(test_project_exact_cap_fields);
    RUN_TEST(test_order_by_desc_limit_topn);
    RUN_TEST(test_order_by_asc_limit_topn);
    return UNITY_END();
}
