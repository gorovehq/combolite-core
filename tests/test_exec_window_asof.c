/* Red->green regression tests for CMBQL executor correctness (#36):
 *   FR1 sliding/hopping windows with per-window aggregation, and
 *   FR2 as-of join match-predicate evaluation + materialize-right-once.
 *
 * Deterministic and hermetic: mock scans over fixed tick fixtures, no
 * wall-clock, network, or shared state. Each assertion fails on the pre-fix
 * merge-base (sliding windows ran as tumbling; as-of ignored its predicate and
 * rescanned the right input per left row).
 *
 * Spec 11.5, 11.10; Spec 14.19.
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

/* Writes an integer literal value, returning its byte length. */
static size_t make_int_lit(uint8_t *buf, size_t cap, int64_t val)
{
    cdb_value_writer w;
    cdb_value_writer_init(&w, buf, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_write_int(&w, val));
    return cdb_value_writer_len(&w);
}

/* Builds a one-field tick row carrying only a timestamp. */
static void make_tick(cdb_exec_row *r, uint64_t id, int64_t ts)
{
    memset(r, 0, sizeof(*r));
    r->entry_id = id;
    r->timestamp = ts;
}

/* ---- FR1: a sliding window produces OVERLAPPING windows (not tumbling) ---- */
static void test_window_sliding_overlapping(void)
{
    uint8_t wire[256], scratch[32768];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row tick;
    cdb_exec_row out_row;
    int has_row = 0;

    /* One tick at ts=12 with size=10, step=5: it is covered by two windows,
     * [5,15) and [10,20). A tumbling executor would emit only one, [10,20). */
    make_tick(&tick, 1, 12);

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_query_write_window(&qw, CDB_WINDOW_SLIDING, NULL, 0, 10u, 5u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "ticks", 5));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "ticks", 5, &tick, 1));

    /* Window 1: [5, 15) */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_TRUE(has_row);
    TEST_ASSERT_EQUAL_STRING_LEN("$window_start", out_row.fields[out_row.n_fields - 2].name, 13);
    TEST_ASSERT_EQUAL_INT64(5, out_row.fields[out_row.n_fields - 2].val.as.i64);
    TEST_ASSERT_EQUAL_INT64(15, out_row.fields[out_row.n_fields - 1].val.as.i64);

    /* Window 2: [10, 20) — the overlap that tumbling cannot produce */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_TRUE(has_row);
    TEST_ASSERT_EQUAL_INT64(10, out_row.fields[out_row.n_fields - 2].val.as.i64);
    TEST_ASSERT_EQUAL_INT64(20, out_row.fields[out_row.n_fields - 1].val.as.i64);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_FALSE(has_row);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* ---- FR1: a tumbling window is unchanged (behavior-preserving) ---- */
static void test_window_tumbling_single(void)
{
    uint8_t wire[256], scratch[32768];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row tick;
    cdb_exec_row out_row;
    int has_row = 0;

    make_tick(&tick, 1, 1500000000LL);

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_query_write_window(&qw, CDB_WINDOW_TUMBLING, NULL, 0, 1000000000ULL, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "ticks", 5));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "ticks", 5, &tick, 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_TRUE(has_row);
    TEST_ASSERT_EQUAL_INT64(1000000000LL, out_row.fields[out_row.n_fields - 2].val.as.i64);
    TEST_ASSERT_EQUAL_INT64(2000000000LL, out_row.fields[out_row.n_fields - 1].val.as.i64);

    /* Tumbling: exactly one window per row */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_FALSE(has_row);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* ---- FR1 (AC2): per-window aggregation over a sliding window ----
 * Aggregate(COUNT(*) GROUP BY $window_start) over Window(size=10, step=5).
 * Ticks at 12, 17, 22 land in windows {5,10}, {10,15}, {15,20}, giving per
 * window counts 1,2,2,1 across starts 5,10,15,20. A tumbling executor would
 * see only starts 10 and 20 with counts 2 and 1. */
static void test_window_sliding_per_window_count(void)
{
    uint8_t wire[512], scratch[65536];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row ticks[3];
    cdb_exec_row out_row;
    int has_row = 0;
    int64_t starts[8];
    int64_t counts[8];
    size_t n = 0, i;

    make_tick(&ticks[0], 1, 12);
    make_tick(&ticks[1], 2, 17);
    make_tick(&ticks[2], 3, 22);

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate(&qw, 1, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_query_write_window(&qw, CDB_WINDOW_SLIDING, NULL, 0, 10u, 5u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "ticks", 5));
    /* Group by $window_start */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "$window_start", 13));
    /* Agg: cnt = COUNT(*) */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate_output(&qw, "cnt", 3, CDB_AGG_COUNT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "*", 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "ticks", 5, ticks, 3));

    for (;;) {
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
        if (!has_row)
            break;
        TEST_ASSERT_TRUE(n < 8);
        /* Fields: [0]=$window_start group value, [1]=cnt */
        starts[n] = out_row.fields[0].val.as.i64;
        counts[n] = out_row.fields[1].val.as.i64;
        n++;
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));

    /* Four overlapping windows, not two tumbling ones */
    TEST_ASSERT_EQUAL_size_t(4, n);
    for (i = 0; i < n; i++) {
        int64_t expect = (starts[i] == 5 || starts[i] == 20) ? 1 : 2;
        TEST_ASSERT_TRUE(starts[i] == 5 || starts[i] == 10 || starts[i] == 15 || starts[i] == 20);
        TEST_ASSERT_EQUAL_INT64(expect, counts[i]);
    }
}

/* Builds a trades (left) row with a price field. */
static void make_trade(cdb_exec_row *r, uint64_t id, int64_t ts, int64_t price)
{
    memset(r, 0, sizeof(*r));
    r->entry_id = id;
    r->timestamp = ts;
    r->n_fields = 1;
    r->fields[0].name = "price";
    r->fields[0].name_len = 5;
    cdb_eval_make_int(&r->fields[0].val, price);
}

/* Builds a quotes (right) row with a bid field. */
static void make_quote(cdb_exec_row *r, uint64_t id, int64_t ts, int64_t bid)
{
    memset(r, 0, sizeof(*r));
    r->entry_id = id;
    r->timestamp = ts;
    r->n_fields = 1;
    r->fields[0].name = "bid";
    r->fields[0].name_len = 3;
    cdb_eval_make_int(&r->fields[0].val, bid);
}

/* ---- FR2 (AC3): as-of join honors its match predicate ----
 * Backward as-of with predicate `bid < 99`. The nearest backward quote (id20,
 * bid=99) fails the predicate, so the match is the farther id10 (bid=98). A
 * predicate-ignoring executor returns id20. */
static void test_asof_honors_predicate(void)
{
    uint8_t wire[512], scratch[32768];
    uint8_t lit99[16];
    size_t lit99_len;
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row trades[1], quotes[3];
    cdb_exec_row out_row;
    int has_row = 0;

    lit99_len = make_int_lit(lit99, sizeof(lit99), 99);

    make_trade(&trades[0], 1, 1500, 100);
    make_quote(&quotes[0], 10, 1000, 98);  /* backward, bid<99 -> eligible */
    make_quote(&quotes[1], 20, 1400, 99);  /* nearest backward, but bid<99 fails */
    make_quote(&quotes[2], 30, 1600, 101); /* forward, excluded by backward */

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_asof_join(&qw, CDB_ASOF_BACKWARD, 1000));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "trades", 6));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "quotes", 6));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "$timestamp", 10));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "$timestamp", 10));
    /* match_cond: bid < 99 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_binary(&qw, CDB_BIN_LT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "bid", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(&qw, lit99, lit99_len));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "trades", 6, trades, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "quotes", 6, quotes, 3));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_TRUE(has_row);
    TEST_ASSERT_TRUE(out_row.has_right);
    TEST_ASSERT_EQUAL_UINT64(10, out_row.right_entry_id); /* the predicate-satisfying match */

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* ---- FR2 (AC4): the right input is materialized once, not rescanned ----
 * With 3 left rows and 4 right rows, a per-left-row rescan would scan the
 * right input 12 times; materialize-once scans it 4 times (once). */
static void test_asof_materialize_right_once(void)
{
    uint8_t wire[512], scratch[32768];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row trades[3], quotes[4];
    cdb_exec_row out_row;
    int has_row = 0;
    int left_rows = 0;

    make_trade(&trades[0], 1, 1500, 100);
    make_trade(&trades[1], 2, 2500, 101);
    make_trade(&trades[2], 3, 3500, 102);
    make_quote(&quotes[0], 10, 1000, 98);
    make_quote(&quotes[1], 20, 1400, 99);
    make_quote(&quotes[2], 30, 2400, 100);
    make_quote(&quotes[3], 40, 3400, 101);

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_asof_join(&qw, CDB_ASOF_BACKWARD, 5000));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "trades", 6));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "quotes", 6));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "$timestamp", 10));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "$timestamp", 10));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(&qw, (const uint8_t *)"\x02", 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "trades", 6, trades, 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "quotes", 6, quotes, 4));

    for (;;) {
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
        if (!has_row)
            break;
        left_rows++;
    }
    TEST_ASSERT_EQUAL_INT(3, left_rows);
    /* Exactly one pass over the 4 right rows, regardless of the 3 left rows. */
    TEST_ASSERT_EQUAL_UINT64(4, cdb_exec_asof_right_scan_count());

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_window_sliding_overlapping);
    RUN_TEST(test_window_tumbling_single);
    RUN_TEST(test_window_sliding_per_window_count);
    RUN_TEST(test_asof_honors_predicate);
    RUN_TEST(test_asof_materialize_right_once);
    return UNITY_END();
}
