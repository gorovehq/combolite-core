/* QA edge/abuse tests for the CMBQL AsofJoin operator (#36 FR2).
 *
 * Complements the implementer's test_exec_window_asof.c (which covers BACKWARD
 * + a literal predicate + the right-scan count) with the match-direction and
 * negative paths it does not: FORWARD nearest selection, NEAREST tie-break,
 * a tolerance that excludes every candidate (left still emitted, no right),
 * an empty right input, and a predicate that compares a RIGHT field against a
 * LEFT field (exercising the combined-row resolver, not just a constant).
 *
 * Deterministic and hermetic: mock scans, no wall-clock/network/shared state.
 * The match-selection assertions fail on the pre-fix merge-base, where the
 * join decoded but never evaluated match_cond and rescanned the right input
 * per left row.
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

/* Encodes a boolean literal, returning its byte length (an always-true match
 * condition for the direction/tolerance-only tests). */
static size_t make_bool_lit(uint8_t *buf, size_t cap, int val)
{
    cdb_value_writer w;
    cdb_value_writer_init(&w, buf, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_write_bool(&w, val));
    return cdb_value_writer_len(&w);
}

/* Builds a trades (left) row carrying a price field. */
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

/* Builds a quotes (right) row carrying a bid field. */
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

/* Writes the asof plan header + two scans + the two $timestamp time exprs.
 * The caller then writes the match condition expression. */
static void write_asof_prefix(cdb_query_writer *qw, uint8_t kind, uint64_t tol)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_asof_join(qw, kind, tol));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(qw, "trades", 6));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(qw, "quotes", 6));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(qw, "$timestamp", 10));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(qw, "$timestamp", 10));
}

/* ---- FR2: FORWARD as-of picks the nearest right point at or after left ----
 * left ts=1500; rights 1000,1400,1600,2000. Forward excludes the earlier two;
 * nearest forward is 1600 (id30). */
static void test_asof_forward_nearest(void)
{
    uint8_t wire[512], scratch[32768], tcond[16];
    size_t tlen;
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row trades[1], quotes[4], out_row;
    int has_row = 0;

    tlen = make_bool_lit(tcond, sizeof(tcond), 1);
    make_trade(&trades[0], 1, 1500, 100);
    make_quote(&quotes[0], 10, 1000, 98);
    make_quote(&quotes[1], 20, 1400, 99);
    make_quote(&quotes[2], 30, 1600, 101);
    make_quote(&quotes[3], 40, 2000, 102);

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    write_asof_prefix(&qw, CDB_ASOF_FORWARD, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(&qw, tcond, tlen));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "trades", 6, trades, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "quotes", 6, quotes, 4));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_TRUE(has_row);
    TEST_ASSERT_TRUE(out_row.has_right);
    TEST_ASSERT_EQUAL_UINT64(30, out_row.right_entry_id);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* ---- FR2: NEAREST as-of resolves a tie deterministically to the first match
 * encountered in scan order. left ts=1500; both 1400 (id20) and 1600 (id30)
 * are 100 away. The materialized right buffer is in scan order, so the earlier
 * 1400 wins. */
static void test_asof_nearest_tie_first(void)
{
    uint8_t wire[512], scratch[32768], tcond[16];
    size_t tlen;
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row trades[1], quotes[4], out_row;
    int has_row = 0;

    tlen = make_bool_lit(tcond, sizeof(tcond), 1);
    make_trade(&trades[0], 1, 1500, 100);
    make_quote(&quotes[0], 10, 1000, 98);
    make_quote(&quotes[1], 20, 1400, 99);
    make_quote(&quotes[2], 30, 1600, 101);
    make_quote(&quotes[3], 40, 2000, 102);

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    write_asof_prefix(&qw, CDB_ASOF_NEAREST, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(&qw, tcond, tlen));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "trades", 6, trades, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "quotes", 6, quotes, 4));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_TRUE(has_row);
    TEST_ASSERT_TRUE(out_row.has_right);
    TEST_ASSERT_EQUAL_UINT64(20, out_row.right_entry_id);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* ---- FR2 (negative): a tolerance that excludes every candidate ----
 * BACKWARD, tolerance=50, left ts=1500; nearest backward is 1400 (100 away) >
 * tolerance -> no right match. The left row is still emitted (left-outer
 * semantics) with has_right=0, and the right input was materialized once
 * (scan count = right row count), not rescanned. */
static void test_asof_tolerance_excludes_all(void)
{
    uint8_t wire[512], scratch[32768], tcond[16];
    size_t tlen;
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row trades[1], quotes[4], out_row;
    int has_row = 0;

    tlen = make_bool_lit(tcond, sizeof(tcond), 1);
    make_trade(&trades[0], 1, 1500, 100);
    make_quote(&quotes[0], 10, 1000, 98);
    make_quote(&quotes[1], 20, 1400, 99);
    make_quote(&quotes[2], 30, 1600, 101);
    make_quote(&quotes[3], 40, 2000, 102);

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    write_asof_prefix(&qw, CDB_ASOF_BACKWARD, 50);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(&qw, tcond, tlen));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "trades", 6, trades, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "quotes", 6, quotes, 4));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_TRUE(has_row);
    TEST_ASSERT_FALSE(out_row.has_right); /* no candidate within tolerance */
    TEST_ASSERT_EQUAL_UINT64(4, cdb_exec_asof_right_scan_count());

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* ---- FR2 (negative): an empty right input emits the left with no match ----
 * right row count 0 -> left emitted, has_right=0, right scan count 0. */
static void test_asof_empty_right(void)
{
    uint8_t wire[512], scratch[32768], tcond[16];
    size_t tlen;
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row trades[1], quotes[1], out_row;
    int has_row = 0;

    tlen = make_bool_lit(tcond, sizeof(tcond), 1);
    make_trade(&trades[0], 1, 1500, 100);
    make_quote(&quotes[0], 10, 1000, 98); /* present but 0 bound below */

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    write_asof_prefix(&qw, CDB_ASOF_BACKWARD, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(&qw, tcond, tlen));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "trades", 6, trades, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "quotes", 6, quotes, 0));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_TRUE(has_row);
    TEST_ASSERT_FALSE(out_row.has_right);
    TEST_ASSERT_EQUAL_UINT64(0, cdb_exec_asof_right_scan_count());

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_FALSE(has_row);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* ---- FR2: match predicate comparing a RIGHT field against a LEFT field ----
 * BACKWARD, predicate `bid < price` (price=100 from the left row). Backward
 * candidates: 1000 (bid=98 < 100, eligible) and 1400 (bid=105, fails). The
 * nearest *passing* candidate is id10 (bid=98), not the time-nearest id20.
 * A predicate-ignoring executor returns id20. This exercises the combined
 * left+right resolver (a constant RHS would not). */
static void test_asof_predicate_cross_field(void)
{
    uint8_t wire[512], scratch[32768];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row trades[1], quotes[3], out_row;
    int has_row = 0;

    make_trade(&trades[0], 1, 1500, 100);
    make_quote(&quotes[0], 10, 1000, 98);  /* backward, bid<price -> eligible */
    make_quote(&quotes[1], 20, 1400, 105); /* nearer in time, but bid<price fails */
    make_quote(&quotes[2], 30, 1600, 90);  /* forward, excluded by BACKWARD */

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    write_asof_prefix(&qw, CDB_ASOF_BACKWARD, 1000);
    /* match_cond: bid < price (right field vs. left field) */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_binary(&qw, CDB_BIN_LT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "bid", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "price", 5));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "trades", 6, trades, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "quotes", 6, quotes, 3));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_TRUE(has_row);
    TEST_ASSERT_TRUE(out_row.has_right);
    TEST_ASSERT_EQUAL_UINT64(10, out_row.right_entry_id); /* the predicate-passing match */

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* ---- FR2 (AC4): FORWARD over multiple left rows still scans right once ----
 * 2 left rows, 3 right rows: a per-left rescan would scan right 6 times;
 * materialize-once scans it exactly 3 times regardless of the left count. */
static void test_asof_forward_materialize_once(void)
{
    uint8_t wire[512], scratch[32768], tcond[16];
    size_t tlen;
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row trades[2], quotes[3], out_row;
    int has_row = 0;
    int left_rows = 0;

    tlen = make_bool_lit(tcond, sizeof(tcond), 1);
    make_trade(&trades[0], 1, 1000, 100);
    make_trade(&trades[1], 2, 2000, 101);
    make_quote(&quotes[0], 10, 1100, 98);
    make_quote(&quotes[1], 20, 2100, 99);
    make_quote(&quotes[2], 30, 3100, 100);

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    write_asof_prefix(&qw, CDB_ASOF_FORWARD, 5000);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(&qw, tcond, tlen));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "trades", 6, trades, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "quotes", 6, quotes, 3));

    for (;;) {
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
        if (!has_row)
            break;
        left_rows++;
    }
    TEST_ASSERT_EQUAL_INT(2, left_rows);
    TEST_ASSERT_EQUAL_UINT64(3, cdb_exec_asof_right_scan_count()); /* m, not n*m */

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_asof_forward_nearest);
    RUN_TEST(test_asof_nearest_tie_first);
    RUN_TEST(test_asof_tolerance_excludes_all);
    RUN_TEST(test_asof_empty_right);
    RUN_TEST(test_asof_predicate_cross_field);
    RUN_TEST(test_asof_forward_materialize_once);
    return UNITY_END();
}
