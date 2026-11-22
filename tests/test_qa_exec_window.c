/* QA edge/abuse tests for the CMBQL Window operator (#36 FR1 + FR5).
 *
 * Complements the implementer's test_exec_window_asof.c with cases it does not
 * cover: the HOPPING window type (type 0x03, step > size) honoring type+step,
 * the half-open [start, start+size) end boundary, per-window MAX aggregation
 * (an int-preserving aggregate distinct from the baseline COUNT), and the
 * FR5 fail-closed path where a near-full input row leaves no room for the two
 * window-bound fields (must error, never silently drop the bounds).
 *
 * Deterministic and hermetic: mock scans over fixed-tick fixtures, no
 * wall-clock, network, or shared mutable state. The window-semantics assertions
 * fail on the pre-fix merge-base, where the executor ignored type+step_ns and
 * ran every window as tumbling from size_ns alone.
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

/* Builds a one-field tick row carrying a timestamp and an int value "v". */
static void make_vrow(cdb_exec_row *r, uint64_t id, int64_t ts, int64_t v)
{
    memset(r, 0, sizeof(*r));
    r->entry_id = id;
    r->timestamp = ts;
    r->n_fields = 1;
    r->fields[0].name = "v";
    r->fields[0].name_len = 1;
    cdb_eval_make_int(&r->fields[0].val, v);
}

/* Builds a bare tick row carrying only a timestamp. */
static void make_tick(cdb_exec_row *r, uint64_t id, int64_t ts)
{
    memset(r, 0, sizeof(*r));
    r->entry_id = id;
    r->timestamp = ts;
}

/* ---- FR1: a HOPPING window (step > size) honors type+step, not size_ns ----
 * size=4, step=10, HOPPING, one tick at ts=12. The hopping window starting at
 * floor(12/10)*10 = 10 covers [10,14); exactly one window (non-overlapping).
 * The pre-fix executor derived the window from size_ns only, giving the
 * tumbling window floor(12/4)*4 = 12 -> [12,16). Asserting start==10 is red on
 * the merge-base and green after the fix. */
static void test_window_hopping_honors_step(void)
{
    uint8_t wire[256], scratch[32768];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row tick, out_row;
    int has_row = 0;

    make_tick(&tick, 1, 12);

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_query_write_window(&qw, CDB_WINDOW_HOPPING, NULL, 0, 4u, 10u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "ticks", 5));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "ticks", 5, &tick, 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_TRUE(has_row);
    /* Hopping start=10 (not the pre-fix tumbling-from-size start=12). */
    TEST_ASSERT_EQUAL_INT64(10, out_row.fields[out_row.n_fields - 2].val.as.i64);
    TEST_ASSERT_EQUAL_INT64(14, out_row.fields[out_row.n_fields - 1].val.as.i64);

    /* Non-overlapping: exactly one window for this row. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_FALSE(has_row);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* ---- FR1: window membership is half-open [start, start+size) ----
 * size=10, step=5, a tick exactly on ts=10. It is covered by [5,15) and
 * [10,20) but NOT by [0,10) (end-exclusive). A broken inclusive-end executor
 * would also emit the window starting at 0. We assert the first emitted window
 * starts at 5 and exactly two windows are produced. */
static void test_window_half_open_end_boundary(void)
{
    uint8_t wire[256], scratch[32768];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row tick, out_row;
    int has_row = 0;
    int64_t starts[8];
    size_t n = 0, i;

    make_tick(&tick, 1, 10);

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_query_write_window(&qw, CDB_WINDOW_SLIDING, NULL, 0, 10u, 5u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "ticks", 5));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "ticks", 5, &tick, 1));

    for (;;) {
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
        if (!has_row)
            break;
        TEST_ASSERT_TRUE(n < 8);
        starts[n++] = out_row.fields[out_row.n_fields - 2].val.as.i64;
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));

    TEST_ASSERT_EQUAL_size_t(2, n);         /* [5,15) and [10,20), not [0,10) */
    TEST_ASSERT_EQUAL_INT64(5, starts[0]);  /* ts=10 excluded from the window ending at 10 */
    TEST_ASSERT_EQUAL_INT64(10, starts[1]);
}

/* ---- FR1 (AC2): per-window MAX aggregation over a sliding window ----
 * Aggregate(MAX(v) GROUP BY $window_start) over Window(size=10, step=5).
 * Ticks (ts,v)=(12,10),(17,100). Row 12 lands in windows starting 5,10; row 17
 * in windows starting 10,15. Per-window MAX(v): start5->10, start10->100,
 * start15->100 -> three groups. A tumbling executor sees only start10 with
 * MAX 100 -> one group. MAX preserves the int value type, so the result reads
 * cleanly as i64. */
static void test_window_sliding_per_window_max(void)
{
    uint8_t wire[512], scratch[65536];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row rows[2], out_row;
    int has_row = 0;
    int64_t starts[8], maxes[8];
    size_t n = 0, i;
    int seen5 = 0, seen10 = 0, seen15 = 0;

    make_vrow(&rows[0], 1, 12, 10);
    make_vrow(&rows[1], 2, 17, 100);

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate(&qw, 1, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_query_write_window(&qw, CDB_WINDOW_SLIDING, NULL, 0, 10u, 5u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "ticks", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "$window_start", 13));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate_output(&qw, "mx", 2, CDB_AGG_MAX));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&qw, "v", 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "ticks", 5, rows, 2));

    for (;;) {
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
        if (!has_row)
            break;
        TEST_ASSERT_TRUE(n < 8);
        starts[n] = out_row.fields[0].val.as.i64;
        maxes[n] = out_row.fields[1].val.as.i64;
        n++;
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));

    TEST_ASSERT_EQUAL_size_t(3, n); /* three overlapping windows, not one tumbling */
    for (i = 0; i < n; i++) {
        if (starts[i] == 5) {
            seen5 = 1;
            TEST_ASSERT_EQUAL_INT64(10, maxes[i]);
        } else if (starts[i] == 10) {
            seen10 = 1;
            TEST_ASSERT_EQUAL_INT64(100, maxes[i]);
        } else if (starts[i] == 15) {
            seen15 = 1;
            TEST_ASSERT_EQUAL_INT64(100, maxes[i]);
        } else {
            TEST_FAIL_MESSAGE("unexpected window start");
        }
    }
    TEST_ASSERT_TRUE(seen5 && seen10 && seen15);
}

/* ---- FR5: a near-full input row that leaves no room for the two window
 * bounds fails closed with CDB_E_OVERFLOW, never silently dropping
 * $window_start/$window_end. A row with CDB_EXEC_MAX_FIELDS-1 fields + 2 bound
 * fields exceeds the row cap. */
static void test_window_overflow_fails_closed(void)
{
    uint8_t wire[256], scratch[32768];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row src, out_row;
    int has_row = 0;
    cdb_status st;
    size_t i;
    const size_t nf = CDB_EXEC_MAX_FIELDS - 1; /* +2 bounds overflows the cap */

    memset(&src, 0, sizeof(src));
    src.entry_id = 1;
    src.timestamp = 5;
    src.n_fields = nf;
    for (i = 0; i < nf; i++) {
        src.fields[i].name = "f";
        src.fields[i].name_len = 1;
        cdb_eval_make_int(&src.fields[i].val, (int64_t)i);
    }

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_query_write_window(&qw, CDB_WINDOW_TUMBLING, NULL, 0, 10u, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "src", 3));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "src", 3, &src, 1));

    st = cdb_exec_next(&cur, &out_row, &has_row);
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, st); /* no silent drop of window bounds */

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* ---- FR5: the boundary just under the cap still returns the window bounds ----
 * A row with CDB_EXEC_MAX_FIELDS-2 fields + 2 bounds == exactly the cap, OK. */
static void test_window_at_cap_boundary_ok(void)
{
    uint8_t wire[256], scratch[32768];
    cdb_query_writer qw;
    cdb_exec_cursor cur;
    cdb_exec_row src, out_row;
    int has_row = 0;
    size_t i;
    const size_t nf = CDB_EXEC_MAX_FIELDS - 2; /* +2 bounds == exactly the cap */

    memset(&src, 0, sizeof(src));
    src.entry_id = 1;
    src.timestamp = 5;
    src.n_fields = nf;
    for (i = 0; i < nf; i++) {
        src.fields[i].name = "f";
        src.fields[i].name_len = 1;
        cdb_eval_make_int(&src.fields[i].val, (int64_t)i);
    }

    cdb_query_writer_init(&qw, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_query_write_window(&qw, CDB_WINDOW_TUMBLING, NULL, 0, 10u, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "src", 3));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, NULL, wire, cdb_query_writer_len(&qw), NULL,
                                                0, scratch, sizeof(scratch)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_set_mock_scan(&cur, "src", 3, &src, 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &out_row, &has_row));
    TEST_ASSERT_TRUE(has_row);
    TEST_ASSERT_EQUAL_size_t(CDB_EXEC_MAX_FIELDS, out_row.n_fields);
    TEST_ASSERT_EQUAL_INT64(0, out_row.fields[out_row.n_fields - 2].val.as.i64);  /* [0,10) */
    TEST_ASSERT_EQUAL_INT64(10, out_row.fields[out_row.n_fields - 1].val.as.i64);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_window_hopping_honors_step);
    RUN_TEST(test_window_half_open_end_boundary);
    RUN_TEST(test_window_sliding_per_window_max);
    RUN_TEST(test_window_overflow_fails_closed);
    RUN_TEST(test_window_at_cap_boundary_ok);
    return UNITY_END();
}
