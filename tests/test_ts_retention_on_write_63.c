/* #63 Item 2: configured retention was applied only by an explicit maintenance
 * call (cdb_ts_apply_retention). The fix auto-enforces retention on the ts write
 * path (ts_append_in): after the points are journaled, the configured retention
 * is applied using the trusted server clock (cdb_db_now, converted to the
 * series' tick precision), so an over-retention series is trimmed on the next
 * write with no explicit maintenance call. The trim is bounded (removes only
 * points older than now-retention, never in-window data, never driven by a
 * point ts) and idempotent (a no-stale write trims nothing).
 *
 *   AC4 writing past the retention window auto-trims the out-of-window points on
 *       the next write, with no cdb_ts_apply_retention call
 *   AC5 in-window points are never trimmed, and a repeat write adding no
 *       over-retention point leaves the series unchanged (bounded, idempotent)
 *   FR5 a series with no retention configured is never trimmed on write
 *
 * Red->green: before the source fix ts_append_in never trimmed, so after a
 * forward-clock write all old points remain; after it, only in-window points
 * survive. Deterministic and hermetic (one fault environment with a controllable
 * clock; no network/threads). */
#define _POSIX_C_SOURCE 200809L

#include <string.h>

#include "unity.h"
#include "cdb_db.h"
#include "cdb_faultenv.h"
#include "cdb_ts.h"
#include "combolite/cdb_value.h"

#define FCAP (1536u * 1024u)
#define PAGE_LOG2 10u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u

/* Timestamps are in milliseconds (CDB_TS_MILLIS); the clock is in nanoseconds,
 * so one ms == one million ns. */
#define MS_NS INT64_C(1000000)
#define RETENTION INT64_C(5000) /* 5000 ms */

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 8192u];
static cdb_faultenv fe;
static cdb_env env;

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[4096];
static uint8_t record_buf[2u * PAGE];
static uint8_t cat_work[24u * 1024u];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static uint8_t doc_buffers[8u * PAGE];
static uint8_t ts_buffers[3u * PAGE];
static uint8_t ts_work[(CDB_TS_BLOCK_MAX_POINTS + 1u) * sizeof(cdb_ts_point)];
static cdb_db_config cfg;
static cdb_db db;

void setUp(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 8192;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));

    memset(&cfg, 0, sizeof cfg);
    cfg.pager.arena = arena;
    cfg.pager.arena_size = sizeof arena;
    cfg.pager.nodes = nodes;
    cfg.pager.node_cap = NODES;
    cfg.pager.free_list = free_list;
    cfg.pager.free_cap = sizeof free_list / sizeof free_list[0];
    cfg.record_buf = record_buf;
    cfg.record_buf_size = sizeof record_buf;
    cfg.catalog_work.bytes = cat_work;
    cfg.catalog_work.bytes_size = sizeof cat_work;
    cfg.catalog_work.entries = cat_entries;
    cfg.catalog_work.entries_cap = 512;
    cfg.catalog_page = cat_page;
    cfg.doc_buffers = doc_buffers;
    cfg.ts_buffers = ts_buffers;
    cfg.ts_work = ts_work;
    cfg.ts_work_size = sizeof ts_work;
    cfg.durability = CDB_DURABILITY_FULL;
}

void tearDown(void)
{
    (void)cdb_db_close(&db);
}

static cdb_status open_db(void)
{
    cdb_header h;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x7E, sizeof h.db_id);
    return cdb_db_open(&db, &env, "t_ts_ret", &cfg, &h);
}

static cdb_ts_def def1(void)
{
    cdb_ts_def d;
    memset(&d, 0, sizeof d);
    d.precision = CDB_TS_MILLIS;
    d.window = 60000;
    d.nfields = 1;
    d.fields[0].id = 1;
    d.fields[0].type = CDB_TYPE_INT;
    return d;
}

/* A one-field integer point at the given ms timestamp. */
static void point_at(int64_t ms, int64_t v, cdb_ts_in *in, uint8_t *enc, size_t cap)
{
    cdb_value_writer w;
    cdb_value_writer_init(&w, enc, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_int(&w, v);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    in->ts = ms;
    in->use_clock = 0;
    in->values = enc;
    in->len = cdb_value_writer_len(&w);
}

/* Sets the clock (ms) and appends one point at ms in its own transaction. */
static void append_at(uint64_t store, uint64_t series, int64_t now_ms, int64_t pt_ms, int64_t v)
{
    uint8_t enc[64];
    cdb_ts_in in;
    cdb_faultenv_set_time(&fe, 1, now_ms * MS_NS);
    point_at(pt_ms, v, &in, enc, sizeof enc);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_append(&db, store, series, &in, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
}

static size_t count_all(uint64_t store, uint64_t series, int64_t *first_ts)
{
    static uint8_t buf[16384];
    static cdb_ts_row rows[256];
    size_t n = 0;
    int64_t next;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_range(&db, store, series, INT64_MIN, INT64_MAX, buf,
                                               sizeof buf, rows, 256, &n, &next));
    if (first_ts != NULL)
        *first_ts = n ? rows[0].ts : INT64_MIN;
    return n;
}

static uint64_t new_series(uint64_t store, const char *name)
{
    cdb_ts_def d = def1();
    uint64_t s = 0;
    int created = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_ts_series(&db, store, name, strlen(name), NULL, 0, &d, &s, &created));
    TEST_ASSERT_TRUE(created);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    return s;
}

/* AC4/AC5: a forward-clock write auto-trims the out-of-window points with no
 * explicit maintenance call; in-window points survive; a further no-stale write
 * trims nothing (bounded, idempotent). */
static void test_retention_auto_enforced_on_write(void)
{
    uint64_t store = 0, series;
    int64_t first = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "m", 1, CDB_TS_LATE_ACCEPT, 0, &store));
    series = new_series(store, "cpu");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_set_retention(&db, store, series, RETENTION));

    /* Three points near t=100000 ms. The clock is at 100200 ms, so cutoff
     * 95200 drops nothing: all three are in-window. */
    append_at(store, series, 100000, 100000, 1);
    append_at(store, series, 100100, 100100, 2);
    append_at(store, series, 100200, 100200, 3);
    TEST_ASSERT_EQUAL_size_t(3, count_all(store, series, &first));
    TEST_ASSERT_EQUAL_INT64(100000, first);

    /* Advance the clock to 200000 ms and append one fresh point. cutoff =
     * 200000 - 5000 = 195000: the three old points (<=100200) are now out of
     * window and auto-trimmed on this write; the fresh point survives.
     * Red pre-fix: no trim on write, so this would read 4 points. */
    append_at(store, series, 200000, 200000, 4);
    TEST_ASSERT_EQUAL_size_t(1, count_all(store, series, &first));
    TEST_ASSERT_EQUAL_INT64(200000, first);

    /* Idempotent/bounded: a nearby write (cutoff 195100) drops nothing more and
     * keeps the in-window point at 200000. Two points remain. */
    append_at(store, series, 200100, 200100, 5);
    TEST_ASSERT_EQUAL_size_t(2, count_all(store, series, &first));
    TEST_ASSERT_EQUAL_INT64(200000, first);
}

/* FR5: a series with no retention configured is never trimmed on write, even
 * with the clock far ahead of the stored points. */
static void test_no_retention_never_trims(void)
{
    uint64_t store = 0, series;
    int64_t first = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "m", 1, CDB_TS_LATE_ACCEPT, 0, &store));
    series = new_series(store, "cpu");
    /* No cdb_ts_set_retention: keep-everything (default). */

    append_at(store, series, 100000, 100000, 1);
    append_at(store, series, 100100, 100100, 2);
    append_at(store, series, 900000, 900000, 3); /* clock far ahead */

    TEST_ASSERT_EQUAL_size_t(3, count_all(store, series, &first));
    TEST_ASSERT_EQUAL_INT64(100000, first);
}

/* FR5/AC6: the explicit cdb_ts_apply_retention path still works unchanged (its
 * caller supplies now_ts; it is not affected by the clock). */
static void test_explicit_retention_still_works(void)
{
    uint64_t store = 0, series;
    int64_t first = 0, dropped = 0;
    unsigned k;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "m", 1, CDB_TS_LATE_ACCEPT, 0, &store));
    series = new_series(store, "cpu");

    /* No clock: auto-trim-on-write is skipped, so all ten points persist. */
    cdb_faultenv_set_time(&fe, 0, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    for (k = 1; k <= 10; k++) {
        uint8_t enc[64];
        cdb_ts_in in;
        point_at((int64_t)k * 1000, (int64_t)k, &in, enc, sizeof enc);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_append(&db, store, series, &in, 1));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_size_t(10, count_all(store, series, &first));

    /* Explicit apply with caller-supplied now=10000, retention=5000: cutoff
     * 5000 keeps points at ts >= 5000 (6 of them). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_set_retention(&db, store, series, RETENTION));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_apply_retention(&db, store, series, 10000, &dropped));
    TEST_ASSERT_EQUAL_INT64(5000, dropped);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_size_t(6, count_all(store, series, &first));
    TEST_ASSERT_EQUAL_INT64(5000, first);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_retention_auto_enforced_on_write);
    RUN_TEST(test_no_retention_never_trims);
    RUN_TEST(test_explicit_retention_still_works);
    return UNITY_END();
}
