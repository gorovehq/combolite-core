/* Regression tests for issue #41 (time-series robustness): four bounded-buffer
 * and validation defects in cdb_ts that silently corrupt or lose data, plus
 * QA-added negative/abuse-path guards.
 *
 * Red -> green against the pre-fix code, using only pre-existing public APIs so
 * the file builds on the merge-base:
 *   FR1  A collision whose replaced row encodes > 512 bytes recorded an EMPTY
 *        value in the governance audit (old_buf[512] overflowed, the write_row
 *        result was ignored). The fix sizes the buffer to the page and checks
 *        the write; the full replaced value reaches the audit log.
 *   FR2  Downsample FIRST/LAST truncated string/binary payloads > 128 bytes.
 *        The fix keeps them in full (fail-closed beyond a bounded capture).
 *   FR3  A downsample bucket whose encoded object overflowed the writer buffer
 *        was appended anyway as a short/invalid object. The fix checks the
 *        writer error and fails closed (CDB_E_OVERFLOW), appending nothing.
 *   FR4  A zero-field series was accepted (spec 10.1 requires >= 1 field). The
 *        fix rejects it with CDB_E_INVALID_ARG.
 *
 * Hermetic: an in-memory fault environment, fixed inputs, no clock or network.
 * All values are synthetic. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_audit.h"
#include "cdb_doc.h"
#include "cdb_faultenv.h"
#include "cdb_ts.h"

#define FCAP (1536u * 1024u)
#define PAGE_LOG2 10u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u

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

static void init_env(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 8192;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
}

void setUp(void)
{
    init_env();
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

void tearDown(void) {}

static cdb_status open_db(void)
{
    cdb_header h;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x7E, sizeof h.db_id);
    return cdb_db_open(&db, &env, "t", &cfg, &h);
}

static void begin(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
}
static void commit(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
}

/* A definition of n string fields with ids 1..n. */
static cdb_ts_def def_str(uint16_t n)
{
    cdb_ts_def d;
    uint16_t i;
    memset(&d, 0, sizeof d);
    d.precision = CDB_TS_MILLIS;
    d.window = 60000;
    d.nfields = n;
    for (i = 0; i < n; i++) {
        d.fields[i].id = (uint64_t)(i + 1u);
        d.fields[i].type = CDB_TYPE_STRING;
    }
    return d;
}

static uint64_t series_of(uint64_t store, const char *name, const cdb_ts_def *d)
{
    uint64_t s;
    int created;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_ts_series(&db, store, name, strlen(name), NULL, 0, d, &s, &created));
    TEST_ASSERT_TRUE(created);
    return s;
}

/* Appends one point setting a single field to a string of `len` copies of `c`. */
static void append_field_str(uint64_t store, uint64_t series, int64_t ts, uint64_t field_id,
                             char c, size_t len)
{
    static uint8_t strbuf[PAGE];
    uint8_t enc[PAGE];
    cdb_value_writer w;
    cdb_ts_in in;
    TEST_ASSERT_TRUE(len <= sizeof strbuf);
    memset(strbuf, c, len);
    cdb_value_writer_init(&w, enc, sizeof enc, CDB_ORDER_LITTLE, CDB_DECIMAL_UNBOUNDED);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, field_id);
    cdb_value_write_string(&w, (const char *)strbuf, len);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    in.ts = ts;
    in.use_clock = 0;
    in.values = enc;
    in.len = cdb_value_writer_len(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_append(&db, store, series, &in, 1));
}

/* The number of committed points in [INT64_MIN, INT64_MAX) of a series. */
static size_t range_count(uint64_t store, uint64_t series)
{
    static uint8_t buf[PAGE * 4u];
    static cdb_ts_row rows[16];
    size_t n;
    int64_t next;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_range(&db, store, series, INT64_MIN, INT64_MAX, buf,
                                               sizeof buf, rows, 16, &n, &next));
    return n;
}

/* Reads field `field_id` of the sole row of `series`, asserting it is a string
 * of exactly `vlen` copies of `c`. */
static void assert_sole_string(uint64_t store, uint64_t series, uint64_t field_id, char c,
                               size_t vlen)
{
    static uint8_t buf[PAGE * 4u];
    static cdb_ts_row rows[8];
    static uint8_t expect[PAGE];
    size_t n;
    int64_t next;
    cdb_value obj, v;
    int found = 0;
    TEST_ASSERT_TRUE(vlen <= sizeof expect);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_range(&db, store, series, INT64_MIN, INT64_MAX, buf,
                                               sizeof buf, rows, 8, &n, &next));
    TEST_ASSERT_EQUAL_size_t(1, n);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_value_read(buf + rows[0].off, rows[0].len, db.pager.order, &obj));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, db.pager.order, field_id, &v, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_STRING, v.type);
    TEST_ASSERT_EQUAL_size_t(vlen, v.payload_len);
    memset(expect, c, vlen);
    TEST_ASSERT_EQUAL_MEMORY(expect, v.payload, vlen);
}

/* FR1 (AC1): the full > 512-byte replaced value reaches the audit log. */
static void test_collision_large_replaced_value_kept_in_full(void)
{
    uint64_t store, series;
    cdb_ts_def d = def_str(1);
    cdb_audit_event events[4];
    static uint8_t payload_buf[PAGE * 2u];
    static uint8_t expect[700];
    size_t count = 0;
    const size_t vlen = 600; /* > 512 (the old buffer), < a page's capacity */

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "s", 1, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();
    series = series_of(store, "m", &d);
    commit();

    /* Original point: ts = 1000, a 600-byte string of 'A'. */
    begin();
    append_field_str(store, series, 1000, 1, 'A', vlen);
    commit();

    /* Colliding point at ts = 1000 with a different 600-byte value. */
    begin();
    append_field_str(store, series, 1000, 1, 'B', vlen);
    commit();

    /* The audit log must carry the replaced value (the 600 'A's) in full. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_query(&db, INT64_MIN, INT64_MAX, payload_buf,
                                                  sizeof payload_buf, events, 4, &count));
    TEST_ASSERT_EQUAL_size_t(1, count);
    TEST_ASSERT_EQUAL_UINT16(CDB_AUDIT_COLLISION, events[0].event_type);
    TEST_ASSERT_EQUAL_UINT64(store, events[0].store_id);
    TEST_ASSERT_EQUAL_UINT64(series, events[0].entity_id);
    {
        cdb_value obj, v;
        int found = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_read(events[0].payload, events[0].payload_len,
                                                     db.pager.order, &obj));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, db.pager.order, 1, &v, &found));
        TEST_ASSERT_TRUE(found);
        TEST_ASSERT_EQUAL_INT(CDB_TYPE_STRING, v.type);
        TEST_ASSERT_EQUAL_size_t(vlen, v.payload_len);
        memset(expect, 'A', vlen);
        TEST_ASSERT_EQUAL_MEMORY(expect, v.payload, vlen);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* FR2 (AC2): a FIRST string value > 128 bytes survives downsampling in full. */
static void test_downsample_first_large_value_not_truncated(void)
{
    uint64_t store, src, dst;
    cdb_ts_def d = def_str(1);
    cdb_ts_downsample_spec spec;
    size_t gen;
    const size_t vlen = 300; /* > 128 (the old cap), <= the capture bound */

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "s", 1, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();
    src = series_of(store, "raw", &d);
    dst = series_of(store, "first", &d);
    append_field_str(store, src, 10, 1, 'C', vlen); /* FIRST */
    append_field_str(store, src, 20, 1, 'z', 4);
    commit();

    memset(&spec, 0, sizeof spec);
    spec.src_store = store;
    spec.src_series = src;
    spec.dst_store = store;
    spec.dst_series = dst;
    spec.bucket_step = 100000;
    spec.field_aggs[0] = CDB_TS_AGG_FIRST;

    gen = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_downsample_run(&db, &spec, 0, 100000, &gen));
    TEST_ASSERT_EQUAL_size_t(1, gen);
    assert_sole_string(store, dst, 1, 'C', vlen);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* FR2 (AC2) symmetric: the LAST capture buffer is the sibling of FIRST and the
 * old code truncated it at 128 too. A LAST string > 128 bytes must survive in
 * full. The big value is the *second* point so it is the LAST, not the FIRST. */
static void test_downsample_last_large_value_not_truncated(void)
{
    uint64_t store, src, dst;
    cdb_ts_def d = def_str(1);
    cdb_ts_downsample_spec spec;
    size_t gen;
    const size_t vlen = 300; /* > 128 (the old cap), <= the capture bound */

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "s", 1, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();
    src = series_of(store, "raw", &d);
    dst = series_of(store, "last", &d);
    append_field_str(store, src, 10, 1, 'y', 4);
    append_field_str(store, src, 20, 1, 'D', vlen); /* LAST */
    commit();

    memset(&spec, 0, sizeof spec);
    spec.src_store = store;
    spec.src_series = src;
    spec.dst_store = store;
    spec.dst_series = dst;
    spec.bucket_step = 100000;
    spec.field_aggs[0] = CDB_TS_AGG_LAST;

    gen = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_downsample_run(&db, &spec, 0, 100000, &gen));
    TEST_ASSERT_EQUAL_size_t(1, gen);
    assert_sole_string(store, dst, 1, 'D', vlen);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* FR3 (AC3): a bucket whose encoded object overflows the writer fails closed
 * with a typed error and appends no summary point. Three fields, each a ~500-
 * byte FIRST value spread one per point in the same bucket, together exceed the
 * page-sized encode buffer. */
static void test_downsample_bucket_overflow_fails_closed(void)
{
    uint64_t store, src, dst;
    cdb_ts_def d = def_str(3);
    cdb_ts_downsample_spec spec;
    size_t gen;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "s", 1, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();
    src = series_of(store, "raw", &d);
    dst = series_of(store, "first", &d);
    append_field_str(store, src, 10, 1, 'P', 500);
    append_field_str(store, src, 20, 2, 'Q', 500);
    append_field_str(store, src, 30, 3, 'R', 500);
    commit();

    memset(&spec, 0, sizeof spec);
    spec.src_store = store;
    spec.src_series = src;
    spec.dst_store = store;
    spec.dst_series = dst;
    spec.bucket_step = 100000;
    spec.field_aggs[0] = CDB_TS_AGG_FIRST;
    spec.field_aggs[1] = CDB_TS_AGG_FIRST;
    spec.field_aggs[2] = CDB_TS_AGG_FIRST;

    gen = 123;
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_ts_downsample_run(&db, &spec, 0, 100000, &gen));
    TEST_ASSERT_EQUAL_size_t(0, gen);
    TEST_ASSERT_EQUAL_size_t(0, range_count(store, dst)); /* no short/invalid point */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* FR4 (AC4): a zero-field series is rejected at create and not created. */
static void test_zero_field_series_rejected(void)
{
    uint64_t store, series = 0;
    cdb_ts_def d = def_str(0); /* nfields == 0 */
    int created = 1;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "s", 1, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_ts_series(&db, store, "m", 1, NULL, 0, &d, &series, &created));
    TEST_ASSERT_EQUAL_INT(0, created);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));

    /* The series must not exist. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND,
                          cdb_ts_series(&db, store, "m", 1, NULL, 0, NULL, &series, &created));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* FR4 guard (QA, regression-only): the other create-time definition checks the
 * nfields==0 clause shares must stay rejecting, so loosening validation around
 * the fix is caught. These are pre-existing behaviors (green before and after
 * the #41 fix); they fence the fix against collateral regression. */
static void test_def_validation_guards_hold(void)
{
    uint64_t store, series = 0;
    int created = 1;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "s", 1, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();

    /* nfields beyond the max -- rejected before the field loop is entered. */
    {
        cdb_ts_def d;
        memset(&d, 0, sizeof d);
        d.precision = CDB_TS_MILLIS;
        d.window = 60000;
        d.nfields = (uint16_t)(CDB_TS_MAX_FIELDS + 1u);
        created = 1;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                              cdb_ts_series(&db, store, "a", 1, NULL, 0, &d, &series, &created));
        TEST_ASSERT_EQUAL_INT(0, created);
    }

    /* Field IDs must be strictly increasing (equal IDs rejected). */
    {
        cdb_ts_def d;
        memset(&d, 0, sizeof d);
        d.precision = CDB_TS_MILLIS;
        d.window = 60000;
        d.nfields = 2;
        d.fields[0].id = 5;
        d.fields[0].type = CDB_TYPE_INT;
        d.fields[1].id = 5; /* not strictly increasing */
        d.fields[1].type = CDB_TYPE_INT;
        created = 1;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                              cdb_ts_series(&db, store, "b", 1, NULL, 0, &d, &series, &created));
        TEST_ASSERT_EQUAL_INT(0, created);
    }

    /* An unknown value type is rejected. */
    {
        cdb_ts_def d;
        memset(&d, 0, sizeof d);
        d.precision = CDB_TS_MILLIS;
        d.window = 60000;
        d.nfields = 1;
        d.fields[0].id = 1;
        d.fields[0].type = CDB_TYPE_UNKNOWN;
        created = 1;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                              cdb_ts_series(&db, store, "c", 1, NULL, 0, &d, &series, &created));
        TEST_ASSERT_EQUAL_INT(0, created);
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_collision_large_replaced_value_kept_in_full);
    RUN_TEST(test_downsample_first_large_value_not_truncated);
    RUN_TEST(test_downsample_last_large_value_not_truncated);
    RUN_TEST(test_downsample_bucket_overflow_fails_closed);
    RUN_TEST(test_zero_field_series_rejected);
    RUN_TEST(test_def_validation_guards_hold);
    return UNITY_END();
}
