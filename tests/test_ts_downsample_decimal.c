/* Regression test for issue #40 (DECIMAL downsample item): time-series
 * downsampling must aggregate DECIMAL (money) fields exactly, and must fail
 * closed on a type that cannot be numerically aggregated, rather than emitting
 * a silent 0.
 *
 * Red -> green: against the pre-fix code SUM/MIN/MAX/AVG over a DECIMAL field
 * emit an F64 0 (the DECIMAL assertions fail), and SUM over a STRING field
 * returns CDB_OK with a silent 0 (the fail-closed assertion fails). The fix
 * makes every assertion below pass.
 *
 * Hermetic: an in-memory fault environment, fixed inputs, no clock or network.
 * All values are synthetic. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_decimal_agg.h"
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
    cfg.max_open = 0;
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
}

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

static cdb_ts_def def1(uint8_t type)
{
    cdb_ts_def d;
    memset(&d, 0, sizeof d);
    d.precision = CDB_TS_MILLIS;
    d.window = 60000;
    d.nfields = 1;
    d.fields[0].id = 1;
    d.fields[0].type = type;
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

/* Appends one single-field DECIMAL point (scale + big-endian unscaled). */
static void append_dec(uint64_t store, uint64_t series, int64_t ts, uint64_t scale,
                       const uint8_t *unscaled, size_t ulen)
{
    uint8_t enc[64];
    cdb_value_writer w;
    cdb_ts_in in;
    cdb_value_writer_init(&w, enc, sizeof enc, CDB_ORDER_LITTLE, CDB_DECIMAL_UNBOUNDED);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_decimal(&w, scale, unscaled, ulen);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    in.ts = ts;
    in.use_clock = 0;
    in.values = enc;
    in.len = cdb_value_writer_len(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_append(&db, store, series, &in, 1));
}

static void append_str(uint64_t store, uint64_t series, int64_t ts, const char *s)
{
    uint8_t enc[64];
    cdb_value_writer w;
    cdb_ts_in in;
    cdb_value_writer_init(&w, enc, sizeof enc, CDB_ORDER_LITTLE, CDB_DECIMAL_UNBOUNDED);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_string(&w, s, strlen(s));
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    in.ts = ts;
    in.use_clock = 0;
    in.values = enc;
    in.len = cdb_value_writer_len(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_append(&db, store, series, &in, 1));
}

/* Reads back the single DECIMAL field of a one-point series. */
static void read_dec(uint64_t store, uint64_t series, uint64_t *scale, uint8_t *out, size_t *olen)
{
    static uint8_t buf[4096];
    static cdb_ts_row rows[16];
    size_t n;
    int64_t next;
    cdb_value obj, v;
    int found;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_range(&db, store, series, INT64_MIN, INT64_MAX, buf,
                                               sizeof buf, rows, 16, &n, &next));
    TEST_ASSERT_EQUAL_size_t(1, n);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_value_read(buf + rows[0].off, rows[0].len, db.pager.order, &obj));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, db.pager.order, 1, &v, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_DECIMAL, v.type);
    *scale = v.as.decimal.scale;
    *olen = v.as.decimal.unscaled_len;
    memcpy(out, v.as.decimal.unscaled, v.as.decimal.unscaled_len);
}

static size_t range_count(uint64_t store, uint64_t series)
{
    static uint8_t buf[4096];
    static cdb_ts_row rows[16];
    size_t n;
    int64_t next;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_range(&db, store, series, INT64_MIN, INT64_MAX, buf,
                                               sizeof buf, rows, 16, &n, &next));
    return n;
}

/* Scale-2 money inputs and their exact aggregates:
 *   10.25 (1025), -3.50 (-350), 100.00 (10000), 0.75 (75)
 *   SUM = 107.50 (10750), MIN = -3.50, MAX = 100.00,
 *   AVG = 10750 / 4 = 2687.5 -> 2688 (26.88) by round-half-to-even. */
static const uint8_t U_1025[2] = {0x04, 0x01};
static const uint8_t U_M350[2] = {0xFE, 0xA2};
static const uint8_t U_10000[2] = {0x27, 0x10};
static const uint8_t U_75[1] = {0x4B};
static const uint8_t U_SUM[2] = {0x29, 0xFE}; /* 10750 */
static const uint8_t U_AVG[2] = {0x0A, 0x80}; /* 2688  */

static void append_money_bucket(uint64_t store, uint64_t src)
{
    append_dec(store, src, 10, 2, U_1025, sizeof U_1025);
    append_dec(store, src, 20, 2, U_M350, sizeof U_M350);
    append_dec(store, src, 30, 2, U_10000, sizeof U_10000);
    append_dec(store, src, 40, 2, U_75, sizeof U_75);
}

static cdb_ts_downsample_spec one_bucket_spec(uint64_t store, uint64_t src, uint64_t dst,
                                              uint16_t agg)
{
    cdb_ts_downsample_spec spec;
    memset(&spec, 0, sizeof spec);
    spec.src_store = store;
    spec.src_series = src;
    spec.dst_store = store;
    spec.dst_series = dst;
    spec.bucket_step = 100000;
    spec.field_aggs[0] = agg;
    return spec;
}

/* AC1/AC2/AC3: SUM / MIN / MAX / AVG over a DECIMAL field are exact. */
static void test_decimal_sum_min_max_avg_exact(void)
{
    uint64_t store, src, d_sum, d_min, d_max, d_avg, scale;
    cdb_ts_def dd = def1(CDB_TYPE_DECIMAL);
    uint8_t got[CDB_DEC_MAX_BYTES];
    size_t glen;
    cdb_ts_downsample_spec spec;
    size_t gen;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "ds", 2, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();
    src = series_of(store, "raw", &dd);
    d_sum = series_of(store, "sum", &dd);
    d_min = series_of(store, "min", &dd);
    d_max = series_of(store, "max", &dd);
    d_avg = series_of(store, "avg", &dd);
    append_money_bucket(store, src);
    commit();

    spec = one_bucket_spec(store, src, d_sum, CDB_TS_AGG_SUM);
    gen = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_downsample_run(&db, &spec, 0, 100000, &gen));
    TEST_ASSERT_EQUAL_size_t(1, gen);
    read_dec(store, d_sum, &scale, got, &glen);
    TEST_ASSERT_EQUAL_UINT64(2, scale);
    TEST_ASSERT_EQUAL_size_t(sizeof U_SUM, glen);
    TEST_ASSERT_EQUAL_MEMORY(U_SUM, got, glen);

    spec = one_bucket_spec(store, src, d_min, CDB_TS_AGG_MIN);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_downsample_run(&db, &spec, 0, 100000, &gen));
    read_dec(store, d_min, &scale, got, &glen);
    TEST_ASSERT_EQUAL_UINT64(2, scale);
    TEST_ASSERT_EQUAL_size_t(sizeof U_M350, glen);
    TEST_ASSERT_EQUAL_MEMORY(U_M350, got, glen);

    spec = one_bucket_spec(store, src, d_max, CDB_TS_AGG_MAX);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_downsample_run(&db, &spec, 0, 100000, &gen));
    read_dec(store, d_max, &scale, got, &glen);
    TEST_ASSERT_EQUAL_UINT64(2, scale);
    TEST_ASSERT_EQUAL_size_t(sizeof U_10000, glen);
    TEST_ASSERT_EQUAL_MEMORY(U_10000, got, glen);

    spec = one_bucket_spec(store, src, d_avg, CDB_TS_AGG_AVG);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_downsample_run(&db, &spec, 0, 100000, &gen));
    read_dec(store, d_avg, &scale, got, &glen);
    TEST_ASSERT_EQUAL_UINT64(2, scale);
    TEST_ASSERT_EQUAL_size_t(sizeof U_AVG, glen);
    TEST_ASSERT_EQUAL_MEMORY(U_AVG, got, glen);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC3 (alignment): SUM over DECIMAL values at different scales is exact.
 *   1.5 (scale 1, unscaled 15) + 2.25 (scale 2, unscaled 225) = 3.75
 *   held at the max scale 2 -> unscaled 375 (0x0177). */
static void test_decimal_sum_mixed_scale_exact(void)
{
    uint64_t store, src, dst, scale;
    cdb_ts_def dd = def1(CDB_TYPE_DECIMAL);
    const uint8_t u15[1] = {0x0F};
    const uint8_t u225[2] = {0x00, 0xE1};
    const uint8_t want[2] = {0x01, 0x77};
    uint8_t got[CDB_DEC_MAX_BYTES];
    size_t glen, gen;
    cdb_ts_downsample_spec spec;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "ds", 2, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();
    src = series_of(store, "raw", &dd);
    dst = series_of(store, "sum", &dd);
    append_dec(store, src, 10, 1, u15, sizeof u15);
    append_dec(store, src, 20, 2, u225, sizeof u225);
    commit();

    spec = one_bucket_spec(store, src, dst, CDB_TS_AGG_SUM);
    gen = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_downsample_run(&db, &spec, 0, 100000, &gen));
    TEST_ASSERT_EQUAL_size_t(1, gen);
    read_dec(store, dst, &scale, got, &glen);
    TEST_ASSERT_EQUAL_UINT64(2, scale);
    TEST_ASSERT_EQUAL_size_t(sizeof want, glen);
    TEST_ASSERT_EQUAL_MEMORY(want, got, glen);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC4: a numeric aggregate over a non-aggregatable type fails closed with a
 * typed error and writes no silent-0 point. */
static void test_nonnumeric_numeric_agg_fails_closed(void)
{
    uint64_t store, src, dst;
    cdb_ts_def ds = def1(CDB_TYPE_STRING);
    cdb_ts_downsample_spec spec;
    size_t gen;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "ds", 2, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();
    src = series_of(store, "raw", &ds);
    dst = series_of(store, "sum", &ds);
    append_str(store, src, 10, "alpha");
    append_str(store, src, 20, "beta");
    commit();

    spec = one_bucket_spec(store, src, dst, CDB_TS_AGG_SUM);
    gen = 123;
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED, cdb_ts_downsample_run(&db, &spec, 0, 100000, &gen));
    TEST_ASSERT_EQUAL_size_t(0, gen);
    TEST_ASSERT_EQUAL_size_t(0, range_count(store, dst)); /* no silent-0 point */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC5 (FR5): COUNT over a DECIMAL field is unaffected by the fix (the numeric
 * guard applies only to SUM/AVG/MIN/MAX). COUNT yields the number of points as
 * an INT, exactly as before.
 *
 * FIRST/LAST over a DECIMAL field are deliberately NOT asserted here: they go
 * through write_agg_val's unchanged generic path, which has a pre-existing
 * defect unrelated to this fix (it re-emits a decimal's payload without its
 * tag). That is a separate issue outside the #40 DECIMAL-downsample item; this
 * change leaves COUNT/FIRST/LAST behavior exactly as it was. */
static void test_decimal_count_unchanged(void)
{
    uint64_t store, src, d_cnt;
    cdb_ts_def dd = def1(CDB_TYPE_DECIMAL);
    cdb_ts_def di = def1(CDB_TYPE_INT);
    size_t gen;
    cdb_ts_downsample_spec spec;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "ds", 2, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();
    src = series_of(store, "raw", &dd);
    d_cnt = series_of(store, "cnt", &di);
    append_money_bucket(store, src);
    commit();

    spec = one_bucket_spec(store, src, d_cnt, CDB_TS_AGG_COUNT);
    gen = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_downsample_run(&db, &spec, 0, 100000, &gen));
    TEST_ASSERT_EQUAL_size_t(1, gen);
    {
        static uint8_t buf[4096];
        static cdb_ts_row rows[16];
        size_t n;
        int64_t next;
        cdb_value obj, v;
        int found;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_range(&db, store, d_cnt, 0, 100000, buf, sizeof buf,
                                                   rows, 16, &n, &next));
        TEST_ASSERT_EQUAL_size_t(1, n);
        TEST_ASSERT_EQUAL_INT(CDB_OK,
                              cdb_value_read(buf + rows[0].off, rows[0].len, db.pager.order, &obj));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, db.pager.order, 1, &v, &found));
        TEST_ASSERT_TRUE(found);
        TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, v.type);
        TEST_ASSERT_EQUAL_INT64(4, v.as.i64);
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_decimal_sum_min_max_avg_exact);
    RUN_TEST(test_decimal_sum_mixed_scale_exact);
    RUN_TEST(test_nonnumeric_numeric_agg_fails_closed);
    RUN_TEST(test_decimal_count_unchanged);
    return UNITY_END();
}
