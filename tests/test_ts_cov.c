/* Branch-coverage companion to test_ts.c for src/cdb_ts.c.
 *
 * Targets the edge and error paths the main suite leaves thin: argument and
 * state validation, cdb_ts_range boundaries (empty/partial/too-small/bogus),
 * describe, and the retention (set/get/apply) and downsample
 * (every aggregation) APIs that the main suite does not touch at all. */

#include <stdio.h>
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

static unsigned collisions;

static void on_collision(void *ctx, uint64_t store, uint64_t series, int64_t ts)
{
    (void)ctx;
    (void)store;
    (void)series;
    (void)ts;
    collisions++;
}

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
    {
        const char *cap = getenv("CDB_TEST_MAX_OPEN");
        cfg.max_open = cap != NULL ? (unsigned)atoi(cap) : 0;
    }
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
    cfg.ts_collision = on_collision;
    cfg.durability = CDB_DURABILITY_FULL;
    collisions = 0;
    TEST_ASSERT_EQUAL_size_t(cdb_ts_work_size(), sizeof ts_work);
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

static void begin(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL)); }
static void commit(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db)); }

/* ------------------------------------------------------------ points */

typedef struct pt {
    int64_t ts;
    uint8_t enc[192];
    size_t n;
} pt;

/* A simple point on the def4 schema: field 1 int always; field 2 f64 when
 * has_f; field 3 string when s; field 4 bool when b >= 0. (As in test_ts.c.) */
static pt make(int64_t ts, int64_t i, int has_f, double f, const char *s, int b)
{
    pt p;
    cdb_value_writer w;
    p.ts = ts;
    cdb_value_writer_init(&w, p.enc, sizeof p.enc, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_int(&w, i);
    if (has_f) {
        cdb_value_field(&w, 2);
        cdb_value_write_f64(&w, f);
    }
    if (s) {
        cdb_value_field(&w, 3);
        cdb_value_write_string(&w, s, strlen(s));
    }
    if (b >= 0) {
        cdb_value_field(&w, 4);
        cdb_value_write_bool(&w, b);
    }
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    p.n = cdb_value_writer_len(&w);
    return p;
}

static cdb_ts_def def4(int cov)
{
    cdb_ts_def d;
    memset(&d, 0, sizeof d);
    d.precision = CDB_TS_MILLIS;
    d.window = 60000;
    d.change_of_value = cov;
    d.nfields = 4;
    d.fields[0].id = 1;
    d.fields[0].type = CDB_TYPE_INT;
    d.fields[1].id = 2;
    d.fields[1].type = CDB_TYPE_F64;
    d.fields[2].id = 3;
    d.fields[2].type = CDB_TYPE_STRING;
    d.fields[3].id = 4;
    d.fields[3].type = CDB_TYPE_BOOL;
    return d;
}

static uint64_t series_of(uint64_t store, const char *name, const cdb_ts_def *d)
{
    uint64_t s;
    int created;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_series(&db, store, name, strlen(name), NULL, 0, d, &s, &created));
    TEST_ASSERT_TRUE(created);
    return s;
}

static cdb_status append1(uint64_t store, uint64_t series, const pt *p)
{
    cdb_ts_in in;
    in.ts = p->ts;
    in.use_clock = 0;
    in.values = p->enc;
    in.len = p->n;
    return cdb_ts_append(&db, store, series, &in, 1);
}

/* Reads a whole range into a fixed buffer and returns the count (asserts OK). */
static size_t read_all(uint64_t store, uint64_t series, int64_t from, int64_t to, int64_t *first_ts)
{
    static uint8_t buf[16384];
    static cdb_ts_row rows[256];
    size_t n;
    int64_t next;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_range(&db, store, series, from, to, buf, sizeof buf, rows, 256, &n, &next));
    if (first_ts != NULL)
        *first_ts = n ? rows[0].ts : INT64_MIN;
    return n;
}

/* ------------------------------------------------------------ create/def errors */

static void test_cov_create_and_def_errors(void)
{
    uint64_t store, s;
    cdb_ts_def d;
    int created;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    /* Bad late mode / negative lateness. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_ts_create(&db, "bad", 3, CDB_TS_LATE_HOLD + 1u, 0, &store));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_ts_create(&db, "bad", 3, CDB_TS_LATE_ACCEPT, -1, &store));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "m", 1, CDB_TS_LATE_ACCEPT, 0, &store));
    /* A store that already exists. */
    TEST_ASSERT_EQUAL_INT(CDB_E_EXISTS, cdb_ts_create(&db, "m", 1, CDB_TS_LATE_ACCEPT, 0, &store));

    /* Creating a store inside a transaction is refused. */
    begin();
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_ts_create(&db, "intx", 4, CDB_TS_LATE_ACCEPT, 0, &s));

    /* A missing series without a def. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_ts_series(&db, store, "none", 4, NULL, 0, NULL, &s, &created));

    /* check_def rejections (the def path needs a transaction). */
    d = def4(0);
    d.precision = (uint8_t)(CDB_TS_NANOS + 1u);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_ts_series(&db, store, "p", 1, NULL, 0, &d, &s, &created));
    d = def4(0);
    d.window = -1;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_ts_series(&db, store, "w", 1, NULL, 0, &d, &s, &created));
    d = def4(0);
    d.fields[0].type = (uint8_t)CDB_TYPE_UNKNOWN;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_ts_series(&db, store, "t", 1, NULL, 0, &d, &s, &created));
    d = def4(0);
    d.fields[1].id = d.fields[0].id; /* not strictly increasing */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_ts_series(&db, store, "i", 1, NULL, 0, &d, &s, &created));

    /* A zero window takes the precision's default (one hour). */
    d = def4(0);
    d.window = 0;
    s = series_of(store, "dw", &d);
    {
        cdb_ts_def got;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_describe(&db, store, s, &got)); /* describe in a tx */
        TEST_ASSERT_EQUAL_INT64(3600000, got.window); /* 1h in ms */
        TEST_ASSERT_EQUAL_UINT16(4, got.nfields);
    }
    commit();

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ------------------------------------------------------------ append/describe errors */

static void test_cov_append_errors(void)
{
    uint64_t store, s;
    cdb_ts_def d = def4(0);
    pt p = make(1000, 1, 0, 0, NULL, -1);
    cdb_ts_in in;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "m", 1, CDB_TS_LATE_ACCEPT, 0, &store));

    /* Appending outside a transaction is refused. */
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, append1(store, 1, &p));
    /* describe of a missing series (not in a tx: rec_get path). */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_ts_describe(&db, store, 1, &d));

    begin();
    s = series_of(store, "cpu", &d);

    /* n == 0 is a no-op success. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_append(&db, store, s, NULL, 0));
    /* n > 0 with a NULL point list. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_ts_append(&db, store, s, NULL, 1));
    /* A series that does not exist. */
    in.ts = 1;
    in.use_clock = 0;
    in.values = p.enc;
    in.len = p.n;
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_ts_append(&db, store, s + 999u, &in, 1));

    /* A value of the wrong type and an unknown field. */
    {
        pt bad;
        cdb_value_writer w;
        cdb_value_writer_init(&w, bad.enc, sizeof bad.enc, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        cdb_value_begin_object(&w);
        cdb_value_field(&w, 1);
        cdb_value_write_string(&w, "x", 1); /* field 1 is INT */
        cdb_value_end_object(&w);
        bad.ts = 2000;
        bad.n = cdb_value_writer_len(&w);
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, append1(store, s, &bad));

        cdb_value_writer_init(&w, bad.enc, sizeof bad.enc, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        cdb_value_begin_object(&w);
        cdb_value_field(&w, 99); /* unknown field */
        cdb_value_write_int(&w, 1);
        cdb_value_end_object(&w);
        bad.n = cdb_value_writer_len(&w);
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, append1(store, s, &bad));
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, append1(store, s, &p));
    commit();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ------------------------------------------------------------ range edges */

static void test_cov_range_edges(void)
{
    uint64_t store, s;
    cdb_ts_def d = def4(0);
    static uint8_t buf[16384];
    static cdb_ts_row rows[256];
    size_t n;
    int64_t next;
    unsigned k;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "m", 1, CDB_TS_LATE_ACCEPT, 0, &store));

    /* A store that does not exist. */
    n = 123;
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND,
                          cdb_ts_range(&db, 987654u, 1, INT64_MIN, INT64_MAX, buf, sizeof buf, rows, 256, &n, &next));
    TEST_ASSERT_EQUAL_size_t(0, n);

    begin();
    s = series_of(store, "cpu", &d);
    commit();

    /* An empty series: OK, nothing returned, next == to. */
    next = 7;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_range(&db, store, s, 0, 1000, buf, sizeof buf, rows, 256, &n, &next));
    TEST_ASSERT_EQUAL_size_t(0, n);
    TEST_ASSERT_EQUAL_INT64(1000, next);

    /* A series that does not exist. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND,
                          cdb_ts_range(&db, store, s + 500u, 0, 10, buf, sizeof buf, rows, 256, &n, &next));

    begin();
    for (k = 0; k < 20; k++) {
        pt p = make(1000 + (int64_t)k * 100, (int64_t)k, 0, 0, NULL, -1);
        TEST_ASSERT_EQUAL_INT(CDB_OK, append1(store, s, &p));
    }
    commit();

    /* from >= to: OK, empty, next == to. */
    next = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_range(&db, store, s, 5000, 5000, buf, sizeof buf, rows, 256, &n, &next));
    TEST_ASSERT_EQUAL_size_t(0, n);
    TEST_ASSERT_EQUAL_INT64(5000, next);

    /* max == 0: cannot fit a row though one is in range -> BUFFER_TOO_SMALL. */
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL,
                          cdb_ts_range(&db, store, s, INT64_MIN, INT64_MAX, buf, sizeof buf, rows, 0, &n, &next));
    TEST_ASSERT_EQUAL_size_t(0, n);

    /* cap too small for even one encoded row -> BUFFER_TOO_SMALL. */
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL,
                          cdb_ts_range(&db, store, s, INT64_MIN, INT64_MAX, buf, 1u, rows, 256, &n, &next));

    /* Paginate in small pages: *next advances and the walk completes. */
    {
        int64_t at = INT64_MIN;
        size_t total = 0;
        for (;;) {
            TEST_ASSERT_EQUAL_INT(CDB_OK,
                                  cdb_ts_range(&db, store, s, at, INT64_MAX, buf, sizeof buf, rows, 7, &n, &next));
            total += n;
            if (next == INT64_MAX)
                break;
            TEST_ASSERT_TRUE(n > 0);
            at = next;
        }
        TEST_ASSERT_EQUAL_size_t(20, total);
    }

    /* A window that lands entirely before any data: OK, empty. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_range(&db, store, s, 0, 500, buf, sizeof buf, rows, 256, &n, &next));
    TEST_ASSERT_EQUAL_size_t(0, n);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ------------------------------------------------------------ retention */

static void test_cov_retention(void)
{
    uint64_t store, s;
    cdb_ts_def d = def4(0);
    int64_t ret, dropped, first;
    unsigned k;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "m", 1, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();
    s = series_of(store, "cpu", &d);
    for (k = 1; k <= 10; k++) {
        pt p = make((int64_t)k * 1000, (int64_t)k, 0, 0, NULL, -1);
        TEST_ASSERT_EQUAL_INT(CDB_OK, append1(store, s, &p));
    }
    commit();

    /* Security guards on the audit store. */
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_ts_set_retention(&db, CDB_AUDIT_STORE_ID, s, 1000));
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_ts_apply_retention(&db, CDB_AUDIT_STORE_ID, s, 0, &dropped));

    /* Argument and lookup errors. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_ts_set_retention(&db, store, s, -1));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_ts_get_retention(&db, store, s, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_ts_set_retention(&db, store, s + 999u, 1000));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_ts_get_retention(&db, store, s + 999u, &ret));

    /* Default is keep-everything. */
    ret = -1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_get_retention(&db, store, s, &ret));
    TEST_ASSERT_EQUAL_INT64(0, ret);

    /* Set, then read back. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_set_retention(&db, store, s, 5000));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_get_retention(&db, store, s, &ret));
    TEST_ASSERT_EQUAL_INT64(5000, ret);

    /* Setting zero clears it (the delete path). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_set_retention(&db, store, s, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_get_retention(&db, store, s, &ret));
    TEST_ASSERT_EQUAL_INT64(0, ret);

    /* apply with no retention: nothing dropped, cutoff reported as INT64_MIN. */
    dropped = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_apply_retention(&db, store, s, 100000, &dropped));
    TEST_ASSERT_EQUAL_INT64(INT64_MIN, dropped);
    TEST_ASSERT_EQUAL_size_t(10, read_all(store, s, INT64_MIN, INT64_MAX, &first));

    /* apply with a real retention: cutoff = now - retention; older points go. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_set_retention(&db, store, s, 5000));
    begin();
    dropped = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_apply_retention(&db, store, s, 10000, &dropped));
    TEST_ASSERT_EQUAL_INT64(5000, dropped);
    commit();
    TEST_ASSERT_EQUAL_size_t(6, read_all(store, s, INT64_MIN, INT64_MAX, &first));
    TEST_ASSERT_EQUAL_INT64(5000, first);

    /* drop_before: the audit guard and a missing series. */
    begin();
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_ts_drop_before(&db, CDB_AUDIT_STORE_ID, s, 0));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_ts_drop_before(&db, store, s + 999u, 0));
    commit();

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ------------------------------------------------------------ downsample */

typedef struct fv {
    uint64_t id;
    uint8_t type;
    int64_t i;
    double f;
    float f32;
    const char *s;
    int b;
} fv;

static size_t enc_point(uint8_t *buf, size_t cap, const fv *fields, size_t nf)
{
    cdb_value_writer w;
    size_t i;
    cdb_value_writer_init(&w, buf, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    for (i = 0; i < nf; i++) {
        cdb_value_field(&w, fields[i].id);
        switch (fields[i].type) {
        case CDB_TYPE_INT: cdb_value_write_int(&w, fields[i].i); break;
        case CDB_TYPE_F64: cdb_value_write_f64(&w, fields[i].f); break;
        case CDB_TYPE_F32: cdb_value_write_f32(&w, fields[i].f32); break;
        case CDB_TYPE_BOOL: cdb_value_write_bool(&w, fields[i].b); break;
        case CDB_TYPE_STRING: cdb_value_write_string(&w, fields[i].s, strlen(fields[i].s)); break;
        default: break;
        }
    }
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    return cdb_value_writer_len(&w);
}

static cdb_ts_def defN(const cdb_ts_field *f, uint16_t nf)
{
    cdb_ts_def d;
    memset(&d, 0, sizeof d);
    d.precision = CDB_TS_MILLIS;
    d.window = 60000;
    d.nfields = nf;
    memcpy(d.fields, f, (size_t)nf * sizeof f[0]);
    return d;
}

/* SUM/MIN/MAX/AVG over int, f64 and f32, plus COUNT. A 3-field source is
 * downsampled once per aggregation (small blocks keep the pager arena within
 * bounds), each run writing to its own destination series. */
static void test_cov_downsample_numeric(void)
{
    static const cdb_ts_field fsrc[3] = { { 1, CDB_TYPE_INT }, { 2, CDB_TYPE_F64 }, { 3, CDB_TYPE_F32 } };
    static const cdb_ts_field fcnt[3] = { { 1, CDB_TYPE_INT }, { 2, CDB_TYPE_INT }, { 3, CDB_TYPE_INT } };
    uint64_t store, src, d_sum, d_min, d_max, d_avg, d_cnt;
    cdb_ts_def dsrc = defN(fsrc, 3), dcnt = defN(fcnt, 3);
    cdb_ts_downsample_spec spec;
    static uint8_t buf[16384];
    static cdb_ts_row rows[16];
    size_t gen, n;
    int64_t next;
    unsigned pi;
    static const int64_t ivals[3] = { 10, 20, 30 };

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "ds", 2, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();
    src = series_of(store, "raw", &dsrc);
    d_sum = series_of(store, "s", &dsrc);
    d_min = series_of(store, "n", &dsrc);
    d_max = series_of(store, "x", &dsrc);
    d_avg = series_of(store, "a", &dsrc);
    d_cnt = series_of(store, "c", &dcnt);
    for (pi = 0; pi < 3; pi++) {
        fv pf[3];
        pt p;
        pf[0].id = 1; pf[0].type = CDB_TYPE_INT; pf[0].i = ivals[pi];
        pf[1].id = 2; pf[1].type = CDB_TYPE_F64; pf[1].f = (double)(pi + 1);
        pf[2].id = 3; pf[2].type = CDB_TYPE_F32; pf[2].f32 = (float)ivals[pi];
        p.ts = 10 + (int64_t)pi * 10;
        p.n = enc_point(p.enc, sizeof p.enc, pf, 3);
        TEST_ASSERT_EQUAL_INT(CDB_OK, append1(store, src, &p));
    }
    commit();

    memset(&spec, 0, sizeof spec);
    spec.src_store = store;
    spec.src_series = src;
    spec.dst_store = store;
    spec.bucket_step = 1000; /* a single bucket over [0, 1000) */

    /* One run per aggregation; each run applies the same aggregation to all
     * three field types, exercising the int/f32/f64 arms of each. */
    {
        struct { uint64_t dst; uint16_t agg; } runs[5] = {
            { 0, CDB_TS_AGG_SUM }, { 0, CDB_TS_AGG_MIN }, { 0, CDB_TS_AGG_MAX },
            { 0, CDB_TS_AGG_AVG }, { 0, CDB_TS_AGG_COUNT }
        };
        unsigned r;
        runs[0].dst = d_sum; runs[1].dst = d_min; runs[2].dst = d_max;
        runs[3].dst = d_avg; runs[4].dst = d_cnt;
        for (r = 0; r < 5; r++) {
            spec.dst_series = runs[r].dst;
            spec.field_aggs[0] = runs[r].agg;
            spec.field_aggs[1] = runs[r].agg;
            spec.field_aggs[2] = runs[r].agg;
            begin();
            gen = 0;
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_downsample_run(&db, &spec, 0, 1000, &gen));
            TEST_ASSERT_EQUAL_size_t(1, gen);
            commit();
        }
    }

    /* Spot-check the integer field across the aggregations. */
    {
        struct { uint64_t dst; int64_t want; } chk[5] = {
            { d_sum, 60 }, { d_min, 10 }, { d_max, 30 }, { d_avg, 20 }, { d_cnt, 3 }
        };
        unsigned r;
        for (r = 0; r < 5; r++) {
            cdb_value obj, v;
            int found;
            TEST_ASSERT_EQUAL_INT(CDB_OK,
                                  cdb_ts_range(&db, store, chk[r].dst, 0, 1000, buf, sizeof buf, rows, 16, &n, &next));
            TEST_ASSERT_EQUAL_size_t(1, n);
            TEST_ASSERT_EQUAL_INT64(0, rows[0].ts);
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_read(buf + rows[0].off, rows[0].len, db.pager.order, &obj));
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, db.pager.order, 1, &v, &found));
            TEST_ASSERT_TRUE(found);
            TEST_ASSERT_EQUAL_INT64(chk[r].want, v.as.i64);
        }
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* FIRST / LAST over int, f64, f32, string, bool (write_agg_val branches). */
static void test_cov_downsample_first_last(void)
{
    static const cdb_ts_field flds[5] = {
        { 1, CDB_TYPE_INT }, { 2, CDB_TYPE_F64 }, { 3, CDB_TYPE_F32 }, { 4, CDB_TYPE_STRING }, { 5, CDB_TYPE_BOOL }
    };
    static const char *names[3] = { "aa", "bb", "cc" };
    uint64_t store, src, dst;
    cdb_ts_def d = defN(flds, 5);
    cdb_ts_downsample_spec spec;
    static uint8_t buf[16384];
    static cdb_ts_row rows[16];
    size_t gen, n;
    int64_t next;
    unsigned pi;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "ds", 2, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();
    src = series_of(store, "raw", &d);
    dst = series_of(store, "agg", &d);
    for (pi = 0; pi < 3; pi++) {
        fv pf[5];
        pt p;
        int64_t base = (int64_t)(pi + 1) * 10;
        pf[0].id = 1; pf[0].type = CDB_TYPE_INT; pf[0].i = base;
        pf[1].id = 2; pf[1].type = CDB_TYPE_F64; pf[1].f = (double)base + 0.25;
        pf[2].id = 3; pf[2].type = CDB_TYPE_F32; pf[2].f32 = (float)base;
        pf[3].id = 4; pf[3].type = CDB_TYPE_STRING; pf[3].s = names[pi];
        pf[4].id = 5; pf[4].type = CDB_TYPE_BOOL; pf[4].b = (int)(pi & 1u);
        p.ts = 10 + (int64_t)pi * 10;
        p.n = enc_point(p.enc, sizeof p.enc, pf, 5);
        TEST_ASSERT_EQUAL_INT(CDB_OK, append1(store, src, &p));
    }
    commit();

    memset(&spec, 0, sizeof spec);
    spec.src_store = store;
    spec.src_series = src;
    spec.dst_store = store;
    spec.dst_series = dst;
    spec.bucket_step = 100000; /* one bucket */
    spec.field_aggs[0] = CDB_TS_AGG_FIRST; /* int */
    spec.field_aggs[1] = CDB_TS_AGG_LAST;  /* f64 */
    spec.field_aggs[2] = CDB_TS_AGG_FIRST; /* f32 */
    spec.field_aggs[3] = CDB_TS_AGG_LAST;  /* string */
    spec.field_aggs[4] = CDB_TS_AGG_FIRST; /* bool */

    /* Run while already inside a transaction (the no-self-commit path). */
    begin();
    gen = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_downsample_run(&db, &spec, 0, 100000, &gen));
    TEST_ASSERT_EQUAL_size_t(1, gen);
    commit();

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_range(&db, store, dst, 0, 100000, buf, sizeof buf, rows, 16, &n, &next));
    TEST_ASSERT_EQUAL_size_t(1, n);
    {
        cdb_value obj, v;
        int found;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_read(buf + rows[0].off, rows[0].len, db.pager.order, &obj));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, db.pager.order, 1, &v, &found)); /* FIRST int */
        TEST_ASSERT_TRUE(found);
        TEST_ASSERT_EQUAL_INT64(10, v.as.i64);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, db.pager.order, 4, &v, &found)); /* LAST string */
        TEST_ASSERT_TRUE(found);
        TEST_ASSERT_EQUAL_size_t(2, v.payload_len);
        TEST_ASSERT_EQUAL_MEMORY("cc", v.payload, 2);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, db.pager.order, 5, &v, &found)); /* FIRST bool */
        TEST_ASSERT_TRUE(found);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

static void test_cov_downsample_errors(void)
{
    uint64_t store, src, dst;
    cdb_ts_def d = def4(0);
    cdb_ts_downsample_spec spec;
    size_t gen;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "ds", 2, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();
    src = series_of(store, "raw", &d);
    dst = series_of(store, "agg", &d);
    {
        pt p = make(50, 1, 1, 1.0, NULL, -1);
        TEST_ASSERT_EQUAL_INT(CDB_OK, append1(store, src, &p));
    }
    commit();

    memset(&spec, 0, sizeof spec);
    spec.src_store = store;
    spec.src_series = src;
    spec.dst_store = store;
    spec.dst_series = dst;
    spec.bucket_step = 100;

    /* NULL arguments. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_ts_downsample_run(&db, NULL, 0, 100, &gen));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_ts_downsample_run(&db, &spec, 0, 100, NULL));

    /* Bad bucket / interval. */
    spec.bucket_step = 0;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_ts_downsample_run(&db, &spec, 0, 100, &gen));
    spec.bucket_step = 100;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_ts_downsample_run(&db, &spec, 100, 100, &gen));

    /* The audit store is off-limits as source and as destination. */
    {
        cdb_ts_downsample_spec a = spec;
        a.src_store = CDB_AUDIT_STORE_ID;
        TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_ts_downsample_run(&db, &a, 0, 100, &gen));
        a = spec;
        a.dst_store = CDB_AUDIT_STORE_ID;
        TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_ts_downsample_run(&db, &a, 0, 100, &gen));
    }

    /* describe failure: a source series that does not exist. */
    {
        cdb_ts_downsample_spec a = spec;
        a.src_series = src + 999u;
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_ts_downsample_run(&db, &a, 0, 100, &gen));
    }

    /* A range with no source points: zero generated, still OK. */
    gen = 123;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_downsample_run(&db, &spec, 100000, 200000, &gen));
    TEST_ASSERT_EQUAL_size_t(0, gen);

    (void)dst;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cov_create_and_def_errors);
    RUN_TEST(test_cov_append_errors);
    RUN_TEST(test_cov_range_edges);
    RUN_TEST(test_cov_retention);
    RUN_TEST(test_cov_downsample_numeric);
    RUN_TEST(test_cov_downsample_first_last);
    RUN_TEST(test_cov_downsample_errors);
    return UNITY_END();
}
