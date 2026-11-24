/* Audit follow-up #52: per-model live cursors / executor scan materialization.
 *
 * Drives the REAL executor scan path (cdb_exec_open + cdb_exec_next over a bare
 * Scan node) against a live database, for the three models the scan used to get
 * wrong:
 *   AC1/AC7 VECTOR -- every live entry comes back with its materialized
 *           $vector value (byte-exact with cdb_vec_get), not an empty record;
 *           a deleted entry is excluded.
 *   AC2/AC3 TIME-SERIES -- a real record per live series (the series key bytes,
 *           via the reused #41 cdb_ts_list enumeration), not a bare ID row.
 *   AC4/AC5 LINK -- a real serialized link record per LIVE link, with a
 *           tombstoned/removed-end link excluded (the #40/#60 live filter,
 *           reused through cdb_link_scan), not a bare ID row.
 *   AC6     Open store -- for a store whose catalog next_entry_id lags the
 *           committed live entries (inserted + committed but not reconciled),
 *           the scan's live-entry count is the true live count, not a count
 *           bounded by next_entry_id.
 *
 * Red against main: the VECTOR branch force-zeroed the record (no $vector) and
 * the TS/LINK branches fell through to a bare store_id/entry_id row, and all
 * three bounded the walk by next_entry_id (which lags an open store). These
 * assertions only use public, pre-existing symbols (cdb_exec_*, the model
 * create/insert APIs, cdb_query_write_scan), so the test builds and runs on the
 * merge-base and is red there; it is green after the cdb_exec.c wiring.
 *
 * Hermetic: an in-memory fault environment, fixed inputs, no clock or network.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_doc.h"
#include "cdb_endian.h"
#include "cdb_exec.h"
#include "cdb_faultenv.h"
#include "cdb_link.h"
#include "cdb_query.h"
#include "cdb_ts.h"
#include "cdb_vec.h"

#define FCAP (1024u * 1024u)
#define PAGE_LOG2 10u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define DIMS 4u

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 4096u];
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
static uint8_t doc_stage[4096];
static uint8_t idx_stage[16u * 1024u];
static uint8_t vec_buffers[3u * PAGE];
static uint8_t ts_buffers[3u * PAGE];
static uint8_t ts_work[(CDB_TS_BLOCK_MAX_POINTS + 1u) * sizeof(cdb_ts_point)];
static cdb_db_config cfg;
static cdb_db db;

static uint8_t scratch[256u * 1024u];
static uint8_t wire[2048];
static cdb_exec_cursor cur;

static void init_env(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 4096;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
}

void setUp(void)
{
    cdb_header h;

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
    cfg.doc_stage = doc_stage;
    cfg.doc_stage_size = sizeof doc_stage;
    cfg.idx_stage = idx_stage;
    cfg.idx_stage_size = sizeof idx_stage;
    cfg.vec_buffers = vec_buffers;
    cfg.ts_buffers = ts_buffers;
    cfg.ts_work = ts_work;
    cfg.ts_work_size = sizeof ts_work;
    cfg.durability = CDB_DURABILITY_FULL;

    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x52, sizeof h.db_id);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "f52", &cfg, &h));
}

void tearDown(void)
{
    cdb_db_close(&db);
}

static void begin(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
}
static void commit(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
}

/* Opens a bare Scan over store_name as the executor root. */
static void open_scan(const char *store_name)
{
    cdb_query_writer qw;
    cdb_query_writer_init(&qw, wire, sizeof wire);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, store_name, strlen(store_name)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, &db, wire, cdb_query_writer_len(&qw), NULL, 0,
                                                scratch, sizeof scratch));
}

static int next_row(cdb_exec_row *row)
{
    int has = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, row, &has));
    return has;
}

/* ------------------------------------------------------------ vectors */

static uint64_t VCOLL;

static size_t encode_vec(uint8_t *buf, size_t cap, const float *f)
{
    cdb_value_writer w;
    cdb_value_writer_init(&w, buf, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_vector(&w, CDB_VEC_F32, DIMS, f);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    return cdb_value_writer_len(&w);
}

static uint64_t insert_vec(const float *f)
{
    uint8_t b[128];
    size_t n = encode_vec(b, sizeof b, f);
    uint64_t e = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_insert(&db, VCOLL, b, n, 0, 0, &e));
    return e;
}

/* A 4-D collection; the caller inserts the vectors inside one transaction. */
static void make_vec_store(void)
{
    cdb_vec_config c;
    memset(&c, 0, sizeof c);
    c.elem = CDB_VEC_F32;
    c.dims = DIMS;
    c.measure = CDB_VEC_EUCLIDEAN;
    c.model = "m";
    c.model_len = 1;
    c.model_version = "1";
    c.model_version_len = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_create(&db, "emb", 3, &c, &VCOLL));
}

/* AC1/AC6/AC7: the scan yields every LIVE vector entry with its $vector value
 * (byte-exact with cdb_vec_get), the deleted one excluded, for an OPEN store
 * (committed but not reconciled, so next_entry_id lags). */
static void test_vector_scan_materializes_vector(void)
{
    static const float v1[DIMS] = {1.0f, 0.0f, 0.0f, 0.0f};
    static const float v2[DIMS] = {0.0f, 1.0f, 0.0f, 0.0f};
    static const float v3[DIMS] = {0.0f, 0.0f, 1.0f, 0.0f};
    static const float v4[DIMS] = {7.0f, 8.0f, 9.0f, 10.0f};
    uint64_t e1, e2, e3, e4;
    cdb_exec_row row;
    size_t n = 0;
    int saw1 = 0, saw2 = 0, saw3 = 0;

    make_vec_store();
    begin();
    e1 = insert_vec(v1);
    e2 = insert_vec(v2);
    e3 = insert_vec(v3);
    e4 = insert_vec(v4);
    commit();
    /* Delete one: it must never appear (live-only). */
    begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_delete(&db, VCOLL, e4));
    commit();
    /* No reconcile: the store stays open, next_entry_id lags the live set. */

    open_scan("emb");
    while (next_row(&row)) {
        uint8_t want[128];
        size_t wlen = 0;
        uint64_t ss, se;
        cdb_value val;

        TEST_ASSERT_TRUE(n < 8);
        TEST_ASSERT_EQUAL_UINT32(CDB_MODEL_VECTOR, row.model);
        TEST_ASSERT_TRUE_MESSAGE(row.entry_id != e4, "deleted vector appeared");

        /* $vector is materialized: a non-empty record that decodes to the
         * stored vector value and is byte-exact with cdb_vec_get. */
        TEST_ASSERT_NOT_NULL_MESSAGE(row.record_data, "vector row has no $vector");
        TEST_ASSERT_TRUE(row.record_len > 0);
        TEST_ASSERT_EQUAL_INT(
            CDB_OK, cdb_value_read(row.record_data, row.record_len, CDB_ORDER_LITTLE, &val));
        TEST_ASSERT_EQUAL_INT(CDB_TYPE_VECTOR, val.type);
        TEST_ASSERT_EQUAL_UINT64(DIMS, val.as.vector.dims);

        TEST_ASSERT_EQUAL_INT(
            CDB_OK, cdb_vec_get(&db, VCOLL, row.entry_id, want, sizeof want, &wlen, &ss, &se));
        TEST_ASSERT_EQUAL_size_t(wlen, row.record_len);
        TEST_ASSERT_EQUAL_MEMORY(want, row.record_data, wlen);

        saw1 |= (row.entry_id == e1);
        saw2 |= (row.entry_id == e2);
        saw3 |= (row.entry_id == e3);
        n++;
    }
    cdb_exec_close(&cur);

    /* AC6: the live count is exactly the three live entries, not bounded by
     * the block-claimed next_entry_id. */
    TEST_ASSERT_EQUAL_size_t_MESSAGE(3, n, "open-store vector live count is wrong");
    TEST_ASSERT_TRUE(saw1 && saw2 && saw3);
}

/* ------------------------------------------------------------ time series */

static cdb_ts_def def_int(void)
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

static uint64_t make_series(uint64_t store, const char *name)
{
    cdb_ts_def d = def_int();
    uint64_t s = 0;
    int created = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_ts_series(&db, store, name, strlen(name), NULL, 0, &d, &s, &created));
    TEST_ASSERT_TRUE(created);
    return s;
}

/* The series key bytes cdb_ts_list reports for a given series ID. */
static size_t ref_series_key(uint64_t store, uint64_t series, uint8_t *out, size_t cap)
{
    cdb_ts_entry ents[8];
    uint8_t buf[512], token[512];
    size_t n = 0, token_len = 0, i;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_list(&db, store, token, sizeof token, &token_len, ents, 8,
                                              buf, sizeof buf, &n));
    for (i = 0; i < n; i++) {
        if (ents[i].series == series) {
            TEST_ASSERT_TRUE(ents[i].len <= cap);
            memcpy(out, buf + ents[i].off, ents[i].len);
            return ents[i].len;
        }
    }
    TEST_FAIL_MESSAGE("series not found in cdb_ts_list");
    return 0;
}

/* AC2/AC3/AC6: the scan yields a real record per live series (the series key
 * bytes, from the reused cdb_ts_list), not a bare ID, over an open store. */
static void test_ts_scan_real_records(void)
{
    uint64_t store, a, b, g;
    cdb_exec_row row;
    size_t n = 0;
    int saw_a = 0, saw_b = 0, saw_g = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "metrics", 7, CDB_TS_LATE_ACCEPT, 0, &store));
    begin();
    a = make_series(store, "alpha");
    b = make_series(store, "beta");
    g = make_series(store, "gamma");
    commit();
    /* No reconcile: open store, next_entry_id lags the committed series. */

    open_scan("metrics");
    while (next_row(&row)) {
        uint8_t want[512];
        size_t wlen;

        TEST_ASSERT_TRUE(n < 8);
        TEST_ASSERT_EQUAL_UINT32(CDB_MODEL_TIME_SERIES, row.model);
        /* A real record, not a bare ID row. */
        TEST_ASSERT_NOT_NULL_MESSAGE(row.record_data, "time-series row has no record");
        TEST_ASSERT_TRUE(row.record_len > 0);

        wlen = ref_series_key(store, row.entry_id, want, sizeof want);
        TEST_ASSERT_EQUAL_size_t(wlen, row.record_len);
        TEST_ASSERT_EQUAL_MEMORY(want, row.record_data, wlen);

        saw_a |= (row.entry_id == a);
        saw_b |= (row.entry_id == b);
        saw_g |= (row.entry_id == g);
        n++;
    }
    cdb_exec_close(&cur);

    TEST_ASSERT_EQUAL_size_t_MESSAGE(3, n, "open-store time-series live count is wrong");
    TEST_ASSERT_TRUE(saw_a && saw_b && saw_g);
}

/* ------------------------------------------------------------ links */

static uint64_t LPOOL;

static uint64_t new_doc(void)
{
    uint8_t b[32];
    cdb_value_writer w;
    uint64_t e = 0;
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_string(&w, "x", 1);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_doc_insert(&db, LPOOL, NULL, 0, b, cdb_value_writer_len(&w), &e));
    return e;
}

/* Decodes the target entry ID from a serialized LINK scan record: type (8),
 * source ref (store 8, entry 8 ...). The target ref starts at 8 + 28 = 36,
 * its entry ID 8 bytes in. */
static uint64_t rec_target_entry(const uint8_t *rec)
{
    return cdb_load_u64(rec + 36u + 8u, CDB_ORDER_BIG);
}

static uint64_t rec_source_entry(const uint8_t *rec)
{
    return cdb_load_u64(rec + 8u + 8u, CDB_ORDER_BIG);
}

/* AC4/AC5/AC7: the scan yields a real serialized link record per LIVE link, a
 * tombstoned (deleted-end) link excluded (the reused #40/#60 filter). */
static void test_link_scan_real_records_live_only(void)
{
    uint64_t t = 0, a, b, c;
    cdb_exec_row row;
    size_t n = 0;
    int saw_ac = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "notes", 5, CDB_MODEL_DOCUMENT, &LPOOL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_define_type(&db, "cites", 5, CDB_CARD_N_M, 1,
                                                       CDB_LINK_ON_DELETE_TOMBSTONE, &t));
    begin();
    a = new_doc();
    b = new_doc();
    c = new_doc();
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_link_add(&db, t, cdb_ref_entry(LPOOL, a), cdb_ref_entry(LPOOL, b), 1.0f, 100));
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_link_add(&db, t, cdb_ref_entry(LPOOL, a), cdb_ref_entry(LPOOL, c), 1.0f, 100));
    commit();
    /* Delete b: a->b is tombstoned (TARGET_GONE); a->c stays live. */
    begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_delete(&db, LPOOL, b));
    commit();

    open_scan(CDB_LINK_STORE_NAME);
    while (next_row(&row)) {
        TEST_ASSERT_TRUE(n < 8);
        TEST_ASSERT_EQUAL_UINT32(CDB_MODEL_LINK, row.model);
        /* A real serialized link record, not a bare ID row. */
        TEST_ASSERT_NOT_NULL_MESSAGE(row.record_data, "link row has no record");
        TEST_ASSERT_TRUE(row.record_len > 0);
        TEST_ASSERT_EQUAL_UINT64(a, rec_source_entry(row.record_data));
        /* The only live link is a->c; a->b must never appear. */
        TEST_ASSERT_TRUE_MESSAGE(rec_target_entry(row.record_data) != b,
                                 "tombstoned link appeared in scan");
        saw_ac |= (rec_target_entry(row.record_data) == c);
        n++;
    }
    cdb_exec_close(&cur);

    TEST_ASSERT_EQUAL_size_t_MESSAGE(1, n, "link scan live count is wrong");
    TEST_ASSERT_TRUE(saw_ac);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_vector_scan_materializes_vector);
    RUN_TEST(test_ts_scan_real_records);
    RUN_TEST(test_link_scan_real_records_live_only);
    return UNITY_END();
}
