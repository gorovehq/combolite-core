/* Second branch-coverage set for cdb_table (agent-authored, increment 3 of the
 * #18 coverage ratchet). Complements tests/test_table_cov.c (argument/schema
 * validation) and tests/test_table.c (behaviour) by exercising reachable
 * encode/decode and success branches those suites leave cold:
 *   - insert -> get round-trips that read back every indexable value type,
 *     driving key_part() and write_as() per type;
 *   - secondary-index build over existing rows (unique + non-unique) and the
 *     unique-duplicate CDB_E_EXISTS path (build-time and insert-time);
 *   - scan over a secondary index with lower/upper array bounds and cursor
 *     continuation, plus the CDB_TABLE_NO_INDEX entry-order path;
 *   - replace / update default-and-base semantics;
 *   - widen int->decimal and f32->f64 with read-through conversion;
 *   - add_column-with-default (row reads the default), drop_column and
 *     rename_column success reflected by describe/column_id;
 *   - live_in_tx, oversized-row and oversized-key CDB_E_OVERFLOW, and nib_moved
 *     on a row table.
 *
 * Plus explicit negative / abuse paths (wrong-type row -> CDB_E_SCHEMA, a
 * not-null column left null -> CDB_E_SCHEMA, duplicate primary key and taken
 * table name -> CDB_E_EXISTS, the index-count limit -> CDB_E_INVALID_ARG,
 * widen of a column with a default -> CDB_E_INVALID_ARG), each asserting the
 * returned typed status without dereferencing a maybe-null result. No src
 * change; characterization only. Column-oriented tables are covered separately
 * by tests/test_coltable.c (they need cdb_db_config.col_work); this harness is
 * row-oriented, so cdb_table.c's column error-return branches and its defensive
 * catalog-CORRUPT branches (reachable only via fault injection) are out of
 * scope here. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_doc.h"
#include "cdb_faultenv.h"
#include "cdb_page.h"
#include "cdb_table.h"

#define FCAP (1024u * 1024u)
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
static uint8_t doc_stage[4096];
static uint8_t idx_stage[16u * 1024u];
static uint8_t table_buffers[4u * PAGE];
static cdb_db_config cfg;
static cdb_db db;

static void init_env(void)
{
    cdb_faultenv_config c;
    memset(&c, 0, sizeof c);
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 8192;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
}

void setUp(void)
{
    const char *cap = NULL;
    init_env();
    memset(&cfg, 0, sizeof cfg);
    cap = getenv("CDB_TEST_MAX_OPEN");
    cfg.max_open = cap != NULL ? (unsigned)atoi(cap) : 0;
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
    cfg.table_buffers = table_buffers;
    cfg.durability = CDB_DURABILITY_FULL;
    TEST_ASSERT_EQUAL_size_t(cdb_table_buffers_size(PAGE, 0), sizeof table_buffers);
}

void tearDown(void) {}

static cdb_status open_db(void)
{
    cdb_header h;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x5C, sizeof h.db_id);
    return cdb_db_open(&db, &env, "r", &cfg, &h);
}

static void begin(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL)); }
static void commit(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db)); }

/* ------------------------------------------------------------ encoders */

typedef struct enc {
    uint8_t b[512];
    size_t n;
    cdb_value_writer w;
} enc;

static void obj_begin(enc *e)
{
    cdb_value_writer_init(&e->w, e->b, sizeof e->b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&e->w);
}

static void arr_begin(enc *e)
{
    cdb_value_writer_init(&e->w, e->b, sizeof e->b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_array(&e->w);
}

static void obj_end(enc *e)
{
    cdb_value_end_object(&e->w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, e->w.error);
    e->n = cdb_value_writer_len(&e->w);
}

static void arr_end(enc *e)
{
    cdb_value_end_array(&e->w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, e->w.error);
    e->n = cdb_value_writer_len(&e->w);
}

/* ------------------------------------------------------------ wide table */

/* A table with one column of each indexable type, so index-key building and
 * row projection exercise every key_part()/write_as() arm.
 *   0 id   int (primary key)   1 flag bool          2 ratio f32
 *   3 wide f64                  4 when timestamp     5 who ref
 *   6 blob binary               7 note string                        */
static uint64_t W, C_ID, C_FLAG, C_RATIO, C_WIDE, C_WHEN, C_WHO, C_BLOB, C_NOTE;

static cdb_status make_wide(void)
{
    cdb_table_column cols[8];
    unsigned pk = 0;
    cdb_table_def def;
    cdb_status s = CDB_OK;
    memset(cols, 0, sizeof cols);
    cols[0].name = "id";
    cols[0].name_len = 2;
    cols[0].type = CDB_TYPE_INT;
    cols[1].name = "flag";
    cols[1].name_len = 4;
    cols[1].type = CDB_TYPE_BOOL;
    cols[2].name = "ratio";
    cols[2].name_len = 5;
    cols[2].type = CDB_TYPE_F32;
    cols[3].name = "wide";
    cols[3].name_len = 4;
    cols[3].type = CDB_TYPE_F64;
    cols[4].name = "when";
    cols[4].name_len = 4;
    cols[4].type = CDB_TYPE_TIMESTAMP;
    cols[5].name = "who";
    cols[5].name_len = 3;
    cols[5].type = CDB_TYPE_REF;
    cols[6].name = "blob";
    cols[6].name_len = 4;
    cols[6].type = CDB_TYPE_BINARY;
    cols[7].name = "note";
    cols[7].name_len = 4;
    cols[7].type = CDB_TYPE_STRING;
    memset(&def, 0, sizeof def);
    def.columns = cols;
    def.ncolumns = 8;
    def.primary_key = &pk;
    def.npk = 1;
    if ((s = cdb_table_create(&db, "wide", 4, &def, &W)) != CDB_OK)
        return s;
    if ((s = cdb_table_column_id(&db, W, "id", 2, &C_ID)) != CDB_OK
        || (s = cdb_table_column_id(&db, W, "flag", 4, &C_FLAG)) != CDB_OK
        || (s = cdb_table_column_id(&db, W, "ratio", 5, &C_RATIO)) != CDB_OK
        || (s = cdb_table_column_id(&db, W, "wide", 4, &C_WIDE)) != CDB_OK
        || (s = cdb_table_column_id(&db, W, "when", 4, &C_WHEN)) != CDB_OK
        || (s = cdb_table_column_id(&db, W, "who", 3, &C_WHO)) != CDB_OK
        || (s = cdb_table_column_id(&db, W, "blob", 4, &C_BLOB)) != CDB_OK)
        return s;
    return cdb_table_column_id(&db, W, "note", 4, &C_NOTE);
}

static cdb_status insert_wide(int64_t id, int flag, float ratio, double wide, int64_t when,
                              uint64_t who_store, uint64_t who_entry, const char *blob, const char *note,
                              uint64_t *entry)
{
    enc e;
    obj_begin(&e);
    cdb_value_field(&e.w, C_ID);
    cdb_value_write_int(&e.w, id);
    cdb_value_field(&e.w, C_FLAG);
    cdb_value_write_bool(&e.w, flag);
    cdb_value_field(&e.w, C_RATIO);
    cdb_value_write_f32(&e.w, ratio);
    cdb_value_field(&e.w, C_WIDE);
    cdb_value_write_f64(&e.w, wide);
    cdb_value_field(&e.w, C_WHEN);
    cdb_value_write_timestamp(&e.w, CDB_TS_MILLIS, when);
    cdb_value_field(&e.w, C_WHO);
    cdb_value_write_ref(&e.w, who_store, who_entry);
    cdb_value_field(&e.w, C_BLOB);
    cdb_value_write_binary(&e.w, blob, strlen(blob));
    cdb_value_field(&e.w, C_NOTE);
    cdb_value_write_string(&e.w, note, strlen(note));
    obj_end(&e);
    return cdb_table_insert(&db, W, e.b, e.n, entry);
}

/* ------------------------------------------------------------ tests */

/* Insert rows with every indexable type, build a secondary index over each
 * type (row_key -> key_part per type), then read a row back and assert each
 * field (project -> row_value -> write_as copy). find and scan then exercise
 * array_key -> key_part for the primary and the typed secondaries. */
static void test_typed_roundtrip_index_find_scan(void)
{
    uint64_t e1 = 0, e2 = 0, got = 0;
    uint32_t ix_flag = 0, ix_ratio = 0, ix_wide = 0, ix_when = 0, ix_who = 0, ix_blob = 0, ix_note = 0;
    uint8_t out[PAGE];
    size_t olen = 0;
    cdb_value obj, v;
    int found = 0;
    enc key;
    uint64_t pk_fields[1];
    uint64_t sec_fields[1];

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, make_wide());

    begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK,
        insert_wide(1, 1, 1.5f, 2.5, 1000, 7, 70, "aa", "first", &e1));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
        insert_wide(2, 0, 3.25f, 4.75, 2000, 8, 80, "bb", "second", &e2));
    commit();

    /* Build one secondary index over each non-key indexable column; each build
     * walks the two committed rows and keys them (key_part per type). pk is
     * index 0, so these are seven secondaries -> exactly CDB_TABLE_MAX_INDEXES. */
    sec_fields[0] = C_FLAG;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create_index(&db, W, sec_fields, 1, 0, &ix_flag));
    sec_fields[0] = C_RATIO;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create_index(&db, W, sec_fields, 1, 0, &ix_ratio));
    sec_fields[0] = C_WIDE;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create_index(&db, W, sec_fields, 1, 0, &ix_wide));
    sec_fields[0] = C_WHEN;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create_index(&db, W, sec_fields, 1, 0, &ix_when));
    sec_fields[0] = C_WHO;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create_index(&db, W, sec_fields, 1, 0, &ix_who));
    sec_fields[0] = C_BLOB;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create_index(&db, W, sec_fields, 1, 1, &ix_blob));
    sec_fields[0] = C_NOTE;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create_index(&db, W, sec_fields, 1, 1, &ix_note));

    /* An eighth secondary would exceed CDB_TABLE_MAX_INDEXES (abuse path). */
    {
        uint32_t ix_over = 0;
        uint64_t again = C_FLAG;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
            cdb_table_create_index(&db, W, &again, 1, 0, &ix_over));
    }

    /* Read row 1 back through the current columns and assert every typed value
     * (project + write_as copy). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_get(&db, W, e1, out, sizeof out, &olen));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_read(out, olen, CDB_ORDER_LITTLE, &obj));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_OBJECT, obj.type);
    found = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, CDB_ORDER_LITTLE, C_ID, &v, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT64(1, v.as.i64);
    found = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, CDB_ORDER_LITTLE, C_FLAG, &v, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT(1, v.as.boolean);
    found = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, CDB_ORDER_LITTLE, C_RATIO, &v, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_FLOAT(1.5f, v.as.f32);
    found = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, CDB_ORDER_LITTLE, C_WIDE, &v, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_DOUBLE(2.5, v.as.f64);
    found = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, CDB_ORDER_LITTLE, C_WHEN, &v, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT64(1000, v.as.ts.ticks);
    found = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, CDB_ORDER_LITTLE, C_WHO, &v, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_UINT64(7, v.as.ref.store_id);
    TEST_ASSERT_EQUAL_UINT64(70, v.as.ref.entry_id);
    found = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, CDB_ORDER_LITTLE, C_BLOB, &v, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_size_t(2, v.payload_len);

    /* find by primary key (array_key -> key_part int). */
    arr_begin(&key);
    cdb_value_write_int(&key.w, 2);
    arr_end(&key);
    found = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_find(&db, W, key.b, key.n, &got, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_UINT64(e2, got);
    (void)pk_fields;

    /* scan each typed secondary with lower/upper array bounds (array_key ->
     * key_part per type). */
    {
        uint64_t entries[8];
        size_t n = 0;
        cdb_table_cursor cur;
        enc lo, hi;

        /* bool */
        memset(&cur, 0, sizeof cur);
        arr_begin(&lo);
        cdb_value_write_bool(&lo.w, 0);
        arr_end(&lo);
        arr_begin(&hi);
        cdb_value_write_bool(&hi.w, 1);
        arr_end(&hi);
        n = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_table_scan(&db, W, ix_flag, lo.b, lo.n, hi.b, hi.n, &cur, entries, 8, &n));
        TEST_ASSERT_EQUAL_size_t(2, n);

        /* f32 */
        memset(&cur, 0, sizeof cur);
        arr_begin(&lo);
        cdb_value_write_f32(&lo.w, 0.0f);
        arr_end(&lo);
        arr_begin(&hi);
        cdb_value_write_f32(&hi.w, 100.0f);
        arr_end(&hi);
        n = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_table_scan(&db, W, ix_ratio, lo.b, lo.n, hi.b, hi.n, &cur, entries, 8, &n));
        TEST_ASSERT_EQUAL_size_t(2, n);

        /* f64 */
        memset(&cur, 0, sizeof cur);
        arr_begin(&lo);
        cdb_value_write_f64(&lo.w, 0.0);
        arr_end(&lo);
        n = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_table_scan(&db, W, ix_wide, lo.b, lo.n, NULL, 0, &cur, entries, 8, &n));
        TEST_ASSERT_EQUAL_size_t(2, n);

        /* timestamp */
        memset(&cur, 0, sizeof cur);
        arr_begin(&lo);
        cdb_value_write_timestamp(&lo.w, CDB_TS_MILLIS, 0);
        arr_end(&lo);
        arr_begin(&hi);
        cdb_value_write_timestamp(&hi.w, CDB_TS_MILLIS, 5000);
        arr_end(&hi);
        n = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_table_scan(&db, W, ix_when, lo.b, lo.n, hi.b, hi.n, &cur, entries, 8, &n));
        TEST_ASSERT_EQUAL_size_t(2, n);

        /* ref */
        memset(&cur, 0, sizeof cur);
        arr_begin(&lo);
        cdb_value_write_ref(&lo.w, 0, 0);
        arr_end(&lo);
        n = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_table_scan(&db, W, ix_who, lo.b, lo.n, NULL, 0, &cur, entries, 8, &n));
        TEST_ASSERT_EQUAL_size_t(2, n);

        /* binary */
        memset(&cur, 0, sizeof cur);
        arr_begin(&lo);
        cdb_value_write_binary(&lo.w, "a", 1);
        arr_end(&lo);
        n = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_table_scan(&db, W, ix_blob, lo.b, lo.n, NULL, 0, &cur, entries, 8, &n));
        TEST_ASSERT_TRUE(n >= 1);

        /* string */
        memset(&cur, 0, sizeof cur);
        arr_begin(&lo);
        cdb_value_write_string(&lo.w, "a", 1);
        arr_end(&lo);
        n = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_table_scan(&db, W, ix_note, lo.b, lo.n, NULL, 0, &cur, entries, 8, &n));
        TEST_ASSERT_EQUAL_size_t(2, n);

        /* entry-order scan (CDB_TABLE_NO_INDEX), one at a time via the cursor. */
        memset(&cur, 0, sizeof cur);
        n = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_table_scan(&db, W, CDB_TABLE_NO_INDEX, NULL, 0, NULL, 0, &cur, entries, 1, &n));
        TEST_ASSERT_EQUAL_size_t(1, n);
        n = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_table_scan(&db, W, CDB_TABLE_NO_INDEX, NULL, 0, NULL, 0, &cur, entries, 1, &n));
        TEST_ASSERT_EQUAL_size_t(1, n);
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* A unique secondary index rejects a second committed row with the same key
 * (check_keys committed-duplicate path), and an index key that is too large is
 * rejected with CDB_E_OVERFLOW (row_key/key_part overflow path). */
static void test_unique_secondary_and_key_overflow(void)
{
    uint64_t store = 0, e = 0, idf = 0, tagf = 0;
    uint32_t ix = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    {
        cdb_table_column cols[2];
        unsigned pk = 0;
        cdb_table_def def;
        memset(cols, 0, sizeof cols);
        cols[0].name = "id";
        cols[0].name_len = 2;
        cols[0].type = CDB_TYPE_INT;
        cols[1].name = "tag";
        cols[1].name_len = 3;
        cols[1].type = CDB_TYPE_STRING;
        memset(&def, 0, sizeof def);
        def.columns = cols;
        def.ncolumns = 2;
        def.primary_key = &pk;
        def.npk = 1;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create(&db, "tags", 4, &def, &store));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, store, "id", 2, &idf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, store, "tag", 3, &tagf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create_index(&db, store, &tagf, 1, 1, &ix));

    /* Commit one row, then a separate transaction cannot insert a duplicate. */
    begin();
    {
        enc r;
        obj_begin(&r);
        cdb_value_field(&r.w, idf);
        cdb_value_write_int(&r.w, 1);
        cdb_value_field(&r.w, tagf);
        cdb_value_write_string(&r.w, "unique", 6);
        obj_end(&r);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_insert(&db, store, r.b, r.n, &e));
    }
    commit();

    begin();
    {
        enc r;
        uint64_t dup = 0;
        obj_begin(&r);
        cdb_value_field(&r.w, idf);
        cdb_value_write_int(&r.w, 2);
        cdb_value_field(&r.w, tagf);
        cdb_value_write_string(&r.w, "unique", 6); /* same key */
        obj_end(&r);
        TEST_ASSERT_EQUAL_INT(CDB_E_EXISTS, cdb_table_insert(&db, store, r.b, r.n, &dup));
    }

    /* An index key larger than CDB_TABLE_KEY_MAX is rejected as OVERFLOW. The
     * row body still fits a page, so the overflow is the key, not the row.
     * Built in a dedicated writer since the long string exceeds the small enc. */
    {
        static uint8_t row_buf[2048];
        static char longtag[768];
        cdb_value_writer w;
        uint64_t big = 0;
        size_t rlen = 0;
        memset(longtag, 'z', sizeof longtag - 1u);
        longtag[sizeof longtag - 1u] = '\0';
        cdb_value_writer_init(&w, row_buf, sizeof row_buf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        cdb_value_begin_object(&w);
        cdb_value_field(&w, idf);
        cdb_value_write_int(&w, 3);
        cdb_value_field(&w, tagf);
        cdb_value_write_string(&w, longtag, strlen(longtag));
        cdb_value_end_object(&w);
        TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
        rlen = cdb_value_writer_len(&w);
        TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_table_insert(&db, store, row_buf, rlen, &big));
    }
    commit();

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* A plain people-style table for replace/update/widen/schema change cases. */
static uint64_t T;
static uint64_t F_ID, F_NAME, F_SCORE, F_NOTE;

static cdb_status make_people(void)
{
    static uint8_t seven[4];
    cdb_value_writer dw;
    cdb_table_column cols[4];
    unsigned pk = 0;
    cdb_table_def def;
    cdb_status s = CDB_OK;
    cdb_value_writer_init(&dw, seven, sizeof seven, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_int(&dw, 7);
    memset(cols, 0, sizeof cols);
    cols[0].name = "id";
    cols[0].name_len = 2;
    cols[0].type = CDB_TYPE_INT;
    cols[1].name = "name";
    cols[1].name_len = 4;
    cols[1].type = CDB_TYPE_STRING;
    cols[1].not_null = 1;
    cols[2].name = "score";
    cols[2].name_len = 5;
    cols[2].type = CDB_TYPE_INT;
    cols[2].default_value = seven;
    cols[2].default_len = cdb_value_writer_len(&dw);
    cols[3].name = "note";
    cols[3].name_len = 4;
    cols[3].type = CDB_TYPE_STRING;
    memset(&def, 0, sizeof def);
    def.columns = cols;
    def.ncolumns = 4;
    def.primary_key = &pk;
    def.npk = 1;
    if ((s = cdb_table_create(&db, "people", 6, &def, &T)) != CDB_OK)
        return s;
    if ((s = cdb_table_column_id(&db, T, "id", 2, &F_ID)) != CDB_OK
        || (s = cdb_table_column_id(&db, T, "name", 4, &F_NAME)) != CDB_OK
        || (s = cdb_table_column_id(&db, T, "score", 5, &F_SCORE)) != CDB_OK)
        return s;
    return cdb_table_column_id(&db, T, "note", 4, &F_NOTE);
}

static cdb_status insert_person(int64_t id, const char *name, int64_t score, uint64_t *entry)
{
    enc e;
    obj_begin(&e);
    cdb_value_field(&e.w, F_ID);
    cdb_value_write_int(&e.w, id);
    cdb_value_field(&e.w, F_NAME);
    cdb_value_write_string(&e.w, name, strlen(name));
    cdb_value_field(&e.w, F_SCORE);
    cdb_value_write_int(&e.w, score);
    obj_end(&e);
    return cdb_table_insert(&db, T, e.b, e.n, entry);
}

static int64_t read_int(uint64_t entry, uint64_t field, int *found)
{
    uint8_t out[PAGE];
    size_t len = 0;
    cdb_value obj, v;
    *found = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_get(&db, T, entry, out, sizeof out, &len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_read(out, len, CDB_ORDER_LITTLE, &obj));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, CDB_ORDER_LITTLE, field, &v, found));
    if (!*found)
        return 0;
    return v.as.i64;
}

/* replace keeps only the columns the new row names (missing become default/
 * null); update changes only the columns its object names. */
static void test_replace_update_semantics(void)
{
    uint64_t e = 0;
    int found = 0;
    int64_t sc = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, make_people());

    /* Reads see committed rows only, so each change is committed before it is
     * read back. */
    begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, insert_person(1, "ada", 3, &e));
    commit();

    /* update: raise only the score; name/id stay. */
    begin();
    {
        enc u;
        obj_begin(&u);
        cdb_value_field(&u.w, F_SCORE);
        cdb_value_write_int(&u.w, 42);
        obj_end(&u);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_update(&db, T, e, u.b, u.n));
    }
    commit();
    sc = read_int(e, F_SCORE, &found);
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT64(42, sc);
    sc = read_int(e, F_ID, &found); /* id untouched by the partial update */
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT64(1, sc);

    /* update that sets a column null (score -> null) removes it from the row. */
    begin();
    {
        enc u;
        obj_begin(&u);
        cdb_value_field(&u.w, F_SCORE);
        cdb_value_write_null(&u.w);
        obj_end(&u);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_update(&db, T, e, u.b, u.n));
    }
    commit();
    (void)read_int(e, F_SCORE, &found);
    TEST_ASSERT_FALSE(found);

    /* replace with only id+name: score is NOT defaulted on replace, so it is
     * absent; name is required (not-null). */
    begin();
    {
        enc r;
        obj_begin(&r);
        cdb_value_field(&r.w, F_ID);
        cdb_value_write_int(&r.w, 1);
        cdb_value_field(&r.w, F_NAME);
        cdb_value_write_string(&r.w, "ada2", 4);
        obj_end(&r);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_replace(&db, T, e, r.b, r.n));
    }

    /* abuse: replace leaving the not-null name out -> CDB_E_SCHEMA. */
    {
        enc r;
        obj_begin(&r);
        cdb_value_field(&r.w, F_ID);
        cdb_value_write_int(&r.w, 1);
        obj_end(&r);
        TEST_ASSERT_EQUAL_INT(CDB_E_SCHEMA, cdb_table_replace(&db, T, e, r.b, r.n));
    }
    commit();
    (void)read_int(e, F_SCORE, &found);
    TEST_ASSERT_FALSE(found);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* widen int->decimal and f32->f64, then read the converted value through the
 * current columns (write_as widening arms). */
static void test_widen_read_through(void)
{
    uint64_t store = 0, e = 0, nid = 0, fid = 0;
    uint8_t out[PAGE];
    size_t olen = 0;
    cdb_value obj, v;
    int found = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    /* id int (pk), n int (plain), r f32 (plain). */
    {
        cdb_table_column cols[3];
        unsigned pk = 0;
        cdb_table_def def;
        memset(cols, 0, sizeof cols);
        cols[0].name = "id";
        cols[0].name_len = 2;
        cols[0].type = CDB_TYPE_INT;
        cols[1].name = "n";
        cols[1].name_len = 1;
        cols[1].type = CDB_TYPE_INT;
        cols[2].name = "r";
        cols[2].name_len = 1;
        cols[2].type = CDB_TYPE_F32;
        memset(&def, 0, sizeof def);
        def.columns = cols;
        def.ncolumns = 3;
        def.primary_key = &pk;
        def.npk = 1;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create(&db, "nums", 4, &def, &store));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, store, "n", 1, &nid));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, store, "r", 1, &fid));

    begin();
    {
        enc row;
        uint64_t idf = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, store, "id", 2, &idf));
        obj_begin(&row);
        cdb_value_field(&row.w, idf);
        cdb_value_write_int(&row.w, 1);
        cdb_value_field(&row.w, nid);
        cdb_value_write_int(&row.w, 9);
        cdb_value_field(&row.w, fid);
        cdb_value_write_f32(&row.w, 2.5f);
        obj_end(&row);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_insert(&db, store, row.b, row.n, &e));
    }
    commit();

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_widen_column(&db, store, nid, CDB_TYPE_DECIMAL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_widen_column(&db, store, fid, CDB_TYPE_F64));

    /* The stored int now reads as decimal, the stored f32 as f64. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_get(&db, store, e, out, sizeof out, &olen));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_read(out, olen, CDB_ORDER_LITTLE, &obj));
    found = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, CDB_ORDER_LITTLE, nid, &v, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_DECIMAL, v.type);
    found = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_object_get(&obj, CDB_ORDER_LITTLE, fid, &v, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_F64, v.type);
    TEST_ASSERT_EQUAL_DOUBLE(2.5, v.as.f64);

    /* abuse: widen a column that has a default is refused. */
    {
        static uint8_t def_bytes[4];
        cdb_value_writer dw;
        cdb_table_column c;
        uint64_t hasdef = 0;
        cdb_value_writer_init(&dw, def_bytes, sizeof def_bytes, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        cdb_value_write_int(&dw, 3);
        memset(&c, 0, sizeof c);
        c.name = "dd";
        c.name_len = 2;
        c.type = CDB_TYPE_INT;
        c.default_value = def_bytes;
        c.default_len = cdb_value_writer_len(&dw);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_add_column(&db, store, &c, &hasdef));
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_widen_column(&db, store, hasdef, CDB_TYPE_DECIMAL));
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* add_column-with-default (an existing row reads the default), drop_column and
 * rename_column success, reflected by describe / column_id. */
static void test_add_drop_rename(void)
{
    uint64_t e = 0, added = 0;
    unsigned n = 0;
    cdb_table_column_info info[8];
    int found = 0;
    int64_t got = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, make_people());

    begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, insert_person(1, "ada", 3, &e));
    commit();

    /* add a column with a default; the pre-existing row reads it (row_value
     * default path: version < added). */
    {
        static uint8_t def_bytes[4];
        cdb_value_writer dw;
        cdb_table_column c;
        cdb_value_writer_init(&dw, def_bytes, sizeof def_bytes, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        cdb_value_write_int(&dw, 55);
        memset(&c, 0, sizeof c);
        c.name = "rank";
        c.name_len = 4;
        c.type = CDB_TYPE_INT;
        c.default_value = def_bytes;
        c.default_len = cdb_value_writer_len(&dw);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_add_column(&db, T, &c, &added));
    }
    got = read_int(e, added, &found);
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT64(55, got);

    /* drop the note column; describe no longer lists it. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_drop_column(&db, T, F_NOTE));
    {
        unsigned i = 0;
        int seen = 0;
        n = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_describe(&db, T, info, 8, &n, NULL, NULL));
        for (i = 0; i < n && i < 8u; i++)
            if (info[i].field_id == F_NOTE)
                seen = 1;
        TEST_ASSERT_FALSE(seen);
    }

    /* rename score -> points: the new name resolves, the old one does not. */
    {
        uint64_t resolved = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_rename_column(&db, T, F_SCORE, "points", 6));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, T, "points", 6, &resolved));
        TEST_ASSERT_EQUAL_UINT64(F_SCORE, resolved);
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_column_id(&db, T, "score", 5, &resolved));
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* A unique secondary index over rows that already hold a duplicate value is
 * refused with CDB_E_EXISTS (add_index build-time unique check). */
static void test_unique_index_build_duplicate(void)
{
    uint64_t store = 0, e = 0, idf = 0, vf = 0;
    uint32_t ix = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    {
        cdb_table_column cols[2];
        unsigned pk = 0;
        cdb_table_def def;
        memset(cols, 0, sizeof cols);
        cols[0].name = "id";
        cols[0].name_len = 2;
        cols[0].type = CDB_TYPE_INT;
        cols[1].name = "v";
        cols[1].name_len = 1;
        cols[1].type = CDB_TYPE_INT;
        memset(&def, 0, sizeof def);
        def.columns = cols;
        def.ncolumns = 2;
        def.primary_key = &pk;
        def.npk = 1;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create(&db, "dups", 4, &def, &store));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, store, "id", 2, &idf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, store, "v", 1, &vf));

    begin();
    {
        enc r;
        obj_begin(&r);
        cdb_value_field(&r.w, idf);
        cdb_value_write_int(&r.w, 1);
        cdb_value_field(&r.w, vf);
        cdb_value_write_int(&r.w, 100);
        obj_end(&r);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_insert(&db, store, r.b, r.n, &e));
        obj_begin(&r);
        cdb_value_field(&r.w, idf);
        cdb_value_write_int(&r.w, 2);
        cdb_value_field(&r.w, vf);
        cdb_value_write_int(&r.w, 100); /* duplicate v */
        obj_end(&r);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_insert(&db, store, r.b, r.n, &e));
    }
    commit();

    /* A non-unique index builds fine; a unique one meets the duplicate. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create_index(&db, store, &vf, 1, 0, &ix));
    {
        uint32_t uix = 0;
        TEST_ASSERT_EQUAL_INT(CDB_E_EXISTS, cdb_table_create_index(&db, store, &vf, 1, 1, &uix));
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* live_in_tx, nib_moved on a row table, and the remaining explicit abuse
 * paths (duplicate PK, wrong-type value, taken table name). */
static void test_misc_and_abuse(void)
{
    uint64_t e = 0;
    int live = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, make_people());

    begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, insert_person(1, "ada", 3, &e));

    /* live_in_tx sees the just-inserted row as live. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_live_in_tx(&db, T, e, &live));
    TEST_ASSERT_TRUE(live);

    /* abuse: a duplicate primary key is refused. */
    {
        uint64_t dup = 0;
        TEST_ASSERT_EQUAL_INT(CDB_E_EXISTS, insert_person(1, "bob", 4, &dup));
    }

    /* abuse: a value of the wrong type for a column -> CDB_E_SCHEMA. */
    {
        enc bad;
        uint64_t be = 0;
        obj_begin(&bad);
        cdb_value_field(&bad.w, F_ID);
        cdb_value_write_int(&bad.w, 5);
        cdb_value_field(&bad.w, F_NAME);
        cdb_value_write_int(&bad.w, 123); /* name is a string column */
        obj_end(&bad);
        TEST_ASSERT_EQUAL_INT(CDB_E_SCHEMA, cdb_table_insert(&db, T, bad.b, bad.n, &be));
    }
    commit();

    /* nib_moved on a row-oriented table reports NOT_FOUND (it owns no chunk). */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND,
        cdb_table_nib_moved(&db, T, (const uint8_t *)"k", 1, 0, 0));

    /* abuse: creating a table whose name is taken -> CDB_E_EXISTS. */
    {
        cdb_table_column c[1];
        cdb_table_def def;
        uint64_t again = 0;
        memset(c, 0, sizeof c);
        c[0].name = "a";
        c[0].name_len = 1;
        c[0].type = CDB_TYPE_INT;
        memset(&def, 0, sizeof def);
        def.columns = c;
        def.ncolumns = 1;
        TEST_ASSERT_EQUAL_INT(CDB_E_EXISTS, cdb_table_create(&db, "people", 6, &def, &again));
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* A genuine oversized row through the table layer: build it in a large heap
 * buffer so normalize() hits its buffer limit and returns CDB_E_OVERFLOW. */
static void test_oversized_row_overflow(void)
{
    uint64_t e = 0;
    cdb_value_writer w;
    static uint8_t big_row[4096];
    static char big[3072];
    uint64_t idf = 0, namef = 0, notef = 0;
    size_t rlen = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, make_people());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, T, "id", 2, &idf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, T, "name", 4, &namef));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, T, "note", 4, &notef));

    memset(big, 'y', sizeof big - 1u);
    big[sizeof big - 1u] = '\0';
    cdb_value_writer_init(&w, big_row, sizeof big_row, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, idf);
    cdb_value_write_int(&w, 1);
    cdb_value_field(&w, namef);
    cdb_value_write_string(&w, "n", 1);
    cdb_value_field(&w, notef);
    cdb_value_write_string(&w, big, strlen(big));
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    rlen = cdb_value_writer_len(&w);
    TEST_ASSERT_TRUE(rlen > PAGE); /* larger than a table buffer */

    begin();
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_table_insert(&db, T, big_row, rlen, &e));
    commit();

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_typed_roundtrip_index_find_scan);
    RUN_TEST(test_unique_secondary_and_key_overflow);
    RUN_TEST(test_replace_update_semantics);
    RUN_TEST(test_widen_read_through);
    RUN_TEST(test_add_drop_rename);
    RUN_TEST(test_unique_index_build_duplicate);
    RUN_TEST(test_misc_and_abuse);
    RUN_TEST(test_oversized_row_overflow);
    return UNITY_END();
}
