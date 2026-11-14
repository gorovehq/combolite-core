/* Branch-coverage set for cdb_table (agent-authored). Exercises reachable
 * edge and error branches of the built, row-oriented table layer that the
 * behavioural suite (tests/test_table.c) leaves uncovered: argument and
 * schema validation in create/add/widen/index, find/scan key errors, the
 * no-primary-key path, the keep setting, and the simple engine hooks.
 *
 * Column-oriented tables are out of scope: they need cdb_db_config.col_work
 * (never configured by this harness) and their row calls are the unbuilt
 * part, so their branches are unreachable from here. */
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
    memset(h.db_id, 0x7A, sizeof h.db_id);
    return cdb_db_open(&db, &env, "r", &cfg, &h);
}

static void begin(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL)); }
static void commit(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db)); }

/* ------------------------------------------------------------ values */

typedef struct enc {
    uint8_t b[256];
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

static void put_int(enc *e, uint64_t f, int64_t v)
{
    if (f)
        cdb_value_field(&e->w, f);
    cdb_value_write_int(&e->w, v);
}

static void put_str(enc *e, uint64_t f, const char *s)
{
    if (f)
        cdb_value_field(&e->w, f);
    cdb_value_write_string(&e->w, s, strlen(s));
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

/* ------------------------------------------------------------ the table */

/* people: id int (primary key), name string not-null, score int default 7,
 * note string.  Mirrors tests/test_table.c. */
static uint64_t T, F_ID, F_NAME, F_SCORE, F_NOTE;

static cdb_status make_table(uint32_t keep)
{
    static uint8_t seven[4];
    cdb_value_writer w;
    cdb_table_column cols[4];
    unsigned pk = 0;
    cdb_table_def def;
    cdb_status s;
    cdb_value_writer_init(&w, seven, sizeof seven, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_int(&w, 7);
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
    cols[2].default_len = cdb_value_writer_len(&w);
    cols[3].name = "note";
    cols[3].name_len = 4;
    cols[3].type = CDB_TYPE_STRING;
    memset(&def, 0, sizeof def);
    def.columns = cols;
    def.ncolumns = 4;
    def.primary_key = &pk;
    def.npk = 1;
    def.keep = keep;
    if ((s = cdb_table_create(&db, "people", 6, &def, &T)) != CDB_OK)
        return s;
    if ((s = cdb_table_column_id(&db, T, "id", 2, &F_ID)) != CDB_OK
        || (s = cdb_table_column_id(&db, T, "name", 4, &F_NAME)) != CDB_OK
        || (s = cdb_table_column_id(&db, T, "score", 5, &F_SCORE)) != CDB_OK)
        return s;
    return cdb_table_column_id(&db, T, "note", 4, &F_NOTE);
}

static enc person(int64_t id, const char *name, int64_t score)
{
    enc e;
    obj_begin(&e);
    put_int(&e, F_ID, id);
    put_str(&e, F_NAME, name);
    if (score >= 0)
        put_int(&e, F_SCORE, score);
    obj_end(&e);
    return e;
}

static cdb_status insert(int64_t id, const char *name, int64_t score, uint64_t *entry)
{
    enc e = person(id, name, score);
    return cdb_table_insert(&db, T, e.b, e.n, entry);
}

/* A table with no primary key (exercises the npk == 0 paths). */
static uint64_t T2;

static cdb_status make_nopk_table(void)
{
    cdb_table_column cols[2];
    cdb_table_def def;
    memset(cols, 0, sizeof cols);
    cols[0].name = "a";
    cols[0].name_len = 1;
    cols[0].type = CDB_TYPE_INT;
    cols[1].name = "b";
    cols[1].name_len = 1;
    cols[1].type = CDB_TYPE_STRING;
    memset(&def, 0, sizeof def);
    def.columns = cols;
    def.ncolumns = 2;
    def.primary_key = NULL;
    def.npk = 0;
    def.keep = 0;
    return cdb_table_create(&db, "nopk", 4, &def, &T2);
}

/* Builds a def and attempts create; returns the status. */
static cdb_status create_expect(const cdb_table_column *cols, unsigned nc, const unsigned *pk, unsigned npk,
                                unsigned layout)
{
    cdb_table_def def;
    uint64_t st = 0;
    memset(&def, 0, sizeof def);
    def.columns = cols;
    def.ncolumns = nc;
    def.primary_key = pk;
    def.npk = npk;
    def.layout = layout;
    return cdb_table_create(&db, "x", 1, &def, &st);
}

/* ------------------------------------------------------------ tests */

/* cdb_table_create argument and schema validation (table_create_in,
 * check_column), plus a successful no-primary-key table. */
static void test_cov_create_validation(void)
{
    cdb_table_column cols[2];
    static uint8_t strdef[16];
    cdb_value_writer w;
    size_t strdef_len;
    uint64_t st = 0;
    unsigned pk[2];

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    /* NULL def, NULL columns, zero columns. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_create(&db, "x", 1, NULL, &st));
    {
        cdb_table_def def;
        memset(&def, 0, sizeof def);
        def.columns = NULL;
        def.ncolumns = 1;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_create(&db, "x", 1, &def, &st));
    }
    memset(cols, 0, sizeof cols);
    cols[0].name = "a";
    cols[0].name_len = 1;
    cols[0].type = CDB_TYPE_INT;
    cols[1].name = "b";
    cols[1].name_len = 1;
    cols[1].type = CDB_TYPE_INT;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, create_expect(cols, 0, NULL, 0, 0));

    /* npk > 0 but no primary_key array. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, create_expect(cols, 2, NULL, 1, 0));

    /* Duplicate column names. */
    {
        cdb_table_column dup[2];
        memset(dup, 0, sizeof dup);
        dup[0].name = "same";
        dup[0].name_len = 4;
        dup[0].type = CDB_TYPE_INT;
        dup[1].name = "same";
        dup[1].name_len = 4;
        dup[1].type = CDB_TYPE_INT;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, create_expect(dup, 2, NULL, 0, 0));
    }

    /* Primary-key position out of range. */
    pk[0] = 5;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, create_expect(cols, 2, pk, 1, 0));

    /* Duplicate primary-key positions. */
    pk[0] = 0;
    pk[1] = 0;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, create_expect(cols, 2, pk, 2, 0));

    /* Primary-key column of a non-indexable type (decimal). */
    {
        cdb_table_column dc[1];
        unsigned dpk = 0;
        memset(dc, 0, sizeof dc);
        dc[0].name = "d";
        dc[0].name_len = 1;
        dc[0].type = CDB_TYPE_DECIMAL;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, create_expect(dc, 1, &dpk, 1, 0));
    }

    /* Unknown layout value (> column). */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, create_expect(cols, 2, NULL, 0, 2u));

    /* check_column: NULL name, zero-length name, bad type. */
    {
        cdb_table_column c[1];
        memset(c, 0, sizeof c);
        c[0].name = NULL;
        c[0].name_len = 0;
        c[0].type = CDB_TYPE_INT;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, create_expect(c, 1, NULL, 0, 0));
        c[0].name = "a";
        c[0].name_len = 0;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, create_expect(c, 1, NULL, 0, 0));
        c[0].name = "a";
        c[0].name_len = 1;
        c[0].type = CDB_TYPE_NULL;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, create_expect(c, 1, NULL, 0, 0));
    }

    /* check_column: a default of the wrong type (string default on int). */
    cdb_value_writer_init(&w, strdef, sizeof strdef, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_string(&w, "x", 1);
    strdef_len = cdb_value_writer_len(&w);
    {
        cdb_table_column c[1];
        memset(c, 0, sizeof c);
        c[0].name = "a";
        c[0].name_len = 1;
        c[0].type = CDB_TYPE_INT;
        c[0].default_value = strdef;
        c[0].default_len = strdef_len;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, create_expect(c, 1, NULL, 0, 0));
    }

    /* Create while a transaction is open: refused. */
    begin();
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, create_expect(cols, 2, NULL, 0, 0));
    commit();

    /* A valid table with no primary key succeeds (add_index is skipped). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, make_nopk_table());

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* describe cap clamp and NULL out params; is_column; chunk_cap; set_keep;
 * flush; and table_get failing on an unknown store. */
static void test_cov_describe_lookups_keep(void)
{
    cdb_table_column_info info[8];
    unsigned n;
    uint32_t keep;
    int is_col;
    uint32_t cap;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, make_table(0));

    /* cap smaller than the column count: n is still the full count. */
    n = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_describe(&db, T, info, 2, &n, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(4, n);

    /* An unknown store fails to load. */
    TEST_ASSERT_NOT_EQUAL(CDB_OK, cdb_table_describe(&db, 999999u, info, 8, &n, NULL, NULL));

    /* Engine hooks on a row table. */
    is_col = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_is_column(&db, T, &is_col));
    TEST_ASSERT_EQUAL_INT(0, is_col);
    cap = 123;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_chunk_cap(&db, T, &cap));
    TEST_ASSERT_EQUAL_UINT32(0, cap);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_flush(&db));

    /* Change the keep window and read it back. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_set_keep(&db, T, 5));
    keep = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_describe(&db, T, info, 8, &n, NULL, &keep));
    TEST_ASSERT_EQUAL_UINT32(5, keep);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* find and scan key-argument errors, including the no-primary-key table. */
static void test_cov_find_scan_errors(void)
{
    uint64_t entry, got[8];
    cdb_table_cursor cur;
    size_t n;
    int found;
    enc k;
    cdb_value_writer w;
    uint8_t ibuf[16];
    size_t ilen;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, make_table(0));
    begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, insert(1, "ada", 3, &entry));
    TEST_ASSERT_EQUAL_INT(CDB_OK, insert(2, "bob", 4, &entry));
    commit();

    /* find: NULL key -> array_key(NULL). */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_find(&db, T, NULL, 0, &entry, &found));

    /* find: a key that is not an array (a bare int). */
    cdb_value_writer_init(&w, ibuf, sizeof ibuf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_int(&w, 1);
    ilen = cdb_value_writer_len(&w);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_find(&db, T, ibuf, ilen, &entry, &found));

    /* find: more key values than the index has columns. */
    arr_begin(&k);
    put_int(&k, 0, 1);
    put_int(&k, 0, 2);
    arr_end(&k);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_find(&db, T, k.b, k.n, &entry, &found));

    /* find: a non-indexable value (decimal) in the key array. */
    arr_begin(&k);
    cdb_value_write_decimal_i64(&k.w, 0, 5);
    arr_end(&k);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_find(&db, T, k.b, k.n, &entry, &found));

    /* scan: unknown index number. */
    memset(&cur, 0, sizeof cur);
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND,
                          cdb_table_scan(&db, T, 999u, NULL, 0, NULL, 0, &cur, got, 8, &n));

    /* scan: a bad `from` bound on the primary index. */
    memset(&cur, 0, sizeof cur);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_table_scan(&db, T, 0, ibuf, ilen, NULL, 0, &cur, got, 8, &n));

    /* A table without a primary key cannot be found by key. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, make_nopk_table());
    arr_begin(&k);
    put_int(&k, 0, 1);
    arr_end(&k);
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_table_find(&db, T2, k.b, k.n, &entry, &found));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* Schema- and index-change validation branches. */
static void test_cov_schema_change_errors(void)
{
    cdb_table_column c;
    uint64_t fid, dfid;
    uint32_t ix;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, make_table(0));

    /* add_column: NULL column. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_add_column(&db, T, NULL, &fid));

    /* add_column: a not-null column with no default is refused. */
    memset(&c, 0, sizeof c);
    c.name = "need";
    c.name_len = 4;
    c.type = CDB_TYPE_INT;
    c.not_null = 1;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_add_column(&db, T, &c, &fid));

    /* widen: unknown column. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_widen_column(&db, T, 999999u, CDB_TYPE_DECIMAL));

    /* widen: an indexed int column to decimal (non-indexable target). F_ID is
     * the primary-key column and has no default. */
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_table_widen_column(&db, T, F_ID, CDB_TYPE_DECIMAL));

    /* drop_index: the primary key's index (0) stays; an unknown number. */
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_table_drop_index(&db, T, 0));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_drop_index(&db, T, 999u));

    /* create_index: NULL fields, NULL out pointer, zero columns. */
    {
        uint64_t f = F_SCORE;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_create_index(&db, T, NULL, 1, 0, &ix));
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_create_index(&db, T, &f, 1, 0, NULL));
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_create_index(&db, T, &f, 0, 0, &ix));
    }

    /* create_index: an unknown field id. */
    {
        uint64_t bad = 999999u;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_create_index(&db, T, &bad, 1, 0, &ix));
    }

    /* create_index: a non-indexable column (a freshly added decimal). */
    memset(&c, 0, sizeof c);
    c.name = "amount";
    c.name_len = 6;
    c.type = CDB_TYPE_DECIMAL;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_add_column(&db, T, &c, &dfid));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_create_index(&db, T, &dfid, 1, 0, &ix));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* Row-call precondition and not-found branches. */
static void test_cov_row_tx_errors(void)
{
    uint64_t entry;
    enc e;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, make_table(0));

    /* A row call with no open transaction. */
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, insert(1, "ada", -1, &entry));

    /* A catalog change is refused inside a transaction. */
    begin();
    {
        cdb_table_column c;
        uint64_t fid;
        memset(&c, 0, sizeof c);
        c.name = "zz";
        c.name_len = 2;
        c.type = CDB_TYPE_INT;
        TEST_ASSERT_NOT_EQUAL(CDB_OK, cdb_table_add_column(&db, T, &c, &fid));
    }
    commit();

    /* update / replace / delete of a row that does not exist. */
    begin();
    e = person(7, "x", -1);
    obj_begin(&e);
    put_str(&e, F_NOTE, "n");
    obj_end(&e);
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_update(&db, T, 999999u, e.b, e.n));
    e = person(7, "x", -1);
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_replace(&db, T, 999999u, e.b, e.n));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_delete(&db, T, 999999u));
    commit();

    /* get of a row that does not exist. */
    {
        uint8_t out[PAGE];
        size_t len;
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_get(&db, T, 999999u, out, sizeof out, &len));
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* cdb_table_keep_setting: empty, a valid settings object, and a corrupt one. */
static void test_cov_keep_setting(void)
{
    uint32_t keep;
    enc e;
    cdb_value_writer w;
    uint8_t ibuf[16];
    size_t ilen;

    /* No settings -> keep 0. */
    keep = 99;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_keep_setting(NULL, 0, CDB_ORDER_LITTLE, &keep));
    TEST_ASSERT_EQUAL_UINT32(0, keep);

    /* A settings object with keep = 3 (field 1). */
    obj_begin(&e);
    put_int(&e, 1u, 3);
    obj_end(&e);
    keep = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_keep_setting(e.b, e.n, CDB_ORDER_LITTLE, &keep));
    TEST_ASSERT_EQUAL_UINT32(3, keep);

    /* Settings that are not an object -> corrupt. */
    cdb_value_writer_init(&w, ibuf, sizeof ibuf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_int(&w, 5);
    ilen = cdb_value_writer_len(&w);
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_table_keep_setting(ibuf, ilen, CDB_ORDER_LITTLE, &keep));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cov_create_validation);
    RUN_TEST(test_cov_describe_lookups_keep);
    RUN_TEST(test_cov_find_scan_errors);
    RUN_TEST(test_cov_schema_change_errors);
    RUN_TEST(test_cov_row_tx_errors);
    RUN_TEST(test_cov_keep_setting);
    return UNITY_END();
}
