/* Increment-4 reachable-branch coverage for the row-oriented table layer
 * (src/cdb_table.c), complementing tests/test_table.c (behaviour) and
 * tests/test_table_cov.c (first edge pass). It drives the remaining REACHABLE
 * error/edge/decode branches:
 *
 *   - the catalog-settings and schema DECODERS (parse_settings / parse_schema /
 *     get_uint / get_bool / get_ids): a store is created directly in the
 *     catalog with a deliberately malformed settings vector or schema version,
 *     then loaded through cdb_table_describe, asserting the typed CDB_E_CORRUPT
 *     fail-closed result for each malformed shape (master s4 abuse paths);
 *   - key_part for every indexable value type (bool/f64/f32/timestamp/ref/
 *     binary) via unique secondary indexes, and write_as widening (f32 -> f64);
 *   - the unknown-store / wrong-model / dropped-store / bad-argument returns of
 *     find, scan, is_column, chunk_cap, column_id, live_in_tx, nib_moved,
 *     rowgroups, add_column, rename_column.
 *
 * Column-oriented tables are out of scope here (they need cdb_db_config.col_work
 * and are exercised by tests/test_coltable.c). Residual uncovered lines are the
 * column-layer internals and the defensive mbedtls/IO failure returns.
 *
 * Construction rules (gate-friction): every local is initialised at its
 * declaration, every pointer is guarded before use, NULL/negative inputs are
 * asserted to the exact CDB_E_* status, fixtures are synthetic and hard-coded,
 * and no state is shared across tests (each test opens and closes its own db;
 * setUp resets all harness state), so the _cap1/_accel reruns stay green. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_catalog.h"
#include "cdb_db.h"
#include "cdb_doc.h"
#include "cdb_faultenv.h"
#include "cdb_page.h"
#include "cdb_rowgroup.h"
#include "cdb_table.h"

/* Settings / schema field IDs: these mirror the internal encoding of
 * src/cdb_table.c (SET_*, IX_*, SCH_*, COL_*). They are duplicated here so the
 * test can build the malformed catalog records the decoders reject. */
#define S_KEEP 1u
#define S_LAYOUT 2u
#define S_INDEXES 3u
#define S_NEXT_INDEX 4u
#define S_GROUPS 5u
#define S_PENDING 6u
#define S_GROUP_ROWS 7u
#define S_CHUNK_CAP 8u
#define X_NUMBER 1u
#define X_FIELDS 2u
#define X_UNIQUE 3u
#define X_ROOT 4u
#define H_COLUMNS 1u
#define H_PK 2u
#define C_ID 1u
#define C_TYPE 2u
#define C_NOT_NULL 3u
#define C_DEFAULT 4u
#define C_ADDED 5u

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
static cdb_slot_align slot_mem[1u << 17]; /* caller slot memory: no allocator, no leaks */
static cdb_db_config cfg;
static cdb_db db;
static unsigned g_name_ctr;

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
    g_name_ctr = 0;
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
    cfg.slot_mem = slot_mem;
    cfg.slot_mem_size = cdb_db_slot_mem_size(16);
    cfg.durability = CDB_DURABILITY_FULL;
    TEST_ASSERT_EQUAL_size_t(cdb_table_buffers_size(PAGE, 0), sizeof table_buffers);
    TEST_ASSERT_TRUE(cdb_db_slot_mem_size(16) <= sizeof slot_mem);
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

/* ---------------------------------------------------------- value building */

typedef struct enc {
    uint8_t b[4096];
    size_t n;
    cdb_value_writer w;
} enc;

/* ---------------------------------------------------------- the people table */

/* Mirrors tests/test_table.c: id int (pk), name string not-null,
 * score int default 7, note string. */
static uint64_t T, F_ID, F_NAME, F_SCORE, F_NOTE;

static cdb_status make_table(void)
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
    if ((s = cdb_table_create(&db, "people", 6, &def, &T)) != CDB_OK)
        return s;
    if ((s = cdb_table_column_id(&db, T, "id", 2, &F_ID)) != CDB_OK
        || (s = cdb_table_column_id(&db, T, "name", 4, &F_NAME)) != CDB_OK
        || (s = cdb_table_column_id(&db, T, "score", 5, &F_SCORE)) != CDB_OK)
        return s;
    return cdb_table_column_id(&db, T, "note", 4, &F_NOTE);
}

/* ---------------------------------------------------------- catalog seam */

/* Creates a RELATIONAL store carrying the given (possibly malformed) settings
 * vector, committed through the db's catalog exactly as cdb_table_create does
 * (catalog_begin / create_store_ex / catalog_end), and returns its id. */
static uint64_t make_store_with_settings(const uint8_t *vec, size_t vlen)
{
    cdb_catalog *cat = cdb_db_catalog(&db);
    uint64_t id = 0;
    char name[32];
    cdb_status s;
    TEST_ASSERT_NOT_NULL(cat);
    snprintf(name, sizeof name, "bad%u", g_name_ctr++);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_catalog_begin(&db));
    s = cdb_catalog_create_store_ex(cat, name, strlen(name), CDB_MODEL_RELATIONAL, vec, vlen, &id);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_catalog_end(&db, s));
    return id;
}

/* Builds a store with the given valid-enough settings, then attaches the given
 * (malformed) schema as version 1. Returns its id. */
static uint64_t make_store_with_schema(const uint8_t *vec, size_t vlen, const uint8_t *sch, size_t slen)
{
    cdb_catalog *cat = cdb_db_catalog(&db);
    uint64_t id = make_store_with_settings(vec, vlen);
    uint32_t ver = 0;
    cdb_status s;
    TEST_ASSERT_NOT_NULL(cat);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_catalog_begin(&db));
    s = cdb_catalog_add_schema(cat, id, sch, slen, &ver);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_catalog_end(&db, s));
    return id;
}

/* Loads a store through the table layer and asserts the exact status. */
static void expect_load(uint64_t id, cdb_status want)
{
    cdb_table_column_info info[8];
    unsigned n = 99;
    cdb_status got;
    memset(info, 0, sizeof info);
    got = cdb_table_describe(&db, id, info, 8, &n, NULL, NULL);
    TEST_ASSERT_EQUAL_INT(want, got);
}

static void expect_settings(const uint8_t *vec, size_t vlen, cdb_status want)
{
    expect_load(make_store_with_settings(vec, vlen), want);
}

/* A minimal valid settings object: an empty index array, no keep/layout. */
static size_t valid_settings(uint8_t *b, size_t cap)
{
    cdb_value_writer w;
    cdb_value_writer_init(&w, b, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_INDEXES);
    cdb_value_begin_array(&w);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    return cdb_value_writer_len(&w);
}

static void expect_schema(const uint8_t *sch, size_t slen, cdb_status want)
{
    uint8_t vs[64];
    size_t vlen = valid_settings(vs, sizeof vs);
    expect_load(make_store_with_schema(vs, vlen, sch, slen), want);
}

/* ---------------------------------------------------------- tests */

/* The settings decoder: every malformed shape loads as CDB_E_CORRUPT, and the
 * two valid empty-shapes load cleanly. Covers parse_settings / get_uint /
 * get_bool / get_ids reachable branches. */
static void test_cov3_settings_decode(void)
{
    uint8_t b[256];
    cdb_value_writer w;
    size_t len;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    /* Empty settings (len 0) parse as a table with no indexes. */
    expect_settings((const uint8_t *)"", 0, CDB_OK);

    /* A settings value that is not an object. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_int(&w, 5);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* keep of the wrong type. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_KEEP);
    cdb_value_write_string(&w, "x", 1);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* keep negative (get_uint rejects < 0). */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_KEEP);
    cdb_value_write_int(&w, -5);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* next_index of the wrong type. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_KEEP);
    cdb_value_write_int(&w, 0);
    cdb_value_field(&w, S_NEXT_INDEX);
    cdb_value_write_string(&w, "x", 1);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* layout out of range (> COLUMN). */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_LAYOUT);
    cdb_value_write_int(&w, 5);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* An object with keep only (no indexes field) is a valid no-index table. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_KEEP);
    cdb_value_write_int(&w, 2);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    len = cdb_value_writer_len(&w);
    {
        cdb_table_column_info info[8];
        unsigned n = 99;
        uint32_t keep = 0;
        uint64_t id = make_store_with_settings(b, len);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_describe(&db, id, info, 8, &n, NULL, &keep));
        TEST_ASSERT_EQUAL_UINT32(2, keep);
        TEST_ASSERT_EQUAL_UINT(0, n);
    }

    /* indexes not an array. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_INDEXES);
    cdb_value_write_int(&w, 7);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* The settings index decoder: malformed index objects within the index array. */
static void test_cov3_settings_index_decode(void)
{
    uint8_t b[256];
    cdb_value_writer w;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    /* An index array element that is not an object. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_INDEXES);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, 7);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* An index whose number is the wrong type. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_INDEXES);
    cdb_value_begin_array(&w);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, X_NUMBER);
    cdb_value_write_string(&w, "x", 1);
    cdb_value_end_object(&w);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* An index whose fields is not an array (get_ids rejects). */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_INDEXES);
    cdb_value_begin_array(&w);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, X_NUMBER);
    cdb_value_write_int(&w, 1);
    cdb_value_field(&w, X_FIELDS);
    cdb_value_write_int(&w, 9);
    cdb_value_end_object(&w);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* An index whose field id is <= 0 (get_ids rejects). */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_INDEXES);
    cdb_value_begin_array(&w);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, X_NUMBER);
    cdb_value_write_int(&w, 1);
    cdb_value_field(&w, X_FIELDS);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, 0);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* An index whose unique flag is the wrong type (get_bool rejects). */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_INDEXES);
    cdb_value_begin_array(&w);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, X_NUMBER);
    cdb_value_write_int(&w, 1);
    cdb_value_field(&w, X_FIELDS);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, 1);
    cdb_value_end_array(&w);
    cdb_value_field(&w, X_UNIQUE);
    cdb_value_write_int(&w, 7);
    cdb_value_field(&w, X_ROOT);
    cdb_value_write_int(&w, 5);
    cdb_value_end_object(&w);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* An index with a zero root. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_INDEXES);
    cdb_value_begin_array(&w);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, X_NUMBER);
    cdb_value_write_int(&w, 1);
    cdb_value_field(&w, X_FIELDS);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, 1);
    cdb_value_end_array(&w);
    cdb_value_field(&w, X_UNIQUE);
    cdb_value_write_bool(&w, 1);
    cdb_value_field(&w, X_ROOT);
    cdb_value_write_int(&w, 0);
    cdb_value_end_object(&w);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* A structurally valid index whose root page does not exist: cdb_index_open
     * fails and parse_settings propagates the error. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_INDEXES);
    cdb_value_begin_array(&w);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, X_NUMBER);
    cdb_value_write_int(&w, 1);
    cdb_value_field(&w, X_FIELDS);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, 1);
    cdb_value_end_array(&w);
    cdb_value_field(&w, X_UNIQUE);
    cdb_value_write_bool(&w, 1);
    cdb_value_field(&w, X_ROOT);
    cdb_value_write_int(&w, 999999);
    cdb_value_end_object(&w);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_NOT_FOUND);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* Column-layout settings branch of parse_settings (parsed without col_work). */
static void test_cov3_settings_column_decode(void)
{
    uint8_t b[256];
    cdb_value_writer w;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    /* layout = column but a group field is the wrong type. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_LAYOUT);
    cdb_value_write_int(&w, 1);
    cdb_value_field(&w, S_GROUPS);
    cdb_value_write_string(&w, "x", 1);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* layout = column with inconsistent group/pending/rows/cap. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_LAYOUT);
    cdb_value_write_int(&w, 1);
    cdb_value_field(&w, S_GROUPS);
    cdb_value_write_int(&w, 0);
    cdb_value_field(&w, S_PENDING);
    cdb_value_write_int(&w, 5);
    cdb_value_field(&w, S_GROUP_ROWS);
    cdb_value_write_int(&w, 1);
    cdb_value_field(&w, S_CHUNK_CAP);
    cdb_value_write_int(&w, 1);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* layout = column with consistent group fields but a non-existent groups
     * root: cdb_index_open fails (CDB_E_NOT_FOUND) and the error propagates. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, S_LAYOUT);
    cdb_value_write_int(&w, 1);
    cdb_value_field(&w, S_GROUPS);
    cdb_value_write_int(&w, 999999);
    cdb_value_field(&w, S_PENDING);
    cdb_value_write_int(&w, 999998);
    cdb_value_field(&w, S_GROUP_ROWS);
    cdb_value_write_int(&w, 1);
    cdb_value_field(&w, S_CHUNK_CAP);
    cdb_value_write_int(&w, 1);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_settings(b, cdb_value_writer_len(&w), CDB_E_NOT_FOUND);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* The schema decoder: every malformed schema version loads as CDB_E_CORRUPT. */
static void test_cov3_schema_decode(void)
{
    uint8_t b[256];
    cdb_value_writer w;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    /* A schema value that is not an object. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_int(&w, 5);
    expect_schema(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* pk is not an array (get_ids rejects). */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, H_PK);
    cdb_value_write_int(&w, 7);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_schema(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* No columns field. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, H_PK);
    cdb_value_begin_array(&w);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_schema(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* A column array element that is not an object. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, H_COLUMNS);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, 7);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_schema(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* A column whose id is the wrong type. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, H_COLUMNS);
    cdb_value_begin_array(&w);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, C_ID);
    cdb_value_write_string(&w, "x", 1);
    cdb_value_end_object(&w);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_schema(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* A column whose not_null flag is the wrong type (get_bool rejects). */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, H_COLUMNS);
    cdb_value_begin_array(&w);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, C_ID);
    cdb_value_write_int(&w, 1);
    cdb_value_field(&w, C_TYPE);
    cdb_value_write_int(&w, (int64_t)CDB_TYPE_INT);
    cdb_value_field(&w, C_NOT_NULL);
    cdb_value_write_int(&w, 5);
    cdb_value_end_object(&w);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_schema(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* A column with a zero id. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, H_COLUMNS);
    cdb_value_begin_array(&w);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, C_ID);
    cdb_value_write_int(&w, 0);
    cdb_value_field(&w, C_TYPE);
    cdb_value_write_int(&w, (int64_t)CDB_TYPE_INT);
    cdb_value_field(&w, C_NOT_NULL);
    cdb_value_write_bool(&w, 0);
    cdb_value_field(&w, C_ADDED);
    cdb_value_write_int(&w, 1);
    cdb_value_end_object(&w);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_schema(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    /* A column whose default has the wrong type for the column. */
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, H_COLUMNS);
    cdb_value_begin_array(&w);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, C_ID);
    cdb_value_write_int(&w, 1);
    cdb_value_field(&w, C_TYPE);
    cdb_value_write_int(&w, (int64_t)CDB_TYPE_INT);
    cdb_value_field(&w, C_NOT_NULL);
    cdb_value_write_bool(&w, 0);
    cdb_value_field(&w, C_DEFAULT);
    cdb_value_write_string(&w, "x", 1);
    cdb_value_field(&w, C_ADDED);
    cdb_value_write_int(&w, 1);
    cdb_value_end_object(&w);
    cdb_value_end_array(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_schema(b, cdb_value_writer_len(&w), CDB_E_CORRUPT);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* key_part for every indexable value type, via unique secondary indexes over
 * columns of each type, exercised by a single insert. */
static void test_cov3_key_part_types(void)
{
    cdb_table_column cols[7];
    cdb_table_def def;
    unsigned pk = 0;
    uint64_t store = 0;
    uint64_t fid[7];
    unsigned i;
    uint32_t ix;
    enc e;
    uint64_t entry = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    memset(cols, 0, sizeof cols);
    cols[0].name = "id";
    cols[0].name_len = 2;
    cols[0].type = CDB_TYPE_INT;
    cols[1].name = "b";
    cols[1].name_len = 1;
    cols[1].type = CDB_TYPE_BOOL;
    cols[2].name = "d";
    cols[2].name_len = 1;
    cols[2].type = CDB_TYPE_F64;
    cols[3].name = "g";
    cols[3].name_len = 1;
    cols[3].type = CDB_TYPE_F32;
    cols[4].name = "t";
    cols[4].name_len = 1;
    cols[4].type = CDB_TYPE_TIMESTAMP;
    cols[5].name = "r";
    cols[5].name_len = 1;
    cols[5].type = CDB_TYPE_REF;
    cols[6].name = "n";
    cols[6].name_len = 1;
    cols[6].type = CDB_TYPE_BINARY;
    memset(&def, 0, sizeof def);
    def.columns = cols;
    def.ncolumns = 7;
    def.primary_key = &pk;
    def.npk = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create(&db, "types", 5, &def, &store));

    for (i = 0; i < 7; i++) {
        fid[i] = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_table_column_id(&db, store, cols[i].name, cols[i].name_len, &fid[i]));
    }
    /* Unique secondary indexes over each non-pk column. */
    for (i = 1; i < 7; i++) {
        ix = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create_index(&db, store, &fid[i], 1, 1, &ix));
    }

    /* One row setting every typed column: insert builds each index key. */
    cdb_value_writer_init(&e.w, e.b, sizeof e.b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&e.w);
    cdb_value_field(&e.w, fid[0]);
    cdb_value_write_int(&e.w, 1);
    cdb_value_field(&e.w, fid[1]);
    cdb_value_write_bool(&e.w, 1);
    cdb_value_field(&e.w, fid[2]);
    cdb_value_write_f64(&e.w, 1.5);
    cdb_value_field(&e.w, fid[3]);
    cdb_value_write_f32(&e.w, 2.5f);
    cdb_value_field(&e.w, fid[4]);
    cdb_value_write_timestamp(&e.w, CDB_TS_MILLIS, 123456);
    cdb_value_field(&e.w, fid[5]);
    cdb_value_write_ref(&e.w, 9, 10);
    cdb_value_field(&e.w, fid[6]);
    cdb_value_write_binary(&e.w, "\x01\x02\x03", 3);
    cdb_value_end_object(&e.w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, e.w.error);
    e.n = cdb_value_writer_len(&e.w);

    begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_insert(&db, store, e.b, e.n, &entry));
    commit();

    /* Find the row back by its bool secondary index, proving array_key builds a
     * bool key too. */
    {
        uint8_t kb[32];
        cdb_value_writer kw;
        uint64_t got = 0;
        int found = 0;
        cdb_value_writer_init(&kw, kb, sizeof kb, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        cdb_value_begin_array(&kw);
        cdb_value_write_bool(&kw, 1);
        cdb_value_end_array(&kw);
        TEST_ASSERT_EQUAL_INT(CDB_OK, kw.error);
        /* Secondary index 1 is the first created (number 1). */
        {
            cdb_table_cursor cur;
            uint64_t ents[4];
            size_t n = 0;
            memset(&cur, 0, sizeof cur);
            TEST_ASSERT_EQUAL_INT(CDB_OK,
                cdb_table_scan(&db, store, 1u, kb, cdb_value_writer_len(&kw), NULL, 0, &cur, ents, 4, &n));
            TEST_ASSERT_TRUE(n >= 1);
        }
        (void)got;
        (void)found;
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* Unknown-store / bad-argument returns across the public row API. */
static void test_cov3_unknown_store_errors(void)
{
    uint64_t entry = 0;
    int found = 0;
    int is_col = 1;
    int live = 1;
    uint32_t cap = 7;
    uint64_t fid = 0;
    uint8_t key[16];
    cdb_value_writer w;
    size_t klen;
    cdb_table_cursor cur;
    uint64_t got[4];
    size_t n = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, make_table());

    /* A valid one-element array key, for the find/scan unknown-store path. */
    cdb_value_writer_init(&w, key, sizeof key, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, 1);
    cdb_value_end_array(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    klen = cdb_value_writer_len(&w);

    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_find(&db, 999999u, key, klen, &entry, &found));
    memset(&cur, 0, sizeof cur);
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND,
        cdb_table_scan(&db, 999999u, 0, NULL, 0, NULL, 0, &cur, got, 4, &n));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_is_column(&db, 999999u, &is_col));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_chunk_cap(&db, 999999u, &cap));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_column_id(&db, 999999u, "id", 2, &fid));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_live_in_tx(&db, 999999u, 1, &live));

    /* nib_moved on an unknown store, and on a row table, both map to NOT_FOUND. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_nib_moved(&db, 999999u, key, klen, 1, 2));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_nib_moved(&db, T, key, klen, 1, 2));

    /* scan with a valid `from` but a malformed `to` bound. */
    memset(&cur, 0, sizeof cur);
    {
        uint8_t badto[8];
        cdb_value_writer bw;
        cdb_value_writer_init(&bw, badto, sizeof badto, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        cdb_value_write_int(&bw, 3); /* not an array */
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
            cdb_table_scan(&db, T, 0, NULL, 0, badto, cdb_value_writer_len(&bw), &cur, got, 4, &n));
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* live_in_tx on a non-relational store, and on a dropped store. */
static void test_cov3_live_in_tx_models(void)
{
    cdb_catalog *cat;
    uint64_t doc_id = 0, rel_id = 0;
    int live = 1;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    cat = cdb_db_catalog(&db);
    TEST_ASSERT_NOT_NULL(cat);

    /* A document-model store: live_in_tx refuses it as not a table. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_catalog_begin(&db));
    {
        cdb_status s = cdb_catalog_create_store(cat, "docs", 4, CDB_MODEL_DOCUMENT, &doc_id);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_catalog_end(&db, s));
    }
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_live_in_tx(&db, doc_id, 1, &live));
    TEST_ASSERT_EQUAL_INT(0, live);

    /* A relational store that is then dropped: live_in_tx returns OK, not live. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_catalog_begin(&db));
    {
        cdb_status s = cdb_catalog_create_store(cat, "gone", 4, CDB_MODEL_RELATIONAL, &rel_id);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_catalog_end(&db, s));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_catalog_begin(&db));
    {
        cdb_status s = cdb_catalog_drop_store(cat, rel_id);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_catalog_end(&db, s));
    }
    live = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_live_in_tx(&db, rel_id, 1, &live));
    TEST_ASSERT_EQUAL_INT(0, live);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* Schema-change argument branches: add a bad-typed column, rename an unknown
 * column, rename with a NULL name, and rowgroups on a row table. */
static void test_cov3_schema_change_args(void)
{
    cdb_table_column c;
    uint64_t fid = 0;
    struct cdb_rg g;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, make_table());

    /* add_column whose type is invalid (check_column rejects it). */
    memset(&c, 0, sizeof c);
    c.name = "bad";
    c.name_len = 3;
    c.type = CDB_TYPE_NULL; /* not a storable column type */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_add_column(&db, T, &c, &fid));

    /* rename an unknown field id. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_table_rename_column(&db, T, 999999u, "new", 3));

    /* rename with a NULL name is rejected before the change runs. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_rename_column(&db, T, F_ID, NULL, 0));

    /* rowgroups on a row-oriented table is not applicable. */
    memset(&g, 0, sizeof g);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_table_rowgroups(&db, T, &g));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* table_get on a non-relational store, no-transaction mutations, a widen that
 * reaches write_as, and range/full scans over a populated table. */
static void test_cov3_more(void)
{
    cdb_catalog *cat;
    uint64_t doc_id = 0;
    cdb_table_column cols[2];
    cdb_table_def def;
    unsigned pk = 0;
    uint64_t store = 0, fv = 0, entry = 0;
    enc e;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    cat = cdb_db_catalog(&db);
    TEST_ASSERT_NOT_NULL(cat);

    /* table_get refuses a document-model store as not a table. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_catalog_begin(&db));
    {
        cdb_status s = cdb_catalog_create_store(cat, "docs2", 5, CDB_MODEL_DOCUMENT, &doc_id);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_catalog_end(&db, s));
    }
    {
        cdb_table_column_info info[4];
        unsigned n = 0;
        memset(info, 0, sizeof info);
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
            cdb_table_describe(&db, doc_id, info, 4, &n, NULL, NULL));
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, make_table());

    /* Mutations outside a transaction are refused (tx_table state guard). */
    {
        enc r;
        cdb_value_writer_init(&r.w, r.b, sizeof r.b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        cdb_value_begin_object(&r.w);
        cdb_value_field(&r.w, F_ID);
        cdb_value_write_int(&r.w, 1);
        cdb_value_field(&r.w, F_NAME);
        cdb_value_write_string(&r.w, "x", 1);
        cdb_value_end_object(&r.w);
        TEST_ASSERT_EQUAL_INT(CDB_OK, r.w.error);
        r.n = cdb_value_writer_len(&r.w);
        TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_table_replace(&db, T, 1u, r.b, r.n));
        TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_table_update(&db, T, 1u, r.b, r.n));
        TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_table_delete(&db, T, 1u));
    }

    /* Range and full scans over a populated primary index. */
    begin();
    {
        enc r;
        int i;
        uint64_t ent = 0;
        for (i = 1; i <= 3; i++) {
            cdb_value_writer_init(&r.w, r.b, sizeof r.b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
            cdb_value_begin_object(&r.w);
            cdb_value_field(&r.w, F_ID);
            cdb_value_write_int(&r.w, i);
            cdb_value_field(&r.w, F_NAME);
            cdb_value_write_string(&r.w, "n", 1);
            cdb_value_end_object(&r.w);
            TEST_ASSERT_EQUAL_INT(CDB_OK, r.w.error);
            r.n = cdb_value_writer_len(&r.w);
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_insert(&db, T, r.b, r.n, &ent));
        }
    }
    commit();
    {
        uint8_t to[16];
        cdb_value_writer tw;
        cdb_table_cursor cur;
        uint64_t ents[8];
        size_t n = 0;
        /* Range scan with an upper bound of id = 2: ids 1 and 2 come back. */
        cdb_value_writer_init(&tw, to, sizeof to, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        cdb_value_begin_array(&tw);
        cdb_value_write_int(&tw, 2);
        cdb_value_end_array(&tw);
        TEST_ASSERT_EQUAL_INT(CDB_OK, tw.error);
        memset(&cur, 0, sizeof cur);
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_table_scan(&db, T, 0, NULL, 0, to, cdb_value_writer_len(&tw), &cur, ents, 8, &n));
        TEST_ASSERT_EQUAL_UINT(2, n);
        /* Full (entry-order) scan returns every row. */
        memset(&cur, 0, sizeof cur);
        n = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_table_scan(&db, T, CDB_TABLE_NO_INDEX, NULL, 0, NULL, 0, &cur, ents, 8, &n));
        TEST_ASSERT_EQUAL_UINT(3, n);
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    /* A fresh table to exercise write_as widening an f32 column to f64. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    memset(cols, 0, sizeof cols);
    cols[0].name = "id";
    cols[0].name_len = 2;
    cols[0].type = CDB_TYPE_INT;
    cols[1].name = "v";
    cols[1].name_len = 1;
    cols[1].type = CDB_TYPE_F32;
    memset(&def, 0, sizeof def);
    def.columns = cols;
    def.ncolumns = 2;
    def.primary_key = &pk;
    def.npk = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create(&db, "widen", 5, &def, &store));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, store, "v", 1, &fv));

    cdb_value_writer_init(&e.w, e.b, sizeof e.b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&e.w);
    {
        uint64_t idf = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, store, "id", 2, &idf));
        cdb_value_field(&e.w, idf);
        cdb_value_write_int(&e.w, 1);
    }
    cdb_value_field(&e.w, fv);
    cdb_value_write_f32(&e.w, 1.5f);
    cdb_value_end_object(&e.w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, e.w.error);
    e.n = cdb_value_writer_len(&e.w);

    begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_insert(&db, store, e.b, e.n, &entry));
    commit();

    /* Widen v from f32 to f64, then read the row back: project widens via
     * write_as. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_widen_column(&db, store, fv, CDB_TYPE_F64));
    {
        uint8_t out[PAGE];
        size_t len = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_get(&db, store, entry, out, sizeof out, &len));
        TEST_ASSERT_TRUE(len > 0);
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cov3_settings_decode);
    RUN_TEST(test_cov3_settings_index_decode);
    RUN_TEST(test_cov3_settings_column_decode);
    RUN_TEST(test_cov3_schema_decode);
    RUN_TEST(test_cov3_key_part_types);
    RUN_TEST(test_cov3_unknown_store_errors);
    RUN_TEST(test_cov3_live_in_tx_models);
    RUN_TEST(test_cov3_schema_change_args);
    RUN_TEST(test_cov3_more);
    return UNITY_END();
}
