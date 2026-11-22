/* combolite-core #35 (sub-feature C) — QA edge/abuse for the public text-query
 * entry cdb_db_query(). Complements tests/test_db_query.c (the happy-path row
 * read + one malformed case) with: parameter binding end-to-end, an empty
 * result set, scratch reuse across sequential queries, and the full set of
 * caller-owned-buffer argument validations (no-heap, fail-closed). Hermetic: a
 * real database over the in-memory fault env. */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_compiler.h"
#include "cdb_eval.h"
#include "cdb_exec.h"
#include "cdb_faultenv.h"
#include "cdb_table.h"

#define FCAP (1024u * 1024u)
#define PAGE_LOG2 10u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define DOC_MAX 12288u
#define DBUF (DOC_MAX + PAGE)

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 8192u];
static cdb_faultenv fe;
static cdb_env env;

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[4096];
static uint8_t record_buf[DOC_MAX + 2u * PAGE];
static uint8_t cat_work[24u * 1024u];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static uint8_t doc_buffers[3u * DBUF + 5u * PAGE];
static uint8_t doc_stage[4096];
static uint8_t idx_stage[16u * 1024u];
static uint8_t table_buffers[64u * 1024u];
static cdb_db_config cfg;
static cdb_db db;

static uint8_t scratch[64u * 1024u];
static uint8_t wire_scratch[4096];

static uint64_t T, F_ID, F_TITLE, F_YEAR;

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
    cfg.table_buffers = table_buffers;
    cfg.doc_max = DOC_MAX;
    cfg.durability = CDB_DURABILITY_FULL;

    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x5D, sizeof h.db_id);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "q35e", &cfg, &h));
}

void tearDown(void) { cdb_db_close(&db); }

static void make_books(void)
{
    static const struct {
        int64_t id;
        const char *title;
        int64_t year;
    } rows[] = {
        {1342, "Pride and Prejudice", 1813},
        {11, "Alice in Wonderland", 1865},
        {1661, "Sherlock Holmes", 1892},
    };
    cdb_table_column cols[3];
    unsigned pk = 0;
    cdb_table_def def;
    uint64_t entry;
    size_t i;
    uint8_t b[256];
    cdb_value_writer w;

    memset(cols, 0, sizeof cols);
    cols[0].name = "id";
    cols[0].name_len = 2;
    cols[0].type = CDB_TYPE_INT;
    cols[1].name = "title";
    cols[1].name_len = 5;
    cols[1].type = CDB_TYPE_STRING;
    cols[2].name = "year";
    cols[2].name_len = 4;
    cols[2].type = CDB_TYPE_INT;
    memset(&def, 0, sizeof def);
    def.columns = cols;
    def.ncolumns = 3;
    def.primary_key = &pk;
    def.npk = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create(&db, "books", 5, &def, &T));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, T, "id", 2, &F_ID));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, T, "title", 5, &F_TITLE));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, T, "year", 4, &F_YEAR));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        cdb_value_begin_object(&w);
        cdb_value_field(&w, F_ID);
        cdb_value_write_int(&w, rows[i].id);
        cdb_value_field(&w, F_TITLE);
        cdb_value_write_string(&w, rows[i].title, strlen(rows[i].title));
        cdb_value_field(&w, F_YEAR);
        cdb_value_write_int(&w, rows[i].year);
        cdb_value_end_object(&w);
        TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
        TEST_ASSERT_EQUAL_INT(CDB_OK,
                              cdb_table_insert(&db, T, b, cdb_value_writer_len(&w), &entry));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
}

/* A bound index parameter ($0) selects the matching row end-to-end. */
static void test_query_with_param(void)
{
    cdb_exec_cursor cur;
    cdb_exec_row row;
    cdb_compile_error err;
    cdb_eval_param p;
    cdb_value v;
    int has = 0, found = 0;
    const char *q = "SELECT title FROM Scan(\"books\") WHERE id == $0";

    make_books();
    memset(&err, 0, sizeof err);
    memset(&p, 0, sizeof p);
    p.name = NULL;
    p.index = 0;
    cdb_eval_make_int(&p.val, 1661);

    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK,
                                  cdb_db_query(&db, q, strlen(q), &p, 1, wire_scratch,
                                               sizeof wire_scratch, &cur, scratch, sizeof scratch,
                                               &err),
                                  err.msg);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &row, &has));
    TEST_ASSERT_TRUE(has);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_row_get_field(&row, &cur.eval_ctx, "title", 5, &v,
                                                         &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_STRING, v.type);
    TEST_ASSERT_EQUAL_MEMORY("Sherlock Holmes", v.payload, v.payload_len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &row, &has));
    TEST_ASSERT_FALSE(has);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* A predicate matching nothing yields an empty cursor, not an error. */
static void test_query_empty_result(void)
{
    cdb_exec_cursor cur;
    cdb_exec_row row;
    cdb_compile_error err;
    int has = 1;
    const char *q = "SELECT title FROM Scan(\"books\") WHERE id == 424242";

    make_books();
    memset(&err, 0, sizeof err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK,
                                  cdb_db_query(&db, q, strlen(q), NULL, 0, wire_scratch,
                                               sizeof wire_scratch, &cur, scratch, sizeof scratch,
                                               &err),
                                  err.msg);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &row, &has));
    TEST_ASSERT_FALSE(has);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* Two sequential queries sharing the same caller scratch both work (no hidden
 * cross-call state; buffers are reusable once the prior cursor is closed). */
static void test_query_scratch_reuse(void)
{
    cdb_exec_cursor cur;
    cdb_exec_row row;
    cdb_compile_error err;
    int has = 0;
    const char *q1 = "SELECT title FROM Scan(\"books\") WHERE id == 11";
    const char *q2 = "Scan(\"books\") | aggregate(n: count(*))";

    make_books();
    memset(&err, 0, sizeof err);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_query(&db, q1, strlen(q1), NULL, 0, wire_scratch,
                                               sizeof wire_scratch, &cur, scratch, sizeof scratch,
                                               &err));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &row, &has));
    TEST_ASSERT_TRUE(has);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));

    has = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_query(&db, q2, strlen(q2), NULL, 0, wire_scratch,
                                               sizeof wire_scratch, &cur, scratch, sizeof scratch,
                                               &err));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &row, &has));
    TEST_ASSERT_TRUE(has);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* ---- caller-owned buffer / argument validation (fail closed) ---- */

static void test_query_null_text(void)
{
    cdb_exec_cursor cur;
    cdb_compile_error err;
    memset(&err, 0, sizeof err);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_db_query(&db, NULL, 10, NULL, 0, wire_scratch, sizeof wire_scratch,
                                       &cur, scratch, sizeof scratch, &err));
}

static void test_query_null_db(void)
{
    cdb_exec_cursor cur;
    cdb_compile_error err;
    memset(&err, 0, sizeof err);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_db_query(NULL, "Scan(\"books\")", 13, NULL, 0, wire_scratch,
                                       sizeof wire_scratch, &cur, scratch, sizeof scratch, &err));
}

static void test_query_null_exec_scratch(void)
{
    cdb_exec_cursor cur;
    cdb_compile_error err;
    memset(&err, 0, sizeof err);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_db_query(&db, "Scan(\"books\")", 13, NULL, 0, wire_scratch,
                                       sizeof wire_scratch, &cur, NULL, 0, &err));
}

static void test_query_zero_exec_cap(void)
{
    cdb_exec_cursor cur;
    cdb_compile_error err;
    memset(&err, 0, sizeof err);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_db_query(&db, "Scan(\"books\")", 13, NULL, 0, wire_scratch,
                                       sizeof wire_scratch, &cur, scratch, 0, &err));
}

/* A real query that cannot fit its compiled wire into a tiny scratch must fail
 * closed (never an out-of-bounds write — ASan-verified). */
static void test_query_tiny_wire_scratch_fail_closed(void)
{
    cdb_exec_cursor cur;
    cdb_compile_error err;
    uint8_t tiny[3];
    cdb_status s;
    make_books();
    memset(&err, 0, sizeof err);
    s = cdb_db_query(&db, "SELECT title, year FROM Scan(\"books\") WHERE id == 1342",
                     strlen("SELECT title, year FROM Scan(\"books\") WHERE id == 1342"), NULL, 0,
                     tiny, sizeof tiny, &cur, scratch, sizeof scratch, &err);
    TEST_ASSERT_TRUE_MESSAGE(s != CDB_OK, "tiny wire scratch must fail closed");
}

/* A valid plan that cannot build its operator tree in a tiny exec arena fails
 * closed on open (no partial cursor handed back). */
static void test_query_tiny_exec_scratch_fail_closed(void)
{
    cdb_exec_cursor cur;
    cdb_compile_error err;
    uint8_t tiny[8];
    cdb_status s;
    make_books();
    memset(&err, 0, sizeof err);
    s = cdb_db_query(&db, "SELECT title FROM Scan(\"books\")",
                     strlen("SELECT title FROM Scan(\"books\")"), NULL, 0, wire_scratch,
                     sizeof wire_scratch, &cur, tiny, sizeof tiny, &err);
    TEST_ASSERT_TRUE_MESSAGE(s != CDB_OK, "tiny exec scratch must fail closed");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_query_with_param);
    RUN_TEST(test_query_empty_result);
    RUN_TEST(test_query_scratch_reuse);
    RUN_TEST(test_query_null_text);
    RUN_TEST(test_query_null_db);
    RUN_TEST(test_query_null_exec_scratch);
    RUN_TEST(test_query_zero_exec_cap);
    RUN_TEST(test_query_tiny_wire_scratch_fail_closed);
    RUN_TEST(test_query_tiny_exec_scratch_fail_closed);
    return UNITY_END();
}
