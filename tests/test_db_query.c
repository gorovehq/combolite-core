/* combolite-core #35:
 *   - Sub-feature C: the public cdb_db_query() text-query entry, end-to-end
 *     against a real database (compile CMBQL text -> run to a cursor), plus
 *     malformed-text fail-closed (AC9/AC10).
 *   - Sub-feature B (FR-B2): post-commit triggers actually FIRE in the live
 *     mutation+commit path. Registering a procedure + trigger on a store, then
 *     inserting a row and committing, runs the procedure (observable via the
 *     registry). This is red->green: before #35 nothing in src/ dispatched a
 *     trigger, so the procedure never ran.
 *
 * Hermetic: a real database backed by the in-memory fault environment. */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_compiler.h"
#include "cdb_eval.h"
#include "cdb_exec.h"
#include "cdb_faultenv.h"
#include "cdb_proc.h"
#include "cdb_table.h"
#include "cdb_trigger.h"

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
    memset(h.db_id, 0x5C, sizeof h.db_id);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "q35", &cfg, &h));
}

void tearDown(void) { cdb_db_close(&db); }

static void begin(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL)); }
static void commit(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db)); }

/* books: id int (primary key), title string, year int */
static uint64_t T, F_ID, F_TITLE, F_YEAR;

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

    begin();
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
    commit();
}

/* ---- Sub-feature C: cdb_db_query end-to-end ---- */

static void test_db_query_runs_text_to_cursor(void)
{
    cdb_exec_cursor cur;
    cdb_exec_row row;
    cdb_compile_error err;
    int has = 0;
    cdb_value v;
    int found = 0;

    make_books();
    memset(&err, 0, sizeof err);

    TEST_ASSERT_EQUAL_INT_MESSAGE(
        CDB_OK,
        cdb_db_query(&db, "SELECT title, year FROM Scan(\"books\") WHERE id == 1342",
                     strlen("SELECT title, year FROM Scan(\"books\") WHERE id == 1342"), NULL, 0,
                     wire_scratch, sizeof wire_scratch, &cur, scratch, sizeof scratch, &err),
        err.msg);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &row, &has));
    TEST_ASSERT_TRUE(has);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_exec_row_get_field(&row, &cur.eval_ctx, "title", 5, &v, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_STRING, v.type);
    TEST_ASSERT_EQUAL_size_t(strlen("Pride and Prejudice"), v.payload_len);
    TEST_ASSERT_EQUAL_MEMORY("Pride and Prejudice", v.payload, v.payload_len);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &row, &has));
    TEST_ASSERT_FALSE(has);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

/* A new-operator text query via the public entry ties sub-feature A to C. */
static void test_db_query_aggregate_text(void)
{
    cdb_exec_cursor cur;
    cdb_exec_row row;
    cdb_compile_error err;
    int has = 0;

    make_books();
    memset(&err, 0, sizeof err);

    TEST_ASSERT_EQUAL_INT_MESSAGE(
        CDB_OK,
        cdb_db_query(&db, "Scan(\"books\") | aggregate(n: count(*))",
                     strlen("Scan(\"books\") | aggregate(n: count(*))"), NULL, 0, wire_scratch,
                     sizeof wire_scratch, &cur, scratch, sizeof scratch, &err),
        err.msg);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &row, &has));
    TEST_ASSERT_TRUE(has); /* one aggregate row */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_close(&cur));
}

static void test_db_query_malformed_fail_closed(void)
{
    cdb_exec_cursor cur;
    cdb_compile_error err;
    cdb_status s;

    make_books();
    memset(&err, 0, sizeof err);
    s = cdb_db_query(&db, "Scan(\"books\") | not_a_stage(oops)",
                     strlen("Scan(\"books\") | not_a_stage(oops)"), NULL, 0, wire_scratch,
                     sizeof wire_scratch, &cur, scratch, sizeof scratch, &err);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, s);
    TEST_ASSERT_NOT_EQUAL(0, err.msg[0]); /* a typed diagnostic, no row data */
}

static void test_db_query_rejects_null_buffers(void)
{
    cdb_exec_cursor cur;
    cdb_compile_error err;
    memset(&err, 0, sizeof err);
    /* No wire scratch: fail closed (caller-owned buffers mandatory). */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_db_query(&db, "Scan(\"books\")", 13, NULL, 0, NULL, 0, &cur, scratch,
                                       sizeof scratch, &err));
}

/* ---- Sub-feature B (FR-B2): triggers fire on the live commit path ---- */

/* Build a proc that returns a constant int (observable the trigger ran). */
static size_t build_const_proc(uint8_t *bc, size_t cap, int64_t val)
{
    uint8_t lit[16];
    cdb_value_writer vw;
    cdb_proc_writer w;
    size_t lit_len;
    cdb_value_writer_init(&vw, lit, sizeof lit, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_int(&vw, val);
    lit_len = cdb_value_writer_len(&vw);
    cdb_proc_writer_init(&w, bc, cap, 4, 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_load_const(&w, 0, lit, lit_len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_return(&w, 0));
    return cdb_proc_writer_len(&w);
}

static void insert_one_book(int64_t id, const char *title, int64_t year)
{
    uint8_t b[256];
    cdb_value_writer w;
    uint64_t entry;
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, F_ID);
    cdb_value_write_int(&w, id);
    cdb_value_field(&w, F_TITLE);
    cdb_value_write_string(&w, title, strlen(title));
    cdb_value_field(&w, F_YEAR);
    cdb_value_write_int(&w, year);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_insert(&db, T, b, cdb_value_writer_len(&w), &entry));
}

static void test_trigger_fires_on_commit(void)
{
    uint8_t bc[128];
    size_t bclen;

    make_books();
    bclen = build_const_proc(bc, sizeof bc, 7777);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_register_proc(&db, "audit", 5, bc, bclen));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_trigger_register(&db, "books_ins", 9, T,
                                                          CDB_TRIGGER_AFTER_INSERT, "audit", 5, 8));

    TEST_ASSERT_EQUAL_INT(0, db.triggers.last_proc_ran);

    /* A mutation + commit on the watched store must run the procedure. */
    begin();
    insert_one_book(99, "Dracula", 1897);
    commit();

    TEST_ASSERT_EQUAL_INT(1, db.triggers.last_proc_ran);
    TEST_ASSERT_EQUAL_INT64(7777, db.triggers.last_proc_ret.as.i64);
}

/* An aborted mutation fires no trigger (fail-closed capture). */
static void test_trigger_not_fired_on_abort(void)
{
    uint8_t bc[128];
    size_t bclen;

    make_books();
    bclen = build_const_proc(bc, sizeof bc, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_register_proc(&db, "audit", 5, bc, bclen));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_trigger_register(&db, "books_ins", 9, T,
                                                          CDB_TRIGGER_AFTER_INSERT, "audit", 5, 8));

    begin();
    insert_one_book(100, "Moby Dick", 1851);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));

    TEST_ASSERT_EQUAL_INT(0, db.triggers.last_proc_ran);
}

/* A mutation on a non-watched store fires nothing. */
static void test_trigger_unmatched_store(void)
{
    uint8_t bc[128];
    size_t bclen;

    make_books();
    bclen = build_const_proc(bc, sizeof bc, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_register_proc(&db, "audit", 5, bc, bclen));
    /* Trigger on a different store id than books. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_trigger_register(&db, "other", 5, T + 999,
                                                          CDB_TRIGGER_AFTER_INSERT, "audit", 5, 8));
    begin();
    insert_one_book(101, "War and Peace", 1869);
    commit();
    TEST_ASSERT_EQUAL_INT(0, db.triggers.last_proc_ran);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_db_query_runs_text_to_cursor);
    RUN_TEST(test_db_query_aggregate_text);
    RUN_TEST(test_db_query_malformed_fail_closed);
    RUN_TEST(test_db_query_rejects_null_buffers);
    RUN_TEST(test_trigger_fires_on_commit);
    RUN_TEST(test_trigger_not_fired_on_abort);
    RUN_TEST(test_trigger_unmatched_store);
    return UNITY_END();
}
