/* combolite-core #34: TEXT_SEARCH executor operator wired to the real BM25
 * engine (cdb_doc_search / cdb_fts_search). Drives the operator over the query
 * wire (writers in cdb_query.h), exactly as the proc-VM OPEN_CURSOR path does,
 * against a live full-text index. Asserts real BM25 ranking and that the limit
 * yields the top-N; red->green vs. the fabricated score=1.0 stub.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_catalog.h"
#include "cdb_doc.h"
#include "cdb_exec.h"
#include "cdb_faultenv.h"
#include "cdb_query.h"

#define FCAP (1024u * 1024u)
#define PAGE_LOG2 10u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u

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
static uint8_t fts_buffers[3u * PAGE];
static cdb_fts_token fts_tokens[2u * PAGE];
static cdb_db_config cfg;
static cdb_db db;

static uint8_t scratch[256u * 1024u];
static uint8_t wire[2048];
static cdb_exec_cursor cur;

/* Entry IDs of the three indexed documents, by expected BM25 rank. */
static uint64_t POOL, E_HI, E_MID, E_LOW, F_TEXT;

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
    cfg.fts_buffers = fts_buffers;
    cfg.fts_tokens = fts_tokens;
    cfg.fts_tokens_cap = sizeof fts_tokens / sizeof fts_tokens[0];
    cfg.durability = CDB_DURABILITY_FULL;

    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x34, sizeof h.db_id);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "ts", &cfg, &h));
}

void tearDown(void)
{
    cdb_db_close(&db);
}

static uint64_t insert_text(const char *text)
{
    uint8_t b[256];
    cdb_value_writer w;
    uint64_t e;
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, F_TEXT);
    cdb_value_write_string(&w, text, strlen(text));
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_doc_insert(&db, POOL, NULL, 0, b, cdb_value_writer_len(&w), &e));
    return e;
}

/* notes(text): three docs matching "alpha" with decreasing BM25 (term
 * frequency and length normalization). E_HI: tf 3, short; E_MID: tf 1, short;
 * E_LOW: tf 1, long. */
static void make_notes(void)
{
    cdb_fts_config c;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "notes", 5, CDB_MODEL_DOCUMENT, &POOL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_catalog_field_id(&db.catalog, POOL, "text", 4, &F_TEXT));

    memset(&c, 0, sizeof c);
    c.paths[0].ids[0] = F_TEXT;
    c.paths[0].depth = 1;
    c.npaths = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_create_full_text(&db, POOL, &c));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    E_HI = insert_text("alpha alpha alpha");
    E_MID = insert_text("alpha beta");
    E_LOW = insert_text("alpha beta gamma delta epsilon zeta eta theta");
    (void)insert_text("beta gamma only no match here"); /* no "alpha" */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
}

static void open_search(uint8_t mode, uint64_t limit, const char *query)
{
    cdb_query_writer qw;
    cdb_query_writer_init(&qw, wire, sizeof wire);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_query_write_text_search(&qw, mode, limit, query, strlen(query), 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "notes", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, &db, wire, cdb_query_writer_len(&qw), NULL, 0,
                                                scratch, sizeof scratch));
}

static int next_row(cdb_exec_row *row)
{
    int has = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, row, &has));
    return has;
}

/* AC1: rows are ordered by real BM25 score, and the scores are not the
 * fabricated constant 1.0 (nor any single constant). */
static void test_bm25_ranking_is_real(void)
{
    cdb_exec_row row;
    float prev = 1e30f;
    uint64_t first = 0;
    size_t n = 0;
    int all_one = 1;

    make_notes();
    open_search(CDB_QUERY_FTS_ANY, 0, "alpha");
    while (next_row(&row)) {
        if (n == 0)
            first = row.entry_id;
        TEST_ASSERT_TRUE(row.score <= prev); /* non-increasing: best first */
        if (row.score != 1.0f)
            all_one = 0;
        prev = row.score;
        n++;
    }
    cdb_exec_close(&cur);

    TEST_ASSERT_EQUAL_size_t(3, n);        /* three docs contain "alpha" */
    TEST_ASSERT_EQUAL_UINT64(E_HI, first); /* highest tf ranks first */
    TEST_ASSERT_FALSE(all_one);            /* not the fabricated score=1.0 */
    TEST_ASSERT_TRUE(prev > 0.0f);         /* real positive BM25 scores */
}

/* AC2: a limit N below the match count returns exactly the top-N by BM25. */
static void test_limit_returns_top_n(void)
{
    cdb_exec_row row;
    uint64_t got[8];
    size_t n = 0;

    make_notes();
    open_search(CDB_QUERY_FTS_ANY, 2, "alpha");
    while (next_row(&row)) {
        TEST_ASSERT_TRUE(n < 8);
        got[n++] = row.entry_id;
    }
    cdb_exec_close(&cur);

    TEST_ASSERT_EQUAL_size_t(2, n); /* limit 2 of 3 matches */
    TEST_ASSERT_EQUAL_UINT64(E_HI, got[0]);
    TEST_ASSERT_EQUAL_UINT64(E_MID, got[1]);
}

/* AC12 edge: a query that matches nothing yields zero rows without crashing. */
static void test_empty_result(void)
{
    cdb_exec_row row;

    make_notes();
    open_search(CDB_QUERY_FTS_ANY, 0, "zzzznomatch");
    TEST_ASSERT_FALSE(next_row(&row));
    cdb_exec_close(&cur);
}

/* AC12 edge: limit 1 (the smallest capping limit) returns only the top hit. */
static void test_limit_one(void)
{
    cdb_exec_row row;

    make_notes();
    open_search(CDB_QUERY_FTS_ANY, 1, "alpha");
    TEST_ASSERT_TRUE(next_row(&row));
    TEST_ASSERT_EQUAL_UINT64(E_HI, row.entry_id);
    TEST_ASSERT_FALSE(next_row(&row));
    cdb_exec_close(&cur);
    (void)E_LOW;
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_bm25_ranking_is_real);
    RUN_TEST(test_limit_returns_top_n);
    RUN_TEST(test_empty_result);
    RUN_TEST(test_limit_one);
    return UNITY_END();
}
