/* combolite-core #34: VECTOR_SEARCH executor operator wired to the real ANN
 * engine (cdb_vec_search_mode / cdb_vec_search) over the neighbour graph.
 * Drives the operator over the query wire with a bounded-decoded near vector,
 * asserting real distance-ranked top-k and metric-dependent ordering;
 * red->green vs. the fabricated score=0.95 stub.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_exec.h"
#include "cdb_faultenv.h"
#include "cdb_query.h"
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
static uint8_t vec_buffers[3u * PAGE];
static cdb_db_config cfg;
static cdb_db db;

static uint8_t scratch[256u * 1024u];
static uint8_t wire[2048];
static cdb_exec_cursor cur;

static uint64_t COLL, E1, E2, E3, E4; /* vector entry IDs */

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
    cfg.vec_buffers = vec_buffers;
    cfg.durability = CDB_DURABILITY_FULL;

    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x34, sizeof h.db_id);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "vec", &cfg, &h));
}

void tearDown(void)
{
    cdb_db_close(&db);
}

/* Encodes a DIMS-float vector value into buf, returning its length. */
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
    uint64_t e;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_insert(&db, COLL, b, n, 0, 0, &e));
    return e;
}

/* A 4-D collection with four vectors: three axis-aligned unit-ish vectors and
 * one large all-ones vector. base measure Euclidean. */
static void make_vectors(void)
{
    cdb_vec_config c;
    static const float v1[DIMS] = {1.0f, 0.0f, 0.0f, 0.0f};
    static const float v2[DIMS] = {0.0f, 1.0f, 0.0f, 0.0f};
    static const float v3[DIMS] = {0.0f, 0.0f, 1.0f, 0.0f};
    static const float v4[DIMS] = {10.0f, 10.0f, 10.0f, 10.0f};

    memset(&c, 0, sizeof c);
    c.elem = CDB_VEC_F32;
    c.dims = DIMS;
    c.measure = CDB_VEC_EUCLIDEAN;
    c.model = "m";
    c.model_len = 1;
    c.model_version = "1";
    c.model_version_len = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_create(&db, "emb", 3, &c, &COLL));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    E1 = insert_vec(v1);
    E2 = insert_vec(v2);
    E3 = insert_vec(v3);
    E4 = insert_vec(v4);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));
}

static void open_vsearch(uint64_t k, uint8_t metric, const float *near)
{
    cdb_query_writer qw;
    uint8_t enc[128];
    size_t enc_len = encode_vec(enc, sizeof enc, near);

    cdb_query_writer_init(&qw, wire, sizeof wire);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_vector_search(&qw, "v", 1, k, metric));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "emb", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(&qw, enc, enc_len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, &db, wire, cdb_query_writer_len(&qw), NULL, 0,
                                                scratch, sizeof scratch));
}

static int next_row(cdb_exec_row *row)
{
    int has = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, row, &has));
    return has;
}

/* AC3: top-k by the chosen metric's distance, ascending, scores not 0.95. */
static void test_euclidean_topk_is_real(void)
{
    cdb_exec_row row;
    static const float q[DIMS] = {0.9f, 0.05f, 0.0f, 0.0f};
    uint64_t got[8];
    float prev = -1.0f;
    size_t n = 0;
    int any_095 = 0;

    make_vectors();
    open_vsearch(3, CDB_QUERY_METRIC_EUCLIDEAN, q);
    while (next_row(&row)) {
        TEST_ASSERT_TRUE(n < 8);
        TEST_ASSERT_TRUE(row.score >= prev); /* non-decreasing distance: nearest first */
        if (row.score == 0.95f)
            any_095 = 1;
        prev = row.score;
        got[n++] = row.entry_id;
    }
    cdb_exec_close(&cur);

    TEST_ASSERT_EQUAL_size_t(3, n);       /* top-3 of 4 */
    TEST_ASSERT_EQUAL_UINT64(E1, got[0]); /* nearest to q is v1 */
    TEST_ASSERT_EQUAL_UINT64(E2, got[1]); /* then v2 */
    TEST_ASSERT_EQUAL_UINT64(E3, got[2]); /* then v3 */
    TEST_ASSERT_FALSE(any_095);           /* no fabricated 0.95 */
}

/* AC4: the metric changes the ordering. Query aligned with v1's direction:
 * cosine makes v1 nearest; dot (-dot, larger magnitude closer) makes v4
 * nearest. */
static void test_metric_changes_ordering(void)
{
    cdb_exec_row row;
    static const float q[DIMS] = {2.0f, 0.0f, 0.0f, 0.0f};
    uint64_t cos_first, dot_first;

    make_vectors();

    open_vsearch(1, CDB_QUERY_METRIC_COSINE, q);
    TEST_ASSERT_TRUE(next_row(&row));
    cos_first = row.entry_id;
    cdb_exec_close(&cur);

    open_vsearch(1, CDB_QUERY_METRIC_DOT, q);
    TEST_ASSERT_TRUE(next_row(&row));
    dot_first = row.entry_id;
    cdb_exec_close(&cur);

    TEST_ASSERT_EQUAL_UINT64(E1, cos_first); /* closest direction */
    TEST_ASSERT_EQUAL_UINT64(E4, dot_first); /* largest projection */
    TEST_ASSERT_TRUE(cos_first != dot_first);
}

/* AC12 edge: k greater than the collection returns all available, no over-read. */
static void test_k_larger_than_collection(void)
{
    cdb_exec_row row;
    static const float q[DIMS] = {0.0f, 0.0f, 0.0f, 1.0f};
    size_t n = 0;

    make_vectors();
    open_vsearch(100, CDB_QUERY_METRIC_EUCLIDEAN, q);
    while (next_row(&row))
        n++;
    cdb_exec_close(&cur);
    TEST_ASSERT_EQUAL_size_t(4, n); /* all four vectors, no crash */
}

/* AC12 edge: k = 0 means unbounded (the wire contract), returns every vector. */
static void test_k_zero_unbounded(void)
{
    cdb_exec_row row;
    static const float q[DIMS] = {1.0f, 1.0f, 1.0f, 1.0f};
    size_t n = 0;

    make_vectors();
    open_vsearch(0, CDB_QUERY_METRIC_DEFAULT, q);
    while (next_row(&row))
        n++;
    cdb_exec_close(&cur);
    TEST_ASSERT_EQUAL_size_t(4, n);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_euclidean_topk_is_real);
    RUN_TEST(test_metric_changes_ordering);
    RUN_TEST(test_k_larger_than_collection);
    RUN_TEST(test_k_zero_unbounded);
    return UNITY_END();
}
