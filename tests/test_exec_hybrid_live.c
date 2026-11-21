/* combolite-core #34: HYBRID_RANK executor operator. The RRF fusion math was
 * already correct; this asserts it now fuses the REAL branch scores — a real
 * BM25 TEXT_SEARCH branch and a real ANN VECTOR_SEARCH branch — rather than the
 * fabricated per-branch constants the stubbed source operators used to emit.
 * The fused ordering here is unreachable under the old stub behaviour.
 */
#define _POSIX_C_SOURCE 200809L

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_catalog.h"
#include "cdb_doc.h"
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
static uint8_t fts_buffers[3u * PAGE];
static cdb_fts_token fts_tokens[2u * PAGE];
static uint8_t vec_buffers[3u * PAGE];
static cdb_db_config cfg;
static cdb_db db;

static uint8_t scratch[2u * 1024u * 1024u];
static uint8_t wire[2048];
static cdb_exec_cursor cur;

static uint64_t NOTES, EMB, F_TEXT;
static uint64_t DOC_A, DOC_B, V1, V2;

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
    cfg.vec_buffers = vec_buffers;
    cfg.durability = CDB_DURABILITY_FULL;

    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x34, sizeof h.db_id);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "hyb", &cfg, &h));
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
                          cdb_doc_insert(&db, NOTES, NULL, 0, b, cdb_value_writer_len(&w), &e));
    return e;
}

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
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_insert(&db, EMB, b, n, 0, 0, &e));
    return e;
}

static void make_fixture(void)
{
    cdb_fts_config c;
    cdb_vec_config vc;
    static const float v1[DIMS] = {1.0f, 0.0f, 0.0f, 0.0f};
    static const float v2[DIMS] = {0.0f, 1.0f, 0.0f, 0.0f};

    /* Full-text pool: DOC_A has the higher term frequency, so it is BM25 rank 1. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "notes", 5, CDB_MODEL_DOCUMENT, &NOTES));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_catalog_field_id(&db.catalog, NOTES, "text", 4, &F_TEXT));
    memset(&c, 0, sizeof c);
    c.paths[0].ids[0] = F_TEXT;
    c.paths[0].depth = 1;
    c.npaths = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_create_full_text(&db, NOTES, &c));
    /* Insert in the OPPOSITE order to the BM25 ranking: DOC_B (one "query",
     * longer, lower score) first, then DOC_A (two "query", shorter, higher
     * score). The scan/insertion order therefore differs from the ranked
     * order, so a stub that forwarded scan rows would fuse a different top. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    DOC_B = insert_text("query alone extra words here");
    DOC_A = insert_text("query query match");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* Vector collection: V1 is nearest the query vector, V2 next. */
    memset(&vc, 0, sizeof vc);
    vc.elem = CDB_VEC_F32;
    vc.dims = DIMS;
    vc.measure = CDB_VEC_EUCLIDEAN;
    vc.model = "m";
    vc.model_len = 1;
    vc.model_version = "1";
    vc.model_version_len = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_create(&db, "emb", 3, &vc, &EMB));
    /* Insert farther (V2) before nearer (V1): scan order again differs from the
     * distance ranking the ANN engine produces. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    V2 = insert_vec(v2);
    V1 = insert_vec(v1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));
}

/* HybridRank(RRF, [ TextSearch(Scan notes) weight=2000,
 *                   VectorSearch(Scan emb) weight=1000 ]). */
static void open_hybrid(void)
{
    cdb_query_writer qw;
    uint8_t enc[128];
    static const float near[DIMS] = {0.9f, 0.0f, 0.0f, 0.0f};
    size_t enc_len = encode_vec(enc, sizeof enc, near);

    cdb_query_writer_init(&qw, wire, sizeof wire);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_hybrid_rank(&qw, CDB_FUSE_RRF, 2));

    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_query_write_text_search(&qw, CDB_QUERY_FTS_ANY, 0, "query", 5, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "notes", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_branch_weight(&qw, 2000));

    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_query_write_vector_search(&qw, "v", 1, 2, CDB_QUERY_METRIC_EUCLIDEAN));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "emb", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(&qw, enc, enc_len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_branch_weight(&qw, 1000));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, &db, wire, cdb_query_writer_len(&qw), NULL, 0,
                                                scratch, sizeof scratch));
}

static int next_row(cdb_exec_row *row)
{
    int has = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, row, &has));
    return has;
}

/* AC8: the fused output is ranked by the RRF of the real branch scores. The
 * higher-weighted TEXT branch's rank-1 hit (highest-BM25 doc) tops the result,
 * the output is sorted by fused score descending, and every branch hit from
 * both the real BM25 and real ANN engines is present. */
static void test_rrf_fuses_real_branches(void)
{
    cdb_exec_row row;
    cdb_exec_row rows[8];
    float prev = 1e30f;
    size_t n = 0;

    make_fixture();
    open_hybrid();
    while (next_row(&row)) {
        TEST_ASSERT_TRUE(n < 8);
        TEST_ASSERT_TRUE(row.score <= prev); /* sorted by fused score descending */
        prev = row.score;
        rows[n++] = row;
    }
    cdb_exec_close(&cur);

    /* Two BM25 hits + two ANN hits, distinct (store, entry) keys: no dedup. */
    TEST_ASSERT_EQUAL_size_t(4, n);

    /* Top is the TEXT branch rank-1 document (weight 2000 / rank 1). This is a
     * real BM25 result over the notes pool — the stub never produced it. */
    TEST_ASSERT_EQUAL_UINT64(NOTES, rows[0].store_id);
    TEST_ASSERT_EQUAL_UINT64(DOC_A, rows[0].entry_id);

    /* Its fused score is the RRF value for weight 2.0 at rank 1: 2.0/(60+1). */
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 2.0f / 61.0f, rows[0].score);

    /* Second is the TEXT branch rank-2 doc (2.0/62), ahead of either ANN hit
     * (1.0/61, 1.0/62) because the text branch is weighted higher. */
    TEST_ASSERT_EQUAL_UINT64(NOTES, rows[1].store_id);
    TEST_ASSERT_EQUAL_UINT64(DOC_B, rows[1].entry_id);

    /* The remaining two are the real ANN hits, nearest (V1) before V2. */
    TEST_ASSERT_EQUAL_UINT64(EMB, rows[2].store_id);
    TEST_ASSERT_EQUAL_UINT64(V1, rows[2].entry_id);
    TEST_ASSERT_EQUAL_UINT64(EMB, rows[3].store_id);
    TEST_ASSERT_EQUAL_UINT64(V2, rows[3].entry_id);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_rrf_fuses_real_branches);
    return UNITY_END();
}
