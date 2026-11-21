/* combolite-core #34: TRAVERSE executor operator wired to the real link store
 * (cdb_link_list). A bounded BFS from each input seed honours direction and
 * max_hops with a global visited set for cycle termination, emitting the real
 * shortest-hop $depth per reached node; red->green vs. the fixed
 * $depth=min_hops stub.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_doc.h"
#include "cdb_exec.h"
#include "cdb_faultenv.h"
#include "cdb_link.h"
#include "cdb_query.h"
#include "cdb_ts.h"

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
static uint8_t doc_stage[4096];
static uint8_t idx_stage[16u * 1024u];
static uint8_t vec_buffers[3u * PAGE];
static uint8_t table_buffers[4u * PAGE];
static uint8_t col_work[64u * 1024u];
static uint8_t ts_buffers[3u * PAGE];
static uint8_t ts_work[(CDB_TS_BLOCK_MAX_POINTS + 1u) * sizeof(cdb_ts_point)];
static cdb_db_config cfg;
static cdb_db db;

static uint8_t scratch[256u * 1024u];
static uint8_t wire[2048];
static cdb_exec_cursor cur;

static uint64_t ROOTS, NODESTORE, EDGE;
static uint64_t R, A, B, X, D; /* entry IDs */

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
    cfg.table_buffers = table_buffers;
    cfg.col_work = col_work;
    cfg.col_work_size = sizeof col_work;
    cfg.ts_buffers = ts_buffers;
    cfg.ts_work = ts_work;
    cfg.ts_work_size = sizeof ts_work;
    cfg.durability = CDB_DURABILITY_FULL;

    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x34, sizeof h.db_id);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "trv", &cfg, &h));
}

void tearDown(void)
{
    cdb_db_close(&db);
}

static uint64_t insert_doc(uint64_t pool)
{
    uint8_t b[64];
    cdb_value_writer w;
    uint64_t e;
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_string(&w, "n", 1);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_doc_insert(&db, pool, NULL, 0, b, cdb_value_writer_len(&w), &e));
    return e;
}

static cdb_ref rref(uint64_t entry)
{
    return cdb_ref_entry(ROOTS, entry);
}
static cdb_ref nref(uint64_t entry)
{
    return cdb_ref_entry(NODESTORE, entry);
}

/* Graph:  X -> R -> A -> B -> A (cycle);  R -> D.
 * R is the only document in the "roots" pool (the single seed). */
static void make_graph(void)
{
    int found = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "roots", 5, CDB_MODEL_DOCUMENT, &ROOTS));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_db_create_store(&db, "nodes", 5, CDB_MODEL_DOCUMENT, &NODESTORE));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    R = insert_doc(ROOTS);
    A = insert_doc(NODESTORE);
    B = insert_doc(NODESTORE);
    X = insert_doc(NODESTORE);
    D = insert_doc(NODESTORE);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_define_type(&db, "edge", 4, CDB_CARD_N_M, 0,
                                                       CDB_LINK_ON_DELETE_TOMBSTONE, &EDGE));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_find_type(&db, "edge", 4, &EDGE, &found));
    TEST_ASSERT_TRUE(found);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_add(&db, EDGE, rref(R), nref(A), 1.0f, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_add(&db, EDGE, nref(A), nref(B), 1.0f, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_add(&db, EDGE, nref(B), nref(A), 1.0f, 1)); /* cycle */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_add(&db, EDGE, rref(R), nref(D), 1.0f, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_add(&db, EDGE, nref(X), rref(R), 1.0f, 1)); /* into R */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
}

static void open_traverse(uint8_t dir, uint64_t min_hops, uint64_t max_hops)
{
    cdb_query_writer qw;
    cdb_query_writer_init(&qw, wire, sizeof wire);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_query_write_traverse(&qw, "edge", 4, dir, min_hops, max_hops));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "roots", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_open(&cur, &db, wire, cdb_query_writer_len(&qw), NULL, 0,
                                                scratch, sizeof scratch));
}

/* One reached node, captured from the stream. */
typedef struct reached {
    uint64_t store;
    uint64_t entry;
    int64_t depth;
} reached;

static size_t drain(reached *out, size_t cap)
{
    cdb_exec_row row;
    size_t n = 0;
    int has = 0;
    while (1) {
        cdb_value v;
        int found = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, &row, &has));
        if (!has)
            break;
        TEST_ASSERT_TRUE(n < cap);
        TEST_ASSERT_EQUAL_INT(CDB_OK,
                              cdb_exec_row_get_field(&row, &cur.eval_ctx, "$depth", 6, &v, &found));
        TEST_ASSERT_TRUE(found);
        out[n].store = row.store_id;
        out[n].entry = row.entry_id;
        out[n].depth = v.as.i64;
        n++;
    }
    cdb_exec_close(&cur);
    return n;
}

/* The depth a (store, entry) was reached at, or -1 if absent (and asserts it
 * appears at most once: the global visited set emits each node once). */
static int64_t depth_of(const reached *r, size_t n, uint64_t store, uint64_t entry)
{
    int64_t depth = -1;
    size_t i, hits = 0;
    for (i = 0; i < n; i++) {
        if (r[i].store == store && r[i].entry == entry) {
            depth = r[i].depth;
            hits++;
        }
    }
    TEST_ASSERT_TRUE(hits <= 1);
    return depth;
}

/* AC5: forward multi-hop. Real shortest $depth per node, <= max_hops; a node
 * past max_hops is absent. */
static void test_forward_multihop_depths(void)
{
    reached r[32];
    size_t n;

    make_graph();
    open_traverse(CDB_TRAVERSE_FWD, 1, 3);
    n = drain(r, 32);

    TEST_ASSERT_EQUAL_INT64(1, depth_of(r, n, NODESTORE, A));  /* R->A */
    TEST_ASSERT_EQUAL_INT64(1, depth_of(r, n, NODESTORE, D));  /* R->D */
    TEST_ASSERT_EQUAL_INT64(2, depth_of(r, n, NODESTORE, B));  /* R->A->B */
    TEST_ASSERT_EQUAL_INT64(-1, depth_of(r, n, NODESTORE, X)); /* X is incoming only */
    TEST_ASSERT_EQUAL_INT64(-1, depth_of(r, n, ROOTS, R));     /* seed excluded (min_hops 1) */
    TEST_ASSERT_EQUAL_size_t(3, n);                            /* A, D, B only */
}

/* AC6: the cycle B->A terminates; A is emitted once at its shortest depth. */
static void test_cycle_terminates(void)
{
    reached r[32];
    size_t n;

    make_graph();
    open_traverse(CDB_TRAVERSE_FWD, 1, 3);
    n = drain(r, 32);
    /* depth_of asserts A appears at most once; it must be present at depth 1. */
    TEST_ASSERT_EQUAL_INT64(1, depth_of(r, n, NODESTORE, A));
}

/* AC5 edge: max_hops bounds reachability — only the 1-hop neighbours. */
static void test_max_hops_one(void)
{
    reached r[32];
    size_t n;

    make_graph();
    open_traverse(CDB_TRAVERSE_FWD, 1, 1);
    n = drain(r, 32);
    TEST_ASSERT_EQUAL_INT64(1, depth_of(r, n, NODESTORE, A));
    TEST_ASSERT_EQUAL_INT64(1, depth_of(r, n, NODESTORE, D));
    TEST_ASSERT_EQUAL_INT64(-1, depth_of(r, n, NODESTORE, B)); /* 2 hops, excluded */
    TEST_ASSERT_EQUAL_size_t(2, n);
}

/* AC7: fwd, rev and both reach different node sets on a directed graph. */
static void test_direction_differs(void)
{
    reached r[32];
    size_t n;

    make_graph();

    open_traverse(CDB_TRAVERSE_FWD, 1, 1);
    n = drain(r, 32);
    TEST_ASSERT_EQUAL_INT64(1, depth_of(r, n, NODESTORE, A));
    TEST_ASSERT_EQUAL_INT64(-1, depth_of(r, n, NODESTORE, X)); /* X is only incoming */

    open_traverse(CDB_TRAVERSE_REV, 1, 1);
    n = drain(r, 32);
    TEST_ASSERT_EQUAL_INT64(1, depth_of(r, n, NODESTORE, X)); /* X -> R */
    TEST_ASSERT_EQUAL_INT64(-1, depth_of(r, n, NODESTORE, A));
    TEST_ASSERT_EQUAL_size_t(1, n);

    open_traverse(CDB_TRAVERSE_BOTH, 1, 1);
    n = drain(r, 32);
    TEST_ASSERT_EQUAL_INT64(1, depth_of(r, n, NODESTORE, A)); /* out */
    TEST_ASSERT_EQUAL_INT64(1, depth_of(r, n, NODESTORE, D)); /* out */
    TEST_ASSERT_EQUAL_INT64(1, depth_of(r, n, NODESTORE, X)); /* in */
    TEST_ASSERT_EQUAL_size_t(3, n);
}

/* AC5 edge: min_hops 0 includes the seed itself at depth 0. */
static void test_min_hops_zero_includes_seed(void)
{
    reached r[32];
    size_t n;

    make_graph();
    open_traverse(CDB_TRAVERSE_FWD, 0, 0);
    n = drain(r, 32);
    TEST_ASSERT_EQUAL_INT64(0, depth_of(r, n, ROOTS, R));
    TEST_ASSERT_EQUAL_size_t(1, n);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_forward_multihop_depths);
    RUN_TEST(test_cycle_terminates);
    RUN_TEST(test_max_hops_one);
    RUN_TEST(test_direction_differs);
    RUN_TEST(test_min_hops_zero_includes_seed);
    return UNITY_END();
}
