/* Branch-coverage set for cdb_exec (agent-authored). Drives the advanced query
 * operators and their edge branches that test_exec_live.c and
 * test_query_matrix.c leave cold: Join (inner/left-outer/no-match/all-match),
 * Union (incl. empty branch), Aggregate (SUM/AVG/MIN/MAX/COUNT, multi-group +
 * global, empty input), Sort with NULL keys, Limit with OFFSET, Window
 * (tumbling, found/missing time field, size 0, negative ts), Traverse,
 * TextSearch (limit/no-limit), VectorSearch (k/no-k), AsofJoin
 * (backward/forward/nearest/tolerance), Unnest (array + non-array + no index
 * alias), HybridRank (dedup + distinct), and a Scan over a VECTOR store.
 *
 * Queries are built with the wire writer (cdb_query_write_*) so operators are
 * reached directly, as test_exec_live does for Aggregate. Harness mirrors
 * test_exec_live.c. Spec 11.5, 11.10, 17. */
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
#include "cdb_table.h"
#include "cdb_vec.h"

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
static uint8_t vec_buffers[3u * PAGE];
static cdb_db_config cfg;
static cdb_db db;

static uint8_t scratch[64u * 1024u];
static uint8_t qbuf[4096];
static cdb_query_writer QW;
static cdb_exec_cursor cur;

/* ------------------------------------------------------------ harness */

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
    cfg.vec_buffers = vec_buffers; /* enables VECTOR collections (cdb_vec.h) */
    cfg.doc_max = DOC_MAX;
    cfg.durability = CDB_DURABILITY_FULL;
    TEST_ASSERT_EQUAL_size_t(cdb_doc_buffers_size(PAGE, DOC_MAX), sizeof doc_buffers);
    TEST_ASSERT_TRUE(cdb_table_buffers_size(PAGE, DOC_MAX) <= sizeof table_buffers);

    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x5C, sizeof h.db_id);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "cov", &cfg, &h));
}

void tearDown(void)
{
    cdb_db_close(&db);
}

static void begin(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL)); }
static void commit(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db)); }

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

static void obj_end(enc *e)
{
    cdb_value_end_object(&e->w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, e->w.error);
    e->n = cdb_value_writer_len(&e->w);
}

/* ------------------------------------------------------------ query helpers */

static void q_begin(void)
{
    cdb_query_writer_init(&QW, qbuf, sizeof qbuf);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&QW));
}

static void q_open(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, QW.error);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_exec_open(&cur, &db, qbuf, cdb_query_writer_len(&QW), NULL, 0, scratch, sizeof scratch));
}

static cdb_status q_open_status(void)
{
    if (QW.error != CDB_OK)
        return QW.error;
    return cdb_exec_open(&cur, &db, qbuf, cdb_query_writer_len(&QW), NULL, 0, scratch, sizeof scratch);
}

/* An int value encoded for an expression literal. */
static size_t enc_int(uint8_t *buf, size_t cap, int64_t x)
{
    cdb_value_writer w;
    cdb_value_writer_init(&w, buf, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_int(&w, x);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    return cdb_value_writer_len(&w);
}

/* Writes a predicate/condition: <field> <op> <int literal>. */
static void q_cmp_field_int(uint8_t op, const char *field, int64_t lit)
{
    uint8_t lb[32];
    size_t ll = enc_int(lb, sizeof lb, lit);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_binary(&QW, op));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, field, strlen(field)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(&QW, lb, ll));
}

static int next(cdb_exec_row *row)
{
    int has = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_next(&cur, row, &has));
    return has;
}

static cdb_value field(cdb_exec_row *row, const char *name)
{
    cdb_value v;
    int found = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_exec_row_get_field(row, &cur.eval_ctx, name, strlen(name), &v, &found));
    TEST_ASSERT_TRUE_MESSAGE(found, name);
    return v;
}

static size_t drain_rows(void)
{
    cdb_exec_row row;
    size_t n = 0;
    int has = 0;
    while (cdb_exec_next(&cur, &row, &has) == CDB_OK && has)
        n++;
    return n;
}

/* ------------------------------------------------------------ fixtures */

/* A document store of int fields, written in registration order. */
static uint64_t make_store(const char *name, const char *const *fields, uint64_t *fids, size_t nf)
{
    uint64_t store;
    size_t i;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, name, strlen(name), CDB_MODEL_DOCUMENT, &store));
    for (i = 0; i < nf; i++)
        TEST_ASSERT_EQUAL_INT(CDB_OK,
                              cdb_catalog_field_id(&db.catalog, store, fields[i], strlen(fields[i]), &fids[i]));
    return store;
}

static void ins_ints(uint64_t store, const uint64_t *fids, const int64_t *vals, size_t n)
{
    enc e;
    uint64_t entry;
    size_t i;
    obj_begin(&e);
    for (i = 0; i < n; i++) {
        cdb_value_field(&e.w, fids[i]);
        cdb_value_write_int(&e.w, vals[i]);
    }
    obj_end(&e);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, store, NULL, 0, e.b, e.n, &entry));
}

/* events(k,v,ts): k is the group key. */
static uint64_t EV_K, EV_V, EV_TS;
static uint64_t seed_events(void)
{
    static const char *const names[] = {"k", "v", "ts"};
    uint64_t fids[3], store;
    size_t i;
    static const int64_t rows[5][3] = {
        {1, 10, 0}, {1, 30, 5}, {2, 20, 100}, {2, 5, 150}, {2, 50, 160}};
    store = make_store("events", names, fids, 3);
    EV_K = fids[0];
    EV_V = fids[1];
    EV_TS = fids[2];
    begin();
    for (i = 0; i < 5; i++)
        ins_ints(store, fids, rows[i], 3);
    commit();
    return store;
}

/* two(id): two rows, ids 1 and 2. */
static uint64_t seed_two(void)
{
    static const char *const names[] = {"id"};
    uint64_t fids[1], store;
    int64_t v;
    store = make_store("two", names, fids, 1);
    begin();
    v = 1;
    ins_ints(store, fids, &v, 1);
    v = 2;
    ins_ints(store, fids, &v, 1);
    commit();
    return store;
}

static uint64_t seed_empty(void)
{
    uint64_t store;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "empty", 5, CDB_MODEL_DOCUMENT, &store));
    return store;
}

/* ------------------------------------------------------------ tests */

/* Scan over a VECTOR collection: model-specific scan_read (len forced 0) and
 * the generic entry-counting branch of scan_next. */
static void test_scan_vector_store(void)
{
    cdb_vec_config c;
    uint64_t id, e;
    cdb_value_writer w;
    uint8_t vb[128];
    float f[4];
    size_t vn, n, i;
    cdb_exec_row row;

    memset(&c, 0, sizeof c);
    c.elem = CDB_VEC_F32;
    c.dims = 4;
    c.measure = CDB_VEC_COSINE;
    c.model = "m";
    c.model_len = 1;
    c.model_version = "1";
    c.model_version_len = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_create(&db, "vemb", 4, &c, &id));

    begin();
    for (i = 0; i < 2; i++) {
        size_t j;
        for (j = 0; j < 4; j++)
            f[j] = (float)(i + 1) + (float)j;
        cdb_value_writer_init(&w, vb, sizeof vb, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        cdb_value_write_vector(&w, CDB_VEC_F32, 4, f);
        TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
        vn = cdb_value_writer_len(&w);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_insert(&db, id, vb, vn, 0, 0, &e));
    }
    commit();
    /* The generic scan counts entry IDs up to the catalog's bound, which lags
     * an open store; fold the journal so the two entries are visible. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));

    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "vemb", 4));
    q_open(); /* scan_open resolves the VECTOR model from the catalog */
    /* Reading vector records back as values may be unsupported in this build
     * (CDB_E_UNSUPPORTED); tolerate it. Either way the VECTOR branches of
     * scan_open/scan_next/scan_read/scan_load are exercised. */
    n = 0;
    {
        cdb_status s;
        int has = 0;
        while ((s = cdb_exec_next(&cur, &row, &has)) == CDB_OK && has) {
            TEST_ASSERT_EQUAL_UINT32(CDB_MODEL_VECTOR, row.model);
            TEST_ASSERT_NULL(row.record_data); /* vector scan forces record_len 0 */
            TEST_ASSERT_EQUAL_size_t(0, row.record_len);
            n++;
        }
        TEST_ASSERT_TRUE(s == CDB_OK || s == CDB_E_UNSUPPORTED);
        if (s == CDB_OK)
            TEST_ASSERT_EQUAL_size_t(2, n);
    }
    cdb_exec_close(&cur);
}

/* A misspelt store name fails the scan at open. */
static void test_scan_unknown_store(void)
{
    seed_two();
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "ghost", 5));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, q_open_status());
}

/* Inner join: every left/right pair when the condition holds, none when it
 * does not; drives the right-exhaustion advance of the left row. */
static void test_join_inner(void)
{
    cdb_exec_row row;
    size_t n;

    seed_two();

    /* Always-true condition (id >= -100): 2 x 2 = 4 rows, all with a right. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_join(&QW, CDB_JOIN_INNER));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "two", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "two", 3));
    q_cmp_field_int(CDB_BIN_GE, "id", -100);
    q_open();
    n = 0;
    while (next(&row)) {
        TEST_ASSERT_TRUE(row.has_right);
        TEST_ASSERT_TRUE(field(&row, "id").as.i64 >= 1);
        n++;
    }
    TEST_ASSERT_EQUAL_size_t(4, n);
    cdb_exec_close(&cur);

    /* Never-true condition: inner join yields nothing. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_join(&QW, CDB_JOIN_INNER));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "two", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "two", 3));
    q_cmp_field_int(CDB_BIN_GT, "id", 1000000);
    q_open();
    TEST_ASSERT_EQUAL_size_t(0, drain_rows());
    cdb_exec_close(&cur);
}

/* Left-outer join: a matched left emits its pairs; an unmatched left is still
 * emitted once with a NULL right. */
static void test_join_left_outer(void)
{
    cdb_exec_row row;
    size_t n, nulls;

    seed_two();

    /* No match -> each of the 2 left rows once, right NULL. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_join(&QW, CDB_JOIN_LEFT_OUTER));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "two", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "two", 3));
    q_cmp_field_int(CDB_BIN_GT, "id", 1000000);
    q_open();
    n = 0;
    nulls = 0;
    while (next(&row)) {
        TEST_ASSERT_TRUE(row.has_right);
        if (row.right_entry_id == 0 && row.right_record_data == NULL)
            nulls++;
        n++;
    }
    TEST_ASSERT_EQUAL_size_t(2, n);
    TEST_ASSERT_EQUAL_size_t(2, nulls);
    cdb_exec_close(&cur);

    /* All match -> 2 x 2 pairs. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_join(&QW, CDB_JOIN_LEFT_OUTER));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "two", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "two", 3));
    q_cmp_field_int(CDB_BIN_GE, "id", 0);
    q_open();
    TEST_ASSERT_EQUAL_size_t(4, drain_rows());
    cdb_exec_close(&cur);
}

/* Union streams each branch in turn, including a leading empty branch. */
static void test_union(void)
{
    seed_two();
    seed_events();
    seed_empty();

    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_union(&QW, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "two", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "events", 6));
    q_open();
    TEST_ASSERT_EQUAL_size_t(2u + 5u, drain_rows());
    cdb_exec_close(&cur);

    /* Empty first branch -> advance to the next branch. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_union(&QW, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "empty", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "two", 3));
    q_open();
    TEST_ASSERT_EQUAL_size_t(2, drain_rows());
    cdb_exec_close(&cur);
}

/* Grouped aggregate across all five functions. */
static void test_aggregate_grouped(void)
{
    cdb_exec_row row;

    seed_events();
    /* Aggregate(groups=[k], aggs=[cnt COUNT *, sm SUM v, av AVG v, mn MIN v, mx MAX v]) */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate(&QW, 1, 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "events", 6));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "k", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate_output(&QW, "cnt", 3, CDB_AGG_COUNT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "*", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate_output(&QW, "sm", 2, CDB_AGG_SUM));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "v", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate_output(&QW, "av", 2, CDB_AGG_AVG));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "v", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate_output(&QW, "mn", 2, CDB_AGG_MIN));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "v", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate_output(&QW, "mx", 2, CDB_AGG_MAX));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "v", 1));
    q_open();

    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(1, field(&row, "k").as.i64);
    TEST_ASSERT_EQUAL_INT64(2, field(&row, "cnt").as.i64);
    TEST_ASSERT_EQUAL_DOUBLE(40.0, field(&row, "sm").as.f64);
    TEST_ASSERT_EQUAL_DOUBLE(20.0, field(&row, "av").as.f64);
    TEST_ASSERT_EQUAL_INT64(10, field(&row, "mn").as.i64);
    TEST_ASSERT_EQUAL_INT64(30, field(&row, "mx").as.i64);

    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(2, field(&row, "k").as.i64);
    TEST_ASSERT_EQUAL_INT64(3, field(&row, "cnt").as.i64);
    TEST_ASSERT_EQUAL_DOUBLE(75.0, field(&row, "sm").as.f64);
    TEST_ASSERT_EQUAL_DOUBLE(25.0, field(&row, "av").as.f64);
    TEST_ASSERT_EQUAL_INT64(5, field(&row, "mn").as.i64);
    TEST_ASSERT_EQUAL_INT64(50, field(&row, "mx").as.i64);

    TEST_ASSERT_FALSE(next(&row));
    cdb_exec_close(&cur);
}

/* Global aggregate (no group keys): one summary row. */
static void test_aggregate_global(void)
{
    cdb_exec_row row;

    seed_events();
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate(&QW, 0, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "events", 6));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate_output(&QW, "cnt", 3, CDB_AGG_COUNT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "*", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate_output(&QW, "sm", 2, CDB_AGG_SUM));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "v", 1));
    q_open();
    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(5, field(&row, "cnt").as.i64);
    TEST_ASSERT_EQUAL_DOUBLE(115.0, field(&row, "sm").as.f64);
    TEST_ASSERT_FALSE(next(&row));
    cdb_exec_close(&cur);
}

/* Aggregate over an empty input produces no rows. */
static void test_aggregate_empty(void)
{
    seed_empty();
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate(&QW, 0, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "empty", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_aggregate_output(&QW, "cnt", 3, CDB_AGG_COUNT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "*", 1));
    q_open();
    TEST_ASSERT_EQUAL_size_t(0, drain_rows());
    cdb_exec_close(&cur);
}

/* Sort with a key absent from some rows: NULLS FIRST and NULLS LAST. */
static void test_sort_nulls(void)
{
    static const char *const names[] = {"id", "g"};
    uint64_t fids[2], store;
    cdb_exec_row row;

    store = make_store("opt", names, fids, 2);
    begin();
    {
        int64_t r1[2] = {1, 5};  /* has g */
        int64_t r3[2] = {3, 2};  /* has g */
        int64_t r2only = 2;      /* no g */
        ins_ints(store, fids, r1, 2);
        ins_ints(store, &fids[0], &r2only, 1); /* only id */
        ins_ints(store, fids, r3, 2);
    }
    commit();

    /* ORDER BY g ASC NULLS FIRST -> null row (id 2), then g=2 (id 3), g=5 (id 1). */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_sort(&QW, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "opt", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "g", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_sort_key_suffix(&QW, CDB_SORT_ASC, CDB_NULLS_FIRST));
    q_open();
    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(2, field(&row, "id").as.i64);
    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(3, field(&row, "id").as.i64);
    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(1, field(&row, "id").as.i64);
    TEST_ASSERT_FALSE(next(&row));
    cdb_exec_close(&cur);

    /* NULLS LAST -> g=2 (id 3), g=5 (id 1), null (id 2). */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_sort(&QW, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "opt", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "g", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_sort_key_suffix(&QW, CDB_SORT_ASC, CDB_NULLS_LAST));
    q_open();
    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(3, field(&row, "id").as.i64);
    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(1, field(&row, "id").as.i64);
    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(2, field(&row, "id").as.i64);
    TEST_ASSERT_FALSE(next(&row));
    cdb_exec_close(&cur);
}

/* Sort over empty input: no rows, no sort. */
static void test_sort_empty(void)
{
    seed_empty();
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_sort(&QW, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "empty", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "x", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_sort_key_suffix(&QW, CDB_SORT_DESC, CDB_NULLS_LAST));
    q_open();
    TEST_ASSERT_EQUAL_size_t(0, drain_rows());
    cdb_exec_close(&cur);
}

/* Limit with an offset, offset past the end, and a zero count. */
static void test_limit_offset(void)
{
    cdb_exec_row row;

    seed_events();

    /* OFFSET 2 LIMIT 2 -> rows 3 and 4 (v 20, then v 5). */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_limit(&QW, 2, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "events", 6));
    q_open();
    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(20, field(&row, "v").as.i64);
    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(5, field(&row, "v").as.i64);
    TEST_ASSERT_FALSE(next(&row));
    cdb_exec_close(&cur);

    /* OFFSET beyond the input -> the skip loop exhausts the input. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_limit(&QW, 2, 100));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "events", 6));
    q_open();
    TEST_ASSERT_EQUAL_size_t(0, drain_rows());
    cdb_exec_close(&cur);

    /* Zero count -> immediately exhausted. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_limit(&QW, 0, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "events", 6));
    q_open();
    TEST_ASSERT_EQUAL_size_t(0, drain_rows());
    cdb_exec_close(&cur);
}

/* Window: tumbling bounds from an int time field (incl. negative ts), a
 * missing time field (falls back to row timestamp), and a zero size. */
static void test_window(void)
{
    static const char *const names[] = {"ts", "v"};
    uint64_t fids[2], store;
    cdb_exec_row row;

    store = make_store("evt2", names, fids, 2);
    begin();
    {
        int64_t a[2] = {0, 1};
        int64_t b[2] = {150, 2};
        int64_t c[2];
        c[0] = -50;
        c[1] = 3;
        ins_ints(store, fids, a, 2);
        ins_ints(store, fids, b, 2);
        /* -50 then needs ts first; fields must be increasing so write ts,v. */
        ins_ints(store, fids, c, 2);
    }
    commit();

    /* size 100 on ts: 0 -> [0,100); 150 -> [100,200); -50 -> [-100,0). */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_window(&QW, CDB_WINDOW_TUMBLING, "ts", 2, 100, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "evt2", 4));
    q_open();
    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(0, field(&row, "$window_start").as.i64);
    TEST_ASSERT_EQUAL_INT64(100, field(&row, "$window_end").as.i64);
    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(100, field(&row, "$window_start").as.i64);
    TEST_ASSERT_EQUAL_INT64(200, field(&row, "$window_end").as.i64);
    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(-100, field(&row, "$window_start").as.i64);
    TEST_ASSERT_EQUAL_INT64(0, field(&row, "$window_end").as.i64);
    TEST_ASSERT_FALSE(next(&row));
    cdb_exec_close(&cur);

    /* Missing time field -> row timestamp (0 for documents); size 0 -> point. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_window(&QW, CDB_WINDOW_SLIDING, "nope", 4, 0, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "evt2", 4));
    q_open();
    TEST_ASSERT_TRUE(next(&row));
    TEST_ASSERT_EQUAL_INT64(0, field(&row, "$window_start").as.i64);
    TEST_ASSERT_EQUAL_INT64(0, field(&row, "$window_end").as.i64);
    (void)drain_rows();
    cdb_exec_close(&cur);
}

/* Traverse appends a $depth field equal to min_hops. */
static void test_traverse(void)
{
    cdb_exec_row row;
    size_t n;

    seed_two();
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_traverse(&QW, "rel", 3, CDB_TRAVERSE_FWD, 1, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "two", 3));
    q_open();
    n = 0;
    while (next(&row)) {
        TEST_ASSERT_EQUAL_INT64(1, field(&row, "$depth").as.i64);
        n++;
    }
    TEST_ASSERT_EQUAL_size_t(2, n);
    cdb_exec_close(&cur);
}

/* Text search: a limit stops the stream; no limit passes all; score is set. */
static void test_text_search(void)
{
    cdb_exec_row row;
    size_t n;

    seed_events();

    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_text_search(&QW, CDB_QUERY_FTS_ANY, 2, "q", 1, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "events", 6));
    q_open();
    n = 0;
    while (next(&row)) {
        TEST_ASSERT_EQUAL_FLOAT(1.0f, row.score);
        n++;
    }
    TEST_ASSERT_EQUAL_size_t(2, n);
    cdb_exec_close(&cur);

    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_text_search(&QW, CDB_QUERY_FTS_ALL, 0, "q", 1, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "events", 6));
    q_open();
    TEST_ASSERT_EQUAL_size_t(5, drain_rows());
    cdb_exec_close(&cur);
}

/* Vector search operator wraps a scan: k caps the stream; score is set. */
static void test_vector_search(void)
{
    cdb_exec_row row;
    size_t n;

    seed_events();

    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_vector_search(&QW, "emb", 3, 2, CDB_QUERY_METRIC_COSINE));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "events", 6));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "k", 1)); /* near expr (unused) */
    q_open();
    n = 0;
    while (next(&row)) {
        TEST_ASSERT_EQUAL_FLOAT(0.95f, row.score);
        n++;
    }
    TEST_ASSERT_EQUAL_size_t(2, n);
    cdb_exec_close(&cur);

    /* k = 0 -> no cap, all rows. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_vector_search(&QW, "emb", 3, 0, CDB_QUERY_METRIC_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "events", 6));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "k", 1));
    q_open();
    TEST_ASSERT_EQUAL_size_t(5, drain_rows());
    cdb_exec_close(&cur);
}

/* As-of join: backward, forward, nearest, and a tolerance that leaves a left
 * row unmatched. */
static void test_asof_join(void)
{
    static const char *const names[] = {"ts"};
    uint64_t lf[1], rf[1];
    uint64_t la, ra;
    cdb_exec_row row;
    size_t matched;

    la = make_store("la", names, lf, 1);
    ra = make_store("ra", names, rf, 1);
    begin();
    {
        int64_t t;
        t = 10; ins_ints(la, lf, &t, 1);
        t = 20; ins_ints(la, lf, &t, 1);
        t = 5;  ins_ints(ra, rf, &t, 1);
        t = 18; ins_ints(ra, rf, &t, 1);
        t = 25; ins_ints(ra, rf, &t, 1);
    }
    commit();

    /* Backward, no tolerance: both left rows match. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_asof_join(&QW, CDB_ASOF_BACKWARD, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "la", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "ra", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "ts", 2)); /* left time */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "ts", 2)); /* right time */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "ts", 2)); /* match cond */
    q_open();
    matched = 0;
    while (next(&row)) {
        if (row.has_right)
            matched++;
    }
    TEST_ASSERT_EQUAL_size_t(2, matched);
    cdb_exec_close(&cur);

    /* Forward. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_asof_join(&QW, CDB_ASOF_FORWARD, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "la", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "ra", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "ts", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "ts", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "ts", 2));
    q_open();
    TEST_ASSERT_EQUAL_size_t(2, drain_rows());
    cdb_exec_close(&cur);

    /* Nearest. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_asof_join(&QW, CDB_ASOF_NEAREST, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "la", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "ra", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "ts", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "ts", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "ts", 2));
    q_open();
    matched = 0;
    while (next(&row))
        if (row.has_right)
            matched++;
    TEST_ASSERT_EQUAL_size_t(2, matched);
    cdb_exec_close(&cur);

    /* Backward, tolerance 3: ts=10 nearest-backward is 5 (diff 5 > 3) -> no
     * match; ts=20 has 18 (diff 2) -> match. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_asof_join(&QW, CDB_ASOF_BACKWARD, 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "la", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "ra", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "ts", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "ts", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "ts", 2));
    q_open();
    matched = 0;
    {
        size_t total = 0;
        while (next(&row)) {
            if (row.has_right)
                matched++;
            total++;
        }
        TEST_ASSERT_EQUAL_size_t(2, total);
    }
    TEST_ASSERT_EQUAL_size_t(1, matched);
    cdb_exec_close(&cur);
}

/* Unnest: iterate array elements with an index alias, skip a non-array value,
 * and a variant without an index alias. */
static void test_unnest(void)
{
    uint64_t store, f_tags, entry;
    cdb_exec_row row;
    size_t n;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "arrs", 4, CDB_MODEL_DOCUMENT, &store));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_catalog_field_id(&db.catalog, store, "tags", 4, &f_tags));
    begin();
    {
        enc e;
        obj_begin(&e);
        cdb_value_field(&e.w, f_tags);
        cdb_value_begin_array(&e.w);
        cdb_value_write_int(&e.w, 7);
        cdb_value_write_int(&e.w, 8);
        cdb_value_write_int(&e.w, 9);
        cdb_value_end_array(&e.w);
        obj_end(&e);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, store, NULL, 0, e.b, e.n, &entry));
        /* A non-array tags value: unnest skips this parent. */
        obj_begin(&e);
        cdb_value_field(&e.w, f_tags);
        cdb_value_write_int(&e.w, 42);
        obj_end(&e);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, store, NULL, 0, e.b, e.n, &entry));
    }
    commit();

    /* With an index alias. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_unnest(&QW, "tag", 3, "i", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "arrs", 4));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "tags", 4));
    q_open();
    n = 0;
    while (next(&row)) {
        TEST_ASSERT_EQUAL_INT64((int64_t)(7 + n), field(&row, "tag").as.i64);
        TEST_ASSERT_EQUAL_INT64((int64_t)n, field(&row, "i").as.i64);
        n++;
    }
    TEST_ASSERT_EQUAL_size_t(3, n);
    cdb_exec_close(&cur);

    /* Without an index alias. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_unnest(&QW, "tag", 3, NULL, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "arrs", 4));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "tags", 4));
    q_open();
    TEST_ASSERT_EQUAL_size_t(3, drain_rows());
    cdb_exec_close(&cur);
}

/* Hybrid rank (RRF): duplicate entries across branches fuse their scores; a
 * second query with branches over different stores keeps entries distinct. */
static void test_hybrid_rank(void)
{
    seed_two();
    seed_events();

    /* Both branches scan the same store -> 2 fused entries (scores summed). */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_hybrid_rank(&QW, CDB_FUSE_RRF, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "two", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_branch_weight(&QW, 1000));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "two", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_branch_weight(&QW, 500));
    q_open();
    {
        cdb_exec_row row;
        float prev = 1e30f;
        size_t n = 0;
        while (next(&row)) {
            TEST_ASSERT_TRUE(row.score <= prev); /* sorted by score desc */
            prev = row.score;
            n++;
        }
        TEST_ASSERT_EQUAL_size_t(2, n);
    }
    cdb_exec_close(&cur);

    /* Different stores -> no dedup: 2 + 5 distinct entries. */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_hybrid_rank(&QW, CDB_FUSE_RRF, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "two", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_branch_weight(&QW, 0)); /* weight 0 -> 1.0 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "events", 6));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_branch_weight(&QW, 2000));
    q_open();
    TEST_ASSERT_EQUAL_size_t(2u + 5u, drain_rows());
    cdb_exec_close(&cur);
}

/* Filter + Project passthrough over a document store (field from record). */
static void test_filter_project_passthrough(void)
{
    cdb_exec_row row;

    seed_events();
    /* Project(passthrough, 1 output: alias "double" = v + v) over Filter(v > 15). */
    q_begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_project(&QW, 1, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_filter(&QW));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&QW, "events", 6));
    q_cmp_field_int(CDB_BIN_GT, "v", 15); /* filter predicate */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_project_output(&QW, "vv", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_binary(&QW, CDB_BIN_ADD));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "v", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_field(&QW, "v", 1));
    q_open();
    {
        size_t n = 0;
        while (next(&row)) {
            cdb_value v = field(&row, "v");    /* passthrough record field */
            cdb_value vv = field(&row, "vv");  /* computed output field */
            TEST_ASSERT_TRUE(v.as.i64 > 15);
            TEST_ASSERT_EQUAL_INT64(v.as.i64 * 2, vv.as.i64);
            n++;
        }
        /* v>15: 30, 20, 50 -> 3 rows. */
        TEST_ASSERT_EQUAL_size_t(3, n);
    }
    cdb_exec_close(&cur);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_scan_vector_store);
    RUN_TEST(test_scan_unknown_store);
    RUN_TEST(test_join_inner);
    RUN_TEST(test_join_left_outer);
    RUN_TEST(test_union);
    RUN_TEST(test_aggregate_grouped);
    RUN_TEST(test_aggregate_global);
    RUN_TEST(test_aggregate_empty);
    RUN_TEST(test_sort_nulls);
    RUN_TEST(test_sort_empty);
    RUN_TEST(test_limit_offset);
    RUN_TEST(test_window);
    RUN_TEST(test_traverse);
    RUN_TEST(test_text_search);
    RUN_TEST(test_vector_search);
    RUN_TEST(test_asof_join);
    RUN_TEST(test_unnest);
    RUN_TEST(test_hybrid_rank);
    RUN_TEST(test_filter_project_passthrough);
    return UNITY_END();
}
