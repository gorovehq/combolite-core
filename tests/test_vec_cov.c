/* Coverage set for cdb_vec (agent-authored).
 *
 * Complements tests/test_vec.c (the behavioural suite) by exercising the
 * branches it leaves cold: the neighbour-graph machinery (create_graph,
 * refresh, neighbours, approximate/exact/auto search, bulk), the
 * accelerator mirrors (fake device), cdb_vec_work_size, cdb_vec_live_in_tx,
 * and a spread of argument/edge error paths. Every assertion is a confirmed
 * behaviour; the file is built under the project's strict warnings. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_doc.h"
#include "cdb_endian.h"
#include "cdb_fakeaccel.h"
#include "cdb_faultenv.h"
#include "cdb_vec.h"

#define FCAP (1536u * 1024u)
#define PAGE_LOG2 10u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define DIMS 16u
#define GK 8u

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 8192u];
static cdb_faultenv fe;
static cdb_env env;
static cdb_fakeaccel fake;

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[4096];
static uint8_t record_buf[2u * PAGE];
static uint8_t cat_work[24u * 1024u];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static uint8_t doc_buffers[8u * PAGE];
static uint8_t vec_buffers[3u * PAGE];
static uint8_t vec_work[64u * 1024u];
static cdb_db_config cfg;
static cdb_db db;

static int use_accel; /* when set, setUp installs the fake accelerator */

static void init_env(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 8192;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
    if (use_accel) {
        cdb_fakeaccel_init(&fake, &env);
        fake.noise = 0.0; /* exact distances, so comparisons are deterministic */
    }
}

void setUp(void)
{
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
    cfg.vec_work = vec_work;
    cfg.vec_work_size = sizeof vec_work;
    cfg.durability = CDB_DURABILITY_FULL;
    cfg.accel_min_bytes = 1;
}

void tearDown(void) {}

static cdb_status open_db(void)
{
    cdb_header h;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x5A, sizeof h.db_id);
    return cdb_db_open(&db, &env, "v", &cfg, &h);
}

/* ------------------------------------------------------------ vectors */

typedef struct vec {
    uint8_t enc[128];
    size_t n;
} vec;

static uint32_t rng = 20260101u;

static int next_int(int lo, int hi)
{
    rng = rng * 1103515245u + 12345u;
    return lo + (int)((rng >> 16) % (uint32_t)(hi - lo + 1));
}

static vec make_vec(cdb_vector_elem elem, int zero)
{
    vec v;
    cdb_value_writer w;
    float f[DIMS];
    int8_t i8[DIMS];
    uint8_t bits[DIMS / 8u];
    unsigned i;
    memset(bits, 0, sizeof bits);
    for (i = 0; i < DIMS; i++) {
        int k = zero ? 0 : next_int(-10, 10);
        if (elem == CDB_VEC_BINARY) {
            if (k > 0)
                bits[i / 8u] |= (uint8_t)(1u << (i % 8u));
        } else if (elem == CDB_VEC_I8) {
            i8[i] = (int8_t)k;
        } else {
            f[i] = (float)k / 4.0f;
        }
    }
    cdb_value_writer_init(&w, v.enc, sizeof v.enc, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    switch (elem) {
    case CDB_VEC_F32: cdb_value_write_vector(&w, elem, DIMS, f); break;
    case CDB_VEC_I8: cdb_value_write_vector(&w, elem, DIMS, i8); break;
    default: cdb_value_write_vector(&w, elem, DIMS, bits); break;
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    v.n = cdb_value_writer_len(&w);
    return v;
}

static uint64_t make_coll(const char *name, cdb_vector_elem elem, unsigned measure)
{
    cdb_vec_config c;
    uint64_t id;
    memset(&c, 0, sizeof c);
    c.elem = elem;
    c.dims = DIMS;
    c.measure = measure;
    c.model = "cov-embedder";
    c.model_len = 12;
    c.model_version = "2";
    c.model_version_len = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_create(&db, name, strlen(name), &c, &id));
    return id;
}

static uint64_t add(uint64_t coll, const vec *v)
{
    uint64_t e;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_insert(&db, coll, v->enc, v->n, 0, 0, &e));
    return e;
}

/* Fills coll with n random vectors in one transaction; returns the last ID. */
static uint64_t fill(uint64_t coll, unsigned n)
{
    unsigned i;
    uint64_t last = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    for (i = 0; i < n; i++) {
        vec v = make_vec(CDB_VEC_F32, 0);
        last = add(coll, &v);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    return last;
}

/* ------------------------------------------------------------ work_size */

static void test_cov_work_size(void)
{
    size_t none = cdb_vec_work_size(CDB_VEC_F32, DIMS, 0);
    size_t small = cdb_vec_work_size(CDB_VEC_F32, DIMS, GK);
    size_t big = cdb_vec_work_size(CDB_VEC_F32, DIMS, CDB_VEC_MAX_K);
    /* A graph needs work; more neighbours need at least as much; every shape
     * fits the configured buffer. */
    TEST_ASSERT_TRUE(small > 0);
    TEST_ASSERT_TRUE(big >= small);
    TEST_ASSERT_TRUE(small >= none);
    TEST_ASSERT_TRUE(big <= sizeof vec_work);
    TEST_ASSERT_TRUE(cdb_vec_work_size(CDB_VEC_I8, DIMS, GK) > 0);
    TEST_ASSERT_TRUE(cdb_vec_work_size(CDB_VEC_BINARY, DIMS, GK) > 0);
}

/* ------------------------------------------- create / live_in_tx / edges */

static void test_cov_create_and_live(void)
{
    vec v, other;
    uint64_t coll, pool, e, e2;
    int live, found;

    rng = 11u;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    coll = make_coll("c", CDB_VEC_F32, CDB_VEC_COSINE);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "docs", 4, CDB_MODEL_DOCUMENT, &pool));
    v = make_vec(CDB_VEC_F32, 0);
    other = make_vec(CDB_VEC_I8, 0);

    /* live_in_tx reports a vector that exists in the open transaction, and
     * the absence of one; it refuses a non-vector store. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    e = add(coll, &v);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_live_in_tx(&db, coll, e, &live));
    TEST_ASSERT_TRUE(live);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_live_in_tx(&db, coll, e + 100u, &live));
    TEST_ASSERT_FALSE(live);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_vec_live_in_tx(&db, pool, 1, &live));
    e2 = add(coll, &v);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_delete(&db, coll, e2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_live_in_tx(&db, coll, e2, &live));
    TEST_ASSERT_FALSE(live);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* Committed, live_in_tx also answers (no open transaction). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_live_in_tx(&db, coll, e, &live));
    TEST_ASSERT_TRUE(live);

    /* get edges: not found, buffer too small, success. */
    {
        uint8_t out[128];
        size_t len;
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_vec_get(&db, coll, 9999, out, sizeof out, &len, NULL, NULL));
        TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_vec_get(&db, coll, e, out, 4, &len, NULL, NULL));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_get(&db, coll, e, out, sizeof out, &len, NULL, NULL));
    }

    /* search argument edges. */
    {
        cdb_vec_hit hits[4];
        size_t n;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_search(&db, coll, v.enc, v.n, CDB_VEC_BASE, hits, 0, &n));
        TEST_ASSERT_EQUAL_size_t(0, n);
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                              cdb_vec_search_mode(&db, coll, v.enc, v.n, CDB_VEC_BASE, 99u, hits, 4, &n));
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                              cdb_vec_search(&db, coll, v.enc, v.n, 77u, hits, 4, &n)); /* bad measure */
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                              cdb_vec_search(&db, coll, other.enc, other.n, CDB_VEC_BASE, hits, 4, &n)); /* wrong type */
    }

    /* by_source edges: NULL entries with non-zero max, and a zero max. */
    {
        uint64_t es[2];
        size_t n;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_vec_by_source(&db, coll, 0, 0, NULL, 2, &n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_by_source(&db, coll, pool, 1, es, 0, &n));
        TEST_ASSERT_EQUAL_size_t(0, n);
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_find_store(&db, "c", 1, &coll, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ---------------------------------------------------- graph lifecycle */

static void test_cov_graph_lifecycle(void)
{
    uint64_t coll;
    cdb_vec_hit hits[GK + 4], ex[GK + 4];
    size_t n, left, ne, i;
    int fresh;

    rng = 31u;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    coll = make_coll("mem", CDB_VEC_F32, CDB_VEC_COSINE);
    (void)fill(coll, 50);

    /* A graph queues every vector; a small budget leaves some pending, then
     * budget 0 clears the rest. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_create_graph(&db, coll, GK));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_neighbours(&db, coll, 1, hits, GK, &n, &fresh));
    TEST_ASSERT_FALSE(fresh); /* still pending right after create */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_refresh(&db, coll, 5, &left));
    TEST_ASSERT_TRUE(left > 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_refresh(&db, coll, 0, &left));
    TEST_ASSERT_EQUAL_size_t(0, left);

    /* A fresh list is the K nearest, nearest first, never the entry itself. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_neighbours(&db, coll, 1, hits, GK + 4, &n, &fresh));
    TEST_ASSERT_TRUE(fresh);
    TEST_ASSERT_TRUE(n > 0 && n <= GK);
    for (i = 0; i < n; i++) {
        TEST_ASSERT_TRUE(hits[i].entry != 1);
        if (i > 0)
            TEST_ASSERT_TRUE(hits[i - 1].distance <= hits[i].distance);
    }

    /* Exact search matches a plain search; approximate and auto run; a
     * different measure re-ranks the approximate result. */
    {
        vec q = make_vec(CDB_VEC_F32, 0);
        cdb_vec_hit ap[GK], pl[GK];
        size_t na, plain;

        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_search_mode(&db, coll, q.enc, q.n, CDB_VEC_BASE, CDB_VEC_APPROX, ap, 0,
                                                          &na));
        TEST_ASSERT_EQUAL_size_t(0, na); /* k == 0 short-circuits */
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_search_mode(&db, coll, q.enc, q.n, CDB_VEC_BASE, CDB_VEC_APPROX, ap, GK,
                                                          &na));
        TEST_ASSERT_TRUE(na > 0 && na <= GK);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_search_mode(&db, coll, q.enc, q.n, CDB_VEC_BASE, CDB_VEC_EXACT, ex, GK,
                                                          &ne));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_search(&db, coll, q.enc, q.n, CDB_VEC_BASE, pl, GK, &plain));
        TEST_ASSERT_EQUAL_size_t(plain, ne);
        for (i = 0; i < ne; i++) {
            TEST_ASSERT_EQUAL_UINT64(pl[i].entry, ex[i].entry);
            TEST_ASSERT_TRUE(pl[i].distance == ex[i].distance);
        }
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_search_mode(&db, coll, q.enc, q.n, CDB_VEC_BASE, CDB_VEC_AUTO, ap, GK,
                                                          &na));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_search_mode(&db, coll, q.enc, q.n, CDB_VEC_EUCLIDEAN, CDB_VEC_APPROX, ap,
                                                          GK, &na));
    }

    /* Changing vectors queues work: delete leaves every list that held it,
     * replace re-embeds, insert queues a new one; all become pending. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_delete(&db, coll, 2));
    {
        vec r = make_vec(CDB_VEC_F32, 0);
        vec ins = make_vec(CDB_VEC_F32, 0);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_replace(&db, coll, 3, r.enc, r.n));
        (void)add(coll, &ins);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_vec_neighbours(&db, coll, 2, hits, GK, &n, &fresh));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_refresh(&db, coll, 0, &left));
    TEST_ASSERT_EQUAL_size_t(0, left);

    /* Reconciliation and a tick keep the graph maintained. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_tick(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    /* The graph persists: reopened, refresh finds nothing pending. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_find_store(&db, "mem", 3, &coll, &fresh));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_refresh(&db, coll, 0, &left));
    TEST_ASSERT_EQUAL_size_t(0, left);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ------------------------------------------------------- graph errors */

static void test_cov_graph_errors(void)
{
    uint64_t coll;
    cdb_vec_hit hits[4];
    size_t n, left;
    int fresh;

    rng = 71u;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    coll = make_coll("g", CDB_VEC_F32, CDB_VEC_COSINE);
    (void)fill(coll, 6);
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_vec_refresh(&db, coll, 0, &n));
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_vec_neighbours(&db, coll, 1, hits, 2, &n, &fresh));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_vec_create_graph(&db, coll, CDB_VEC_MAX_K + 1u));
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_vec_create_graph(&db, coll, GK + 1u)); /* 1 KB pages hold 8 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_vec_create_graph(&db, coll, GK));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));

    /* A graph, then a second is a conflict; neighbours of a missing entry. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_create_graph(&db, coll, GK));
    TEST_ASSERT_EQUAL_INT(CDB_E_EXISTS, cdb_vec_create_graph(&db, coll, GK));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_refresh(&db, coll, 0, &left));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_vec_neighbours(&db, coll, 9999, hits, 2, &n, &fresh));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    /* A fresh collection opened without vec_work cannot grow a graph. */
    cfg.vec_work = NULL;
    cfg.vec_work_size = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    {
        uint64_t c2 = make_coll("g2", CDB_VEC_F32, CDB_VEC_COSINE);
        TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED, cdb_vec_create_graph(&db, c2, GK));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* --------------------------------------------------- accelerator paths */

static void test_cov_accelerator(void)
{
    uint64_t coll;
    static const void *qp[8];
    static size_t ql[8];
    static vec qv[8];
    cdb_vec_hit got[8 * GK], one[GK];
    size_t counts[8], n1, i, j;

    use_accel = 1;
    rng = 123u;
    setUp(); /* installs the fake accelerator onto env */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    coll = make_coll("a", CDB_VEC_F32, CDB_VEC_COSINE);
    (void)fill(coll, 60);

    /* A first search asks the accelerator for a mirror; maintenance fills it. */
    {
        vec q = make_vec(CDB_VEC_F32, 0);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_search(&db, coll, q.enc, q.n, CDB_VEC_BASE, one, GK, &n1));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_accel_maintain(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_tick(&db));

    for (i = 0; i < 8; i++) {
        qv[i] = make_vec(CDB_VEC_F32, 0);
        qp[i] = qv[i].enc;
        ql[i] = qv[i].n;
    }
    /* Bulk search over the device gives each query what a single search does. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_search_bulk(&db, coll, qp, ql, 8, CDB_VEC_BASE, CDB_VEC_AUTO, got, GK, counts));
    for (i = 0; i < 8; i++) {
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_search(&db, coll, qp[i], ql[i], CDB_VEC_BASE, one, GK, &n1));
        TEST_ASSERT_EQUAL_size_t(n1, counts[i]);
        for (j = 0; j < n1; j++)
            TEST_ASSERT_EQUAL_UINT64(one[j].entry, got[i * GK + j].entry);
    }
    /* The exact mode routes every query to the device in batches; it still
     * agrees with a single search. */
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_vec_search_bulk(&db, coll, qp, ql, 8, CDB_VEC_BASE, CDB_VEC_EXACT, got, GK, counts));
    for (i = 0; i < 8; i++) {
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_search(&db, coll, qp[i], ql[i], CDB_VEC_BASE, one, GK, &n1));
        TEST_ASSERT_EQUAL_size_t(n1, counts[i]);
        for (j = 0; j < n1; j++)
            TEST_ASSERT_EQUAL_UINT64(one[j].entry, got[i * GK + j].entry);
    }
    /* An empty bulk request is a no-op. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_search_bulk(&db, coll, qp, ql, 0, CDB_VEC_BASE, CDB_VEC_AUTO, got, GK, counts));

    /* The suite reached the device (otherwise the mirror paths ran nothing). */
    TEST_ASSERT_TRUE(fake.opens > 0);

    (void)cdb_vec_accel_floor(&db);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_vec_accel_rebase(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
    use_accel = 0;
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cov_work_size);
    RUN_TEST(test_cov_create_and_live);
    RUN_TEST(test_cov_graph_lifecycle);
    RUN_TEST(test_cov_graph_errors);
    RUN_TEST(test_cov_accelerator);
    return UNITY_END();
}
