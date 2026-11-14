/* Coverage set for cdb_doc: error/edge paths the behavioural test_doc.c misses —
 * buffer-too-small, big-doc overflow round-trip + reopen, head live/NOT_FOUND,
 * next_live iteration, delete-then-absent, replace history revision, set_keep.
 * Bodies are encoded cdb_value objects (spec 14.6). Spec 8 (document model). */
#include <stdio.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_doc.h"
#include "cdb_faultenv.h"

#define FCAP (768u * 1024u)
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
static uint8_t record_buf[6u * PAGE];
static uint8_t cat_work[24u * 1024u];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static uint8_t doc_buffers[16u * PAGE];  /* >= cdb_doc_buffers_size(PAGE, 2*PAGE) = 14*PAGE */
static uint8_t doc_stage[16u * 1024u];
#define DOC_MAX (2u * PAGE)
static cdb_db_config cfg;
static cdb_db db;

static uint8_t out[16u * PAGE];

typedef struct { uint8_t b[8u * PAGE]; size_t n; } docbody;

/* { 1: <str> } */
static docbody make_body(const char *s, size_t len)
{
    docbody d;
    cdb_value_writer w;
    cdb_value_writer_init(&w, d.b, sizeof d.b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_string(&w, s, len);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    d.n = cdb_value_writer_len(&w);
    return d;
}

void setUp(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena; c.file_capacity = FCAP;
    c.records = env_records; c.records_per_file = 4096;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
    memset(&cfg, 0, sizeof cfg);
    cfg.pager.arena = arena; cfg.pager.arena_size = sizeof arena;
    cfg.pager.nodes = nodes; cfg.pager.node_cap = NODES;
    cfg.pager.free_list = free_list; cfg.pager.free_cap = sizeof free_list / sizeof free_list[0];
    cfg.record_buf = record_buf; cfg.record_buf_size = sizeof record_buf;
    cfg.catalog_work.bytes = cat_work; cfg.catalog_work.bytes_size = sizeof cat_work;
    cfg.catalog_work.entries = cat_entries; cfg.catalog_work.entries_cap = 512;
    cfg.catalog_page = cat_page;
    cfg.doc_buffers = doc_buffers; cfg.doc_stage = doc_stage; cfg.doc_stage_size = sizeof doc_stage;
    cfg.doc_max = DOC_MAX;  /* enable the overflow chain for bodies > 1 page */
    cfg.durability = CDB_DURABILITY_FULL;
}
void tearDown(void) {}

static cdb_status open_db(void)
{
    cdb_header h;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x6D, sizeof h.db_id);
    return cdb_db_open(&db, &env, "dc", &cfg, &h);
}
static uint64_t make_pool(const char *name)
{
    uint64_t id;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, name, strlen(name), CDB_MODEL_DOCUMENT, &id));
    return id;
}

static void test_get_errors_and_roundtrip(void)
{
    uint64_t pool, e; size_t len = 0;
    docbody v = make_body("hello-body", 10);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("docs");

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "sum", 3, v.b, v.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* round-trip: body bytes come back verbatim */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(v.n, len);
    TEST_ASSERT_EQUAL_MEMORY(v.b, out, len);
    /* unknown entry + unknown store */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_get(&db, pool, 999, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, 123456, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    /* buffer too small reports the needed length and can be retried */
    {
        uint8_t tiny[2]; size_t need = 0;
        TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL,
            cdb_doc_get(&db, pool, e, 0, tiny, sizeof tiny, &need, NULL, 0, NULL, NULL));
        TEST_ASSERT_EQUAL_UINT(v.n, need);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
        TEST_ASSERT_EQUAL_UINT(v.n, len);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

static void test_big_doc_overflow(void)
{
    uint64_t pool, e; size_t len = 0; size_t i;
    static char bigstr[PAGE + PAGE / 2u];  /* > 1 page, <= doc_max: forces overflow chain */
    docbody v;
    for (i = 0; i < sizeof bigstr; i++) bigstr[i] = (char)('a' + (int)(i % 26u));
    v = make_body(bigstr, sizeof bigstr);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("big");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "b", 1, v.b, v.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    /* round-trip through the overflow chain */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(v.n, len);
    TEST_ASSERT_EQUAL_MEMORY(v.b, out, len);
    /* survives reopen (overflow pages rebuilt from disk) */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(v.n, len);
    TEST_ASSERT_EQUAL_MEMORY(v.b, out, len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

static void test_head_nextlive_delete(void)
{
    uint64_t pool, e1, e2, cur; int done = 0, live = 0; uint64_t rev = 0; size_t len = 0;
    docbody a = make_body("aa", 2), b = make_body("bb", 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("hn");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "a", 1, a.b, a.n, &e1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "b", 1, b.b, b.n, &e2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* head: live doc + NOT_FOUND */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_head(&db, pool, e1, &rev, &live));
    TEST_ASSERT_TRUE(live);
    TEST_ASSERT_TRUE(rev >= 1);
    {
        int l2 = 1; uint64_t r2 = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_head(&db, pool, 999, &r2, &l2));
        TEST_ASSERT_FALSE(l2);
    }

    /* next_live iterates both live entries then reports done */
    {
        int count = 0; cur = 0; done = 0;
        while (cdb_doc_next_live(&db, pool, cur, &cur, &done) == CDB_OK && !done) count++;
        TEST_ASSERT_EQUAL_INT(2, count);
    }

    /* delete -> get NOT_FOUND, next_live drops to one */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_delete(&db, pool, e2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_get(&db, pool, e2, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    {
        int count = 0; cur = 0; done = 0;
        while (cdb_doc_next_live(&db, pool, cur, &cur, &done) == CDB_OK && !done) count++;
        TEST_ASSERT_EQUAL_INT(1, count);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

static void test_replace_history_and_keep(void)
{
    uint64_t pool, e; size_t len = 0; cdb_doc_info info;
    docbody v1 = make_body("v1", 2), v2 = make_body("v2", 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("rh");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v1.b, v1.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_replace(&db, pool, e, NULL, 0, v2.b, v2.n));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    /* current reads v2 at revision >= 2 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, &info));
    TEST_ASSERT_EQUAL_UINT(v2.n, len);
    TEST_ASSERT_EQUAL_MEMORY(v2.b, out, len);
    TEST_ASSERT_TRUE(info.revision >= 2);
    /* revision 1 still reads v1 (history chain) */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 1, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(v1.n, len);
    TEST_ASSERT_EQUAL_MEMORY(v1.b, out, len);
    /* replace a missing entry -> NOT_FOUND */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_replace(&db, pool, 999, NULL, 0, v2.b, v2.n));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    /* set_keep (revision-retention knob) */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_set_keep(&db, pool, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_get_errors_and_roundtrip);
    RUN_TEST(test_big_doc_overflow);
    RUN_TEST(test_head_nextlive_delete);
    RUN_TEST(test_replace_history_and_keep);
    return UNITY_END();
}
