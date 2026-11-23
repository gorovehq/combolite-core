/* #40 FR3: a graph link list must never return a tombstoned (dead) link end
 * as a live result. After one end of a link is deleted (tombstoning the link),
 * cdb_link_list filters it out (live-only, the default), while cdb_link_get
 * still reports the row with its explicit dead-state in out->flags -- the
 * documented way to inspect a link's state.
 *
 * Red->green: pre-fix cdb_link_list returned the tombstoned link as if live
 * (count stayed 2); post-fix it returns only the live link (count 1). */
#define _POSIX_C_SOURCE 200809L

#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_doc.h"
#include "cdb_faultenv.h"
#include "cdb_link.h"

#define FCAP (512u * 1024u)
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
static cdb_db_config cfg;
static cdb_db db;
static uint64_t pool;

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
    memset(h.db_id, 0x43, sizeof h.db_id);
    return cdb_db_open(&db, &env, "lf40", &cfg, &h);
}

static void begin(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL)); }
static void commit(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db)); }

static uint64_t new_doc(void)
{
    uint8_t b[32];
    cdb_value_writer w;
    uint64_t e = 0;
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_string(&w, "x", 1);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, b, cdb_value_writer_len(&w), &e));
    return e;
}

static cdb_ref D(uint64_t entry) { return cdb_ref_entry(pool, entry); }

static size_t live_count(cdb_ref e, int dir, uint64_t type)
{
    cdb_link out[16];
    size_t n = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_list(&db, e, dir, type, NULL, out, 16, &n));
    return n;
}

static void test_list_filters_tombstoned_end(void)
{
    uint64_t t = 0, a, b, c;
    cdb_link l;
    int found;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_db_create_store(&db, "notes", 5, CDB_MODEL_DOCUMENT, &pool));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_define_type(&db, "cites", 5, CDB_CARD_N_M, 1,
                                                       CDB_LINK_ON_DELETE_TOMBSTONE, &t));
    begin();
    a = new_doc();
    b = new_doc();
    c = new_doc();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_add(&db, t, D(a), D(b), 1.0f, 100));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_add(&db, t, D(a), D(c), 1.0f, 100));
    commit();

    /* Both ends live: list returns two. */
    TEST_ASSERT_EQUAL_size_t(2, live_count(D(a), CDB_LINK_OUT, t));

    /* Delete b: the link a->b is tombstoned (TARGET_GONE). */
    begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_delete(&db, pool, b));
    commit();

    /* FR3: list is live-only -- it returns only a->c, never the dead a->b. */
    TEST_ASSERT_EQUAL_size_t_MESSAGE(1, live_count(D(a), CDB_LINK_OUT, t),
                                     "link_list returned a tombstoned end as live");

    /* And the single live end is a->c. */
    {
        cdb_link out[16];
        size_t n = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_list(&db, D(a), CDB_LINK_OUT, t, NULL, out, 16, &n));
        TEST_ASSERT_EQUAL_size_t(1, n);
        TEST_ASSERT_EQUAL_UINT64(c, out[0].target.entry);
        TEST_ASSERT_EQUAL_UINT8(0, out[0].flags); /* live, no tombstone bits */
    }

    /* get still exposes the dead state explicitly (not silent): found with the
     * tombstone flags set -- the documented inspection path. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_get(&db, t, D(a), D(b), &l, &found));
    TEST_ASSERT_EQUAL_INT(1, found);
    TEST_ASSERT_TRUE((l.flags & CDB_LINK_TOMBSTONE) != 0);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_list_filters_tombstoned_end);
    return UNITY_END();
}
