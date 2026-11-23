/* #40 data-model robustness regressions.
 *
 * FR1: creating a unique index that meets a duplicate must leave no orphaned
 *      index pages (AC1/AC2). Pinned as an invariant via cdb_db_reclaim == 0.
 *      This holds pre-fix too -- the catalog-abort rebase already reclaims the
 *      half-built index -- so it is NOT a red->green replay; the cdb_index_drop
 *      fix is defense-in-depth that makes the failure path self-cleaning
 *      regardless of the outer rebase (see the test's own note).
 * FR2: a row delete refused by a REFUSE-rule graph link must fully roll back
 *      its index staging -- no tombstone may survive, or it would shadow the
 *      still-live row's unique-index key (a later duplicate insert would then
 *      wrongly succeed). This IS red->green: pre-fix the stage watermark grows
 *      and the duplicate insert wrongly succeeds; post-fix both are correct. */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_doc.h"
#include "cdb_faultenv.h"
#include "cdb_link.h"
#include "cdb_table.h"

#define FCAP (1024u * 1024u)
#define PAGE_LOG2 10u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 8192u];
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
static uint8_t table_buffers[4u * PAGE];
static cdb_db_config cfg;
static cdb_db db;

static uint64_t F_ID, F_SCORE, F_K;

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
    memset(h.db_id, 0x40, sizeof h.db_id);
    return cdb_db_open(&db, &env, "f40", &cfg, &h);
}

static void begin(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL)); }
static void commit(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db)); }

/* A table (id int PK, score int, k int) and its field IDs. */
static uint64_t make_table(void)
{
    uint64_t t = 0;
    unsigned pk = 0;
    cdb_table_column cols[3];
    cdb_table_def def;
    memset(cols, 0, sizeof cols);
    cols[0].name = "id";
    cols[0].name_len = 2;
    cols[0].type = CDB_TYPE_INT;
    cols[1].name = "score";
    cols[1].name_len = 5;
    cols[1].type = CDB_TYPE_INT;
    cols[2].name = "k";
    cols[2].name_len = 1;
    cols[2].type = CDB_TYPE_INT;
    memset(&def, 0, sizeof def);
    def.columns = cols;
    def.ncolumns = 3;
    def.primary_key = &pk;
    def.npk = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create(&db, "t", 1, &def, &t));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, t, "id", 2, &F_ID));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, t, "score", 5, &F_SCORE));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_column_id(&db, t, "k", 1, &F_K));
    return t;
}

static cdb_status insert_row(uint64_t t, int64_t id, int64_t score, int64_t k, uint64_t *entry)
{
    uint8_t b[256];
    cdb_value_writer w;
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, F_ID);
    cdb_value_write_int(&w, id);
    cdb_value_field(&w, F_SCORE);
    cdb_value_write_int(&w, score);
    cdb_value_field(&w, F_K);
    cdb_value_write_int(&w, k);
    cdb_value_end_object(&w);
    if (w.error != CDB_OK)
        return w.error;
    return cdb_table_insert(&db, t, b, cdb_value_writer_len(&w), entry);
}

#define FR1_ROWS 200u /* enough distinct keys that the half-built index splits */

/* FR1 (AC1/AC2): a unique-index create that meets a duplicate must leave no
 * orphaned (unreferenced) index pages. The authoritative oracle is
 * cdb_db_reclaim: the reclaim/scrub pass walks reachability and frees anything
 * allocated-but-unreferenced, so a leaked index page would show as pages_freed
 * > 0.
 *
 * Note: the catalog op's abort path already reloads the pager (rebase) on
 * failure, which reclaims the half-built index too, so this invariant also
 * holds on the pre-fix code -- it is not a red->green replay like FR2-FR4.
 * The fix (cdb_index_drop on every add_index failure path) makes the failure
 * self-cleaning independent of that outer safety net (defense in depth); this
 * test pins the AC1 invariant that no index pages are ever orphaned by a
 * failed create. */
static void test_unique_index_duplicate_reclaims_pages(void)
{
    uint64_t t, e;
    uint32_t ix;
    unsigned i;
    uint64_t pages_freed = 0, nibblets_freed = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    t = make_table(); /* a catalog op: commits on its own, not inside a tx */
    begin();
    /* Many distinct scores so the fill grows the index past its root, then a
     * final duplicate score so the create fails after real page allocation. */
    for (i = 0; i < FR1_ROWS; i++)
        TEST_ASSERT_EQUAL_INT(CDB_OK, insert_row(t, (int64_t)i, (int64_t)i, (int64_t)i, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, insert_row(t, FR1_ROWS, (int64_t)(FR1_ROWS - 1u), 9999, &e));
    commit();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));

    /* A clean baseline: nothing is orphaned before the failed create. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reclaim(&db, &pages_freed, &nibblets_freed));
    TEST_ASSERT_EQUAL_UINT64(0u, pages_freed);

    /* The failed unique-index create over the duplicate score. */
    TEST_ASSERT_EQUAL_INT(CDB_E_EXISTS, cdb_table_create_index(&db, t, &F_SCORE, 1, 1, &ix));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));

    /* FR1 oracle: no index pages were orphaned by the failed create. */
    pages_freed = 999;
    nibblets_freed = 999;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reclaim(&db, &pages_freed, &nibblets_freed));
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(0u, pages_freed, "unique-index-duplicate leaked index pages");

    /* A non-unique index over the same duplicate still succeeds (sanity). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create_index(&db, t, &F_SCORE, 1, 0, &ix));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* FR2: a delete refused by a REFUSE link rolls its index staging fully back;
 * the row stays live and its unique key still blocks a duplicate insert. */
static void test_refused_delete_rolls_back_index_staging(void)
{
    uint64_t t, r, refuse, pooldoc, doc, dup;
    uint32_t ix;
    cdb_ref r_row, r_doc;
    size_t used_before;
    uint8_t out[256];
    size_t rlen;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    t = make_table(); /* a catalog op: commits on its own, not inside a tx */
    begin();
    TEST_ASSERT_EQUAL_INT(CDB_OK, insert_row(t, 1, 1, 1000, &r)); /* unique k = 1000 */
    commit();
    /* A unique index on k, created cleanly (distinct values). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_create_index(&db, t, &F_K, 1, 1, &ix));

    /* A doc that holds a REFUSE link INTO the row, so deleting the row is
     * refused while the link is live. */
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_db_create_store(&db, "notes", 5, CDB_MODEL_DOCUMENT, &pooldoc));
    refuse = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_define_type(&db, "needs", 5, CDB_CARD_N_M, 1,
                                                       CDB_LINK_ON_DELETE_REFUSE, &refuse));
    begin();
    {
        uint8_t b[32];
        cdb_value_writer w;
        cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        cdb_value_begin_object(&w);
        cdb_value_field(&w, 1);
        cdb_value_write_string(&w, "x", 1);
        cdb_value_end_object(&w);
        TEST_ASSERT_EQUAL_INT(CDB_OK,
                              cdb_doc_insert(&db, pooldoc, NULL, 0, b, cdb_value_writer_len(&w), &doc));
    }
    r_row = cdb_ref_entry(t, r);
    r_doc = cdb_ref_entry(pooldoc, doc);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_link_add(&db, refuse, r_doc, r_row, 1.0f, 100));
    commit();

    /* The refused delete must leave the index stage exactly as it found it. */
    begin();
    used_before = db.stage_idx_used;
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_table_delete(&db, t, r));
    TEST_ASSERT_EQUAL_size_t_MESSAGE(used_before, db.stage_idx_used,
                                     "refused delete left index-stage tombstones");

    /* The row is still live: a re-find succeeds and its unique key (k = 1000)
     * still blocks a duplicate insert. Pre-fix, the stray tombstone hid the
     * key and this insert wrongly succeeded. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_table_get(&db, t, r, out, sizeof out, &rlen));
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_EXISTS, insert_row(t, 2, 2, 1000, &dup),
                                  "a refused delete's stale tombstone unblocked a duplicate key");
    commit();

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_unique_index_duplicate_reclaims_pages);
    RUN_TEST(test_refused_delete_rolls_back_index_staging);
    return UNITY_END();
}
