/* #54 F3: a BATON audit event fired only on the reconcile path (cdb_db_reconcile).
 * Other baton-ACQUIRING maintenance ops -- reclaim and compaction -- also take
 * the baton (a genuine coordinator handoff) via reconcile_hold but emitted no
 * BATON event. Wire the emit at those acquisition sites (db_reclaim_in,
 * db_compact_in), with the same not-held -> held transition detection used by
 * cdb_db_reconcile so a standing baton does not double-emit.
 *
 *   AC4 a compaction that acquires the baton emits a BATON event
 *   AC5 a reclaim that acquires the baton emits a BATON event
 *   AC6 an op that already holds a standing baton does NOT emit a BATON
 *
 * Red->green: before the source fix reclaim/compact acquired the baton silently
 * (BATON count 0); after it, the genuine handoff is audited. Deterministic and
 * hermetic: two coordinators in one thread sharing one fault environment, the
 * sleep hook letting the other beat (as test_audit_chain_xproc / test_multiwriter
 * do). No real process race, clock, or network. */
#define _POSIX_C_SOURCE 200809L

#include <string.h>

#include "unity.h"
#include "cdb_audit.h"
#include "cdb_coord.h"
#include "cdb_db.h"
#include "cdb_faultenv.h"
#include "combolite/cdb_crypto.h"

#define FCAP (512u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 24u
#define DIR "bx"

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 4096u];
static cdb_faultenv fe;
static cdb_env env;
static const uint8_t db_id[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static cdb_identity id;

struct proc {
    uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
    cdb_pager_node nodes[NODES];
    cdb_free_extent free_list[2048];
    uint8_t record_buf[1024];
    uint8_t cat_work[24u * 1024u];
    cdb_index_entry cat_entries[512];
    uint8_t cat_page[PAGE];
    cdb_db_config cfg;
    cdb_db db;
};
static struct proc p1, p2;

#define KV_PAGES 64u

static cdb_status kv_apply(void *ctx, cdb_pager *p, const cdb_delta *d)
{
    cdb_page_header t;
    uint64_t lid;
    cdb_status s;
    (void)ctx;
    if (d->entry_id >= KV_PAGES)
        return CDB_E_INVALID_ARG;
    while (p->next_lid < KV_PAGES)
        if ((s = cdb_pager_alloc(p, &lid)) != CDB_OK)
            return s;
    memset(&t, 0, sizeof t);
    t.type = CDB_PAGE_TYPE_DATA_TEST;
    t.store_id = d->store_id;
    return cdb_pager_write(p, d->entry_id, &t, d->data, d->len);
}

static cdb_status open_proc(struct proc *p)
{
    cdb_header h;
    memset(&p->cfg, 0, sizeof p->cfg);
    p->cfg.pager.arena = p->arena;
    p->cfg.pager.arena_size = sizeof p->arena;
    p->cfg.pager.nodes = p->nodes;
    p->cfg.pager.node_cap = NODES;
    p->cfg.pager.free_list = p->free_list;
    p->cfg.pager.free_cap = sizeof p->free_list / sizeof p->free_list[0];
    p->cfg.record_buf = p->record_buf;
    p->cfg.record_buf_size = sizeof p->record_buf;
    p->cfg.apply = kv_apply;
    p->cfg.catalog_work.bytes = p->cat_work;
    p->cfg.catalog_work.bytes_size = sizeof p->cat_work;
    p->cfg.catalog_work.entries = p->cat_entries;
    p->cfg.catalog_work.entries_cap = 512;
    p->cfg.catalog_page = p->cat_page;
    p->cfg.durability = CDB_DURABILITY_FULL;
    p->cfg.identity = &id;
    p->cfg.signing_policy = CDB_SIGN_AUDIT_ONLY;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memcpy(h.db_id, db_id, 16);
    return cdb_db_open(&p->db, &env, DIR "/db", &p->cfg, &h);
}

static void tick_both(void *arg)
{
    (void)arg;
    if (p1.db.coord.joined)
        (void)cdb_db_tick(&p1.db);
    if (p2.db.coord.joined)
        (void)cdb_db_tick(&p2.db);
}

static void init_env(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 4096;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
    TEST_ASSERT_EQUAL_INT(CDB_OK, env.ops->mkdir(env.ctx, DIR));
    TEST_ASSERT_EQUAL_INT(CDB_OK, env.ops->sync_dir(env.ctx, "."));
    memset(&p1.db, 0, sizeof p1.db);
    memset(&p2.db, 0, sizeof p2.db);
}

void setUp(void)
{
    init_env();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_generate_env(&env, &id, 7, 1));
}

void tearDown(void)
{
    cdb_faultenv_on_sleep(&fe, NULL, NULL);
    if (p2.db.hb_running)
        (void)cdb_db_close(&p2.db);
    if (p1.db.hb_running)
        (void)cdb_db_close(&p1.db);
}

/* Counts audit events of a given type across the whole series on `p`; the chain
 * must verify. */
static size_t count_type(struct proc *p, uint16_t type)
{
    cdb_audit_event ev[32];
    uint8_t pbuf[1024];
    size_t count = 0, i, n = 0;
    int valid = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&p->db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_query(&p->db, INT64_MIN, INT64_MAX, pbuf, sizeof pbuf,
                                                  ev, 32, &count));
    for (i = 0; i < count; i++)
        if (ev[i].event_type == type)
            n++;
    return n;
}

/* AC5: a reclaim that acquires the baton (handoff from p1) emits a BATON event.
 * p1 holds the standing baton; p2 does not and takes it by reclaiming. */
static void test_baton_on_reclaim_acquire(void)
{
    uint64_t pages = 0, nibs = 0;

    cdb_faultenv_on_sleep(&fe, tick_both, NULL);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p2));
    cdb_faultenv_advance(&fe, 10 * 1000 * 1000);

    TEST_ASSERT_FALSE(cdb_coord_baton_held(&p2.db.coord));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reclaim(&p2.db, &pages, &nibs));

    TEST_ASSERT_TRUE(count_type(&p2, CDB_AUDIT_BATON) >= 1); /* red pre-fix: 0 */

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* AC4: a compaction that acquires the baton emits a BATON event. */
static void test_baton_on_compact_acquire(void)
{
    uint64_t moved = 0, reclaimed = 0;

    cdb_faultenv_on_sleep(&fe, tick_both, NULL);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p2));
    cdb_faultenv_advance(&fe, 10 * 1000 * 1000);

    TEST_ASSERT_FALSE(cdb_coord_baton_held(&p2.db.coord));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_compact(&p2.db, 16, &moved, &reclaimed));

    TEST_ASSERT_TRUE(count_type(&p2, CDB_AUDIT_BATON) >= 1); /* red pre-fix: 0 */

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* AC6: an op that already holds a standing baton does not emit a BATON. A sole
 * coordinator holds the baton from open, so its reclaim is no handoff. */
static void test_no_baton_when_already_held(void)
{
    uint64_t pages = 0, nibs = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1));
    TEST_ASSERT_TRUE(cdb_coord_baton_held(&p1.db.coord)); /* sole coordinator holds it */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reclaim(&p1.db, &pages, &nibs));

    TEST_ASSERT_EQUAL_size_t(0, count_type(&p1, CDB_AUDIT_BATON)); /* no handoff -> no event */

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_baton_on_reclaim_acquire);
    RUN_TEST(test_baton_on_compact_acquire);
    RUN_TEST(test_no_baton_when_already_held);
    return UNITY_END();
}
