/* #60 B1 end-to-end — the reconciled-write-set ring wired into the live commit
 * path (ADR-0004). Behavioural proof that merge_journals POPULATES the ring and
 * coordinate_commit CONSULTS it, narrowing the blanket "committed_seq moved ->
 * COLLISION" gate from write-set-blind to write-set-aware, WITHOUT weakening
 * first-committer-wins / no-silent-loss (#33).
 *
 * Deterministic multi-coordinator fault environment (two coordinators in one
 * thread; the sleep hook lets both beat as other processes would — no real
 * process race, clock or network), modelled on test_coord_bounded_wait_f42.c and
 * test_coord_contention_collision_f60.c.
 *
 *   (a) AC1/AC6  DISJOINT writers straddling a peer reconcile: the later commit
 *               now SUCCEEDS (was CDB_E_COLLISION pre-wiring) — B1 fixed. The
 *               red->green flip is also pinned in test_coord_contention_
 *               collision_f60.c::test_disjoint_straddle_now_commits_b1_fixed,
 *               whose prior assertion was CDB_E_COLLISION against the pre-wiring
 *               code.
 *   (b) AC2     OVERLAPPING writers (same store,entry) straddling a reconcile:
 *               still CDB_E_COLLISION — detection is narrowed, never relaxed.
 *   (c) AC3     RECONCILED-OVERLAP (#33 cardinal case): a writer whose write set
 *               was reconciled away between its base and now: still
 *               CDB_E_COLLISION — the ring catches the reconciled-away key.
 *   (d) AC4     UNREADABLE region: a torn/corrupt ring page => the consult cannot
 *               read it => conservative reject (fail-closed). This is also AC3's
 *               "ring forced to not-cover => still rejects".
 *   (e) AC5     POPULATE publishes before visible: when a peer first sees the
 *               advanced committed_seq, the covering ring entry is already durable
 *               and consistent (publish-after-sync).
 */
#define _POSIX_C_SOURCE 200809L

#include <string.h>

#include "unity.h"
#include "cdb_coord.h"
#include "cdb_db.h"
#include "cdb_endian.h"
#include "cdb_faultenv.h"
#include "cdb_header.h"
#include "cdb_wsring.h"

#define FCAP (256u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define DIR "c60e"
#define SEC 1000000000

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 2048u];
static cdb_faultenv fe;
static cdb_env env;
static const uint8_t db_id[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

struct proc {
    uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
    cdb_pager_node nodes[NODES];
    cdb_free_extent free_list[1024];
    uint8_t record_buf[1024];
    uint8_t cat_work[24u * 1024u];
    cdb_index_entry cat_entries[512];
    uint8_t cat_page[PAGE];
    cdb_db_config cfg;
    cdb_db db;
};
static struct proc p1, p2;

/* Entry N is logical page N; keeps the test's key-value pages. */
static cdb_status kv_apply(void *ctx, cdb_pager *p, const cdb_delta *d)
{
    uint8_t val[PAGE];
    cdb_page_header t;
    uint64_t lid;
    cdb_status s;
    (void)ctx;
    if (d->entry_id >= 64)
        return CDB_E_INVALID_ARG;
    while (p->next_lid < 64)
        if ((s = cdb_pager_alloc(p, &lid)) != CDB_OK)
            return s;
    if (d->op == CDB_OP_DELETE)
        return cdb_pager_free(p, d->entry_id);
    if (d->len >= PAGE)
        return CDB_E_INVALID_ARG;
    memcpy(val, d->data, d->len);
    memset(&t, 0, sizeof t);
    t.type = CDB_PAGE_TYPE_DATA_TEST;
    t.store_id = d->store_id;
    return cdb_pager_write(p, d->entry_id, &t, val, d->len);
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
    p->cfg.coord.max_coords = 0;
    p->cfg.flags = 0;
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

/* Both beat and mutually observe liveness, so each sees live_others > 0 and runs
 * the prepare/settle/scan path at commit (and the committed-seq straddle gate). */
static void settle_peers(void)
{
    int i;
    for (i = 0; i < 4; i++) {
        cdb_faultenv_advance(&fe, SEC / 8);
        (void)cdb_db_tick(&p1.db);
        (void)cdb_db_tick(&p2.db);
    }
}

void setUp(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 2048;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
    TEST_ASSERT_EQUAL_INT(CDB_OK, env.ops->mkdir(env.ctx, DIR));
    TEST_ASSERT_EQUAL_INT(CDB_OK, env.ops->sync_dir(env.ctx, "."));
    memset(&p1.db, 0, sizeof p1.db);
    memset(&p2.db, 0, sizeof p2.db);
    cdb_faultenv_on_sleep(&fe, tick_both, NULL);
}

void tearDown(void)
{
    cdb_faultenv_on_sleep(&fe, NULL, NULL);
    if (p2.db.hb_running)
        (void)cdb_db_close(&p2.db);
    if (p1.db.hb_running)
        (void)cdb_db_close(&p1.db);
}

static void open_two(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p2));
    TEST_ASSERT_EQUAL_UINT(0, p1.db.coord.me.slot);
    TEST_ASSERT_EQUAL_UINT(1, p2.db.coord.me.slot);
    settle_peers();
}

/* commit (store,entry)=v on p, returning the commit status. */
static cdb_status commit_one(struct proc *p, uint64_t store, uint64_t entry, const char *v)
{
    cdb_status s;
    if ((s = cdb_tx_begin(&p->db, CDB_DURABILITY_FULL)) != CDB_OK)
        return s;
    if ((s = cdb_tx_put(&p->db, store, entry, CDB_OP_REPLACE, v, strlen(v))) != CDB_OK) {
        (void)cdb_tx_abort(&p->db);
        return s;
    }
    return cdb_tx_commit(&p->db);
}

/* Reads the archive's committed sequence and the ring region anchor (if any)
 * directly from the file, exactly as a committer's consult would see them. */
static int read_archive(struct proc *p, uint64_t *committed, uint64_t *ring_phys,
                        uint32_t *ring_size)
{
    cdb_header_state hs;
    cdb_region_anchor a;
    if (cdb_header_open(&p->db.archive_st, &hs) != CDB_OK)
        return 0;
    *committed = hs.record.committed_seq;
    if (cdb_header_region_find(&hs.record, CDB_REGION_FEATURE_WRITESET_RING, &a)) {
        *ring_phys = a.anchor;
        *ring_size = a.size_hint;
    } else {
        *ring_phys = 0;
        *ring_size = 0;
    }
    return 1;
}

/* (a) AC1/AC6: a DISJOINT writer straddling a peer reconcile now COMMITS. */
static void test_disjoint_straddle_now_succeeds(void)
{
    open_two();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&p2.db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&p2.db, 2, 2, CDB_OP_REPLACE, "b", 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, commit_one(&p1, 1, 5, "a"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&p1.db));

    TEST_ASSERT_EQUAL_INT_MESSAGE(
        CDB_OK, cdb_tx_commit(&p2.db),
        "disjoint straddle must be proven covered-and-disjoint and commit (B1 fixed)");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* (b) AC2: an OVERLAPPING writer straddling a reconcile is still rejected. */
static void test_overlap_straddle_still_rejected(void)
{
    open_two();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&p2.db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&p2.db, 1, 5, CDB_OP_REPLACE, "b", 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, commit_one(&p1, 1, 5, "a"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&p1.db));

    TEST_ASSERT_EQUAL_INT_MESSAGE(
        CDB_E_COLLISION, cdb_tx_commit(&p2.db),
        "overlapping straddle (same store,entry) MUST still collide — detection not relaxed");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* (c) AC3: a reconciled-away overlap (#33 cardinal case) is still rejected — the
 * ring records the key that left every journal when p1 reconciled it. */
static void test_reconciled_overlap_still_rejected(void)
{
    open_two();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&p2.db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&p2.db, 7, 9, CDB_OP_REPLACE, "b", 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, commit_one(&p1, 7, 9, "a"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&p1.db));

    TEST_ASSERT_EQUAL_INT_MESSAGE(
        CDB_E_COLLISION, cdb_tx_commit(&p2.db),
        "a reconciled-away overlap MUST still be rejected — never silent-accept (#33)");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* (d) AC4 / AC3-fail-closed: a torn/corrupt ring page cannot be read, so the
 * consult takes the conservative reject even for a DISJOINT straddle that would
 * otherwise commit. Proves the fail-closed boundary (publish-after-sync aside,
 * any unreadable region is today's blanket reject). */
static void test_unreadable_region_forces_reject(void)
{
    uint64_t committed = 0, phys = 0;
    uint32_t size = 0;
    uint8_t junk[16];

    open_two();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&p2.db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&p2.db, 2, 2, CDB_OP_REPLACE, "b", 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, commit_one(&p1, 1, 5, "a"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&p1.db));

    /* The ring is present and rooted; corrupt its page bytes on disk so the
     * ring's own CRC fails on decode (a torn / half-published region). */
    TEST_ASSERT_TRUE(read_archive(&p1, &committed, &phys, &size));
    TEST_ASSERT_TRUE(phys != 0 && size > 0);
    memset(junk, 0xFF, sizeof junk);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_storage_program(&p1.db.archive_st, phys * (uint64_t)PAGE + 8u,
                                                      junk, sizeof junk));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_storage_sync(&p1.db.archive_st));

    TEST_ASSERT_EQUAL_INT_MESSAGE(
        CDB_E_COLLISION, cdb_tx_commit(&p2.db),
        "an unreadable/torn ring region MUST force the conservative reject (fail-closed)");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* (e) AC5: when a peer first observes the advanced committed_seq, the covering
 * ring entry is already durable and consistent — reading the ring the same way a
 * committer would shows it provably covers (base, current]. */
static void test_populate_publishes_before_visible(void)
{
    uint64_t base = 0, phys0 = 0, current = 0, phys = 0;
    uint32_t size0 = 0, size = 0;
    uint8_t region[PAGE];

    open_two();
    TEST_ASSERT_TRUE(read_archive(&p1, &base, &phys0, &size0));

    TEST_ASSERT_EQUAL_INT(CDB_OK, commit_one(&p1, 1, 5, "a"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&p1.db));

    /* The committed sequence advanced AND a ring region is rooted at it. */
    TEST_ASSERT_TRUE(read_archive(&p1, &current, &phys, &size));
    TEST_ASSERT_TRUE(current > base);
    TEST_ASSERT_TRUE(phys != 0 && size > 0 && size <= PAGE);

    /* The ring bytes visible at the committed_seq a peer sees already cover the
     * straddle (base, current] — it was durable before the sequence was visible. */
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_storage_read(&p1.db.archive_st, phys * (uint64_t)PAGE, region, size));
    TEST_ASSERT_EQUAL_INT(1, cdb_wsring_covers(region, size, CDB_ORDER_LITTLE, base, current));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_disjoint_straddle_now_succeeds);
    RUN_TEST(test_overlap_straddle_still_rejected);
    RUN_TEST(test_reconciled_overlap_still_rejected);
    RUN_TEST(test_unreadable_region_forces_reject);
    RUN_TEST(test_populate_publishes_before_visible);
    return UNITY_END();
}
