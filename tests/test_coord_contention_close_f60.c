/* #60 B2/FR2 + AC4/AC5 and B3/FR3 + AC6 — clean close under live peers releases
 * the coordinator slot, never a false busy, never a spurious CDB_E_STATE.
 * Deterministic regression oracle for audit follow-up #60.
 *
 * Trace: ideation FR2 (clean close releases the slot under live peers, no false
 * busy, no leak) + FR3 (no spurious CDB_E_STATE under load) + FR5 (no committed
 * tx dropped) -> issue #60 -> this test -> gate verdict.
 *
 * Setup (lock hook, deterministic, hermetic): one long-lived live peer (p1,
 * slot 0, holds its slot lock for the whole run), and a churner (p2) that
 * repeatedly opens -> commits -> closes CLEANLY while p1 stays live. Each p2
 * close leaves slot 1 as CLOSED + journal-pending (spec 5.9.1), releasing its
 * lock; the next p2 open adopts slot 1 and folds the pending journal.
 *
 *   AC5  every clean p2 close returns CDB_OK — NEVER CDB_E_BUSY from a live peer
 *        (the false "close busy" of B2).
 *   AC4  the slot is reclaimed: p2 is re-granted the SAME slot index every churn
 *        (no monotonic growth toward CDB_COORD_MAX), and the fault-env held-lock
 *        count does not grow across churn (no slot/lock leak).
 *   AC6  no begin/put/commit/close ever returns CDB_E_STATE (B3 invariant).
 *   AC4  a final alone close of p1 succeeds — every slot fully reclaimed.
 *
 * Note on the B2 code branch: the specific fence-busy-at-close -> close_pending
 * reroute (cdb_db.c, the landed +19/-4) is reachable ONLY in the lock-free
 * heartbeat fallback (a peer overriding a holder judged dead); under the lock
 * hook a live holder's baton is never stolen, so the branch is not taken here.
 * This test pins the OBSERVABLE FR2 contract (no false busy, no leak) under the
 * lock hook; the fallback close path is additionally smoked in
 * test_coord_contention_fallback_f60. The exact fence race is not deterministically
 * reproducible in-process (documented in docs/audit/2026-11-60-coord-contention.md). */
#define _POSIX_C_SOURCE 200809L

#include <string.h>

#include "unity.h"
#include "cdb_coord.h"
#include "cdb_db.h"
#include "cdb_faultenv.h"

#define FCAP (256u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define DIR "c60k"
#define SEC 1000000000
#define CHURN 12 /* well under CDB_COORD_MAX (64): a leak would march the slot up */

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

static cdb_status open_proc(struct proc *p, unsigned flags)
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
    p->cfg.flags = flags;
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

/* The core FR2/AC4/AC5 + B3/AC6 oracle. */
static void test_clean_close_under_live_peer_reclaims_slot(void)
{
    unsigned first_slot = 0, base_locks = 0;
    int i;
    cdb_status s;

    /* p1 is the live peer for the whole run; it holds slot 0's lock throughout,
     * so p2's closes are always "not alone" (the under-live-peers path). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1, 0));
    TEST_ASSERT_EQUAL_UINT(0, p1.db.coord.me.slot);

    for (i = 0; i < CHURN; i++) {
        /* Open the churner fresh (reuses the struct; adopts slot 1's pending
         * journal left by the previous clean close). */
        memset(&p2.db, 0, sizeof p2.db);
        s = open_proc(&p2, 0);
        TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, s, "churner must reopen under a live peer");
        TEST_ASSERT_NOT_EQUAL_MESSAGE(CDB_E_STATE, s, "no spurious CDB_E_STATE at open (B3/AC6)");

        if (i == 0)
            first_slot = p2.db.coord.me.slot;
        /* AC4: the slot is reused, not leaked — it must never grow above the
         * first-granted index (a leak would hand out a fresh, higher slot). */
        TEST_ASSERT_TRUE_MESSAGE(p2.db.coord.me.slot <= first_slot,
                                 "coordinator slot grew: a clean close leaked its slot (B2/AC4)");
        TEST_ASSERT_TRUE_MESSAGE(p2.db.coord.me.slot < CDB_COORD_MAX, "slot exhaustion (AC4)");

        cdb_faultenv_advance(&fe, 10 * 1000 * 1000);

        s = cdb_tx_begin(&p2.db, CDB_DURABILITY_FULL);
        TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, s, "begin under live peer");
        TEST_ASSERT_NOT_EQUAL_MESSAGE(CDB_E_STATE, s, "no CDB_E_STATE at begin (B3/AC6)");
        s = cdb_tx_put(&p2.db, 1, 2, CDB_OP_REPLACE, "x", 1);
        TEST_ASSERT_EQUAL_INT(CDB_OK, s);
        s = cdb_tx_commit(&p2.db);
        TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, s, "disjoint commit under live peer");
        TEST_ASSERT_NOT_EQUAL_MESSAGE(CDB_E_STATE, s, "no CDB_E_STATE at commit (B3/AC6)");

        /* AC5 / B2: a CLEAN close while a peer is live must succeed and release
         * the slot — never a false CDB_E_BUSY, never CDB_E_STATE. */
        s = cdb_db_close(&p2.db);
        TEST_ASSERT_NOT_EQUAL_MESSAGE(CDB_E_BUSY, s,
                                      "clean close under a live peer falsely reported busy (B2/AC5)");
        TEST_ASSERT_NOT_EQUAL_MESSAGE(CDB_E_STATE, s, "no CDB_E_STATE at close (B3/AC6)");
        TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, s, "clean close must succeed and release the slot (FR2)");

        /* AC4 at the lock level: once p2 has fully closed, no residual lock is
         * held on its behalf — the baseline (p1's) count stays constant. */
        if (i == 0)
            base_locks = cdb_faultenv_held_locks(&fe);
        else
            TEST_ASSERT_TRUE_MESSAGE(cdb_faultenv_held_locks(&fe) <= base_locks,
                                     "held-lock count grew across churn: a lock/slot leaked (AC4)");
    }

    /* AC4: the final alone close reclaims every slot and tears down cleanly. */
    s = cdb_db_close(&p1.db);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, s, "final alone close must reclaim all slots");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_clean_close_under_live_peer_reclaims_slot);
    return UNITY_END();
}
