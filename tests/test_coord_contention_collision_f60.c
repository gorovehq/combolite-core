/* #60 B1/FR1 + AC1/AC2/AC9 — write-set collision detection: precise, not coarse,
 * and fail-closed. Deterministic regression oracle for audit follow-up #60.
 *
 * Trace: ideation FR1 (disjoint write-sets proceed concurrently; overlap still
 * collides) + FR5 (no fail-closed guard weakened) -> issue #60 -> this test ->
 * gate verdict. Companion to the fork #67 that would narrow the archive-
 * committed-seq straddle gate (B1).
 *
 * What this pins (all under the lock hook, two coordinators in one thread, the
 * sleep hook lets both beat while one waits — no real process race/clock/net):
 *
 *   AC1  Two writers on DISJOINT (store,entry) write-sets, with NO reconcile
 *        straddling between them, both commit — detection does not over-serialize
 *        disjoint work (the journal-scan path, check_slot_collisions, is write-set
 *        based, spec 5.9.4).
 *   AC2  Two writers on the SAME (store,entry) — an OVERLAPPING write set — the
 *        later committer is rejected with CDB_E_COLLISION (never a silent accept
 *        of both). This is the fail-closed detection the #60 work must NOT relax.
 *   FR5  A reconciled-away overlap (peer reconciled an overlapping tx into the
 *        archive, so it left every journal) is STILL rejected — the conservative
 *        committed-seq gate (coordinate_commit) catches it. Permanent safety
 *        assertion: a straddling overlap is never silently accepted (#33 cardinal
 *        risk). This must hold forever, including after #67.
 *   B1   A reconciled straddle of a DISJOINT writer is ALSO rejected today
 *        (the gate is write-set-blind). This is the documented B1 over-rejection,
 *        reported as design fork #67, NOT relaxed. The assertion encodes the
 *        current fail-closed-but-conservative contract; when #67 lands an
 *        archive-side reconciled-write-set signal, the DISJOINT straddle becomes
 *        CDB_OK and this one assertion is updated — the overlap one above stays.
 *   AC9  The #42 bounded-wait constant is not weakened: the pure bound function
 *        clamps an absent/huge (untrusted) holder estimate to the hard cap.
 */
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
#define DIR "c60c"
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

/* Both beat and mutually observe liveness, so each sees live_others > 0 and runs
 * the prepare/settle/scan path at commit (without it a sole coordinator skips
 * the scan and no overlap would be detected — which would make AC2 vacuous). */
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
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p2, 0));
    TEST_ASSERT_EQUAL_UINT(0, p1.db.coord.me.slot);
    TEST_ASSERT_EQUAL_UINT(1, p2.db.coord.me.slot);
    settle_peers();
}

/* commit (store,entry)="v" on p, returning the commit status. */
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

/* AC1 (FR1): two writers on DISJOINT write-sets with no reconcile between them
 * both commit — disjoint work is not coerced into serialization. */
static void test_disjoint_writers_commit_concurrently(void)
{
    open_two();
    /* No reconcile straddles; committed_seq is unchanged for both. */
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, commit_one(&p1, 1, 5, "a"),
                                  "writer 1 on (1,5) must commit");
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, commit_one(&p2, 1, 6, "b"),
                                  "disjoint writer 2 on (1,6) must NOT false-collide (FR1/AC1)");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* AC2 (FR5): two writers on the SAME (store,entry) overlap; the later committer
 * is rejected with CDB_E_COLLISION (never both silently accepted). This is the
 * precise journal-scan detection (check_slot_collisions) the #60 work must keep. */
static void test_overlapping_writers_collide(void)
{
    cdb_status s;
    open_two();
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, commit_one(&p1, 1, 5, "a"),
                                  "writer 1 on (1,5) must commit");
    /* p2 overlaps p1's committed-but-unreconciled tx; its scan of slot 0 finds
     * the overlap and rejects (spec 5.9.4 first-committer-wins). */
    s = commit_one(&p2, 1, 5, "b");
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_COLLISION, s,
                                  "real write-set overlap MUST collide (AC2/FR5) — not relaxed");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* FR5 permanent safety: a reconciled-away OVERLAP is still rejected. p2 opens a
 * tx on the old archive snapshot; p1 commits an overlapping (1,5) AND reconciles
 * it into the archive (so it leaves every journal, advancing committed_seq);
 * p2's overlapping commit must still be rejected by the conservative committed-
 * seq gate (coordinate_commit) — never a silent accept (the #33 cardinal risk).
 * This must hold forever, including after #67. */
static void test_reconciled_overlap_straddle_rejected(void)
{
    cdb_status s;
    open_two();

    /* p2 pins the current (empty) archive snapshot with an open tx first. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&p2.db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&p2.db, 1, 5, CDB_OP_REPLACE, "b", 1));

    /* p1 commits the same (1,5) and reconciles it away into the archive. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, commit_one(&p1, 1, 5, "a"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&p1.db));

    /* p2 now commits over a moved archive: the reconciled overlap is invisible in
     * any journal, but the committed-seq gate rejects the straddle. */
    s = cdb_tx_commit(&p2.db);
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        CDB_E_COLLISION, s,
        "a reconciled-away overlap MUST still be rejected (FR5) — never silent-accept");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* B1 current contract / reproduction (reported as fork #67, NOT relaxed): a
 * DISJOINT writer that straddles a peer's reconcile is ALSO rejected today,
 * because the committed-seq gate is write-set-blind. This is the over-rejection
 * B1 describes — fail-closed (safe) but too conservative. The assertion pins the
 * landed behavior; when #67 adds an archive-side reconciled-write-set signal
 * this DISJOINT straddle becomes CDB_OK and THIS assertion flips to CDB_OK
 * (the overlap-straddle test above stays CDB_E_COLLISION). */
static void test_disjoint_straddle_rejected_b1_fork67(void)
{
    cdb_status s;
    open_two();

    /* p2 pins the empty-archive snapshot with an open DISJOINT tx on (2,2). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&p2.db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&p2.db, 2, 2, CDB_OP_REPLACE, "b", 1));

    /* p1 commits+reconciles a DISJOINT (1,5), advancing committed_seq. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, commit_one(&p1, 1, 5, "a"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&p1.db));

    s = cdb_tx_commit(&p2.db);
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        CDB_E_COLLISION, s,
        "B1 (#67): disjoint straddle is conservatively rejected today — fail-closed, not relaxed");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* AC9 / FR5 guard-the-guard: the #42 bounded-wait constant is intact. The pure
 * bound function clamps an absent/huge (untrusted cross-process) holder estimate
 * to the hard cap, so no peer-published value can induce an unbounded wait. (The
 * full scenario oracle is test_coord_bounded_wait_f42; this is a cheap tripwire
 * that the #60 close/collision edits did not touch the cap.) */
static void test_bounded_wait_cap_not_weakened(void)
{
    const uint64_t cap = (uint64_t)CDB_TX_WAIT_HARD_CAP_MS * 1000000u;
    TEST_ASSERT_EQUAL_UINT64(cap, cdb_tx_collision_wait_bound_ns(CDB_COORD_ESTIMATE_UNKNOWN));
    TEST_ASSERT_EQUAL_UINT64(cap, cdb_tx_collision_wait_bound_ns(0xFFFFFFFEu));
    TEST_ASSERT_TRUE(cdb_tx_collision_wait_bound_ns(1u) > 0u); /* finite, no busy-spin */
    TEST_ASSERT_TRUE(cdb_tx_collision_wait_bound_ns(CDB_COORD_ESTIMATE_UNKNOWN) <= cap);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_disjoint_writers_commit_concurrently);
    RUN_TEST(test_overlapping_writers_collide);
    RUN_TEST(test_reconciled_overlap_straddle_rejected);
    RUN_TEST(test_disjoint_straddle_rejected_b1_fork67);
    RUN_TEST(test_bounded_wait_cap_not_weakened);
    return UNITY_END();
}
