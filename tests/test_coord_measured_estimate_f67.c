/* #67 (spec 5.9.6) — measured per-op-kind completion estimate for the non-baton
 * busy op kinds (RECONCILE/COMPACT/GRAPH/RECOVER/REBASE).
 *
 * Regression oracle for audit item #67, the storage/coord follow-up deferred
 * from #42. Before the fix the five non-baton busy op kinds always published the
 * flat conservative constant (CDB_COORD_ESTIMATE_CONSERVATIVE_MS, 30 s) because
 * the measured path in estimate_of was gated on holding the baton (issued != 0).
 * A prepared-tx collision waiter (#42, spec 5.9.5, cdb_db.c check_slot_collisions)
 * therefore read a fictitious 30 s bound for a non-baton operation that may be
 * finishing in milliseconds.
 *
 * The fix derives a measured estimate from the op's own progress already in the
 * coord record (x/x_total scaled by work-left/work-done, else the bounded elapsed
 * time since status_start), for the non-baton kinds too — no new stored field.
 *
 * What this test pins down, deterministically on the fault environment's virtual
 * clock (no wall-clock or network dependence):
 *   - AC1: a non-baton holder with real progress publishes a measured estimate
 *          derived from that progress — not the flat constant, and finite.
 *   - AC2: the same op kind with no progress basis still falls back to the flat
 *          constant.
 *   - AC3: every produced value is finite and below the UNKNOWN sentinel; a COMMIT
 *          with no baton progress and an unknown op kind stay UNKNOWN; idle is 0.
 *   - AC5: a genuine measurement never collides with the fallback magnitude (it is
 *          nudged off 30000), so holder_outlasts can tell measured from fallback by
 *          value alone, with no stored flag.
 *   - AC4: the #42 bounded prepared-tx wait against a live non-baton holder that
 *          now publishes a measured estimate still returns CDB_E_BUSY within the
 *          bound, never past the hard cap.
 *
 * Red->green (AC6): against the pre-fix tree the non-baton estimate is exactly the
 * flat 30 000 ms constant for a progressing holder, so AC1/AC5's measured-value
 * assertions fail; after the fix a progressing holder yields a measured value and
 * they pass. */
#define _POSIX_C_SOURCE 200809L

#include <string.h>

#include "unity.h"
#include "cdb_coord.h"
#include "cdb_db.h"
#include "cdb_endian.h"
#include "cdb_faultenv.h"
#include "cdb_journal.h"

#define FCAP (256u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define DIR "me67"
#define SEC 1000000000

/* Overlapping target both transactions in the #42 scenario write. */
#define OVERLAP_STORE 1u
#define OVERLAP_ENTRY 5u

/* A prepare stamp far above any clock-derived stamp the waiter can take, so the
 * holder is always the later writer and is waited out, not rejected (spec 5.9.4). */
#define HOLDER_PREP_STAMP 0x0FFFFFFFFFFFFFFFull

/* Virtual time the sleep hook adds per sleep, so the bound is reached in a few
 * dozen iterations with no real delay. */
#define HOOK_ADVANCE_NS SEC

/* Sleeps after which the holder is force-killed (only reached if the wait runs
 * unbounded). Comfortably above the iterations a bounded wait needs. */
#define HANG_GUARD 400

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
static struct proc holder, waiter;

/* A lone coordinator used for the pure estimate-value cases. */
static cdb_coord ec;

static unsigned hook_calls;
static int holder_forced_dead;

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

/* Keeps both coordinators beating as other processes would, and advances the
 * virtual clock so a bounded wait terminates quickly. Past the hang guard it
 * stops beating the holder and jumps the clock, so an unbounded (pre-fix) wait
 * sees the holder die and the test still terminates. */
static void sleep_hook(void *arg)
{
    (void)arg;
    hook_calls++;
    if (hook_calls > HANG_GUARD) {
        holder_forced_dead = 1;
        cdb_faultenv_advance(&fe, 20 * (int64_t)SEC); /* past the dead timeout */
        if (waiter.db.coord.joined)
            (void)cdb_db_tick(&waiter.db);
        return;
    }
    cdb_faultenv_advance(&fe, HOOK_ADVANCE_NS);
    if (holder.db.coord.joined)
        (void)cdb_db_tick(&holder.db);
    if (waiter.db.coord.joined)
        (void)cdb_db_tick(&waiter.db);
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
    memset(&holder.db, 0, sizeof holder.db);
    memset(&waiter.db, 0, sizeof waiter.db);
    memset(&ec, 0, sizeof ec);
    hook_calls = 0;
    holder_forced_dead = 0;
    cdb_faultenv_on_sleep(&fe, sleep_hook, NULL);
}

void tearDown(void)
{
    cdb_faultenv_on_sleep(&fe, NULL, NULL);
    if (ec.joined)
        (void)cdb_coord_leave(&ec);
    if (waiter.db.hb_running)
        (void)cdb_db_close(&waiter.db);
    /* The holder is left mid-transaction on purpose; closing may report that,
     * which is not what these tests assert. */
    if (holder.db.hb_running)
        (void)cdb_db_close(&holder.db);
}

/* -------------------------------------------------------- estimate values */

/* On the lone coordinator ec: re-stamps a busy status at "now", publishes
 * progress x/x_total, lets elapsed_ns of virtual time pass, forces a heartbeat,
 * and returns the estimate it wrote to its slot (spec 5.8). Re-stamping through
 * IDLE guarantees status_start is taken at this call even when op is unchanged,
 * so elapsed is exactly elapsed_ns and the case is deterministic. A lone primary
 * heartbeat does not sleep, so no virtual time passes except elapsed_ns. */
static uint32_t est_publish(uint8_t op, int64_t elapsed_ns, uint64_t x, uint64_t x_total)
{
    cdb_coord_status_save sv;
    cdb_coord_status_begin(&ec, CDB_COORD_OP_IDLE, &sv);
    cdb_coord_status_begin(&ec, op, &sv);
    (void)sv;
    ec.me.x = x;
    ec.me.x_total = x_total;
    if (elapsed_ns > 0)
        cdb_faultenv_advance(&fe, elapsed_ns);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_coord_beat(&ec, 1));
    return ec.me.estimate_ms;
}

static void join_ec(void)
{
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_coord_join(&ec, &env, DIR "/coord", db_id, CDB_ORDER_LITTLE, NULL));
}

/* AC1/AC3 (FR1/FR3): a non-baton holder with real progress publishes a measured
 * estimate derived from that progress — not the flat constant, finite, below the
 * UNKNOWN sentinel — on both the x/x_total basis and the elapsed-only basis. */
static void test_non_baton_progress_is_measured(void)
{
    uint32_t e;
    join_ec();

    /* Basis C (no work counters): the elapsed time since the op began. Three
     * virtual seconds elapsed -> 3000 ms, not the 30000 ms constant. */
    e = est_publish(CDB_COORD_OP_COMPACT, 3 * (int64_t)SEC, 0, 0);
    TEST_ASSERT_EQUAL_UINT32(3000u, e);
    TEST_ASSERT_TRUE(e != CDB_COORD_ESTIMATE_CONSERVATIVE_MS);
    TEST_ASSERT_TRUE(e < CDB_COORD_ESTIMATE_UNKNOWN);

    /* Basis A (x/x_total): two seconds elapsed, a quarter done -> three quarters
     * left -> 6000 ms, again not the constant. */
    e = est_publish(CDB_COORD_OP_GRAPH, 2 * (int64_t)SEC, 25, 100);
    TEST_ASSERT_EQUAL_UINT32(6000u, e);
    TEST_ASSERT_TRUE(e != CDB_COORD_ESTIMATE_CONSERVATIVE_MS);
    TEST_ASSERT_TRUE(e < CDB_COORD_ESTIMATE_UNKNOWN);

    /* The remaining three non-baton kinds also measure from elapsed time. */
    TEST_ASSERT_EQUAL_UINT32(1000u, est_publish(CDB_COORD_OP_RECONCILE, 1 * (int64_t)SEC, 0, 0));
    TEST_ASSERT_EQUAL_UINT32(4000u, est_publish(CDB_COORD_OP_RECOVER, 4 * (int64_t)SEC, 0, 0));
    TEST_ASSERT_EQUAL_UINT32(5000u, est_publish(CDB_COORD_OP_REBASE, 5 * (int64_t)SEC, 0, 0));
}

/* AC2 (FR2): the same op kinds with no progress basis (no time elapsed, no work
 * counters) fall back to the flat conservative constant. */
static void test_non_baton_no_basis_falls_back(void)
{
    join_ec();
    TEST_ASSERT_EQUAL_UINT32(CDB_COORD_ESTIMATE_CONSERVATIVE_MS,
                             est_publish(CDB_COORD_OP_RECONCILE, 0, 0, 0));
    TEST_ASSERT_EQUAL_UINT32(CDB_COORD_ESTIMATE_CONSERVATIVE_MS,
                             est_publish(CDB_COORD_OP_COMPACT, 0, 0, 0));
    TEST_ASSERT_EQUAL_UINT32(CDB_COORD_ESTIMATE_CONSERVATIVE_MS,
                             est_publish(CDB_COORD_OP_GRAPH, 0, 0, 0));
    TEST_ASSERT_EQUAL_UINT32(CDB_COORD_ESTIMATE_CONSERVATIVE_MS,
                             est_publish(CDB_COORD_OP_RECOVER, 0, 0, 0));
    TEST_ASSERT_EQUAL_UINT32(CDB_COORD_ESTIMATE_CONSERVATIVE_MS,
                             est_publish(CDB_COORD_OP_REBASE, 0, 0, 0));
}

/* AC3 (FR2): COMMIT with no baton progress stays UNKNOWN, an unknown op kind
 * stays UNKNOWN (even if it carries progress counters), and idle is 0. */
static void test_commit_and_unknown_and_idle(void)
{
    join_ec();
    /* COMMIT without the baton (issued == 0): no measured basis -> UNKNOWN. */
    TEST_ASSERT_EQUAL_UINT32(CDB_COORD_ESTIMATE_UNKNOWN,
                             est_publish(CDB_COORD_OP_COMMIT, 2 * (int64_t)SEC, 0, 0));
    /* An unknown op kind is not measurable, progress counters notwithstanding. */
    TEST_ASSERT_EQUAL_UINT32(CDB_COORD_ESTIMATE_UNKNOWN,
                             est_publish(CDB_COORD_OP_OTHER, 2 * (int64_t)SEC, 10, 100));
    /* Idle always estimates zero. */
    TEST_ASSERT_EQUAL_UINT32(0u, est_publish(CDB_COORD_OP_IDLE, 2 * (int64_t)SEC, 0, 0));
}

/* AC5/R1 (FR5): a genuine measurement never collides with the conservative
 * fallback magnitude. A basis that computes to exactly 30000 ms is nudged off by
 * 1 ms, so holder_outlasts's value test (== CONSERVATIVE_MS means "fallback,
 * ignore") can never misclassify a real measurement as a fallback. */
static void test_measured_never_equals_fallback(void)
{
    uint32_t e;
    join_ec();
    /* elapsed 1 ms, 1 of 30001 done -> 30000 left before the collision nudge. */
    e = est_publish(CDB_COORD_OP_COMPACT, 1 * (int64_t)SEC / 1000, 1, 30001);
    TEST_ASSERT_EQUAL_UINT32(CDB_COORD_ESTIMATE_CONSERVATIVE_MS - 1u, e);
    TEST_ASSERT_TRUE(e != CDB_COORD_ESTIMATE_CONSERVATIVE_MS);
}

/* -------------------------------------------------------- #42 bounded wait */

/* Leaves the holder (slot 0) with a genuine, uncommitted, higher-stamped prepare
 * overlapping (OVERLAP_STORE, OVERLAP_ENTRY), publishing a busy non-baton status
 * (COMPACT). Lets some virtual time elapse before beating it out, so the status
 * carries a MEASURED estimate (the #67 non-baton path), not the flat constant. */
static void arm_measured_holder(void)
{
    cdb_coord_status_save sv;
    uint8_t prep[CDB_PREPARE_PAYLOAD_SIZE];
    cdb_record r;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&holder.db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_tx_put(&holder.db, OVERLAP_STORE, OVERLAP_ENTRY, CDB_OP_REPLACE, "h", 1));

    cdb_store_u64(prep, HOLDER_PREP_STAMP, holder.db.pager.order);
    memset(&r, 0, sizeof r);
    r.kind = (uint8_t)CDB_RECORD_PREPARE;
    r.tx_id = holder.db.tx_id;
    r.payload = prep;
    r.payload_len = CDB_PREPARE_PAYLOAD_SIZE;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_journal_append(&holder.db.journal, &r, holder.db.cfg.record_buf,
                                             holder.db.cfg.record_buf_size));

    /* Publish a busy non-baton status, let time pass so the estimate is measured
     * (#67), then beat it out so the waiter sees it. */
    cdb_coord_status_begin(&holder.db.coord, CDB_COORD_OP_COMPACT, &sv);
    (void)sv; /* the status stands for the rest of the test */
    cdb_faultenv_advance(&fe, 2 * (int64_t)SEC);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_tick(&holder.db));
}

/* AC4 (FR4): the #42 bounded prepared-tx wait against a live non-baton holder
 * that now publishes a MEASURED estimate still returns CDB_E_BUSY within the
 * bound, without the hang guard ever having to kill the holder (which would mean
 * the wait ran unbounded). It also confirms the holder's published estimate is a
 * real measurement (neither UNKNOWN nor the flat constant), so the measured path
 * is what the waiter read. */
static void test_measured_holder_wait_is_bounded(void)
{
    cdb_coord_rec r;
    cdb_status s;
    int valid;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&holder));
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&waiter));
    TEST_ASSERT_EQUAL_UINT(0, holder.db.coord.me.slot);
    TEST_ASSERT_EQUAL_UINT(1, waiter.db.coord.me.slot);

    arm_measured_holder();

    /* The waiter reads a measured, finite, non-constant estimate from the holder. */
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_coord_read_slot(&waiter.db.coord, holder.db.coord.me.slot, &r, &valid));
    TEST_ASSERT_TRUE(valid);
    TEST_ASSERT_EQUAL_UINT(CDB_COORD_OP_COMPACT, r.status_op);
    TEST_ASSERT_TRUE(r.estimate_ms != CDB_COORD_ESTIMATE_UNKNOWN);
    TEST_ASSERT_TRUE(r.estimate_ms != CDB_COORD_ESTIMATE_CONSERVATIVE_MS);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&waiter.db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_tx_put(&waiter.db, OVERLAP_STORE, OVERLAP_ENTRY, CDB_OP_REPLACE, "w", 1));
    s = cdb_tx_commit(&waiter.db);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_BUSY, s,
                                  "bounded wait must shed a measured non-baton holder as BUSY");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, holder_forced_dead,
                                  "wait ran unbounded: the hang guard had to kill the holder");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_non_baton_progress_is_measured);
    RUN_TEST(test_non_baton_no_basis_falls_back);
    RUN_TEST(test_commit_and_unknown_and_idle);
    RUN_TEST(test_measured_never_equals_fallback);
    RUN_TEST(test_measured_holder_wait_is_bounded);
    return UNITY_END();
}
