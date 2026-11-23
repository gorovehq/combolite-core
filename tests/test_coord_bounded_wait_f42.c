/* #42 FR1/FR2 — the prepared-transaction collision wait is bounded.
 *
 * Regression oracle for audit item #42: a waiter that collides with a live
 * holder's later, higher-stamped prepare (spec 5.9.4) must not stall forever on
 * an alive-but-slow holder. It reads the holder's published completion estimate
 * and waits at most min(estimate + margin, hard cap) on the monotonic clock,
 * then returns CDB_E_BUSY (spec 5.9.5, cdb_db.c check_slot_collisions).
 *
 * The scenario is built deterministically on one fault environment (two
 * coordinators in one thread, the sleep hook beats the holder as another
 * process would): the holder (slot 0) is left with a genuine, uncommitted,
 * higher-stamped overlapping prepare — a holder stuck between PREPARE and
 * COMMIT — and keeps beating. The waiter (slot 1) then commits an overlapping
 * write and must return CDB_E_BUSY within the bound.
 *
 * Red->green / anti-hang guard: the sleep hook advances a virtual clock so the
 * bound is reached in a handful of iterations and the test takes no real time;
 * a high iteration guard force-kills the holder if the wait ever runs unbounded
 * (the pre-fix behaviour), so the test terminates either way. The assertions
 * are result == CDB_E_BUSY *and* holder never force-killed: pre-fix the wait is
 * infinite, the guard trips, the holder dies and the waiter returns CDB_OK —
 * both assertions fail (red). Post-fix the bound returns CDB_E_BUSY first
 * (green). */
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
#define DIR "bw"
#define SEC 1000000000

/* Overlapping target both transactions write. */
#define OVERLAP_STORE 1u
#define OVERLAP_ENTRY 5u

/* A prepare stamp far larger than any clock-derived stamp the waiter can take,
 * so the holder is always the later writer and the waiter waits rather than
 * rejecting it outright (spec 5.9.4). */
#define HOLDER_PREP_STAMP 0x0FFFFFFFFFFFFFFFull

/* Virtual time the sleep hook adds per sleep, so the bound (tens of seconds of
 * virtual time) is reached in a few dozen iterations with no real delay. */
#define HOOK_ADVANCE_NS SEC

/* Sleeps after which the holder is force-killed (only reached if the wait runs
 * unbounded). Comfortably above the iterations a bounded wait needs even at the
 * 60 s hard cap (~60), so a bounded wait never trips it. */
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
    hook_calls = 0;
    holder_forced_dead = 0;
    cdb_faultenv_on_sleep(&fe, sleep_hook, NULL);
}

void tearDown(void)
{
    cdb_faultenv_on_sleep(&fe, NULL, NULL);
    if (waiter.db.hb_running)
        (void)cdb_db_close(&waiter.db);
    /* The holder is left mid-transaction on purpose; closing may report that,
     * which is not what this test asserts. */
    if (holder.db.hb_running)
        (void)cdb_db_close(&holder.db);
}

/* Leaves the holder with a genuine, uncommitted, higher-stamped prepare that
 * overlaps (OVERLAP_STORE, OVERLAP_ENTRY): a real data record from the engine
 * plus a hand-appended PREPARE, with no COMMIT or ABORT — exactly a holder
 * stuck between prepare and commit. The holder keeps its coordinator joined and
 * beating. `op` is the status the holder publishes, which drives the estimate
 * it publishes (spec 5.8). */
static void arm_stuck_holder(uint8_t op)
{
    cdb_coord_status_save sv;
    uint8_t prep[CDB_PREPARE_PAYLOAD_SIZE];
    cdb_record r;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&holder.db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_tx_put(&holder.db, OVERLAP_STORE, OVERLAP_ENTRY, CDB_OP_REPLACE, "h", 1));

    /* Append a prepare with a stamp above any clock-derived stamp the waiter
     * can take, so the holder is the later writer and is waited out, not
     * rejected (spec 5.9.4). The transaction is deliberately never finished. */
    cdb_store_u64(prep, HOLDER_PREP_STAMP, holder.db.pager.order);
    memset(&r, 0, sizeof r);
    r.kind = (uint8_t)CDB_RECORD_PREPARE;
    r.tx_id = holder.db.tx_id;
    r.payload = prep;
    r.payload_len = CDB_PREPARE_PAYLOAD_SIZE;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_journal_append(&holder.db.journal, &r, holder.db.cfg.record_buf,
                                             holder.db.cfg.record_buf_size));

    /* Publish a busy status so the holder's slot carries a completion estimate
     * the waiter can read (FR2); beat it out so the waiter sees it. */
    cdb_coord_status_begin(&holder.db.coord, op, &sv);
    (void)sv; /* the status stands for the rest of the test */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_tick(&holder.db));
}

/* The waiter commits an overlapping write and must return CDB_E_BUSY from the
 * bounded collision wait, without the hang guard ever having to kill the
 * holder. */
static void assert_waiter_busy_not_hung(void)
{
    cdb_status s;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&waiter.db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_tx_put(&waiter.db, OVERLAP_STORE, OVERLAP_ENTRY, CDB_OP_REPLACE, "w", 1));
    s = cdb_tx_commit(&waiter.db);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_BUSY, s, "bounded wait must shed a stuck holder as BUSY");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, holder_forced_dead,
                                  "wait ran unbounded: the hang guard had to kill the holder");
}

/* AC1: a COMMIT-kind holder (no progress basis -> estimate UNKNOWN) is bounded
 * by the hard cap, not infinite. */
static void test_commit_holder_wait_is_bounded(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&holder));
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&waiter));
    TEST_ASSERT_EQUAL_UINT(0, holder.db.coord.me.slot);
    TEST_ASSERT_EQUAL_UINT(1, waiter.db.coord.me.slot);

    arm_stuck_holder(CDB_COORD_OP_COMMIT);
    assert_waiter_busy_not_hung();
}

/* AC3: a non-commit op-kind holder (COMPACT) publishes a finite conservative
 * estimate (FR2), and the waiter against it is bounded, not infinite. */
static void test_compact_holder_wait_is_bounded(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&holder));
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&waiter));
    TEST_ASSERT_EQUAL_UINT(0, holder.db.coord.me.slot);
    TEST_ASSERT_EQUAL_UINT(1, waiter.db.coord.me.slot);

    arm_stuck_holder(CDB_COORD_OP_COMPACT);
    assert_waiter_busy_not_hung();
}

/* AC2/AC4 companion: the pure bound function is finite and positive for every
 * estimate, clamps UNKNOWN and over-cap values to the hard cap (the untrusted
 * holder cannot induce an unbounded wait), and adds the margin otherwise. */
static void test_bound_is_always_finite(void)
{
    const uint64_t cap = (uint64_t)CDB_TX_WAIT_HARD_CAP_MS * 1000000u;
    TEST_ASSERT_EQUAL_UINT64(cap, cdb_tx_collision_wait_bound_ns(CDB_COORD_ESTIMATE_UNKNOWN));
    TEST_ASSERT_EQUAL_UINT64(cap, cdb_tx_collision_wait_bound_ns(CDB_TX_WAIT_HARD_CAP_MS));
    TEST_ASSERT_EQUAL_UINT64(cap,
                             cdb_tx_collision_wait_bound_ns(0xFFFFFFFEu)); /* huge -> clamped */
    TEST_ASSERT_EQUAL_UINT64((uint64_t)(CDB_TX_WAIT_MARGIN_MS) * 1000000u,
                             cdb_tx_collision_wait_bound_ns(0u));
    TEST_ASSERT_EQUAL_UINT64((uint64_t)(100u + CDB_TX_WAIT_MARGIN_MS) * 1000000u,
                             cdb_tx_collision_wait_bound_ns(100u));
    /* Finite and positive across the range, never zero (no busy-spin). */
    TEST_ASSERT_TRUE(cdb_tx_collision_wait_bound_ns(1u) > 0u);
    TEST_ASSERT_TRUE(cdb_tx_collision_wait_bound_ns(CDB_COORD_ESTIMATE_UNKNOWN) <= cap);
}

static cdb_coord est_coord;

/* Joins one coordinator, sets a busy status, forces a heartbeat, and returns
 * the estimate it published to its slot (spec 5.8). */
static uint32_t published_estimate(uint8_t op)
{
    cdb_coord_status_save sv;
    cdb_coord_status_begin(&est_coord, op, &sv);
    (void)sv; /* the status stands until the next call changes it */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_coord_beat(&est_coord, 1));
    return est_coord.me.estimate_ms;
}

/* AC3/AC4 (FR2): every busy non-baton op kind publishes the named conservative
 * constant (not UNKNOWN), so a waiter's bounded wait has a finite value to read
 * for any holder; COMMIT without a progress basis stays UNKNOWN (still bounded
 * by the hard cap), and idle is zero. */
static void test_fr2_estimate_finite_for_every_busy_op(void)
{
    memset(&est_coord, 0, sizeof est_coord);
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_coord_join(&est_coord, &env, DIR "/coord", db_id, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_UINT32(CDB_COORD_ESTIMATE_CONSERVATIVE_MS,
                             published_estimate(CDB_COORD_OP_RECONCILE));
    TEST_ASSERT_EQUAL_UINT32(CDB_COORD_ESTIMATE_CONSERVATIVE_MS,
                             published_estimate(CDB_COORD_OP_COMPACT));
    TEST_ASSERT_EQUAL_UINT32(CDB_COORD_ESTIMATE_CONSERVATIVE_MS,
                             published_estimate(CDB_COORD_OP_GRAPH));
    TEST_ASSERT_EQUAL_UINT32(CDB_COORD_ESTIMATE_CONSERVATIVE_MS,
                             published_estimate(CDB_COORD_OP_RECOVER));
    TEST_ASSERT_EQUAL_UINT32(CDB_COORD_ESTIMATE_CONSERVATIVE_MS,
                             published_estimate(CDB_COORD_OP_REBASE));
    TEST_ASSERT_EQUAL_UINT32(CDB_COORD_ESTIMATE_UNKNOWN, published_estimate(CDB_COORD_OP_COMMIT));
    TEST_ASSERT_EQUAL_UINT32(0u, published_estimate(CDB_COORD_OP_IDLE));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_coord_leave(&est_coord));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_bound_is_always_finite);
    RUN_TEST(test_fr2_estimate_finite_for_every_busy_op);
    RUN_TEST(test_commit_holder_wait_is_bounded);
    RUN_TEST(test_compact_holder_wait_is_bounded);
    return UNITY_END();
}
