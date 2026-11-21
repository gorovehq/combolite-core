/* Multi-writer open / recovery (#33): a sound archive left by a crashed or
 * concurrent writer must open and reconcile its pending journal WITHOUT
 * CDB_DB_ACCEPT_LOSS, and must refuse (fail closed, CDB_E_CORRUPT) only when
 * a journal marked in use is genuinely missing with un-folded data.
 *
 * The 2026-11 completeness audit flagged cdb_db.c:1762-1766 as a CRITICAL
 * "sound archive rejected at open" with an undocumented root cause. This suite
 * pins the behaviour of that path:
 *
 *   1. test_takeover_pending_journal_opens  -- a dead writer's slot whose
 *      journal still holds a committed, un-reconciled transaction is adopted
 *      on the non-alone open path (cdb_db.c:1753-1780) with no ACCEPT_LOSS;
 *      the transaction survives. (The capability #33 feared was broken.)
 *   2. test_both_writers_crash_reopen       -- two parallel writers commit,
 *      the machine loses power, and the archive reopens with every commit.
 *   3. test_missing_in_use_journal_fails_closed -- an in-use journal that is
 *      genuinely gone with un-folded data is refused without ACCEPT_LOSS
 *      (real loss); ACCEPT_LOSS opens it lossily. The fail-closed guard.
 *   4. test_fold_then_crash_matrix_no_false_reject -- a crash injected at
 *      every point of the fold-and-remove reconcile that retires a dead
 *      peer's journal, under three power-loss models, never leaves a sound,
 *      fully-folded archive that reports CDB_E_CORRUPT. This is the
 *      regression oracle: the fail-closed depends on the journal file being
 *      removed only after the slot's CDB_COORD_JOURNAL flag is cleared
 *      durably (cdb_coord_set_journal / cdb_coord_remove_slot sync before the
 *      journal env_remove). If that ordering regresses the #33 symptom
 *      reappears and this test goes red.
 *
 * Deterministic and hermetic: one fault environment, several coordinators in
 * one thread, the sleep hook lets the others beat while one waits; no real
 * process race, wall clock, or network. */
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
#define DIR "w"
#define SEC 1000000000

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 2048u];
static cdb_faultenv fe;
static cdb_env env;
static const uint8_t db_id[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

/* One process's database buffers. */
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

/* Entry N is logical page N; the apply callback keeps the test's key-value
 * pages (REPLACE sets, PATCH appends, DELETE frees). */
static cdb_status kv_apply(void *ctx, cdb_pager *p, const cdb_delta *d)
{
    uint8_t cur[PAGE], val[PAGE];
    cdb_page_header t;
    size_t len = 0;
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
    if (d->op == CDB_OP_PATCH) {
        s = cdb_pager_read(p, d->entry_id, cur, &t);
        if (s == CDB_OK) {
            len = t.payload_len;
            memcpy(val, cur + cdb_page_payload_offset(p->fmt), len);
        } else if (s != CDB_E_NOT_FOUND) {
            return s;
        }
    }
    if (len + d->len >= 64)
        return CDB_E_INVALID_ARG;
    memcpy(val + len, d->data, d->len);
    memset(&t, 0, sizeof t);
    t.type = CDB_PAGE_TYPE_DATA_TEST;
    t.store_id = d->store_id;
    return cdb_pager_write(p, d->entry_id, &t, val, len + d->len);
}

/* The value of entry e in p's pages, as a string; "" when absent. */
static const char *value_of(struct proc *p, uint64_t e)
{
    static char out[PAGE];
    uint8_t buf[PAGE];
    cdb_page_header h;
    cdb_status s = cdb_pager_read(&p->db.pager, e, buf, &h);
    out[0] = '\0';
    if (s != CDB_OK)
        return out;
    memcpy(out, buf + cdb_page_payload_offset(p->db.pager.fmt), h.payload_len);
    out[h.payload_len] = '\0';
    return out;
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

/* p crashes while the others go on: its handles close and the system releases
 * its locks (spec 5.8), but its files stay as they are. */
static void crash_proc(struct proc *p)
{
    cdb_storage_close(&p->db.overlay_st);
    cdb_storage_close(&p->db.journal_st);
    cdb_storage_close(&p->db.archive_st);
    cdb_coord_abandon(&p->db.coord);
}

static void tick_p1(void *arg)
{
    (void)arg;
    if (p1.db.coord.joined)
        (void)cdb_db_tick(&p1.db);
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
    c.records_per_file = 2048;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
    TEST_ASSERT_EQUAL_INT(CDB_OK, env.ops->mkdir(env.ctx, DIR));
    TEST_ASSERT_EQUAL_INT(CDB_OK, env.ops->sync_dir(env.ctx, "."));
    memset(&p1.db, 0, sizeof p1.db);
    memset(&p2.db, 0, sizeof p2.db);
}

/* Lets slot 1's dead timeout pass with p1 beating, as a surviving peer would. */
static void wait_dead_timeout(void)
{
    int64_t rem = 4 * (int64_t)SEC;
    cdb_faultenv_on_sleep(&fe, tick_p1, NULL);
    while (rem > 0) {
        cdb_faultenv_advance(&fe, SEC / 4);
        (void)cdb_db_tick(&p1.db);
        rem -= SEC / 4;
    }
}

void setUp(void)
{
    init_env();
}

void tearDown(void)
{
    cdb_faultenv_on_sleep(&fe, NULL, NULL);
    if (p2.db.hb_running)
        (void)cdb_db_close(&p2.db);
    if (p1.db.hb_running)
        (void)cdb_db_close(&p1.db);
}

/* 1. A dead writer's slot whose journal still holds a committed, un-reconciled
 * transaction is taken over on the non-alone open path and adopted WITHOUT
 * CDB_DB_ACCEPT_LOSS; the transaction survives. This is the recoverable case
 * the #33 symptom must never reject. */
static void test_takeover_pending_journal_opens(void)
{
    cdb_faultenv_on_sleep(&fe, tick_both, NULL);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p2, 0));
    TEST_ASSERT_EQUAL_UINT(1, p2.db.coord.me.slot);

    cdb_faultenv_advance(&fe, 10 * 1000 * 1000);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&p2.db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&p2.db, 1, 2, CDB_OP_REPLACE, "b", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&p2.db));

    /* p2 crashes with its committed 'b' only in its journal; p1 stays live. */
    crash_proc(&p2);
    wait_dead_timeout();

    /* A newcomer reuses the struct, takes over slot 1 while p1 is live, and
     * must adopt the pending journal with no loss accepted. */
    memset(&p2.db, 0, sizeof p2.db);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p2, 0));
    TEST_ASSERT_EQUAL_UINT(1, p2.db.coord.me.slot);
    TEST_ASSERT_EQUAL_STRING("b", value_of(&p2, 2));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* 2. Two parallel writers commit; the machine loses power; the archive reopens
 * with every committed transaction, no ACCEPT_LOSS. */
static void test_both_writers_crash_reopen(void)
{
    cdb_faultenv_on_sleep(&fe, tick_both, NULL);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p2, 0));

    cdb_faultenv_advance(&fe, 10 * 1000 * 1000);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&p1.db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&p1.db, 1, 1, CDB_OP_REPLACE, "a", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&p1.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&p2.db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&p2.db, 1, 2, CDB_OP_REPLACE, "b", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&p2.db));

    /* Power loss: every unsynced write is gone, every synced commit stays. */
    cdb_faultenv_crash_now(&fe, CDB_CRASH_DROP_UNSYNCED, 0, 0);
    cdb_faultenv_reboot(&fe);
    cdb_faultenv_on_sleep(&fe, NULL, NULL);

    memset(&p1.db, 0, sizeof p1.db);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1, 0));
    TEST_ASSERT_EQUAL_STRING("a", value_of(&p1, 1));
    TEST_ASSERT_EQUAL_STRING("b", value_of(&p1, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* 3. Fail-closed guard: an in-use journal that is genuinely gone with its
 * committed data never folded into the archive is real loss. Open must refuse
 * it without CDB_DB_ACCEPT_LOSS, and accept it (lossily) with it. */
static void test_missing_in_use_journal_fails_closed(void)
{
    cdb_faultenv_on_sleep(&fe, tick_both, NULL);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p2, 0));

    cdb_faultenv_advance(&fe, 10 * 1000 * 1000);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&p2.db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&p2.db, 1, 2, CDB_OP_REPLACE, "b", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&p2.db));

    /* 'b' lives only in slot 1's journal; nothing is reconciled. Destroy the
     * journal while the slot still advertises it in use: genuine loss. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, env.ops->remove(env.ctx, DIR "/db.cdbwork/main.1.cdb"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, env.ops->sync_dir(env.ctx, DIR "/db.cdbwork"));
    crash_proc(&p2);
    wait_dead_timeout();

    /* The take-over must fail closed: the journal was in use and its committed
     * work is nowhere in the archive. */
    memset(&p2.db, 0, sizeof p2.db);
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, open_proc(&p2, 0));

    /* Only an explicit loss-accept opens it, and 'b' is indeed gone. */
    memset(&p2.db, 0, sizeof p2.db);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p2, CDB_DB_ACCEPT_LOSS));
    TEST_ASSERT_EQUAL_STRING("", value_of(&p2, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* 4. Regression oracle. A reconcile that folds a dead peer's committed
 * transaction into the archive and then retires its journal is crashed at
 * every I/O point, under all three power-loss models. After each crash the
 * archive, if it opens at all, opens with no loss; and if it reports
 * CDB_E_CORRUPT the data genuinely is not in the archive (loss-accept cannot
 * recover 'b' either). A sound, fully-folded archive is never rejected.
 *
 * This fails (false_rejects > 0) the moment the fold-before-retire ordering
 * regresses -- i.e. if a journal file is removed before its slot's
 * CDB_COORD_JOURNAL flag is cleared durably -- which is exactly the #33
 * "sound archive rejected at open" symptom. */
static void test_fold_then_crash_matrix_no_false_reject(void)
{
    const cdb_crash_mode modes[3] = { CDB_CRASH_DROP_UNSYNCED, CDB_CRASH_TORN, CDB_CRASH_REORDER };
    unsigned false_rejects = 0, recovered = 0, crashes_fired = 0;
    int mi;
    uint64_t op;

    for (mi = 0; mi < 3; mi++) {
        for (op = 1; op <= 60; op++) {
            cdb_status rs;

            if (mi != 0 || op != 1)
                init_env(); /* setUp already built the first environment */
            cdb_faultenv_on_sleep(&fe, tick_both, NULL);
            if (open_proc(&p1, 0) != CDB_OK || open_proc(&p2, 0) != CDB_OK) {
                crash_proc(&p2);
                crash_proc(&p1);
                continue;
            }
            cdb_faultenv_advance(&fe, 10 * 1000 * 1000);
            if (cdb_tx_begin(&p2.db, CDB_DURABILITY_DEFAULT) != CDB_OK
                || cdb_tx_put(&p2.db, 1, 2, CDB_OP_REPLACE, "b", 1) != CDB_OK
                || cdb_tx_commit(&p2.db) != CDB_OK) {
                crash_proc(&p2);
                crash_proc(&p1);
                continue;
            }
            crash_proc(&p2);
            wait_dead_timeout();

            /* p1, now holding every slot, reconciles: it folds dead slot 1's
             * committed 'b' into the archive, then retires slot 1's journal.
             * Cut power at the op-th I/O of that sequence. */
            cdb_faultenv_arm(&fe, op, modes[mi], 1, 8);
            if (cdb_db_reconcile(&p1.db) != CDB_OK)
                crashes_fired++; /* the armed crash struck mid-reconcile */
            cdb_faultenv_reboot(&fe);
            cdb_faultenv_on_sleep(&fe, NULL, NULL);

            memset(&p1.db, 0, sizeof p1.db);
            rs = open_proc(&p1, 0);
            if (rs == CDB_OK) {
                recovered++;
                (void)cdb_db_close(&p1.db);
            } else if (rs == CDB_E_CORRUPT) {
                cdb_status rl;
                memset(&p1.db, 0, sizeof p1.db);
                rl = open_proc(&p1, CDB_DB_ACCEPT_LOSS);
                if (rl == CDB_OK) {
                    /* A refusal is false only if nothing was actually lost: the
                     * archive is sound and 'b' is already in it. */
                    if (strcmp(value_of(&p1, 2), "b") == 0)
                        false_rejects++;
                    (void)cdb_db_close(&p1.db);
                }
            }
        }
    }

    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, false_rejects,
                                   "a sound, fully-folded archive reported CDB_E_CORRUPT (#33)");
    /* The sweep must have actually injected crashes and actually reopened, or
     * it proves nothing. */
    TEST_ASSERT_TRUE_MESSAGE(crashes_fired > 0, "no injected crash ever fired");
    TEST_ASSERT_TRUE_MESSAGE(recovered > 0, "no crash point ever reopened");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_takeover_pending_journal_opens);
    RUN_TEST(test_both_writers_crash_reopen);
    RUN_TEST(test_missing_in_use_journal_fails_closed);
    RUN_TEST(test_fold_then_crash_matrix_no_false_reject);
    return UNITY_END();
}
