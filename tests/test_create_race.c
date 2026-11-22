/* Concurrent database CREATION race (#46).
 *
 * The create path once checked "does the archive exist?" and then created it
 * with O_CREAT only (cdb_db.c:~1756->1761, cdb_hostfile.c). Two processes
 * creating the SAME new database at the same instant both saw "not there" and
 * both ran cdb_pager_create over one file: a check-then-create TOCTOU
 * (CWE-367) that double-formats a fresh archive. Coordinators cannot mediate
 * it -- they key off the archive's db_id, which does not exist until the
 * header is written -- so the claim must be atomic at the file-open layer.
 *
 * The fix gives the environment an exclusive-create mode (CDB_ENV_EXCL ->
 * O_EXCL): the create path requests CDB_ENV_CREATE|CDB_ENV_EXCL, so exactly
 * one creator wins and every loser gets CDB_E_EXISTS and fails closed, never
 * proceeding into an archive another creator is still formatting.
 *
 * The TOCTOU window (between the exists-check and the create-open) has no
 * sleep point, so a test cannot drive it with the sleep hook alone. Instead an
 * interposing environment shim wraps the fault env's `open`: when the first
 * creator reaches its archive create-open, the shim runs the SECOND creator to
 * full completion first, then lets the first creator's open proceed -- exactly
 * the pre-slot-init interleaving the bug needs. Everything delegates to one
 * fault env; the shim only overrides `open`, so it stays deterministic and
 * hermetic (no real process race, wall clock, or network) and uses only the
 * public cdb_env / cdb_db API, so it compiles and reproduces RED at the
 * pre-fix merge-base.
 *
 * Deferred to a separate follow-up (explicitly out of scope here): concurrent
 * writers of different books colliding on nearly every tx; a writer unable to
 * close while others are live ("close failed: busy", leaking slots); the
 * one-off CDB_E_STATE under load. These are coordinator-contention items, not
 * the create race. */
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
#define DIR "cr"
#define ARCHIVE_SUFFIX ".cdbarch"

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 2048u];
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
static struct proc pa, pb; /* pa is the outer creator, pb the interposed one */

/* The interposing environment: a fault env (first member, so the delegated
 * ops that cast ctx to cdb_faultenv* keep working) plus a copy of its op table
 * with `open` overridden. */
struct shim {
    cdb_faultenv fe;
    cdb_env_ops ops;
    cdb_status (*inner_open)(void *ctx, const char *path, unsigned flags, cdb_storage *out);
    int armed;  /* a nested creator should run at the next archive create-open */
    int firing; /* re-entrancy guard: the nested creator must not re-trigger */
};
static struct shim sh;
static cdb_env env;

static cdb_status rc_b; /* the interposed creator's result */
static int b_ran;

static int ends_with(const char *s, const char *suffix)
{
    size_t ls = strlen(s), lx = strlen(suffix);
    return ls >= lx && strcmp(s + (ls - lx), suffix) == 0;
}

/* Entry N is logical page N; the apply callback keeps the test's key-value
 * pages (REPLACE sets). */
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
    if (d->len >= 64)
        return CDB_E_INVALID_ARG;
    memcpy(val, d->data, d->len);
    memset(&t, 0, sizeof t);
    t.type = CDB_PAGE_TYPE_DATA_TEST;
    t.store_id = d->store_id;
    return cdb_pager_write(p, d->entry_id, &t, val, d->len);
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

/* Beats whichever coordinators have already joined, so the first creator's
 * coordinator join (the merge-base RED path, where the loser still reaches it)
 * can complete against a live winner, as a real peer would. */
static void tick_joined(void *arg)
{
    (void)arg;
    if (pa.db.coord.joined)
        (void)cdb_db_tick(&pa.db);
    if (pb.db.coord.joined)
        (void)cdb_db_tick(&pb.db);
}

/* Runs the second creator to completion. Invoked from inside the first
 * creator's archive create-open (see shim_open). */
static void run_b(void)
{
    rc_b = open_proc(&pb, 0);
    b_ran = 1;
}

static cdb_status shim_open(void *ctx, const char *path, unsigned flags, cdb_storage *out)
{
    struct shim *s = (struct shim *)ctx; /* fe is the first member, so ctx == s */
    if (s->armed && !s->firing && (flags & CDB_ENV_CREATE) && ends_with(path, ARCHIVE_SUFFIX)) {
        s->armed = 0; /* one-shot */
        s->firing = 1;
        run_b();
        s->firing = 0;
    }
    return s->inner_open(ctx, path, flags, out);
}

static void init_env(void)
{
    cdb_faultenv_config c;
    cdb_env base;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 2048;
    memset(&sh, 0, sizeof sh);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&sh.fe, &c, &base));
    sh.ops = *base.ops; /* copy the table; override only open */
    sh.inner_open = base.ops->open;
    sh.ops.open = shim_open;
    env.ops = &sh.ops;
    env.ctx = &sh.fe;
    env.accel = NULL;
    env.accel_ctx = NULL;
    TEST_ASSERT_EQUAL_INT(CDB_OK, env.ops->mkdir(env.ctx, DIR));
    TEST_ASSERT_EQUAL_INT(CDB_OK, env.ops->sync_dir(env.ctx, "."));
    memset(&pa.db, 0, sizeof pa.db);
    memset(&pb.db, 0, sizeof pb.db);
    rc_b = CDB_E_INVALID_ARG;
    b_ran = 0;
}

void setUp(void)
{
    init_env();
}

void tearDown(void)
{
    cdb_faultenv_on_sleep(&sh.fe, NULL, NULL);
    if (pb.db.hb_running)
        (void)cdb_db_close(&pb.db);
    if (pa.db.hb_running)
        (void)cdb_db_close(&pa.db);
}

/* The primary red->green oracle. Two creators of one new database driven into
 * the exact pre-slot-init interleaving: exactly one wins, the other gets a
 * typed EXISTS/BUSY error and no usable handle, and the survivor's data reads
 * back intact after a close and reopen.
 *
 * Merge-base (O_CREAT only): both creators run cdb_pager_create over one file,
 * so both "win" (oks == 2) or the doubly-formatted survivor fails to reopen ->
 * RED. With CDB_ENV_EXCL the loser is turned away cleanly -> GREEN. */
static void test_create_race_single_winner(void)
{
    cdb_status rc_a, loser;
    struct proc *win, *lose;
    int oks;

    cdb_faultenv_on_sleep(&sh.fe, tick_joined, NULL);
    sh.armed = 1;
    rc_a = open_proc(&pa, 0); /* triggers run_b at the archive create-open */
    cdb_faultenv_on_sleep(&sh.fe, NULL, NULL);

    TEST_ASSERT_TRUE_MESSAGE(b_ran, "the interposed second creator never ran");

    /* AC2: exactly one creator wins. */
    oks = (rc_a == CDB_OK) + (rc_b == CDB_OK);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, oks, "two creators both won the create race (#46)");

    /* AC3: the loser gets a clean typed status, never a usable handle. */
    loser = (rc_a == CDB_OK) ? rc_b : rc_a;
    TEST_ASSERT_TRUE_MESSAGE(loser == CDB_E_EXISTS || loser == CDB_E_BUSY,
                             "losing creator did not return a typed EXISTS/BUSY error");

    win = (rc_a == CDB_OK) ? &pa : &pb;
    lose = (rc_a == CDB_OK) ? &pb : &pa;
    TEST_ASSERT_FALSE_MESSAGE(lose->db.coord.joined,
                              "the losing creator joined a coordinator slot");

    /* AC4/AC6: the winner is a sound archive; its data survives close+reopen. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&win->db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&win->db, 1, 7, CDB_OP_REPLACE, "hi", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&win->db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&win->db));

    memset(&pa.db, 0, sizeof pa.db);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&pa, 0)); /* open-existing */
    TEST_ASSERT_EQUAL_STRING("hi", value_of(&pa, 7));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&pa.db));
}

/* AC6/FR5: with no race, a normal create then a normal reopen (open-existing
 * path) is unchanged by the exclusive-create claim. */
static void test_open_existing_preserved(void)
{
    sh.armed = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&pa, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&pa.db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&pa.db, 1, 3, CDB_OP_REPLACE, "x", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&pa.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&pa.db));

    memset(&pa.db, 0, sizeof pa.db);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&pa, 0)); /* exists -> open-existing */
    TEST_ASSERT_EQUAL_STRING("x", value_of(&pa, 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&pa.db));
}

/* AC1: the exclusive-create primitive itself, at the env boundary. First claim
 * of a fresh path wins; a second exclusive create of the same path loses with
 * CDB_E_EXISTS; EXCL without CREATE is rejected; plain open-existing still
 * works. */
static void test_env_exclusive_create_primitive(void)
{
    cdb_storage st1, st2;

    sh.armed = 0;
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, env.ops->open(env.ctx, DIR "/claim", CDB_ENV_CREATE | CDB_ENV_EXCL, &st1));
    cdb_storage_close(&st1);
    TEST_ASSERT_EQUAL_INT(
        CDB_E_EXISTS, env.ops->open(env.ctx, DIR "/claim", CDB_ENV_CREATE | CDB_ENV_EXCL, &st2));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          env.ops->open(env.ctx, DIR "/claim", CDB_ENV_EXCL, &st2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, env.ops->open(env.ctx, DIR "/claim", 0, &st2));
    cdb_storage_close(&st2);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_create_race_single_winner);
    RUN_TEST(test_open_existing_preserved);
    RUN_TEST(test_env_exclusive_create_primitive);
    return UNITY_END();
}
