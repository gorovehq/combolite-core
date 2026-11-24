/* #60 B2/FR2 (fallback path) — the lock-free heartbeat fallback close path,
 * where the landed B2 reroute (fence-busy-at-close -> close_pending, cdb_db.c)
 * lives, closes cleanly and loses no committed data.
 *
 * Trace: ideation FR2 + FR5 -> issue #60 -> this test -> gate verdict.
 *
 * Under the lock hook a live holder's baton is never stolen, so the B2 branch is
 * unreachable in-process (see test_coord_contention_close_f60 and the audit).
 * The branch only exists for the lock-free fallback (spec 5.9.6/5.9.8). The
 * exact CTS-override-mid-close race is not deterministically reproducible as a
 * unit (documented not-reproducible in docs/audit/2026-11-60-coord-contention.md),
 * so this test pins the reachable, deterministic fallback CONTRACT instead: in
 * the lock-free environment (cdb_faultenv_without_locks) a writer that commits,
 * reconciles (takes + releases the baton), and closes must return CDB_OK and
 * every committed transaction must survive a reopen (FR5 — the B2 change is
 * safety-neutral: it never drops a committed tx). A regression in the fallback
 * close path (e.g. a close that errored or lost data) turns this red. */
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
#define DIR "c60f"
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
static struct proc p1;

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

/* Value of entry e in p1's pages as a string; "" when absent. */
static const char *value_of(uint64_t e)
{
    static char out[PAGE];
    uint8_t buf[PAGE];
    cdb_page_header h;
    cdb_status s = cdb_pager_read(&p1.db.pager, e, buf, &h);
    out[0] = '\0';
    if (s != CDB_OK)
        return out;
    memcpy(out, buf + cdb_page_payload_offset(p1.db.pager.fmt), h.payload_len);
    out[h.payload_len] = '\0';
    return out;
}

static void self_tick(void *arg)
{
    (void)arg;
    if (p1.db.coord.joined)
        (void)cdb_db_tick(&p1.db);
}

void setUp(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 2048;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
    cdb_faultenv_without_locks(&env); /* the lock-free heartbeat fallback (spec 5.9.6) */
    TEST_ASSERT_EQUAL_INT(CDB_OK, env.ops->mkdir(env.ctx, DIR));
    TEST_ASSERT_EQUAL_INT(CDB_OK, env.ops->sync_dir(env.ctx, "."));
    memset(&p1.db, 0, sizeof p1.db);
    cdb_faultenv_on_sleep(&fe, self_tick, NULL);
}

void tearDown(void)
{
    cdb_faultenv_on_sleep(&fe, NULL, NULL);
    if (p1.db.hb_running)
        (void)cdb_db_close(&p1.db);
}

/* FR2/FR5 fallback contract: commit -> reconcile (baton take/release) -> close
 * returns CDB_OK and the committed value survives a reopen. Exercises the
 * lock-free fallback close path (reconcile_hold / close_pending) that hosts the
 * B2 reroute, and proves the close path is safety-neutral (no committed tx lost). */
static void test_fallback_close_commits_durable(void)
{
    cdb_status s;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1, 0));
    TEST_ASSERT_TRUE_MESSAGE(p1.db.coord.joined, "fallback join must succeed");

    cdb_faultenv_advance(&fe, 10 * 1000 * 1000);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&p1.db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&p1.db, 1, 7, CDB_OP_REPLACE, "zz", 2));
    s = cdb_tx_commit(&p1.db);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, s, "commit in the lock-free fallback");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(CDB_E_STATE, s, "no spurious CDB_E_STATE (B3)");

    /* Take + release the baton via a reconcile, then close cleanly. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&p1.db));

    s = cdb_db_close(&p1.db);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(CDB_E_BUSY, s, "fallback clean close falsely reported busy (B2)");
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, s, "fallback clean close must succeed (FR2)");

    /* FR5: the committed value survives the reopen — the close path dropped nothing. */
    memset(&p1.db, 0, sizeof p1.db);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1, 0));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("zz", value_of(7), "committed value lost across fallback close (FR5)");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_fallback_close_commits_durable);
    return UNITY_END();
}
