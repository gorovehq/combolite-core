/* #54 F4: audit_reload_head keeps one chain across reconciled slots, but the
 * append (reload-head -> build -> index_put -> update-head) was not serialized
 * under a single-writer lock, so two un-reconciled concurrent writers could
 * interleave. cdb_audit_log now runs that append under the coordinator baton
 * (take-if-not-held, append, release): a writer that does not already hold the
 * baton must ACQUIRE the exclusive write baton for its append, so two writers
 * cannot append without one holding it -- single-writer serialization.
 *
 *   AC7 a non-holder's audit append acquires the exclusive baton (observable:
 *       it is taken from the prior holder), and the chain stays verifiable.
 *   AC8 verify-on-read stays fail-closed on a tampered signature (unchanged by
 *       the serialization work); verify still binds to the reader's active key.
 *
 * Red->green for AC7: before the source fix the append did not touch the baton,
 * so a non-holder appended WITHOUT acquiring exclusive write access and the prior
 * holder kept the baton; after it, the prior holder is handed the baton off --
 * proving the append is now baton-serialized. Deterministic and hermetic: two
 * coordinators in one thread sharing one fault environment, the sleep hook
 * letting the other beat. No real process race, clock, or network.
 *
 * Scope note (honesty, per the #40 FR1 precedent): a chain *corruption* from a
 * genuinely simultaneous interleave is reachable only under a true OS-thread data
 * race, which is non-deterministic and out of scope for a deterministic gate. In
 * the single-writer coordinator model every persistent append already runs while
 * holding the baton (a sole coordinator holds it from open; governance ops hold
 * it mid-session), so this test asserts the serialization invariant -- that the
 * append acquires the exclusive baton -- rather than replaying a flaky break. */
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
#define DIR "cx"

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 4096u];
static cdb_faultenv fe;
static cdb_env env;
static const uint8_t db_id[16] = { 2, 4, 6, 8, 10, 12, 14, 16, 1, 3, 5, 7, 9, 11, 13, 15 };
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

/* AC7: a non-baton-holder's audit append acquires the exclusive write baton, so
 * the append is serialized (two writers cannot both append without one holding
 * the baton). Observable: p1 holds the standing baton; after p2 -- which does not
 * hold it -- emits an audit event, the baton has been taken from p1. The chain
 * stays verifiable. Red pre-fix: the append never touched the baton, so p1 kept
 * it (the un-serialized interleave the residual called out). */
static void test_append_serialized_under_baton(void)
{
    int valid = 0;

    cdb_faultenv_on_sleep(&fe, tick_both, NULL);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1));
    /* p1 reconciles while sole -> it keeps a standing baton. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&p1.db));
    TEST_ASSERT_TRUE(cdb_coord_baton_held(&p1.db.coord));

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p2));
    cdb_faultenv_advance(&fe, 10 * 1000 * 1000);
    TEST_ASSERT_TRUE(cdb_coord_baton_held(&p1.db.coord));
    TEST_ASSERT_FALSE(cdb_coord_baton_held(&p2.db.coord));

    /* p2 emits an audit event while NOT holding the baton. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_log(&p2.db, CDB_AUDIT_CUSTOM, 7, 0, 2, "b", 1));

    /* The append acquired the exclusive baton -- so it was taken from p1 (the
     * prior holder). Pre-fix the append ignored the baton and p1 kept it. */
    TEST_ASSERT_FALSE(cdb_coord_baton_held(&p1.db.coord));

    /* The chain stays single and verifiable on both views. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&p2.db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&p1.db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* AC8: verify-on-read stays fail-closed after F4. A signed audit chain verifies;
 * corrupting the reader's verifying key flips the verdict (the signature is
 * present and checked) -- the serialization work did not weaken the read path.
 * Verify binds to the reader's active key (per-signer registry is a follow-up). */
static void test_verify_on_read_fail_closed(void)
{
    int valid = 0;
    uint8_t saved;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_log(&p1.db, CDB_AUDIT_CUSTOM, 7, 0, 1, "a", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_log(&p1.db, CDB_AUDIT_CUSTOM, 7, 0, 2, "b", 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&p1.db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);

    saved = p1.db.active_identity.public_key[1];
    p1.db.active_identity.public_key[1] ^= 0xFF;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&p1.db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(0, valid); /* fail closed on a bad signature */
    p1.db.active_identity.public_key[1] = saved;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&p1.db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_append_serialized_under_baton);
    RUN_TEST(test_verify_on_read_fail_closed);
    return UNITY_END();
}
