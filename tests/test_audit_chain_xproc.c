/* #37 FR5/FR3: the hash-chained audit series must stay a single, tamper-evident
 * chain across coordinator slots / processes, and a baton handoff is a governance
 * event.
 *
 *   AC10 two coordinators appending audit events keep ONE intact chain (each
 *        link's prev-hash matches), because the chain head is reloaded from the
 *        durable index tail before every append rather than trusting a
 *        per-process in-memory head (which would fork).
 *   AC6  acquiring the baton at reconcile (a coordinator handoff) emits a BATON
 *        audit event.
 *
 * Red->green: before the fix last_audit_hash/audit_seq were per-process and set
 * once, so a second coordinator that had seen the first's reconciled events
 * would still fork the chain; and BATON was never emitted.
 *
 * Deterministic and hermetic: two coordinators in one thread sharing one fault
 * environment; the sleep hook lets the other coordinator beat while one waits,
 * as test_multiwriter_open does. No real process race, clock, or network.
 *
 * Residual (stated in the writeup): the append is not yet baton-serialized, so a
 * true simultaneous interleave between two writers that have not reconciled is
 * out of scope; durable-head reload is the governance-spec floor. */
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
#define DIR "ax"
#define SEC 1000000000

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 4096u];
static cdb_faultenv fe;
static cdb_env env;
static const uint8_t db_id[16] = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6 };
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

/* Counts audit events of a given type across the whole series on `p`. */
static size_t count_type(struct proc *p, uint16_t type, int *valid_out)
{
    cdb_audit_event ev[32];
    uint8_t pbuf[1024];
    size_t count = 0, i, n = 0;
    int valid = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&p->db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_query(&p->db, INT64_MIN, INT64_MAX, pbuf, sizeof pbuf,
                                                  ev, 32, &count));
    for (i = 0; i < count; i++)
        if (ev[i].event_type == type)
            n++;
    if (valid_out != NULL)
        *valid_out = valid;
    return n;
}

/* AC10: two live coordinators' events form ONE intact chain. p1 logs E1 and
 * reconciles it into the shared archive; p2 joins, sees E1 through the durable
 * audit index, and appends E2 whose prev-hash is reloaded from that tail -- so
 * the chain continues rather than forking at genesis. */
static void test_single_chain_two_coords(void)
{
    cdb_audit_event ev[32];
    uint8_t pbuf[1024];
    size_t count = 0, custom = 0, i;
    int valid = 0;

    cdb_faultenv_on_sleep(&fe, tick_both, NULL);

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_log(&p1.db, CDB_AUDIT_CUSTOM, 7, 0, 1, "e1", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&p1.db));

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p2));
    cdb_faultenv_advance(&fe, 10 * 1000 * 1000);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_log(&p2.db, CDB_AUDIT_CUSTOM, 7, 0, 2, "e2", 2));

    /* p2's view holds both E1 (archive) and E2 (its overlay) as one chain. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&p2.db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid); /* single, intact, signed chain */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_query(&p2.db, INT64_MIN, INT64_MAX, pbuf, sizeof pbuf,
                                                  ev, 32, &count));
    for (i = 0; i < count; i++)
        if (ev[i].event_type == CDB_AUDIT_CUSTOM)
            custom++;
    TEST_ASSERT_EQUAL_size_t(2, custom); /* both coordinators' events, one chain */
    /* Each link's prev-hash matches the previous event's hash (no fork). */
    for (i = 1; i < count; i++)
        TEST_ASSERT_EQUAL_MEMORY(ev[i - 1].hash, ev[i].prev_hash, 32);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

/* AC6: acquiring the baton at reconcile is a coordinator handoff and emits a
 * BATON governance event. p1 holds the standing baton; p2 reconciles, which
 * takes the baton from p1. */
static void test_baton_handoff_audited(void)
{
    size_t baton;
    int valid = 0;

    cdb_faultenv_on_sleep(&fe, tick_both, NULL);

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_proc(&p2));
    cdb_faultenv_advance(&fe, 10 * 1000 * 1000);

    /* p2 does not hold the baton; reconciling acquires it from p1 (handoff). */
    TEST_ASSERT_FALSE(cdb_coord_baton_held(&p2.db.coord));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&p2.db));

    baton = count_type(&p2, CDB_AUDIT_BATON, &valid);
    TEST_ASSERT_EQUAL_INT(1, valid);
    TEST_ASSERT_TRUE(baton >= 1);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p2.db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&p1.db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_single_chain_two_coords);
    RUN_TEST(test_baton_handoff_audited);
    return UNITY_END();
}
