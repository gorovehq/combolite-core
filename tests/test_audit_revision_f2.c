/* #54 F2: CDB_AUDIT_REVISION is a defined event type that was never emitted. A
 * committed transaction that mutates a document or table store must emit exactly
 * one CDB_AUDIT_REVISION governance event at the write-path commit site
 * (tx_commit_locked), mirroring the #37 KEY_OP/SCHEMA guard shape: attributed to
 * the active principal, or principal 0 when no identity is registered.
 *
 *   AC1 a revision under an active identity emits exactly one REVISION with the
 *       real principal_id
 *   AC2 the same revision with no identity still emits one REVISION, principal 0
 *   AC6-like a commit touching only a non-revision model (time-series) emits no
 *       REVISION (the per-tx model gate), and an empty commit emits none
 *
 * Red->green: before the source fix tx_commit_locked emitted nothing, so the
 * query finds zero REVISION events; after it, exactly one. Deterministic and
 * hermetic (one fault environment, no clock/network/threads). */
#define _POSIX_C_SOURCE 200809L

#include <string.h>

#include "unity.h"
#include "cdb_audit.h"
#include "cdb_catalog.h"
#include "cdb_db.h"
#include "cdb_faultenv.h"
#include "cdb_journal.h"
#include "combolite/cdb_crypto.h"

#define FCAP (512u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 32u

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 4096u];
static cdb_faultenv fe;
static cdb_env env;

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[8192];
static uint8_t record_buf[1024];
static uint8_t cat_work[16384];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static cdb_db_config cfg;
static cdb_db db;
static cdb_identity id;

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

static cdb_header settings(void)
{
    cdb_header h;
    unsigned i;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    for (i = 0; i < 16; i++)
        h.db_id[i] = (uint8_t)(0x70 + i);
    return h;
}

void setUp(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 4096;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_generate_env(&env, &id, 7, 1));

    memset(&cfg, 0, sizeof cfg);
    cfg.pager.arena = arena;
    cfg.pager.arena_size = sizeof arena;
    cfg.pager.nodes = nodes;
    cfg.pager.node_cap = NODES;
    cfg.pager.free_list = free_list;
    cfg.pager.free_cap = sizeof free_list / sizeof free_list[0];
    cfg.record_buf = record_buf;
    cfg.record_buf_size = sizeof record_buf;
    cfg.apply = kv_apply;
    cfg.catalog_work.bytes = cat_work;
    cfg.catalog_work.bytes_size = sizeof cat_work;
    cfg.catalog_work.entries = cat_entries;
    cfg.catalog_work.entries_cap = 512;
    cfg.catalog_page = cat_page;
    cfg.durability = CDB_DURABILITY_FULL;
    cfg.signing_policy = CDB_SIGN_AUDIT_ONLY;
    cfg.identity = &id; /* individual tests may override to NULL before open */
}

void tearDown(void)
{
    (void)cdb_db_close(&db);
}

/* Counts audit events of a given type over the whole series, and (optionally)
 * returns the principal of the first such event. The chain must verify. */
static size_t count_type(uint16_t type, uint32_t *first_principal)
{
    cdb_audit_event ev[32];
    uint8_t pbuf[1024];
    size_t count = 0, i, n = 0;
    int valid = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_audit_query(&db, INT64_MIN, INT64_MAX, pbuf, sizeof pbuf, ev, 32,
                                          &count));
    for (i = 0; i < count; i++)
        if (ev[i].event_type == type) {
            if (n == 0 && first_principal != NULL)
                *first_principal = ev[i].principal_id;
            n++;
        }
    return n;
}

/* Commits one revision to a store of the given model; returns the store id. */
static uint64_t revise(uint32_t model, uint64_t entry, const char *body)
{
    uint64_t store = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "s", 1, model, &store));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_tx_put(&db, store, entry, CDB_OP_INSERT, body, strlen(body)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    return store;
}

/* AC1: a document revision under an active identity emits exactly one REVISION
 * carrying the real principal (7). Red: pre-fix no REVISION is emitted. */
static void test_revision_document_attributed(void)
{
    cdb_header h = settings();
    uint32_t principal = 0xFFFFFFFFu;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "rev_doc", &cfg, &h));
    (void)revise(CDB_MODEL_DOCUMENT, 1, "d1");

    TEST_ASSERT_EQUAL_size_t(1, count_type(CDB_AUDIT_REVISION, &principal));
    TEST_ASSERT_EQUAL_UINT32(7, principal); /* attributed to the active identity */
}

/* AC1: a table (relational) revision likewise emits exactly one REVISION. */
static void test_revision_table_attributed(void)
{
    cdb_header h = settings();
    uint32_t principal = 0xFFFFFFFFu;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "rev_tab", &cfg, &h));
    (void)revise(CDB_MODEL_RELATIONAL, 2, "t1");

    TEST_ASSERT_EQUAL_size_t(1, count_type(CDB_AUDIT_REVISION, &principal));
    TEST_ASSERT_EQUAL_UINT32(7, principal);
}

/* AC2: the same document revision with NO identity still emits one REVISION,
 * unattributed (principal 0) -- never gated on has_identity (that would fail
 * open, reopening the #37 gap). Set by the harness via have_id. */
static void test_revision_unattributed_without_identity(void)
{
    cdb_header h = settings();
    uint32_t principal = 0xFFFFFFFFu;

    cfg.identity = NULL; /* no registered principal */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "rev_noid", &cfg, &h));
    (void)revise(CDB_MODEL_DOCUMENT, 1, "d1");

    TEST_ASSERT_EQUAL_size_t(1, count_type(CDB_AUDIT_REVISION, &principal));
    TEST_ASSERT_EQUAL_UINT32(0, principal); /* unattributed */
}

/* The per-tx model gate: a commit touching only a non-revision model
 * (time-series) emits no REVISION, and an empty transaction emits none. */
static void test_no_revision_for_non_revision_models(void)
{
    cdb_header h = settings();

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "rev_ts", &cfg, &h));
    (void)revise(CDB_MODEL_TIME_SERIES, 3, "p1");
    TEST_ASSERT_EQUAL_size_t(0, count_type(CDB_AUDIT_REVISION, NULL));

    /* An empty commit makes no revision either. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_size_t(0, count_type(CDB_AUDIT_REVISION, NULL));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_revision_document_attributed);
    RUN_TEST(test_revision_table_attributed);
    RUN_TEST(test_revision_unattributed_without_identity);
    RUN_TEST(test_no_revision_for_non_revision_models);
    return UNITY_END();
}
