/* #37 FR2: commit signatures must be VERIFIED on the read path (recovery /
 * replay / merge), not merely written. When the signing policy requires signed
 * revisions, a commit whose signature is missing or does not validate against
 * the active identity is rejected with a typed CDB_E_SECURITY (fail closed);
 * under an unsigned policy verification is not forced (no false rejection).
 *
 * Red->green: before the fix cdb_identity_verify had no caller, so a crashed
 * session's journal replayed WITHOUT checking the commit signature -- every
 * case below opened CDB_OK. After the fix the two abuse cases fail closed.
 *
 * Mechanism: a writer commits (durably, in its journal) then "crashes" before
 * reconciling, leaving the committed transaction in the journal. A fresh handle
 * reopens the same files, recovering alone, which replays and verifies the
 * commit. Deterministic and hermetic (one fault environment). */
#define _POSIX_C_SOURCE 200809L

#include <string.h>

#include "unity.h"
#include "cdb_coord.h"
#include "cdb_db.h"
#include "cdb_faultenv.h"
#include "combolite/cdb_crypto.h"

#define FCAP (256u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define STORE 1u

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 2048u];
static cdb_faultenv fe;
static cdb_env env;

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[4096];
static uint8_t record_buf[1024];
static uint8_t cat_work[16384];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static cdb_db_config cfg;
static cdb_db db;
static cdb_identity id_a, id_b;

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
        h.db_id[i] = (uint8_t)(0x50 + i);
    return h;
}

void setUp(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 2048;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_generate_env(&env, &id_a, 101, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_generate_env(&env, &id_b, 202, 1));

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
}

void tearDown(void) {}

/* Crash: drop the handles and the coordinator slot, leaving the files as they
 * are, then clear the struct so a reopen recovers from scratch. */
static void crash(void)
{
    cdb_storage_close(&db.overlay_st);
    cdb_storage_close(&db.journal_st);
    cdb_storage_close(&db.archive_st);
    cdb_coord_abandon(&db.coord);
    memset(&db, 0, sizeof db);
}

/* Opens, commits one signed/unsigned transaction under the given identity and
 * policy, then crashes without reconciling, leaving it in the journal. */
static void write_then_crash(const cdb_identity *id, cdb_signing_policy policy, int create)
{
    cdb_header h = settings();
    cfg.identity = id;
    cfg.signing_policy = policy;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_db_open(&db, &env, "sig_db", &cfg, create ? &h : NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 1, CDB_OP_REPLACE, "v1", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    crash();
}

static cdb_status reopen(const cdb_identity *id, cdb_signing_policy policy)
{
    cfg.identity = id;
    cfg.signing_policy = policy;
    return cdb_db_open(&db, &env, "sig_db", &cfg, NULL);
}

/* AC4: a validly signed commit is accepted on recovery under the same policy
 * and identity. */
static void test_valid_signed_commit_accepted(void)
{
    write_then_crash(&id_a, CDB_SIGN_EVERY_REVISION, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, reopen(&id_a, CDB_SIGN_EVERY_REVISION));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC3 (abuse): a commit signed by one identity is rejected when recovered under
 * a signing policy with a DIFFERENT active identity -- the signature does not
 * validate, so recovery fails closed. Pre-fix: accepted (never verified). */
static void test_wrong_identity_rejected(void)
{
    write_then_crash(&id_a, CDB_SIGN_EVERY_REVISION, 1);
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, reopen(&id_b, CDB_SIGN_EVERY_REVISION));
}

/* AC3 (abuse): a commit written without a signature (unsigned policy) is
 * rejected when recovered under a policy that requires signed revisions -- a
 * stripped/missing signature fails closed. Pre-fix: accepted. */
static void test_missing_signature_rejected(void)
{
    write_then_crash(&id_a, CDB_SIGN_AUDIT_ONLY, 1); /* audit-only: commit unsigned */
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, reopen(&id_a, CDB_SIGN_EVERY_REVISION));
}

/* AC4: under an unsigned policy, recovery does not force verification, so
 * neither an unsigned commit nor a validly-signed one is falsely rejected. */
static void test_unsigned_policy_no_false_reject(void)
{
    write_then_crash(&id_a, CDB_SIGN_NONE, 1); /* unsigned commit */
    TEST_ASSERT_EQUAL_INT(CDB_OK, reopen(&id_a, CDB_SIGN_NONE));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

static void test_signed_commit_under_unsigned_policy_not_forced(void)
{
    write_then_crash(&id_a, CDB_SIGN_EVERY_REVISION, 1); /* signed commit */
    /* Recover with no signing policy: a present signature is not verified and
     * must not cause a false rejection. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, reopen(&id_a, CDB_SIGN_NONE));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_valid_signed_commit_accepted);
    RUN_TEST(test_wrong_identity_rejected);
    RUN_TEST(test_missing_signature_rejected);
    RUN_TEST(test_unsigned_policy_no_false_reject);
    RUN_TEST(test_signed_commit_under_unsigned_policy_not_forced);
    return UNITY_END();
}
