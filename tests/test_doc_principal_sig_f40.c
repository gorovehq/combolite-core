/* #40 FR4: document revisions attribute the real active principal and set +
 * verify the spec-14.9.1 bit-2 signed-revision flag.
 *
 * AC5: a revision written under an active identity records that principal's id
 *      (not 0); with no identity present it records 0.
 * AC6: under CDB_SIGN_EVERY_REVISION the signed-revision flag is set and the
 *      signature round-trips and verifies on read; a signature that does not
 *      match the active identity fails closed (CDB_E_SECURITY), never a silent
 *      pass.
 *
 * Red->green: pre-fix the principal was hardcoded 0 and the flag was never set
 * or verified, so (AC5) principal came back 0 and (AC6) a mismatched read
 * passed silently. Post-fix principal is the real id and the mismatched read
 * fails closed. */
#define _POSIX_C_SOURCE 200809L

#include <string.h>

#include "unity.h"
#include "combolite/cdb_crypto.h"
#include "combolite/cdb_value.h"
#include "cdb_doc.h"
#include "cdb_faultenv.h"

#define FCAP (512u * 1024u)
#define PAGE_LOG2 10u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define PRINCIPAL_A 101u
#define PRINCIPAL_B 202u

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 4096u];
static cdb_faultenv fe;
static cdb_env env;

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[4096];
static uint8_t record_buf[2u * PAGE];
static uint8_t cat_work[24u * 1024u];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static uint8_t doc_buffers[8u * PAGE];
static uint8_t doc_stage[4096];
static uint8_t idx_stage[16u * 1024u];
static cdb_db_config cfg;
static cdb_db db;
static cdb_identity id_a, id_b;

static void init_env(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 4096;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
}

void setUp(void)
{
    init_env();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_generate_env(&env, &id_a, PRINCIPAL_A, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_generate_env(&env, &id_b, PRINCIPAL_B, 1));
    memset(&cfg, 0, sizeof cfg);
    cfg.pager.arena = arena;
    cfg.pager.arena_size = sizeof arena;
    cfg.pager.nodes = nodes;
    cfg.pager.node_cap = NODES;
    cfg.pager.free_list = free_list;
    cfg.pager.free_cap = sizeof free_list / sizeof free_list[0];
    cfg.record_buf = record_buf;
    cfg.record_buf_size = sizeof record_buf;
    cfg.catalog_work.bytes = cat_work;
    cfg.catalog_work.bytes_size = sizeof cat_work;
    cfg.catalog_work.entries = cat_entries;
    cfg.catalog_work.entries_cap = 512;
    cfg.catalog_page = cat_page;
    cfg.doc_buffers = doc_buffers;
    cfg.doc_stage = doc_stage;
    cfg.doc_stage_size = sizeof doc_stage;
    cfg.idx_stage = idx_stage;
    cfg.idx_stage_size = sizeof idx_stage;
    cfg.durability = CDB_DURABILITY_FULL;
}

void tearDown(void) {}

static cdb_status open_db(const cdb_identity *id, cdb_signing_policy policy)
{
    cdb_header h;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x44, sizeof h.db_id);
    cfg.identity = id;
    cfg.signing_policy = policy;
    return cdb_db_open(&db, &env, "d40", &cfg, &h);
}

static void begin(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL)); }
static void commit(void) { TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db)); }

static uint64_t make_pool(void)
{
    uint64_t id = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "notes", 5, CDB_MODEL_DOCUMENT, &id));
    return id;
}

static uint64_t insert_doc(uint64_t pool, const char *s)
{
    uint8_t b[64];
    cdb_value_writer w;
    uint64_t e = 0;
    cdb_value_writer_init(&w, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_string(&w, s, strlen(s));
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, b, cdb_value_writer_len(&w), &e));
    return e;
}

static cdb_status read_doc(uint64_t pool, uint64_t e, cdb_doc_info *info)
{
    uint8_t body[256];
    size_t blen = 0;
    return cdb_doc_get(&db, pool, e, 0, body, sizeof body, &blen, NULL, 0, NULL, info);
}

/* AC5 + AC6: under an active identity + sign-every-revision, the revision is
 * attributed to the real principal and its signature verifies on read. */
static void test_principal_and_signature_roundtrip(void)
{
    uint64_t pool, e;
    cdb_doc_info info;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(&id_a, CDB_SIGN_EVERY_REVISION));
    pool = make_pool();
    begin();
    e = insert_doc(pool, "hello");
    commit();

    memset(&info, 0, sizeof info);
    /* The read materializes the revision and verifies its signature; success
     * proves the flag was set and the signature round-trips. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, read_doc(pool, e, &info));
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(PRINCIPAL_A, info.principal,
                                     "revision not attributed to the active principal");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC5: with no active identity, principal is 0 (explicit "no identity"). */
static void test_no_identity_principal_zero(void)
{
    uint64_t pool, e;
    cdb_doc_info info;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(NULL, CDB_SIGN_NONE));
    pool = make_pool();
    begin();
    e = insert_doc(pool, "anon");
    commit();
    memset(&info, 0xFF, sizeof info);
    TEST_ASSERT_EQUAL_INT(CDB_OK, read_doc(pool, e, &info));
    TEST_ASSERT_EQUAL_UINT64(0u, info.principal);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC6: a signature that does not match the active identity fails closed on
 * read -- the verify is real, not a silent pass. A revision signed by A is
 * read back under B's key and must be rejected. */
static void test_mismatched_signature_fails_closed(void)
{
    uint64_t pool, e;
    cdb_doc_info info;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(&id_a, CDB_SIGN_EVERY_REVISION));
    pool = make_pool();
    begin();
    e = insert_doc(pool, "signed-by-a");
    commit();
    TEST_ASSERT_EQUAL_INT(CDB_OK, read_doc(pool, e, &info)); /* A verifies its own */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    /* Reopen as a different principal: the stored signature cannot verify
     * under B's public key, so the read fails closed. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(&id_b, CDB_SIGN_EVERY_REVISION));
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_SECURITY, read_doc(pool, e, &info),
                                  "a non-matching revision signature was accepted silently");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_principal_and_signature_roundtrip);
    RUN_TEST(test_no_identity_principal_zero);
    RUN_TEST(test_mismatched_signature_fails_closed);
    return UNITY_END();
}
