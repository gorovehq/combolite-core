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
 * fails closed.
 *
 * #65 (recovery-replay principal): a revision's journal record now stores the
 * writer's principal, so RECOVERY replay keeps the original attribution instead
 * of laundering the recovering session's identity onto it.
 *
 * AC1/AC2/AC6 (#65): write under identity A, crash, recover under a different
 *      identity B -> the recovered revision keeps A's principal (red->green:
 *      pre-fix it came back as B's/0).
 * AC3 (#65): a record with no stored principal (old format / no writer identity)
 *      falls back to the recovering session without crashing.
 * AC4 (#65): a new-format journal record round-trips the principal, and both
 *      new- and old-format records decode; a FLAG_PRINCIPAL body too short to
 *      hold the suffix is rejected fail-closed (CDB_E_CORRUPT). */
#define _POSIX_C_SOURCE 200809L

#include <string.h>

#include "unity.h"
#include "combolite/cdb_crypto.h"
#include "combolite/cdb_value.h"
#include "cdb_crc32c.h"
#include "cdb_doc.h"
#include "cdb_endian.h"
#include "cdb_faultdev.h"
#include "cdb_faultenv.h"
#include "cdb_journal.h"

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

/* AC1/AC2 (#65): a revision written under identity A, recovered under a
 * DIFFERENT identity B, keeps A's principal. The commit is durable only in the
 * journal (no clean close before the crash), so recovery replays it through
 * apply_change under B -- and the stored principal must win.
 *
 * Red->green: pre-fix apply_change attributed the recovering session, so the
 * recovered revision came back as B (202); post-fix it is A (101). */
static void test_recovery_replay_keeps_original_principal(void)
{
    uint64_t pool, e;
    cdb_doc_info info;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(&id_a, CDB_SIGN_NONE));
    pool = make_pool();
    begin();
    e = insert_doc(pool, "by-a");
    commit();
    /* Crash before reconciliation folds the journal into the archive: the
     * revision lives only in the (synced) journal and must replay on reopen. */
    cdb_faultenv_reboot(&fe);
    /* Recover under a different identity B. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(&id_b, CDB_SIGN_NONE));
    memset(&info, 0, sizeof info);
    TEST_ASSERT_EQUAL_INT(CDB_OK, read_doc(pool, e, &info));
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(
        PRINCIPAL_A, info.principal,
        "recovered revision attributed to the recovering session, not the original writer");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC3 (#65): a record with no stored principal (written without an active
 * identity, as pre-change journals are) must not crash on replay and falls back
 * to the recovering session's documented attribution. */
static void test_old_format_record_falls_back(void)
{
    uint64_t pool, e;
    cdb_doc_info info;
    /* No writer identity -> the record carries no FLAG_PRINCIPAL (old format). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(NULL, CDB_SIGN_NONE));
    pool = make_pool();
    begin();
    e = insert_doc(pool, "legacy");
    commit();
    cdb_faultenv_reboot(&fe);
    /* Recover under identity B: a record with no stored principal must replay
     * without crashing and fall back to the recovering session (B). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(&id_b, CDB_SIGN_NONE));
    memset(&info, 0, sizeof info);
    TEST_ASSERT_EQUAL_INT(CDB_OK, read_doc(pool, e, &info));
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(PRINCIPAL_B, info.principal,
                                     "legacy record did not fall back to the recovering session");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ------------------------------------------------- journal-level roundtrip */

/* A standalone journal backed by a fault device, for the record-format tests. */
typedef struct jfix {
    uint8_t current[8192];
    uint8_t durable[8192];
    uint8_t log_data[8192];
    cdb_fault_record log_records[64];
    cdb_faultdev dev;
    cdb_storage st;
    cdb_journal j;
} jfix;

static void jfix_open(jfix *f)
{
    cdb_faultdev_config c;
    cdb_journal_header h;
    memset(f, 0, sizeof *f);
    memset(&c, 0, sizeof c);
    c.current = f->current;
    c.durable = f->durable;
    c.capacity = sizeof f->current;
    c.log = f->log_records;
    c.log_cap = 64;
    c.log_data = f->log_data;
    c.log_data_cap = sizeof f->log_data;
    c.geometry.program_unit = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultdev_init(&f->dev, &c, &f->st));
    memset(&h, 0, sizeof h);
    h.type_id = CDB_COMPANION_MAIN_JOURNAL;
    memset(h.db_id, 0x5A, sizeof h.db_id);
    h.first_seq = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_journal_create(&f->j, &f->st, CDB_ORDER_LITTLE, &h));
}

/* AC4 (#65): a new-format record round-trips the principal; an old-format
 * record (no flag) still decodes with principal 0. */
static void test_record_principal_roundtrip_versioned(void)
{
    static const char payload[] = "op+model-bytes";
    const uint32_t plen = (uint32_t)(sizeof payload - 1u);
    jfix f;
    cdb_record r, rd;
    uint8_t buf[512];
    uint64_t off_new, off_old, next;

    jfix_open(&f);

    /* New format: FLAG_PRINCIPAL carries the writer's id in the body suffix. */
    memset(&r, 0, sizeof r);
    r.kind = CDB_RECORD_DATA;
    r.tx_id = 1;
    r.store_id = 1;
    r.entry_id = 9;
    r.flags = CDB_RECORD_FLAG_PRINCIPAL;
    r.principal = PRINCIPAL_A;
    r.payload = (const uint8_t *)payload;
    r.payload_len = plen;
    off_new = f.j.end;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_journal_append(&f.j, &r, buf, sizeof buf));

    /* Old format: no flag, no stored principal. */
    memset(&r, 0, sizeof r);
    r.kind = CDB_RECORD_DATA;
    r.tx_id = 1;
    r.store_id = 1;
    r.entry_id = 9;
    r.payload = (const uint8_t *)payload;
    r.payload_len = plen;
    off_old = f.j.end;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_journal_append(&f.j, &r, buf, sizeof buf));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_journal_read(&f.j, off_new, buf, sizeof buf, &rd, &next));
    TEST_ASSERT_TRUE((rd.flags & CDB_RECORD_FLAG_PRINCIPAL) != 0);
    TEST_ASSERT_EQUAL_UINT64(PRINCIPAL_A, rd.principal);
    TEST_ASSERT_EQUAL_UINT32(plen, rd.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, rd.payload, plen);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_journal_read(&f.j, off_old, buf, sizeof buf, &rd, &next));
    TEST_ASSERT_TRUE((rd.flags & CDB_RECORD_FLAG_PRINCIPAL) == 0);
    TEST_ASSERT_EQUAL_UINT64(0u, rd.principal);
    TEST_ASSERT_EQUAL_UINT32(plen, rd.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, rd.payload, plen);
}

/* AC4 (#65) DoS edge: a record that claims FLAG_PRINCIPAL but whose body is too
 * short to hold the 8-byte suffix is rejected fail-closed (CDB_E_CORRUPT),
 * never an under-read. The record is hand-crafted with a valid CRC so the
 * length guard -- not the CRC -- is what rejects it. */
static void test_principal_short_body_rejected(void)
{
    jfix f;
    cdb_record rd;
    uint8_t rec[CDB_RECORD_HEADER_SIZE + 2u + CDB_RECORD_TRAILER_SIZE];
    uint8_t buf[512];
    uint64_t off, next;
    const uint32_t body_len = 2u; /* < sizeof(uint64_t): too short for a principal */
    size_t crc_over = CDB_RECORD_HEADER_SIZE + body_len;

    jfix_open(&f);
    off = f.j.end;

    memset(rec, 0, sizeof rec);
    rec[0] = 0xC0u;
    rec[1] = 0xDEu;
    rec[2] = (uint8_t)CDB_RECORD_DATA;
    rec[3] = (uint8_t)CDB_RECORD_FLAG_PRINCIPAL; /* claims a principal it cannot hold */
    cdb_store_u32(rec + 4, body_len, CDB_ORDER_LITTLE);
    cdb_store_u64(rec + 8, f.j.next_seq, CDB_ORDER_LITTLE); /* seq */
    cdb_store_u64(rec + 16, 1u, CDB_ORDER_LITTLE);          /* tx_id */
    cdb_store_u64(rec + 24, 1u, CDB_ORDER_LITTLE);          /* store_id */
    cdb_store_u64(rec + 32, 9u, CDB_ORDER_LITTLE);          /* entry_id */
    rec[CDB_RECORD_HEADER_SIZE] = 0x01u;
    rec[CDB_RECORD_HEADER_SIZE + 1u] = 0x02u;
    cdb_store_u32(rec + crc_over, cdb_crc32c(rec, crc_over), CDB_ORDER_LITTLE);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_storage_program(&f.st, off, rec, sizeof rec));

    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_CORRUPT,
                                  cdb_journal_read(&f.j, off, buf, sizeof buf, &rd, &next),
                                  "a FLAG_PRINCIPAL record with a too-short body was not rejected");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_principal_and_signature_roundtrip);
    RUN_TEST(test_no_identity_principal_zero);
    RUN_TEST(test_mismatched_signature_fails_closed);
    RUN_TEST(test_recovery_replay_keeps_original_principal);
    RUN_TEST(test_old_format_record_falls_back);
    RUN_TEST(test_record_principal_roundtrip_versioned);
    RUN_TEST(test_principal_short_body_rejected);
    return UNITY_END();
}
