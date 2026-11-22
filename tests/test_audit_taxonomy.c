/* #37 FR3/FR4: the defined audit event types must actually be emitted at their
 * governance origin sites, with redacted payloads, and audit-series events must
 * be signed under the default policy.
 *
 * Covered here (single process, principal identity, default CDB_SIGN_AUDIT_ONLY):
 *   AC5  master-key rotation emits exactly one KEY_OP event
 *   AC7  a schema change emits a SCHEMA event (carrying the new version only)
 *   AC8  emitted payloads contain no key material / secrets (redaction)
 *   AC9  appended audit events carry a signature that cdb_audit_verify checks
 *   AC11 a broken/altered chain link is detected (fail closed)
 *
 * Red->green: before the fix only CDB_AUDIT_COLLISION was ever logged, so
 * rotation and schema changes emitted nothing (query count 0), and audit events
 * were hash-chained but unsigned (corrupting the verifier's key left them
 * "valid"). Deterministic and hermetic (one fault environment). */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "cdb_audit.h"
#include "cdb_catalog.h"
#include "cdb_db.h"
#include "cdb_endian.h"
#include "cdb_faultenv.h"
#include "cdb_page.h"
#include "combolite/cdb_crypto.h"
#include "combolite/cdb_value.h"

#define FCAP (512u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 32u
#define MK_HEX "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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
        h.db_id[i] = (uint8_t)(0x60 + i);
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

    setenv("CDB_TAX_MK", MK_HEX, 1);
    setenv("CDB_TAX_MK_NEW", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 1);
    setenv("CDB_TAX_ENC", "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff", 1);

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
    cfg.identity = &id;
    cfg.signing_policy = CDB_SIGN_AUDIT_ONLY; /* spec 12.5 default: sign audit events */
}

void tearDown(void)
{
    (void)cdb_db_close(&db);
}

/* AC5/AC8/AC9: master-key rotation emits one redacted, signed KEY_OP event. */
static void test_keyop_on_master_rotation(void)
{
    cdb_header h = settings();
    cdb_audit_event ev[8];
    uint8_t pbuf[256];
    size_t count = 0;
    int valid = 0;
    uint8_t saved_pub;

    cfg.master_key_uri = "env://CDB_TAX_MK";
    cfg.aead_alg = CDB_AEAD_AES_256_GCM;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "tax_keyop", &cfg, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_enclave(&db, 42, "env://CDB_TAX_ENC"));

    /* No audit events yet (enclave creation is not audited here). */
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_audit_query(&db, INT64_MIN, INT64_MAX, pbuf, sizeof pbuf, ev, 8,
                                          &count));
    TEST_ASSERT_EQUAL_size_t(0, count);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_rotate_master_key(&db, "env://CDB_TAX_MK_NEW"));

    /* AC5: exactly one KEY_OP event. */
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_audit_query(&db, INT64_MIN, INT64_MAX, pbuf, sizeof pbuf, ev, 8,
                                          &count));
    TEST_ASSERT_EQUAL_size_t(1, count);
    TEST_ASSERT_EQUAL_UINT16(CDB_AUDIT_KEY_OP, ev[0].event_type);
    TEST_ASSERT_EQUAL_UINT32(7, ev[0].principal_id); /* attributed to the identity */

    /* AC8: the payload is a 1-byte redacted sub-op marker -- no key material. */
    TEST_ASSERT_EQUAL_UINT32(1, ev[0].payload_len);
    TEST_ASSERT_EQUAL_UINT8(1, ev[0].payload[0]);

    /* AC9: the event is signed and the chain (with signature) verifies. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);

    /* Corrupting the verifying public key must flip the verdict -- proving a
     * real signature is present and checked (pre-fix: unsigned, so unaffected). */
    saved_pub = db.active_identity.public_key[1];
    db.active_identity.public_key[1] ^= 0xFF;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(0, valid);
    db.active_identity.public_key[1] = saved_pub;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);
}

/* AC7: a schema change emits a SCHEMA event carrying only the new version. */
static void test_schema_on_add_schema(void)
{
    cdb_header h = settings();
    cdb_audit_event ev[8];
    uint8_t pbuf[256];
    size_t count = 0;
    uint64_t store = 0;
    uint32_t version = 0;
    uint8_t schema[32];
    size_t schema_len;
    cdb_value_writer w;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "tax_schema", &cfg, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "docs", 4, CDB_MODEL_DOCUMENT, &store));

    /* An empty object {} is a valid (accept-everything) schema. */
    cdb_value_writer_init(&w, schema, sizeof schema, db.pager.order, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    schema_len = cdb_value_writer_len(&w);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_add_schema(&db, store, schema, schema_len, &version));
    TEST_ASSERT_TRUE(version >= 1u);

    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_audit_query(&db, INT64_MIN, INT64_MAX, pbuf, sizeof pbuf, ev, 8,
                                          &count));
    TEST_ASSERT_EQUAL_size_t(1, count);
    TEST_ASSERT_EQUAL_UINT16(CDB_AUDIT_SCHEMA, ev[0].event_type);
    TEST_ASSERT_EQUAL_UINT64(store, ev[0].store_id);
    TEST_ASSERT_EQUAL_UINT32(4, ev[0].payload_len); /* the version, redacted (no schema body) */
    TEST_ASSERT_EQUAL_UINT32(version, cdb_load_u32(ev[0].payload, db.pager.order));
}

/* F1 (#37 review): a governance-mode DB with a master key but NO registered
 * principal identity must STILL emit the governance audit event, unattributed
 * (principal_id=0). Pre-fix the emit was gated on has_identity and silently
 * dropped -- a fail-open gap on a security-observability path, reopening exactly
 * what #37 closes. Mirrors the COLLISION emit, which logs with principal 0. */
static void test_keyop_without_identity_still_fires(void)
{
    cdb_header h = settings();
    cdb_audit_event ev[8];
    uint8_t pbuf[256];
    size_t count = 0;

    cfg.identity = NULL; /* master key present, no principal registered */
    cfg.signing_policy = CDB_SIGN_AUDIT_ONLY;
    cfg.master_key_uri = "env://CDB_TAX_MK";
    cfg.aead_alg = CDB_AEAD_AES_256_GCM;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "tax_keyop_noid", &cfg, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_enclave(&db, 42, "env://CDB_TAX_ENC"));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_rotate_master_key(&db, "env://CDB_TAX_MK_NEW"));

    /* The KEY_OP event fires despite no identity, attributed to principal 0. */
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_audit_query(&db, INT64_MIN, INT64_MAX, pbuf, sizeof pbuf, ev, 8,
                                          &count));
    TEST_ASSERT_EQUAL_size_t(1, count);
    TEST_ASSERT_EQUAL_UINT16(CDB_AUDIT_KEY_OP, ev[0].event_type);
    TEST_ASSERT_EQUAL_UINT32(0, ev[0].principal_id); /* unattributed */
}

/* AC11 (abuse): an altered chain link is detected and reported (fail closed). */
static void test_broken_chain_detected(void)
{
    cdb_header h = settings();
    uint8_t pg[PAGE];
    cdb_page_header ph;
    size_t hdr_sz, payload_cap;
    int valid = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "tax_chain", &cfg, &h));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_log(&db, CDB_AUDIT_CUSTOM, 7, 0, 1, "e1", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_log(&db, CDB_AUDIT_CUSTOM, 7, 0, 2, "e2", 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_log(&db, CDB_AUDIT_CUSTOM, 7, 0, 3, "e3", 2));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);

    /* Flip bytes in the audit index root page: the stored hashes no longer match
     * the recomputed chain, so verification must fail closed. */
    TEST_ASSERT_TRUE(db.pager.catroot.audit_root != 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(&db.pager, db.pager.catroot.audit_root, pg, &ph));
    hdr_sz = cdb_page_payload_offset(db.pager.fmt);
    payload_cap = cdb_page_capacity(db.pager.fmt, db.pager.page_size);
    pg[hdr_sz + payload_cap - 20] ^= 0xFF;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_write(&db.pager, db.pager.catroot.audit_root, &ph,
                                                  pg + hdr_sz, payload_cap));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(0, valid);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_keyop_on_master_rotation);
    RUN_TEST(test_schema_on_add_schema);
    RUN_TEST(test_keyop_without_identity_still_fires);
    RUN_TEST(test_broken_chain_detected);
    return UNITY_END();
}
