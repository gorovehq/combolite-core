#define _POSIX_C_SOURCE 200809L
/* Golden / known-answer tests (KAT) for the crypto artifact (critical path):
 * fixed input -> fixed expected output, to catch any silent change in the
 * primitives. SHA-256 vectors are the published standard (external validation);
 * the HMAC vector is a captured reference (regression golden). Spec 12 (crypto). */
#include "unity.h"
#include "cdb_db.h"
#include "cdb_faultenv.h"
#include "combolite/cdb_crypto.h"
#include <stdlib.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* FIPS 180-4 / standard SHA-256 test vectors. */
static void test_sha256_known_answers(void)
{
    uint8_t h[CDB_CRYPTO_HASH_SIZE];
    /* SHA-256("abc") */
    static const uint8_t abc[CDB_CRYPTO_HASH_SIZE] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_sha256("abc", 3, h));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(abc, h, CDB_CRYPTO_HASH_SIZE);
    /* SHA-256("") */
    static const uint8_t empty[CDB_CRYPTO_HASH_SIZE] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55 };
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_sha256("", 0, h));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(empty, h, CDB_CRYPTO_HASH_SIZE);
}

/* HMAC-SHA256 with a fixed 32-byte key (0x11 repeated) over "abc": captured
 * reference golden -- any change in the HMAC path is caught. */
static void test_hmac_sha256_golden(void)
{
    uint8_t key[CDB_CRYPTO_KEY_SIZE];
    uint8_t mac[CDB_CRYPTO_HASH_SIZE];
    static const uint8_t want[CDB_CRYPTO_HASH_SIZE] = {
        0x80,0x94,0xa4,0xaa,0x03,0x11,0xce,0xad,0xd6,0x2b,0xd4,0xb1,0x7f,0xa7,0x6c,0xb0,
        0x06,0x6c,0xff,0x4f,0x12,0x5c,0xbf,0xc6,0x4d,0xea,0x5b,0xab,0x24,0x93,0xf2,0xcd };
    memset(key, 0x11, sizeof key);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hmac_sha256(key, (const uint8_t *)"abc", 3, mac));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, mac, CDB_CRYPTO_HASH_SIZE);
}

/* -------------------- CR2 SEAL/REPL subkey KAT harness (audit #72) -------- */

#define K72_FCAP (640u * 1024u)
#define K72_PAGE_LOG2 9u
#define K72_PAGE (1u << K72_PAGE_LOG2)
#define K72_NODES 16u
/* The enclave key the goldens below were computed from (11223344...eeff x2). */
#define K72_ENC_KEY_HEX "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
/* The master key the db is opened with (0123...ef x4); used for distinctness. */
#define K72_MK_HEX "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static uint8_t k72_env_arena[CDB_FAULTENV_MAX_FILES * 3u * K72_FCAP];
static cdb_fault_record k72_env_records[CDB_FAULTENV_MAX_FILES * 4096u];
static cdb_faultenv k72_fe;
static uint8_t k72_arena[K72_NODES * 2u * K72_PAGE + 2u * K72_PAGE];
static cdb_pager_node k72_nodes[K72_NODES];
static cdb_free_extent k72_free_list[8192];
static uint8_t k72_record_buf[1024];
static uint8_t k72_cat_work[16384];
static cdb_index_entry k72_cat_entries[512];
static uint8_t k72_cat_page[K72_PAGE];

static cdb_status k72_apply(void *ctx, cdb_pager *p, const cdb_delta *d)
{
    (void)ctx;
    (void)p;
    (void)d;
    return CDB_OK;
}

static int k72_open_with_enclave(cdb_db *db, cdb_env *env, const char *name)
{
    cdb_faultenv_config c;
    cdb_db_config cfg;
    cdb_header h;
    unsigned i;
    int idx = -1;

    setenv("CDB_K72_MK", K72_MK_HEX, 1);
    setenv("CDB_K72_ENC", K72_ENC_KEY_HEX, 1);

    c.arena = k72_env_arena;
    c.file_capacity = K72_FCAP;
    c.records = k72_env_records;
    c.records_per_file = 4096;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&k72_fe, &c, env));

    memset(&cfg, 0, sizeof cfg);
    cfg.pager.arena = k72_arena;
    cfg.pager.arena_size = sizeof k72_arena;
    cfg.pager.nodes = k72_nodes;
    cfg.pager.node_cap = K72_NODES;
    cfg.pager.free_list = k72_free_list;
    cfg.pager.free_cap = sizeof k72_free_list / sizeof k72_free_list[0];
    cfg.record_buf = k72_record_buf;
    cfg.record_buf_size = sizeof k72_record_buf;
    cfg.apply = k72_apply;
    cfg.catalog_work.bytes = k72_cat_work;
    cfg.catalog_work.bytes_size = sizeof k72_cat_work;
    cfg.catalog_work.entries = k72_cat_entries;
    cfg.catalog_work.entries_cap = 512;
    cfg.catalog_page = k72_cat_page;
    cfg.durability = CDB_DURABILITY_FULL;
    cfg.master_key_uri = "env://CDB_K72_MK";

    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)K72_PAGE_LOG2;
    for (i = 0; i < 16; i++)
        h.db_id[i] = (uint8_t)(0x30 + i);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(db, env, name, &cfg, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_enclave(db, 42, "env://CDB_K72_ENC"));

    for (i = 0; i < sizeof(db->enclaves) / sizeof(db->enclaves[0]); i++) {
        if (db->enclaves[i].in_use && db->enclaves[i].enclave_id == 42) {
            idx = (int)i;
            break;
        }
    }
    TEST_ASSERT_TRUE(idx >= 0);
    return idx;
}

/* AC5: after enclave key setup, seal_key/repl_key equal the HKDF-SHA256 goldens
 * for info labels "cdb seal" / "cdb repl" from the enclave key (goldens
 * computed independently with Python's hmac module, not captured from the
 * implementation), and are pairwise distinct and distinct from the master key. */
static void test_seal_repl_hkdf_kat(void)
{
    /* HKDF-SHA256(ikm=enclave_key, salt=<empty>, info="cdb seal"/"cdb repl", L=32). */
    static const uint8_t want_seal[32] = {
        0xa5,0xdb,0x30,0xaf,0x89,0xc4,0x1d,0x15,
        0x7a,0x60,0x38,0xfe,0x33,0xcb,0xff,0x11,
        0x6d,0xf5,0xe7,0x81,0x57,0x4f,0x69,0x67,
        0x92,0xd9,0x78,0x1c,0x4d,0x72,0x90,0x1d };
    static const uint8_t want_repl[32] = {
        0x57,0x5b,0x78,0x4b,0xdc,0x65,0x70,0xfd,
        0xb5,0xca,0x48,0xa6,0x9f,0x73,0x34,0xb2,
        0xb0,0x2d,0x22,0x4c,0xdf,0x7a,0x9e,0x1b,
        0x88,0x0e,0x9c,0x60,0xd8,0x44,0xdc,0x5c };
    static cdb_env env;
    static cdb_db db;
    int idx = k72_open_with_enclave(&db, &env, "k72_kat");

    TEST_ASSERT_EQUAL_MEMORY(want_seal, db.enclaves[idx].seal_key, 32);
    TEST_ASSERT_EQUAL_MEMORY(want_repl, db.enclaves[idx].repl_key, 32);

    /* Pairwise distinct and distinct from the master key. */
    TEST_ASSERT_NOT_EQUAL(0, memcmp(want_seal, want_repl, 32));
    TEST_ASSERT_NOT_EQUAL(0, memcmp(db.enclaves[idx].seal_key, db.master_key, 32));
    TEST_ASSERT_NOT_EQUAL(0, memcmp(db.enclaves[idx].repl_key, db.master_key, 32));
    TEST_ASSERT_NOT_EQUAL(0, memcmp(db.enclaves[idx].seal_key, db.enclaves[idx].enclave_key, 32));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_sha256_known_answers);
    RUN_TEST(test_hmac_sha256_golden);
    RUN_TEST(test_seal_repl_hkdf_kat);
    return UNITY_END();
}
