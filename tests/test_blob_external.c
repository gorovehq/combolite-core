/* Audit follow-up #56 FR1: external-file-backed blobs (cdb_blob.h flags bit 0).
 *
 * Red on current main: cdb_blob_store_external_db / cdb_blob_read_external_db
 * do not exist, so the external-file path cannot store or read a blob. Green
 * after the cdb_blob.c edit: a blob written with the external flag reads back
 * byte-identical, and a missing / short / altered external file fails closed,
 * returning no bytes. All file I/O goes through cdb_env (no hardcoded POSIX). */
#include <string.h>

#include "unity.h"
#include "combolite/cdb_blob.h"
#include "cdb_db.h"
#include "cdb_faultenv.h"

#define FCAP (256u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 32u
#define STORE_ID 77u

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 4096u];
static cdb_faultenv fe;
static cdb_env env;

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[4096];
static uint8_t record_buf[2048];
static uint8_t cat_work[16384];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static uint8_t doc_buffers[8u * PAGE];
static uint8_t doc_stage[4096];
static cdb_db_config cfg;
static cdb_db db;

static void init_env(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 4096;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
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
        h.db_id[i] = (uint8_t)(0x40 + i);
    return h;
}

void setUp(void)
{
    init_env();
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
    cfg.durability = CDB_DURABILITY_FULL;
}

void tearDown(void) {}

static void open_db(const char *name)
{
    cdb_header h = settings();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, name, &cfg, &h));
}

/* AC1/AC4: a blob written with the external flag reads back byte-identical
 * through cdb_env file ops; the ref carries flags bit 0 and no page chain. */
static void test_external_store_read_roundtrip(void)
{
    static const char payload[] = "Hello, external attachment! 0123456789 the quick brown fox.";
    size_t len = sizeof payload - 1u;
    cdb_blob_ref ref;
    uint8_t got[256];
    size_t out_len = 999;

    open_db("ext_rt");

    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_blob_store_external_db(&db, STORE_ID, payload, len, NULL, &ref));
    TEST_ASSERT_EQUAL_UINT32(0x01u, ref.flags & 0x01u); /* external */
    TEST_ASSERT_EQUAL_UINT32(0u, ref.flags & 0x02u);    /* not enclave */
    TEST_ASSERT_EQUAL_UINT64(len, ref.total_len);
    TEST_ASSERT_EQUAL_UINT64(0, ref.first_page); /* no overflow page chain */
    TEST_ASSERT_EQUAL_UINT64(0, ref.page_count);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_read_external_db(&db, &ref, CDB_BLOB_VERIFY_DEFAULT,
                                                            NULL, got, sizeof got, &out_len));
    TEST_ASSERT_EQUAL_size_t(len, out_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, got, len);

    /* Content-addressed: storing the same bytes again is a durable no-op that
     * yields the same reference. */
    cdb_blob_ref ref2;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_blob_store_external_db(&db, STORE_ID, payload, len, NULL, &ref2));
    TEST_ASSERT_EQUAL_MEMORY(ref.hash, ref2.hash, CDB_CRYPTO_HASH_SIZE);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* An empty external blob round-trips with a zero length. */
static void test_external_empty(void)
{
    cdb_blob_ref ref;
    uint8_t got[16];
    size_t out_len = 999;

    open_db("ext_empty");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_store_external_db(&db, STORE_ID, "", 0, NULL, &ref));
    TEST_ASSERT_EQUAL_UINT64(0, ref.total_len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_read_external_db(&db, &ref, CDB_BLOB_VERIFY_DEFAULT,
                                                            NULL, got, sizeof got, &out_len));
    TEST_ASSERT_EQUAL_size_t(0, out_len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC2: a missing external file fails closed (never success with zero bytes). */
static void test_external_missing_fails_closed(void)
{
    cdb_blob_ref ref;
    uint8_t got[16];
    size_t out_len = 999;

    open_db("ext_missing");
    /* A ref with a hash that was never stored resolves to no file. */
    memset(&ref, 0, sizeof ref);
    ref.flags = 0x01u;
    ref.total_len = 8;
    memset(ref.hash, 0xAB, sizeof ref.hash);

    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND,
                          cdb_blob_read_external_db(&db, &ref, CDB_BLOB_VERIFY_DEFAULT, NULL, got,
                                                    sizeof got, &out_len));
    TEST_ASSERT_EQUAL_size_t(0, out_len); /* no bytes returned */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC3: an external file shorter than ref->total_len (truncation) is rejected. */
static void test_external_short_fails_closed(void)
{
    static const char payload[] = "external body that is a known length";
    size_t len = sizeof payload - 1u;
    cdb_blob_ref ref, inflated;
    uint8_t got[256];
    size_t out_len = 999;

    open_db("ext_short");
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_blob_store_external_db(&db, STORE_ID, payload, len, NULL, &ref));

    /* A ref claiming more bytes than the file holds: the size check rejects it
     * before any bytes are read. */
    inflated = ref;
    inflated.total_len = ref.total_len + 32u;
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_blob_read_external_db(&db, &inflated, CDB_BLOB_VERIFY_DEFAULT, NULL,
                                                    got, sizeof got, &out_len));
    TEST_ASSERT_EQUAL_size_t(0, out_len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC3: a same-size but altered external file fails closed (verify-on-read). */
static void test_external_altered_fails_closed(void)
{
    static const char payload[] = "tamper me if you can, the hash will not match";
    size_t len = sizeof payload - 1u;
    cdb_blob_ref ref;
    char path[256];
    cdb_storage st;
    unsigned flip;
    uint8_t byte;
    uint8_t got[256];
    size_t out_len = 999;

    open_db("ext_altered");
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_blob_store_external_db(&db, STORE_ID, payload, len, NULL, &ref));

    /* Overwrite one byte of the companion file in place (same size) through the
     * environment, then read the original ref: verify-on-read must reject it. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_external_path_for_test(&db, &ref, path, sizeof path));
    TEST_ASSERT_EQUAL_INT(CDB_OK, env.ops->open(env.ctx, path, 0u, &st));
    flip = (unsigned)(unsigned char)payload[0] ^ 0xFFu;
    byte = (uint8_t)flip;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_storage_program(&st, 0, &byte, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_storage_sync(&st));
    cdb_storage_close(&st);

    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_blob_read_external_db(&db, &ref, CDB_BLOB_VERIFY_DEFAULT, NULL, got,
                                                    sizeof got, &out_len));
    TEST_ASSERT_EQUAL_size_t(0, out_len);

    /* The size is unchanged, so opting out of verification (NO_VERIFY) still
     * succeeds — proving it is the hash check, not the size check, that caught
     * the alteration above. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_read_external_db(&db, &ref, CDB_BLOB_NO_VERIFY, NULL,
                                                            got, sizeof got, &out_len));
    TEST_ASSERT_EQUAL_size_t(len, out_len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* Enclave external blobs hash with HMAC: the right key verifies, a wrong key
 * is rejected, and the enclave flag is recorded. */
static void test_external_enclave_hmac(void)
{
    static const char payload[] = "enclave-protected external attachment bytes";
    size_t len = sizeof payload - 1u;
    uint8_t key[CDB_CRYPTO_KEY_SIZE], wrong[CDB_CRYPTO_KEY_SIZE];
    cdb_blob_ref ref;
    uint8_t got[256];
    size_t out_len = 999;

    memset(key, 0x5A, sizeof key);
    memset(wrong, 0xA5, sizeof wrong);

    open_db("ext_enclave");
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_blob_store_external_db(&db, STORE_ID, payload, len, key, &ref));
    TEST_ASSERT_EQUAL_UINT32(0x02u, ref.flags & 0x02u); /* enclave */

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_read_external_db(&db, &ref, CDB_BLOB_VERIFY_DEFAULT, key,
                                                            got, sizeof got, &out_len));
    TEST_ASSERT_EQUAL_size_t(len, out_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, got, len);

    out_len = 999;
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_blob_read_external_db(&db, &ref, CDB_BLOB_VERIFY_DEFAULT, wrong, got,
                                                    sizeof got, &out_len));
    TEST_ASSERT_EQUAL_size_t(0, out_len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* A non-external ref (flags bit 0 clear) is rejected by the external reader,
 * and too-small a destination reports the needed size path (fail closed). */
static void test_external_guards(void)
{
    static const char payload[] = "guard rails for the external read path";
    size_t len = sizeof payload - 1u;
    cdb_blob_ref ref, bad;
    uint8_t got[8];
    size_t out_len = 999;

    open_db("ext_guards");
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_blob_store_external_db(&db, STORE_ID, payload, len, NULL, &ref));

    bad = ref;
    bad.flags &= ~0x01u; /* clear the external flag */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_blob_read_external_db(&db, &bad, CDB_BLOB_VERIFY_DEFAULT, NULL, got,
                                                    sizeof got, &out_len));

    /* Destination smaller than the body: rejected, nothing written. */
    out_len = 999;
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL,
                          cdb_blob_read_external_db(&db, &ref, CDB_BLOB_VERIFY_DEFAULT, NULL, got,
                                                    sizeof got, &out_len));
    TEST_ASSERT_EQUAL_size_t(0, out_len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_external_store_read_roundtrip);
    RUN_TEST(test_external_empty);
    RUN_TEST(test_external_missing_fails_closed);
    RUN_TEST(test_external_short_fails_closed);
    RUN_TEST(test_external_altered_fails_closed);
    RUN_TEST(test_external_enclave_hmac);
    RUN_TEST(test_external_guards);
    return UNITY_END();
}
