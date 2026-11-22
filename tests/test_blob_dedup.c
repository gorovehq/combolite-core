/* Content-addressed, deduplicated, integrity-verified blob storage (issue #39).
 *
 * Red->green regressions for: dedup by content hash with per-domain refcount;
 * refcounted free (pages released only at zero); dedup index persistence via
 * dedup_root; verify-by-default on read; tight per-page length validation even
 * with verification off; and the total_len -> size_t truncation guard. */
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_blob.h"
#include "cdb_db.h"
#include "cdb_faultenv.h"
#include "cdb_overflow.h"
#include "cdb_page.h"

#define FCAP (1024u * 1024u)
#define PAGE_LOG2 9u /* 512-byte pages */
#define PAGE (1u << PAGE_LOG2)
#define NODES 32u
#define TEST_STORE_ID 77u

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 4096u];
static cdb_faultenv fe;
static cdb_env env;

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[8192];
static uint8_t record_buf[2048];
static uint8_t cat_work[16384];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static uint8_t doc_buffers[8u * PAGE];
static uint8_t doc_stage[4096];
static uint8_t page_buf[PAGE];
static uint8_t scratch_buf[PAGE];
static cdb_db_config cfg;
static cdb_db db;

/* A payload spanning several overflow pages so dedup covers multi-page chains. */
static uint8_t payload[4096];

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
    size_t i;
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

    for (i = 0; i < sizeof payload; ++i)
        payload[i] = (uint8_t)((i * 31u + 7u) & 0xFFu);
}

void tearDown(void)
{
}

/* Writes payload[0..len) through the high-level (deduplicating) wrapper. */
static cdb_blob_ref write_blob(uint64_t store, const uint8_t *data, size_t len)
{
    cdb_blob_writer w;
    cdb_blob_ref ref;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_write_begin(&db, store, scratch_buf, &w));
    if (len > 0)
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_write_chunk(&w, data, len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_write_end(&w, &ref));
    return ref;
}

/* Reads the whole blob and asserts it equals data[0..len). verify selects the
 * integrity mode. */
static void read_and_check(uint64_t store, const cdb_blob_ref *ref, int verify, const uint8_t *data,
                           size_t len)
{
    cdb_blob_reader r;
    static uint8_t out[sizeof payload];
    size_t off = 0, got;
    TEST_ASSERT_TRUE(len <= sizeof out);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_read_begin(&db, store, ref, page_buf, verify, &r));
    while (off < len) {
        got = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_read_chunk(&r, out + off, len - off, &got));
        TEST_ASSERT_TRUE(got > 0);
        off += got;
    }
    got = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_db_blob_read_chunk(&r, scratch_buf, sizeof scratch_buf, &got));
    TEST_ASSERT_EQUAL_UINT64(0, got);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_read_end(&r));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(data, out, len);
}

/* AC1/AC2: identical content stores one chain; refcounted free. */
static void test_dedup_single_copy_and_refcount(void)
{
    cdb_header h = settings();
    cdb_blob_ref r1, r2, r3;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "test_b_dedup", &cfg, &h));

    r1 = write_blob(TEST_STORE_ID, payload, sizeof payload);
    TEST_ASSERT_TRUE(r1.page_count > 1); /* multi-page chain */
    r2 = write_blob(TEST_STORE_ID, payload, sizeof payload);

    /* Content-addressed: the second write returns the SAME canonical chain,
     * not a fresh copy (pre-fix: write_end always allocated a new chain). */
    TEST_ASSERT_EQUAL_UINT64(r1.first_page, r2.first_page);
    TEST_ASSERT_EQUAL_UINT64(r1.page_count, r2.page_count);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(r1.hash, r2.hash, CDB_CRYPTO_HASH_SIZE);

    /* refcount == 2. Freeing one reference must keep the data readable
     * (pre-fix: the first free released the only shared chain). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, TEST_STORE_ID, &r1, page_buf));
    read_and_check(TEST_STORE_ID, &r2, CDB_BLOB_VERIFY, payload, sizeof payload);

    /* Freeing the last reference releases the chain and drops the entry. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, TEST_STORE_ID, &r2, page_buf));

    /* The entry is gone, so writing the same content now allocates a fresh
     * chain at a higher (never-reused) logical id. */
    r3 = write_blob(TEST_STORE_ID, payload, sizeof payload);
    TEST_ASSERT_TRUE(r3.first_page > r1.first_page);
    read_and_check(TEST_STORE_ID, &r3, CDB_BLOB_VERIFY, payload, sizeof payload);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, TEST_STORE_ID, &r3, page_buf));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC3: the dedup index survives a close/reopen via dedup_root. */
static void test_dedup_persists_across_reopen(void)
{
    cdb_header h = settings();
    cdb_blob_ref r1, r2;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "test_b_persist", &cfg, &h));
    r1 = write_blob(TEST_STORE_ID, payload, sizeof payload);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db)); /* commits the pager */

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "test_b_persist", &cfg, &h));
    r2 = write_blob(TEST_STORE_ID, payload, sizeof payload);
    /* Hit against the persisted dedup index: same canonical chain. */
    TEST_ASSERT_EQUAL_UINT64(r1.first_page, r2.first_page);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(r1.hash, r2.hash, CDB_CRYPTO_HASH_SIZE);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, TEST_STORE_ID, &r2, page_buf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, TEST_STORE_ID, &r1, page_buf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC4/AC5: verification is the default; only the explicit opt-out skips it. */
static void test_verify_by_default(void)
{
    cdb_header h = settings();
    cdb_blob_writer w;
    cdb_blob_ref ref;
    cdb_blob_reader r;
    cdb_page_header ph;
    static uint8_t out[sizeof payload];
    size_t got;
    cdb_status s;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "test_b_verify", &cfg, &h));

    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_blob_write_begin(&db.pager, TEST_STORE_ID, scratch_buf, NULL, &w));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_write_chunk(&w, payload, sizeof payload));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_write_end(&w, &ref));

    /* Tamper a payload byte on the first page (length unchanged). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(&db.pager, ref.first_page, page_buf, &ph));
    page_buf[cdb_page_payload_offset(db.pager.fmt) + db.pager.addr_width + 3] ^= 0xA5;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_write(&db.pager, ref.first_page, &ph,
                                                  page_buf + cdb_page_payload_offset(db.pager.fmt),
                                                  ph.payload_len));

    /* Read with the DEFAULT mode (0) — pre-fix this meant "no verify" and the
     * corrupt bytes came back silently; now it must be rejected. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_read_begin(&db.pager, TEST_STORE_ID, &ref, page_buf,
                                                      CDB_BLOB_VERIFY_DEFAULT, NULL, &r));
    s = cdb_blob_read_chunk(&r, out, sizeof out, &got);
    if (s == CDB_OK)
        s = cdb_blob_read_chunk(&r, scratch_buf, 1, &got);
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, s);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_read_end(&r));

    /* Explicit opt-out: the escape hatch skips the hash check and returns the
     * (tampered) bytes without CDB_E_CORRUPT. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_read_begin(&db.pager, TEST_STORE_ID, &ref, page_buf,
                                                      CDB_BLOB_NO_VERIFY, NULL, &r));
    got = 0;
    s = cdb_blob_read_chunk(&r, out, sizeof out, &got);
    while (s == CDB_OK && got > 0 && got < sizeof out)
        s = cdb_blob_read_chunk(&r, out + got, sizeof out - got, &got);
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_read_end(&r));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC6: a malformed interior page length is rejected even with verify OFF. */
static void test_tight_page_length_no_verify(void)
{
    cdb_header h = settings();
    cdb_blob_writer w;
    cdb_blob_ref ref;
    cdb_blob_reader r;
    cdb_page_header ph;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "test_b_len", &cfg, &h));

    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_blob_write_begin(&db.pager, TEST_STORE_ID, scratch_buf, NULL, &w));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_write_chunk(&w, payload, sizeof payload));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_write_end(&w, &ref));
    TEST_ASSERT_TRUE(ref.page_count > 1); /* a full interior first page */

    /* Shorten the first (interior, must-be-full) page's payload by one byte:
     * payload_len != addr_width + part. The exact chain check must catch it. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(&db.pager, ref.first_page, page_buf, &ph));
    TEST_ASSERT_TRUE(ph.payload_len > db.pager.addr_width + 1u);
    ph.payload_len -= 1u;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_write(&db.pager, ref.first_page, &ph,
                                                  page_buf + cdb_page_payload_offset(db.pager.fmt),
                                                  ph.payload_len));

    /* Even with verification explicitly OFF, the malformed interior length is
     * rejected as the chain is walked (pre-fix the loose "payload_len >=
     * addr_width" check accepted it and returned the bytes). The first page is
     * the malformed one, so the exact check fires at read_begin. */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_blob_read_begin(&db.pager, TEST_STORE_ID, &ref, page_buf,
                                              CDB_BLOB_NO_VERIFY, NULL, &r));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC7: the total_len -> size_t conversion is guarded, not silently truncated.
 * Exercised through the test hook so the guard is deterministic on LP64 hosts
 * where total_len can never actually exceed SIZE_MAX. */
static void test_total_len_size_guard(void)
{
    /* Simulate a 32-bit size_t: a value above the max is rejected. */
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW,
                          cdb_blob_len_within_for_test(0x1FFFFFFFFULL, 0xFFFFFFFFULL));
    /* A value within the max is accepted. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_len_within_for_test(4096u, 0xFFFFFFFFULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_len_within_for_test(0xFFFFFFFFULL, 0xFFFFFFFFULL));
    /* Boundary: exactly one past the max is rejected. */
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW,
                          cdb_blob_len_within_for_test(0x100000000ULL, 0xFFFFFFFFULL));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_dedup_single_copy_and_refcount);
    RUN_TEST(test_dedup_persists_across_reopen);
    RUN_TEST(test_verify_by_default);
    RUN_TEST(test_tight_page_length_no_verify);
    RUN_TEST(test_total_len_size_guard);
    return UNITY_END();
}
