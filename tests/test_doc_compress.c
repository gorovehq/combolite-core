/* Audit follow-up #56 FR2: doc-body compression on the cdb_doc write path
 * (spec 15.3), wired through cdb_codec with raw-fallback.
 *
 * Red on current main: doc bodies are always written uncompressed, so no
 * revision ever carries ENV_FLAG_COMPRESSED and cfg.doc_compress does not
 * exist. Green after the cdb_doc.c edit: with compression enabled a
 * compressible body is stored compressed (flag set) and reads back
 * byte-identical, while an incompressible body falls back to stored-raw (flag
 * clear) and also reads back identical. With compression disabled (the
 * default) even a compressible body is stored raw, so existing callers are
 * unaffected.
 *
 * Scope: doc-bodies only. Journal and page compression are deferred-with-note
 * (see docs/BACKLOG.md) and are NOT exercised here. */
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_catalog.h"
#include "cdb_doc.h"
#include "cdb_faultenv.h"

#define FCAP (768u * 1024u)
#define PAGE_LOG2 10u
#define PAGE (1u << PAGE_LOG2)
#define NODES 64u
#define DOC_MAX 8192u
#define BODY_BYTES 3000u

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 4096u];
static cdb_faultenv fe;
static cdb_env env;

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[8192];
static uint8_t record_buf[4u * DOC_MAX];
static uint8_t cat_work[48u * 1024u];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static uint8_t doc_buffers[64u * 1024u];
static uint8_t doc_stage[8192];
static cdb_db_config cfg;
static cdb_db db;

static uint8_t out[32u * 1024u];

static void init_env(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 4096;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
}

static void base_cfg(void)
{
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
    cfg.doc_max = DOC_MAX;
    cfg.durability = CDB_DURABILITY_FULL;
}

void setUp(void)
{
    init_env();
    base_cfg();
    TEST_ASSERT_TRUE(cdb_doc_buffers_size(PAGE, DOC_MAX) <= sizeof doc_buffers);
}

void tearDown(void) {}

static cdb_status open_db(const char *name)
{
    cdb_header h;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x5D, sizeof h.db_id);
    return cdb_db_open(&db, &env, name, &cfg, &h);
}

/* Builds a one-field document object { 1: binary(data, len) }. */
static size_t make_doc(const uint8_t *data, size_t len, uint8_t *buf, size_t cap)
{
    cdb_value_writer w;
    cdb_value_writer_init(&w, buf, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_binary(&w, data, len);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    return cdb_value_writer_len(&w);
}

static void fill_repeating(uint8_t *b, size_t n)
{
    memset(b, 'A', n); /* highly compressible */
}

static void fill_random(uint8_t *b, size_t n)
{
    uint32_t s = 0x9E3779B9u; /* deterministic, high-entropy (incompressible) */
    size_t i;
    for (i = 0; i < n; i++) {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        b[i] = (uint8_t)(s >> 24);
    }
}

/* Inserts one document in a fresh document pool and returns its entry. */
static uint64_t insert_doc(uint64_t *pool_out, const uint8_t *body, size_t body_len)
{
    uint64_t pool = 0, entry = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "docs", 4, CDB_MODEL_DOCUMENT, &pool));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, body, body_len, &entry));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    *pool_out = pool;
    return entry;
}

static void expect_body(uint64_t pool, uint64_t entry, const uint8_t *body, size_t body_len)
{
    size_t got = 0;
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_doc_get(&db, pool, entry, 0, out, sizeof out, &got, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_size_t(body_len, got);
    TEST_ASSERT_EQUAL_MEMORY(body, out, body_len);
}

/* AC5: a compressible body, with compression enabled, is stored compressed
 * (ENV_FLAG_COMPRESSED set) and reads back byte-identical. */
static void test_compressible_stored_compressed(void)
{
    uint8_t body[BODY_BYTES];
    uint8_t doc[16u * 1024u];
    uint64_t pool = 0, entry;
    size_t dlen;
    uint8_t flags = 0;

    cfg.doc_compress = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db("doc_comp_on"));
    fill_repeating(body, sizeof body);
    dlen = make_doc(body, sizeof body, doc, sizeof doc);
    entry = insert_doc(&pool, doc, dlen);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_head_flags_for_test(&db, pool, entry, &flags));
    TEST_ASSERT_EQUAL_UINT8(CDB_DOC_ENV_FLAG_COMPRESSED,
                            flags & CDB_DOC_ENV_FLAG_COMPRESSED); /* stored compressed */

    expect_body(pool, entry, doc, dlen); /* byte-identical round-trip */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC6: an incompressible body falls back to stored-raw (flag clear) and still
 * reads back byte-identical. */
static void test_incompressible_falls_back_raw(void)
{
    uint8_t body[BODY_BYTES];
    uint8_t doc[16u * 1024u];
    uint64_t pool = 0, entry;
    size_t dlen;
    uint8_t flags = 0xFF;

    cfg.doc_compress = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db("doc_comp_raw"));
    fill_random(body, sizeof body);
    dlen = make_doc(body, sizeof body, doc, sizeof doc);
    entry = insert_doc(&pool, doc, dlen);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_head_flags_for_test(&db, pool, entry, &flags));
    TEST_ASSERT_EQUAL_UINT8(0u, flags & CDB_DOC_ENV_FLAG_COMPRESSED); /* stored raw */

    expect_body(pool, entry, doc, dlen);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* Opt-out (the default): even a compressible body is stored raw when
 * compression is disabled, so existing behaviour is unchanged. */
static void test_disabled_stores_raw(void)
{
    uint8_t body[BODY_BYTES];
    uint8_t doc[16u * 1024u];
    uint64_t pool = 0, entry;
    size_t dlen;
    uint8_t flags = 0xFF;

    cfg.doc_compress = 0; /* default */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db("doc_comp_off"));
    fill_repeating(body, sizeof body);
    dlen = make_doc(body, sizeof body, doc, sizeof doc);
    entry = insert_doc(&pool, doc, dlen);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_head_flags_for_test(&db, pool, entry, &flags));
    TEST_ASSERT_EQUAL_UINT8(0u, flags & CDB_DOC_ENV_FLAG_COMPRESSED);

    expect_body(pool, entry, doc, dlen);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* A compressed body survives replacement and patch materialization: the
 * delta chain decompresses transparently. */
static void test_compressed_replace_roundtrip(void)
{
    uint8_t body_a[BODY_BYTES], body_b[BODY_BYTES];
    uint8_t doc_a[16u * 1024u], doc_b[16u * 1024u];
    uint64_t pool = 0, entry;
    size_t da, dbn;

    cfg.doc_compress = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db("doc_comp_repl"));
    memset(body_a, 'A', sizeof body_a);
    memset(body_b, 'B', sizeof body_b);
    da = make_doc(body_a, sizeof body_a, doc_a, sizeof doc_a);
    dbn = make_doc(body_b, sizeof body_b, doc_b, sizeof doc_b);

    entry = insert_doc(&pool, doc_a, da);
    expect_body(pool, entry, doc_a, da);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_replace(&db, pool, entry, NULL, 0, doc_b, dbn));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    expect_body(pool, entry, doc_b, dbn);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_compressible_stored_compressed);
    RUN_TEST(test_incompressible_falls_back_raw);
    RUN_TEST(test_disabled_stores_raw);
    RUN_TEST(test_compressed_replace_roundtrip);
    return UNITY_END();
}
