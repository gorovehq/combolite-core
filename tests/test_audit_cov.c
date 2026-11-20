#define _POSIX_C_SOURCE 200809L
/* Coverage set for cdb_audit: argument guards, the root-split catroot update,
 * range/limit breaks, payload-buffer handling, and the tamper-evidence
 * branches of cdb_audit_verify / cdb_audit_query. Hash-chain records are
 * crafted directly into the audit index (mirroring the engine's own record
 * layout and SHA-256 chaining) so the verifier's corruption, length-mismatch
 * and broken-prev-link branches are reached with a specific *valid==0 /
 * CDB_E_CORRUPT outcome, proving the chain fails closed. Hermetic: faultenv
 * db, tmp arena, no network/clock. Spec 10.6, 10.7, 12.7. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "cdb_audit.h"
#include "cdb_catroot.h"
#include "cdb_db.h"
#include "cdb_endian.h"
#include "cdb_faultenv.h"
#include "cdb_index.h"
#include "cdb_page.h"
#include "combolite/cdb_crypto.h"

#define FCAP (1024u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 32u

#define AUDIT_OFF_TYPE 0u
#define AUDIT_OFF_PRINCIPAL 2u
#define AUDIT_OFF_STORE 6u
#define AUDIT_OFF_ENTITY 14u
#define AUDIT_OFF_PREV_HASH 22u
#define AUDIT_OFF_HASH 54u
#define AUDIT_OFF_PAYLOAD_LEN 86u
#define AUDIT_OFF_PAYLOAD 90u
#define AUDIT_HDR_LEN 90u

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 8192u];
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
static cdb_db_config cfg;
static cdb_db db;

static void init_env(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 8192;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
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
    cfg.durability = CDB_DURABILITY_FULL;
}

void tearDown(void)
{
    (void)cdb_db_close(&db);
}

static cdb_status open_db(void)
{
    cdb_header h;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x7E, sizeof h.db_id);
    return cdb_db_open(&db, &env, "test_audit_cov_db", &cfg, &h);
}

/* Mirror of the engine's audit key: sign-flipped timestamp then sequence. */
static void audit_key(uint8_t out[16], int64_t ts, uint64_t seq)
{
    cdb_store_u64(out, (uint64_t)ts ^ (UINT64_C(1) << 63), CDB_ORDER_BIG);
    cdb_store_u64(out + 8, seq, CDB_ORDER_BIG);
}

/* Mirror of compute_audit_hash: SHA-256 over key||meta22||prev32||plen4||payload. */
static void audit_hash(const uint8_t k[16], uint16_t type, uint32_t prin, uint64_t store,
                       uint64_t entity, const uint8_t prev[32], const uint8_t *payload,
                       uint32_t plen, uint8_t out[32])
{
    cdb_crypto_hash_ctx h;
    uint8_t meta[22];
    uint8_t pb[4];

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_init(&h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&h, k, 16));
    cdb_store_u16(meta, type, CDB_ORDER_BIG);
    cdb_store_u32(meta + 2, prin, CDB_ORDER_BIG);
    cdb_store_u64(meta + 6, store, CDB_ORDER_BIG);
    cdb_store_u64(meta + 14, entity, CDB_ORDER_BIG);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&h, meta, 22));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&h, prev, 32));
    cdb_store_u32(pb, plen, CDB_ORDER_BIG);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&h, pb, 4));
    if (plen > 0)
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&h, payload, plen));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_final(&h, out));
    cdb_crypto_hash_free(&h);
}

/* Creates a fresh, empty audit index and installs it as the catalog's audit root. */
static void craft_index(cdb_index *ix)
{
    cdb_catroot r;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
        cdb_index_create(ix, &db.pager, 0, CDB_INDEX_FLAG_UNIQUE, &db.cfg.catalog_work));
    r = db.pager.catroot;
    r.audit_root = ix->root;
    cdb_pager_set_catroot(&db.pager, &r);
}

static void commit_index(cdb_index *ix)
{
    if (ix->root != db.pager.catroot.audit_root) {
        cdb_catroot r = db.pager.catroot;
        r.audit_root = ix->root;
        cdb_pager_set_catroot(&db.pager, &r);
    }
}

/* Writes a fully-formed audit record (valid self-hash) under (ts, seq). */
static void put_record(cdb_index *ix, int64_t ts, uint64_t seq, uint16_t type, uint32_t prin,
                       uint64_t store, uint64_t entity, const uint8_t prev[32],
                       const char *payload, uint32_t plen)
{
    uint8_t k[16];
    uint8_t v[256];

    audit_key(k, ts, seq);
    cdb_store_u16(v + AUDIT_OFF_TYPE, type, CDB_ORDER_BIG);
    cdb_store_u32(v + AUDIT_OFF_PRINCIPAL, prin, CDB_ORDER_BIG);
    cdb_store_u64(v + AUDIT_OFF_STORE, store, CDB_ORDER_BIG);
    cdb_store_u64(v + AUDIT_OFF_ENTITY, entity, CDB_ORDER_BIG);
    memcpy(v + AUDIT_OFF_PREV_HASH, prev, 32);
    audit_hash(k, type, prin, store, entity, prev, (const uint8_t *)payload, plen, v + AUDIT_OFF_HASH);
    cdb_store_u32(v + AUDIT_OFF_PAYLOAD_LEN, plen, CDB_ORDER_BIG);
    if (plen > 0)
        memcpy(v + AUDIT_OFF_PAYLOAD, payload, plen);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_index_put(ix, k, 16, v, AUDIT_HDR_LEN + plen));
    commit_index(ix);
}

/* ------------------------------------------------------------ argument guards */

static void test_audit_arg_guards(void)
{
    int valid = 0;
    size_t count = 0;
    cdb_audit_event ev[2];
    uint8_t big[4096];

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_audit_log(NULL, CDB_AUDIT_CUSTOM, 0, 0, 0, NULL, 0));
    /* Oversized payload is refused. */
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL,
                          cdb_audit_log(&db, CDB_AUDIT_CUSTOM, 0, 0, 0, big, sizeof big));

    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_audit_verify(NULL, 0, 1, &valid));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_audit_verify(&db, 0, 1, NULL));

    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_audit_query(NULL, 0, 1, NULL, 0, ev, 2, &count));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_audit_query(&db, 0, 1, NULL, 0, ev, 2, NULL));
}

/* ------------------------------------------------------------ empty / no-catalog */

static void test_audit_empty_and_no_catalog(void)
{
    int valid = 0;
    size_t count = 0;
    cdb_audit_event ev[2];

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    /* Empty series (no audit root yet): valid, zero events. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_query(&db, INT64_MIN, INT64_MAX, NULL, 0, ev, 2, &count));
    TEST_ASSERT_EQUAL_size_t(0, count);

    /* Log one event, then drive the "no catalog page" early-outs: audit_init and
     * verify/query all return OK without iterating when catalog_page is absent. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_log(&db, CDB_AUDIT_CUSTOM, 1, 0, 0, "x", 1));

    db.audit_initialized = 0;
    db.cfg.catalog_page = NULL;
    valid = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);

    db.audit_initialized = 0;
    count = 99;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_query(&db, INT64_MIN, INT64_MAX, NULL, 0, ev, 2, &count));
    TEST_ASSERT_EQUAL_size_t(0, count);

    db.cfg.catalog_page = cat_page; /* restore for teardown */
}

/* ------------------------------------------------------------ root split + ranges */

static void test_audit_many_events_and_ranges(void)
{
    int valid = 0;
    size_t count = 0;
    cdb_audit_event ev[64];
    unsigned i;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    /* Enough events (with payloads) to split the index root, exercising the
     * catroot-update branch in cdb_audit_log. */
    for (i = 0; i < 60u; i++)
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_audit_log(&db, CDB_AUDIT_CUSTOM, i, 0, i, "event-payload-bytes", 19));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);

    /* Without a clock the timestamps are sequential (1..60); a bounded range
     * stops the verify loop early at ts >= to_ts. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, 4, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);

    /* Query with a tight to_ts breaks the loop; expect fewer than all events. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_query(&db, INT64_MIN, 4, NULL, 0, ev, 64, &count));
    TEST_ASSERT_EQUAL_size_t(3, count); /* ts 1,2,3 */

    /* max_events caps the result; payload_buf NULL leaves ev.payload NULL. */
    count = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_query(&db, INT64_MIN, INT64_MAX, NULL, 0, ev, 5, &count));
    TEST_ASSERT_EQUAL_size_t(5, count);
    TEST_ASSERT_NULL(ev[0].payload);
    TEST_ASSERT_EQUAL_UINT32(19, ev[0].payload_len);

    /* With a payload buffer the payloads are copied out. */
    {
        uint8_t pbuf[256];
        count = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_query(&db, INT64_MIN, INT64_MAX, pbuf, sizeof pbuf, ev, 5, &count));
        TEST_ASSERT_EQUAL_size_t(5, count);
        TEST_ASSERT_NOT_NULL(ev[0].payload);
        TEST_ASSERT_EQUAL_MEMORY("event-payload-bytes", ev[0].payload, 19);
    }
}

/* ------------------------------------------------------------ crafted corruption */

static void test_audit_short_record(void)
{
    cdb_index ix;
    int valid = 1;
    size_t count = 0;
    cdb_audit_event ev[2];
    uint8_t k[16];
    uint8_t shortv[10] = { 0 };

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    craft_index(&ix);

    /* A record whose value is shorter than the fixed header is corruption. */
    audit_key(k, 1, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_index_put(&ix, k, 16, shortv, sizeof shortv));
    commit_index(&ix);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(0, valid);

    db.audit_initialized = 0;
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_audit_query(&db, INT64_MIN, INT64_MAX, NULL, 0, ev, 2, &count));
}

static void test_audit_payload_len_mismatch(void)
{
    cdb_index ix;
    int valid = 1;
    uint8_t k[16];
    uint8_t v[AUDIT_HDR_LEN];

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    craft_index(&ix);

    /* Header-only value (vlen == 90) but a payload_len field claiming 5 bytes:
     * the stored length disagrees with the record, which is corruption. */
    memset(v, 0, sizeof v);
    audit_key(k, 1, 1);
    cdb_store_u32(v + AUDIT_OFF_PAYLOAD_LEN, 5u, CDB_ORDER_BIG);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_index_put(&ix, k, 16, v, AUDIT_HDR_LEN));
    commit_index(&ix);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(0, valid);
}

static void test_audit_broken_prev_link(void)
{
    cdb_index ix;
    int valid = 1;
    uint8_t zero[32];
    uint8_t wrong[32];

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    craft_index(&ix);

    memset(zero, 0, sizeof zero);
    memset(wrong, 0xCC, sizeof wrong);

    /* First record: valid self-hash, genesis prev-hash (all zero). As the first
     * record verify has no prior hash to compare, so this link is accepted. */
    put_record(&ix, 1, 1, CDB_AUDIT_CUSTOM, 1, 0, 0, zero, "a", 1);
    /* Second record: valid self-hash computed over a prev-hash that does NOT
     * match the first record's hash -> the chain link is broken. */
    put_record(&ix, 2, 2, CDB_AUDIT_CUSTOM, 2, 0, 0, wrong, "b", 1);

    db.audit_initialized = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(0, valid);
}

static void test_audit_crafted_chain_valid(void)
{
    cdb_index ix;
    int valid = 0;
    uint8_t zero[32];
    uint8_t h0[32];
    uint8_t k0[16];

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    craft_index(&ix);

    memset(zero, 0, sizeof zero);

    /* A correctly-chained pair must verify as valid: record 1's prev-hash equals
     * record 0's self-hash. This is the positive counterpart to the broken-link
     * test and proves the verifier accepts a well-formed chain. */
    put_record(&ix, 1, 1, CDB_AUDIT_REVISION, 7, 3, 100, zero, "first", 5);
    audit_key(k0, 1, 1);
    audit_hash(k0, CDB_AUDIT_REVISION, 7, 3, 100, zero, (const uint8_t *)"first", 5, h0);
    put_record(&ix, 2, 2, CDB_AUDIT_REVISION, 8, 3, 101, h0, "second", 6);

    db.audit_initialized = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);
}

/* ------------------------------------------------------------ I/O faults */

static void test_audit_io_faults(void)
{
    int valid = 0;
    size_t count = 0;
    cdb_audit_event ev[2];
    uint64_t sid = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    /* Establish the audit index with a couple of real events. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_log(&db, CDB_AUDIT_CUSTOM, 1, 0, 0, "a", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_log(&db, CDB_AUDIT_CUSTOM, 2, 0, 0, "b", 1));

    /* Arm a crash on the next device mutation; the index write inside the next
     * log triggers it and must propagate a failure rather than losing the
     * event silently. After the crash every device call fails closed. */
    cdb_faultenv_arm(&fe, 1, CDB_CRASH_DROP_UNSYNCED, 0, 0);
    TEST_ASSERT_NOT_EQUAL(CDB_OK, cdb_audit_log(&db, CDB_AUDIT_CUSTOM, 3, 0, 0, "c", 1));

    /* Reads over the now-failed device propagate the error (open/index I/O). */
    TEST_ASSERT_NOT_EQUAL(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_NOT_EQUAL(CDB_OK, cdb_audit_query(&db, INT64_MIN, INT64_MAX, NULL, 0, ev, 2, &count));

    /* Forcing re-initialization drives the audit_init failure propagation in
     * each entry point. */
    db.audit_initialized = 0;
    TEST_ASSERT_NOT_EQUAL(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    db.audit_initialized = 0;
    TEST_ASSERT_NOT_EQUAL(CDB_OK, cdb_audit_query(&db, INT64_MIN, INT64_MAX, NULL, 0, ev, 2, &count));
    db.audit_initialized = 0;
    TEST_ASSERT_NOT_EQUAL(CDB_OK, cdb_audit_log(&db, CDB_AUDIT_CUSTOM, 4, 0, 0, "d", 1));

    (void)sid;
}

static void test_audit_create_fault(void)
{
    uint64_t sid = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    /* No audit events yet (audit root == 0). Crash the device via an unrelated
     * mutation, then the first audit_log must fail while creating the index
     * rather than reporting success. */
    cdb_faultenv_arm(&fe, 1, CDB_CRASH_DROP_UNSYNCED, 0, 0);
    (void)cdb_db_create_store(&db, "s", 1, CDB_MODEL_DOCUMENT, &sid);
    TEST_ASSERT_NOT_EQUAL(CDB_OK, cdb_audit_log(&db, CDB_AUDIT_CUSTOM, 1, 0, 0, "x", 1));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_audit_arg_guards);
    RUN_TEST(test_audit_empty_and_no_catalog);
    RUN_TEST(test_audit_many_events_and_ranges);
    RUN_TEST(test_audit_short_record);
    RUN_TEST(test_audit_payload_len_mismatch);
    RUN_TEST(test_audit_broken_prev_link);
    RUN_TEST(test_audit_crafted_chain_valid);
    RUN_TEST(test_audit_io_faults);
    RUN_TEST(test_audit_create_fault);
    return UNITY_END();
}
