/* Coverage set for cdb_db (agent-authored): deep paths test_db.c and
 * test_db_fault.c miss. Targets the replicated-change import functions
 * (cdb_db_crdt_import_deltas / _import_slice and their crdt_import_* helpers),
 * enclave creation + key rotation (db_rotate_enclave_key_in,
 * cdb_db_rotate_master_key, cdb_db_check_key_rotation), the salt scrub
 * (db_scrub_in), RBAC, triggers, streaming blobs, the single-process
 * reconciliation-request path, the entry-ID block lifecycle
 * (release_held_blocks / raise_block_counters via the document model), and the
 * operation-scope helpers. Spec 19 (CRDT), 12 (crypto/RBAC), 5.9.3/8
 * (coordination), 8.4 (blobs), 11.6 (triggers). */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "combolite/cdb_crypto.h"
#include "combolite/cdb_crdt.h"
#include "cdb_db.h"
#include "cdb_doc.h"
#include "cdb_faultenv.h"

#define FCAP (768u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define STORE 1u
#define KV_PAGES 128u
#define ENCLAVE 42u /* stores from 42 are enclaves (kv_apply tags their pages) */

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 4096u];
static cdb_faultenv fe;
static cdb_env env;

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[8192];
static uint8_t record_buf[2048];
static uint8_t cat_work[24u * 1024u];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static uint8_t doc_buffers[8u * PAGE];
static uint8_t doc_stage[4096];
static uint8_t idx_stage[8u * 1024u];
static uint8_t page[PAGE];
static uint8_t scratch[PAGE];
static cdb_db_config cfg;
static cdb_db db;

/* A tiny key-value apply (as in the CRDT/security tests): entry N lives in
 * logical page N; stores from ENCLAVE tag their pages with that domain so the
 * crypto and scrub paths engage. */
static cdb_status kv_apply(void *ctx, cdb_pager *p, const cdb_delta *d)
{
    cdb_page_header t;
    uint64_t lid;
    cdb_status s;
    (void)ctx;
    TEST_ASSERT_TRUE(d->entry_id < KV_PAGES);
    if (d->op == CDB_OP_DELETE) {
        s = cdb_pager_free(p, d->entry_id);
        return s == CDB_E_NOT_FOUND ? CDB_OK : s;
    }
    while (p->next_lid < KV_PAGES)
        if ((s = cdb_pager_alloc(p, &lid)) != CDB_OK)
            return s;
    memset(&t, 0, sizeof t);
    t.type = CDB_PAGE_TYPE_DATA_TEST;
    t.store_id = d->store_id;
    t.domain_id = d->store_id >= ENCLAVE ? d->store_id : 0u;
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
    cfg.doc_buffers = doc_buffers;
    cfg.doc_stage = doc_stage;
    cfg.doc_stage_size = sizeof doc_stage;
    cfg.idx_stage = idx_stage;
    cfg.idx_stage_size = sizeof idx_stage;
    cfg.durability = CDB_DURABILITY_FULL;

    setenv("CDB_T2_MK", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1);
    setenv("CDB_T2_MK_NEW", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 1);
    setenv("CDB_T2_ENC", "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff", 1);
    setenv("CDB_T2_ENC2", "22334455667788990011bbccddeeff0022334455667788990011bbccddeeff00", 1);
}

void tearDown(void) {}

static cdb_status open_kv(const char *base, const cdb_header *create)
{
    cdb_header h = settings();
    return cdb_db_open(&db, &env, base, &cfg, create ? create : &h);
}

/* Reads back the payload a kv page carries, or returns 1 when absent and text
 * is NULL. */
static int page_is(uint64_t lid, const char *text)
{
    cdb_page_header ph;
    cdb_status s = cdb_pager_read(&db.pager, lid, page, &ph);
    if (s == CDB_E_NOT_FOUND)
        return text == NULL;
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);
    if (text == NULL)
        return 0;
    return ph.payload_len == strlen(text)
           && memcmp(page + cdb_page_payload_offset(db.pager.fmt), text, ph.payload_len) == 0;
}

/* ---------------------------------------------- 1. CRDT import of deltas */

static cdb_crdt_delta_rec drec(uint64_t entry, uint8_t op, uint32_t peer, uint64_t phys, const char *data)
{
    cdb_crdt_delta_rec r;
    memset(&r, 0, sizeof r);
    r.store_id = STORE;
    r.entry_id = entry;
    r.op = op;
    r.hlc.physical = phys;
    r.hlc.peer_id = peer;
    r.data = (const uint8_t *)data;
    r.len = data ? strlen(data) : 0u;
    return r;
}

/* The argument-validation branches and the empty-batch early return. */
static void test_import_deltas_argcheck(void)
{
    cdb_crdt_delta_rec r = drec(1, CDB_OP_INSERT, 9, 100, "x");
    size_t applied = 123;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("idarg", NULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_crdt_import_deltas(NULL, 9, &r, 1, &applied));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_crdt_import_deltas(&db, 9, &r, 1, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_crdt_import_deltas(&db, 9, NULL, 1, &applied));
    applied = 7;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_deltas(&db, 9, NULL, 0, &applied));
    TEST_ASSERT_EQUAL_UINT(0u, (unsigned)applied);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* Own-origin skip, already-seen skip, a real apply, the sender becoming
 * known, and idempotence (own-transaction commit path). */
static void test_import_deltas_apply_and_skip(void)
{
    cdb_crdt_delta_rec batch[4];
    size_t applied = 99;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("idapply", NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_set_peer_id(&db, 5u));

    batch[0] = drec(5, CDB_OP_INSERT, 5u, 100, "self");   /* our own peer: skipped */
    batch[1] = drec(10, CDB_OP_INSERT, 9u, 200, "nine");  /* applied */
    batch[2] = drec(10, CDB_OP_INSERT, 9u, 150, "older"); /* seen within the call: skipped */
    batch[3] = drec(11, CDB_OP_INSERT, 0u, 300, "anon");  /* peer 0: never skipped */
    /* remote_peer 77 never appears as an origin, so it is recorded as known. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_deltas(&db, 77u, batch, 4, &applied));
    TEST_ASSERT_EQUAL_UINT(2u, (unsigned)applied);
    TEST_ASSERT_TRUE(page_is(10, "nine"));
    TEST_ASSERT_TRUE(page_is(11, "anon"));
    TEST_ASSERT_TRUE(page_is(5, NULL));
    {
        cdb_crdt_peer_entry pe;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crdt_vector_get(&db.crdt_vector, 77u, &pe));
    }

    /* The same batch again: the peer-9 records are seen, but a record with no
     * origin (peer 0) carries no causality and always re-applies, so one lands. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_deltas(&db, 77u, batch, 4, &applied));
    TEST_ASSERT_EQUAL_UINT(1u, (unsigned)applied);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* When every record is skipped the opened transaction is aborted, not
 * committed (crdt_import_end's applied==0 branch). */
static void test_import_deltas_all_skipped_aborts(void)
{
    cdb_crdt_delta_rec batch[2];
    size_t applied = 5;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("idskip", NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_set_peer_id(&db, 3u));
    batch[0] = drec(1, CDB_OP_INSERT, 3u, 10, "self1");
    batch[1] = drec(2, CDB_OP_INSERT, 3u, 20, "self2");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_deltas(&db, 3u, batch, 2, &applied));
    TEST_ASSERT_EQUAL_UINT(0u, (unsigned)applied);
    TEST_ASSERT_FALSE(db.in_tx); /* the opened transaction was aborted */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* Imported inside a caller transaction: the savepoint path (crdt_import_begin
 * own_tx==0) and the commit-at-caller-commit vector advance (spec 19.4). */
static void test_import_deltas_in_caller_tx(void)
{
    cdb_crdt_delta_rec r = drec(12, CDB_OP_INSERT, 8u, 400, "caller");
    size_t applied = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("idtx", NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_set_peer_id(&db, 2u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 13, CDB_OP_INSERT, "own", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_deltas(&db, 8u, &r, 1, &applied));
    TEST_ASSERT_EQUAL_UINT(1u, (unsigned)applied);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_TRUE(page_is(12, "caller"));
    TEST_ASSERT_TRUE(page_is(13, "own"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* More distinct origins in one call than CDB_CRDT_MAX_PEERS: the one past the
 * limit is refused and the whole call undone (own-transaction abort). */
static void test_import_deltas_too_many_origins(void)
{
    cdb_crdt_delta_rec batch[CDB_CRDT_MAX_PEERS + 1u];
    size_t applied = 42;
    unsigned i;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("idmany", NULL));
    for (i = 0; i < CDB_CRDT_MAX_PEERS + 1u; i++)
        batch[i] = drec((uint64_t)i + 1u, CDB_OP_INSERT, (uint32_t)(100u + i), 500u + i, "p");
    TEST_ASSERT_EQUAL_INT(CDB_E_OUT_OF_BUDGET,
                          cdb_db_crdt_import_deltas(&db, 0u, batch, CDB_CRDT_MAX_PEERS + 1u, &applied));
    TEST_ASSERT_FALSE(db.in_tx);        /* the opened transaction was rolled all the way back */
    TEST_ASSERT_TRUE(page_is(1, NULL)); /* nothing of the failed call landed */

    /* The same failure inside a caller transaction rolls back only to the
     * call's savepoint (crdt_import_fail's non-own-tx branch); the caller's
     * earlier change survives its own commit. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 100, CDB_OP_INSERT, "survivor", 8));
    TEST_ASSERT_EQUAL_INT(CDB_E_OUT_OF_BUDGET,
                          cdb_db_crdt_import_deltas(&db, 0u, batch, CDB_CRDT_MAX_PEERS + 1u, &applied));
    TEST_ASSERT_TRUE(db.in_tx); /* still open: only the import's savepoint was undone */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_TRUE(page_is(100, "survivor"));
    TEST_ASSERT_TRUE(page_is(1, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ---------------------------------------------- 1b. CRDT export of deltas */

/* Export the committed changes as a wire slice (cdb_db_crdt_export_slice +
 * crdt_walk): the size-measuring pass (out_buf NULL), a full export, a
 * re-export filtered by a since-vector, and round-tripping it back in. */
static void test_export_slice(void)
{
    uint8_t slice[1024];
    size_t needed = 0, len = 0, applied = 0;
    cdb_crdt_vector since;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("exp2", NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_set_peer_id(&db, 1u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 1, CDB_OP_INSERT, "a", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 2, CDB_OP_INSERT, "b", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* Argument checks and the measure pass (out_buf NULL -> size only). */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_crdt_export_slice(NULL, NULL, slice, sizeof slice, &len));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_crdt_export_slice(&db, NULL, slice, sizeof slice, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_db_crdt_export_slice(&db, NULL, NULL, 0, &needed));
    TEST_ASSERT_TRUE(needed > 12u);

    /* A full export fits and its wire header carries the magic + our peer. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_export_slice(&db, NULL, slice, sizeof slice, &len));
    TEST_ASSERT_EQUAL_size_t(needed, len);
    TEST_ASSERT_EQUAL_UINT32(CDB_CRDT_WIRE_MAGIC, cdb_load_u32(slice, CDB_ORDER_BIG));
    TEST_ASSERT_EQUAL_UINT32(1u, cdb_load_u32(slice + 4, CDB_ORDER_BIG));
    TEST_ASSERT_TRUE(cdb_load_u32(slice + 8, CDB_ORDER_BIG) >= 2u);

    /* A since-vector already past our counter yields the header alone. */
    memset(&since, 0, sizeof since);
    cdb_crdt_vector_set(&since, 1u, 1000u, (cdb_hlc){ 0u, 0u, 1u });
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_export_slice(&db, &since, slice, sizeof slice, &len));
    TEST_ASSERT_EQUAL_UINT32(0u, cdb_load_u32(slice + 8, CDB_ORDER_BIG));

    /* The full slice imports into a second peer. */
    {
        static cdb_db db2;
        static cdb_db_config cfg2;
        static uint8_t arena2[NODES * 2u * PAGE + 2u * PAGE];
        static cdb_pager_node nodes2[NODES];
        static cdb_free_extent fl2[8192];
        static uint8_t rb2[2048], cw2[24u * 1024u], cp2[PAGE], pg2[PAGE];
        static cdb_index_entry ce2[512];
        cdb_header h = settings();
        cdb_page_header ph;

        memset(&cfg2, 0, sizeof cfg2);
        cfg2.pager.arena = arena2;
        cfg2.pager.arena_size = sizeof arena2;
        cfg2.pager.nodes = nodes2;
        cfg2.pager.node_cap = NODES;
        cfg2.pager.free_list = fl2;
        cfg2.pager.free_cap = sizeof fl2 / sizeof fl2[0];
        cfg2.record_buf = rb2;
        cfg2.record_buf_size = sizeof rb2;
        cfg2.apply = kv_apply;
        cfg2.catalog_work.bytes = cw2;
        cfg2.catalog_work.bytes_size = sizeof cw2;
        cfg2.catalog_work.entries = ce2;
        cfg2.catalog_work.entries_cap = 512;
        cfg2.catalog_page = cp2;
        cfg2.durability = CDB_DURABILITY_FULL;

        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db2, &env, "exp2b", &cfg2, &h));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_set_peer_id(&db2, 2u));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_export_slice(&db, NULL, slice, sizeof slice, &len));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_slice(&db2, slice, len, &applied));
        TEST_ASSERT_TRUE(applied >= 2u);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(&db2.pager, 1, pg2, &ph));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db2));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ---------------------------------------------- 2. CRDT import wire errors */

static void test_import_slice_wire_errors(void)
{
    uint8_t buf[64];
    size_t applied = 9;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("slerr", NULL));

    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_crdt_import_slice(&db, NULL, 12, &applied));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_crdt_import_slice(&db, buf, 12, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_TRUNCATED, cdb_db_crdt_import_slice(&db, buf, 8, &applied));

    memset(buf, 0, sizeof buf); /* bad magic */
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_db_crdt_import_slice(&db, buf, 12, &applied));

    cdb_store_u32(buf, CDB_CRDT_WIRE_MAGIC, CDB_ORDER_BIG);
    cdb_store_u32(buf + 4, 0u, CDB_ORDER_BIG);
    cdb_store_u32(buf + 8, 0u, CDB_ORDER_BIG); /* zero records: nothing to do */
    applied = 9;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_slice(&db, buf, 12, &applied));
    TEST_ASSERT_EQUAL_UINT(0u, (unsigned)applied);

    /* One record claimed, but the buffer is shorter than one record header. */
    cdb_store_u32(buf + 8, 1u, CDB_ORDER_BIG);
    TEST_ASSERT_EQUAL_INT(CDB_E_TRUNCATED, cdb_db_crdt_import_slice(&db, buf, 20, &applied));

    /* One record with a declared data length past the buffer end. */
    {
        uint8_t big[64];
        memset(big, 0, sizeof big);
        cdb_store_u32(big, CDB_CRDT_WIRE_MAGIC, CDB_ORDER_BIG);
        cdb_store_u32(big + 8, 1u, CDB_ORDER_BIG);
        cdb_store_u32(big + 12 + 33, 0xFFFFu, CDB_ORDER_BIG); /* dlen huge */
        TEST_ASSERT_EQUAL_INT(CDB_E_TRUNCATED, cdb_db_crdt_import_slice(&db, big, 12 + 37, &applied));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ---------------------------------------------- 3. Enclaves & key rotation */

static cdb_status put_enc(uint64_t store, uint64_t entry, const char *text)
{
    cdb_status s;
    if ((s = cdb_tx_begin(&db, CDB_DURABILITY_FULL)) != CDB_OK)
        return s;
    if ((s = cdb_tx_put(&db, store, entry, CDB_OP_REPLACE, text, strlen(text))) != CDB_OK)
        return s;
    return cdb_tx_commit(&db);
}

/* Create an enclave, write it, then rotate its key and write under the new
 * version (db_rotate_enclave_key_in). Rotation re-keys going forward only, so
 * the new page is what we read back. */
static void test_enclave_key_rotation(void)
{
    cdb_header h = settings();
    cfg.master_key_uri = "env://CDB_T2_MK";
    cfg.aead_alg = CDB_AEAD_AES_256_GCM;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "enc2a", &cfg, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_enclave(&db, ENCLAVE, "env://CDB_T2_ENC"));
    TEST_ASSERT_EQUAL_INT(CDB_E_EXISTS, cdb_db_create_enclave(&db, ENCLAVE, "env://CDB_T2_ENC"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, put_enc(ENCLAVE, 1, "v1"));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_rotate_enclave_key(&db, ENCLAVE, "env://CDB_T2_ENC2"));
    TEST_ASSERT_EQUAL_UINT32(2u, db.enclaves[0].key_version);
    TEST_ASSERT_EQUAL_INT(CDB_OK, put_enc(ENCLAVE, 2, "v2"));
    TEST_ASSERT_TRUE(page_is(2, "v2"));

    /* Rotating an enclave that was never created is reported, not invented. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_db_rotate_enclave_key(&db, 99u, "env://CDB_T2_ENC"));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_rotate_enclave_key(&db, 0u, "env://CDB_T2_ENC"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* Rotate the master key (cdb_db_rotate_master_key): the enclave key is
 * unchanged, so its page stays readable, and a session opened under the new
 * master key reads it once the enclave is opened. */
static void test_master_key_rotation(void)
{
    cdb_header h = settings();
    cfg.master_key_uri = "env://CDB_T2_MK";
    cfg.aead_alg = CDB_AEAD_AES_256_GCM;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "enc2b", &cfg, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_enclave(&db, ENCLAVE, "env://CDB_T2_ENC"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, put_enc(ENCLAVE, 1, "v1"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_rotate_master_key(&db, "env://CDB_T2_MK_NEW"));
    TEST_ASSERT_TRUE(page_is(1, "v1"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    /* Reopen under the rotated master key: unreadable until the enclave opens. */
    cfg.master_key_uri = "env://CDB_T2_MK_NEW";
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "enc2b", &cfg, NULL));
    {
        cdb_page_header ph;
        TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_pager_read(&db.pager, 1, page, &ph));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open_enclave(&db, ENCLAVE, "env://CDB_T2_ENC"));
    TEST_ASSERT_TRUE(page_is(1, "v1"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

static void test_rotation_policy_and_check(void)
{
    cdb_header h = settings();
    cfg.master_key_uri = "env://CDB_T2_MK";
    cfg.rotation_interval_days = 90;

    /* REFUSE_OPEN: an expired interval fails the check. */
    cfg.rotation_policy = CDB_ROTATION_REFUSE_OPEN;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "rotpol", &cfg, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_check_key_rotation(&db)); /* not expired yet */
    db.rotation_expired = 1;
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_db_check_key_rotation(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    /* REFUSE_WRITES: a transaction is refused once the interval is expired. */
    cfg.rotation_policy = CDB_ROTATION_REFUSE_WRITES;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "rotpol2", &cfg, &h));
    db.rotation_expired = 1;
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ---------------------------------------------- 4. Salt scrub */

/* A scrub pass over encrypted pages: a whole pass, then a budgeted
 * (page-at-a-time) pass in a later session with a second salt. */
static void test_scrub_pass_and_prune(void)
{
    cdb_header h = settings();
    int done;
    cfg.master_key_uri = "env://CDB_T2_MK";
    cfg.aead_alg = CDB_AEAD_AES_256_GCM;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "scrub2", &cfg, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_enclave(&db, ENCLAVE, "env://CDB_T2_ENC"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, put_enc(ENCLAVE, 1, "s1"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, put_enc(STORE, 2, "pub")); /* a public page too */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));

    /* A whole pass in one call reports completion. */
    done = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_scrub(&db, UINT64_MAX, &done));
    TEST_ASSERT_EQUAL_INT(1, done);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    /* A second session draws a second salt; a page-at-a-time pass still
     * completes, driving the resume branch of db_scrub_in. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "scrub2", &cfg, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open_enclave(&db, ENCLAVE, "env://CDB_T2_ENC"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, put_enc(ENCLAVE, 3, "s2"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));
    done = 0;
    do
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_scrub(&db, 1, &done));
    while (!done);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ---------------------------------------------- 5. RBAC */

static void test_rbac(void)
{
    uint8_t pub[33];
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("rbac2", NULL));
    memset(pub, 0xA1, sizeof pub);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_register_principal(&db, 101, 1, pub));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_grant_role(&db, 101, 1, ENCLAVE, CDB_PERM_READ));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_check_perm(&db, 101, ENCLAVE, CDB_PERM_READ));
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_db_check_perm(&db, 101, ENCLAVE, CDB_PERM_WRITE));
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_db_check_perm(&db, 101, 99, CDB_PERM_READ));
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_db_check_perm(&db, 202, ENCLAVE, CDB_PERM_READ));

    /* An admin grant at the global scope covers every scope and permission. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_register_principal(&db, 1, 1, pub));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_grant_role(&db, 1, 1, 0, CDB_PERM_ADMIN));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_check_perm(&db, 1, ENCLAVE, CDB_PERM_WRITE));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ---------------------------------------------- 6. Triggers */

static void test_triggers(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("trig2", NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_db_trigger_register(&db, "t_ins", 5, 101, CDB_TRIGGER_AFTER_INSERT, "fn", 2, 8));
    TEST_ASSERT_EQUAL_INT(CDB_E_EXISTS,
                          cdb_db_trigger_register(&db, "t_ins", 5, 101, CDB_TRIGGER_AFTER_INSERT, "fn", 2, 8));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_trigger_unregister(&db, "t_ins", 5));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_db_trigger_unregister(&db, "t_ins", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ---------------------------------------------- 7. Streaming blobs */

static void test_blob_roundtrip(void)
{
    cdb_blob_writer w;
    cdb_blob_reader r;
    cdb_blob_ref ref;
    uint8_t got[600];
    size_t total = 0, n;
    static const char payload[] =
        "the quick brown fox jumps over the lazy dog, repeatedly, for a blob long enough "
        "to span more than a single page so the overflow chain is exercised end to end.";

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("blob2", NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_write_begin(&db, STORE, scratch, &w));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_write_chunk(&w, payload, 40));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_write_chunk(&w, payload + 40, sizeof payload - 1u - 40u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_write_end(&w, &ref));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_read_begin(&db, STORE, &ref, page, 1, &r));
    for (;;) {
        cdb_status s = cdb_db_blob_read_chunk(&r, got + total, 32, &n);
        TEST_ASSERT_EQUAL_INT(CDB_OK, s);
        if (n == 0)
            break;
        total += n;
        TEST_ASSERT_TRUE(total <= sizeof got);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_read_end(&r));
    TEST_ASSERT_EQUAL_size_t(sizeof payload - 1u, total);
    TEST_ASSERT_EQUAL_MEMORY(payload, got, total);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, STORE, &ref, page));

    /* An aborted write reclaims its pages. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_write_begin(&db, STORE, scratch, &w));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_write_chunk(&w, payload, 50));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_write_abort(&w));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ---------------------------------------------- 8. Reconcile request (solo) */

/* With nobody else holding the baton, a reconciliation request reconciles
 * at once (spec 5.9.8). */
static void test_reconcile_request_solo(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("recreq", NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_OFF));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 1, CDB_OP_INSERT, "req", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile_request(&db));
    TEST_ASSERT_EQUAL_UINT64(CDB_JOURNAL_HEADER_SIZE, db.journal.end); /* reconciled now */
    TEST_ASSERT_TRUE(page_is(1, "req"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ---------------------------------------------- 9. Entry-ID blocks (doc model) */

/* The document model allocates entry IDs from claimed coordinator blocks, so
 * inserts across several stores, then a reconcile, drive release_held_blocks
 * and raise_block_counters. */
static cdb_status doc_insert(uint64_t store, int64_t v, uint64_t *entry)
{
    uint8_t body[48];
    cdb_value_writer w;
    cdb_value_writer_init(&w, body, sizeof body, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_int(&w, v);
    cdb_value_end_object(&w);
    return cdb_doc_insert(&db, store, NULL, 0, body, cdb_value_writer_len(&w), entry);
}

static void test_id_blocks_doc_model(void)
{
    uint64_t s0, s1, s2, e, id, next;
    int dirty = 0;

    cfg.apply = NULL; /* the built-in document apply */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("ids2", NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "a", 1, CDB_MODEL_DOCUMENT, &s0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "b", 1, CDB_MODEL_DOCUMENT, &s1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "c", 1, CDB_MODEL_DOCUMENT, &s2));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, doc_insert(s0, 1, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, doc_insert(s1, 2, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, doc_insert(s2, 3, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    /* Reconcile folds the blocks back and raises catalog counters. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));

    /* Direct peek/take of an entry ID in a transaction. */
    next = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_peek_entry(&db, s0, &next, &id));
    TEST_ASSERT_EQUAL_UINT64(id, cdb_db_take_entry(&db, s0, &next, &dirty));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    /* Reopen raises each store's counter past every claimed block. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("ids2", NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ---------------------------------------------- 10. Operation scopes */

static void test_op_scopes(void)
{
    uint64_t s0, s1, found_id;
    int found;
    cfg.apply = NULL;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("ops2", NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "x", 1, CDB_MODEL_DOCUMENT, &s0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "y", 1, CDB_MODEL_DOCUMENT, &s1));

    /* A nested scope keeps both stores open across the inner lookups. */
    cdb_db_op_begin(&db);
    cdb_db_op_begin(&db);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_find_store(&db, "x", 1, &found_id, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_find_store(&db, "y", 1, &found_id, &found));
    TEST_ASSERT_TRUE(found);
    cdb_db_op_end(&db);
    cdb_db_op_end(&db);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_import_deltas_argcheck);
    RUN_TEST(test_import_deltas_apply_and_skip);
    RUN_TEST(test_import_deltas_all_skipped_aborts);
    RUN_TEST(test_import_deltas_in_caller_tx);
    RUN_TEST(test_import_deltas_too_many_origins);
    RUN_TEST(test_export_slice);
    RUN_TEST(test_import_slice_wire_errors);
    RUN_TEST(test_enclave_key_rotation);
    RUN_TEST(test_master_key_rotation);
    RUN_TEST(test_rotation_policy_and_check);
    RUN_TEST(test_scrub_pass_and_prune);
    RUN_TEST(test_rbac);
    RUN_TEST(test_triggers);
    RUN_TEST(test_blob_roundtrip);
    RUN_TEST(test_reconcile_request_solo);
    RUN_TEST(test_id_blocks_doc_model);
    RUN_TEST(test_op_scopes);
    return UNITY_END();
}
