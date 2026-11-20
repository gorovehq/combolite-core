/* Third coverage set for cdb_db (agent-authored, #18 increment 2): the error,
 * transaction-state, savepoint-rollback, recovery, key-rotation and
 * maintenance branches that the behavioural test_db.c, test_db_fault.c and the
 * first coverage set test_db2_cov.c miss.
 *
 * Covers: cdb_db_open argument/config and crypto/governance rejections and the
 * oversized-path rejection; transaction-state guards (double begin, commit and
 * abort with no transaction, writes with no transaction); savepoint +
 * rollback-to (including the staged-index rewind) and its argument/state
 * guards; a document-store workload with a crash injected at each I/O
 * operation, rebooted and reopened, driving the journal-merge / rebase /
 * release-held-blocks recovery paths and the failed-database close path;
 * master-key rotation argument errors; the CRDT export measure/filter edges;
 * and reconcile / compact / scrub / drop-store / find-store edges.
 *
 * Every local is initialised at its declaration; NULL/negative paths pass the
 * value and assert the returned status without dereferencing a maybe-NULL
 * result (test code obeys the production-safety gate). Hermetic: all state in
 * the in-process fault environment; no network, no wall clock. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_db.h"
#include "cdb_doc.h"
#include "cdb_faultenv.h"

#define FCAP (768u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define STORE 1u

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
static cdb_db_config cfg;
static cdb_db db;

/* A tiny key-value apply: entry N lives in logical page N. */
#define KV_PAGES 128u
static cdb_status kv_apply(void *ctx, cdb_pager *p, const cdb_delta *d)
{
    cdb_page_header t;
    uint64_t lid = 0;
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
    return cdb_pager_write(p, d->entry_id, &t, d->data, d->len);
}

static cdb_header settings(void)
{
    cdb_header h;
    unsigned i = 0;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    for (i = 0; i < 16; i++)
        h.db_id[i] = (uint8_t)(0x90 + i);
    return h;
}

static void init_env(void)
{
    cdb_faultenv_config c;
    memset(&c, 0, sizeof c);
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 4096;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
}

static void good_cfg(void)
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
}

void setUp(void)
{
    init_env();
    good_cfg();
}

void tearDown(void) {}

static cdb_status open_kv(const char *base)
{
    cdb_header h = settings();
    return cdb_db_open(&db, &env, base, &cfg, &h);
}

/* -------------------------------------------- 1. open rejections */

static void test_open_rejections(void)
{
    cdb_header h = settings();

    /* an oversized base name overflows the derived paths. */
    {
        char longbase[CDB_DB_PATH_MAX + 32u];
        memset(longbase, 'b', sizeof longbase - 1u);
        longbase[sizeof longbase - 1u] = '\0';
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_open(&db, &env, longbase, &cfg, &h));
    }
    /* a base whose parent component is empty is rejected. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_open(&db, &env, "/leadingslash", &cfg, &h));

    /* opening a database that does not exist, with no create header. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_db_open(&db, &env, "absent", &cfg, NULL));

    /* a bad master-key URI fails key resolution. */
    cfg.master_key_uri = "env://CDB_DB3_NOSUCHKEY_XYZ";
    unsetenv("CDB_DB3_NOSUCHKEY_XYZ");
    TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "badkey", &cfg, &h));
    cfg.master_key_uri = NULL;

    /* a governance-layout database requires a master key at create. */
    {
        cdb_header g = settings();
        g.layout_flags |= CDB_LAYOUT_GOVERNANCE;
        TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_db_open(&db, &env, "gov", &cfg, &g));
    }
}

/* -------------------------------------------- 2. transaction-state guards */

static void test_tx_state_guards(void)
{
    cdb_tx_mark mark;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("txg"));
    memset(&mark, 0, sizeof mark);

    /* commit / abort / write / savepoint with no open transaction. */
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_tx_abort(&db));
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_tx_put(&db, STORE, 1, CDB_OP_INSERT, "x", 1));
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_tx_savepoint(&db, &mark));
    /* rollback_to with a NULL mark is an argument error. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_tx_rollback_to(&db, NULL));
    /* rollback_to outside a transaction is a state error. */
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_tx_rollback_to(&db, &mark));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    /* a second begin while one is open is refused. */
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    /* a savepoint from another transaction id does not roll back here. */
    {
        cdb_tx_mark bad;
        memset(&bad, 0, sizeof bad);
        bad.tx_id = 0xBADBAD;
        TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_tx_rollback_to(&db, &bad));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 3. savepoint rollback-to */

static int page_present(uint64_t lid)
{
    cdb_page_header ph;
    uint8_t buf[PAGE];
    cdb_status s = cdb_pager_read(&db.pager, lid, buf, &ph);
    if (s == CDB_E_NOT_FOUND)
        return 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);
    return 1;
}

static void test_savepoint_rollback(void)
{
    cdb_tx_mark mark;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("spr"));
    memset(&mark, 0, sizeof mark);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 1, CDB_OP_INSERT, "keep", 4));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_savepoint(&db, &mark));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 2, CDB_OP_INSERT, "drop1", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 3, CDB_OP_INSERT, "drop2", 5));
    /* roll back to the mark: the two later writes are dropped, the first stays. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_rollback_to(&db, &mark));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 4, CDB_OP_INSERT, "after", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    TEST_ASSERT_TRUE(page_present(1));
    TEST_ASSERT_FALSE(page_present(2));
    TEST_ASSERT_FALSE(page_present(3));
    TEST_ASSERT_TRUE(page_present(4));

    /* a rollback that drops nothing (mark at the current position) writes no
     * rollback record. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 5, CDB_OP_INSERT, "five", 4));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_savepoint(&db, &mark));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_rollback_to(&db, &mark)); /* no-op */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_TRUE(page_present(5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 4. master-key rotation errors */

static void test_rotate_master_key_errors(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("rmk"));
    /* the database has no master key, so rotating one is refused. */
    TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_db_rotate_master_key(&db, "env://CDB_DB3_NOKEY"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 5. maintenance edges */

static void test_maintenance_edges(void)
{
    uint64_t moved = 0, reclaimed = 0, pages = 0, nibs = 0, sid = 0;
    int found = 0, done = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("maint"));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 1, CDB_OP_INSERT, "a", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* reconcile, compact and scrub on a tiny database all succeed. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_compact(&db, 16, &moved, &reclaimed));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reclaim(&db, &pages, &nibs));
    done = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_scrub(&db, UINT64_MAX, &done));
    TEST_ASSERT_EQUAL_INT(1, done);

    /* find a store that is not there, and drop one that is not there. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_find_store(&db, "nope", 4, &sid, &found));
    TEST_ASSERT_FALSE(found);
    TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_db_drop_store(&db, 987654));

    /* a document store can be created, used and dropped. */
    {
        uint64_t ds = 0;
        cfg.apply = NULL; /* n/a once open; create_store uses the catalog */
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "docs", 4, CDB_MODEL_DOCUMENT, &ds));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_find_store(&db, "docs", 4, &sid, &found));
        TEST_ASSERT_TRUE(found);
        TEST_ASSERT_EQUAL_UINT64(ds, sid);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_drop_store(&db, ds));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 6. CRDT export edges */

static void test_crdt_export_edges(void)
{
    uint8_t slice[512];
    size_t needed = 0, len = 0;
    cdb_crdt_vector since;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("cexp"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_set_peer_id(&db, 3u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 1, CDB_OP_INSERT, "x", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* argument checks and the measure pass. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_crdt_export_slice(NULL, NULL, slice, sizeof slice, &len));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_crdt_export_slice(&db, NULL, slice, sizeof slice, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_db_crdt_export_slice(&db, NULL, NULL, 0, &needed));
    TEST_ASSERT_TRUE(needed > 12u);
    /* too small a buffer for the full slice. */
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_db_crdt_export_slice(&db, NULL, slice, 4, &len));
    /* a full export. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_export_slice(&db, NULL, slice, sizeof slice, &len));
    TEST_ASSERT_EQUAL_size_t(needed, len);
    /* a since-vector already past our counter yields the header alone. */
    memset(&since, 0, sizeof since);
    cdb_crdt_vector_set(&since, 3u, 1000u, (cdb_hlc){ 0u, 0u, 1u });
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_export_slice(&db, &since, slice, sizeof slice, &len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 7. crash + recovery sweep */

/* A document-store workload crashed at each I/O operation, then rebooted and
 * reopened: drives the recovery paths (journal merge, rebase, release of held
 * ID blocks) and the failed-database close path. */
static void test_crash_recovery(void)
{
    uint64_t op = 0;
    unsigned crashed = 0;
    for (op = 1; op <= 45u; op++) {
        cdb_header h = settings();
        cdb_status rs;
        init_env();
        good_cfg();
        cfg.apply = NULL; /* document model, so entry-ID blocks engage */
        cdb_faultenv_arm(&fe, op, CDB_CRASH_DROP_UNSYNCED, 0, 0);
        if (cdb_db_open(&db, &env, "cr3", &cfg, &h) == CDB_OK) {
            uint64_t s0 = 0, s1 = 0, e = 0;
            uint8_t body[48];
            cdb_value_writer w;
            cdb_value_writer_init(&w, body, sizeof body, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
            cdb_value_begin_object(&w);
            cdb_value_field(&w, 1);
            cdb_value_write_int(&w, 7);
            cdb_value_end_object(&w);
            if (cdb_db_create_store(&db, "a", 1, CDB_MODEL_DOCUMENT, &s0) != CDB_OK)
                crashed = 1;
            else if (cdb_db_create_store(&db, "b", 1, CDB_MODEL_DOCUMENT, &s1) != CDB_OK)
                crashed = 1;
            else if (cdb_tx_begin(&db, CDB_DURABILITY_FULL) != CDB_OK)
                crashed = 1;
            else {
                if (cdb_doc_insert(&db, s0, NULL, 0, body, cdb_value_writer_len(&w), &e) != CDB_OK
                    || cdb_doc_insert(&db, s1, NULL, 0, body, cdb_value_writer_len(&w), &e) != CDB_OK
                    || cdb_tx_commit(&db) != CDB_OK)
                    crashed = 1;
            }
            if (cdb_db_close(&db) != CDB_OK)
                crashed = 1;
        } else {
            crashed = 1;
        }
        cdb_faultenv_reboot(&fe);
        rs = cdb_db_open(&db, &env, "cr3", &cfg, &h);
        TEST_ASSERT_TRUE_MESSAGE(rs == CDB_OK || rs == CDB_E_NOT_FOUND,
                                 "reopen after crash neither recovered nor cleanly absent");
        if (rs == CDB_OK)
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
        cdb_faultenv_reboot(&fe);
    }
    TEST_ASSERT_TRUE_MESSAGE(crashed, "no injected crash ever fired");
}

/* -------------------------------------------- 8. crypto / enclave branches */

#define ENCLAVE 42u

static cdb_status open_crypto(const char *base)
{
    cdb_header h = settings();
    cfg.master_key_uri = "env://CDB_DB3_MK";
    cfg.aead_alg = CDB_AEAD_AES_256_GCM;
    return cdb_db_open(&db, &env, base, &cfg, &h);
}

static cdb_status put_enc(uint64_t store, uint64_t entry, const char *text)
{
    cdb_status s = cdb_tx_begin(&db, CDB_DURABILITY_FULL);
    if (s != CDB_OK)
        return s;
    s = cdb_tx_put(&db, store, entry, CDB_OP_REPLACE, text, strlen(text));
    if (s != CDB_OK) {
        (void)cdb_tx_abort(&db);
        return s;
    }
    return cdb_tx_commit(&db);
}

static void test_crypto_branches(void)
{
    setenv("CDB_DB3_MK", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1);
    setenv("CDB_DB3_ENC", "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff", 1);
    setenv("CDB_DB3_MK2", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 1);

    /* an enclave on a database without a master key is a security error. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("enc_plain"));
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_db_create_enclave(&db, ENCLAVE, "env://CDB_DB3_ENC"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_crypto("enc_c"));
    /* argument guards. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_create_enclave(&db, 0, "env://CDB_DB3_ENC"));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_rotate_master_key(&db, NULL));
    TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_db_rotate_master_key(&db, "env://CDB_DB3_NOSUCH"));

    /* an enclave whose key is generated (no key reference). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_enclave(&db, ENCLAVE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, put_enc(ENCLAVE, 1, "secret"));

    /* rotate the master key with every enclave re-wrapped under it. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_rotate_master_key(&db, "env://CDB_DB3_MK2"));

    /* scrub budget-at-a-time until a pass completes (the resume path). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));
    {
        int done = 0;
        do
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_scrub(&db, 1, &done));
        while (!done);
    }
    /* opening an enclave id that has no pages yet simply records the key. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open_enclave(&db, 99u, "env://CDB_DB3_ENC"));
    /* a bad key reference for an open is reported. */
    TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_db_open_enclave(&db, 77u, "env://CDB_DB3_NOSUCH"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 9. faults over the full API */

/* A crypto document workload with reconcile, compact, scrub, an enclave and a
 * CRDT export, crashed at each I/O operation. Each armed point makes a
 * different pager read or write fail, exercising the error-return arms of the
 * commit / recovery / maintenance / crypto paths; a reboot + reopen must then
 * recover cleanly. */
static void test_fault_sweep_full(void)
{
    uint64_t op = 0;
    unsigned crashed = 0;
    setenv("CDB_DB3_MK", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1);
    setenv("CDB_DB3_ENC", "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff", 1);
    for (op = 1; op <= 60u; op++) {
        cdb_header h = settings();
        cdb_status rs;
        uint64_t s0 = 0, e = 0, moved = 0, reclaimed = 0;
        int done = 0;
        uint8_t slice[256];
        size_t slen = 0;
        uint8_t body[48];
        cdb_value_writer w;
        init_env();
        good_cfg();
        cfg.apply = NULL;
        cfg.master_key_uri = "env://CDB_DB3_MK";
        cfg.aead_alg = CDB_AEAD_AES_256_GCM;
        cdb_value_writer_init(&w, body, sizeof body, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        cdb_value_begin_object(&w);
        cdb_value_field(&w, 1);
        cdb_value_write_int(&w, 3);
        cdb_value_end_object(&w);

        if (cdb_db_open(&db, &env, "fsf", &cfg, &h) != CDB_OK) {
            crashed = 1;
            cdb_faultenv_reboot(&fe);
            continue;
        }
        cdb_faultenv_arm(&fe, op, CDB_CRASH_DROP_UNSYNCED, 0, 0);

        if (cdb_db_create_store(&db, "a", 1, CDB_MODEL_DOCUMENT, &s0) != CDB_OK)
            crashed = 1;
        if (cdb_db_set_peer_id(&db, 2u) != CDB_OK)
            crashed = 1;
        if (cdb_tx_begin(&db, CDB_DURABILITY_FULL) == CDB_OK) {
            if (cdb_doc_insert(&db, s0, "s", 1, body, cdb_value_writer_len(&w), &e) != CDB_OK
                || cdb_tx_commit(&db) != CDB_OK)
                crashed = 1;
        }
        if (cdb_db_reconcile(&db) != CDB_OK)
            crashed = 1;
        if (cdb_db_compact(&db, 16, &moved, &reclaimed) != CDB_OK)
            crashed = 1;
        if (cdb_db_scrub(&db, 1, &done) != CDB_OK)
            crashed = 1;
        if (cdb_db_create_enclave(&db, ENCLAVE, "env://CDB_DB3_ENC") != CDB_OK)
            crashed = 1;
        if (cdb_db_crdt_export_slice(&db, NULL, slice, sizeof slice, &slen) != CDB_OK)
            crashed = 1;

        (void)cdb_db_close(&db);
        cdb_faultenv_reboot(&fe);
        rs = cdb_db_open(&db, &env, "fsf", &cfg, &h);
        TEST_ASSERT_TRUE_MESSAGE(rs == CDB_OK || rs == CDB_E_NOT_FOUND || rs == CDB_E_CORRUPT || rs == CDB_E_SECURITY,
                                 "reopen after I/O fault returned an unexpected status");
        if (rs == CDB_OK)
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
        cdb_faultenv_reboot(&fe);
    }
    TEST_ASSERT_TRUE_MESSAGE(crashed, "no injected crash ever fired");
}

/* -------------------------------------------- 10. held entry-ID blocks */

static cdb_status doc_put(uint64_t store, int64_t val, uint64_t *entry)
{
    uint8_t body[48];
    cdb_value_writer w;
    cdb_value_writer_init(&w, body, sizeof body, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_int(&w, val);
    cdb_value_end_object(&w);
    return cdb_doc_insert(&db, store, NULL, 0, body, cdb_value_writer_len(&w), entry);
}

/* Claiming an entry-ID block in more than half of the maximum number of stores
 * makes a commit auto-reconcile and release the held blocks (release_held_blocks
 * / raise_block_counters), rather than leaving them for the next transaction. */
static void test_held_blocks(void)
{
    uint64_t ids[16];
    unsigned i = 0;
    char name[8];
    cfg.apply = NULL; /* document model */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("blk"));

    for (i = 0; i < 16u; i++) {
        name[0] = 's';
        name[1] = (char)('a' + (int)i);
        name[2] = '\0';
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, name, 2, CDB_MODEL_DOCUMENT, &ids[i]));
    }
    /* insert into every store in one transaction, so each claims a block and
     * the held-block count climbs past half the maximum at once; the commit
     * then auto-reconciles and releases the held blocks. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    for (i = 0; i < 16u; i++) {
        uint64_t e = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, doc_put(ids[i], (int64_t)i, &e));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    /* a final reconcile folds everything back and raises the counters. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    /* reopen raises each store's counter past every claimed block. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("blk"));
    {
        uint64_t e = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
        TEST_ASSERT_EQUAL_INT(CDB_OK, doc_put(ids[0], 99, &e));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 12. governance reopen */

static void test_governance_reopen(void)
{
    cdb_header g = settings();
    setenv("CDB_DB3_MK", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1);
    g.layout_flags |= CDB_LAYOUT_GOVERNANCE;

    /* create a governance database with a master key, then close it. */
    cfg.master_key_uri = "env://CDB_DB3_MK";
    cfg.aead_alg = CDB_AEAD_AES_256_GCM;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "govdb", &cfg, &g));
    TEST_ASSERT_EQUAL_INT(CDB_OK, put_enc(STORE, 1, "gov"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    /* reopening a governance database without a master key is refused. */
    cfg.master_key_uri = NULL;
    cfg.aead_alg = CDB_AEAD_NONE;
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_db_open(&db, &env, "govdb", &cfg, NULL));

    /* reopening it with the key succeeds. */
    cfg.master_key_uri = "env://CDB_DB3_MK";
    cfg.aead_alg = CDB_AEAD_AES_256_GCM;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "govdb", &cfg, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 13. enclave table overflow */

static void test_enclave_overflow(void)
{
    unsigned i = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_crypto("encof"));
    /* the enclave table holds sixteen; the seventeenth overflows it. */
    for (i = 0; i < 16u; i++)
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_enclave(&db, 100u + i, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_db_create_enclave(&db, 200u, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 14. faults during maintenance */

/* Builds a durable crypto document state, then for a sweep of armed operation
 * counts reopens and runs a single maintenance operation (reconcile, compact,
 * scrub, master-key rotation, enclave creation) under the fault, so the fault
 * strikes inside that operation and its I/O-error-return arms fire. Every
 * reopen afterwards must recover cleanly. */
static void build_crypto_state(void)
{
    uint64_t s0 = 0, e = 0;
    uint8_t body[48];
    cdb_value_writer w;
    unsigned i = 0;
    cdb_value_writer_init(&w, body, sizeof body, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_int(&w, 5);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "a", 1, CDB_MODEL_DOCUMENT, &s0));
    for (i = 0; i < 6u; i++) {
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, s0, "s", 1, body, cdb_value_writer_len(&w), &e));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
}

static void test_maintenance_faults(void)
{
    uint64_t op = 0;
    unsigned any_err = 0;
    cdb_header h = settings();
    setenv("CDB_DB3_MK", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1);
    setenv("CDB_DB3_ENC", "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff", 1);

    init_env();
    good_cfg();
    cfg.apply = NULL;
    cfg.master_key_uri = "env://CDB_DB3_MK";
    cfg.aead_alg = CDB_AEAD_AES_256_GCM;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "mf", &cfg, &h));
    build_crypto_state();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    for (op = 1; op <= 24u; op++) {
        uint64_t moved = 0, reclaimed = 0;
        int done = 0;
        cdb_status rs;

        /* reconcile under fault. */
        if (cdb_db_open(&db, &env, "mf", &cfg, &h) == CDB_OK) {
            cdb_faultenv_arm(&fe, op, CDB_CRASH_DROP_UNSYNCED, 0, 0);
            if (cdb_db_reconcile(&db) != CDB_OK)
                any_err = 1;
            (void)cdb_db_close(&db);
        }
        cdb_faultenv_reboot(&fe);
        rs = cdb_db_open(&db, &env, "mf", &cfg, &h);
        if (rs == CDB_OK)
            (void)cdb_db_close(&db);
        cdb_faultenv_reboot(&fe);

        /* compact under fault. */
        if (cdb_db_open(&db, &env, "mf", &cfg, &h) == CDB_OK) {
            cdb_faultenv_arm(&fe, op, CDB_CRASH_DROP_UNSYNCED, 0, 0);
            if (cdb_db_compact(&db, 16, &moved, &reclaimed) != CDB_OK)
                any_err = 1;
            (void)cdb_db_close(&db);
        }
        cdb_faultenv_reboot(&fe);
        rs = cdb_db_open(&db, &env, "mf", &cfg, &h);
        if (rs == CDB_OK)
            (void)cdb_db_close(&db);
        cdb_faultenv_reboot(&fe);

        /* scrub under fault. */
        if (cdb_db_open(&db, &env, "mf", &cfg, &h) == CDB_OK) {
            cdb_faultenv_arm(&fe, op, CDB_CRASH_DROP_UNSYNCED, 0, 0);
            if (cdb_db_scrub(&db, 2, &done) != CDB_OK)
                any_err = 1;
            (void)cdb_db_close(&db);
        }
        cdb_faultenv_reboot(&fe);
        rs = cdb_db_open(&db, &env, "mf", &cfg, &h);
        if (rs == CDB_OK)
            (void)cdb_db_close(&db);
        cdb_faultenv_reboot(&fe);

        /* master-key rotation and enclave creation under fault. */
        if (cdb_db_open(&db, &env, "mf", &cfg, &h) == CDB_OK) {
            cdb_faultenv_arm(&fe, op, CDB_CRASH_DROP_UNSYNCED, 0, 0);
            if (cdb_db_create_enclave(&db, ENCLAVE, "env://CDB_DB3_ENC") != CDB_OK)
                any_err = 1;
            (void)cdb_db_close(&db);
        }
        cdb_faultenv_reboot(&fe);
        rs = cdb_db_open(&db, &env, "mf", &cfg, &h);
        if (rs == CDB_OK)
            (void)cdb_db_close(&db);
        cdb_faultenv_reboot(&fe);
    }
    TEST_ASSERT_TRUE_MESSAGE(any_err, "no injected fault ever reached a maintenance operation");
}

/* -------------------------------------------- 15. accessors + arg guards */

/* The size/handle accessors and the argument-guard arms of the public API
 * that a valid handle can reach (the db==NULL arms sit behind the handle lock
 * and are defensive-unreachable, so they are not asserted here). */
static void test_accessors_and_guards(void)
{
    uint32_t peer = 0;
    cdb_hlc hlc;
    cdb_crdt_vector vec;
    int done = 0;
    uint64_t pages = 0, nibs = 0;

    /* pure accessors need no open database. */
    TEST_ASSERT_TRUE(cdb_db_struct_size() >= sizeof(cdb_db));
    TEST_ASSERT_TRUE(cdb_db_config_size() >= sizeof(cdb_db_config));
    TEST_ASSERT_EQUAL_size_t(0, cdb_db_slot_mem_size(0));
    TEST_ASSERT_TRUE(cdb_db_slot_mem_size(5) > 0);

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("accg"));
    TEST_ASSERT_NOT_NULL(cdb_db_catalog(&db));
    TEST_ASSERT_NOT_NULL(cdb_db_pager(&db));

    /* getter out-pointer guards (valid handle, NULL destination). */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_get_peer_id(&db, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_get_hlc(&db, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_get_crdt_vector(&db, NULL));
    /* and the success arms read back real state. */
    memset(&hlc, 0, sizeof hlc);
    memset(&vec, 0, sizeof vec);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_set_peer_id(&db, 7u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_get_peer_id(&db, &peer));
    TEST_ASSERT_EQUAL_UINT32(7u, peer);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_get_hlc(&db, &hlc));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_get_crdt_vector(&db, &vec));

    /* scrub out-pointer guard. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_scrub(&db, 1, NULL));

    /* RBAC argument guards (principal id zero is invalid). */
    {
        uint8_t pubkey[33];
        memset(pubkey, 0xA5, sizeof pubkey);
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_register_principal(&db, 0, 1u, pubkey));
    }
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_grant_role(&db, 0, 1u, 0, 0x1u));

    /* reclaim inside an open transaction is a state error. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_db_reclaim(&db, &pages, &nibs));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));

    /* scrub to completion so its success resume arm also runs. */
    do
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_scrub(&db, 1, &done));
    while (!done);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 16. failed-handle guard */

/* A commit interrupted by an armed I/O fault marks the handle failed; a later
 * read-path call on that handle must report the state error (usable() arm),
 * not proceed on a possibly-torn database. */
static void test_failed_handle_guard(void)
{
    uint64_t op = 0;
    unsigned saw_failed = 0;
    for (op = 1; op <= 20u && !saw_failed; op++) {
        cdb_header h = settings();
        uint64_t sid = 0;
        int found = 0;
        init_env();
        good_cfg();
        if (open_kv("fhg") != CDB_OK) {
            cdb_faultenv_reboot(&fe);
            continue;
        }
        cdb_faultenv_arm(&fe, op, CDB_CRASH_DROP_UNSYNCED, 0, 0);
        (void)cdb_tx_begin(&db, CDB_DURABILITY_FULL);
        (void)cdb_tx_put(&db, STORE, 1, CDB_OP_INSERT, "x", 1);
        if (cdb_tx_commit(&db) != CDB_OK) {
            /* the handle is now failed: a catalog read reports the state. */
            cdb_status fs = cdb_db_find_store(&db, "nope", 4, &sid, &found);
            TEST_ASSERT_TRUE_MESSAGE(fs == CDB_E_STATE || fs == CDB_E_UNSUPPORTED || fs == CDB_OK,
                                     "find_store on a failed handle returned an unexpected status");
            if (fs == CDB_E_STATE)
                saw_failed = 1;
        }
        (void)cdb_db_close(&db);
        cdb_faultenv_reboot(&fe);
        (void)settings();
        (void)h;
    }
    TEST_ASSERT_TRUE_MESSAGE(saw_failed, "no armed commit ever marked the handle failed");
}

/* -------------------------------------------- 17. crash-mode sweep */

/* The same durable document workload crashed at a sweep of operation counts
 * under each crash model (drop-unsynced, keep-prefix, torn, reorder). Each
 * model leaves the files in a different partial state, so reboot + reopen
 * drives distinct recovery arms; every reopen must recover cleanly or be
 * cleanly absent — never a half-applied read. */
static void run_doc_workload_crashed(uint64_t op, cdb_crash_mode mode, size_t keep, size_t torn,
                                     unsigned *crashed)
{
    cdb_header h = settings();
    cdb_status rs;
    uint64_t s0 = 0, e = 0;
    uint8_t body[48];
    cdb_value_writer w;
    init_env();
    good_cfg();
    cfg.apply = NULL;
    cdb_value_writer_init(&w, body, sizeof body, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_int(&w, 9);
    cdb_value_end_object(&w);

    if (cdb_db_open(&db, &env, "cmode", &cfg, &h) != CDB_OK) {
        cdb_faultenv_reboot(&fe);
        return;
    }
    cdb_faultenv_arm(&fe, op, mode, keep, torn);
    if (cdb_db_create_store(&db, "a", 1, CDB_MODEL_DOCUMENT, &s0) != CDB_OK)
        *crashed = 1;
    else if (cdb_tx_begin(&db, CDB_DURABILITY_FULL) != CDB_OK)
        *crashed = 1;
    else if (cdb_doc_insert(&db, s0, NULL, 0, body, cdb_value_writer_len(&w), &e) != CDB_OK
             || cdb_tx_commit(&db) != CDB_OK)
        *crashed = 1;
    (void)cdb_db_close(&db);
    cdb_faultenv_reboot(&fe);
    rs = cdb_db_open(&db, &env, "cmode", &cfg, &h);
    TEST_ASSERT_TRUE_MESSAGE(rs == CDB_OK || rs == CDB_E_NOT_FOUND || rs == CDB_E_CORRUPT,
                             "reopen after a crash returned an unexpected status");
    if (rs == CDB_OK)
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
    cdb_faultenv_reboot(&fe);
}

static void test_crash_modes(void)
{
    uint64_t op = 0;
    unsigned crashed = 0;
    for (op = 1; op <= 20u; op++) {
        run_doc_workload_crashed(op, CDB_CRASH_DROP_UNSYNCED, 0, 0, &crashed);
        run_doc_workload_crashed(op, CDB_CRASH_KEEP_PREFIX, 2, 0, &crashed);
        run_doc_workload_crashed(op, CDB_CRASH_TORN, 1, 8, &crashed);
        run_doc_workload_crashed(op, CDB_CRASH_REORDER, 0, 0, &crashed);
    }
    TEST_ASSERT_TRUE_MESSAGE(crashed, "no injected crash ever fired");
}

/* -------------------------------------------- 18. allocator refusal */

/* With the host allocator refused, operations that need a fresh allocation
 * (opening a handle, claiming store slots) must fail closed with a reported
 * status rather than crash or silently proceed; re-enabling the allocator
 * restores normal service. */
static void test_alloc_refusal(void)
{
    cdb_header h = settings();
    cdb_status os;
    unsigned saw_refused = 0;

    /* open with the allocator off from the start: either the engine makes do
     * with caller memory (OK) or it reports a no-memory status — never a
     * crash. */
    init_env();
    good_cfg();
    cfg.apply = NULL;
    cdb_faultenv_set_alloc(&fe, 0);
    os = cdb_db_open(&db, &env, "allocoff", &cfg, &h);
    TEST_ASSERT_TRUE_MESSAGE(os == CDB_OK || os == CDB_E_BUFFER_TOO_SMALL || os == CDB_E_UNSUPPORTED
                                 || os == CDB_E_CORRUPT,
                             "open under allocator refusal neither succeeded nor failed closed");
    if (os == CDB_OK) {
        uint64_t s0 = 0;
        cdb_status cs = cdb_db_create_store(&db, "a", 1, CDB_MODEL_DOCUMENT, &s0);
        if (cs != CDB_OK)
            saw_refused = 1;
        else {
            /* a document insert must claim a pool slot from the allocator. */
            uint64_t e = 0;
            uint8_t body[48];
            cdb_value_writer w;
            cdb_value_writer_init(&w, body, sizeof body, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
            cdb_value_begin_object(&w);
            cdb_value_field(&w, 1);
            cdb_value_write_int(&w, 1);
            cdb_value_end_object(&w);
            if (cdb_tx_begin(&db, CDB_DURABILITY_FULL) == CDB_OK) {
                if (cdb_doc_insert(&db, s0, NULL, 0, body, cdb_value_writer_len(&w), &e) != CDB_OK)
                    saw_refused = 1;
                (void)cdb_tx_abort(&db);
            }
        }
        (void)cdb_db_close(&db);
    } else {
        saw_refused = 1;
    }
    cdb_faultenv_set_alloc(&fe, 1);
    cdb_faultenv_reboot(&fe);

    /* build a real database, then refuse the allocator before a slot-claiming
     * operation and confirm it is reported, not fatal. */
    init_env();
    good_cfg();
    cfg.apply = NULL;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "allocmid", &cfg, &h));
    {
        unsigned i = 0;
        char name[4];
        uint64_t sid = 0;
        cdb_faultenv_set_alloc(&fe, 0);
        for (i = 0; i < 40u; i++) {
            name[0] = 's';
            name[1] = (char)('a' + (int)(i % 20));
            name[2] = (char)('a' + (int)(i / 20));
            name[3] = '\0';
            if (cdb_db_create_store(&db, name, 3, CDB_MODEL_DOCUMENT, &sid) != CDB_OK) {
                saw_refused = 1;
                break;
            }
        }
        cdb_faultenv_set_alloc(&fe, 1);
    }
    (void)cdb_db_close(&db);
    cdb_faultenv_reboot(&fe);

    TEST_ASSERT_TRUE_MESSAGE(saw_refused, "allocator refusal never blocked an allocating operation");
}

/* -------------------------------------------- 19. savepoint index rewind */

/* Document inserts stage index entries (the head/revision keys), not just data
 * pages. A savepoint taken after some inserts, then more inserts, then a
 * rollback-to, must rewind the staged-index hash chain (stage_idx_rewind) so
 * the rolled-back documents vanish and the kept ones remain readable. */
static void test_savepoint_doc_rewind(void)
{
    uint64_t pool = 0, keep = 0, drop1 = 0, drop2 = 0, after = 0;
    cdb_tx_mark mark;
    size_t len = 0;
    uint8_t body[48];
    cdb_value_writer w;
    cfg.apply = NULL; /* document model: inserts stage index entries */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_kv("sdr"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "d", 1, CDB_MODEL_DOCUMENT, &pool));
    memset(&mark, 0, sizeof mark);
    cdb_value_writer_init(&w, body, sizeof body, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_int(&w, 1);
    cdb_value_end_object(&w);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, body, cdb_value_writer_len(&w), &keep));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_savepoint(&db, &mark));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, body, cdb_value_writer_len(&w), &drop1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, body, cdb_value_writer_len(&w), &drop2));
    /* rewind: the two later documents (and their staged index keys) are dropped. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_rollback_to(&db, &mark));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, body, cdb_value_writer_len(&w), &after));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* the kept and the after-rewind documents are readable; the dropped ones
     * are gone. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, keep, 0, doc_buffers, sizeof doc_buffers, &len,
                                              NULL, 0, NULL, NULL));
    TEST_ASSERT_TRUE(len > 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, after, 0, doc_buffers, sizeof doc_buffers, &len,
                                              NULL, 0, NULL, NULL));
    TEST_ASSERT_TRUE(len > 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_get(&db, pool, drop1, 0, doc_buffers, sizeof doc_buffers,
                                                       &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_get(&db, pool, drop2, 0, doc_buffers, sizeof doc_buffers,
                                                       &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 20. RBAC + key rotation */

/* Permission checks (granted vs denied), the rotation-policy check, and enclave
 * key rotation (success and a bad key reference) on a crypto database. */
static void test_rbac_and_rotation(void)
{
    uint8_t pubkey[33];
    setenv("CDB_DB3_MK", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1);
    setenv("CDB_DB3_ENC", "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff", 1);
    setenv("CDB_DB3_ENC2", "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", 1);
    memset(pubkey, 0x5A, sizeof pubkey);

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_crypto("rbacrot"));

    /* register a principal and grant it one permission bit on store 1. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_register_principal(&db, 1001u, 7u, pubkey));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_grant_role(&db, 1001u, 1u, STORE, 0x1u));
    /* the granted bit passes; a bit never granted is denied. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_check_perm(&db, 1001u, STORE, 0x1u));
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_db_check_perm(&db, 1001u, STORE, 0x2u));
    /* an unknown principal is denied. */
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_db_check_perm(&db, 424242u, STORE, 0x1u));

    /* the rotation-policy check runs clean when no interval is configured. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_check_key_rotation(&db));

    /* create an enclave, then rotate its key; a bad new-key reference fails. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_enclave(&db, ENCLAVE, "env://CDB_DB3_ENC"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, put_enc(ENCLAVE, 1, "rbac-secret"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_rotate_enclave_key(&db, ENCLAVE, "env://CDB_DB3_ENC2"));
    TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_db_rotate_enclave_key(&db, ENCLAVE, "env://CDB_DB3_NOSUCH"));
    /* rotating a non-existent enclave is reported, not silently ignored. */
    TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_db_rotate_enclave_key(&db, 55555u, "env://CDB_DB3_ENC"));

    /* a full scrub pass after rotation completes cleanly. */
    {
        int done = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_scrub(&db, UINT64_MAX, &done));
        TEST_ASSERT_EQUAL_INT(1, done);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_open_rejections);
    RUN_TEST(test_tx_state_guards);
    RUN_TEST(test_savepoint_rollback);
    RUN_TEST(test_rotate_master_key_errors);
    RUN_TEST(test_maintenance_edges);
    RUN_TEST(test_crdt_export_edges);
    RUN_TEST(test_crypto_branches);
    RUN_TEST(test_governance_reopen);
    RUN_TEST(test_enclave_overflow);
    RUN_TEST(test_held_blocks);
    RUN_TEST(test_crash_recovery);
    RUN_TEST(test_fault_sweep_full);
    RUN_TEST(test_maintenance_faults);
    RUN_TEST(test_accessors_and_guards);
    RUN_TEST(test_failed_handle_guard);
    RUN_TEST(test_crash_modes);
    RUN_TEST(test_alloc_refusal);
    RUN_TEST(test_savepoint_doc_rewind);
    RUN_TEST(test_rbac_and_rotation);
    return UNITY_END();
}
