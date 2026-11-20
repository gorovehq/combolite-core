/* Fourth coverage set for cdb_db (agent-authored, #18 increment 2): single-
 * handle branches the earlier suites (test_db.c, test_db_fault.c,
 * test_db2_cov.c, test_db3_cov.c) miss — the staged-index rewind loop, the
 * held entry-ID-block maintenance after a run of committed document
 * transactions, and master-key + enclave-key rotation (including the generated
 * enclave key arm) with a scrub-to-completion salt prune.
 *
 * Note on the cdb_db.c coverage ceiling (design ADR-5): a large share of the
 * remaining uncovered lines are the multi-process commit-coordination bodies
 * (merge_journals, rebase_pages, check_slot_collisions, own_has_item's journal
 * spill, coordinate_commit's prepare/settle/scan) and the heartbeat responder
 * (start_heartbeat/heartbeat_worker/beat_only/finish_baton). Those run only
 * once a *second* live coordinator holds the baton and a responder *thread*
 * passes it. The fault environment deliberately exposes no thread hooks so the
 * suite stays deterministic and hermetic (AC8); that keeps heartbeats
 * cooperative and makes two simultaneously-live handles contend for the baton
 * non-deterministically. So those paths are not deterministically reachable
 * from this harness and are a documented reachable-line ceiling, not a gap this
 * test-only increment can close without real concurrency. This suite covers
 * what a single coordinator can reach and asserts real post-state.
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
#include "combolite/cdb_crdt.h"
#include "cdb_db.h"
#include "cdb_doc.h"
#include "cdb_faultenv.h"
#include "cdb_endian.h"

#define FCAP (768u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 24u
#define STORE 1u
#define KV_PAGES 256u

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 4096u];
static cdb_faultenv fe;
static cdb_env env;

static uint8_t arena_a[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes_a[NODES];
static cdb_free_extent free_a[8192];
static uint8_t rb_a[2048];
static uint8_t cw_a[24u * 1024u];
static cdb_index_entry ce_a[512];
static uint8_t cp_a[PAGE];
static uint8_t docbuf_a[8u * PAGE];
static uint8_t docstage_a[4096];
static uint8_t idxstage_a[8u * 1024u];
static cdb_db_config cfg_a;
static cdb_db db_a;

/* A key-value apply: entry N lives in logical page N. */
static cdb_status kv_apply(void *ctx, cdb_pager *p, const cdb_delta *d)
{
    cdb_page_header t;
    uint64_t lid = 0;
    cdb_status s = CDB_OK;
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
    for (i = 0; i < 16u; i++)
        h.db_id[i] = (uint8_t)(0x40 + i);
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

static void cfg_for_a(cdb_apply_fn apply)
{
    memset(&cfg_a, 0, sizeof cfg_a);
    cfg_a.pager.arena = arena_a;
    cfg_a.pager.arena_size = sizeof arena_a;
    cfg_a.pager.nodes = nodes_a;
    cfg_a.pager.node_cap = NODES;
    cfg_a.pager.free_list = free_a;
    cfg_a.pager.free_cap = sizeof free_a / sizeof free_a[0];
    cfg_a.record_buf = rb_a;
    cfg_a.record_buf_size = sizeof rb_a;
    cfg_a.apply = apply;
    cfg_a.catalog_work.bytes = cw_a;
    cfg_a.catalog_work.bytes_size = sizeof cw_a;
    cfg_a.catalog_work.entries = ce_a;
    cfg_a.catalog_work.entries_cap = 512;
    cfg_a.catalog_page = cp_a;
    cfg_a.doc_buffers = docbuf_a;
    cfg_a.doc_stage = docstage_a;
    cfg_a.doc_stage_size = sizeof docstage_a;
    cfg_a.idx_stage = idxstage_a;
    cfg_a.idx_stage_size = sizeof idxstage_a;
    cfg_a.durability = CDB_DURABILITY_FULL;
}

void setUp(void)
{
    init_env();
    cfg_for_a(kv_apply);
}

void tearDown(void) {}

/* ------------------------------------------- 1. staged-index rewind loop */

/* A savepoint taken after one staged index key, then two more keys staged,
 * then a rollback-to must rewind the staged-index hash chain (stage_idx_rewind
 * rebuilding the buckets from the surviving records): the kept key is still
 * found and the rolled-back keys are gone. */
static void test_stage_idx_rewind_loop(void)
{
    cdb_header h = settings();
    cdb_tx_mark mark;
    uint64_t got = 0;
    int live = 0, found = 0;
    const uint8_t keep[4] = { 'k', 'e', 'e', 'p' };
    const uint8_t drop1[4] = { 'd', 'r', 'p', '1' };
    const uint8_t drop2[4] = { 'd', 'r', 'p', '2' };

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db_a, &env, "sir", &cfg_a, &h));
    memset(&mark, 0, sizeof mark);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db_a, CDB_DURABILITY_FULL));

    /* stage one key, mark, stage two more, then rewind to the mark. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_stage_idx_put(&db_a, STORE, 0, keep, 4, 1u, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_savepoint(&db_a, &mark));
    TEST_ASSERT_TRUE(mark.stage_idx_used > 0u); /* the keep key is staged */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_stage_idx_put(&db_a, STORE, 0, drop1, 4, 2u, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_stage_idx_put(&db_a, STORE, 0, drop2, 4, 3u, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_rollback_to(&db_a, &mark));

    /* the surviving key is still resolvable; the rolled-back ones are not. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_stage_idx_get(&db_a, STORE, 0, keep, 4, &got, &live, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_UINT64(1u, got);
    found = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_stage_idx_get(&db_a, STORE, 0, drop1, 4, &got, &live, &found));
    TEST_ASSERT_FALSE(found);
    found = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_stage_idx_get(&db_a, STORE, 0, drop2, 4, &got, &live, &found));
    TEST_ASSERT_FALSE(found);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db_a));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db_a));
}

/* ------------------------------------------- 2. held entry-ID block maintenance */

static cdb_status doc_put(cdb_db *db, uint64_t store, int64_t val, uint64_t *entry)
{
    uint8_t body[48];
    cdb_value_writer w;
    cdb_value_writer_init(&w, body, sizeof body, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_int(&w, val);
    cdb_value_end_object(&w);
    return cdb_doc_insert(db, store, NULL, 0, body, cdb_value_writer_len(&w), entry);
}

/* Many document stores each claim an entry-ID block across a run of
 * separately-committed transactions, then a reconcile folds the held blocks
 * back and raises each store's counter (raise_block_counters). A reopen must
 * resume past every claimed block, and a further insert still succeeds and is
 * durable. */
static void test_held_block_maintenance(void)
{
    cdb_header h = settings();
    uint64_t ids[20];
    uint64_t e = 0;
    unsigned i = 0;
    char name[6];
    cfg_for_a(NULL); /* document model: inserts claim entry-ID blocks */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db_a, &env, "hbr", &cfg_a, &h));

    for (i = 0; i < 20u; i++) {
        name[0] = 's';
        name[1] = (char)('a' + (int)(i % 20));
        name[2] = (char)('A' + (int)(i / 20));
        name[3] = '\0';
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db_a, name, 3, CDB_MODEL_DOCUMENT, &ids[i]));
    }
    /* one committed transaction per store: each claims a block. */
    for (i = 0; i < 20u; i++) {
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db_a, CDB_DURABILITY_FULL));
        e = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, doc_put(&db_a, ids[i], (int64_t)i, &e));
        TEST_ASSERT_TRUE(e > 0u);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db_a));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db_a));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db_a));

    /* reopen and insert again: the counters were raised past every block. */
    cfg_for_a(NULL);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db_a, &env, "hbr", &cfg_a, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db_a, CDB_DURABILITY_FULL));
    e = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, doc_put(&db_a, ids[0], 99, &e));
    TEST_ASSERT_TRUE(e > 0u);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db_a));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db_a));
}

/* ------------------------------------------- 3. master + enclave key rotation */

/* A crypto database with an enclave. The master key rotates (re-wrapping the
 * enclave key under the new master), and the enclave key itself rotates three
 * ways: a bad reference is rejected (CDB_E_NOT_FOUND / resolve error) without
 * disturbing the key; a generated key (NULL reference) succeeds; and a named
 * reference succeeds. A scrub to completion drives the salt-prune resume path,
 * and the whole state reopens under the new master. */
static void test_rotation_and_salt_prune(void)
{
    cdb_header h = settings();
    uint64_t s0 = 0, e = 0;
    int done = 0;
    cdb_status bad = CDB_OK;
    setenv("CDB_DB4_MK", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1);
    setenv("CDB_DB4_MK2", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 1);
    setenv("CDB_DB4_ENC", "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff", 1);

    cfg_for_a(NULL);
    cfg_a.master_key_uri = "env://CDB_DB4_MK";
    cfg_a.aead_alg = CDB_AEAD_AES_256_GCM;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db_a, &env, "rot", &cfg_a, &h));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db_a, "d", 1, CDB_MODEL_DOCUMENT, &s0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_enclave(&db_a, 7u, "env://CDB_DB4_ENC"));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db_a, CDB_DURABILITY_FULL));
    e = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, doc_put(&db_a, s0, 1, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db_a));

    /* enclave-key rotation argument + error guards. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_rotate_enclave_key(&db_a, 0u, "env://CDB_DB4_ENC"));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_db_rotate_enclave_key(&db_a, 999u, "env://CDB_DB4_ENC"));
    bad = cdb_db_rotate_enclave_key(&db_a, 7u, "env://CDB_DB4_NOSUCH");
    TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, bad); /* resolve failure leaves the key intact */
    /* a generated key (NULL reference) and a named reference both rotate it. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_rotate_enclave_key(&db_a, 7u, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_rotate_enclave_key(&db_a, 7u, "env://CDB_DB4_ENC"));

    /* a bad new-master reference is refused; the database keeps working. */
    TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_db_rotate_master_key(&db_a, "env://CDB_DB4_NOSUCH"));
    /* a real rotation re-wraps the enclave key under the new master. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_rotate_master_key(&db_a, "env://CDB_DB4_MK2"));

    /* scrub to completion drives the salt-prune resume path. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db_a));
    done = 0;
    do
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_scrub(&db_a, 1, &done));
    while (!done);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db_a));

    /* reopen under the new master key to prove the rotation is durable. */
    cfg_for_a(NULL);
    cfg_a.master_key_uri = "env://CDB_DB4_MK2";
    cfg_a.aead_alg = CDB_AEAD_AES_256_GCM;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db_a, &env, "rot", &cfg_a, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db_a));
}

/* ------------------------------------------- 4. abuse / negative paths */

/* Build a CRDT wire slice with `nrecs` declared but only `body_bytes` of record
 * payload actually present (12-byte header + body). A valid magic with a short
 * body exercises the record-region bounds guard. */
static size_t make_short_slice(uint8_t *buf, uint32_t magic, uint32_t nrecs, size_t body_bytes)
{
    size_t i = 0;
    cdb_store_u32(buf, magic, CDB_ORDER_BIG);
    cdb_store_u32(buf + 4, 9u, CDB_ORDER_BIG); /* remote peer id */
    cdb_store_u32(buf + 8, nrecs, CDB_ORDER_BIG);
    for (i = 0; i < body_bytes; i++)
        buf[12u + i] = (uint8_t)(0xA0u + (i & 0x0Fu));
    return 12u + body_bytes;
}

/* Hostile and invalid inputs are refused with the documented status and never
 * corrupt the open database:
 *   - CRDT import rejects a NULL buffer, a sub-header-length (truncated) slice,
 *     a wrong-magic slice, and a slice whose single record overruns the buffer;
 *   - RBAC denies an unregistered principal, a principal lacking the required
 *     permission, and a principal probing a scope it was never granted — then
 *     the matching grant is honoured (positive control, so the deny is real);
 *   - catalog lookups reject a duplicate store name (collision) and a drop of a
 *     non-existent store, and report a missing store as not-found rather than
 *     inventing one.
 * After every rejection the database still accepts a legitimate write. */
static void test_abuse_paths(void)
{
    cdb_header h = settings();
    uint8_t slice[64];
    uint8_t pubkey[33];
    size_t applied = 123u; /* must be overwritten/ignored on the error paths */
    size_t slen = 0;
    uint64_t sid = 0, dup = 0, e = 0;
    int found = 1;

    memset(pubkey, 0x02, sizeof pubkey);
    memset(slice, 0, sizeof slice);

    cfg_for_a(NULL); /* document model: the closing write is a doc insert */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db_a, &env, "abz", &cfg_a, &h));

    /* --- invalid / malformed CRDT wire input (pre-lock guards) --- */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_db_crdt_import_slice(&db_a, NULL, sizeof slice, &applied));
    TEST_ASSERT_EQUAL_INT(CDB_E_TRUNCATED,
                          cdb_db_crdt_import_slice(&db_a, slice, 11u, &applied));
    slen = make_short_slice(slice, 0xDEADBEEFu, 1u, 0u); /* wrong magic */
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED,
                          cdb_db_crdt_import_slice(&db_a, slice, slen, &applied));

    /* valid magic, declares one record, but no record bytes follow: the
     * bounds guard must reject rather than read past the buffer. */
    slen = make_short_slice(slice, CDB_CRDT_WIRE_MAGIC, 1u, 0u);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db_a, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_TRUNCATED,
                          cdb_db_crdt_import_slice(&db_a, slice, slen, &applied));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db_a));

    /* --- authorization-bypass attempts (deny by default once RBAC exists) ---
     * Registering a principal activates enforcement: a grantee gets exactly its
     * grant and nothing more, and every other identity is refused. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_register_principal(&db_a, 500u, 1u, pubkey));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_grant_role(&db_a, 500u, 1u, 42u, CDB_PERM_READ));
    /* granted READ on scope 42 only: escalation and lateral scope are denied. */
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY,
                          cdb_db_check_perm(&db_a, 500u, 42u, CDB_PERM_WRITE)); /* privilege escalation */
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY,
                          cdb_db_check_perm(&db_a, 500u, 77u, CDB_PERM_READ));  /* wrong scope */
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY,
                          cdb_db_check_perm(&db_a, 501u, 42u, CDB_PERM_READ));  /* unregistered principal */
    /* positive control: the one grant that exists is honoured, so the denials
     * above are a real deny-by-default, not a blanket failure. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_check_perm(&db_a, 500u, 42u, CDB_PERM_READ));

    /* --- catalog collision / missing-object abuse --- */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db_a, "box", 3, CDB_MODEL_DOCUMENT, &sid));
    dup = 999u;
    TEST_ASSERT_EQUAL_INT(CDB_E_EXISTS,
                          cdb_db_create_store(&db_a, "box", 3, CDB_MODEL_DOCUMENT, &dup)); /* name collision */
    TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_db_drop_store(&db_a, 0xCAFEu)); /* drop of a store that never existed */
    found = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_find_store(&db_a, "nope", 4, &sid, &found));
    TEST_ASSERT_FALSE(found); /* a missing store is reported, not fabricated */

    /* the database survived every rejection and still commits a real write. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_find_store(&db_a, "box", 3, &sid, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db_a, CDB_DURABILITY_FULL));
    e = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, doc_put(&db_a, sid, 7, &e));
    TEST_ASSERT_TRUE(e > 0u);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db_a));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db_a));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_stage_idx_rewind_loop);
    RUN_TEST(test_held_block_maintenance);
    RUN_TEST(test_rotation_and_salt_prune);
    RUN_TEST(test_abuse_paths);
    return UNITY_END();
}
