#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "unity.h"
#include "combolite/cdb_crdt.h"
#include "cdb_db.h"
#include "cdb_crdt.h"
#include "cdb_faultenv.h"

#define FCAP (640u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define STORE 1u
#define KV_PAGES 128u

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 4096u];
static cdb_faultenv fe;
static cdb_env env;

/* Caller memory for Peer 1 */
static uint8_t arena1[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes1[NODES];
static cdb_free_extent free_list1[4096];
static uint8_t record_buf1[1024];
static uint8_t cat_work1[16384];
static cdb_index_entry cat_entries1[512];
static uint8_t cat_page1[PAGE];
static cdb_db_config cfg1;
static cdb_db db1;

/* Caller memory for Peer 2 */
static uint8_t arena2[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes2[NODES];
static cdb_free_extent free_list2[4096];
static uint8_t record_buf2[1024];
static uint8_t cat_work2[16384];
static cdb_index_entry cat_entries2[512];
static uint8_t cat_page2[PAGE];
static cdb_db_config cfg2;
static cdb_db db2;

/* #38 F2: one-shot fault, set by the baton-expiry test. The first apply call
 * after it is set returns CDB_E_BUSY once, forcing the baton-expiry commit
 * branch; the clock remains the synchronous logical counter. */
static int g_apply_fail_busy = 0;

static cdb_status kv_apply(void *ctx, cdb_pager *p, const cdb_delta *d)
{
    cdb_page_header t;
    uint64_t lid;
    cdb_status s;
    (void)ctx;
    if (g_apply_fail_busy) {
        g_apply_fail_busy = 0;
        return CDB_E_BUSY;
    }
    TEST_ASSERT_TRUE(d->entry_id < KV_PAGES);
    if (d->op == CDB_OP_DELETE) {
        s = cdb_pager_free(p, d->entry_id);
        return s == CDB_E_NOT_FOUND ? CDB_OK : s;
    }
    while (p->next_lid < KV_PAGES) {
        if ((s = cdb_pager_alloc(p, &lid)) != CDB_OK)
            return s;
    }
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
        h.db_id[i] = (uint8_t)(0x40 + i);
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
    g_apply_fail_busy = 0;
    init_env();

    memset(&cfg1, 0, sizeof cfg1);
    cfg1.pager.arena = arena1;
    cfg1.pager.arena_size = sizeof arena1;
    cfg1.pager.nodes = nodes1;
    cfg1.pager.node_cap = NODES;
    cfg1.pager.free_list = free_list1;
    cfg1.pager.free_cap = sizeof free_list1 / sizeof free_list1[0];
    cfg1.record_buf = record_buf1;
    cfg1.record_buf_size = sizeof record_buf1;
    cfg1.apply = kv_apply;
    cfg1.catalog_work.bytes = cat_work1;
    cfg1.catalog_work.bytes_size = sizeof cat_work1;
    cfg1.catalog_work.entries = cat_entries1;
    cfg1.catalog_work.entries_cap = 512;
    cfg1.catalog_page = cat_page1;
    cfg1.durability = CDB_DURABILITY_FULL;

    memset(&cfg2, 0, sizeof cfg2);
    cfg2.pager.arena = arena2;
    cfg2.pager.arena_size = sizeof arena2;
    cfg2.pager.nodes = nodes2;
    cfg2.pager.node_cap = NODES;
    cfg2.pager.free_list = free_list2;
    cfg2.pager.free_cap = sizeof free_list2 / sizeof free_list2[0];
    cfg2.record_buf = record_buf2;
    cfg2.record_buf_size = sizeof record_buf2;
    cfg2.apply = kv_apply;
    cfg2.catalog_work.bytes = cat_work2;
    cfg2.catalog_work.bytes_size = sizeof cat_work2;
    cfg2.catalog_work.entries = cat_entries2;
    cfg2.catalog_work.entries_cap = 512;
    cfg2.catalog_page = cat_page2;
    cfg2.durability = CDB_DURABILITY_FULL;
}

void tearDown(void)
{
}

/* ------------------------------------------------------------ 1. HLC Tests */

static void test_hlc_total_order_and_ticks(void)
{
    cdb_hlc a = {1000u, 0u, 1u};
    cdb_hlc b = {1000u, 0u, 2u};
    cdb_hlc c = {1000u, 1u, 1u};
    cdb_hlc d = {1001u, 0u, 1u};
    cdb_hlc clock = {0u, 0u, 42u};

    /* Comparison total ordering */
    TEST_ASSERT_TRUE(cdb_hlc_compare(a, a) == 0);
    TEST_ASSERT_TRUE(cdb_hlc_compare(a, b) < 0);
    TEST_ASSERT_TRUE(cdb_hlc_compare(b, a) > 0);
    TEST_ASSERT_TRUE(cdb_hlc_compare(a, c) < 0);
    TEST_ASSERT_TRUE(cdb_hlc_compare(c, d) < 0);
    TEST_ASSERT_TRUE(cdb_hlc_compare(d, c) > 0);

    /* Local tick advances */
    cdb_hlc_tick(&clock, 500u);
    TEST_ASSERT_EQUAL_UINT64(500u, clock.physical);
    TEST_ASSERT_EQUAL_UINT32(0u, clock.logical);
    TEST_ASSERT_EQUAL_UINT32(42u, clock.peer_id);

    /* Same wall time increments logical sequence */
    cdb_hlc_tick(&clock, 500u);
    TEST_ASSERT_EQUAL_UINT64(500u, clock.physical);
    TEST_ASSERT_EQUAL_UINT32(1u, clock.logical);

    /* New wall time resets logical sequence */
    cdb_hlc_tick(&clock, 600u);
    TEST_ASSERT_EQUAL_UINT64(600u, clock.physical);
    TEST_ASSERT_EQUAL_UINT32(0u, clock.logical);

    /* Remote clock update with higher physical time */
    {
        cdb_hlc remote = {700u, 5u, 99u};
        cdb_hlc_update(&clock, remote, 650u);
        TEST_ASSERT_EQUAL_UINT64(700u, clock.physical);
        TEST_ASSERT_EQUAL_UINT32(6u, clock.logical);
    }

    /* Remote clock update with concurrent equal physical time */
    {
        cdb_hlc remote = {700u, 10u, 99u};
        cdb_hlc_update(&clock, remote, 700u);
        TEST_ASSERT_EQUAL_UINT64(700u, clock.physical);
        TEST_ASSERT_EQUAL_UINT32(11u, clock.logical);
    }
}

/* ------------------------------------------------------------ 2. Version Vector Tests */

static void test_version_vector_dominance_and_concurrency(void)
{
    cdb_crdt_vector va, vb, vc;
    cdb_hlc h1 = {100u, 0u, 1u};
    cdb_hlc h2 = {100u, 0u, 2u};
    cdb_crdt_peer_entry out;

    memset(&va, 0, sizeof va);
    memset(&vb, 0, sizeof vb);
    memset(&vc, 0, sizeof vc);

    cdb_crdt_vector_set(&va, 1u, 5u, h1);
    cdb_crdt_vector_set(&va, 2u, 10u, h2);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crdt_vector_get(&va, 1u, &out));
    TEST_ASSERT_EQUAL_UINT64(5u, out.counter);
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_crdt_vector_get(&va, 99u, &out));

    /* Identical vectors are equal */
    cdb_crdt_vector_set(&vb, 1u, 5u, h1);
    cdb_crdt_vector_set(&vb, 2u, 10u, h2);
    TEST_ASSERT_EQUAL_INT(CDB_CRDT_CMP_EQUAL, cdb_crdt_vector_compare(&va, &vb));

    /* vb strictly ahead: vb dominates va, va dominated by vb */
    cdb_crdt_vector_set(&vb, 1u, 6u, h1);
    TEST_ASSERT_EQUAL_INT(CDB_CRDT_CMP_DOMINATED, cdb_crdt_vector_compare(&va, &vb));
    TEST_ASSERT_EQUAL_INT(CDB_CRDT_CMP_DOMINATES, cdb_crdt_vector_compare(&vb, &va));

    /* vc concurrent: peer 1 higher, peer 2 lower */
    cdb_crdt_vector_set(&vc, 1u, 10u, h1);
    cdb_crdt_vector_set(&vc, 2u, 2u, h2);
    TEST_ASSERT_EQUAL_INT(CDB_CRDT_CMP_CONCURRENT, cdb_crdt_vector_compare(&va, &vc));

    /* Merge takes maximum counters */
    cdb_crdt_vector_merge(&va, &vc);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crdt_vector_get(&va, 1u, &out));
    TEST_ASSERT_EQUAL_UINT64(10u, out.counter);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crdt_vector_get(&va, 2u, &out));
    TEST_ASSERT_EQUAL_UINT64(10u, out.counter);
}

/* ------------------------------------------------------------ 3. PN-Counter Tests */

static void test_pn_counter_convergence(void)
{
    cdb_pn_counter c1, c2, m1, m2;

    cdb_pn_counter_init(&c1);
    cdb_pn_counter_init(&c2);

    /* Replica 1 operations */
    cdb_pn_counter_inc(&c1, 0u, 100u);
    cdb_pn_counter_dec(&c1, 0u, 25u);
    TEST_ASSERT_EQUAL_INT64(75, cdb_pn_counter_val(&c1));

    /* Replica 2 operations */
    cdb_pn_counter_inc(&c2, 1u, 50u);
    cdb_pn_counter_dec(&c2, 1u, 10u);
    TEST_ASSERT_EQUAL_INT64(40, cdb_pn_counter_val(&c2));

    /* Commutative merge: merge(c1, c2) == merge(c2, c1) */
    cdb_pn_counter_merge(&m1, &c1, &c2);
    cdb_pn_counter_merge(&m2, &c2, &c1);

    TEST_ASSERT_EQUAL_INT64(115, cdb_pn_counter_val(&m1));
    TEST_ASSERT_EQUAL_INT64(115, cdb_pn_counter_val(&m2));
    TEST_ASSERT_EQUAL_MEMORY(&m1, &m2, sizeof m1);
}

/* ------------------------------------------------------------ 4. LWW Document Field Merge */

static void test_lww_document_field_merge(void)
{
    const uint8_t val_alice[] = "Alice";
    const uint8_t val_alicia[] = "Alicia";
    const uint8_t val_active[] = "Active";
    const uint8_t val_engineer[] = "Engineer";

    cdb_crdt_field doc_a[2];
    cdb_crdt_field doc_b[3];
    cdb_crdt_field merged[8];
    size_t out_count = 0;

    /* Doc A: field 101="Alice" @ t=10, field 102="Active" @ t=10 */
    doc_a[0].field_id = 101u;
    doc_a[0].op = CDB_CRDT_FIELD_SET;
    doc_a[0].hlc = (cdb_hlc){10u, 0u, 1u};
    doc_a[0].val = val_alice;
    doc_a[0].val_len = sizeof val_alice;

    doc_a[1].field_id = 102u;
    doc_a[1].op = CDB_CRDT_FIELD_SET;
    doc_a[1].hlc = (cdb_hlc){10u, 0u, 1u};
    doc_a[1].val = val_active;
    doc_a[1].val_len = sizeof val_active;

    /* Doc B: field 101="Alicia" @ t=12 (wins), field 102 tombstoned @ t=15 (wins), field 103="Engineer" @ t=11 */
    doc_b[0].field_id = 101u;
    doc_b[0].op = CDB_CRDT_FIELD_SET;
    doc_b[0].hlc = (cdb_hlc){12u, 0u, 2u};
    doc_b[0].val = val_alicia;
    doc_b[0].val_len = sizeof val_alicia;

    doc_b[1].field_id = 102u;
    doc_b[1].op = CDB_CRDT_FIELD_TOMBSTONE;
    doc_b[1].hlc = (cdb_hlc){15u, 0u, 2u};
    doc_b[1].val = NULL;
    doc_b[1].val_len = 0u;

    doc_b[2].field_id = 103u;
    doc_b[2].op = CDB_CRDT_FIELD_SET;
    doc_b[2].hlc = (cdb_hlc){11u, 0u, 2u};
    doc_b[2].val = val_engineer;
    doc_b[2].val_len = sizeof val_engineer;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crdt_lww_merge(doc_a, 2, doc_b, 3, merged, 8, &out_count));
    TEST_ASSERT_EQUAL_UINT32(3u, (uint32_t)out_count);

    /* Verify field 101 winner is Alicia */
    TEST_ASSERT_EQUAL_UINT64(101u, merged[0].field_id);
    TEST_ASSERT_EQUAL_STRING("Alicia", (const char *)merged[0].val);

    /* Verify field 102 winner is tombstone */
    TEST_ASSERT_EQUAL_UINT64(102u, merged[1].field_id);
    TEST_ASSERT_EQUAL_UINT8(CDB_CRDT_FIELD_TOMBSTONE, merged[1].op);

    /* Verify field 103 is present */
    TEST_ASSERT_EQUAL_UINT64(103u, merged[2].field_id);
    TEST_ASSERT_EQUAL_STRING("Engineer", (const char *)merged[2].val);
}

/* ------------------------------------------------------------ 5. Graph Link AWORSet */

static void test_graph_link_aworset(void)
{
    cdb_crdt_link_token add_early = {1, 10, 20, 10, 30, {100u, 0u, 1u}, 0};
    cdb_crdt_link_token remove_late = {1, 10, 20, 10, 30, {200u, 0u, 2u}, 1};
    cdb_crdt_link_token add_newer = {1, 10, 20, 10, 30, {300u, 0u, 3u}, 0};
    cdb_crdt_link_token del_same = {1, 10, 20, 10, 30, {300u, 0u, 3u}, 1};

    /* Later remove tombstones earlier addition */
    TEST_ASSERT_EQUAL_INT(0, cdb_crdt_link_resolve(add_early, remove_late));

    /* Concurrent or later addition wins over prior removal */
    TEST_ASSERT_EQUAL_INT(1, cdb_crdt_link_resolve(add_newer, remove_late));

    /* Add-Wins tie break on identical timestamp */
    TEST_ASSERT_EQUAL_INT(1, cdb_crdt_link_resolve(add_newer, del_same));
}

/* ------------------------------------------------------------ 6. Handshake & Slice Wire Codec */

static void test_replication_handshake_and_slice_wire_codec(void)
{
    uint8_t buf[512];
    size_t len = 0;
    cdb_crdt_vector vin, vout;
    uint32_t peer_id_out = 0;
    cdb_crdt_delta_rec sin[2], sout[4];
    size_t count_out = 0;

    /* Handshake encode / decode */
    memset(&vin, 0, sizeof vin);
    cdb_crdt_vector_set(&vin, 10u, 42u, (cdb_hlc){100u, 1u, 10u});
    cdb_crdt_vector_set(&vin, 20u, 84u, (cdb_hlc){200u, 2u, 20u});

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crdt_handshake_encode(77u, &vin, buf, sizeof buf, &len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crdt_handshake_decode(buf, len, &peer_id_out, &vout));
    TEST_ASSERT_EQUAL_UINT32(77u, peer_id_out);
    TEST_ASSERT_EQUAL_INT(CDB_CRDT_CMP_EQUAL, cdb_crdt_vector_compare(&vin, &vout));

    /* Error handling */
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_crdt_handshake_encode(77u, &vin, buf, 10u, &len));
    TEST_ASSERT_EQUAL_INT(CDB_E_TRUNCATED, cdb_crdt_handshake_decode(buf, 8u, &peer_id_out, &vout));

    buf[0] = 0; /* corrupt magic */
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_crdt_handshake_decode(buf, len, &peer_id_out, &vout));

    /* Slice encode / decode */
    sin[0].store_id = 1u;
    sin[0].entry_id = 10u;
    sin[0].op = CDB_OP_INSERT;
    sin[0].hlc = (cdb_hlc){100u, 0u, 1u};
    sin[0].data = (const uint8_t *)"hello";
    sin[0].len = 5u;

    sin[1].store_id = 1u;
    sin[1].entry_id = 11u;
    sin[1].op = CDB_OP_REPLACE;
    sin[1].hlc = (cdb_hlc){105u, 1u, 1u};
    sin[1].data = (const uint8_t *)"world";
    sin[1].len = 5u;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crdt_slice_encode(1u, sin, 2, buf, sizeof buf, &len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crdt_slice_decode(buf, len, &peer_id_out, sout, 4, &count_out));
    TEST_ASSERT_EQUAL_UINT32(1u, peer_id_out);
    TEST_ASSERT_EQUAL_UINT32(2u, (uint32_t)count_out);
    TEST_ASSERT_EQUAL_UINT64(10u, sout[0].entry_id);
    TEST_ASSERT_EQUAL_UINT8(CDB_OP_INSERT, sout[0].op);
    TEST_ASSERT_EQUAL_STRING_LEN("hello", sout[0].data, 5);
    TEST_ASSERT_EQUAL_UINT64(11u, sout[1].entry_id);
    TEST_ASSERT_EQUAL_UINT8(CDB_OP_REPLACE, sout[1].op);
    TEST_ASSERT_EQUAL_STRING_LEN("world", sout[1].data, 5);
}

/* ------------------------------------------------------------ 7. Multi-Peer Replication Sync */

static void test_db_multi_peer_replication_sync(void)
{
    cdb_header h = settings();
    uint8_t slice[1024];
    size_t slice_len = 0;
    size_t applied = 0;
    cdb_hlc hlc1;
    cdb_crdt_vector v1, v2;
    uint8_t page_buf[PAGE];
    cdb_page_header ph;

    /* Open Peer 1 and Peer 2 databases */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db1, &env, "peer1", &cfg1, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db2, &env, "peer2", &cfg2, &h));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_set_peer_id(&db1, 1u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_set_peer_id(&db2, 2u));

    /* Peer 1 writes a transaction */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db1, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db1, STORE, 5u, CDB_OP_INSERT, "Peer1Data", 9u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db1));

    /* Peer 1's HLC has ticked */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_get_hlc(&db1, &hlc1));
    TEST_ASSERT_EQUAL_UINT32(1u, hlc1.peer_id);
    TEST_ASSERT_TRUE(hlc1.physical > 0 || hlc1.logical > 0);

    /* Peer 2 asks Peer 1 for delta slice since Peer 2's known vector for Peer 1 (initially 0) */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_get_crdt_vector(&db2, &v2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_export_slice(&db1, &v2, slice, sizeof slice, &slice_len));
    TEST_ASSERT_TRUE(slice_len > 0);

    /* Peer 2 imports delta slice */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_slice(&db2, slice, slice_len, &applied));
    TEST_ASSERT_EQUAL_UINT32(1u, (uint32_t)applied);

    /* Verify Peer 2 now has the data on page 5 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(&db2.pager, 5u, page_buf, &ph));
    TEST_ASSERT_EQUAL_STRING_LEN("Peer1Data", page_buf + cdb_page_payload_offset(CDB_PAGE_FMT_FULL64), 9);

    /* Peer 2 now commits its own change on page 6 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db2, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db2, STORE, 6u, CDB_OP_INSERT, "Peer2Data", 9u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db2));

    /* Peer 1 syncs from Peer 2 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_get_crdt_vector(&db1, &v1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_export_slice(&db2, &v1, slice, sizeof slice, &slice_len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_slice(&db1, slice, slice_len, &applied));
    TEST_ASSERT_EQUAL_UINT32(1u, (uint32_t)applied);

    /* Verify Peer 1 now has page 6 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(&db1.pager, 6u, page_buf, &ph));
    TEST_ASSERT_EQUAL_STRING_LEN("Peer2Data", page_buf + cdb_page_payload_offset(CDB_PAGE_FMT_FULL64), 9);

    /* Re-importing already seen deltas applies 0 records (idempotence) */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_slice(&db1, slice, slice_len, &applied));
    TEST_ASSERT_EQUAL_UINT32(0u, (uint32_t)applied);

    /* Clean close */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db2));
}

/* The export sends only what this database kept (spec 14.4.9 rule 6): an
 * aborted transaction before a committed one, and a change a savepoint
 * rollback dropped inside the committed one, stay out of the slice. */
static void test_export_skips_aborted_and_rolled_back(void)
{
    cdb_header h = settings();
    uint8_t slice[1024];
    size_t slice_len = 0;
    size_t applied = 0;
    cdb_crdt_vector v2;
    cdb_tx_mark mark;
    uint8_t page_buf[PAGE];
    cdb_page_header ph;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db1, &env, "peer1", &cfg1, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db2, &env, "peer2", &cfg2, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_set_peer_id(&db1, 1u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_set_peer_id(&db2, 2u));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db1, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db1, STORE, 7u, CDB_OP_INSERT, "Aborted", 7u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db1, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db1, STORE, 8u, CDB_OP_INSERT, "Kept", 4u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_savepoint(&db1, &mark));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db1, STORE, 9u, CDB_OP_INSERT, "Dropped", 7u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_rollback_to(&db1, &mark));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_get_crdt_vector(&db2, &v2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_export_slice(&db1, &v2, slice, sizeof slice, &slice_len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_slice(&db2, slice, slice_len, &applied));
    TEST_ASSERT_EQUAL_UINT32(1u, (uint32_t)applied);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(&db2.pager, 8u, page_buf, &ph));
    TEST_ASSERT_EQUAL_STRING_LEN("Kept", page_buf + cdb_page_payload_offset(CDB_PAGE_FMT_FULL64), 4);
    if (cdb_pager_read(&db2.pager, 7u, page_buf, &ph) == CDB_OK)
        TEST_ASSERT_TRUE(memcmp("Aborted", page_buf + cdb_page_payload_offset(CDB_PAGE_FMT_FULL64), 7) != 0);
    if (cdb_pager_read(&db2.pager, 9u, page_buf, &ph) == CDB_OK)
        TEST_ASSERT_TRUE(memcmp("Dropped", page_buf + cdb_page_payload_offset(CDB_PAGE_FMT_FULL64), 7) != 0);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db2));
}

/* A slice from peer 7 with n records on pages 20, 21, ...; record i
 * carries "Ri" at clock 100 + i. With big set, the last record is too large
 * for one journal record, so importing it fails after the earlier ones are
 * journaled. */
static size_t make_slice(uint8_t *buf, size_t cap, size_t n, int big)
{
    static uint8_t data[8][1200];
    cdb_crdt_delta_rec recs[8];
    size_t i, len = 0;
    TEST_ASSERT_TRUE(n <= 8);
    for (i = 0; i < n; i++) {
        memset(&recs[i], 0, sizeof recs[i]);
        data[i][0] = 'R';
        data[i][1] = (uint8_t)('0' + i);
        recs[i].store_id = STORE;
        recs[i].entry_id = 20u + i;
        recs[i].op = CDB_OP_INSERT;
        recs[i].hlc.physical = 100u + i;
        recs[i].hlc.peer_id = 7u;
        recs[i].data = data[i];
        recs[i].len = big && i == n - 1u ? sizeof data[i] : 2u;
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crdt_slice_encode(7u, recs, n, buf, cap, &len));
    return len;
}

/* The version vector advances only when the transaction that applied the
 * changes commits (spec 19.4): an abort, a failed import, or a rollback to
 * a savepoint leaves the changes importable again. */
static void test_import_vector_advances_at_commit(void)
{
    cdb_header h = settings();
    static uint8_t slice[4096];
    size_t len, applied = 0;
    cdb_tx_mark m;
    uint8_t page_buf[PAGE];
    cdb_page_header ph;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db2, &env, "peer2", &cfg2, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_set_peer_id(&db2, 2u));
    len = make_slice(slice, sizeof slice, 2, 0);

    /* Imported in the caller's transaction, which aborts. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db2, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_slice(&db2, slice, len, &applied));
    TEST_ASSERT_EQUAL_UINT32(2u, (uint32_t)applied);
    /* Within the transaction, the same slice is already seen. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_slice(&db2, slice, len, &applied));
    TEST_ASSERT_EQUAL_UINT32(0u, (uint32_t)applied);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db2));

    /* Rolled back to a savepoint, then committed. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db2, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_savepoint(&db2, &m));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_slice(&db2, slice, len, &applied));
    TEST_ASSERT_EQUAL_UINT32(2u, (uint32_t)applied);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_rollback_to(&db2, &m));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db2, STORE, 30u, CDB_OP_INSERT, "x", 1u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db2));

    /* A slice whose last record can't be journaled fails as a whole. */
    len = make_slice(slice, sizeof slice, 3, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db2, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_crdt_import_slice(&db2, slice, len, &applied));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db2));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_pager_read(&db2.pager, 20u, page_buf, &ph));

    /* None of that counted: the slice still applies in full, once. */
    len = make_slice(slice, sizeof slice, 2, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_slice(&db2, slice, len, &applied));
    TEST_ASSERT_EQUAL_UINT32(2u, (uint32_t)applied);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(&db2.pager, 21u, page_buf, &ph));
    TEST_ASSERT_EQUAL_STRING_LEN("R1", page_buf + cdb_page_payload_offset(CDB_PAGE_FMT_FULL64), 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_slice(&db2, slice, len, &applied));
    TEST_ASSERT_EQUAL_UINT32(0u, (uint32_t)applied);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db2));
}

/* ------------------------------------------------------------ 8. #38 convergence */

/* Opens db on name with peer_id set and replication enabled. */
static void open_peer(cdb_db *db, cdb_db_config *cfg, const char *name, uint32_t peer)
{
    cdb_header h = settings();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(db, &env, name, cfg, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_set_peer_id(db, peer));
}

/* Builds a delta record for store STORE. */
static cdb_crdt_delta_rec mk(uint64_t entry, uint8_t op, cdb_hlc hlc, const void *data, size_t len)
{
    cdb_crdt_delta_rec r;
    memset(&r, 0, sizeof r);
    r.store_id = STORE;
    r.entry_id = entry;
    r.op = op;
    r.hlc = hlc;
    r.data = (const uint8_t *)data;
    r.len = len;
    return r;
}

/* Reads outlen payload bytes of a page; 1 when present, 0 when absent. */
static int read_val(cdb_db *db, uint64_t entry, uint8_t *out, size_t outlen)
{
    uint8_t pb[PAGE];
    cdb_page_header ph;
    if (cdb_pager_read(&db->pager, entry, pb, &ph) != CDB_OK)
        return 0;
    memcpy(out, pb + cdb_page_payload_offset(CDB_PAGE_FMT_FULL64), outlen);
    return 1;
}

static void import_pair(cdb_db *db, cdb_crdt_delta_rec a, cdb_crdt_delta_rec b, size_t *applied)
{
    cdb_crdt_delta_rec recs[2];
    recs[0] = a;
    recs[1] = b;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_deltas(db, 0u, recs, 2, applied));
}

/* AC1: two peers' concurrent writes to the same (store,entry) converge to the
 * SAME value regardless of import order (pre-fix: order-dependent divergence). */
static void test_convergence_order_independent(void)
{
    cdb_hlc ha = {10u, 0u, 1u};
    cdb_hlc hb = {20u, 0u, 2u};
    cdb_crdt_delta_rec a = mk(40u, CDB_OP_INSERT, ha, "AAAA", 4u);
    cdb_crdt_delta_rec b = mk(40u, CDB_OP_INSERT, hb, "BBBB", 4u);
    uint8_t v1[4], v2[4];
    size_t applied = 0;

    open_peer(&db1, &cfg1, "rA", 100u);
    import_pair(&db1, a, b, &applied); /* order A, B */
    TEST_ASSERT_TRUE(read_val(&db1, 40u, v1, sizeof v1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db1));

    open_peer(&db2, &cfg2, "rB", 200u);
    import_pair(&db2, b, a, &applied); /* order B, A */
    TEST_ASSERT_TRUE(read_val(&db2, 40u, v2, sizeof v2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db2));

    TEST_ASSERT_EQUAL_MEMORY(v1, v2, 4);  /* order-independent convergence */
    TEST_ASSERT_EQUAL_MEMORY("BBBB", v1, 4); /* higher HLC wins */
}

/* AC3: LWW resolves to the higher-HLC write, with a stable peer-id tiebreak on
 * equal physical/logical clocks. */
static void test_lww_resolves_higher_hlc(void)
{
    cdb_hlc lo = {10u, 0u, 1u};
    cdb_hlc hi = {10u, 0u, 2u}; /* equal clock, higher peer wins */
    cdb_crdt_delta_rec a = mk(45u, CDB_OP_INSERT, lo, "LLLL", 4u);
    cdb_crdt_delta_rec b = mk(45u, CDB_OP_INSERT, hi, "HHHH", 4u);
    uint8_t v[4];
    size_t applied = 0;

    open_peer(&db1, &cfg1, "lww", 100u);
    import_pair(&db1, a, b, &applied);
    TEST_ASSERT_TRUE(read_val(&db1, 45u, v, sizeof v));
    TEST_ASSERT_EQUAL_MEMORY("HHHH", v, 4);
    /* Reverse order converges to the same winner. */
    import_pair(&db1, b, a, &applied);
    TEST_ASSERT_TRUE(read_val(&db1, 45u, v, sizeof v));
    TEST_ASSERT_EQUAL_MEMORY("HHHH", v, 4);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db1));
}

/* AC4 / F1: concurrent PN-counter increments NET (sum), not last-write-wins,
 * and converge to the same net independent of import order. */
static void test_pn_counter_apply_nets(void)
{
    cdb_hlc ha = {10u, 0u, 1u};
    cdb_hlc hb = {20u, 0u, 2u};
    uint8_t da[8], dbuf[8], v[8];
    cdb_crdt_delta_rec a, b;
    size_t applied = 0;

    cdb_store_u64(da, 100u, CDB_ORDER_BIG);
    cdb_store_u64(dbuf, 50u, CDB_ORDER_BIG);
    a = mk(42u, CDB_OP_INSERT, ha, da, 8u);
    b = mk(42u, CDB_OP_INSERT, hb, dbuf, 8u);

    open_peer(&db1, &cfg1, "cA", 100u);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_db_crdt_set_store_merge(&db1, STORE, CDB_CRDT_MERGE_COUNTER));
    import_pair(&db1, a, b, &applied); /* +100@1 then +50@2 */
    TEST_ASSERT_TRUE(read_val(&db1, 42u, v, sizeof v));
    TEST_ASSERT_EQUAL_INT64(150, (int64_t)cdb_load_u64(v, CDB_ORDER_BIG));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db1));

    open_peer(&db2, &cfg2, "cB", 200u);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_db_crdt_set_store_merge(&db2, STORE, CDB_CRDT_MERGE_COUNTER));
    import_pair(&db2, b, a, &applied); /* +50@2 then +100@1 */
    TEST_ASSERT_TRUE(read_val(&db2, 42u, v, sizeof v));
    TEST_ASSERT_EQUAL_INT64(150, (int64_t)cdb_load_u64(v, CDB_ORDER_BIG));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db2));
}

/* QA F1-strengthening: PN netting with a SIGNED decrement. +100@peerA and
 * -30@peerB must NET to 70 (not last-write-wins), and converge to the same net
 * regardless of import order — proves PN semantics, not merely additive sums. */
static void test_pn_counter_apply_nets_with_decrement(void)
{
    cdb_hlc ha = {10u, 0u, 1u};
    cdb_hlc hb = {20u, 0u, 2u};
    uint8_t da[8], dbuf[8], v[8];
    cdb_crdt_delta_rec a, b;
    size_t applied = 0;

    cdb_store_u64(da, (uint64_t)(int64_t)100, CDB_ORDER_BIG);  /* +100 */
    cdb_store_u64(dbuf, (uint64_t)(int64_t)-30, CDB_ORDER_BIG); /* -30 (two's complement) */
    a = mk(46u, CDB_OP_INSERT, ha, da, 8u);
    b = mk(46u, CDB_OP_INSERT, hb, dbuf, 8u);

    open_peer(&db1, &cfg1, "dA", 100u);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_db_crdt_set_store_merge(&db1, STORE, CDB_CRDT_MERGE_COUNTER));
    import_pair(&db1, a, b, &applied); /* +100@1 then -30@2 */
    TEST_ASSERT_TRUE(read_val(&db1, 46u, v, sizeof v));
    TEST_ASSERT_EQUAL_INT64(70, (int64_t)cdb_load_u64(v, CDB_ORDER_BIG));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db1));

    open_peer(&db2, &cfg2, "dB", 200u);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_db_crdt_set_store_merge(&db2, STORE, CDB_CRDT_MERGE_COUNTER));
    import_pair(&db2, b, a, &applied); /* -30@2 then +100@1, same net */
    TEST_ASSERT_TRUE(read_val(&db2, 46u, v, sizeof v));
    TEST_ASSERT_EQUAL_INT64(70, (int64_t)cdb_load_u64(v, CDB_ORDER_BIG));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db2));
}

/* QA abuse: a COUNTER-class store treats the payload as a signed 8-byte
 * increment; a wrong-length payload is untrusted input and must be rejected
 * fail-closed (no crash, no silent mis-net), leaving the database usable. */
static void test_counter_rejects_bad_payload_len(void)
{
    cdb_hlc h = {10u, 0u, 1u};
    cdb_crdt_delta_rec bad, good;
    uint8_t gd[8], v[8];
    size_t applied = 0;

    open_peer(&db1, &cfg1, "cbad", 100u);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_db_crdt_set_store_merge(&db1, STORE, CDB_CRDT_MERGE_COUNTER));

    /* 4-byte payload on a COUNTER store: rejected, nothing applied. */
    bad = mk(47u, CDB_OP_INSERT, h, "\x00\x00\x00\x01", 4u);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED,
                          cdb_db_crdt_import_deltas(&db1, 0u, &bad, 1, &applied));
    TEST_ASSERT_EQUAL_UINT32(0u, (uint32_t)applied);
    TEST_ASSERT_EQUAL_INT(0, read_val(&db1, 47u, v, sizeof v)); /* not written */

    /* Still usable: a correct 8-byte increment nets normally afterwards. */
    cdb_store_u64(gd, (uint64_t)(int64_t)5, CDB_ORDER_BIG);
    good = mk(47u, CDB_OP_INSERT, h, gd, 8u);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_deltas(&db1, 0u, &good, 1, &applied));
    TEST_ASSERT_EQUAL_UINT32(1u, (uint32_t)applied);
    TEST_ASSERT_TRUE(read_val(&db1, 47u, v, sizeof v));
    TEST_ASSERT_EQUAL_INT64(5, (int64_t)cdb_load_u64(v, CDB_ORDER_BIG));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db1));
}

/* QA abuse: the delta-slice wire is untrusted. Truncated, magic-corrupted, and
 * under-capacity decodes are rejected (non-OK) without crashing or reading OOB
 * (ASan/UBSan clean), and a valid slice still decodes afterwards. */
static void test_slice_decode_rejects_corrupt_wire(void)
{
    uint8_t buf[512];
    size_t len = 0, count_out = 0;
    uint32_t peer_out = 0;
    cdb_crdt_delta_rec sin[2], sout[4];

    sin[0] = mk(10u, CDB_OP_INSERT, (cdb_hlc){100u, 0u, 1u}, "hello", 5u);
    sin[1] = mk(11u, CDB_OP_REPLACE, (cdb_hlc){105u, 1u, 1u}, "world", 5u);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crdt_slice_encode(1u, sin, 2, buf, sizeof buf, &len));
    TEST_ASSERT_TRUE(len > 12u);

    /* Truncated to a few bytes: must not decode, must not crash. */
    TEST_ASSERT_NOT_EQUAL(CDB_OK,
                          cdb_crdt_slice_decode(buf, 6u, &peer_out, sout, 4, &count_out));

    /* Corrupt magic: rejected. */
    {
        uint8_t corrupt[512];
        memcpy(corrupt, buf, len);
        corrupt[0] ^= 0xFFu;
        TEST_ASSERT_NOT_EQUAL(CDB_OK,
                              cdb_crdt_slice_decode(corrupt, len, &peer_out, sout, 4, &count_out));
    }

    /* Output capacity too small for the record count: rejected, no OOB write. */
    TEST_ASSERT_NOT_EQUAL(CDB_OK,
                          cdb_crdt_slice_decode(buf, len, &peer_out, sout, 1, &count_out));

    /* The genuine slice still decodes cleanly after the abuse. */
    count_out = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_crdt_slice_decode(buf, len, &peer_out, sout, 4, &count_out));
    TEST_ASSERT_EQUAL_UINT32(1u, peer_out);
    TEST_ASSERT_EQUAL_UINT32(2u, (uint32_t)count_out);
}

/* AC5: an AWORSet link add wins over a concurrent (older) remove, both orders. */
static void test_aworset_add_wins(void)
{
    cdb_hlc hadd = {30u, 0u, 1u};
    cdb_hlc hrem = {20u, 0u, 2u};
    cdb_crdt_delta_rec add = mk(43u, CDB_OP_INSERT, hadd, "LINK", 4u);
    cdb_crdt_delta_rec rem = mk(43u, CDB_OP_DELETE, hrem, NULL, 0u);
    uint8_t v[4];
    size_t applied = 0;

    open_peer(&db1, &cfg1, "aA", 100u);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_db_crdt_set_store_merge(&db1, STORE, CDB_CRDT_MERGE_AWORSET));
    import_pair(&db1, add, rem, &applied);
    TEST_ASSERT_TRUE(read_val(&db1, 43u, v, sizeof v)); /* link survives */
    TEST_ASSERT_EQUAL_MEMORY("LINK", v, 4);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db1));

    open_peer(&db2, &cfg2, "aB", 200u);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_db_crdt_set_store_merge(&db2, STORE, CDB_CRDT_MERGE_AWORSET));
    import_pair(&db2, rem, add, &applied);
    TEST_ASSERT_TRUE(read_val(&db2, 43u, v, sizeof v)); /* same result */
    TEST_ASSERT_EQUAL_MEMORY("LINK", v, 4);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db2));
}

/* AC6: duplicate commutative-TS points dedup to a single application. */
static void test_ts_dedup(void)
{
    cdb_hlc ht = {10u, 0u, 7u};
    cdb_crdt_delta_rec d = mk(44u, CDB_OP_INSERT, ht, "P", 1u);
    cdb_crdt_delta_rec recs[2];
    uint8_t v[1];
    size_t applied = 0;

    recs[0] = d;
    recs[1] = d; /* identical (series, ts, peer) */
    open_peer(&db1, &cfg1, "ts", 100u);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_set_store_merge(&db1, STORE, CDB_CRDT_MERGE_TS));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_deltas(&db1, 0u, recs, 2, &applied));
    TEST_ASSERT_EQUAL_UINT32(1u, (uint32_t)applied); /* deduped to one */
    TEST_ASSERT_TRUE(read_val(&db1, 44u, v, sizeof v));
    TEST_ASSERT_EQUAL_MEMORY("P", v, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db1));
}

/* AC2 / FR1: an exported delta carries the real db->hlc, not the tx counter. */
static void test_emit_carries_real_hlc(void)
{
    uint8_t slice[1024];
    size_t slice_len = 0;
    cdb_hlc hlc1;
    cdb_hlc emitted;

    open_peer(&db1, &cfg1, "emit", 1u);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db1, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db1, STORE, 5u, CDB_OP_INSERT, "data", 4u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_get_hlc(&db1, &hlc1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_export_slice(&db1, NULL, slice, sizeof slice, &slice_len));
    TEST_ASSERT_TRUE(slice_len >= 12u + 37u);

    /* Decode the first record's HLC (record starts at 12; hlc at +17/+25/+29). */
    emitted.physical = cdb_load_u64(slice + 12u + 17u, CDB_ORDER_BIG);
    emitted.logical = cdb_load_u32(slice + 12u + 25u, CDB_ORDER_BIG);
    emitted.peer_id = cdb_load_u32(slice + 12u + 29u, CDB_ORDER_BIG);

    TEST_ASSERT_EQUAL_INT(0, cdb_hlc_compare(emitted, hlc1)); /* real HLC, not faked */
    TEST_ASSERT_EQUAL_UINT32(1u, emitted.peer_id);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db1));
}

/* AC7 / F2: a multi-record transaction committed via the baton-expiry branch,
 * under replication, keeps every record on export+import (no collapsed clocks). */
static void test_baton_expiry_multirecord_survives(void)
{
    uint8_t slice[1024];
    size_t slice_len = 0, applied = 0;
    uint8_t v[4];

    open_peer(&db1, &cfg1, "batonA", 1u);
    open_peer(&db2, &cfg2, "batonB", 2u);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db1, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db1, STORE, 50u, CDB_OP_INSERT, "R0__", 4u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db1, STORE, 51u, CDB_OP_INSERT, "R1__", 4u));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db1, STORE, 52u, CDB_OP_INSERT, "R2__", 4u));
    g_apply_fail_busy = 1; /* force the baton-expiry commit branch */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db1));

    /* F2: the baton-expiry branch advanced the clock and the local version
     * vector (without the stamp it would stay at the open-time zero). */
    {
        cdb_crdt_vector vv;
        cdb_crdt_peer_entry pe;
        cdb_hlc hlc;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_get_hlc(&db1, &hlc));
        TEST_ASSERT_TRUE(hlc.physical > 0 || hlc.logical >= 3u); /* three sub-ticks */
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_get_crdt_vector(&db1, &vv));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crdt_vector_get(&vv, 1u, &pe));
        TEST_ASSERT_TRUE(pe.counter > 0u); /* advanced by the committed tx */
    }

    /* All three records are present locally after the rebase replay. */
    TEST_ASSERT_TRUE(read_val(&db1, 50u, v, sizeof v));
    TEST_ASSERT_EQUAL_MEMORY("R0__", v, 4);
    TEST_ASSERT_TRUE(read_val(&db1, 52u, v, sizeof v));
    TEST_ASSERT_EQUAL_MEMORY("R2__", v, 4);

    /* And all three survive export + import into a fresh peer (distinct clocks). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_export_slice(&db1, NULL, slice, sizeof slice, &slice_len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_slice(&db2, slice, slice_len, &applied));
    TEST_ASSERT_EQUAL_UINT32(3u, (uint32_t)applied);
    TEST_ASSERT_TRUE(read_val(&db2, 50u, v, sizeof v));
    TEST_ASSERT_EQUAL_MEMORY("R0__", v, 4);
    TEST_ASSERT_TRUE(read_val(&db2, 51u, v, sizeof v));
    TEST_ASSERT_EQUAL_MEMORY("R1__", v, 4);
    TEST_ASSERT_TRUE(read_val(&db2, 52u, v, sizeof v));
    TEST_ASSERT_EQUAL_MEMORY("R2__", v, 4);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db2));
}

/* AC12 / FR8: an imported delta is untrusted; malformed deltas are rejected
 * fail-closed (no crash, no OOB), and the database stays usable. */
static void test_import_rejects_malformed_delta(void)
{
    cdb_hlc h = {10u, 0u, 1u};
    cdb_crdt_delta_rec bad;
    cdb_crdt_delta_rec good;
    uint8_t v[4];
    size_t applied = 0;
    static uint8_t tiny[1];

    /* Unit-level: validation screens op, merge nibble, length, and NULL data. */
    bad = mk(60u, 7u, h, "x", 1u); /* base op 7 is not a known CDB_OP_* */
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_crdt_delta_validate(&bad));
    bad = mk(60u, CDB_CRDT_OP_PACK(CDB_OP_INSERT, 7u), h, "x", 1u); /* merge nibble 7 */
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_crdt_delta_validate(&bad));
    bad = mk(60u, CDB_OP_INSERT, h, tiny, (size_t)CDB_CRDT_MAX_DELTA_LEN + 1u); /* oversized */
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_crdt_delta_validate(&bad));
    bad = mk(60u, CDB_OP_INSERT, h, NULL, 4u); /* non-empty but NULL payload */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crdt_delta_validate(&bad));

    /* Engine-level: a malformed delta is rejected on import, fail-closed. */
    open_peer(&db1, &cfg1, "bad", 100u);
    bad = mk(60u, 7u, h, "x", 1u);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_db_crdt_import_deltas(&db1, 0u, &bad, 1, &applied));
    TEST_ASSERT_EQUAL_UINT32(0u, (uint32_t)applied);

    /* The database is still usable: a well-formed delta applies afterwards. */
    good = mk(61u, CDB_OP_INSERT, h, "OK__", 4u);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_crdt_import_deltas(&db1, 0u, &good, 1, &applied));
    TEST_ASSERT_EQUAL_UINT32(1u, (uint32_t)applied);
    TEST_ASSERT_TRUE(read_val(&db1, 61u, v, sizeof v));
    TEST_ASSERT_EQUAL_MEMORY("OK__", v, 4);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db1));
}

/* Durable-state value codecs round-trip (persistence-ready side store, #38). */
static void test_durable_state_codecs(void)
{
    cdb_hlc h = {0x1122334455667788ull, 0xAABBCCDDu, 0x01020304u};
    cdb_hlc back;
    uint8_t hbuf[CDB_CRDT_HLC_ENC_LEN];
    uint8_t pbuf[CDB_CRDT_PN_ENC_LEN];
    size_t len = 0;
    cdb_pn_counter c, dec;

    cdb_crdt_hlc_encode(h, hbuf);
    back = cdb_crdt_hlc_decode(hbuf);
    TEST_ASSERT_EQUAL_INT(0, cdb_hlc_compare(h, back));

    cdb_pn_counter_init(&c);
    cdb_pn_counter_inc(&c, 0u, 100u);
    cdb_pn_counter_inc(&c, 3u, 7u);
    cdb_pn_counter_dec(&c, 3u, 2u);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crdt_pn_encode(&c, pbuf, sizeof pbuf, &len));
    TEST_ASSERT_EQUAL_UINT32((uint32_t)CDB_CRDT_PN_ENC_LEN, (uint32_t)len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crdt_pn_decode(pbuf, len, &dec));
    TEST_ASSERT_EQUAL_INT64(cdb_pn_counter_val(&c), cdb_pn_counter_val(&dec));
    TEST_ASSERT_EQUAL_MEMORY(&c, &dec, sizeof c);

    /* Fail-closed on a short buffer / wrong length. */
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_crdt_pn_encode(&c, pbuf, 4u, &len));
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_crdt_pn_decode(pbuf, 4u, &dec));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_hlc_total_order_and_ticks);
    RUN_TEST(test_version_vector_dominance_and_concurrency);
    RUN_TEST(test_pn_counter_convergence);
    RUN_TEST(test_lww_document_field_merge);
    RUN_TEST(test_graph_link_aworset);
    RUN_TEST(test_replication_handshake_and_slice_wire_codec);
    RUN_TEST(test_db_multi_peer_replication_sync);
    RUN_TEST(test_export_skips_aborted_and_rolled_back);
    RUN_TEST(test_import_vector_advances_at_commit);
    RUN_TEST(test_convergence_order_independent);
    RUN_TEST(test_lww_resolves_higher_hlc);
    RUN_TEST(test_pn_counter_apply_nets);
    RUN_TEST(test_pn_counter_apply_nets_with_decrement);
    RUN_TEST(test_counter_rejects_bad_payload_len);
    RUN_TEST(test_slice_decode_rejects_corrupt_wire);
    RUN_TEST(test_aworset_add_wins);
    RUN_TEST(test_ts_dedup);
    RUN_TEST(test_emit_carries_real_hlc);
    RUN_TEST(test_baton_expiry_multirecord_survives);
    RUN_TEST(test_import_rejects_malformed_delta);
    RUN_TEST(test_durable_state_codecs);
    return UNITY_END();
}
