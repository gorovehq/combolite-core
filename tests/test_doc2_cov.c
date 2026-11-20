/* Second coverage set for cdb_doc (agent-authored, #18 increment 2): error,
 * overflow, patch and relocation branches the behavioural test_doc.c and the
 * first coverage set test_doc_cov.c miss.
 *
 * Covers: the nibblet-relocation callbacks cdb_doc_nib_moved and
 * cdb_doc_overflow_tail_moved (argument/store/key/old-address branches, driven
 * by constructing the public (entry,revision) index key of a real document);
 * the patch parser's malformed-operation branches (parse_op/validate_patch);
 * revision pruning that rewrites a delta as a checkpoint and frees the rest
 * (prune -> make_full/materialize -> free_from/release) via cdb_doc_set_keep;
 * patching and growing an overflow (multi-page) document (rewrite/write_chain/
 * split); schema set/get and schema-violation rejection; full-text create +
 * search; summary read-back and buffer-too-small; and the tombstone / delete-
 * reinsert / get-in-transaction edges. Spec 8 (document model), 14.9 (patches),
 * 14.15 (overflow), 8.3 (schema), 8.10/14.14 (full text).
 *
 * Every local is initialised at its declaration; NULL/negative paths pass the
 * value and assert the returned status without dereferencing a maybe-NULL
 * result (test code obeys the production-safety gate). Hermetic: all state in
 * the in-process fault environment; no network, no wall clock. */
#include <stdio.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_endian.h"
#include "cdb_doc.h"
#include "cdb_fts.h"
#include "cdb_faultenv.h"

#define FCAP (768u * 1024u)
#define PAGE_LOG2 10u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define DOC_MAX (2u * PAGE)

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 4096u];
static cdb_faultenv fe;
static cdb_env env;

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[4096];
static uint8_t record_buf[6u * PAGE];
static uint8_t cat_work[24u * 1024u];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static uint8_t doc_buffers[16u * PAGE];
static uint8_t doc_stage[16u * 1024u];
static uint8_t fts_buffers[8u * PAGE];
static cdb_fts_token fts_tokens[8u * PAGE]; /* >= cdb_fts_tokens_needed(PAGE, DOC_MAX) = 2*(DOC_MAX+PAGE) */
static cdb_db_config cfg;
static cdb_db db;

static uint8_t out[16u * PAGE];

typedef struct {
    uint8_t b[8u * PAGE];
    size_t n;
} docbody;

/* { 1: <str> } */
static docbody make_body(const char *s, size_t len)
{
    docbody d;
    cdb_value_writer w;
    memset(&d, 0, sizeof d);
    cdb_value_writer_init(&w, d.b, sizeof d.b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_string(&w, s, len);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    d.n = cdb_value_writer_len(&w);
    return d;
}

/* { 1: <str>, 2: <int> } — a two-field object, so a patch has a sorted-order
 * neighbour to copy past (rewrite's "fid > target" / "fid < target" arms). */
static docbody make_body2(const char *s, int64_t k)
{
    docbody d;
    cdb_value_writer w;
    memset(&d, 0, sizeof d);
    cdb_value_writer_init(&w, d.b, sizeof d.b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_string(&w, s, strlen(s));
    cdb_value_field(&w, 3);
    cdb_value_write_int(&w, k);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    d.n = cdb_value_writer_len(&w);
    return d;
}

/* A one-operation patch: set (value != NULL) or remove, at a field path. */
static docbody make_patch(const int64_t *path, unsigned depth, const char *value)
{
    docbody d;
    cdb_value_writer w;
    unsigned i = 0;
    memset(&d, 0, sizeof d);
    cdb_value_writer_init(&w, d.b, sizeof d.b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_array(&w);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, value ? CDB_PATCH_SET : CDB_PATCH_REMOVE);
    cdb_value_begin_array(&w);
    for (i = 0; i < depth; i++)
        cdb_value_write_int(&w, path[i]);
    cdb_value_end_array(&w);
    if (value)
        cdb_value_write_string(&w, value, strlen(value));
    cdb_value_end_array(&w);
    cdb_value_end_array(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    d.n = cdb_value_writer_len(&w);
    return d;
}

void setUp(void)
{
    cdb_faultenv_config c;
    memset(&c, 0, sizeof c);
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 4096;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
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
    cfg.fts_buffers = fts_buffers;
    cfg.fts_tokens = fts_tokens;
    cfg.fts_tokens_cap = sizeof fts_tokens / sizeof fts_tokens[0];
    cfg.doc_max = DOC_MAX;
    cfg.durability = CDB_DURABILITY_FULL;
}

void tearDown(void) {}

static cdb_status open_db(void)
{
    cdb_header h;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x7D, sizeof h.db_id);
    return cdb_db_open(&db, &env, "dc2", &cfg, &h);
}

static uint64_t make_pool(const char *name)
{
    uint64_t id = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, name, strlen(name), CDB_MODEL_DOCUMENT, &id));
    return id;
}

/* Builds the 16-byte (entry, revision) big-endian index key a document's
 * revision is stored under (cdb_doc's k_rev), so a relocation callback can be
 * driven with a key it will actually find. */
static void rev_key(uint8_t k[16], uint64_t entry, uint64_t rev)
{
    cdb_store_u64(k, entry, CDB_ORDER_BIG);
    cdb_store_u64(k + 8, rev, CDB_ORDER_BIG);
}

/* Counts the entries a transaction walk reports (cdb_doc_tx_entries). */
static cdb_status count_entry(void *ctx, uint64_t entry, size_t staged_off);

/* -------------------------------------------- 1. nib_moved callback paths */

static void test_nib_moved_paths(void)
{
    uint64_t pool = 0, e = 0;
    uint8_t key[16];
    docbody v = make_body("nm", 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("nm");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* oklen != 16 is reported as corruption. */
    rev_key(key, e, 1);
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_doc_nib_moved(&db, pool, key, 15, 100, 200));
    /* a store that is not a document pool: the record is dropped. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_nib_moved(&db, 987654, key, 16, 100, 200));
    /* a key with no such revision: dropped. */
    {
        uint8_t miss[16];
        rev_key(miss, 55555, 9);
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_nib_moved(&db, pool, miss, 16, 100, 200));
    }
    /* the revision exists, but the old address does not match its current
     * one, so the move does not apply (cur != old_addr). */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_nib_moved(&db, pool, key, 16, 0xDEADBEEF, 0xBEEF));
    /* the document is still intact and readable. */
    {
        size_t len = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
        TEST_ASSERT_EQUAL_UINT(v.n, len);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 2. overflow_tail_moved paths */

static void test_overflow_tail_moved_paths(void)
{
    uint64_t pool = 0, small = 0, big = 0, bigs = 0;
    size_t i = 0, len = 0;
    uint8_t key[16];
    static char bigstr[PAGE + PAGE / 2u];
    docbody sv = make_body("one-page", 8);
    docbody bv;
    for (i = 0; i < sizeof bigstr; i++)
        bigstr[i] = (char)('A' + (int)(i % 26u));
    bv = make_body(bigstr, sizeof bigstr);

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("ov");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, sv.b, sv.n, &small));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, bv.b, bv.n, &big));
    /* an overflow document WITH a summary: its revision page carries the
     * summary inline, so the tail-move parse walks past it (summary branch). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "a-summary-here", 14, bv.b, bv.n, &bigs));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* oklen != 16 is corruption. */
    rev_key(key, big, 1);
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_doc_overflow_tail_moved(&db, pool, key, 8, 1, 2));
    /* a store that is not a document pool: dropped. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_overflow_tail_moved(&db, 987654, key, 16, 1, 2));
    /* a key with no such revision: dropped. */
    {
        uint8_t miss[16];
        rev_key(miss, 44444, 7);
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_overflow_tail_moved(&db, pool, miss, 16, 1, 2));
    }
    /* a revision that has no overflow (the one-page document): there is no
     * tail to move, so NOT_FOUND after the envelope is read. */
    {
        uint8_t skey[16];
        rev_key(skey, small, 1);
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_overflow_tail_moved(&db, pool, skey, 16, 1, 2));
    }
    /* the overflow document's revision does carry a tail, but the supplied
     * old address is not the one stored, so the move does not apply (the
     * envelope/overflow/summary parsing runs, then the address check fails). */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND,
                          cdb_doc_overflow_tail_moved(&db, pool, key, 16, 0xFACEFEEDu, 0xC0FFEEu));
    /* the summary-carrying overflow document: the parse walks past the inline
     * summary before the (mismatched) address check. */
    {
        uint8_t skey[16];
        rev_key(skey, bigs, 1);
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND,
                              cdb_doc_overflow_tail_moved(&db, pool, skey, 16, 0x1234u, 0x5678u));
    }
    /* the big document is still intact end to end. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, big, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(bv.n, len);
    TEST_ASSERT_EQUAL_MEMORY(bv.b, out, len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 3. malformed patch operations */

/* Writes a raw patch body with a writer callback, so each malformed shape can
 * be constructed exactly, then asserts cdb_doc_patch rejects it with
 * CDB_E_INVALID_ARG (the patch is validated when journaled; nothing lands). */
static void expect_bad_patch(uint64_t pool, uint64_t e, const uint8_t *p, size_t n)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_doc_patch(&db, pool, e, p, n));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));
}

static void test_patch_malformed(void)
{
    uint64_t pool = 0, e = 0;
    cdb_value_writer w;
    uint8_t buf[256];
    unsigned i = 0;
    docbody v = make_body("pm", 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("pm");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* top level not an array -> INVALID_ARG */
    cdb_value_writer_init(&w, buf, sizeof buf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_int(&w, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_bad_patch(pool, e, buf, cdb_value_writer_len(&w));

    /* an operation that is not an array */
    cdb_value_writer_init(&w, buf, sizeof buf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, 7); /* op is an int, not an [ ... ] */
    cdb_value_end_array(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_bad_patch(pool, e, buf, cdb_value_writer_len(&w));

    /* op array whose first element is not an int */
    cdb_value_writer_init(&w, buf, sizeof buf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_array(&w);
    cdb_value_begin_array(&w);
    cdb_value_write_string(&w, "x", 1); /* op code should be an int */
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, 1);
    cdb_value_end_array(&w);
    cdb_value_write_string(&w, "v", 1);
    cdb_value_end_array(&w);
    cdb_value_end_array(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_bad_patch(pool, e, buf, cdb_value_writer_len(&w));

    /* op array whose second element (path) is not an array */
    cdb_value_writer_init(&w, buf, sizeof buf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_array(&w);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, CDB_PATCH_SET);
    cdb_value_write_int(&w, 5); /* path should be an array */
    cdb_value_write_string(&w, "v", 1);
    cdb_value_end_array(&w);
    cdb_value_end_array(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_bad_patch(pool, e, buf, cdb_value_writer_len(&w));

    /* empty path (depth 0) */
    {
        docbody p = make_patch(NULL, 0, "v");
        expect_bad_patch(pool, e, p.b, p.n);
    }
    /* negative path segment */
    {
        int64_t path[1] = { -1 };
        docbody p = make_patch(path, 1, "v");
        expect_bad_patch(pool, e, p.b, p.n);
    }
    /* non-integer path segment */
    cdb_value_writer_init(&w, buf, sizeof buf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_array(&w);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, CDB_PATCH_SET);
    cdb_value_begin_array(&w);
    cdb_value_write_string(&w, "k", 1); /* a path segment must be an int */
    cdb_value_end_array(&w);
    cdb_value_write_string(&w, "v", 1);
    cdb_value_end_array(&w);
    cdb_value_end_array(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_bad_patch(pool, e, buf, cdb_value_writer_len(&w));

    /* a set with no value */
    cdb_value_writer_init(&w, buf, sizeof buf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_array(&w);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, CDB_PATCH_SET);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, 1);
    cdb_value_end_array(&w);
    cdb_value_end_array(&w);
    cdb_value_end_array(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_bad_patch(pool, e, buf, cdb_value_writer_len(&w));

    /* a set with a trailing element after the value */
    cdb_value_writer_init(&w, buf, sizeof buf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_array(&w);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, CDB_PATCH_SET);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, 1);
    cdb_value_end_array(&w);
    cdb_value_write_string(&w, "v", 1);
    cdb_value_write_int(&w, 99); /* trailing */
    cdb_value_end_array(&w);
    cdb_value_end_array(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_bad_patch(pool, e, buf, cdb_value_writer_len(&w));

    /* a remove with a trailing element */
    cdb_value_writer_init(&w, buf, sizeof buf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_array(&w);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, CDB_PATCH_REMOVE);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, 1);
    cdb_value_end_array(&w);
    cdb_value_write_int(&w, 7); /* remove takes no value */
    cdb_value_end_array(&w);
    cdb_value_end_array(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_bad_patch(pool, e, buf, cdb_value_writer_len(&w));

    /* a path deeper than MAX_PATH (16) */
    cdb_value_writer_init(&w, buf, sizeof buf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_array(&w);
    cdb_value_begin_array(&w);
    cdb_value_write_int(&w, CDB_PATCH_SET);
    cdb_value_begin_array(&w);
    for (i = 0; i < 17u; i++)
        cdb_value_write_int(&w, (int64_t)i + 1);
    cdb_value_end_array(&w);
    cdb_value_write_string(&w, "v", 1);
    cdb_value_end_array(&w);
    cdb_value_end_array(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    expect_bad_patch(pool, e, buf, cdb_value_writer_len(&w));

    /* the document never changed. */
    {
        size_t len = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
        TEST_ASSERT_EQUAL_UINT(v.n, len);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 4. prune: delta -> checkpoint */

static cdb_status replace1(uint64_t pool, uint64_t e, const char *s)
{
    docbody v = make_body(s, strlen(s));
    cdb_status s1 = cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT);
    if (s1 != CDB_OK)
        return s1;
    s1 = cdb_doc_replace(&db, pool, e, NULL, 0, v.b, v.n);
    if (s1 != CDB_OK) {
        (void)cdb_tx_abort(&db);
        return s1;
    }
    return cdb_tx_commit(&db);
}

static void test_prune_make_full(void)
{
    uint64_t pool = 0, e = 0;
    size_t len = 0;
    docbody v0 = make_body("r0", 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("pr");

    /* Build a delta chain while keep is 0: original + several deltas. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "sum", 3, v0.b, v0.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, replace1(pool, e, "r1"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, replace1(pool, e, "r2"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, replace1(pool, e, "r3"));

    /* Now keep only the last two revisions; the next change prunes, which
     * rewrites the oldest kept revision (a delta) as a full checkpoint and
     * frees the revisions before it. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_set_keep(&db, pool, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, replace1(pool, e, "r4"));

    /* current reads the newest body. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    {
        docbody want = make_body("r4", 2);
        TEST_ASSERT_EQUAL_UINT(want.n, len);
        TEST_ASSERT_EQUAL_MEMORY(want.b, out, len);
    }
    /* the kept checkpoint (revision 4) still materialises correctly. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 4, out, sizeof out, &len, NULL, 0, NULL, NULL));
    {
        docbody want = make_body("r3", 2);
        TEST_ASSERT_EQUAL_UINT(want.n, len);
        TEST_ASSERT_EQUAL_MEMORY(want.b, out, len);
    }
    /* a pruned-away old revision can no longer be materialised: the head's
     * chain accounting still implies it, but its page and key are gone, so
     * the read fails closed (rev_lid reports the severed chain). */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_doc_get(&db, pool, e, 1, out, sizeof out, &len, NULL, 0, NULL, NULL));

    /* Deleting with keep set removes the row and its kept revisions. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_delete(&db, pool, e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 5. patch checkpoint via keep */

/* With keep set, a patch is materialised and stored as a full checkpoint
 * (apply_patch on the checkpoint path), exercising set/remove/nested rewrite. */
static void test_patch_checkpoint(void)
{
    uint64_t pool = 0, e = 0;
    size_t len = 0;
    docbody v = make_body2("hello", 5);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("pc");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_set_keep(&db, pool, 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* set a new field 2 (inserted before field 3 in sorted order) */
    {
        int64_t path[1] = { 2 };
        docbody p = make_patch(path, 1, "world");
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, pool, e, p.b, p.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    /* set a nested object at a new deep path (write_chain builds the chain) */
    {
        int64_t path[2] = { 9, 4 };
        docbody p = make_patch(path, 2, "deep");
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, pool, e, p.b, p.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    /* replace an existing field 1 with a scalar through a non-object */
    {
        int64_t path[1] = { 1 };
        docbody p = make_patch(path, 1, "changed");
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, pool, e, p.b, p.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    /* remove field 3 (a present field at the end of the path) */
    {
        int64_t path[1] = { 3 };
        docbody p = make_patch(path, 1, NULL);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, pool, e, p.b, p.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    /* remove a field that does not exist: a no-op, still valid */
    {
        int64_t path[1] = { 77 };
        docbody p = make_patch(path, 1, NULL);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, pool, e, p.b, p.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    /* the document still reads back. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_TRUE(len > 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 6. patch/grow an overflow doc */

static void test_overflow_patch(void)
{
    uint64_t pool = 0, e = 0;
    size_t i = 0, len = 0;
    static char bigstr[PAGE + PAGE / 3u];
    docbody bv;
    for (i = 0; i < sizeof bigstr; i++)
        bigstr[i] = (char)('a' + (int)(i % 26u));
    bv = make_body(bigstr, sizeof bigstr);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("op");

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, bv.b, bv.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* patch a new field onto the (overflowing) document: the result is
     * rewritten and re-split across the overflow chain. */
    {
        int64_t path[1] = { 2 };
        docbody p = make_patch(path, 1, "tag");
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, pool, e, p.b, p.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    /* replace the whole overflow body with a different large body. */
    {
        static char big2[PAGE + PAGE / 2u];
        docbody rv;
        for (i = 0; i < sizeof big2; i++)
            big2[i] = (char)('Z' - (int)(i % 26u));
        rv = make_body(big2, sizeof big2);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_replace(&db, pool, e, NULL, 0, rv.b, rv.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
        TEST_ASSERT_EQUAL_UINT(rv.n, len);
        TEST_ASSERT_EQUAL_MEMORY(rv.b, out, len);
    }
    /* a body larger than doc_max is refused with OVERFLOW; nothing lands. */
    {
        static char huge[3u * PAGE];
        docbody hv;
        for (i = 0; i < sizeof huge; i++)
            huge[i] = 'q';
        hv = make_body(huge, sizeof huge);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_doc_replace(&db, pool, e, NULL, 0, hv.b, hv.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));
    }
    /* a patch whose body fits as a delta, but whose applied result overflows
     * the document buffer, is refused with OVERFLOW (apply_patch's
     * buffer-too-small -> overflow arm). */
    {
        static char fat[PAGE + 200u];
        int64_t path[1] = { 7 };
        docbody p;
        for (i = 0; i < sizeof fat; i++)
            fat[i] = 'Z';
        fat[sizeof fat - 1u] = '\0';
        p = make_patch(path, 1, fat);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_doc_patch(&db, pool, e, p.b, p.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 7. schema set/get/violation */

/* { } — an empty object schema (accepts everything, clears a schema). */
static docbody make_open_schema(void)
{
    docbody d;
    cdb_value_writer w;
    memset(&d, 0, sizeof d);
    cdb_value_writer_init(&w, d.b, sizeof d.b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    d.n = cdb_value_writer_len(&w);
    return d;
}

static void test_schema(void)
{
    uint64_t pool = 0, e = 0;
    uint32_t version = 0, current = 0;
    size_t slen = 0;
    static uint8_t sbuf[512];
    docbody open_s = make_open_schema();
    docbody v = make_body("sx", 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("sc");

    /* An open schema is accepted and becomes a version. */
    version = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_set_schema(&db, pool, open_s.b, open_s.n, &version));
    TEST_ASSERT_TRUE(version >= 1);

    /* get the current schema (version 0) and a specific version. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get_schema(&db, pool, 0, sbuf, sizeof sbuf, &slen, &current));
    TEST_ASSERT_EQUAL_UINT32(version, current);
    TEST_ASSERT_TRUE(slen >= 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get_schema(&db, pool, version, sbuf, sizeof sbuf, &slen, &current));

    /* an unknown schema version is not found. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND,
                          cdb_doc_get_schema(&db, pool, version + 99u, sbuf, sizeof sbuf, &slen, &current));

    /* a document still inserts under the open schema. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 8. full text create + search */

static cdb_fts_config fts_cfg(void)
{
    cdb_fts_config c;
    memset(&c, 0, sizeof c);
    c.paths[0].ids[0] = 1;
    c.paths[0].depth = 1;
    c.npaths = 1;
    c.summary = 1;
    return c;
}

static void test_full_text(void)
{
    uint64_t pool = 0, e = 0;
    uint64_t gone = 0;
    size_t n = 0;
    cdb_fts_hit hits[8];
    cdb_fts_config c = fts_cfg();
    docbody a = make_body("alpha beta gamma", 16);
    docbody b = make_body("beta delta", 10);
    docbody dead = make_body("deadword", 8);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("ft");

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "one", 3, a.b, a.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "two", 3, b.b, b.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "x", 1, dead.b, dead.n, &gone));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    /* delete one document before building the index, so the index-build loop
     * walks past a tombstone (the skip-deleted branch). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_delete(&db, pool, gone));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* searching before an index exists is a clean not-found. */
    n = 7;
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_search(&db, pool, "beta", 4, CDB_FTS_ANY, hits, 8, &n));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_create_full_text(&db, pool, &c));
    /* a second create is refused. */
    TEST_ASSERT_EQUAL_INT(CDB_E_EXISTS, cdb_doc_create_full_text(&db, pool, &c));
    /* the deleted document never entered the index. */
    n = 7;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_search(&db, pool, "deadword", 8, CDB_FTS_ANY, hits, 8, &n));
    TEST_ASSERT_EQUAL_UINT(0u, (unsigned)n);

    n = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_search(&db, pool, "beta", 4, CDB_FTS_ANY, hits, 8, &n));
    TEST_ASSERT_EQUAL_UINT(2u, (unsigned)n);
    n = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_search(&db, pool, "alpha gamma", 11, CDB_FTS_ALL, hits, 8, &n));
    TEST_ASSERT_EQUAL_UINT(1u, (unsigned)n);
    n = 7;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_search(&db, pool, "unheardof", 9, CDB_FTS_ANY, hits, 8, &n));
    TEST_ASSERT_EQUAL_UINT(0u, (unsigned)n);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 9. summary read-back + edges */

static void test_summary_and_info(void)
{
    uint64_t pool = 0, e = 0;
    size_t len = 0, slen = 0;
    char summary[32];
    cdb_doc_info info;
    docbody v = make_body("withsum", 7);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("su");
    memset(&info, 0, sizeof info);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "a-summary", 9, v.b, v.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* read body + summary + info together. */
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, summary, sizeof summary, &slen, &info));
    TEST_ASSERT_EQUAL_UINT(9u, (unsigned)slen);
    TEST_ASSERT_EQUAL_MEMORY("a-summary", summary, 9);
    TEST_ASSERT_EQUAL_UINT(1u, (unsigned)info.revision);
    TEST_ASSERT_EQUAL_UINT8(CDB_REV_ORIGINAL, info.kind);

    /* a summary buffer too small reports the needed length and can retry. */
    {
        char tiny[4];
        size_t need = 0;
        TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL,
                              cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, tiny, sizeof tiny, &need, NULL));
        TEST_ASSERT_EQUAL_UINT(9u, (unsigned)need);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 10. tombstone + delete edges */

static void test_delete_reinsert(void)
{
    uint64_t pool = 0, e = 0, e2 = 0;
    size_t len = 0;
    int live = 1;
    docbody v1 = make_body("first", 5);
    docbody v2 = make_body("second", 6);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("dr");

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v1.b, v1.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* delete it: a tombstone revision; reads are NOT_FOUND. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_delete(&db, pool, e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));

    /* the tombstone revision read by number is also not found. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_get(&db, pool, e, 2, out, sizeof out, &len, NULL, 0, NULL, NULL));
    /* but the original revision still reads (history stays). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 1, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(v1.n, len);

    /* replace / patch / delete of a deleted document are NOT_FOUND. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_replace(&db, pool, e, NULL, 0, v2.b, v2.n));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_delete(&db, pool, e));
    {
        int64_t path[1] = { 1 };
        docbody p = make_patch(path, 1, "x");
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_patch(&db, pool, e, p.b, p.n));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));

    /* insert a fresh document: it gets its own entry ID. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v2.b, v2.n, &e2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_TRUE(e2 != e);

    /* live reports deleted vs present. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_live_in_tx(&db, pool, e, &live));
    TEST_ASSERT_FALSE(live);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_live_in_tx(&db, pool, e2, &live));
    TEST_ASSERT_TRUE(live);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 11. get-in-transaction edges */

static void test_get_in_tx(void)
{
    uint64_t pool = 0, e = 0;
    size_t len = 0;
    int live = 0;
    uint32_t schema = 0;
    docbody v = make_body("staged", 6);
    docbody v2 = make_body("restaged", 8);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("gt");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e));

    /* read the document as the open transaction sees it (before commit). */
    len = 0;
    live = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_doc_get_in_tx(&db, pool, e, CDB_STAGE_OFF_NONE, out, sizeof out, &len, &live, &schema));
    TEST_ASSERT_TRUE(live);
    TEST_ASSERT_EQUAL_UINT(v.n, len);

    /* replace within the same transaction, then read the staged state. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_replace(&db, pool, e, NULL, 0, v2.b, v2.n));
    len = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_doc_get_in_tx(&db, pool, e, CDB_STAGE_OFF_NONE, out, sizeof out, &len, &live, &schema));
    TEST_ASSERT_TRUE(live);
    TEST_ASSERT_EQUAL_UINT(v2.n, len);

    /* an unknown entry is not live. */
    live = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_doc_get_in_tx(&db, pool, 9999, CDB_STAGE_OFF_NONE, out, sizeof out, &len, &live, &schema));
    TEST_ASSERT_FALSE(live);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 12. nested-object rewrite */

static docbody make_patch_str_at(const int64_t *path, unsigned depth, const char *value)
{
    return make_patch(path, depth, value);
}

static void test_rewrite_nested(void)
{
    uint64_t pool = 0, e = 0;
    size_t len = 0;
    docbody v = make_body2("base", 1); /* { 1:"base", 3:1 } */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("rn");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_set_keep(&db, pool, 1)); /* patches checkpoint: rewrite runs */

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* create a nested object at field 5: { 5: { 4: "leaf" } } (write_chain). */
    {
        int64_t path[2] = { 5, 4 };
        docbody p = make_patch_str_at(path, 2, "leaf");
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, pool, e, p.b, p.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    /* add a second field into the SAME existing nested object 5 (the rewrite
     * recurses into the object at field 5: v.type == OBJECT branch). */
    {
        int64_t path[2] = { 5, 6 };
        docbody p = make_patch_str_at(path, 2, "two");
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, pool, e, p.b, p.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    /* remove a present field inside the nested object (remove at path end). */
    {
        int64_t path[2] = { 5, 4 };
        docbody p = make_patch_str_at(path, 2, NULL);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, pool, e, p.b, p.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    /* remove through a non-object (field 3 is an int): a no-op that keeps it. */
    {
        int64_t path[2] = { 3, 9 };
        docbody p = make_patch_str_at(path, 2, NULL);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, pool, e, p.b, p.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    /* set THROUGH a non-object field 3: it is replaced by a new chain. */
    {
        int64_t path[2] = { 3, 9 };
        docbody p = make_patch_str_at(path, 2, "nowobj");
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, pool, e, p.b, p.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_TRUE(len > 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ------------------------------------------ 13. apply_change checkpoint/delete */

static void test_apply_change_branches(void)
{
    uint64_t pool = 0, e = 0;
    size_t len = 0;
    unsigned i = 0;
    char txt[8];
    docbody v0 = make_body("c0", 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("ac");

    /* keep == 0: replace many times. The chain reaches checkpoint_every and a
     * replace is stored whole as a checkpoint (not a delta), carrying the
     * current summary forward because the replace gives none. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "keepsum", 7, v0.b, v0.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    for (i = 0; i < 40u; i++) {
        docbody v;
        memset(txt, 0, sizeof txt);
        txt[0] = 'v';
        txt[1] = (char)('0' + (int)(i % 10u));
        v = make_body(txt, 2);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_replace(&db, pool, e, NULL, 0, v.b, v.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    /* the summary survived the checkpoints. */
    {
        char summary[16];
        size_t slen = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK,
                              cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, summary, sizeof summary, &slen, NULL));
        TEST_ASSERT_EQUAL_UINT(7u, (unsigned)slen);
        TEST_ASSERT_EQUAL_MEMORY("keepsum", summary, 7);
    }

    /* delete without keep leaves a readable tombstone + history. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_delete(&db, pool, e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    /* an early, still-present revision materialises through its delta chain. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 1, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(v0.n, len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* --------------------------------------- 14. release an overflow revision */

static void test_release_overflow(void)
{
    uint64_t pool = 0, e = 0;
    size_t i = 0, len = 0;
    static char b1[PAGE + PAGE / 2u];
    static char b2[PAGE + PAGE / 3u];
    docbody v1;
    docbody v2;
    for (i = 0; i < sizeof b1; i++)
        b1[i] = (char)('a' + (int)(i % 26u));
    for (i = 0; i < sizeof b2; i++)
        b2[i] = (char)('A' + (int)(i % 26u));
    v1 = make_body(b1, sizeof b1);
    v2 = make_body(b2, sizeof b2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("ro");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_set_keep(&db, pool, 1));

    /* insert then replace an overflow document with keep 1: the prune frees
     * the old overflow revision, exercising release()'s chain-free branch. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v1.b, v1.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_replace(&db, pool, e, NULL, 0, v2.b, v2.n));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(v2.n, len);
    TEST_ASSERT_EQUAL_MEMORY(v2.b, out, len);
    /* deleting with keep frees the kept overflow revision too. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_delete(&db, pool, e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ------------------------------------- 15. compaction relocates records */

/* Builds fragmentation (many small revisions as nibblets plus an overflow
 * document with a small tail), frees some, then compacts: the pager moves the
 * survivors down and tells their owner, driving cdb_doc_nib_moved and
 * cdb_doc_overflow_tail_moved on their move (happy) paths. */
#define NDOCS 60u
static void test_compact_relocation(void)
{
    uint64_t pool = 0, big = 0, ids[NDOCS];
    size_t i = 0, len = 0;
    uint64_t moved = 0, reclaimed = 0;
    static char bigstr[2u * PAGE - 200u]; /* near doc_max: a multi-page overflow chain */
    docbody bv;
    for (i = 0; i < sizeof bigstr; i++)
        bigstr[i] = (char)('a' + (int)(i % 26u));
    bv = make_body(bigstr, sizeof bigstr);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("cp");
    /* keep only the latest revision, so deleting a document frees its
     * revision nibblet outright (rather than leaving a tombstone), which
     * empties out the nibblet pages the survivors still sit on. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_set_keep(&db, pool, 1));

    /* many tiny documents: their small revisions pack into nibblet pages. */
    for (i = 0; i < NDOCS; i++) {
        char t[4];
        docbody v;
        t[0] = 'x';
        t[1] = (char)('a' + (int)(i % 26u));
        t[2] = (char)('0' + (int)(i % 10u));
        v = make_body(t, 3);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "s", 1, v.b, v.n, &ids[i]));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    /* a large multi-page overflow document with a summary. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "big-summary", 11, bv.b, bv.n, &big));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));

    /* delete most of the tiny documents, leaving a sparse scatter of
     * survivors, so the nibblet pages fall well under half full. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    for (i = 0; i < NDOCS; i++)
        if (i % 7u != 0u)
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_delete(&db, pool, ids[i]));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* reconcile folds the journal in and (flush_pools) merges the
     * under-half-full nibblet pages, moving the surviving revision records
     * and telling the document store, which updates its indexes. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));

    /* compact the archive too (moves live pages down). */
    for (i = 0; i < 8u; i++) {
        moved = 0;
        reclaimed = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_compact(&db, 128, &moved, &reclaimed));
        if (moved == 0 && reclaimed == 0)
            break;
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));

    /* the big document and every survivor still read back verbatim. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, big, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(bv.n, len);
    TEST_ASSERT_EQUAL_MEMORY(bv.b, out, len);
    for (i = 0; i < NDOCS; i += 7u) {
        len = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, ids[i], 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
        TEST_ASSERT_TRUE(len > 0);
    }
    /* survive a reopen (indexes rebuilt from the relocated records). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, big, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(bv.n, len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ------------------------------------- 16. recovery replays doc changes */

/* Commits varied document changes durably, then reboots the environment as a
 * killed process would (no clean close, so no reconciliation). Reopening
 * replays the journal, re-running the document apply for each change
 * (apply_change on the recovery path, materialising deltas and reading
 * overflow revisions), and every document must come back. */
static void test_doc_recovery(void)
{
    uint64_t pool = 0, e1 = 0, e2 = 0, ebig = 0;
    size_t i = 0, len = 0;
    static char bigstr[PAGE + PAGE / 2u];
    docbody a = make_body("alpha", 5);
    docbody b = make_body("bravo", 5);
    docbody bv;
    for (i = 0; i < sizeof bigstr; i++)
        bigstr[i] = (char)('m' + (int)(i % 13u));
    bv = make_body(bigstr, sizeof bigstr);

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("rc");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "s1", 2, a.b, a.n, &e1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "s2", 2, b.b, b.n, &e2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, bv.b, bv.n, &ebig));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    /* a second durable transaction: replace (delta) and a patch. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_replace(&db, pool, e1, NULL, 0, b.b, b.n));
    {
        int64_t path[1] = { 2 };
        docbody p = make_patch(path, 1, "patched");
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, pool, e2, p.b, p.n));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* kill the process (no close -> no reconcile) and restart. */
    cdb_faultenv_reboot(&fe);

    /* reopen without a create header: recovery replays the journal. */
    {
        cdb_header h;
        memset(&h, 0, sizeof h);
        h.order = CDB_ORDER_LITTLE;
        h.layout_flags = CDB_LAYOUT_ADDR64;
        h.default_page_log2 = (uint8_t)PAGE_LOG2;
        memset(h.db_id, 0x7D, sizeof h.db_id);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "dc2", &cfg, &h));
    }
    /* every document survived recovery. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e1, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(b.n, len);
    TEST_ASSERT_EQUAL_MEMORY(b.b, out, len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, ebig, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(bv.n, len);
    TEST_ASSERT_EQUAL_MEMORY(bv.b, out, len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e2, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_TRUE(len > 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ------------------------------------- 17. staged-state overflow (replay_tx) */

/* A schema'd pool caches each changed document in doc_stage. With a tiny
 * stage, a transaction that changes several documents overflows it, and a
 * subsequent in-transaction read rebuilds the document from the journal
 * (replay_tx's journal-walk path) instead of the stage. */
static void test_stage_overflow(void)
{
    uint64_t pool = 0, e1 = 0, e2 = 0, e3 = 0;
    size_t i = 0, len = 0;
    int live = 0;
    uint32_t schema = 0;
    docbody open_s = make_open_schema();
    docbody v = make_body("stageme", 7);

    /* reopen the environment with a deliberately tiny document stage. */
    cfg.doc_stage_size = 96;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("so");
    {
        uint32_t version = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_set_schema(&db, pool, open_s.b, open_s.n, &version));
    }

    /* commit e1 and e2 first, so a later transaction replays over a
     * committed base state (materialised, then this tx's records applied). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    /* overflow the tiny stage with fresh inserts. */
    for (i = 0; i < 8u; i++) {
        uint64_t junk = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &junk));
    }
    /* a fresh insert carrying a summary, within the overflowed transaction:
     * replaying its journal record exercises the summary arm. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, "stage-summary", 13, v.b, v.n, &e3));
    /* change the committed e1 within this (overflowed) transaction: replace
     * (with a summary) then patch. A read now rebuilds e1 by replaying these
     * journal records over the committed base. */
    {
        docbody v2 = make_body("replacedstage", 13);
        int64_t path[1] = { 9 };
        docbody p = make_patch(path, 1, "p");
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_replace(&db, pool, e1, "e1-sum", 6, v2.b, v2.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, pool, e1, p.b, p.n));
    }
    /* read e3 (summary insert) back under overflow: its summary is replayed. */
    {
        char summary[20];
        size_t slen = 0;
        len = 0;
        live = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK,
                              cdb_doc_get_in_tx(&db, pool, e3, CDB_STAGE_OFF_NONE, out, sizeof out, &len, &live, &schema));
        TEST_ASSERT_TRUE(live);
        (void)summary;
        (void)slen;
    }
    live = 0;
    len = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_doc_get_in_tx(&db, pool, e1, CDB_STAGE_OFF_NONE, out, sizeof out, &len, &live, &schema));
    TEST_ASSERT_TRUE(live);
    TEST_ASSERT_TRUE(len > 0);
    /* e2 is still live and read from committed state under overflow. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_live_in_tx(&db, pool, e2, &live));
    TEST_ASSERT_TRUE(live);
    /* delete e1 within the transaction, then a read sees it gone (the replay
     * DELETE arm). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_delete(&db, pool, e1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_live_in_tx(&db, pool, e1, &live));
    TEST_ASSERT_FALSE(live);
    /* walking the transaction's entries reads them back from the journal
     * (tx_entries' overflow path). */
    {
        unsigned seen = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_tx_entries(&db, pool, count_entry, &seen));
        TEST_ASSERT_TRUE(seen >= 3u);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* --------------------------------------- 17b. tx_entries over the stage */

static cdb_status count_entry(void *ctx, uint64_t entry, size_t staged_off)
{
    unsigned *n = (unsigned *)ctx;
    (void)entry;
    (void)staged_off;
    if (n != NULL)
        (*n)++;
    return CDB_OK;
}

static void test_tx_entries_staged(void)
{
    uint64_t pool = 0, e = 0;
    unsigned seen = 0;
    docbody open_s = make_open_schema();
    docbody v = make_body("te", 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("te");
    {
        uint32_t version = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_set_schema(&db, pool, open_s.b, open_s.n, &version));
    }

    /* outside a transaction there is nothing to walk. */
    seen = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_tx_entries(&db, pool, count_entry, &seen));
    TEST_ASSERT_EQUAL_UINT(0u, seen);

    /* a few staged changes fit the (default) stage: the staged walk sees them. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e));
    seen = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_tx_entries(&db, pool, count_entry, &seen));
    TEST_ASSERT_TRUE(seen >= 2u);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ------------------------------------- 18. put_body / read edge errors */

static void test_edge_errors(void)
{
    uint64_t pool = 0, e = 0;
    size_t len = 0;
    int live = 1;
    uint8_t intbody[8];
    cdb_value_writer w;
    docbody v = make_body("edge", 4);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("ee");

    /* a document change outside a transaction is refused. */
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    /* a body that is a valid value but not an object is rejected. */
    cdb_value_writer_init(&w, intbody, sizeof intbody, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_int(&w, 42);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_doc_insert(&db, pool, NULL, 0, intbody, cdb_value_writer_len(&w), &e));
    /* a NULL body is rejected. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_doc_insert(&db, pool, NULL, 0, NULL, 4, &e));
    /* summary_len without a summary pointer is rejected. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_doc_insert(&db, pool, NULL, 5, v.b, v.n, &e));
    /* a summary that is not valid UTF-8 is rejected. */
    {
        char bad[3];
        bad[0] = (char)0xFF;
        bad[1] = (char)0xFE;
        bad[2] = (char)0xFD;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_doc_insert(&db, pool, bad, sizeof bad, v.b, v.n, &e));
    }
    /* a good insert lands. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* a revision beyond the head is not found. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_get(&db, pool, e, 99, out, sizeof out, &len, NULL, 0, NULL, NULL));

    /* head / live / next_live of an unknown store report it cleanly. */
    {
        uint64_t rev = 0;
        int l2 = 1;
        TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_doc_head(&db, 765432, e, &rev, &l2));
    }
    TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_doc_live_in_tx(&db, 765432, e, &live));
    {
        uint64_t cur = 0;
        int done = 1;
        TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_doc_next_live(&db, 765432, 0, &cur, &done));
    }
    /* set_keep on an unknown store is reported. */
    TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_doc_set_keep(&db, 765432, 1));

    /* replace / patch / delete edges, inside a transaction. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    {
        int64_t path[1] = { 1 };
        docbody p = make_patch(path, 1, "x");
        /* entry 0 and an entry past the allocated range are not found. */
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_replace(&db, pool, 0, NULL, 0, v.b, v.n));
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_replace(&db, pool, 999999, NULL, 0, v.b, v.n));
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_patch(&db, pool, 0, p.b, p.n));
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_patch(&db, pool, 999999, p.b, p.n));
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_delete(&db, pool, 0));
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_delete(&db, pool, 999999));
        /* on an unknown store, the pool lookup fails. */
        TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_doc_replace(&db, 765432, e, NULL, 0, v.b, v.n));
        TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, 765432, e, p.b, p.n));
        TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, cdb_doc_delete(&db, 765432, e));
    }
    /* a patch whose body is larger than a delta revision can hold is refused. */
    {
        static char huge[2u * PAGE + 64u];
        int64_t path[1] = { 1 };
        docbody p;
        memset(huge, 'Q', sizeof huge);
        huge[sizeof huge - 1u] = '\0'; /* make_patch takes strlen(value) */
        p = make_patch(path, 1, huge);
        TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_doc_patch(&db, pool, e, p.b, p.n));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ------------------------------------- 19. full-text update after changes */

static void test_fts_update(void)
{
    uint64_t pool = 0, e1 = 0, e2 = 0;
    size_t n = 0;
    cdb_fts_hit hits[8];
    cdb_fts_config c = fts_cfg();
    docbody a = make_body("apple orange", 12);
    docbody b = make_body("orange pear", 11);
    docbody a2 = make_body("kiwi melon", 10);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("fu");

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, a.b, a.n, &e1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    /* index over the existing document, then keep it current as the pool
     * changes: inserts, a replace (the fts index diffs old vs new words) and
     * a delete all drive cdb_fts_update. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_create_full_text(&db, pool, &c));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, b.b, b.n, &e2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    n = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_search(&db, pool, "orange", 6, CDB_FTS_ANY, hits, 8, &n));
    TEST_ASSERT_EQUAL_UINT(2u, (unsigned)n);

    /* replace e1's content: its old words leave the index, the new ones enter. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_replace(&db, pool, e1, NULL, 0, a2.b, a2.n));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    n = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_search(&db, pool, "apple", 5, CDB_FTS_ANY, hits, 8, &n));
    TEST_ASSERT_EQUAL_UINT(0u, (unsigned)n);
    n = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_search(&db, pool, "kiwi", 4, CDB_FTS_ANY, hits, 8, &n));
    TEST_ASSERT_EQUAL_UINT(1u, (unsigned)n);

    /* delete e2: it leaves the index. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_delete(&db, pool, e2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    n = 7;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_search(&db, pool, "pear", 4, CDB_FTS_ANY, hits, 8, &n));
    TEST_ASSERT_EQUAL_UINT(0u, (unsigned)n);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ------------------------------------- 20. more read / iteration edges */

static void test_more_edges(void)
{
    uint64_t pool = 0, e = 0, es = 0;
    size_t len = 0;
    int live = 0, done = 0;
    uint32_t schema = 0;
    uint64_t cur = 0;
    uint8_t tiny[2];
    static char medstr[900]; /* a sub-page body that is its own revision page */
    docbody open_s = make_open_schema();
    docbody v = make_body("edgy-body", 9);
    docbody med;
    size_t i = 0;
    for (i = 0; i < sizeof medstr; i++)
        medstr[i] = (char)('a' + (int)(i % 26u));
    med = make_body(medstr, sizeof medstr);
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("me");
    {
        uint32_t version = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_set_schema(&db, pool, open_s.b, open_s.n, &version));
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, med.b, med.n, &es));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* get-in-tx of a committed document into a too-small buffer reports it. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    live = 0;
    len = 0;
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL,
                          cdb_doc_get_in_tx(&db, pool, e, CDB_STAGE_OFF_NONE, tiny, sizeof tiny, &len, &live, &schema));
    TEST_ASSERT_EQUAL_UINT(v.n, len);
    /* stage a change, then read the staged record into a too-small buffer. */
    {
        docbody v2 = make_body("restaged-bigger-body", 20);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_replace(&db, pool, e, NULL, 0, v2.b, v2.n));
        len = 0;
        TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL,
                              cdb_doc_get_in_tx(&db, pool, e, CDB_STAGE_OFF_NONE, tiny, sizeof tiny, &len, &live, &schema));
        TEST_ASSERT_EQUAL_UINT(v2.n, len);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));

    /* next_live with the max cursor stops at once. */
    cur = 7;
    done = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_next_live(&db, pool, UINT64_MAX, &cur, &done));
    TEST_ASSERT_TRUE(done);

    /* the medium document is a full revision page with no overflow: the
     * tail-move hook finds nothing to move past the envelope. */
    {
        uint8_t mkey[16];
        rev_key(mkey, es, 1);
        TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_doc_overflow_tail_moved(&db, pool, mkey, 16, 1, 2));
    }

    /* in-transaction liveness / read of an out-of-range entry on a real pool:
     * entry 0 and entries past the allocated counter are simply not live. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    live = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_live_in_tx(&db, pool, 0, &live));
    TEST_ASSERT_FALSE(live);
    live = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_live_in_tx(&db, pool, 999999, &live));
    TEST_ASSERT_FALSE(live);
    live = 1;
    len = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_doc_get_in_tx(&db, pool, 999999, CDB_STAGE_OFF_NONE, out, sizeof out, &len, &live, &schema));
    TEST_ASSERT_FALSE(live);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------- 20b. multi-field rewrite branches */

/* { f0:0, f1:1, ... } for the given ascending field IDs. */
static docbody make_multi(const int64_t *fields, unsigned n)
{
    docbody d;
    cdb_value_writer w;
    unsigned i = 0;
    memset(&d, 0, sizeof d);
    cdb_value_writer_init(&w, d.b, sizeof d.b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    for (i = 0; i < n; i++) {
        cdb_value_field(&w, (uint64_t)fields[i]);
        cdb_value_write_int(&w, (int64_t)i);
    }
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    d.n = cdb_value_writer_len(&w);
    return d;
}

static void patch_ok(uint64_t pool, uint64_t e, const docbody *p)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_patch(&db, pool, e, p->b, p->n));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
}

static void test_rewrite_multifield(void)
{
    uint64_t pool = 0, e = 0;
    size_t len = 0;
    int64_t fields[4] = { 1, 2, 4, 5 };
    docbody v = make_multi(fields, 4); /* { 1,2,4,5 } */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    pool = make_pool("rm");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* set a new field 3: sorts between 2 and 4, so fields 1,2 copy, 3 is
     * inserted at its place, then 4,5 copy (insert-before + copy-after). */
    {
        int64_t path[1] = { 3 };
        docbody p = make_patch(path, 1, "mid");
        patch_ok(pool, e, &p);
    }
    /* set an existing first field 1 (replace at path end over a scalar). */
    {
        int64_t path[1] = { 1 };
        docbody p = make_patch(path, 1, "first");
        patch_ok(pool, e, &p);
    }
    /* set a field after every existing one (append at the end). */
    {
        int64_t path[1] = { 99 };
        docbody p = make_patch(path, 1, "last");
        patch_ok(pool, e, &p);
    }
    /* remove an existing middle field. */
    {
        int64_t path[1] = { 4 };
        docbody p = make_patch(path, 1, NULL);
        patch_ok(pool, e, &p);
    }
    /* set THROUGH a scalar field 5 (replace it with a nested chain). */
    {
        int64_t path[2] = { 5, 1 };
        docbody p = make_patch(path, 2, "deep");
        patch_ok(pool, e, &p);
    }
    /* recurse into the now-object field 5 to add another leaf. */
    {
        int64_t path[2] = { 5, 2 };
        docbody p = make_patch(path, 2, "deep2");
        patch_ok(pool, e, &p);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_TRUE(len > 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ------------------------------------- 21. I/O faults during doc ops */

/* Builds a document state (an overflow document, a delta chain, small docs),
 * then, for a sweep of armed operation counts, injects an I/O fault and drives
 * reads, patches and prunes over it. Each armed point makes a different pager
 * read or write fail with CDB_E_IO, which the document code must propagate
 * (the error-return arms of read_revision / materialize / write_revision /
 * release / make_full / apply_change), never crash or corrupt. The database is
 * refused once failed; a reboot + reopen must recover cleanly. */
static void build_doc_state(uint64_t *pool, uint64_t *ebig, uint64_t *edelta)
{
    size_t i = 0;
    static char bigstr[PAGE + PAGE / 2u];
    docbody bv;
    docbody v0 = make_body("d0", 2);
    for (i = 0; i < sizeof bigstr; i++)
        bigstr[i] = (char)('a' + (int)(i % 26u));
    bv = make_body(bigstr, sizeof bigstr);
    *pool = make_pool("fs");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, *pool, "bs", 2, bv.b, bv.n, ebig));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, *pool, NULL, 0, v0.b, v0.n, edelta));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    /* a few deltas so the delta doc materialises through a chain. */
    for (i = 0; i < 4u; i++) {
        char t[4];
        docbody v;
        t[0] = 'd';
        t[1] = (char)('1' + (int)i);
        v = make_body(t, 2);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_replace(&db, *pool, *edelta, NULL, 0, v.b, v.n));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_reconcile(&db));
}

static void test_doc_fault_sweep(void)
{
    uint64_t op = 0;
    uint64_t pool = 0, ebig = 0, edelta = 0;
    size_t len = 0;
    int any_io = 0;

    /* build durable state with no fault, then close cleanly. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    build_doc_state(&pool, &ebig, &edelta);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    for (op = 1; op <= 50u; op++) {
        cdb_status rs;
        cdb_header h;
        memset(&h, 0, sizeof h);
        h.order = CDB_ORDER_LITTLE;
        h.layout_flags = CDB_LAYOUT_ADDR64;
        h.default_page_log2 = (uint8_t)PAGE_LOG2;
        memset(h.db_id, 0x7D, sizeof h.db_id);
        if (cdb_db_open(&db, &env, "dc2", &cfg, &h) != CDB_OK) {
            cdb_faultenv_reboot(&fe);
            continue;
        }
        cdb_faultenv_arm(&fe, op, CDB_CRASH_DROP_UNSYNCED, 0, 0);

        /* reads of the overflow and delta-chain documents (multi-page and
         * multi-revision materialisation) under the fault. */
        len = 0;
        rs = cdb_doc_get(&db, pool, ebig, 0, out, sizeof out, &len, NULL, 0, NULL, NULL);
        if (rs == CDB_E_IO)
            any_io = 1;
        rs = cdb_doc_get(&db, pool, edelta, 2, out, sizeof out, &len, NULL, 0, NULL, NULL);
        if (rs == CDB_E_IO)
            any_io = 1;

        /* writes under the fault: replace the overflow body, patch, and a
         * keep-triggered prune. Each may fail with CDB_E_IO. */
        if (cdb_tx_begin(&db, CDB_DURABILITY_FULL) == CDB_OK) {
            static char b2[PAGE + PAGE / 3u];
            docbody rv;
            int64_t path[1] = { 2 };
            docbody p = make_patch(path, 1, "f");
            size_t i = 0;
            for (i = 0; i < sizeof b2; i++)
                b2[i] = (char)('A' + (int)(i % 26u));
            rv = make_body(b2, sizeof b2);
            if (cdb_doc_replace(&db, pool, ebig, NULL, 0, rv.b, rv.n) == CDB_E_IO)
                any_io = 1;
            if (cdb_doc_patch(&db, pool, edelta, p.b, p.n) == CDB_E_IO)
                any_io = 1;
            if (cdb_tx_commit(&db) == CDB_E_IO)
                any_io = 1;
        }
        (void)cdb_doc_set_keep(&db, pool, 2);
        (void)cdb_db_reconcile(&db);

        (void)cdb_db_close(&db);
        cdb_faultenv_reboot(&fe);

        /* reopen after the fault must recover cleanly (or be cleanly absent). */
        rs = cdb_db_open(&db, &env, "dc2", &cfg, &h);
        TEST_ASSERT_TRUE_MESSAGE(rs == CDB_OK || rs == CDB_E_NOT_FOUND,
                                 "doc reopen after I/O fault neither recovered nor cleanly absent");
        if (rs == CDB_OK)
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
        cdb_faultenv_reboot(&fe);
    }
    TEST_ASSERT_TRUE_MESSAGE(any_io, "no injected I/O fault ever reached a document operation");
}

/* -------------------------------------------- 24. 32-bit address width */

/* The default harness opens 64-bit-address databases; a 32-bit-address one
 * exercises the narrow store_lid / address-width branches on the write and
 * read paths. The document must still round-trip verbatim. */
static void test_addr32_roundtrip(void)
{
    cdb_header h;
    uint64_t pool = 0, e = 0, ebig = 0;
    size_t len = 0, i = 0;
    docbody v = make_body("addr32", 6);
    static char bigstr[PAGE + PAGE / 2u]; /* an overflow (multi-page) body */
    docbody bv;
    for (i = 0; i < sizeof bigstr; i++)
        bigstr[i] = (char)('0' + (int)(i % 10u));
    bv = make_body(bigstr, sizeof bigstr);

    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = 0; /* no ADDR64: a 4-byte address width */
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x31, sizeof h.db_id);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "a32", &cfg, &h));
    TEST_ASSERT_EQUAL_UINT(4u, db.pager.addr_width);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "p", 1, CDB_MODEL_DOCUMENT, &pool));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e));
    /* an overflow body writes a 4-byte chain address (the narrow store_lid). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, pool, NULL, 0, bv.b, bv.n, &ebig));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, e, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(v.n, len);
    TEST_ASSERT_EQUAL_MEMORY(v.b, out, len);
    /* the overflow document round-trips verbatim through the 4-byte chain. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_get(&db, pool, ebig, 0, out, sizeof out, &len, NULL, 0, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT(bv.n, len);
    TEST_ASSERT_EQUAL_MEMORY(bv.b, out, len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* -------------------------------------------- 25. unsupported + oversize */

/* A pool opened without document buffers configured, and a body larger than
 * the configured doc_max, are both rejected with their defined status; nothing
 * is written and the configured database stays usable. */
static void test_unsupported_and_oversize(void)
{
    uint64_t pool = 0, e = 0, big_pool = 0, he = 0;
    size_t i = 0;
    docbody v = make_body("nd", 2);
    static char huge[3u * PAGE];
    docbody hv;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    /* opening a document pool needs the document buffers: with them removed
     * from the live config, the first op on a fresh pool is unsupported (no
     * partial state is written). The buffers are restored immediately after. */
    pool = make_pool("nd");
    db.cfg.doc_buffers = NULL;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED, cdb_doc_insert(&db, pool, NULL, 0, v.b, v.n, &e));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));
    db.cfg.doc_buffers = doc_buffers;

    /* a body larger than doc_max cannot fit even an overflow chain. */
    for (i = 0; i < sizeof huge; i++)
        huge[i] = (char)('a' + (int)(i % 26u));
    hv = make_body(huge, sizeof huge);
    big_pool = make_pool("big");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_doc_insert(&db, big_pool, NULL, 0, hv.b, hv.n, &he));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));

    /* a summary that overflows the revision envelope on its own is rejected:
     * the summary must fit the revision page even when the body overflows. */
    {
        static char bigsum[2u * PAGE];
        uint64_t se = 0;
        docbody sbody = make_body("x", 1);
        for (i = 0; i < sizeof bigsum; i++)
            bigsum[i] = (char)('S');
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW,
                              cdb_doc_insert(&db, big_pool, bigsum, sizeof bigsum, sbody.b, sbody.n, &se));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));
    }

    /* a patch body that is not a valid value encoding is rejected outright. */
    {
        uint64_t pe = 0;
        uint8_t garbage[16];
        docbody first = make_body("p", 1);
        memset(garbage, 0xFF, sizeof garbage);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_DEFAULT));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, big_pool, NULL, 0, first.b, first.n, &pe));
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_doc_patch(&db, big_pool, pe, garbage, sizeof garbage));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_abort(&db));
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_nib_moved_paths);
    RUN_TEST(test_overflow_tail_moved_paths);
    RUN_TEST(test_patch_malformed);
    RUN_TEST(test_prune_make_full);
    RUN_TEST(test_patch_checkpoint);
    RUN_TEST(test_overflow_patch);
    RUN_TEST(test_schema);
    RUN_TEST(test_full_text);
    RUN_TEST(test_summary_and_info);
    RUN_TEST(test_delete_reinsert);
    RUN_TEST(test_get_in_tx);
    RUN_TEST(test_rewrite_nested);
    RUN_TEST(test_apply_change_branches);
    RUN_TEST(test_release_overflow);
    RUN_TEST(test_compact_relocation);
    RUN_TEST(test_doc_recovery);
    RUN_TEST(test_stage_overflow);
    RUN_TEST(test_tx_entries_staged);
    RUN_TEST(test_edge_errors);
    RUN_TEST(test_fts_update);
    RUN_TEST(test_more_edges);
    RUN_TEST(test_rewrite_multifield);
    RUN_TEST(test_doc_fault_sweep);
    RUN_TEST(test_addr32_roundtrip);
    RUN_TEST(test_unsupported_and_oversize);
    return UNITY_END();
}
