/* Abuse / negative-path suite for content-addressed blob storage (issue #39).
 *
 * Complements tests/test_blob_dedup.c. Where that file proves the happy-path
 * red->green regressions, this file attacks the two load-bearing claims of a
 * content-addressed store directly, so a future regression that silently
 * loosens them is caught:
 *
 *   "content-addressed + integrity-verified":
 *     - a substituted chain (valid structure, matching total_len, DIFFERENT
 *       content) must be rejected on a default read, and only an explicit
 *       opt-out may return it (the whole point of the store);
 *     - corruption of an INTERIOR / non-first page must be caught at EOF, not
 *       just a tweak to the first byte of the first page;
 *     - a structurally truncated chain (interior link zeroed) must be rejected
 *       even with verification off (the tight per-page link check);
 *   "deduplicated + refcounted":
 *     - distinct content must NOT collapse to one chain (dedup keyed by hash,
 *       not blindly merged);
 *     - a refcount deeper than two is honoured (each free keeps data until 0);
 *     - empty blobs are never deduplicated and still read back verified;
 *   fail-closed:
 *     - NULL / bad-argument paths return an error, never a crash or silent OK;
 *     - the total_len -> size_t guard rejects over-range values at the
 *       boundary (deterministic on any platform via the test hook).
 *
 * Deterministic & hermetic: a fresh in-memory fault env per test (setUp), no
 * network/clock/RNG, fixed deterministic payloads.
 *
 * Deferred (noted, not covered here): cross-encryption-domain dedup aliasing
 * (EoP, ADR-1) needs an enclave store set up with keys; it is out of scope for
 * this hermetic suite and is called out as a follow-up test gap. */
#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "combolite/cdb_blob.h"
#include "cdb_db.h"
#include "cdb_endian.h"
#include "cdb_faultenv.h"
#include "cdb_overflow.h"
#include "cdb_page.h"

#define FCAP (1024u * 1024u)
#define PAGE_LOG2 9u /* 512-byte pages, so a 4 KiB payload spans many pages */
#define PAGE (1u << PAGE_LOG2)
#define NODES 32u
#define STORE 77u

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

/* Two deterministic payloads of IDENTICAL length but DIFFERENT content: the
 * length match is what makes the substitution attack subtle (a store that only
 * compares total_len would be fooled). */
static uint8_t payload_a[4096];
static uint8_t payload_b[4096];
static uint8_t out[4096];

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

    for (i = 0; i < sizeof payload_a; ++i) {
        payload_a[i] = (uint8_t)((i * 31u + 7u) & 0xFFu);
        payload_b[i] = (uint8_t)((i * 17u + 200u) & 0xFFu); /* same len, differs */
    }
    /* Guarantee the two payloads really differ (not an accidental alias). */
    TEST_ASSERT_TRUE(memcmp(payload_a, payload_b, sizeof payload_a) != 0);
    memset(out, 0, sizeof out);
}

void tearDown(void)
{
}

/* The next-page link lives at the front of the page payload, at the file's
 * address width and byte order (mirrors the blob/overflow readers). */
static size_t payoff(void)
{
    return cdb_page_payload_offset(db.pager.fmt);
}

static uint64_t ld_lid(const uint8_t *b)
{
    return db.pager.addr_width == 8 ? cdb_load_u64(b, db.pager.order)
                                    : cdb_load_u32(b, db.pager.order);
}

static void st_lid(uint8_t *b, uint64_t v)
{
    if (db.pager.addr_width == 8)
        cdb_store_u64(b, v, db.pager.order);
    else
        cdb_store_u32(b, (uint32_t)v, db.pager.order);
}

/* --- pager-level (non-dedup) write: full control over independent chains. --- */
static cdb_blob_ref raw_write(const uint8_t *data, size_t len)
{
    cdb_blob_writer w;
    cdb_blob_ref ref;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_write_begin(&db.pager, STORE, scratch_buf, NULL, &w));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_write_chunk(&w, data, len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_write_end(&w, &ref));
    return ref;
}

/* Reads the whole chain pager-level in small chunks, returning the first
 * non-OK status (or CDB_OK at EOF). dst/cap must hold the full content. The
 * EOF hash verification fires on the chunk that drains the last byte, so a
 * tampered/substituted chain surfaces as that chunk's status. */
static cdb_status raw_read_all(const cdb_blob_ref *ref, int verify, uint8_t *dst, size_t cap,
                               size_t *total)
{
    cdb_blob_reader r;
    cdb_status s;
    size_t got;
    *total = 0;
    s = cdb_blob_read_begin(&db.pager, STORE, ref, page_buf, verify, NULL, &r);
    if (s != CDB_OK)
        return s;
    for (;;) {
        size_t want = cap - *total;
        if (want > 128u)
            want = 128u;
        got = 0;
        s = cdb_blob_read_chunk(&r, dst + *total, want, &got);
        if (s != CDB_OK) {
            cdb_blob_read_end(&r);
            return s;
        }
        if (got == 0)
            break;
        *total += got;
        TEST_ASSERT_TRUE(*total <= cap);
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_read_end(&r));
    return CDB_OK;
}

/* --- db-level (deduplicating) write + verified read. --- */
static cdb_blob_ref db_write(const uint8_t *data, size_t len)
{
    cdb_blob_writer w;
    cdb_blob_ref ref;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_write_begin(&db, STORE, scratch_buf, &w));
    if (len > 0)
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_write_chunk(&w, data, len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_write_end(&w, &ref));
    return ref;
}

static void db_read_expect(const cdb_blob_ref *ref, const uint8_t *data, size_t len)
{
    cdb_blob_reader r;
    size_t off = 0, got;
    memset(out, 0, sizeof out);
    TEST_ASSERT_TRUE(len <= sizeof out);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_db_blob_read_begin(&db, STORE, ref, page_buf, CDB_BLOB_VERIFY, &r));
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

/* ============================ integrity abuse ============================= */

/* The core content-addressed guarantee: a chain whose STRUCTURE is valid and
 * whose total_len matches, but whose CONTENT differs from the referenced hash,
 * must be rejected by default and only returned under the explicit opt-out.
 * Pre-fix (default == no-verify) the substituted bytes came back silently as if
 * they were the referenced content. */
static void test_substituted_chain_rejected_by_default(void)
{
    cdb_header h = settings();
    cdb_blob_ref ref_a, ref_b, ref_sub;
    size_t total;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "b_subst", &cfg, &h));

    ref_a = raw_write(payload_a, sizeof payload_a);
    ref_b = raw_write(payload_b, sizeof payload_b);
    TEST_ASSERT_TRUE(ref_a.page_count > 1);
    TEST_ASSERT_EQUAL_UINT64(ref_a.total_len, ref_b.total_len);
    TEST_ASSERT_TRUE(memcmp(ref_a.hash, ref_b.hash, CDB_CRYPTO_HASH_SIZE) != 0);
    TEST_ASSERT_TRUE(ref_a.first_page != ref_b.first_page);

    /* A ref that CLAIMS payload_a (its hash + length) but POINTS at payload_b's
     * perfectly valid chain. */
    ref_sub = ref_a;
    ref_sub.first_page = ref_b.first_page;
    ref_sub.page_count = ref_b.page_count;

    /* Default read must reject it (hash mismatch at EOF). */
    total = 0;
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          raw_read_all(&ref_sub, CDB_BLOB_VERIFY_DEFAULT, out, sizeof out, &total));

    /* Explicit opt-out is the only way to get the (substituted) bytes back, and
     * they are payload_b's content, confirming the substitution was real. */
    total = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          raw_read_all(&ref_sub, CDB_BLOB_NO_VERIFY, out, sizeof out, &total));
    TEST_ASSERT_EQUAL_UINT64(sizeof payload_b, total);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(payload_b, out, sizeof payload_b);

    /* Release the two real chains (raw, no dedup). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_free(&db.pager, STORE, &ref_a, page_buf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_free(&db.pager, STORE, &ref_b, page_buf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* Corruption of a NON-first (interior) page must be caught too, not just a flip
 * of the first byte of the first page. Proves verification covers the whole
 * chain through to EOF. */
static void test_interior_page_tamper_rejected_by_default(void)
{
    cdb_header h = settings();
    cdb_blob_ref ref;
    cdb_page_header ph;
    uint64_t p2;
    size_t total;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "b_interior", &cfg, &h));

    ref = raw_write(payload_a, sizeof payload_a);
    TEST_ASSERT_TRUE(ref.page_count > 2);

    /* Walk one hop to the second page and flip a value byte (length untouched). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(&db.pager, ref.first_page, page_buf, &ph));
    p2 = ld_lid(page_buf + payoff());
    TEST_ASSERT_TRUE(p2 != 0);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(&db.pager, p2, page_buf, &ph));
    page_buf[payoff() + db.pager.addr_width + 5] ^= 0x5A;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_pager_write(&db.pager, p2, &ph, page_buf + payoff(), ph.payload_len));

    /* Default read walks the valid structure but the EOF hash no longer matches. */
    total = 0;
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          raw_read_all(&ref, CDB_BLOB_VERIFY_DEFAULT, out, sizeof out, &total));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_free(&db.pager, STORE, &ref, page_buf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* A structurally truncated chain (an interior page's next-link zeroed so it
 * falsely claims to be the last page while total_len says more remains) must be
 * rejected by the tight per-page link check EVEN WITH VERIFICATION OFF. This is
 * the "last <=> next == 0" invariant, independent of hashing. Pre-fix the loose
 * check accepted it. */
static void test_truncated_chain_rejected_without_verify(void)
{
    cdb_header h = settings();
    cdb_blob_ref ref;
    cdb_page_header ph;
    size_t total;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "b_trunc", &cfg, &h));

    ref = raw_write(payload_a, sizeof payload_a);
    TEST_ASSERT_TRUE(ref.page_count > 1);

    /* Zero the first (full, must-continue) page's next-link; payload_len stays
     * addr_width + room, so only the link invariant is violated. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(&db.pager, ref.first_page, page_buf, &ph));
    TEST_ASSERT_TRUE(ld_lid(page_buf + payoff()) != 0); /* it is an interior page */
    st_lid(page_buf + payoff(), 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_write(&db.pager, ref.first_page, &ph,
                                                  page_buf + payoff(), ph.payload_len));

    /* Caught during the chain walk regardless of the verify mode. */
    total = 0;
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          raw_read_all(&ref, CDB_BLOB_NO_VERIFY, out, sizeof out, &total));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ============================ dedup / refcount ============================ */

/* Distinct content must NOT be collapsed: dedup is keyed by content hash, so
 * two different payloads keep two independent chains, both readable. Guards
 * against a regression that over-merges unrelated blobs. */
static void test_distinct_content_not_deduplicated(void)
{
    cdb_header h = settings();
    cdb_blob_ref a1, a2, b1;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "b_distinct", &cfg, &h));

    a1 = db_write(payload_a, sizeof payload_a);
    a2 = db_write(payload_a, sizeof payload_a); /* identical -> dedup to a1 */
    b1 = db_write(payload_b, sizeof payload_b); /* different -> own chain */

    TEST_ASSERT_EQUAL_UINT64(a1.first_page, a2.first_page);
    TEST_ASSERT_TRUE(b1.first_page != a1.first_page);
    TEST_ASSERT_TRUE(memcmp(a1.hash, b1.hash, CDB_CRYPTO_HASH_SIZE) != 0);

    db_read_expect(&a1, payload_a, sizeof payload_a);
    db_read_expect(&b1, payload_b, sizeof payload_b);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, STORE, &a2, page_buf));
    db_read_expect(&a1, payload_a, sizeof payload_a); /* a1 survives a2's free */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, STORE, &a1, page_buf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, STORE, &b1, page_buf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* A refcount deeper than two: three references share one chain; the data stays
 * readable until the THIRD free, then the chain is released and the same
 * content allocates a fresh (never-reused) page. Pre-fix the first free
 * released the shared chain. */
static void test_refcount_depth_three(void)
{
    cdb_header h = settings();
    cdb_blob_ref r1, r2, r3, r4;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "b_rc3", &cfg, &h));

    r1 = db_write(payload_a, sizeof payload_a);
    r2 = db_write(payload_a, sizeof payload_a);
    r3 = db_write(payload_a, sizeof payload_a);
    TEST_ASSERT_EQUAL_UINT64(r1.first_page, r2.first_page);
    TEST_ASSERT_EQUAL_UINT64(r1.first_page, r3.first_page);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, STORE, &r1, page_buf)); /* 3 -> 2 */
    db_read_expect(&r3, payload_a, sizeof payload_a);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, STORE, &r2, page_buf)); /* 2 -> 1 */
    db_read_expect(&r3, payload_a, sizeof payload_a);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, STORE, &r3, page_buf)); /* 1 -> 0 */

    /* Entry gone: identical content now stores a brand-new chain. */
    r4 = db_write(payload_a, sizeof payload_a);
    TEST_ASSERT_TRUE(r4.first_page > r1.first_page);
    db_read_expect(&r4, payload_a, sizeof payload_a);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, STORE, &r4, page_buf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* Empty blobs are never deduplicated (no entry) and still read back under the
 * default (verifying) mode without a spurious corruption error. */
static void test_empty_blob_exempt_and_verified(void)
{
    cdb_header h = settings();
    cdb_blob_ref e1, e2;
    cdb_blob_reader r;
    size_t got;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "b_empty", &cfg, &h));

    e1 = db_write(NULL, 0);
    e2 = db_write(NULL, 0);
    TEST_ASSERT_EQUAL_UINT64(0, e1.total_len);
    TEST_ASSERT_EQUAL_UINT64(0, e1.first_page);
    TEST_ASSERT_EQUAL_UINT64(0, e2.first_page); /* not pointed at a shared chain */

    /* Default-verifying read of the empty blob succeeds (hash of no bytes). */
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_db_blob_read_begin(&db, STORE, &e1, page_buf, CDB_BLOB_VERIFY_DEFAULT, &r));
    got = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_read_chunk(&r, out, sizeof out, &got));
    TEST_ASSERT_EQUAL_UINT64(0, got);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_read_end(&r));

    /* Freeing an empty ref is a safe no-op. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, STORE, &e1, page_buf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_blob_free(&db, STORE, &e2, page_buf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ============================ fail-closed args =========================== */

/* NULL / bad-argument paths return an error, never a crash or a silent OK.
 * Fail-closed on ambiguity (master S2). */
static void test_fail_closed_bad_args(void)
{
    cdb_header h = settings();
    cdb_blob_reader r;
    cdb_blob_ref ref;
    size_t got = 123;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "b_args", &cfg, &h));
    ref = raw_write(payload_a, sizeof payload_a);

    /* read_begin: NULL ref / NULL page buffer / NULL reader. */
    TEST_ASSERT_EQUAL_INT(
        CDB_E_INVALID_ARG,
        cdb_blob_read_begin(&db.pager, STORE, NULL, page_buf, CDB_BLOB_VERIFY, NULL, &r));
    TEST_ASSERT_EQUAL_INT(
        CDB_E_INVALID_ARG,
        cdb_blob_read_begin(&db.pager, STORE, &ref, NULL, CDB_BLOB_VERIFY, NULL, &r));

    /* chunk calls on NULL contexts. */
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_blob_write_chunk(NULL, payload_a, 8));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_blob_read_chunk(NULL, out, sizeof out, &got));

    /* free: NULL ref via the public db wrapper and the pager-level primitive. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_blob_free(&db, STORE, NULL, page_buf));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_blob_free(&db.pager, STORE, &ref, NULL));

    /* write_end via the public wrapper with a NULL writer fails closed. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_blob_write_end(NULL, &ref));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_free(&db.pager, STORE, &ref, page_buf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* ============================ total_len guard ============================= */

/* The uint64 total_len -> size_t conversion guard, exercised at the boundary
 * on any platform through the deterministic test hook (on an LP64 host the real
 * path is unreachable because SIZE_MAX == UINT64_MAX). Complements the hook
 * values in test_blob_dedup.c with the max/zero boundaries and a 16-bit model. */
static void test_total_len_guard_boundaries(void)
{
    /* 32-bit size_t model. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_len_within_for_test(0u, 0xFFFFFFFFULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_len_within_for_test(0xFFFFFFFFULL, 0xFFFFFFFFULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW,
                          cdb_blob_len_within_for_test(0x100000000ULL, 0xFFFFFFFFULL));

    /* 16-bit size_t model: the boundary moves with size_max (runtime arg). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_len_within_for_test(0xFFFFULL, 0xFFFFULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_blob_len_within_for_test(0x10000ULL, 0xFFFFULL));

    /* Full 64-bit max is always representable when size_max is UINT64_MAX. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_blob_len_within_for_test(UINT64_MAX, UINT64_MAX));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_substituted_chain_rejected_by_default);
    RUN_TEST(test_interior_page_tamper_rejected_by_default);
    RUN_TEST(test_truncated_chain_rejected_without_verify);
    RUN_TEST(test_distinct_content_not_deduplicated);
    RUN_TEST(test_refcount_depth_three);
    RUN_TEST(test_empty_blob_exempt_and_verified);
    RUN_TEST(test_fail_closed_bad_args);
    RUN_TEST(test_total_len_guard_boundaries);
    return UNITY_END();
}
