/* combolite-core #34: fast unit tests for the four wired executor operators'
 * WIRE PARAMETER contract (TEXT_SEARCH / VECTOR_SEARCH / TRAVERSE /
 * HYBRID_RANK). These are the broad, fast base of the test pyramid: pure,
 * hermetic wire encode->validate->decode roundtrips with NO database, env, or
 * I/O. They lock the exact op-struct fields the executor now consumes to drive
 * the real engines (query text / limit / field / metric / k / direction /
 * hop bounds / fuse), so the slower live integration suites stay few.
 *
 * Each test builds a minimal valid plan with the public writers from
 * cdb_query.h, validates it, and reads the operator node back via
 * cdb_query_read_node, asserting the decoded parameters round-trip exactly and
 * cover the #34 abuse/edge cases (limit=0, k=0, max_hops=0, empty query,
 * single-hop).
 *
 * The suite is deliberately negative/abuse-heavy, not just happy paths:
 *   - writer-boundary rejection of hostile parameters (out-of-range text mode,
 *     vector metric, traverse direction; inverted hop bounds; non-RRF fuse;
 *     zero-branch hybrid) — invalid input is refused before a plan exists;
 *   - validator rejection of malformed / attacker-supplied raw wire (NULL,
 *     short, bad magic, bad version, dirty reserved byte, unknown node tag,
 *     trailing garbage, and byte-corrupted enum fields) — fail-closed, never a
 *     silent mis-decode;
 *   - truncated wire for all four operators;
 *   - hostile deeply-nested wire (CWE-674) rejected with CDB_E_DEPTH instead of
 *     overflowing the C stack.
 */
#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>

#include "unity.h"
#include "cdb_query.h"

static uint8_t wire[1024];
static cdb_query_writer w;

void setUp(void)
{
    cdb_query_writer_init(&w, wire, sizeof wire);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&w));
}

void tearDown(void) {}

/* Validate the full plan and position *p at the root operator node. */
static const uint8_t *decode_root(cdb_query_node *node)
{
    size_t root_off = 0;
    const uint8_t *p;
    const uint8_t *end = wire + cdb_query_writer_len(&w);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_validate(wire, cdb_query_writer_len(&w), &root_off));
    p = wire + root_off;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_node(&p, end, node));
    return end;
}

/* --------------------------------------------------------------------------
 * TEXT_SEARCH parameter contract (query text / mode / limit / fields)
 * -------------------------------------------------------------------------- */

static void test_text_decode_mode_any(void)
{
    cdb_query_node n;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_text_search(&w, CDB_QUERY_FTS_ANY, 10, "alpha", 5, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "notes", 5));
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_TEXT_SEARCH, n.tag);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_FTS_ANY, n.as.text_search.mode);
    TEST_ASSERT_EQUAL_UINT64(10, n.as.text_search.limit);
    TEST_ASSERT_EQUAL_STRING_LEN("alpha", n.as.text_search.query, 5);
    TEST_ASSERT_EQUAL_size_t(5, n.as.text_search.query_len);
    TEST_ASSERT_EQUAL_size_t(0, n.as.text_search.n_fields);
    TEST_ASSERT_NOT_NULL(n.as.text_search.input_wire);
}

static void test_text_decode_mode_all(void)
{
    cdb_query_node n;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_text_search(&w, CDB_QUERY_FTS_ALL, 3, "a b", 3, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "notes", 5));
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_FTS_ALL, n.as.text_search.mode);
    TEST_ASSERT_EQUAL_UINT64(3, n.as.text_search.limit);
}

/* Edge: limit=0 must decode to 0 (the operator treats it as "no cap"). */
static void test_text_limit_zero_decodes(void)
{
    cdb_query_node n;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_text_search(&w, CDB_QUERY_FTS_ANY, 0, "alpha", 5, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "notes", 5));
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_UINT64(0, n.as.text_search.limit);
}

/* Abuse edge: an empty query string round-trips with query_len 0. */
static void test_text_empty_query_decodes(void)
{
    cdb_query_node n;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_text_search(&w, CDB_QUERY_FTS_ANY, 5, "", 0, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "notes", 5));
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_size_t(0, n.as.text_search.query_len);
}

/* A field restriction round-trips as n_fields and a fields_wire. */
static void test_text_with_field(void)
{
    cdb_query_node n;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_text_search(&w, CDB_QUERY_FTS_ANY, 5, "alpha", 5, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "notes", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_field_name(&w, "text", 4));
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_size_t(1, n.as.text_search.n_fields);
    TEST_ASSERT_NOT_NULL(n.as.text_search.fields_wire);
}

/* --------------------------------------------------------------------------
 * VECTOR_SEARCH parameter contract (field / metric / k / near expr)
 * -------------------------------------------------------------------------- */

static void vec_plan(const char *field, size_t flen, uint64_t k, uint8_t metric)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_vector_search(&w, field, flen, k, metric));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "emb", 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_param_index(&w, 0)); /* near vector */
}

static void test_vec_decode_euclidean(void)
{
    cdb_query_node n;
    vec_plan("v", 1, 5, CDB_QUERY_METRIC_EUCLIDEAN);
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_VECTOR_SEARCH, n.tag);
    TEST_ASSERT_EQUAL_STRING_LEN("v", n.as.vector_search.field, 1);
    TEST_ASSERT_EQUAL_size_t(1, n.as.vector_search.field_len);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_METRIC_EUCLIDEAN, n.as.vector_search.metric);
    TEST_ASSERT_EQUAL_UINT64(5, n.as.vector_search.k);
    TEST_ASSERT_NOT_NULL(n.as.vector_search.near_wire); /* #34: near decoded, not ignored */
    TEST_ASSERT_NOT_NULL(n.as.vector_search.input_wire);
}

static void test_vec_decode_cosine(void)
{
    cdb_query_node n;
    vec_plan("v", 1, 2, CDB_QUERY_METRIC_COSINE);
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_METRIC_COSINE, n.as.vector_search.metric);
}

static void test_vec_decode_dot(void)
{
    cdb_query_node n;
    vec_plan("v", 1, 2, CDB_QUERY_METRIC_DOT);
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_METRIC_DOT, n.as.vector_search.metric);
}

static void test_vec_decode_default_metric(void)
{
    cdb_query_node n;
    vec_plan("v", 1, 2, CDB_QUERY_METRIC_DEFAULT);
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_METRIC_DEFAULT, n.as.vector_search.metric);
}

/* Abuse edge: k=0 round-trips (operator must handle an empty top-k request). */
static void test_vec_k_zero_decodes(void)
{
    cdb_query_node n;
    vec_plan("v", 1, 0, CDB_QUERY_METRIC_EUCLIDEAN);
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_UINT64(0, n.as.vector_search.k);
}

/* --------------------------------------------------------------------------
 * TRAVERSE parameter contract (link type / direction / hop bounds)
 * -------------------------------------------------------------------------- */

static void trav_plan(const char *lt, size_t len, uint8_t dir, uint64_t lo, uint64_t hi)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_traverse(&w, lt, len, dir, lo, hi));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "users", 5));
}

static void test_trav_decode_fwd(void)
{
    cdb_query_node n;
    trav_plan("follows", 7, CDB_TRAVERSE_FWD, 1, 3);
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_TRAVERSE, n.tag);
    TEST_ASSERT_EQUAL_STRING_LEN("follows", n.as.traverse.link_type, 7);
    TEST_ASSERT_EQUAL_UINT8(CDB_TRAVERSE_FWD, n.as.traverse.dir);
    TEST_ASSERT_EQUAL_UINT64(1, n.as.traverse.min_hops);
    TEST_ASSERT_EQUAL_UINT64(3, n.as.traverse.max_hops); /* #34: max_hops honored, not ignored */
    TEST_ASSERT_NOT_NULL(n.as.traverse.input_wire);
}

static void test_trav_decode_rev(void)
{
    cdb_query_node n;
    trav_plan("follows", 7, CDB_TRAVERSE_REV, 1, 2);
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_UINT8(CDB_TRAVERSE_REV, n.as.traverse.dir);
}

static void test_trav_decode_both(void)
{
    cdb_query_node n;
    trav_plan("follows", 7, CDB_TRAVERSE_BOTH, 1, 4);
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_UINT8(CDB_TRAVERSE_BOTH, n.as.traverse.dir);
    TEST_ASSERT_EQUAL_UINT64(4, n.as.traverse.max_hops);
}

/* Edge: a single-hop traverse (min == max) round-trips. */
static void test_trav_single_hop(void)
{
    cdb_query_node n;
    trav_plan("follows", 7, CDB_TRAVERSE_FWD, 1, 1);
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_UINT64(1, n.as.traverse.min_hops);
    TEST_ASSERT_EQUAL_UINT64(1, n.as.traverse.max_hops);
}

/* Abuse edge: max_hops=0 round-trips (operator must terminate immediately). */
static void test_trav_max_hops_zero(void)
{
    cdb_query_node n;
    trav_plan("follows", 7, CDB_TRAVERSE_FWD, 0, 0);
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_UINT64(0, n.as.traverse.max_hops);
}

/* --------------------------------------------------------------------------
 * HYBRID_RANK parameter contract (fuse / branch count)
 * -------------------------------------------------------------------------- */

static void test_hybrid_decode_rrf_two_branches(void)
{
    cdb_query_node n;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_hybrid_rank(&w, CDB_FUSE_RRF, 2));
    /* Branch 0: text search */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_text_search(&w, CDB_QUERY_FTS_ANY, 5, "alpha", 5, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "notes", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_branch_weight(&w, 1000));
    /* Branch 1: text search */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_text_search(&w, CDB_QUERY_FTS_ANY, 5, "beta", 4, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "notes", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_branch_weight(&w, 1000));
    (void)decode_root(&n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_HYBRID_RANK, n.tag);
    TEST_ASSERT_EQUAL_UINT8(CDB_FUSE_RRF, n.as.hybrid_rank.fuse);
    TEST_ASSERT_EQUAL_size_t(2, n.as.hybrid_rank.count);
    TEST_ASSERT_NOT_NULL(n.as.hybrid_rank.branches_wire);
}

/* --------------------------------------------------------------------------
 * Fail-closed: a truncated operator wire must be rejected, not misdecoded.
 * -------------------------------------------------------------------------- */

static void test_truncated_text_wire_rejected(void)
{
    size_t root_off = 0;
    size_t len;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_text_search(&w, CDB_QUERY_FTS_ANY, 5, "alpha", 5, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "notes", 5));
    len = cdb_query_writer_len(&w);
    /* Dropping the final byte must fail validation (fail closed). */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_query_validate(wire, len - 1, &root_off));
}

/* Any rejection (< 0) is acceptable for truncation; the contract is fail-closed,
 * never a mis-decode that silently drops bytes. */
static void assert_rejected(cdb_status s)
{
    TEST_ASSERT_TRUE_MESSAGE(s != CDB_OK, "hostile/malformed wire must be rejected");
}

static void test_truncated_vec_wire_rejected(void)
{
    size_t root_off = 0;
    size_t len;
    vec_plan("v", 1, 5, CDB_QUERY_METRIC_EUCLIDEAN);
    len = cdb_query_writer_len(&w);
    assert_rejected(cdb_query_validate(wire, len - 1, &root_off));
}

static void test_truncated_trav_wire_rejected(void)
{
    size_t root_off = 0;
    size_t len;
    trav_plan("follows", 7, CDB_TRAVERSE_FWD, 1, 3);
    len = cdb_query_writer_len(&w);
    assert_rejected(cdb_query_validate(wire, len - 1, &root_off));
}

static void test_truncated_hybrid_wire_rejected(void)
{
    size_t root_off = 0;
    size_t len;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_hybrid_rank(&w, CDB_FUSE_RRF, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_text_search(&w, CDB_QUERY_FTS_ANY, 5, "alpha", 5, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "notes", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_branch_weight(&w, 1000));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_text_search(&w, CDB_QUERY_FTS_ANY, 5, "beta", 4, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "notes", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_branch_weight(&w, 1000));
    len = cdb_query_writer_len(&w);
    assert_rejected(cdb_query_validate(wire, len - 1, &root_off));
}

/* --------------------------------------------------------------------------
 * Abuse: writer boundary rejects hostile operator parameters (fail closed at
 * the public API, before any wire is emitted). These are the "invalid input"
 * negative paths — out-of-range enums and inverted bounds must never produce a
 * plan that later drives an engine with garbage.
 * -------------------------------------------------------------------------- */

static void test_text_writer_rejects_bad_mode(void)
{
    /* 0x00 (none) and 0x03 (above FTS_ALL) are not valid text-search modes. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_query_write_text_search(&w, 0x00u, 5, "alpha", 5, 0));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_query_write_text_search(&w, 0x03u, 5, "alpha", 5, 0));
}

static void test_vec_writer_rejects_bad_metric(void)
{
    /* 0x04 is past CDB_QUERY_METRIC_DOT — a hostile metric must be refused. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_query_write_vector_search(&w, "v", 1, 5, 0x04u));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_query_write_vector_search(&w, "v", 1, 5, 0xFFu));
}

static void test_trav_writer_rejects_bad_dir(void)
{
    /* dir 0x00 (none) and 0x04 (above BOTH) are invalid traverse directions. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_query_write_traverse(&w, "follows", 7, 0x00u, 1, 3));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_query_write_traverse(&w, "follows", 7, 0x04u, 1, 3));
}

/* Abuse: an inverted hop range (max < min) is a nonsensical/hostile bound that
 * the walk must never accept — it would otherwise under/over-run the frontier. */
static void test_trav_writer_rejects_inverted_hops(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_query_write_traverse(&w, "follows", 7, CDB_TRAVERSE_FWD, 5, 2));
}

static void test_hybrid_writer_rejects_bad_fuse(void)
{
    /* RRF (0x01) is the only supported fusion; anything else is refused. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_query_write_hybrid_rank(&w, 0x00u, 2));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_query_write_hybrid_rank(&w, 0x02u, 2));
}

/* Abuse: a hybrid rank with zero branches has nothing to fuse — reject it
 * rather than emit a degenerate plan. */
static void test_hybrid_writer_rejects_zero_branches(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_query_write_hybrid_rank(&w, CDB_FUSE_RRF, 0));
}

/* --------------------------------------------------------------------------
 * Abuse: the validator rejects malformed / hostile raw wire. These mutate
 * known-good bytes to simulate a corrupted or attacker-supplied plan buffer
 * arriving over the query wire, and assert fail-closed rejection (never a
 * silent mis-decode). The root operator node always begins at
 * CDB_QUERY_HEADER_SIZE (6); the enum byte sits right after the node tag.
 * -------------------------------------------------------------------------- */

/* Build a minimal valid single-op plan into `wire` and return its length. */
static size_t build_text_plan(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_text_search(&w, CDB_QUERY_FTS_ANY, 5, "alpha", 5, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "notes", 5));
    return cdb_query_writer_len(&w);
}

static void test_null_wire_rejected(void)
{
    size_t root_off = 0;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_query_validate(NULL, 32, &root_off));
}

static void test_short_wire_rejected(void)
{
    size_t root_off = 0;
    (void)build_text_plan();
    /* Anything shorter than the fixed header cannot be a plan. */
    assert_rejected(cdb_query_validate(wire, CDB_QUERY_HEADER_SIZE - 1, &root_off));
}

static void test_bad_magic_rejected(void)
{
    size_t root_off = 0;
    size_t len = build_text_plan();
    wire[0] = 0x00u; /* corrupt first magic byte */
    assert_rejected(cdb_query_validate(wire, len, &root_off));
}

static void test_bad_version_rejected(void)
{
    size_t root_off = 0;
    size_t len = build_text_plan();
    wire[4] = 0x7Fu; /* unsupported version */
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED, cdb_query_validate(wire, len, &root_off));
}

static void test_reserved_byte_rejected(void)
{
    size_t root_off = 0;
    size_t len = build_text_plan();
    wire[5] = 0xFFu; /* reserved header byte must be zero */
    assert_rejected(cdb_query_validate(wire, len, &root_off));
}

static void test_unknown_node_tag_rejected(void)
{
    size_t root_off = 0;
    size_t len = build_text_plan();
    wire[CDB_QUERY_HEADER_SIZE] = 0xFEu; /* not a known operator tag */
    assert_rejected(cdb_query_validate(wire, len, &root_off));
}

static void test_trailing_garbage_rejected(void)
{
    size_t root_off = 0;
    size_t len = build_text_plan();
    /* A well-formed plan followed by stray bytes must be refused, not ignored. */
    wire[len] = 0x00u;
    assert_rejected(cdb_query_validate(wire, len + 1, &root_off));
}

/* Corrupting the text-search mode byte (immediately after the node tag) to an
 * out-of-range value must be caught by the validator. */
static void test_text_mode_byte_corrupted_rejected(void)
{
    size_t root_off = 0;
    size_t len = build_text_plan();
    wire[CDB_QUERY_HEADER_SIZE + 1] = 0x03u; /* above CDB_QUERY_FTS_ALL */
    assert_rejected(cdb_query_validate(wire, len, &root_off));
}

/* Corrupting the hybrid-rank fuse byte to a non-RRF value must be rejected. */
static void test_hybrid_fuse_byte_corrupted_rejected(void)
{
    size_t root_off = 0;
    size_t len;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_hybrid_rank(&w, CDB_FUSE_RRF, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_text_search(&w, CDB_QUERY_FTS_ANY, 5, "a", 1, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "notes", 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_branch_weight(&w, 1000));
    len = cdb_query_writer_len(&w);
    wire[CDB_QUERY_HEADER_SIZE + 1] = 0x02u; /* not CDB_FUSE_RRF */
    assert_rejected(cdb_query_validate(wire, len, &root_off));
}

/* Corrupting the traverse direction byte to an out-of-range value must be
 * rejected. Layout: tag@6, str("x")=varint(1)@7 + 'x'@8, dir@9. */
static void test_trav_dir_byte_corrupted_rejected(void)
{
    size_t root_off = 0;
    size_t len;
    trav_plan("x", 1, CDB_TRAVERSE_FWD, 1, 3);
    len = cdb_query_writer_len(&w);
    wire[CDB_QUERY_HEADER_SIZE + 3] = 0x04u; /* above CDB_TRAVERSE_BOTH */
    assert_rejected(cdb_query_validate(wire, len, &root_off));
}

/* Abuse: hostile deeply-nested wire (CWE-674) must be rejected with a bounded
 * error instead of overflowing the C stack. Nest TEXT_SEARCH well past
 * CDB_QUERY_MAX_DEPTH, then an innermost scan. */
static void test_hostile_deep_nesting_rejected(void)
{
    size_t root_off = 0;
    size_t len;
    unsigned i;
    for (i = 0; i < CDB_QUERY_MAX_DEPTH + 6u; i++)
        TEST_ASSERT_EQUAL_INT(CDB_OK,
                              cdb_query_write_text_search(&w, CDB_QUERY_FTS_ANY, 0, "", 0, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&w, "notes", 5));
    len = cdb_query_writer_len(&w);
    TEST_ASSERT_EQUAL_INT(CDB_E_DEPTH, cdb_query_validate(wire, len, &root_off));
}

int main(void)
{
    UNITY_BEGIN();
    /* TEXT_SEARCH */
    RUN_TEST(test_text_decode_mode_any);
    RUN_TEST(test_text_decode_mode_all);
    RUN_TEST(test_text_limit_zero_decodes);
    RUN_TEST(test_text_empty_query_decodes);
    RUN_TEST(test_text_with_field);
    /* VECTOR_SEARCH */
    RUN_TEST(test_vec_decode_euclidean);
    RUN_TEST(test_vec_decode_cosine);
    RUN_TEST(test_vec_decode_dot);
    RUN_TEST(test_vec_decode_default_metric);
    RUN_TEST(test_vec_k_zero_decodes);
    /* TRAVERSE */
    RUN_TEST(test_trav_decode_fwd);
    RUN_TEST(test_trav_decode_rev);
    RUN_TEST(test_trav_decode_both);
    RUN_TEST(test_trav_single_hop);
    RUN_TEST(test_trav_max_hops_zero);
    /* HYBRID_RANK */
    RUN_TEST(test_hybrid_decode_rrf_two_branches);
    /* fail-closed: truncated operator wire (all four ops) */
    RUN_TEST(test_truncated_text_wire_rejected);
    RUN_TEST(test_truncated_vec_wire_rejected);
    RUN_TEST(test_truncated_trav_wire_rejected);
    RUN_TEST(test_truncated_hybrid_wire_rejected);
    /* abuse: writer-boundary rejection of hostile parameters */
    RUN_TEST(test_text_writer_rejects_bad_mode);
    RUN_TEST(test_vec_writer_rejects_bad_metric);
    RUN_TEST(test_trav_writer_rejects_bad_dir);
    RUN_TEST(test_trav_writer_rejects_inverted_hops);
    RUN_TEST(test_hybrid_writer_rejects_bad_fuse);
    RUN_TEST(test_hybrid_writer_rejects_zero_branches);
    /* abuse: malformed / hostile raw wire rejected by the validator */
    RUN_TEST(test_null_wire_rejected);
    RUN_TEST(test_short_wire_rejected);
    RUN_TEST(test_bad_magic_rejected);
    RUN_TEST(test_bad_version_rejected);
    RUN_TEST(test_reserved_byte_rejected);
    RUN_TEST(test_unknown_node_tag_rejected);
    RUN_TEST(test_trailing_garbage_rejected);
    RUN_TEST(test_text_mode_byte_corrupted_rejected);
    RUN_TEST(test_hybrid_fuse_byte_corrupted_rejected);
    RUN_TEST(test_trav_dir_byte_corrupted_rejected);
    /* abuse: hostile deep nesting (CWE-674) rejected, no stack overflow */
    RUN_TEST(test_hostile_deep_nesting_rejected);
    return UNITY_END();
}
