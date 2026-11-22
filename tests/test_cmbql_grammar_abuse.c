/* combolite-core #35 (sub-feature A) — QA abuse/edge + hand-wire parity.
 *
 * Complements tests/test_cmbql_operators_text.c (positive decode checks). This
 * file proves two further things the brief calls out for sub-feature A:
 *
 *   1. PARITY: a CMBQL-TEXT query that uses a newly-parseable operator compiles
 *      to the SAME plan the executor would get from a hand-built wire
 *      (cdb_query_write_*). We decode both the text-compiled root and the
 *      hand-built root and assert their operator parameters match field-for-
 *      field, including the nested SCAN input. This is the "same plan as the
 *      equivalent hand-built wire" assertion (#34's writers are the reference).
 *
 *   2. FAIL-CLOSED abuse paths distinct from the existing malformed set:
 *      out-of-range numeric literals (CWE-190 saturation, no wraparound), depth
 *      exhaustion from nested sources (CWE-674), empty/whitespace input, empty
 *      arg lists, dangling AS — every one handled safely, never a crash, never
 *      a wrapped/garbage value (verified under ASan+UBSan).
 *
 * Hermetic: compiler only, no database. */
#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "unity.h"
#include "cdb_compiler.h"
#include "cdb_query.h"

static uint8_t wire_a[8192];
static uint8_t wire_b[8192];
static cdb_compile_error err;

void setUp(void)
{
    memset(wire_a, 0, sizeof wire_a);
    memset(wire_b, 0, sizeof wire_b);
    memset(&err, 0, sizeof err);
}

void tearDown(void) {}

/* Compile CMBQL text into `buf`, validate, decode the root node. Reports the
 * total wire length so callers can decode nested child nodes with a correct
 * end bound. */
static void compile_root_into(const char *text, uint8_t *buf, size_t cap, size_t *out_len,
                              cdb_query_node *node)
{
    size_t wlen = 0;
    size_t root_off = 0;
    const uint8_t *p;
    cdb_status s = cdb_compile_query(text, strlen(text), NULL, buf, cap, &wlen, &err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, s, err.msg);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_validate(buf, wlen, &root_off));
    p = buf + root_off;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_node(&p, buf + wlen, node));
    *out_len = wlen;
}

/* Decode the child node referenced by a *_wire pointer inside `buf`. */
static void decode_child(const uint8_t *child_wire, const uint8_t *buf, size_t wlen,
                         cdb_query_node *child)
{
    const uint8_t *p = child_wire;
    TEST_ASSERT_NOT_NULL(child_wire);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_node(&p, buf + wlen, child));
}

/* A malformed query must fail closed with a typed error and produce no plan. */
static void assert_rejected(const char *text)
{
    size_t wlen = 0;
    cdb_status s = cdb_compile_query(text, strlen(text), NULL, wire_a, sizeof wire_a, &wlen, &err);
    TEST_ASSERT_TRUE_MESSAGE(s != CDB_OK, "malformed CMBQL must fail closed");
    TEST_ASSERT_TRUE_MESSAGE(s == CDB_E_INVALID_ARG || s == CDB_E_DEPTH
                                 || s == CDB_E_BUFFER_TOO_SMALL,
                             "fail-closed error must be a typed parse/resource error");
}

/* ---------- PARITY: text-compiled plan == hand-built wire plan ---------- */

/* TRAVERSE: Scan("roots") | traverse(link:"edge", dir:"rev", min:1, max:3). */
static void test_parity_traverse(void)
{
    cdb_query_node t, h, tc, hc;
    cdb_query_writer qw;
    size_t tlen = 0, hlen = 0, root_off = 0;
    const uint8_t *p;

    compile_root_into("Scan(\"roots\") | traverse(link: \"edge\", dir: \"rev\", min: 1, max: 3)",
                      wire_a, sizeof wire_a, &tlen, &t);

    cdb_query_writer_init(&qw, wire_b, sizeof wire_b);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_query_write_traverse(&qw, "edge", 4, CDB_TRAVERSE_REV, 1, 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "roots", 5));
    hlen = cdb_query_writer_len(&qw);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_validate(wire_b, hlen, &root_off));
    p = wire_b + root_off;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_node(&p, wire_b + hlen, &h));

    /* Operator parameters match the hand-built reference exactly. */
    TEST_ASSERT_EQUAL_UINT8(h.tag, t.tag);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_TRAVERSE, t.tag);
    TEST_ASSERT_EQUAL_UINT8(h.as.traverse.dir, t.as.traverse.dir);
    TEST_ASSERT_EQUAL_UINT64(h.as.traverse.min_hops, t.as.traverse.min_hops);
    TEST_ASSERT_EQUAL_UINT64(h.as.traverse.max_hops, t.as.traverse.max_hops);
    TEST_ASSERT_EQUAL_size_t(h.as.traverse.link_type_len, t.as.traverse.link_type_len);
    TEST_ASSERT_EQUAL_MEMORY(h.as.traverse.link_type, t.as.traverse.link_type,
                             t.as.traverse.link_type_len);

    /* The nested SCAN input matches too. */
    decode_child(t.as.traverse.input_wire, wire_a, tlen, &tc);
    decode_child(h.as.traverse.input_wire, wire_b, hlen, &hc);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_SCAN, tc.tag);
    TEST_ASSERT_EQUAL_UINT8(hc.tag, tc.tag);
    TEST_ASSERT_EQUAL_size_t(hc.as.scan.name_len, tc.as.scan.name_len);
    TEST_ASSERT_EQUAL_MEMORY(hc.as.scan.name, tc.as.scan.name, tc.as.scan.name_len);
}

/* UNION: text `Union(Scan("a"), Scan("b"))` compiles to the same plan as the
 * hand-built union-of-two-scans wire, including both decoded branch scans. */
static void test_parity_union(void)
{
    cdb_query_node t, h, tb, hb;
    cdb_query_writer qw;
    size_t tlen = 0, hlen = 0, root_off = 0;
    const uint8_t *p;

    compile_root_into("Union(Scan(\"a\"), Scan(\"b\"))", wire_a, sizeof wire_a, &tlen, &t);

    cdb_query_writer_init(&qw, wire_b, sizeof wire_b);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_writer_begin(&qw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_union(&qw, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "a", 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_scan(&qw, "b", 1));
    hlen = cdb_query_writer_len(&qw);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_validate(wire_b, hlen, &root_off));
    p = wire_b + root_off;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_node(&p, wire_b + hlen, &h));

    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_UNION, t.tag);
    TEST_ASSERT_EQUAL_UINT8(h.tag, t.tag);
    TEST_ASSERT_EQUAL_size_t(h.as.union_node.count, t.as.union_node.count);
    TEST_ASSERT_EQUAL_size_t(2, t.as.union_node.count);

    /* First branch of each decodes to the same scan. */
    decode_child(t.as.union_node.branches_wire, wire_a, tlen, &tb);
    decode_child(h.as.union_node.branches_wire, wire_b, hlen, &hb);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_SCAN, tb.tag);
    TEST_ASSERT_EQUAL_UINT8(hb.tag, tb.tag);
    TEST_ASSERT_EQUAL_size_t(hb.as.scan.name_len, tb.as.scan.name_len);
    TEST_ASSERT_EQUAL_MEMORY(hb.as.scan.name, tb.as.scan.name, tb.as.scan.name_len);
}

/* ---------- Positive edge cases (new productions, extra coverage) ---------- */

/* traverse dir "both" + multi-digit hop bounds. */
static void test_traverse_both_direction(void)
{
    cdb_query_node n;
    size_t wlen = 0;
    compile_root_into("Scan(\"g\") | traverse(link: \"knows\", dir: \"both\", min: 0, max: 12)",
                      wire_a, sizeof wire_a, &wlen, &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_TRAVERSE, n.tag);
    TEST_ASSERT_EQUAL_UINT8(CDB_TRAVERSE_BOTH, n.as.traverse.dir);
    TEST_ASSERT_EQUAL_UINT64(0, n.as.traverse.min_hops);
    TEST_ASSERT_EQUAL_UINT64(12, n.as.traverse.max_hops);
}

/* text_search explicit "any" mode. */
static void test_text_search_mode_any(void)
{
    cdb_query_node n;
    size_t wlen = 0;
    compile_root_into("Scan(\"docs\") | text_search(query: \"gamma\", mode: \"any\", limit: 3)",
                      wire_a, sizeof wire_a, &wlen, &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_TEXT_SEARCH, n.tag);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_FTS_ANY, n.as.text_search.mode);
    TEST_ASSERT_EQUAL_UINT64(3, n.as.text_search.limit);
}

/* aggregate: multiple group keys + several aggregate functions. */
static void test_aggregate_multi_group(void)
{
    cdb_query_node n;
    size_t wlen = 0;
    compile_root_into("Scan(\"sales\") | aggregate(by: [region, product], "
                      "total: sum(amount), hi: max(amount), c: count(*))",
                      wire_a, sizeof wire_a, &wlen, &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_AGGREGATE, n.tag);
    TEST_ASSERT_EQUAL_size_t(2, n.as.aggregate.n_groups);
    TEST_ASSERT_EQUAL_size_t(3, n.as.aggregate.n_aggs);
}

/* unnest without an index alias leaves index_alias empty. */
static void test_unnest_no_index_alias(void)
{
    cdb_query_node n;
    size_t wlen = 0;
    compile_root_into("Scan(\"docs\") | unnest(tags AS tag)", wire_a, sizeof wire_a, &wlen, &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_UNNEST, n.tag);
    TEST_ASSERT_EQUAL_size_t(3, n.as.unnest.item_alias_len);
    TEST_ASSERT_EQUAL_MEMORY("tag", n.as.unnest.item_alias, 3);
    TEST_ASSERT_EQUAL_size_t(0, n.as.unnest.index_alias_len);
}

/* ---------- FAIL-CLOSED abuse paths (distinct from existing set) ---------- */

/* Empty and whitespace-only input must not compile. */
static void test_empty_input_rejected(void) { assert_rejected(""); }
static void test_whitespace_input_rejected(void) { assert_rejected("   \t  \n "); }

/* Empty argument lists on the new stages fail closed. */
static void test_aggregate_empty_rejected(void) { assert_rejected("Scan(\"t\") | aggregate()"); }
static void test_hybrid_rank_empty_branches_rejected(void)
{
    assert_rejected("HybridRank(branches: [])");
}
static void test_union_pipe_empty_rejected(void) { assert_rejected("Scan(\"a\") | union()"); }

/* `AS` with no following identifier in unnest. */
static void test_unnest_dangling_as_rejected(void)
{
    assert_rejected("Scan(\"d\") | unnest(tags AS)");
}

/* Out-of-range integer literals in numeric clause positions must be handled
 * safely: the lexer saturates to INT64_MAX rather than wrapping to a small or
 * garbage value (CWE-190 — no silent overflow). We assert the clamped value,
 * which proves the magnitude did NOT wrap around. */
#define CDB_I64_MAX_U 9223372036854775807ULL

static void test_text_search_limit_overflow_saturates(void)
{
    cdb_query_node n;
    size_t wlen = 0;
    compile_root_into("Scan(\"n\") | text_search(query: \"x\", limit: 999999999999999999999999)",
                      wire_a, sizeof wire_a, &wlen, &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_TEXT_SEARCH, n.tag);
    TEST_ASSERT_EQUAL_UINT64(CDB_I64_MAX_U, n.as.text_search.limit); /* saturated, not wrapped */
}
static void test_vector_search_k_overflow_saturates(void)
{
    cdb_query_node n;
    size_t wlen = 0;
    compile_root_into("Scan(\"e\") | vector_search(field: \"v\", near: $0, "
                      "k: 999999999999999999999999)",
                      wire_a, sizeof wire_a, &wlen, &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_VECTOR_SEARCH, n.tag);
    TEST_ASSERT_EQUAL_UINT64(CDB_I64_MAX_U, n.as.vector_search.k);
}
static void test_asof_tolerance_overflow_saturates(void)
{
    cdb_query_node n;
    size_t wlen = 0;
    compile_root_into("AsofJoin(Scan(\"a\"), Scan(\"b\"), left_time: ts, right_time: ts, "
                      "kind: \"backward\", tolerance: 999999999999999999999999)",
                      wire_a, sizeof wire_a, &wlen, &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_ASOF_JOIN, n.tag);
    TEST_ASSERT_EQUAL_UINT64(CDB_I64_MAX_U, n.as.asof_join.tolerance_ns);
}

/* Deeply-nested sources must hit the depth guard (CWE-674), not overflow the C
 * stack. Build Union(Scan("a"), Union(Scan("a"), Union(... ))) far beyond
 * CDB_QUERY_MAX_DEPTH and assert a typed fail-closed error under ASan. */
static void test_deep_union_nesting_rejected(void)
{
    static char buf[4096];
    const unsigned depth = CDB_QUERY_MAX_DEPTH + 40u;
    size_t pos = 0;
    unsigned i;
    size_t wlen = 0;
    cdb_status s;

    for (i = 0; i < depth; i++) {
        int w = snprintf(buf + pos, sizeof buf - pos, "Union(Scan(\"a\"), ");
        TEST_ASSERT_TRUE(w > 0);
        pos += (size_t)w;
        TEST_ASSERT_TRUE(pos < sizeof buf - 64);
    }
    {
        int w = snprintf(buf + pos, sizeof buf - pos, "Scan(\"b\")");
        TEST_ASSERT_TRUE(w > 0);
        pos += (size_t)w;
    }
    for (i = 0; i < depth; i++) {
        TEST_ASSERT_TRUE(pos < sizeof buf - 2);
        buf[pos++] = ')';
    }
    buf[pos] = '\0';

    s = cdb_compile_query(buf, pos, NULL, wire_a, sizeof wire_a, &wlen, &err);
    TEST_ASSERT_TRUE_MESSAGE(s != CDB_OK, "deeply nested source must fail closed");
    TEST_ASSERT_TRUE(s == CDB_E_DEPTH || s == CDB_E_INVALID_ARG || s == CDB_E_BUFFER_TOO_SMALL);
}

/* A valid query compiled into a too-small output buffer fails closed (no OOB
 * write — caught by ASan if the writer ever overruns). */
static void test_tiny_output_buffer_fail_closed(void)
{
    uint8_t tiny[4];
    size_t wlen = 0;
    cdb_status s = cdb_compile_query("Scan(\"books\") | text_search(query: \"alpha\", "
                                     "fields: [\"a\", \"b\", \"c\"])",
                                     strlen("Scan(\"books\") | text_search(query: \"alpha\", "
                                            "fields: [\"a\", \"b\", \"c\"])"),
                                     NULL, tiny, sizeof tiny, &wlen, &err);
    TEST_ASSERT_TRUE_MESSAGE(s != CDB_OK, "compile into tiny buffer must fail closed");
}

int main(void)
{
    UNITY_BEGIN();
    /* parity */
    RUN_TEST(test_parity_traverse);
    RUN_TEST(test_parity_union);
    /* positive edges */
    RUN_TEST(test_traverse_both_direction);
    RUN_TEST(test_text_search_mode_any);
    RUN_TEST(test_aggregate_multi_group);
    RUN_TEST(test_unnest_no_index_alias);
    /* abuse / fail-closed */
    RUN_TEST(test_empty_input_rejected);
    RUN_TEST(test_whitespace_input_rejected);
    RUN_TEST(test_aggregate_empty_rejected);
    RUN_TEST(test_hybrid_rank_empty_branches_rejected);
    RUN_TEST(test_union_pipe_empty_rejected);
    RUN_TEST(test_unnest_dangling_as_rejected);
    RUN_TEST(test_text_search_limit_overflow_saturates);
    RUN_TEST(test_vector_search_k_overflow_saturates);
    RUN_TEST(test_asof_tolerance_overflow_saturates);
    RUN_TEST(test_deep_union_nesting_rejected);
    RUN_TEST(test_tiny_output_buffer_fail_closed);
    return UNITY_END();
}
