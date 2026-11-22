/* combolite-core #35 (sub-feature A): CMBQL-TEXT grammar for the 8 formerly
 * text-unreachable operators (AGGREGATE, UNION, TRAVERSE, TEXT_SEARCH,
 * VECTOR_SEARCH, HYBRID_RANK, ASOF_JOIN, UNNEST).
 *
 * Hermetic, no database: each test compiles a CMBQL-TEXT query that exercises a
 * new production, validates the emitted CMBQ wire, and decodes the root node to
 * assert it carries exactly the parameters the executor (#34) consumes — i.e.
 * the text front-end emits the same wire a hand-built plan does. Because these
 * productions did not exist before #35, every positive case here FAILS against
 * the pre-production compiler (it returns a typed "Unknown pipeline stage" /
 * "Expected valid source" / "Unknown function call" error) and PASSES after
 * (red -> green, AC1/AC2).
 *
 * The negative cases feed a malformed clause for each operator and assert a
 * typed parse error is returned, fail closed, under ASan+UBSan (AC4).
 */
#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <string.h>

#include "unity.h"
#include "cdb_compiler.h"
#include "cdb_query.h"

static uint8_t wire[4096];
static cdb_compile_error err;

void setUp(void)
{
    memset(wire, 0, sizeof wire);
    memset(&err, 0, sizeof err);
}

void tearDown(void) {}

/* Compile CMBQL text, assert success, validate, and decode the root node. */
static void compile_root(const char *text, cdb_query_node *node)
{
    size_t wlen = 0;
    size_t root_off = 0;
    const uint8_t *p;
    cdb_status s = cdb_compile_query(text, strlen(text), NULL, wire, sizeof wire, &wlen, &err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, s, err.msg);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_validate(wire, wlen, &root_off));
    p = wire + root_off;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_node(&p, wire + wlen, node));
}

/* Assert that compiling malformed text fails closed with a typed error. */
static void assert_compile_rejected(const char *text)
{
    size_t wlen = 0;
    cdb_status s = cdb_compile_query(text, strlen(text), NULL, wire, sizeof wire, &wlen, &err);
    TEST_ASSERT_TRUE_MESSAGE(s != CDB_OK, "malformed CMBQL must fail closed");
    TEST_ASSERT_TRUE(s == CDB_E_INVALID_ARG || s == CDB_E_DEPTH);
}

/* ---- TEXT_SEARCH ---- */
static void test_text_search_pipe(void)
{
    cdb_query_node n;
    compile_root("Scan(\"notes\") | text_search(query: \"alpha\", mode: \"all\", "
                 "limit: 10, fields: [\"body\", \"title\"])",
                 &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_TEXT_SEARCH, n.tag);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_FTS_ALL, n.as.text_search.mode);
    TEST_ASSERT_EQUAL_UINT64(10, n.as.text_search.limit);
    TEST_ASSERT_EQUAL_STRING_LEN("alpha", n.as.text_search.query, 5);
    TEST_ASSERT_EQUAL_size_t(2, n.as.text_search.n_fields);
    TEST_ASSERT_NOT_NULL(n.as.text_search.input_wire);
}

static void test_text_search_constructor(void)
{
    cdb_query_node n;
    compile_root("TextSearch(Scan(\"notes\"), query: \"beta\")", &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_TEXT_SEARCH, n.tag);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_FTS_ANY, n.as.text_search.mode);
    TEST_ASSERT_EQUAL_STRING_LEN("beta", n.as.text_search.query, 4);
}

/* ---- VECTOR_SEARCH ---- */
static void test_vector_search_pipe(void)
{
    cdb_query_node n;
    compile_root("Scan(\"emb\") | vector_search(field: \"$vector\", near: $0, k: 5, "
                 "metric: \"cosine\")",
                 &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_VECTOR_SEARCH, n.tag);
    TEST_ASSERT_EQUAL_STRING_LEN("$vector", n.as.vector_search.field, 7);
    TEST_ASSERT_EQUAL_UINT64(5, n.as.vector_search.k);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_METRIC_COSINE, n.as.vector_search.metric);
    TEST_ASSERT_NOT_NULL(n.as.vector_search.near_wire);
}

/* ---- TRAVERSE ---- */
static void test_traverse_pipe(void)
{
    cdb_query_node n;
    compile_root("Scan(\"users\") | traverse(link: \"follows\", dir: \"rev\", min: 1, max: 3)", &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_TRAVERSE, n.tag);
    TEST_ASSERT_EQUAL_STRING_LEN("follows", n.as.traverse.link_type, 7);
    TEST_ASSERT_EQUAL_UINT8(CDB_TRAVERSE_REV, n.as.traverse.dir);
    TEST_ASSERT_EQUAL_UINT64(1, n.as.traverse.min_hops);
    TEST_ASSERT_EQUAL_UINT64(3, n.as.traverse.max_hops);
}

/* ---- HYBRID_RANK ---- */
static void test_hybrid_rank_constructor(void)
{
    cdb_query_node n;
    compile_root("HybridRank(branches: [TextSearch(Scan(\"notes\"), query: \"a\"), "
                 "TextSearch(Scan(\"notes\"), query: \"b\")], weights: [1000, 500])",
                 &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_HYBRID_RANK, n.tag);
    TEST_ASSERT_EQUAL_UINT8(CDB_FUSE_RRF, n.as.hybrid_rank.fuse);
    TEST_ASSERT_EQUAL_size_t(2, n.as.hybrid_rank.count);
}

/* ---- AGGREGATE + count(*) (closes BACKLOG items) ---- */
static void test_aggregate_pipe(void)
{
    cdb_query_node n;
    compile_root("Scan(\"telemetry\") | aggregate(by: [device_id], avg_v: avg(voltage), "
                 "n: count(*))",
                 &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_AGGREGATE, n.tag);
    TEST_ASSERT_EQUAL_size_t(1, n.as.aggregate.n_groups);
    TEST_ASSERT_EQUAL_size_t(2, n.as.aggregate.n_aggs);
}

static void test_count_star(void)
{
    cdb_query_node n;
    /* count(*) used to error "Unknown function call"; now compiles in aggregate. */
    compile_root("Scan(\"t\") | aggregate(total: count(*))", &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_AGGREGATE, n.tag);
    TEST_ASSERT_EQUAL_size_t(0, n.as.aggregate.n_groups);
    TEST_ASSERT_EQUAL_size_t(1, n.as.aggregate.n_aggs);
}

/* ---- ASOF_JOIN ---- */
static void test_asof_join_constructor(void)
{
    cdb_query_node n;
    compile_root("AsofJoin(Scan(\"events\"), Scan(\"metrics\"), left_time: ts, "
                 "right_time: ts, kind: \"forward\", tolerance: 5000)",
                 &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_ASOF_JOIN, n.tag);
    TEST_ASSERT_EQUAL_UINT8(CDB_ASOF_FORWARD, n.as.asof_join.kind);
    TEST_ASSERT_EQUAL_UINT64(5000, n.as.asof_join.tolerance_ns);
}

/* ---- UNNEST ---- */
static void test_unnest_pipe(void)
{
    cdb_query_node n;
    compile_root("Scan(\"docs\") | unnest(tags AS tag)", &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_UNNEST, n.tag);
    TEST_ASSERT_EQUAL_STRING_LEN("tag", n.as.unnest.item_alias, 3);
    TEST_ASSERT_EQUAL_size_t(3, n.as.unnest.item_alias_len);
}

/* ---- UNION ---- */
static void test_union_constructor(void)
{
    cdb_query_node n;
    compile_root("Union(Scan(\"a\"), Scan(\"b\"), Scan(\"c\"))", &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_UNION, n.tag);
    TEST_ASSERT_EQUAL_size_t(3, n.as.union_node.count);
}

static void test_union_pipe(void)
{
    cdb_query_node n;
    compile_root("Scan(\"a\") | union(Scan(\"b\"))", &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_UNION, n.tag);
    TEST_ASSERT_EQUAL_size_t(2, n.as.union_node.count);
}

/* ---- Reserved word as field (FR-A3) ---- */
static void test_reserved_word_as_field(void)
{
    cdb_query_node n;
    compile_root("Scan(\"metrics\") | filter(time > 100 AND source == \"probe\")", &n);
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_FILTER, n.tag);
}

/* ---- Malformed clauses fail closed (AC4) ---- */
static void test_malformed_text_search_no_query(void)
{
    assert_compile_rejected("Scan(\"n\") | text_search(limit: 5)");
}
static void test_malformed_vector_search_no_near(void)
{
    assert_compile_rejected("Scan(\"e\") | vector_search(field: \"v\")");
}
static void test_malformed_traverse_bad_dir(void)
{
    assert_compile_rejected("Scan(\"u\") | traverse(link: \"f\", dir: \"sideways\")");
}
static void test_malformed_aggregate_bad_fn(void)
{
    assert_compile_rejected("Scan(\"t\") | aggregate(x: bogus(y))");
}
static void test_malformed_hybrid_rank_no_branches(void)
{
    assert_compile_rejected("HybridRank(fuse: \"rrf\")");
}
static void test_malformed_asof_join_missing_times(void)
{
    assert_compile_rejected("AsofJoin(Scan(\"a\"), Scan(\"b\"), kind: \"backward\")");
}
static void test_malformed_unnest_no_expr(void)
{
    assert_compile_rejected("Scan(\"d\") | unnest()");
}
static void test_malformed_union_single_branch(void)
{
    assert_compile_rejected("Union(Scan(\"a\"))");
}
static void test_malformed_traverse_inverted_hops(void)
{
    assert_compile_rejected("Scan(\"u\") | traverse(link: \"f\", dir: \"fwd\", min: 5, max: 2)");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_text_search_pipe);
    RUN_TEST(test_text_search_constructor);
    RUN_TEST(test_vector_search_pipe);
    RUN_TEST(test_traverse_pipe);
    RUN_TEST(test_hybrid_rank_constructor);
    RUN_TEST(test_aggregate_pipe);
    RUN_TEST(test_count_star);
    RUN_TEST(test_asof_join_constructor);
    RUN_TEST(test_unnest_pipe);
    RUN_TEST(test_union_constructor);
    RUN_TEST(test_union_pipe);
    RUN_TEST(test_reserved_word_as_field);
    RUN_TEST(test_malformed_text_search_no_query);
    RUN_TEST(test_malformed_vector_search_no_near);
    RUN_TEST(test_malformed_traverse_bad_dir);
    RUN_TEST(test_malformed_aggregate_bad_fn);
    RUN_TEST(test_malformed_hybrid_rank_no_branches);
    RUN_TEST(test_malformed_asof_join_missing_times);
    RUN_TEST(test_malformed_unnest_no_expr);
    RUN_TEST(test_malformed_union_single_branch);
    RUN_TEST(test_malformed_traverse_inverted_hops);
    return UNITY_END();
}
