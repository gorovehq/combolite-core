/* Red->green regression tests for CMBQL compiler field-name fidelity (#36):
 *   FR3 backtick quoted-identifier that preserves a literal dot, and an
 *       over-255-byte path that is a typed compile error (not silent
 *       truncation); and
 *   FR4 reserved keywords usable as field names at field/expression
 *       positions (verifying the #35 behavior, incl. count(*)).
 *
 * Deterministic and hermetic: pure string compilation, no catalog, no I/O.
 * Pre-fix the merge-base compiles a backtick identifier as a STRING LITERAL
 * (so `a.b` is not a field reference) and truncates an over-255 path silently.
 */
#include "unity.h"
#include "cdb_query.h"
#include "cdb_compiler.h"

#include <string.h>

void setUp(void)
{
}
void tearDown(void)
{
}

/* Compiles `Scan("t") | filter(<lhs> > 1)` and returns the LHS expr of the
 * filter predicate (its bytes live in the caller-provided wire buffer). */
static cdb_status compile_filter_lhs(const char *lhs_expr, uint8_t *wire, size_t wire_cap,
                                     cdb_query_expr *out_lhs)
{
    char text[512];
    size_t wlen = 0, root_off = 0;
    cdb_compile_error err;
    cdb_query_node node;
    cdb_query_expr bin;
    const uint8_t *p;
    cdb_status s;
    int n;

    memset(&err, 0, sizeof err);
    n = snprintf(text, sizeof text, "Scan(\"t\") | filter(%s > 1)", lhs_expr);
    s = cdb_compile_query(text, (size_t)n, NULL, wire, wire_cap, &wlen, &err);
    if (s != CDB_OK)
        return s;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_validate(wire, wlen, &root_off));
    p = wire + root_off;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_node(&p, wire + wlen, &node));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_FILTER, node.tag);
    p = node.as.filter.pred_wire;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, wire + wlen, &bin));
    p = bin.as.binary.left_wire;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, wire + wlen, out_lhs));
    return CDB_OK;
}

/* ---- FR3 (AC5): a backtick identifier is a field with a literal dot ---- */
static void test_backtick_preserves_literal_dot(void)
{
    uint8_t wire[4096];
    cdb_query_expr lhs;

    TEST_ASSERT_EQUAL_INT(CDB_OK, compile_filter_lhs("`a.b`", wire, sizeof wire, &lhs));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_FIELD, lhs.tag); /* a field, not a literal */
    TEST_ASSERT_EQUAL_size_t(3, lhs.as.field.len);
    TEST_ASSERT_EQUAL_MEMORY("a.b", lhs.as.field.path, 3); /* exact bytes, dot intact */
}

/* ---- FR3: a double-quoted string stays a string literal (discriminator) ---- */
static void test_doublequote_stays_literal(void)
{
    uint8_t wire[4096];
    cdb_query_expr lhs;

    TEST_ASSERT_EQUAL_INT(CDB_OK, compile_filter_lhs("\"a.b\"", wire, sizeof wire, &lhs));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_LITERAL, lhs.tag);
}

/* ---- FR3: an unquoted dotted path keeps its 0x1F-joined schemaless form ---- */
static void test_unquoted_dotted_path_separator(void)
{
    uint8_t wire[4096];
    cdb_query_expr lhs;
    const char expect[] = {'a', 0x1F, 'b', 0x1F, 'c'};

    TEST_ASSERT_EQUAL_INT(CDB_OK, compile_filter_lhs("a.b.c", wire, sizeof wire, &lhs));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_FIELD, lhs.tag);
    TEST_ASSERT_EQUAL_size_t(5, lhs.as.field.len);
    TEST_ASSERT_EQUAL_MEMORY(expect, lhs.as.field.path, 5);
}

/* Builds a backtick-quoted identifier of n inner bytes into dst. */
static void make_backtick(char *dst, size_t n)
{
    size_t i;
    dst[0] = '`';
    for (i = 0; i < n; i++)
        dst[1 + i] = 'a';
    dst[1 + n] = '`';
    dst[2 + n] = '\0';
}

/* ---- FR3 (AC6): an over-255 path is a typed error, not truncation ---- */
static void test_over_255_path_errors(void)
{
    uint8_t wire[4096];
    cdb_query_expr lhs;
    char lhs255[260];
    char lhs256[260];

    /* Exactly 255 bytes still compiles to a field. */
    make_backtick(lhs255, 255);
    TEST_ASSERT_EQUAL_INT(CDB_OK, compile_filter_lhs(lhs255, wire, sizeof wire, &lhs));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_FIELD, lhs.tag);
    TEST_ASSERT_EQUAL_size_t(255, lhs.as.field.len);

    /* 256 bytes fails closed with the documented overflow status. */
    make_backtick(lhs256, 256);
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, compile_filter_lhs(lhs256, wire, sizeof wire, &lhs));
}

/* ---- FR3 (AC6): an unquoted over-255 dotted path also errors ---- */
static void test_over_255_dotted_path_errors(void)
{
    uint8_t wire[4096];
    cdb_query_expr lhs;
    char text[600];
    size_t i;

    /* "aaa...(300).b" — a 300-char first segment exceeds the path cap. */
    for (i = 0; i < 300; i++)
        text[i] = 'a';
    text[300] = '.';
    text[301] = 'b';
    text[302] = '\0';
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, compile_filter_lhs(text, wire, sizeof wire, &lhs));
}

/* ---- FR4 (AC7): reserved keywords resolve as fields ---- */
static void test_reserved_keyword_as_field(void)
{
    uint8_t wire[4096];
    cdb_query_expr lhs;

    TEST_ASSERT_EQUAL_INT(CDB_OK, compile_filter_lhs("type", wire, sizeof wire, &lhs));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_FIELD, lhs.tag);
    TEST_ASSERT_EQUAL_MEMORY("type", lhs.as.field.path, 4);

    TEST_ASSERT_EQUAL_INT(CDB_OK, compile_filter_lhs("weight", wire, sizeof wire, &lhs));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_FIELD, lhs.tag);
    TEST_ASSERT_EQUAL_MEMORY("weight", lhs.as.field.path, 6);

    TEST_ASSERT_EQUAL_INT(CDB_OK, compile_filter_lhs("model", wire, sizeof wire, &lhs));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_FIELD, lhs.tag);
}

/* ---- FR4 (AC7): keywords as fields in sort / project / group positions ---- */
static void test_reserved_keyword_other_positions(void)
{
    uint8_t wire[4096];
    size_t wlen = 0;
    cdb_compile_error err;

    static const char *const ok[] = {
        "Scan(\"t\") | sort(type DESC, weight ASC)",
        "Scan(\"t\") | project(type, data AS d)",
        "Scan(\"t\") | aggregate(by: [type, source], n: count(*))",
        "Scan(\"t\") | sort(`a.b` ASC)",
    };
    size_t i;
    for (i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        memset(&err, 0, sizeof err);
        TEST_ASSERT_EQUAL_INT_MESSAGE(
            CDB_OK, cdb_compile_query(ok[i], strlen(ok[i]), NULL, wire, sizeof wire, &wlen, &err),
            ok[i]);
    }
}

/* ---- FR4 (AC8): count(*) / aggregate-in-text still compiles (#35 guard) ---- */
static void test_count_star_aggregate(void)
{
    uint8_t wire[4096];
    size_t wlen = 0, root_off = 0;
    cdb_compile_error err;
    cdb_query_node node;
    const uint8_t *p;
    const char *text = "Scan(\"telemetry\") | aggregate(by: [device_id], n: count(*))";

    memset(&err, 0, sizeof err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        CDB_OK, cdb_compile_query(text, strlen(text), NULL, wire, sizeof wire, &wlen, &err),
        err.msg);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_validate(wire, wlen, &root_off));
    p = wire + root_off;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_node(&p, wire + wlen, &node));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_AGGREGATE, node.tag);
    TEST_ASSERT_EQUAL_size_t(1, node.as.aggregate.n_groups);
    TEST_ASSERT_EQUAL_size_t(1, node.as.aggregate.n_aggs);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_backtick_preserves_literal_dot);
    RUN_TEST(test_doublequote_stays_literal);
    RUN_TEST(test_unquoted_dotted_path_separator);
    RUN_TEST(test_over_255_path_errors);
    RUN_TEST(test_over_255_dotted_path_errors);
    RUN_TEST(test_reserved_keyword_as_field);
    RUN_TEST(test_reserved_keyword_other_positions);
    RUN_TEST(test_count_star_aggregate);
    return UNITY_END();
}
