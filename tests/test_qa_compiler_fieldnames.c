/* QA edge/abuse tests for CMBQL compiler field-name fidelity (#36 FR3 + FR4).
 *
 * Complements the implementer's test_compiler_fieldnames.c with cases it does
 * not cover: a multi-segment backtick identifier (`a.b.c`) whose literal dots
 * survive (and contain no 0x1F path separator), the canonical `where type = x`
 * full predicate round-trip, a broader sweep of reserved keywords as fields,
 * keywords at project/group/sort positions, and an abusively long (1000-byte)
 * backtick identifier that fails closed with CDB_E_OVERFLOW rather than
 * reading out of bounds or silently truncating.
 *
 * Deterministic and hermetic: pure string compilation, no catalog, no I/O.
 * Pre-fix the merge-base compiled a backtick identifier as a STRING LITERAL and
 * truncated an over-255 path silently; the FR3/FR4 assertions are red there.
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

/* Compiles `Scan("t") | filter(<expr>)` and returns the filter's predicate
 * expression (bytes live in the caller wire buffer). Reports the wire length so
 * callers can bound sub-expression reads. */
static cdb_status compile_pred(const char *pred, uint8_t *wire, size_t wire_cap, size_t *out_wlen,
                               cdb_query_expr *out_pred)
{
    char text[2048];
    size_t wlen = 0, root_off = 0;
    cdb_compile_error err;
    cdb_query_node node;
    const uint8_t *p;
    cdb_status s;
    int n;

    memset(&err, 0, sizeof err);
    n = snprintf(text, sizeof text, "Scan(\"t\") | filter(%s)", pred);
    TEST_ASSERT_TRUE((size_t)n < sizeof text); /* no snprintf truncation */
    s = cdb_compile_query(text, (size_t)n, NULL, wire, wire_cap, &wlen, &err);
    if (s != CDB_OK)
        return s;
    *out_wlen = wlen;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_validate(wire, wlen, &root_off));
    p = wire + root_off;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_node(&p, wire + wlen, &node));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_FILTER, node.tag);
    p = node.as.filter.pred_wire;
    return cdb_query_read_expr(&p, wire + wlen, out_pred);
}

/* Convenience: compile `filter(<lhs> > 1)` and return its LHS expression. */
static cdb_status compile_lhs(const char *lhs, uint8_t *wire, size_t wire_cap, cdb_query_expr *out)
{
    char expr[320];
    cdb_query_expr bin;
    size_t wlen = 0;
    const uint8_t *p;
    cdb_status s;
    int n = snprintf(expr, sizeof expr, "%s > 1", lhs);
    TEST_ASSERT_TRUE((size_t)n < sizeof expr);
    s = compile_pred(expr, wire, wire_cap, &wlen, &bin);
    if (s != CDB_OK)
        return s;
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_BINARY, bin.tag);
    p = bin.as.binary.left_wire;
    return cdb_query_read_expr(&p, wire + wlen, out);
}

/* ---- FR3: a multi-segment backtick identifier keeps every literal dot ----
 * `a.b.c` must be a single field path of exactly the 5 bytes "a.b.c" with
 * literal 0x2E dots and NO 0x1F path separator (the schemaless joiner used for
 * unquoted dotted paths). Pre-fix this compiled to a string literal. */
static void test_backtick_multi_dot_literal(void)
{
    uint8_t wire[4096];
    cdb_query_expr lhs;
    size_t i;

    TEST_ASSERT_EQUAL_INT(CDB_OK, compile_lhs("`a.b.c`", wire, sizeof wire, &lhs));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_FIELD, lhs.tag);
    TEST_ASSERT_EQUAL_size_t(5, lhs.as.field.len);
    TEST_ASSERT_EQUAL_MEMORY("a.b.c", lhs.as.field.path, 5);
    for (i = 0; i < lhs.as.field.len; i++)
        TEST_ASSERT_NOT_EQUAL_UINT8(0x1F, (uint8_t)lhs.as.field.path[i]); /* no separator */
}

/* ---- FR4: the canonical `where type = "x"` round-trips ----
 * The predicate's LHS is the field `type` (not a parse error on the keyword),
 * and the RHS is the string literal. */
static void test_where_keyword_equals_literal(void)
{
    uint8_t wire[4096];
    size_t wlen = 0;
    cdb_query_expr pred, lhs, rhs;
    const uint8_t *p;

    TEST_ASSERT_EQUAL_INT(CDB_OK, compile_pred("type = \"x\"", wire, sizeof wire, &wlen, &pred));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_BINARY, pred.tag);
    TEST_ASSERT_EQUAL_UINT8(CDB_BIN_EQ, pred.as.binary.op);

    p = pred.as.binary.left_wire;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, wire + wlen, &lhs));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_FIELD, lhs.tag);
    TEST_ASSERT_EQUAL_size_t(4, lhs.as.field.len);
    TEST_ASSERT_EQUAL_MEMORY("type", lhs.as.field.path, 4);

    p = pred.as.binary.right_wire;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, wire + wlen, &rhs));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_LITERAL, rhs.tag);
}

/* ---- FR4: a sweep of reserved keywords all resolve as fields ---- */
static void test_reserved_keyword_sweep(void)
{
    uint8_t wire[4096];
    cdb_query_expr lhs;
    size_t i;
    static const char *const kws[] = {"type",   "time",  "data", "source", "weight",   "model",
                                      "age",    "tags",  "role", "series", "summary",  "store"};

    for (i = 0; i < sizeof(kws) / sizeof(kws[0]); i++) {
        TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, compile_lhs(kws[i], wire, sizeof wire, &lhs), kws[i]);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(CDB_QUERY_EXPR_FIELD, lhs.tag, kws[i]);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(kws[i], lhs.as.field.path, strlen(kws[i]), kws[i]);
    }
}

/* ---- FR4: keywords usable at project / group / sort positions ---- */
static void test_reserved_keyword_positions(void)
{
    uint8_t wire[4096];
    size_t wlen = 0;
    cdb_compile_error err;
    size_t i;
    static const char *const ok[] = {
        "Scan(\"t\") | project(type, source AS s)",
        "Scan(\"t\") | sort(weight DESC, age ASC)",
        "Scan(\"t\") | aggregate(by: [model, source], n: count(*))",
        "Scan(\"t\") | filter(type = \"a\" and source = \"b\")",
    };
    for (i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        memset(&err, 0, sizeof err);
        TEST_ASSERT_EQUAL_INT_MESSAGE(
            CDB_OK, cdb_compile_query(ok[i], strlen(ok[i]), NULL, wire, sizeof wire, &wlen, &err),
            ok[i]);
    }
}

/* ---- FR3 (abuse): an abusively long backtick identifier fails closed ----
 * A 1000-byte backtick identifier is far past the 255-byte path cap. It must
 * return CDB_E_OVERFLOW (not truncate, not read out of bounds — ASan/UBSan
 * verify the latter). */
static void test_backtick_huge_overflow(void)
{
    uint8_t wire[4096];
    char text[1200];
    size_t wlen = 0, pos = 0, i;
    cdb_compile_error err;
    const char *head = "Scan(\"t\") | filter(`";
    const char *tail = "` > 1)";

    memset(&err, 0, sizeof err);
    memcpy(text + pos, head, strlen(head));
    pos += strlen(head);
    for (i = 0; i < 1000; i++)
        text[pos++] = 'a';
    memcpy(text + pos, tail, strlen(tail));
    pos += strlen(tail);

    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW,
                          cdb_compile_query(text, pos, NULL, wire, sizeof wire, &wlen, &err));
}

/* ---- FR3: a double-quoted dotted string stays a literal (discriminator) ---- */
static void test_doublequote_dotted_is_literal(void)
{
    uint8_t wire[4096];
    cdb_query_expr lhs;

    TEST_ASSERT_EQUAL_INT(CDB_OK, compile_lhs("\"x.y.z\"", wire, sizeof wire, &lhs));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_LITERAL, lhs.tag);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_backtick_multi_dot_literal);
    RUN_TEST(test_where_keyword_equals_literal);
    RUN_TEST(test_reserved_keyword_sweep);
    RUN_TEST(test_reserved_keyword_positions);
    RUN_TEST(test_backtick_huge_overflow);
    RUN_TEST(test_doublequote_dotted_is_literal);
    return UNITY_END();
}
