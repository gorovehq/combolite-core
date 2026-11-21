/* Regression + abuse suite for F2 / GHSA-rf29-8939-p85v (CWE-674, uncontrolled
 * recursion) — the CMBQL recursive-descent parser.
 *
 * VULN: cdb_compile_query parsed untrusted query text with NO recursion-depth
 * bound. Two mutually-recursive cycles are reachable from the query string:
 *   - query/source cycle: parse_query -> parse_source -> parse_query   (subquery '(')
 *   - expression cycle:   parse_expr -> ... -> parse_primary -> parse_expr
 *                         (parenthesised sub-expr, function argument) and
 *                         parse_unary -> parse_unary                   (NOT/'!'/MINUS).
 * A bare '(' (or '!') allocates no AST node, so depth was bounded only by input
 * length: tens of thousands of nested '(' / '!' drove unbounded C recursion ->
 * stack overflow -> SIGSEGV. The parser failed OPEN.
 *
 * RED->GREEN ORACLE: the abuse assertions SIGSEGV / stack-overflow (ASan reports
 * stack-overflow, process aborts) against the PRE-FIX parser, and PASS against
 * the fixed parser, which rejects over-deep input with a compile error
 * (CDB_E_DEPTH) instead of recursing. The guard must be TOTAL — each of the four
 * recursive edges is exercised independently (paren-expr, function-arg, unary,
 * subquery) so a cap that misses one edge still fails the suite.
 *
 * NO REGRESSION: valid flat, modestly-nested, and near-but-under-cap legitimate
 * queries must still compile to CDB_OK (the fix must not change behaviour for
 * reasonably-nested input). Spec 11.1. CWE-674. */
#include "unity.h"
#include "cdb_compiler.h"
#include <string.h>

/* Abuse nesting: well past CDB_CMBQL_MAX_DEPTH (64) and large enough that the
 * unbounded (pre-fix) parser overflows a default 8 MiB stack. */
#define DEEP 50000u
/* Legitimate nesting comfortably under the cap — proves no off-by-one regression
 * for input a human might plausibly write. */
#define NEAR 20u
#define BUFSZ (DEEP * 2u + 256u)

/* Caller-owned scratch (honors the no-heap/caller-owned memory model; kept off
 * the stack so the test's own frame stays small). */
static char g_buf[BUFSZ];

void setUp(void) {}
void tearDown(void) {}

/* Writes prefix + n*'(' + inner + n*')' + '\0' into buf (bounded by cap).
 * Returns bytes written (excluding the terminator). */
static size_t build_paren_nest(char *buf, size_t cap, const char *prefix,
                               size_t n, const char *inner) {
    size_t pos = 0;
    size_t i = 0;
    size_t plen = strlen(prefix);
    size_t ilen = strlen(inner);
    for (i = 0; i < plen && pos + 1u < cap; i++) buf[pos++] = prefix[i];
    for (i = 0; i < n && pos + 1u < cap; i++) buf[pos++] = '(';
    for (i = 0; i < ilen && pos + 1u < cap; i++) buf[pos++] = inner[i];
    for (i = 0; i < n && pos + 1u < cap; i++) buf[pos++] = ')';
    buf[pos] = '\0';
    return pos;
}

/* Writes prefix + n*fill + suffix + '\0' into buf (bounded by cap).
 * Returns bytes written (excluding the terminator). */
static size_t build_prefix_repeat(char *buf, size_t cap, const char *prefix,
                                  char fill, size_t n, const char *suffix) {
    size_t pos = 0;
    size_t i = 0;
    size_t plen = strlen(prefix);
    size_t slen = strlen(suffix);
    for (i = 0; i < plen && pos + 1u < cap; i++) buf[pos++] = prefix[i];
    for (i = 0; i < n && pos + 1u < cap; i++) buf[pos++] = fill;
    for (i = 0; i < slen && pos + 1u < cap; i++) buf[pos++] = suffix[i];
    buf[pos] = '\0';
    return pos;
}

/* Writes prefix + n*(fill + ' ') + suffix + '\0' into buf (bounded by cap).
 * Space-separates each fill char so a two-char operator (e.g. unary "- -") is NOT
 * re-lexed as a single '--' line comment: each '-' stays an independent MINUS
 * token, which is what drives parse_unary's MINUS self-recursion. Returns bytes
 * written (excluding the terminator). */
static size_t build_spaced_repeat(char *buf, size_t cap, const char *prefix,
                                  char fill, size_t n, const char *suffix) {
    size_t pos = 0;
    size_t i = 0;
    size_t plen = strlen(prefix);
    size_t slen = strlen(suffix);
    for (i = 0; i < plen && pos + 1u < cap; i++) buf[pos++] = prefix[i];
    for (i = 0; i < n && pos + 2u < cap; i++) { buf[pos++] = fill; buf[pos++] = ' '; }
    for (i = 0; i < slen && pos + 1u < cap; i++) buf[pos++] = suffix[i];
    buf[pos] = '\0';
    return pos;
}

/* Compile helper that discards diagnostics (returns only the status). */
static cdb_status compile(const char *src, size_t len) {
    uint8_t wire[2048];
    size_t wire_len = 0;
    cdb_compile_error err;
    memset(wire, 0, sizeof(wire));
    memset(&err, 0, sizeof(err));
    return cdb_compile_query(src, len, NULL, wire, sizeof(wire), &wire_len, &err);
}

/* ---- Abuse / negative paths: each independent recursive edge must fail closed ---- */

/* Edge 1 — query/source cycle: deeply nested bare parens (subquery recursion). */
static void test_deep_paren_rejected(void) {
    size_t len = build_paren_nest(g_buf, sizeof(g_buf), "", DEEP, "1");
    cdb_status s = compile(g_buf, len);
    TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(CDB_OK, s, "deep parens must be rejected, not crash");
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_DEPTH, s, "expected CDB_E_DEPTH for deep parens");
}

/* Edge 1 — query/source cycle: deeply nested subqueries wrapping a real SELECT. */
static void test_deep_subquery_rejected(void) {
    size_t len = build_paren_nest(g_buf, sizeof(g_buf), "", DEEP,
                                  "SELECT title FROM Scan(\"books\")");
    cdb_status s = compile(g_buf, len);
    TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(CDB_OK, s, "deep subqueries must be rejected");
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_DEPTH, s, "expected CDB_E_DEPTH for deep subqueries");
}

/* Edge 2 — expression cycle: deeply nested parens inside a filter expression. */
static void test_deep_expr_paren_rejected(void) {
    size_t len = build_paren_nest(g_buf, sizeof(g_buf), "Scan(\"x\") | filter(",
                                  DEEP, "1");
    cdb_status s = compile(g_buf, len);
    TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(CDB_OK, s, "deep expr parens must be rejected");
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_DEPTH, s, "expected CDB_E_DEPTH for deep expr parens");
}

/* Edge 3 — expression cycle: deeply nested unary operators (parse_unary self-recursion). */
static void test_deep_unary_rejected(void) {
    size_t len = build_prefix_repeat(g_buf, sizeof(g_buf), "Scan(\"x\") | filter(",
                                     '!', DEEP, "x)");
    cdb_status s = compile(g_buf, len);
    TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(CDB_OK, s, "deep unary must be rejected");
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_DEPTH, s, "expected CDB_E_DEPTH for deep unary");
}

/* Edge 4 — expression cycle: deeply nested unary MINUS (second parse_unary edge).
 * Minuses are space-separated ("- - - … x"): consecutive '--' would be lexed as a
 * line comment (cdb_lexer.c), so spacing keeps each a distinct MINUS token that
 * re-enters parse_unary, exercising the MINUS recursion edge independently. */
static void test_deep_unary_minus_rejected(void) {
    size_t len = build_spaced_repeat(g_buf, sizeof(g_buf), "Scan(\"x\") | filter(",
                                     '-', DEEP, "x)");
    cdb_status s = compile(g_buf, len);
    TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(CDB_OK, s, "deep unary minus must be rejected");
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_DEPTH, s, "expected CDB_E_DEPTH for deep unary minus");
}

/* Fail-closed quality: rejection populates a bounded diagnostic and does NOT echo
 * the attacker payload back (no info disclosure, msg stays within its buffer). */
static void test_depth_error_is_diagnosed_not_leaked(void) {
    uint8_t wire[2048];
    size_t wire_len = 0;
    cdb_compile_error err;
    size_t len = build_paren_nest(g_buf, sizeof(g_buf), "", DEEP, "1");
    cdb_status s = CDB_OK;
    memset(wire, 0, sizeof(wire));
    memset(&err, 0, sizeof(err));
    s = cdb_compile_query(g_buf, len, NULL, wire, sizeof(wire), &wire_len, &err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_DEPTH, s, "over-depth must map to CDB_E_DEPTH");
    TEST_ASSERT_TRUE_MESSAGE(err.msg[0] != '\0', "depth error must set a diagnostic message");
    /* msg is a fixed 128-byte buffer; it must remain NUL-terminated within bounds
     * (no unbounded payload interpolation). */
    TEST_ASSERT_TRUE_MESSAGE(memchr(err.msg, '\0', sizeof(err.msg)) != NULL,
                             "error message must be NUL-terminated within its buffer");
    /* No wire output is emitted on a failed compile. */
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0u, (unsigned)wire_len,
                                   "no wire output on rejected (over-depth) query");
}

/* ---- No-regression paths: valid queries, incl. legitimate nesting, still compile ---- */

static void test_valid_flat_query_compiles(void) {
    const char *q = "SELECT title FROM Scan(\"books\") WHERE score >= 0.8;";
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, compile(q, strlen(q)),
                                  "valid flat query must compile");
}

static void test_valid_modest_nesting_compiles(void) {
    const char *q = "Scan(\"x\") | filter(((temp > 85.0)));";
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, compile(q, strlen(q)),
                                  "valid modestly-nested query must compile");
}

/* Near-but-under-cap legitimate nesting must still compile: proves the cap leaves
 * generous headroom for valid input and has no off-by-one at the lower boundary. */
static void test_valid_near_cap_nesting_compiles(void) {
    size_t len = build_paren_nest(g_buf, sizeof(g_buf), "Scan(\"x\") | filter(",
                                  NEAR, "temp > 1");
    /* close the enclosing filter( ... ) */
    if (len + 1u < sizeof(g_buf)) { g_buf[len++] = ')'; g_buf[len] = '\0'; }
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, compile(g_buf, len),
                                  "legitimate near-cap nesting must still compile");
}

int main(void) {
    UNITY_BEGIN();
    /* abuse / negative — all four recursive edges + fail-closed diagnostics */
    RUN_TEST(test_deep_paren_rejected);
    RUN_TEST(test_deep_subquery_rejected);
    RUN_TEST(test_deep_expr_paren_rejected);
    RUN_TEST(test_deep_unary_rejected);
    RUN_TEST(test_deep_unary_minus_rejected);
    RUN_TEST(test_depth_error_is_diagnosed_not_leaked);
    /* no regression */
    RUN_TEST(test_valid_flat_query_compiles);
    RUN_TEST(test_valid_modest_nesting_compiles);
    RUN_TEST(test_valid_near_cap_nesting_compiles);
    return UNITY_END();
}
