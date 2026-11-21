/* Regression test for GHSA-rf29-8939-p85v / finding F3 (CWE-674):
 * untrusted query-wire / proc-bytecode recursion was unbounded in
 * cdb_query_skip_expr, cdb_query_skip_node (reached via cdb_query_validate),
 * and build_exec_tree (reached via cdb_exec_open). Crafted deeply-nested wire
 * (~2-3 bytes per level) drove unbounded C recursion to a stack overflow
 * (SIGSEGV) in the very code that gates untrusted input.
 *
 * Red->green oracle: the abuse cases below SIGSEGV against the pre-fix code and
 * return the typed error CDB_E_DEPTH (not a crash/hang) after the fix, under
 * ASan+UBSan. The no-regression cases confirm valid, modestly-nested wire still
 * parses. Every local is initialized at its declaration.
 *
 * Coverage of the three bounded descents (design ADR-F3-6, AC2-AC5):
 *   - cdb_query_skip_expr            : expr self-recursion (direct + via node)
 *   - cdb_query_skip_node / validate : node self-recursion + node->expr edge
 *   - build_exec_tree / cdb_exec_open: public entry, defense-in-depth descent */
#include "unity.h"

#include "cdb_exec.h"
#include "cdb_query.h"

#include <stdint.h>
#include <stdlib.h>

/* Nesting depth used for the abuse cases: far past the CDB_QUERY_MAX_DEPTH (64)
 * runtime cap and deep enough to overflow a typical thread stack pre-fix. */
#define WIRE_DEPTH_ABUSE 300000u
/* A valid, modestly-nested depth, well within the cap. */
#define WIRE_DEPTH_OK 5u

void setUp(void) {}
void tearDown(void) {}

/* Builds an expression-nesting chain: `levels` UNARY(NOT) wrappers around a
 * single empty FIELD leaf. Each UNARY level is 2 bytes; the leaf is 2 bytes.
 * Returns a malloc'd buffer (caller frees) and writes its length to *out_len. */
static uint8_t *build_expr_chain(size_t levels, size_t *out_len)
{
    size_t len = (levels * 2u) + 2u;
    uint8_t *buf = (uint8_t *)malloc(len);
    size_t i = 0;
    if (buf == NULL)
        return NULL;
    for (i = 0; i < levels; i++) {
        buf[i * 2u] = (uint8_t)CDB_QUERY_EXPR_UNARY;
        buf[(i * 2u) + 1u] = (uint8_t)CDB_UNARY_NOT;
    }
    buf[levels * 2u] = (uint8_t)CDB_QUERY_EXPR_FIELD;
    buf[(levels * 2u) + 1u] = (uint8_t)0x00; /* varint field-path length 0 */
    *out_len = len;
    return buf;
}

/* Builds a full query wire: 6-byte header, then `levels` LIMIT(0,0) wrappers
 * around a single empty SCAN leaf. Each LIMIT level is 3 bytes; the leaf is
 * 2 bytes. Returns a malloc'd buffer (caller frees). */
static uint8_t *build_node_wire(size_t levels, size_t *out_len)
{
    size_t len = CDB_QUERY_HEADER_SIZE + (levels * 3u) + 2u;
    uint8_t *buf = (uint8_t *)malloc(len);
    size_t base = CDB_QUERY_HEADER_SIZE;
    size_t i = 0;
    if (buf == NULL)
        return NULL;
    buf[0] = (uint8_t)CDB_QUERY_MAGIC_0;
    buf[1] = (uint8_t)CDB_QUERY_MAGIC_1;
    buf[2] = (uint8_t)CDB_QUERY_MAGIC_2;
    buf[3] = (uint8_t)CDB_QUERY_MAGIC_3;
    buf[4] = (uint8_t)CDB_QUERY_VERSION_1;
    buf[5] = (uint8_t)0x00;
    for (i = 0; i < levels; i++) {
        buf[base + (i * 3u)] = (uint8_t)CDB_QUERY_NODE_LIMIT;
        buf[base + (i * 3u) + 1u] = (uint8_t)0x00; /* varint count 0 */
        buf[base + (i * 3u) + 2u] = (uint8_t)0x00; /* varint offset 0 */
    }
    buf[base + (levels * 3u)] = (uint8_t)CDB_QUERY_NODE_SCAN;
    buf[base + (levels * 3u) + 1u] = (uint8_t)0x00; /* varint name length 0 */
    *out_len = len;
    return buf;
}

/* Builds a full query wire exercising the node->expr mutual-recursion edge:
 * 6-byte header, a single FILTER node whose input is an empty SCAN and whose
 * predicate is a `pred_levels`-deep UNARY(NOT) expression chain. validate ->
 * skip_node_d(FILTER) -> skip_node_d(SCAN) -> cdb_query_skip_expr(pred), so an
 * over-deep predicate must be rejected by the expr cap reached *through* a node
 * (proves the guard is total across the mutual edge, AC5). Caller frees. */
static uint8_t *build_filter_deep_pred_wire(size_t pred_levels, size_t *out_len)
{
    size_t pred_len = (pred_levels * 2u) + 2u;
    size_t len = CDB_QUERY_HEADER_SIZE + 1u /*FILTER tag*/ + 2u /*SCAN*/ + pred_len;
    uint8_t *buf = (uint8_t *)malloc(len);
    size_t pos = 0;
    size_t i = 0;
    if (buf == NULL)
        return NULL;
    buf[0] = (uint8_t)CDB_QUERY_MAGIC_0;
    buf[1] = (uint8_t)CDB_QUERY_MAGIC_1;
    buf[2] = (uint8_t)CDB_QUERY_MAGIC_2;
    buf[3] = (uint8_t)CDB_QUERY_MAGIC_3;
    buf[4] = (uint8_t)CDB_QUERY_VERSION_1;
    buf[5] = (uint8_t)0x00;
    pos = CDB_QUERY_HEADER_SIZE;
    buf[pos] = (uint8_t)CDB_QUERY_NODE_FILTER; /* FILTER input then predicate */
    pos += 1u;
    buf[pos] = (uint8_t)CDB_QUERY_NODE_SCAN; /* input: empty scan */
    buf[pos + 1u] = (uint8_t)0x00;           /* varint scan name length 0 */
    pos += 2u;
    for (i = 0; i < pred_levels; i++) { /* predicate: deep UNARY(NOT) chain */
        buf[pos + (i * 2u)] = (uint8_t)CDB_QUERY_EXPR_UNARY;
        buf[pos + (i * 2u) + 1u] = (uint8_t)CDB_UNARY_NOT;
    }
    buf[pos + (pred_levels * 2u)] = (uint8_t)CDB_QUERY_EXPR_FIELD;
    buf[pos + (pred_levels * 2u) + 1u] = (uint8_t)0x00; /* empty field leaf */
    *out_len = len;
    return buf;
}

/* ABUSE: an over-deep expression chain driven straight through the public
 * expression skipper must return CDB_E_DEPTH, not crash. (Pre-fix: SIGSEGV.) */
static void test_skip_expr_over_deep_is_typed_error(void)
{
    size_t len = 0;
    uint8_t *buf = build_expr_chain(WIRE_DEPTH_ABUSE, &len);
    const uint8_t *p = NULL;
    const uint8_t *end = NULL;
    cdb_status s = CDB_OK;

    TEST_ASSERT_NOT_NULL(buf);
    p = buf;
    end = buf + len;
    s = cdb_query_skip_expr(&p, end);
    TEST_ASSERT_EQUAL_INT(CDB_E_DEPTH, s);
    free(buf);
}

/* ABUSE: an over-deep node plan driven through the public entry cdb_exec_open
 * (validate -> skip_node) must return CDB_E_DEPTH, not crash. (Pre-fix:
 * SIGSEGV.) db is NULL: validation fails before any database access. */
static void test_exec_open_over_deep_is_typed_error(void)
{
    size_t len = 0;
    uint8_t *buf = build_node_wire(WIRE_DEPTH_ABUSE, &len);
    cdb_exec_cursor cur;
    uint8_t scratch[4096];
    cdb_status s = CDB_OK;

    TEST_ASSERT_NOT_NULL(buf);
    s = cdb_exec_open(&cur, NULL, buf, len, NULL, 0, scratch, sizeof scratch);
    TEST_ASSERT_EQUAL_INT(CDB_E_DEPTH, s);
    free(buf);
}

/* ABUSE: an over-deep node plan driven straight through cdb_query_validate
 * (skip_node) must return CDB_E_DEPTH, not crash. (Pre-fix: SIGSEGV.) */
static void test_validate_over_deep_is_typed_error(void)
{
    size_t len = 0;
    uint8_t *buf = build_node_wire(WIRE_DEPTH_ABUSE, &len);
    size_t root_off = 0;
    cdb_status s = CDB_OK;

    TEST_ASSERT_NOT_NULL(buf);
    s = cdb_query_validate(buf, len, &root_off);
    TEST_ASSERT_EQUAL_INT(CDB_E_DEPTH, s);
    free(buf);
}

/* ABUSE: an over-deep node plan driven straight through the public node skipper
 * cdb_query_skip_node must return CDB_E_DEPTH, not crash. Exercises the public
 * depth-0 wrapper over raw node wire (no header). (Pre-fix: SIGSEGV.) */
static void test_skip_node_over_deep_is_typed_error(void)
{
    size_t len = 0;
    uint8_t *buf = build_node_wire(WIRE_DEPTH_ABUSE, &len);
    const uint8_t *p = NULL;
    const uint8_t *end = NULL;
    cdb_status s = CDB_OK;

    TEST_ASSERT_NOT_NULL(buf);
    p = buf + CDB_QUERY_HEADER_SIZE; /* skip the 6-byte header to the root node */
    end = buf + len;
    s = cdb_query_skip_node(&p, end);
    TEST_ASSERT_EQUAL_INT(CDB_E_DEPTH, s);
    free(buf);
}

/* ABUSE (mutual-recursion edge, AC5 totality): a FILTER node carrying an
 * over-deep predicate expression must be rejected with CDB_E_DEPTH when the
 * expr cap is reached *through* the node->expr edge (skip_node -> skip_expr),
 * not crash. (Pre-fix: SIGSEGV in the expr descent.) */
static void test_validate_filter_deep_pred_is_typed_error(void)
{
    size_t len = 0;
    uint8_t *buf = build_filter_deep_pred_wire(WIRE_DEPTH_ABUSE, &len);
    size_t root_off = 0;
    cdb_status s = CDB_OK;

    TEST_ASSERT_NOT_NULL(buf);
    s = cdb_query_validate(buf, len, &root_off);
    TEST_ASSERT_EQUAL_INT(CDB_E_DEPTH, s);
    free(buf);
}

/* NO REGRESSION: a valid, modestly-nested expression chain still parses. */
static void test_skip_expr_valid_depth_ok(void)
{
    size_t len = 0;
    uint8_t *buf = build_expr_chain(WIRE_DEPTH_OK, &len);
    const uint8_t *p = NULL;
    const uint8_t *end = NULL;
    cdb_status s = CDB_OK;

    TEST_ASSERT_NOT_NULL(buf);
    p = buf;
    end = buf + len;
    s = cdb_query_skip_expr(&p, end);
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);
    TEST_ASSERT_TRUE(p == end); /* whole chain consumed */
    free(buf);
}

/* NO REGRESSION: a valid, modestly-nested node plan still validates. */
static void test_validate_valid_depth_ok(void)
{
    size_t len = 0;
    uint8_t *buf = build_node_wire(WIRE_DEPTH_OK, &len);
    size_t root_off = 0;
    cdb_status s = CDB_OK;

    TEST_ASSERT_NOT_NULL(buf);
    s = cdb_query_validate(buf, len, &root_off);
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);
    TEST_ASSERT_EQUAL_size_t(CDB_QUERY_HEADER_SIZE, root_off);
    free(buf);
}

/* NO REGRESSION: a FILTER whose predicate is a valid, shallow expression still
 * validates (the node->expr edge is not over-triggered within the cap). */
static void test_validate_filter_shallow_pred_ok(void)
{
    size_t len = 0;
    uint8_t *buf = build_filter_deep_pred_wire(WIRE_DEPTH_OK, &len);
    size_t root_off = 0;
    cdb_status s = CDB_OK;

    TEST_ASSERT_NOT_NULL(buf);
    s = cdb_query_validate(buf, len, &root_off);
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);
    free(buf);
}

/* NO REGRESSION: a boundary-depth chain exactly at the deepest accepted level
 * (CDB_QUERY_MAX_DEPTH - 1 expr frames below the root) still parses, proving the
 * cap admits the full valid range and is off-by-one correct. */
static void test_skip_expr_at_cap_boundary_ok(void)
{
    size_t len = 0;
    /* skip_expr_d is entered at depth 0; the leaf is entered one level below the
     * last UNARY. (CDB_QUERY_MAX_DEPTH - 1) UNARY frames keep the deepest entry
     * at depth CDB_QUERY_MAX_DEPTH - 1 (< cap) -> accepted. */
    uint8_t *buf = build_expr_chain((size_t)CDB_QUERY_MAX_DEPTH - 1u, &len);
    const uint8_t *p = NULL;
    const uint8_t *end = NULL;
    cdb_status s = CDB_OK;

    TEST_ASSERT_NOT_NULL(buf);
    p = buf;
    end = buf + len;
    s = cdb_query_skip_expr(&p, end);
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);
    TEST_ASSERT_TRUE(p == end);
    free(buf);
}

/* NO REGRESSION: a valid shallow plan through cdb_exec_open must NOT be
 * rejected with CDB_E_DEPTH (the guard does not false-trigger within the cap). */
static void test_exec_open_valid_depth_not_depth_error(void)
{
    size_t len = 0;
    uint8_t *buf = build_node_wire(WIRE_DEPTH_OK, &len);
    cdb_exec_cursor cur;
    uint8_t scratch[4096];
    cdb_status s = CDB_OK;

    TEST_ASSERT_NOT_NULL(buf);
    s = cdb_exec_open(&cur, NULL, buf, len, NULL, 0, scratch, sizeof scratch);
    TEST_ASSERT_NOT_EQUAL(CDB_E_DEPTH, s);
    free(buf);
}

int main(void)
{
    UNITY_BEGIN();
    /* Abuse / fail-closed paths (red pre-fix, green post-fix). */
    RUN_TEST(test_skip_expr_over_deep_is_typed_error);
    RUN_TEST(test_exec_open_over_deep_is_typed_error);
    RUN_TEST(test_validate_over_deep_is_typed_error);
    RUN_TEST(test_skip_node_over_deep_is_typed_error);
    RUN_TEST(test_validate_filter_deep_pred_is_typed_error);
    /* No-regression / valid-within-cap paths. */
    RUN_TEST(test_skip_expr_valid_depth_ok);
    RUN_TEST(test_validate_valid_depth_ok);
    RUN_TEST(test_validate_filter_shallow_pred_ok);
    RUN_TEST(test_skip_expr_at_cap_boundary_ok);
    RUN_TEST(test_exec_open_valid_depth_not_depth_error);
    return UNITY_END();
}
