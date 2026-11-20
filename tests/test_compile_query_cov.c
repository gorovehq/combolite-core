/* Branch-coverage set for cdb_compile_query (agent-authored, increment 3 of the
 * #18 coverage ratchet). Complements tests/test_compiler.c (a few happy-path
 * examples) by driving the query-compiler parse/serialize branches the existing
 * suites leave cold: SELECT with alias/ORDER BY/NULLS/LIMIT OFFSET/JOIN, every
 * pipeline stage (project, select, sort, window with args, filter), the bare-name
 * and subquery sources, the expression forms (param by index and by name,
 * explicit Field(...), unary NOT/negate, arithmetic, dotted paths, literals),
 * plus the NULL-argument and malformed-query rejection paths with a populated
 * cdb_compile_error. Compile-only (no DB); hermetic; every value initialised at
 * declaration; abuse paths pass bad input and assert the returned status without
 * dereferencing a maybe-null result. Spec 11. */
#include "unity.h"
#include "cdb_compiler.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* Compiles q; asserts success and a non-empty wire payload. */
static void ok(const char *q)
{
    uint8_t wire[4096];
    size_t n = 0;
    cdb_compile_error e;
    cdb_status s;
    memset(&e, 0, sizeof e);
    s = cdb_compile_query(q, strlen(q), NULL, wire, sizeof wire, &n, &e);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, s, q);
    TEST_ASSERT_TRUE_MESSAGE(n > 0, q);
}

/* Compiles q; asserts a typed rejection with a populated diagnostic message. */
static void reject(const char *q)
{
    uint8_t wire[4096];
    size_t n = 0;
    cdb_compile_error e;
    cdb_status s;
    memset(&e, 0, sizeof e);
    s = cdb_compile_query(q, strlen(q), NULL, wire, sizeof wire, &n, &e);
    TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(CDB_OK, s, q);
    TEST_ASSERT_TRUE_MESSAGE(strlen(e.msg) > 0, q);
}

static void test_select_clauses(void)
{
    ok("SELECT a AS x, b FROM Scan(\"t\") WHERE a > 1 ORDER BY a DESC NULLS FIRST LIMIT 5 OFFSET 2;");
    ok("SELECT * FROM Scan(\"t\") LIMIT 3, 1;");
    ok("SELECT a FROM Scan(\"t\") ORDER BY a ASC NULLS LAST;");
    ok("QUERY myq(a, b) SELECT a FROM Scan(\"t\");");
}

static void test_join_sources(void)
{
    ok("SELECT a FROM Scan(\"a\") JOIN Scan(\"b\") ON a == b;");
    ok("SELECT a FROM Scan(\"a\") LEFT OUTER JOIN Scan(\"b\") ON a == b;");
    ok("SELECT a FROM Scan(\"a\") INNER JOIN Scan(\"b\") ON a == b;");
    /* bare table-name source and parenthesized subquery source */
    ok("telemetry | filter(temp > 1) | limit(5);");
    ok("(SELECT * FROM Scan(\"t\")) | limit(2);");
}

static void test_pipeline_stages(void)
{
    ok("Scan(\"t\") | project(a, b AS c) | limit(1);");
    ok("Scan(\"t\") | select(a, b) | sort(a DESC, b ASC);");
    ok("Scan(\"t\") | window(field: \"ts\", size: 100, step: 50) | limit(1);");
    ok("Scan(\"t\") | window(size: 10);");
    ok("Scan(\"t\") | where(a > 0) | sort(a NULLS FIRST);");
}

static void test_expression_forms(void)
{
    ok("Scan(\"t\") | filter(x > $1 AND y < $name);");
    ok("Scan(\"t\") | filter(Field(\"col\") == 5);");
    ok("Scan(\"t\") | filter(-a > 3 AND NOT b);");
    ok("Scan(\"t\") | filter(!b OR a % 2 == 0 AND a / 2 > 1);");
    ok("Scan(\"t\") | filter(a.b.c > 1);");
    ok("Scan(\"t\") | filter(TRUE AND FALSE OR x == NULL);");
    ok("Scan(\"t\") | filter(sin(phase) > 0.5);");
}

static void test_rejections(void)
{
    /* NULL / zero-capacity argument guards. */
    {
        uint8_t wire[64];
        size_t n = 0;
        cdb_compile_error e;
        memset(&e, 0, sizeof e);
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
            cdb_compile_query(NULL, 0, NULL, wire, sizeof wire, &n, &e));
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
            cdb_compile_query("SELECT a FROM Scan(\"t\");", 24, NULL, NULL, 10, &n, &e));
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
            cdb_compile_query("SELECT a FROM Scan(\"t\");", 24, NULL, wire, 0, &n, &e));
    }
    /* Malformed queries: bad source, unknown stage, garbage expression. */
    reject("SELECT a FROM;");
    reject("Scan(\"t\") | unknownstage(1);");
    reject("Scan(\"t\") | filter(@@@);");
    reject("%%% not a query");

    /* wire buffer far too small for the compiled output fails closed. */
    {
        uint8_t tiny[8];
        size_t n = 0;
        cdb_compile_error e;
        const char *q = "SELECT a, b, c FROM Scan(\"telemetry\") WHERE a > 1 ORDER BY a DESC LIMIT 100;";
        cdb_status s;
        memset(&e, 0, sizeof e);
        s = cdb_compile_query(q, strlen(q), NULL, tiny, sizeof tiny, &n, &e);
        TEST_ASSERT_NOT_EQUAL_INT(CDB_OK, s);
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_select_clauses);
    RUN_TEST(test_join_sources);
    RUN_TEST(test_pipeline_stages);
    RUN_TEST(test_expression_forms);
    RUN_TEST(test_rejections);
    return UNITY_END();
}
