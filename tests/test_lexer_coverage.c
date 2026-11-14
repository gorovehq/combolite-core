/* Lexer tokenization coverage: compile programs/queries containing diverse token
 * and literal forms (integers incl. negative/hex/64-bit-max, floats incl.
 * exponent/negative, string escapes + embedded quotes, booleans, NULL, $params,
 * comments, irregular whitespace) to drive cdb_lexer scanning branches.
 * Compile-only (no DB). Spec 19 (CMBQL lexing). */
#include "unity.h"
#include "cdb_compiler.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void q_ok(const char *q)
{
    uint8_t w[2048]; size_t n = 0; cdb_compile_error e;
    memset(&e, 0, sizeof e);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, cdb_compile_query(q, strlen(q), NULL, w, sizeof w, &n, &e), q);
}
static void p_ok(const char *p)
{
    uint8_t b[4096]; size_t n = 0; cdb_compile_error e;
    memset(&e, 0, sizeof e);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, cdb_compile_proc(p, strlen(p), NULL, b, sizeof b, &n, &e), p);
}

static void test_token_and_literal_forms(void)
{
    q_ok("SELECT a FROM Scan(\"d\") WHERE a = 42");
    q_ok("SELECT a FROM Scan(\"d\") WHERE a = -7");
    q_ok("SELECT a FROM Scan(\"d\") WHERE a = 0xFF");
    q_ok("SELECT a FROM Scan(\"d\") WHERE a = 9223372036854775807");
    q_ok("SELECT a FROM Scan(\"d\") WHERE a = 3.14");
    q_ok("SELECT a FROM Scan(\"d\") WHERE a = 1.5e3");
    q_ok("SELECT a FROM Scan(\"d\") WHERE a = -0.5");
    q_ok("SELECT a FROM Scan(\"d\") WHERE s = \"a\\tb\\n\"");
    q_ok("SELECT a FROM Scan(\"d\") WHERE s = \"he said \\\"hi\\\"\"");
    q_ok("SELECT a FROM Scan(\"d\") WHERE a = TRUE");
    q_ok("SELECT a FROM Scan(\"d\") WHERE a = FALSE");
    q_ok("SELECT a FROM Scan(\"d\") WHERE a = NULL");
    p_ok("LET $x = 1; RETURN $x;");
    p_ok("CREATE STORE \"a\" MODEL document; -- a trailing comment\n");
    p_ok("  CREATE   STORE   \"a\"   MODEL   document ;  ");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_token_and_literal_forms);
    return UNITY_END();
}
