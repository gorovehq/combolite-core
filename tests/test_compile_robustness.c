/* Robustness characterization for the CMBQL compiler's handling of malformed
 * input. Two guarantees are distinguished:
 *
 *  1. Memory safety (enforced now): malformed/garbage/truncated input must not
 *     crash, hang, or read/write out of bounds — it returns, cleanly. This runs
 *     under ASan/UBSan and is a standing contract.
 *
 *  2. Fail-closed parsing (KNOWN GAP, not yet enforced): a malformed program
 *     SHOULD be rejected with a non-OK status. Today cdb_compile_proc's statement
 *     parser falls through unmatched tokens with a "consume and return OK" path,
 *     so garbage ("FOOBAR;", "@#$%", "CREATE STORE \"x\" MODEL notamodel;",
 *     truncated clauses) silently "compiles" to a no-op/partial program instead
 *     of erroring (CWE-20 improper input validation, fail-open). The intended
 *     assertions are kept below under TEST_IGNORE; hardening the parser is a
 *     design change (it must not break any intentional skip behaviour), tracked
 *     separately -- remove the ignore to turn this into the enforcing test.
 *
 * Spec 19 (CMBQL compile). */
#include "unity.h"
#include "cdb_compiler.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static const char *const malformed[] = {
    "", ";", "FOOBAR baz;", "@#$%^&*(", "123 456;",
    "CREATE", "CREATE STORE", "CREATE STORE \"x\" MODEL notamodel;",
    "INSERT", "INSERT INTO \"x\" (", "DELETE FROM",
    "GRANT ROLE 1 TO", "ROTATE MASTER KEY", "SAVEPOINT", "ROLLBACK TO",
    "SELECT * FROM Scan(", "INSERT INTO \"unterminated",
};
#define N_MALFORMED (sizeof malformed / sizeof malformed[0])

/* Enforced now: malformed input is handled without a crash/overrun. */
static void test_malformed_input_is_memory_safe(void)
{
    uint8_t bc[4096];
    size_t i;
    for (i = 0; i < N_MALFORMED; i++) {
        size_t bc_len = 0;
        cdb_compile_error err;
        memset(&err, 0, sizeof err);
        /* return value intentionally unchecked here: this test asserts only that
         * the call completes safely (ASan/UBSan clean), not the verdict. */
        (void)cdb_compile_proc(malformed[i], strlen(malformed[i]), NULL,
                               bc, sizeof bc, &bc_len, &err);
    }
    TEST_PASS();
}

/* KNOWN GAP (fail-open parser): once the compiler rejects malformed input,
 * remove the TEST_IGNORE and this becomes the enforcing regression test. */
static void test_malformed_input_rejected(void)
{
    uint8_t bc[4096];
    size_t i;

    TEST_IGNORE_MESSAGE("KNOWN GAP: CMBQL compiler accepts malformed input "
                        "(fail-open, CWE-20) — un-ignore when the parser is hardened");

    for (i = 0; i < N_MALFORMED; i++) {
        size_t bc_len = 0;
        cdb_compile_error err;
        cdb_status s;
        memset(&err, 0, sizeof err);
        s = cdb_compile_proc(malformed[i], strlen(malformed[i]), NULL,
                             bc, sizeof bc, &bc_len, &err);
        TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(CDB_OK, s, malformed[i]);
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_malformed_input_is_memory_safe);
    RUN_TEST(test_malformed_input_rejected);
    return UNITY_END();
}
