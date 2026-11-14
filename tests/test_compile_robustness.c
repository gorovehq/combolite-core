/* Memory-safety characterization for the CMBQL compiler on malformed input:
 * garbage / truncated / unterminated programs must be handled without a crash,
 * hang, or out-of-bounds access. Runs under ASan/UBSan. (That malformed input is
 * also *rejected* fail-closed is enforced separately by test_compile_reject on
 * the fix branch, once the parser hardening lands.) Spec 19. */
#include "unity.h"
#include "cdb_compiler.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static const char *const inputs[] = {
    "", ";", "FOOBAR baz;", "@#$%^&*(", "123 456;",
    "CREATE", "CREATE STORE", "CREATE STORE \"x\" MODEL notamodel;",
    "INSERT", "INSERT INTO \"x\" (", "DELETE FROM",
    "GRANT ROLE 1 TO", "ROTATE MASTER KEY", "SAVEPOINT", "ROLLBACK TO",
    "SELECT * FROM Scan(", "INSERT INTO \"unterminated",
};

static void test_malformed_input_is_memory_safe(void)
{
    uint8_t bc[4096];
    size_t i;
    for (i = 0; i < sizeof inputs / sizeof inputs[0]; i++) {
        size_t bc_len = 0;
        cdb_compile_error err;
        memset(&err, 0, sizeof err);
        /* verdict intentionally unchecked: this asserts only that the call
         * completes safely (ASan/UBSan clean), not the pass/fail result. */
        (void)cdb_compile_proc(inputs[i], strlen(inputs[i]), NULL,
                               bc, sizeof bc, &bc_len, &err);
    }
    TEST_PASS();
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_malformed_input_is_memory_safe);
    return UNITY_END();
}
