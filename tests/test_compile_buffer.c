/* Regression for the fail-open output-buffer bug: cdb_compile_proc used to return
 * CDB_OK even when the bytecode writer ran out of room, handing back a truncated
 * (invalid) program. It must instead propagate the writer's failure. A valid
 * program with an ample buffer still compiles OK. Spec 21 (proc bytecode). */
#include "unity.h"
#include "cdb_compiler.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static const char *PROG = "CREATE STORE \"docs\" MODEL document;";

static void test_too_small_output_buffer_fails_closed(void)
{
    uint8_t tiny[4]; /* below the proc header; the writer cannot emit into this */
    size_t bc_len = 0;
    cdb_compile_error err;
    cdb_status s;
    memset(&err, 0, sizeof err);
    s = cdb_compile_proc(PROG, strlen(PROG), NULL, tiny, sizeof tiny, &bc_len, &err);
    TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(CDB_OK, s,
        "compile reported success into a buffer too small to hold the bytecode");
}

static void test_ample_buffer_still_ok(void)
{
    uint8_t bc[4096];
    size_t bc_len = 0;
    cdb_compile_error err;
    cdb_status s;
    memset(&err, 0, sizeof err);
    s = cdb_compile_proc(PROG, strlen(PROG), NULL, bc, sizeof bc, &bc_len, &err);
    TEST_ASSERT_EQUAL_INT(CDB_OK, s);
    TEST_ASSERT_TRUE(bc_len > 0);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_too_small_output_buffer_fails_closed);
    RUN_TEST(test_ample_buffer_still_ok);
    return UNITY_END();
}
