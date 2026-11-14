/* Golden fixtures for the CMBQL compiler artifact: canonical programs must compile
 * to exact, stable bytecode. Captured reference -> any change in the compiler's
 * emitted bytecode is caught (silent output drift). Spec 21 (proc bytecode). */
#include "unity.h"
#include "cdb_compiler.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void golden(const char *src, const uint8_t *want, size_t wlen)
{
    uint8_t bc[4096]; size_t n = 0; cdb_compile_error e;
    memset(&e, 0, sizeof e);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, cdb_compile_proc(src, strlen(src), NULL, bc, sizeof bc, &n, &e), src);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(wlen, n, src);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(want, bc, wlen, src);
}

static void test_create_store_bytecode(void)
{
    static const uint8_t g[] = {
        0x43,0x4d,0x42,0x50,0x01,0x00,0x40,0x08,0x15,0x01,0x01,0x06,0x40,0x04,0x64,0x6f,
        0x63,0x73,0x01,0x02,0x02,0x03,0x04,0x11,0x00,0x15,0x02,0x01,0x02,0x0d };
    golden("CREATE STORE \"docs\" MODEL document;", g, sizeof g);
}

static void test_insert_bytecode(void)
{
    static const uint8_t g[] = {
        0x43,0x4d,0x42,0x50,0x01,0x00,0x40,0x08,0x24,0x01,0x01,0x06,0x40,0x04,0x64,0x6f,
        0x63,0x73,0x01,0x02,0x09,0x40,0x07,0x7b,0x22,0x6e,0x22,0x3a,0x31,0x7d,0x01,0x03,
        0x04,0x40,0x02,0x6b,0x31,0x11,0x00,0x01,0x03,0x01,0x02,0x03,0x0d };
    golden("INSERT INTO \"docs\" (\"{\\\"n\\\":1}\", \"k1\");", g, sizeof g);
}

static void test_reclaim_bytecode(void)
{
    static const uint8_t g[] = {
        0x43,0x4d,0x42,0x50,0x01,0x00,0x40,0x08,0x05,0x11,0x00,0x22,0x00,0x0d };
    golden("RECLAIM;", g, sizeof g);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_create_store_bytecode);
    RUN_TEST(test_insert_bytecode);
    RUN_TEST(test_reclaim_bytecode);
    return UNITY_END();
}
