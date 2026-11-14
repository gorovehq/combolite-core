/* Regression for F-C1: the CMBQL compiler must reject malformed/unknown statements
 * (fail closed) instead of silently consuming the token and reporting success.
 * Guards against over-correction: well-formed statements (incl. the flux forms
 * repaired for F-C1b) still compile. Spec 19. */
#include "unity.h"
#include "cdb_compiler.h"
#include <string.h>
void setUp(void){} void tearDown(void){}
static cdb_status compile(const char *src){
    uint8_t bc[4096]; size_t n=0; cdb_compile_error e; memset(&e,0,sizeof e);
    return cdb_compile_proc(src, strlen(src), NULL, bc, sizeof bc, &n, &e);
}
static const char *const bad[] = {
    "FOOBAR baz;", "@#$%^&*(", "123 456;", "notakeyword \"x\";",
    "WOBBLE 5;", "ZZZ;",
};
static const char *const good[] = {
    "", ";",
    "CREATE STORE \"docs\" MODEL document;",
    "INSERT INTO \"docs\" (\"{\\\"n\\\":1}\", \"a\");",
    "RECLAIM;", "RECONCILE;",
    "reinforce(type: 1, from: [10, 100], to: [20, 200], weight: 1.5);",
    "link(type: 1, from: [10, 100], to: [20, 200], weight: 2.5, time: 5000);",
    "unlink(type: 1, from: [10, 100], to: [20, 200]);",
    "downsample(source: [1, 1], into: [1, 2], step: 60, from: 0, to: 1000);",
    "CREATE LINK TYPE \"authored\" CARDINALITY 1:N ENFORCED;",
};
static void test_malformed_rejected(void){
    size_t i; for(i=0;i<sizeof bad/sizeof bad[0];i++)
        TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(CDB_OK, compile(bad[i]), bad[i]);
}
static void test_wellformed_compiles(void){
    size_t i; for(i=0;i<sizeof good/sizeof good[0];i++)
        TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, compile(good[i]), good[i]);
}
int main(void){UNITY_BEGIN();RUN_TEST(test_malformed_rejected);RUN_TEST(test_wellformed_compiles);return UNITY_END();}
