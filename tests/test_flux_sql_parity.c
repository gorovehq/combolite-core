/* Verify flux-style statements compile to the SAME bytecode as their SQL-style
 * equivalents (differential oracle): identical bytecode => identical semantics.
 * Covers finding F-C1b (flux key:/[array] link forms previously no-op'd). */
#include "unity.h"
#include "cdb_compiler.h"
#include <string.h>
void setUp(void){} void tearDown(void){}
static void same(const char *flux, const char *sql){
    uint8_t a[4096], b[4096]; size_t la=0, lb=0; cdb_compile_error ea, eb;
    memset(&ea,0,sizeof ea); memset(&eb,0,sizeof eb);
    cdb_status sa = cdb_compile_proc(flux, strlen(flux), NULL, a, sizeof a, &la, &ea);
    cdb_status sb = cdb_compile_proc(sql, strlen(sql), NULL, b, sizeof b, &lb, &eb);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, sb, sql);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, sa, flux);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(lb, la, flux);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(b, a, lb, flux);
}
static void test_reinforce(void){ same(
  "reinforce(type: 1, from: [10, 100], to: [20, 200], weight: 1.5);",
  "REINFORCE LINK 1 FROM 10:100 TO 20:200 WEIGHT 1.5;"); }
static void test_link(void){ same(
  "link(type: 1, from: [10, 100], to: [20, 200], weight: 2.5, time: 5000);",
  "LINK 1 FROM 10:100 TO 20:200 WEIGHT 2.5 TIME 5000;"); }
static void test_unlink(void){ same(
  "unlink(type: 1, from: [10, 100], to: [20, 200]);",
  "UNLINK 1 FROM 10:100 TO 20:200;"); }
static void test_downsample(void){ same(
  "downsample(source: [1, 1], into: [1, 2], step: 60, from: 0, to: 1000);",
  "DOWNSAMPLE TIMESERIES SOURCE 1:1 INTO 1:2 STEP 60 FROM 0 TO 1000;"); }
int main(void){UNITY_BEGIN();RUN_TEST(test_reinforce);RUN_TEST(test_link);RUN_TEST(test_unlink);RUN_TEST(test_downsample);return UNITY_END();}
