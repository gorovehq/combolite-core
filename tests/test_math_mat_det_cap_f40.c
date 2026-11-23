/* #40 FR5: cdb_math_mat_det is a documented capability cap -- dimensions 1-3
 * only; a 4x4 (or larger) square matrix returns CDB_E_UNSUPPORTED (there is no
 * general LU path yet). This asserts the capped behavior stays put; it is not
 * a defect and no new behavior is introduced. */
#include <string.h>

#include "unity.h"
#include "cdb_math.h"

void setUp(void) {}
void tearDown(void) {}

static void test_det_1x2x3_supported(void)
{
    float out = 0.0f;
    const float m1[1] = {7.0f};
    const float m2[4] = {1.0f, 2.0f, 3.0f, 4.0f};               /* det = -2 */
    const float m3[9] = {1, 2, 3, 0, 1, 4, 5, 6, 0};            /* det = 1 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_det(m1, 1, &out));
    TEST_ASSERT_EQUAL_FLOAT(7.0f, out);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_det(m2, 2, &out));
    TEST_ASSERT_EQUAL_FLOAT(-2.0f, out);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_det(m3, 3, &out));
    TEST_ASSERT_EQUAL_FLOAT(1.0f, out);
}

static void test_det_4x4_unsupported(void)
{
    float m4[16];
    float out = 123.0f;
    unsigned i;
    for (i = 0; i < 16; i++)
        m4[i] = (float)(i + 1);
    /* Documented cap: 4x4 (and larger) is CDB_E_UNSUPPORTED, not a silent or
     * wrong determinant. */
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED, cdb_math_mat_det(m4, 4, &out));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_det_1x2x3_supported);
    RUN_TEST(test_det_4x4_unsupported);
    return UNITY_END();
}
