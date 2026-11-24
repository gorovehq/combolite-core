/* #40 FR5 cap, updated by #65: cdb_math_mat_det used to cap at dim 3 (a 4x4 or
 * larger returned CDB_E_UNSUPPORTED). #65 lifted that ceiling with a general LU
 * path, so the documented cap now sits at CDB_MATH_MAT_DET_MAX_DIM (32): dim
 * 1..32 are supported and only a dim ABOVE the cap returns CDB_E_UNSUPPORTED.
 * This test still guards that the cap is a clean, documented boundary -- the
 * assertion simply moved from 4x4 to dim MAX_DIM+1 (the sanctioned "cap value
 * changed" edit). The dim 1/2/3 supported assertions are unchanged. */
#include <string.h>

#include "unity.h"
#include "cdb_math.h"

/* Mirror of the cap constant in src/cdb_math.c (kept in sync with it). */
#define TEST_MAT_DET_MAX_DIM 32

void setUp(void)
{
}
void tearDown(void)
{
}

static void test_det_1x2x3_supported(void)
{
    float out = 0.0f;
    const float m1[1] = {7.0f};
    const float m2[4] = {1.0f, 2.0f, 3.0f, 4.0f};    /* det = -2 */
    const float m3[9] = {1, 2, 3, 0, 1, 4, 5, 6, 0}; /* det = 1 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_det(m1, 1, &out));
    TEST_ASSERT_EQUAL_FLOAT(7.0f, out);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_det(m2, 2, &out));
    TEST_ASSERT_EQUAL_FLOAT(-2.0f, out);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_det(m3, 3, &out));
    TEST_ASSERT_EQUAL_FLOAT(1.0f, out);
}

static void test_det_4x4_now_supported(void)
{
    float m4[16];
    float out = 123.0f;
    unsigned i;
    for (i = 0; i < 16; i++)
        m4[i] = (float)(i + 1);
    /* #65: a 4x4 is no longer the cap -- it now returns CDB_OK (this matrix is
     * rank-deficient, so its determinant is 0), never CDB_E_UNSUPPORTED. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_det(m4, 4, &out));
    TEST_ASSERT_EQUAL_FLOAT(0.0f, out);
}

static void test_det_above_cap_unsupported(void)
{
    const float m[1] = {0.0f};
    float out = 123.0f;
    /* Documented cap: a dim ABOVE CDB_MATH_MAT_DET_MAX_DIM is CDB_E_UNSUPPORTED,
     * not a silent or wrong determinant. */
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED,
                          cdb_math_mat_det(m, (size_t)TEST_MAT_DET_MAX_DIM + 1, &out));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_det_1x2x3_supported);
    RUN_TEST(test_det_4x4_now_supported);
    RUN_TEST(test_det_above_cap_unsupported);
    return UNITY_END();
}
