/* #65 (closing the #40 FR5 cap): cdb_math_mat_det now computes the determinant
 * for dim >= 4 via LU decomposition with partial pivoting. This is the red->green
 * regression: against the pre-#65 code (CDB_E_UNSUPPORTED for every dim >= 4) the
 * 4x4, 5x5 and singular assertions below FAIL; against the LU path they PASS.
 *
 * Coverage: a known 4x4 (AC1), a known 5x5 (AC2), a cleanly-singular dim-4
 * matrix => 0.0 (AC3), a 3x3 that still matches the Rule-of-Sarrus fast path
 * (AC4, continuity), a dim past the cap => CDB_E_UNSUPPORTED (AC5), and null
 * arguments => CDB_E_INVALID_ARG (AC6). Expected determinants were computed
 * exactly with rational Gaussian elimination. */
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

/* AC1: known 4x4, det = 8 (classic LU example matrix). */
static void test_det_4x4_known(void)
{
    const float m[16] = {2, 1, 1, 0, 4, 3, 3, 1, 8, 7, 9, 5, 6, 7, 9, 8};
    float out = 0.0f;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_det(m, 4, &out));
    TEST_ASSERT_EQUAL_FLOAT(8.0f, out);
}

/* AC2: known 5x5, det = -35. */
static void test_det_5x5_known(void)
{
    const float m[25] = {2, 1, 0, 0, 3, 1, 2, 1, 0, 0, 0, 1, 2, 1, 0, 0, 0, 1, 2, 1, 4, 0, 0, 1, 2};
    float out = 0.0f;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_det(m, 5, &out));
    TEST_ASSERT_EQUAL_FLOAT(-35.0f, out);
}

/* AC3: a cleanly dependent row (row 2 = row 0 + row 1) => exactly singular. */
static void test_det_singular_is_zero(void)
{
    const float m[16] = {1, 2, 3, 4, 5, 6, 7, 8, 6, 8, 10, 12, 1, 0, 0, 1};
    float out = 123.0f;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_det(m, 4, &out));
    TEST_ASSERT_EQUAL_FLOAT(0.0f, out);
}

/* AC4: the 3x3 fast path (Rule of Sarrus) is unchanged; det = 1. */
static void test_det_3x3_continuity(void)
{
    const float m[9] = {1, 2, 3, 0, 1, 4, 5, 6, 0};
    float out = 0.0f;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_det(m, 3, &out));
    TEST_ASSERT_EQUAL_FLOAT(1.0f, out);
}

/* AC5: one past the supported cap => CDB_E_UNSUPPORTED (fail closed, no scratch
 * overrun). The matrix is never read for an out-of-cap dim, so a tiny stand-in
 * pointer is sufficient. */
static void test_det_above_cap_unsupported(void)
{
    const float m[1] = {0.0f};
    float out = 7.0f;
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED,
                          cdb_math_mat_det(m, (size_t)TEST_MAT_DET_MAX_DIM + 1, &out));
}

/* AC6: null arguments fail closed with CDB_E_INVALID_ARG. */
static void test_det_null_args(void)
{
    const float m[16] = {0};
    float out = 0.0f;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_math_mat_det(NULL, 4, &out));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_math_mat_det(m, 4, NULL));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_det_4x4_known);
    RUN_TEST(test_det_5x5_known);
    RUN_TEST(test_det_singular_is_zero);
    RUN_TEST(test_det_3x3_continuity);
    RUN_TEST(test_det_above_cap_unsupported);
    RUN_TEST(test_det_null_args);
    return UNITY_END();
}
