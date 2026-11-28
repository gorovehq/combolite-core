/* Audit #81 (CWE-197 numeric truncation / CWE-681 incorrect conversion): five
 * scalar-result functions in src/cdb_math.c computed a double, narrowed it to
 * float, wrote *out, and returned CDB_OK with NO finiteness guard -- shipping an
 * Inf/NaN behind the success code, indistinguishable from a real result. This is
 * the same defect class #79/#80 fixed on the dim->=4 LU determinant path; #81
 * closes the five remaining sites.
 *
 * One deterministic red->green regression test per site. Each writes a sentinel
 * to *out, invokes the function with an input whose exact result overflows float
 * (or propagates a non-finite value), and asserts the function returns
 * CDB_E_OVERFLOW AND leaves *out untouched (fail closed, write-on-success-only).
 * Mirrors #80's test_det_overflow_signals_error (4x4 diag 1e20f).
 *
 * Trigger choice (deterministic + sanitizer-robust): every overflow case feeds a
 * non-finite (Inf) caller input that PROPAGATES through the double computation to
 * a non-finite double, so the narrowing `(float)acc` is Inf->Inf -- a
 * representable conversion, never a finite-out-of-range narrowing that a strict
 * UBSan float-cast-overflow/implicit-conversion build could trap on. The guard
 * (`!isfinite(result)`) still fires identically, matching the audit's "an
 * overflow OR a non-finite propagating input" defect (CWE-197/-681) and ADR-0081-7.
 *
 * Replay oracle (verified empirically): against pre-#81 main each overflow site
 * returns CDB_OK with a non-finite *out, so the CDB_E_OVERFLOW assertion FAILS
 * (RED); after the guard each returns CDB_E_OVERFLOW with *out untouched (GREEN).
 * A final finite-result test proves no behaviour change for representable
 * results. */
#include <math.h> /* INFINITY */

#include "unity.h"
#include "cdb_math.h"

void setUp(void)
{
}
void tearDown(void)
{
}

/* S1 cdb_math_vec_dot (src/cdb_math.c ~784 `*out = (float)acc;`): an infinite
 * component propagates through the dot-product sum (Inf * 1 = Inf), so acc is a
 * non-finite double and the narrowed result is non-finite. */
static void test_vec_dot_overflow_signals_error(void)
{
    const float u[1] = {(float)INFINITY};
    const float v[1] = {1.0f};
    float out = -7.0f;
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_math_vec_dot(u, v, 1, &out));
    /* *out is meaningful only on CDB_OK: it must be left as the caller set it. */
    TEST_ASSERT_EQUAL_FLOAT(-7.0f, out);
}

/* S2 cdb_math_vec_distance (src/cdb_math.c ~828 `*out = (float)sqrt(acc);`):
 * sqrt shrinks magnitude, so a finite large acc cannot overflow post-root. The
 * deterministic trigger is a non-finite caller input (an infinite component)
 * that propagates through the squared-distance sum and survives the square root
 * -> non-finite result. */
static void test_vec_distance_overflow_signals_error(void)
{
    const float u[1] = {(float)INFINITY};
    const float v[1] = {0.0f};
    float out = -7.0f;
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_math_vec_distance(u, v, 1, &out));
    TEST_ASSERT_EQUAL_FLOAT(-7.0f, out);
}

/* S3 cdb_math_mat_det dim==2 (src/cdb_math.c ~945 `*out = (float)(a*d-b*c);`):
 * det = a*d - b*c. An infinite diagonal entry propagates (Inf*1 - 0 = Inf), so
 * the narrowed determinant is non-finite. */
static void test_mat_det2_overflow_signals_error(void)
{
    const float m[4] = {(float)INFINITY, 0.0f, 0.0f, 1.0f};
    float out = -7.0f;
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_math_mat_det(m, 2, &out));
    TEST_ASSERT_EQUAL_FLOAT(-7.0f, out);
}

/* S4 cdb_math_mat_det dim==3 (src/cdb_math.c ~954 `*out = (float)det;`): Rule of
 * Sarrus. An infinite diagonal entry propagates through the expansion (its
 * cofactor term is Inf), so the narrowed determinant is non-finite. */
static void test_mat_det3_overflow_signals_error(void)
{
    const float m[9] = {(float)INFINITY, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
    float out = -7.0f;
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_math_mat_det(m, 3, &out));
    TEST_ASSERT_EQUAL_FLOAT(-7.0f, out);
}

/* S5 cdb_math_mat_trace (src/cdb_math.c ~1040 `*out = (float)acc;`): sum of the
 * diagonal. An infinite diagonal entry propagates through the sum (Inf + 1 =
 * Inf), so the narrowed trace is non-finite. */
static void test_mat_trace_overflow_signals_error(void)
{
    const float m[4] = {(float)INFINITY, 0.0f, 0.0f, 1.0f};
    float out = -7.0f;
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_math_mat_trace(m, 2, &out));
    TEST_ASSERT_EQUAL_FLOAT(-7.0f, out);
}

/* Continuity: a representable (finite) result for each hardened site is
 * unchanged -- CDB_OK with the correct value written to *out. Proves the guard
 * adds no behaviour change for normal inputs. */
static void test_math_overflow_sites_finite_unchanged(void)
{
    float out = 0.0f;

    /* S1: dot([1,2,3],[4,5,6]) = 4 + 10 + 18 = 32. */
    {
        const float u[3] = {1.0f, 2.0f, 3.0f};
        const float v[3] = {4.0f, 5.0f, 6.0f};
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_vec_dot(u, v, 3, &out));
        TEST_ASSERT_EQUAL_FLOAT(32.0f, out);
    }
    /* S2: distance([0,0],[3,4]) = sqrt(9 + 16) = 5. */
    {
        const float u[2] = {0.0f, 0.0f};
        const float v[2] = {3.0f, 4.0f};
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_vec_distance(u, v, 2, &out));
        TEST_ASSERT_EQUAL_FLOAT(5.0f, out);
    }
    /* S3: det([[1,2],[3,4]]) = 1*4 - 2*3 = -2. */
    {
        const float m[4] = {1.0f, 2.0f, 3.0f, 4.0f};
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_det(m, 2, &out));
        TEST_ASSERT_EQUAL_FLOAT(-2.0f, out);
    }
    /* S4: det([[1,2,3],[0,1,4],[5,6,0]]) = 1. */
    {
        const float m[9] = {1.0f, 2.0f, 3.0f, 0.0f, 1.0f, 4.0f, 5.0f, 6.0f, 0.0f};
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_det(m, 3, &out));
        TEST_ASSERT_EQUAL_FLOAT(1.0f, out);
    }
    /* S4b: a legitimately zero 3x3 determinant stays CDB_OK (not an error). */
    {
        const float m[9] = {1.0f, 2.0f, 3.0f, 2.0f, 4.0f, 6.0f, 7.0f, 8.0f, 9.0f};
        out = -7.0f;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_det(m, 3, &out));
        TEST_ASSERT_EQUAL_FLOAT(0.0f, out);
    }
    /* S5: trace([[1,2],[3,4]]) = 1 + 4 = 5. */
    {
        const float m[4] = {1.0f, 2.0f, 3.0f, 4.0f};
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_trace(m, 2, &out));
        TEST_ASSERT_EQUAL_FLOAT(5.0f, out);
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_vec_dot_overflow_signals_error);
    RUN_TEST(test_vec_distance_overflow_signals_error);
    RUN_TEST(test_mat_det2_overflow_signals_error);
    RUN_TEST(test_mat_det3_overflow_signals_error);
    RUN_TEST(test_mat_trace_overflow_signals_error);
    RUN_TEST(test_math_overflow_sites_finite_unchanged);
    return UNITY_END();
}
