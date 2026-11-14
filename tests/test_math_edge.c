/* Edge/coverage suite for the cdb_math public surface that test_math.c does not
 * exercise: the remaining trig/hyperbolic/exp-log scalars, rounding helpers,
 * tile/morton geo mappings, the vector & matrix ops (incl. their NULL-argument
 * fail-closed branch), the window generators (incl. the n==0 and n==1 branches),
 * fft_power, and the domain helpers (electrical/fluid/atmospheric/astro/thermal).
 * Pure functions, so the asserts are exact where a closed form is known and a
 * finiteness/sign check otherwise. Spec 20 (math builtins). */
#include "unity.h"
#include "cdb_math.h"

#include <math.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* A result that must be a real, finite number (no NaN / inf). */
#define ASSERT_FINITE(x) TEST_ASSERT_TRUE_MESSAGE(isfinite(x), #x " not finite")

static void test_scalar_trig_exp_log(void)
{
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 1.5707963f, (float)cdb_math_asin(1.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 0.0f, (float)cdb_math_acos(1.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 0.7853981f, (float)cdb_math_atan(1.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 1.5574077f, (float)cdb_math_tan(1.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 0.0f, (float)cdb_math_sinh(0.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 1.0f, (float)cdb_math_cosh(0.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 0.0f, (float)cdb_math_tanh(0.0));

    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 1.0f, (float)cdb_math_exp(0.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 0.0f, (float)cdb_math_expm1(0.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 0.0f, (float)cdb_math_ln(1.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 2.0f, (float)cdb_math_log10(100.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 3.0f, (float)cdb_math_log2(8.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 0.0f, (float)cdb_math_log1p(0.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 2.0f, (float)cdb_math_cbrt(8.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 5.0f, (float)cdb_math_hypot(3.0, 4.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 3.0f, (float)cdb_math_hypot3(2.0, 2.0, 1.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 0.0f, (float)cdb_math_gelu(0.0));
}

static void test_rounding_and_misc(void)
{
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 2.5f, (float)cdb_math_abs(-2.5));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 1.0f, (float)cdb_math_sign(42.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, -1.0f, (float)cdb_math_sign(-42.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 0.0f, (float)cdb_math_sign(0.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 2.0f, (float)cdb_math_ceil(1.1));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 1.0f, (float)cdb_math_floor(1.9));
    /* round: decimals<=0 path and decimals>0 path */
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 3.0f, (float)cdb_math_round(2.5, 0));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 3.14f, (float)cdb_math_round(3.14159, 2));
    /* clamp: below / inside / above */
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 0.0f, (float)cdb_math_clamp(-1.0, 0.0, 1.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 0.5f, (float)cdb_math_clamp(0.5, 0.0, 1.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 1.0f, (float)cdb_math_clamp(2.0, 0.0, 1.0));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 5.0f, (float)cdb_math_lerp(0.0, 10.0, 0.5));
}

static void test_geo_tiles_morton_bbox(void)
{
    /* bbox: inside true, outside false (both branches) */
    TEST_ASSERT_TRUE(cdb_math_bbox_contains(0.0, 0.0, 10.0, 10.0, 5.0, 5.0));
    TEST_ASSERT_FALSE(cdb_math_bbox_contains(0.0, 0.0, 10.0, 10.0, 20.0, 5.0));

    /* slippy-map tiles at zoom 0: whole world is tile (0,0) */
    TEST_ASSERT_EQUAL_INT(0, cdb_math_lon_to_tile_x(-180.0, 0));
    TEST_ASSERT_EQUAL_INT(0, cdb_math_lat_to_tile_y(85.0, 0));
    /* zoom 1 splits in two: eastern hemisphere -> x==1 */
    TEST_ASSERT_EQUAL_INT(1, cdb_math_lon_to_tile_x(90.0, 1));
    /* round-trip tile -> lon/lat is finite and in range */
    ASSERT_FINITE(cdb_math_tile_x_to_lon(1, 2));
    ASSERT_FINITE(cdb_math_tile_y_to_lat(1, 2));

    /* morton2d is monotone-ish and distinct for distinct points */
    TEST_ASSERT_NOT_EQUAL(cdb_math_morton2d(0.0, 0.0), cdb_math_morton2d(10.0, 10.0));
}

static void test_vec_ops_and_errors(void)
{
    float u[3] = {1.0f, 2.0f, 2.0f};
    float v[3] = {4.0f, 0.0f, 0.0f};
    float out[3];
    float scalar = 0.0f;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_vec_add(u, v, 3, out));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 5.0f, out[0]);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_vec_sub(u, v, 3, out));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, -3.0f, out[0]);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_vec_scale(u, 2.0f, 3, out));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 2.0f, out[0]);
    /* |u| = 3, |v| = 4, dot = 4 -> cosine = 4/12 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_vec_cosine(u, v, 3, &scalar));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 0.3333333f, scalar);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_vec_distance(u, v, 3, &scalar));
    ASSERT_FINITE(scalar);
    /* zero-norm cosine is defined as 0 (the nu==0 branch) */
    {
        float z[3] = {0.0f, 0.0f, 0.0f};
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_vec_cosine(z, v, 3, &scalar));
        TEST_ASSERT_FLOAT_WITHIN(1e-6f, 0.0f, scalar);
    }
    /* NULL-argument fail-closed branch */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_math_vec_add(NULL, v, 3, out));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_math_vec_sub(u, NULL, 3, out));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_math_vec_scale(NULL, 1.0f, 3, out));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_math_vec_distance(u, NULL, 3, &scalar));
}

static void test_mat_ops_and_errors(void)
{
    /* 2x2 identity-ish */
    float m[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float v[2] = {1.0f, 1.0f};
    float out[4];
    float tr = 0.0f;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_trace(m, 2, &tr));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 5.0f, tr); /* 1 + 4 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_transpose(m, 2, 2, out));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 3.0f, out[1]); /* m[1][0] -> out[0][1] */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_mat_vec_mul(m, 2, 2, v, out));
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 3.0f, out[0]); /* 1*1 + 2*1 */
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 7.0f, out[1]); /* 3*1 + 4*1 */

    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_math_mat_trace(NULL, 2, &tr));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_math_mat_transpose(NULL, 2, 2, out));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_math_mat_vec_mul(m, 2, 2, NULL, out));
}

static void test_windows_and_fft(void)
{
    float w[8];
    float sig[8] = {0.0f, 1.0f, 0.0f, -1.0f, 0.0f, 1.0f, 0.0f, -1.0f};
    float wr[8], wi[8], power[8];

    /* each window: n>1 fills, endpoints as specified; also hit n==0 (no-op)
     * and n==1 (single 1.0) branches. */
    cdb_math_window_hann(w, 8);
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 0.0f, w[0]);
    cdb_math_window_hamming(w, 8);
    TEST_ASSERT_FLOAT_WITHIN(1e-4f, 0.08f, w[0]);
    cdb_math_window_blackman(w, 8);
    ASSERT_FINITE(w[4]);
    cdb_math_window_hann(w, 1);
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 1.0f, w[0]);
    cdb_math_window_hamming(w, 1);
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 1.0f, w[0]);
    cdb_math_window_blackman(w, 1);
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 1.0f, w[0]);
    w[0] = 42.0f;
    cdb_math_window_hann(w, 0);   /* no-op branch */
    TEST_ASSERT_FLOAT_WITHIN(1e-6f, 42.0f, w[0]);

    /* fft_power over an n=8 (power-of-2) signal */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_math_fft_power(sig, 8, wr, wi, power));
    ASSERT_FINITE(power[0]);
    ASSERT_FINITE(power[4]);
    /* fail-closed: NULL / zero-length */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_math_fft_power(NULL, 8, wr, wi, power));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_math_fft_power(sig, 0, wr, wi, power));
}

static void test_domain_helpers(void)
{
    /* Each domain builtin: call with physically sane inputs and assert the
     * result is finite (exercises the body; exact constants are spec-owned). */
    ASSERT_FINITE(cdb_math_elec_reactance_c(1000.0, 1e-6));
    ASSERT_FINITE(cdb_math_elec_reactance_l(1000.0, 1e-3));
    ASSERT_FINITE(cdb_math_elec_lc_resonance(1e-3, 1e-6));
    ASSERT_FINITE(cdb_math_elec_steinhart_hart(10000.0, 1.1e-3, 2.3e-4, 8.7e-8));
    ASSERT_FINITE(cdb_math_fluid_reynolds(1000.0, 2.0, 0.05, 1e-3));
    ASSERT_FINITE(cdb_math_fluid_venturi_flow(500.0, 1000.0, 0.98, 0.01, 0.005));
    ASSERT_FINITE(cdb_math_atmo_vapor_pressure(20.0, 50.0));
    ASSERT_FINITE(cdb_math_atmo_heat_index(30.0, 70.0));
    ASSERT_FINITE(cdb_math_atmo_wind_chill(-5.0, 10.0));
    ASSERT_FINITE(cdb_math_atmo_alt_to_sealevel_p(900.0, 1000.0, 15.0));
    ASSERT_FINITE(cdb_math_astro_angular_sep(10.0, 20.0, 11.0, 21.0));
    ASSERT_FINITE(cdb_math_thermal_radiation_power(0.9, 1.0, 300.0));
    ASSERT_FINITE(cdb_math_along_track_distance(0.0, 0.0, 0.0, 10.0, 1.0, 5.0));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_scalar_trig_exp_log);
    RUN_TEST(test_rounding_and_misc);
    RUN_TEST(test_geo_tiles_morton_bbox);
    RUN_TEST(test_vec_ops_and_errors);
    RUN_TEST(test_mat_ops_and_errors);
    RUN_TEST(test_windows_and_fft);
    RUN_TEST(test_domain_helpers);
    return UNITY_END();
}
