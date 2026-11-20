#define _POSIX_C_SOURCE 200809L
/* Branch-coverage set for cdb_eval: operator, type-coercion, error and
 * math-CALL paths that test_eval_cov / test_eval_edge miss. Expressions are
 * built directly in CMBQL wire form (cdb_query_write_expr_*) and evaluated with
 * cdb_eval_expr_wire, so every arithmetic/unary/compare/CALL branch is reached
 * with a real, asserted outcome (value, type, or CDB_E_* enum) rather than mere
 * line execution. Math CALL results are checked against the cdb_math engine
 * directly. Fully hermetic: no DB, no network, static buffers. Spec 11.10. */
#include <stdio.h>
#include <string.h>

#include "unity.h"
#include "cdb_eval.h"
#include "cdb_math.h"
#include "cdb_query.h"
#include "combolite/cdb_value.h"

void setUp(void) {}
void tearDown(void) {}

/* ------------------------------------------------------------ builders */

static void put_lit_int(cdb_query_writer *w, int64_t v)
{
    uint8_t b[32];
    cdb_value_writer vw;
    cdb_value_writer_init(&vw, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_write_int(&vw, v));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(w, b, cdb_value_writer_len(&vw)));
}

static void put_lit_f64(cdb_query_writer *w, double v)
{
    uint8_t b[32];
    cdb_value_writer vw;
    cdb_value_writer_init(&vw, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_write_f64(&vw, v));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(w, b, cdb_value_writer_len(&vw)));
}

static void put_lit_str(cdb_query_writer *w, const char *s)
{
    uint8_t b[256];
    cdb_value_writer vw;
    cdb_value_writer_init(&vw, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_write_string(&vw, s, strlen(s)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(w, b, cdb_value_writer_len(&vw)));
}

static void put_lit_bool(cdb_query_writer *w, int b)
{
    uint8_t bb[16];
    cdb_value_writer vw;
    cdb_value_writer_init(&vw, bb, sizeof bb, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_write_bool(&vw, b));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(w, bb, cdb_value_writer_len(&vw)));
}

static void put_lit_null(cdb_query_writer *w)
{
    uint8_t b[16];
    cdb_value_writer vw;
    cdb_value_writer_init(&vw, b, sizeof b, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_write_null(&vw));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_literal(w, b, cdb_value_writer_len(&vw)));
}

static cdb_status eval(const uint8_t *wire, size_t len, cdb_value *out)
{
    cdb_eval_ctx ctx;
    size_t consumed = 0;
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    return cdb_eval_expr_wire(&ctx, wire, len, out, &consumed);
}

/* ------------------------------------------------------------ math CALL */

static double call_f64(uint16_t fn, const double *a, int n)
{
    uint8_t buf[1024];
    cdb_query_writer w;
    cdb_value out;
    cdb_eval_ctx ctx;
    size_t consumed = 0;
    int i;

    cdb_query_writer_init(&w, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_call(&w, fn, (uint16_t)n));
    for (i = 0; i < n; i++)
        put_lit_f64(&w, a[i]);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);

    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_F64, out.type);
    return out.as.f64;
}

static int64_t call_int(uint16_t fn, const double *a, int n)
{
    uint8_t buf[1024];
    cdb_query_writer w;
    cdb_value out;
    cdb_eval_ctx ctx;
    size_t consumed = 0;
    int i;

    cdb_query_writer_init(&w, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_call(&w, fn, (uint16_t)n));
    for (i = 0; i < n; i++)
        put_lit_f64(&w, a[i]);
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, out.type);
    return out.as.i64;
}

static int call_bool(uint16_t fn, const double *a, int n)
{
    uint8_t buf[1024];
    cdb_query_writer w;
    cdb_value out;
    cdb_eval_ctx ctx;
    size_t consumed = 0;
    int i;

    cdb_query_writer_init(&w, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_call(&w, fn, (uint16_t)n));
    for (i = 0; i < n; i++)
        put_lit_f64(&w, a[i]);
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_BOOL, out.type);
    return out.as.boolean;
}

#define A1 (double[]){ 0.5 }
#define CHKF(fn, expect, ...) \
    do { \
        double _a[] = { __VA_ARGS__ }; \
        TEST_ASSERT_EQUAL_DOUBLE((expect), call_f64((fn), _a, (int)(sizeof _a / sizeof _a[0]))); \
    } while (0)

static void test_call_trig_algebra(void)
{
    CHKF(CDB_FN_SIN, cdb_math_sin(0.5), 0.5);
    CHKF(CDB_FN_COS, cdb_math_cos(0.5), 0.5);
    CHKF(CDB_FN_TAN, cdb_math_tan(0.5), 0.5);
    CHKF(CDB_FN_ASIN, cdb_math_asin(0.5), 0.5);
    CHKF(CDB_FN_ACOS, cdb_math_acos(0.5), 0.5);
    CHKF(CDB_FN_ATAN, cdb_math_atan(0.5), 0.5);
    CHKF(CDB_FN_ATAN2, cdb_math_atan2(1.0, 2.0), 1.0, 2.0);
    CHKF(CDB_FN_SINH, cdb_math_sinh(0.5), 0.5);
    CHKF(CDB_FN_COSH, cdb_math_cosh(0.5), 0.5);
    CHKF(CDB_FN_TANH, cdb_math_tanh(0.5), 0.5);
    CHKF(CDB_FN_DEGREES, cdb_math_degrees(1.0), 1.0);
    CHKF(CDB_FN_RADIANS, cdb_math_radians(90.0), 90.0);

    CHKF(CDB_FN_SQRT, cdb_math_sqrt(16.0), 16.0);
    CHKF(CDB_FN_CBRT, cdb_math_cbrt(27.0), 27.0);
    CHKF(CDB_FN_POW, cdb_math_pow(2.0, 10.0), 2.0, 10.0);
    CHKF(CDB_FN_EXP, cdb_math_exp(1.0), 1.0);
    CHKF(CDB_FN_EXPM1, cdb_math_expm1(1.0), 1.0);
    CHKF(CDB_FN_LN, cdb_math_ln(2.0), 2.0);
    CHKF(CDB_FN_LOG10, cdb_math_log10(1000.0), 1000.0);
    CHKF(CDB_FN_LOG2, cdb_math_log2(8.0), 8.0);
    CHKF(CDB_FN_LOG1P, cdb_math_log1p(1.0), 1.0);
    CHKF(CDB_FN_ABS, cdb_math_abs(-3.0), -3.0);
    CHKF(CDB_FN_SIGN, cdb_math_sign(-3.0), -3.0);
    CHKF(CDB_FN_ROUND, cdb_math_round(3.14159, 0), 3.14159);
    CHKF(CDB_FN_FLOOR, cdb_math_floor(3.7), 3.7);
    CHKF(CDB_FN_CEIL, cdb_math_ceil(3.2), 3.2);
    CHKF(CDB_FN_CLAMP, cdb_math_clamp(5.0, 0.0, 3.0), 5.0, 0.0, 3.0);
    CHKF(CDB_FN_LERP, cdb_math_lerp(0.0, 10.0, 0.5), 0.0, 10.0, 0.5);
    CHKF(CDB_FN_SIGMOID, cdb_math_sigmoid(0.5), 0.5);
    CHKF(CDB_FN_RELU, cdb_math_relu(-2.0), -2.0);
    CHKF(CDB_FN_GELU, cdb_math_gelu(0.5), 0.5);
    CHKF(CDB_FN_ERF, cdb_math_erf(0.5), 0.5);

    CHKF(CDB_FN_DIFF, cdb_math_diff(5.0, 2.0), 5.0, 2.0);
    CHKF(CDB_FN_DERIVATIVE, cdb_math_derivative(3.0, 1.5), 3.0, 1.5);
    CHKF(CDB_FN_TRAPEZOID, cdb_math_trapezoid(1.0, 2.0, 0.5), 1.0, 2.0, 0.5);
}

static void test_call_geo_dsp(void)
{
    double two[2] = { 3.0, 4.0 };
    double z2[2] = { 5.0, 10.0 };
    double hv[4] = { 40.0, -74.0, 41.0, -75.0 };
    double bbox[6] = { 0.0, 0.0, 10.0, 10.0, 5.0, 5.0 };
    double pic[5] = { 1.0, 1.0, 1.0, 1.0, 1000.0 };

    CHKF(CDB_FN_HYPOT, cdb_math_hypot(3.0, 4.0), 3.0, 4.0);
    CHKF(CDB_FN_HYPOT3, cdb_math_hypot3(1.0, 2.0, 2.0), 1.0, 2.0, 2.0);
    CHKF(CDB_FN_HAVERSINE, cdb_math_haversine(40.0, -74.0, 41.0, -75.0), 40.0, -74.0, 41.0, -75.0);
    CHKF(CDB_FN_BEARING, cdb_math_bearing(40.0, -74.0, 41.0, -75.0), 40.0, -74.0, 41.0, -75.0);
    CHKF(CDB_FN_CROSS_TRACK_DISTANCE,
         cdb_math_cross_track_distance(40.0, -74.0, 41.0, -75.0, 40.5, -74.5),
         40.0, -74.0, 41.0, -75.0, 40.5, -74.5);
    CHKF(CDB_FN_ALONG_TRACK_DISTANCE,
         cdb_math_along_track_distance(40.0, -74.0, 41.0, -75.0, 40.5, -74.5),
         40.0, -74.0, 41.0, -75.0, 40.5, -74.5);
    CHKF(CDB_FN_WGS84_TO_MERCATOR_X, cdb_math_wgs84_to_mercator_x(-74.0), -74.0);
    CHKF(CDB_FN_WGS84_TO_MERCATOR_Y, cdb_math_wgs84_to_mercator_y(40.0), 40.0);
    CHKF(CDB_FN_MERCATOR_TO_WGS84_LON, cdb_math_mercator_to_wgs84_lon(100.0), 100.0);
    CHKF(CDB_FN_MERCATOR_TO_WGS84_LAT, cdb_math_mercator_to_wgs84_lat(100.0), 100.0);

    /* Spectral / SDR */
    CHKF(CDB_FN_IQ_MAGNITUDE, cdb_math_iq_magnitude(3.0, 4.0), 3.0, 4.0);
    CHKF(CDB_FN_IQ_PHASE, cdb_math_iq_phase(1.0, 1.0), 1.0, 1.0);
    CHKF(CDB_FN_IQ_DEMOD_FM, cdb_math_iq_demod_fm(1.0, 0.5, 0.9, 0.4), 1.0, 0.5, 0.9, 0.4);
    CHKF(CDB_FN_DBFS, cdb_math_dbfs(0.5), 0.5);

    /* Integer-valued geo functions. */
    TEST_ASSERT_EQUAL_INT64(cdb_math_lon_to_tile_x(-74.0, 5), call_int(CDB_FN_TILE_X, (double[]){ -74.0, 5.0 }, 2));
    TEST_ASSERT_EQUAL_INT64(cdb_math_lat_to_tile_y(40.0, 5), call_int(CDB_FN_TILE_Y, (double[]){ 40.0, 5.0 }, 2));
    TEST_ASSERT_EQUAL_INT64((int64_t)cdb_math_morton2d(40.0, -74.0), call_int(CDB_FN_MORTON2D, hv, 2));

    /* Boolean-valued geo functions. */
    TEST_ASSERT_EQUAL_INT(cdb_math_bbox_contains(0.0, 0.0, 10.0, 10.0, 5.0, 5.0),
                          call_bool(CDB_FN_BBOX_CONTAINS, bbox, 6));
    TEST_ASSERT_EQUAL_INT(cdb_math_point_in_circle(1.0, 1.0, 1.0, 1.0, 1000.0),
                          call_bool(CDB_FN_POINT_IN_CIRCLE, pic, 5));
    (void)two;
    (void)z2;
}

static void test_call_astro(void)
{
    double in6[6] = { 40.0, -74.0, 100.0, 41.0, -75.0, 500.0 };
    double az = 0.0, alt = 0.0, r = 0.0;
    cdb_math_astro_topocentric(40.0, -74.0, 100.0, 41.0, -75.0, 500.0, &az, &alt, &r);
    TEST_ASSERT_EQUAL_DOUBLE(alt, call_f64(CDB_FN_ASTRO_ALT, in6, 6));
    TEST_ASSERT_EQUAL_DOUBLE(az, call_f64(CDB_FN_ASTRO_AZ, in6, 6));
    TEST_ASSERT_EQUAL_DOUBLE(r, call_f64(CDB_FN_ASTRO_RANGE, in6, 6));

    {
        double in5[5] = { 45.0, 180.0, 40.0, -74.0, 1700000000.0 };
        double ra = 0.0, dec = 0.0, alt2 = 0.0, az2 = 0.0;
        cdb_math_astro_altaz_to_radec(45.0, 180.0, 40.0, -74.0, (int64_t)1700000000.0, &ra, &dec);
        TEST_ASSERT_EQUAL_DOUBLE(ra, call_f64(CDB_FN_ASTRO_ALTAZ_TO_RA, in5, 5));
        TEST_ASSERT_EQUAL_DOUBLE(dec, call_f64(CDB_FN_ASTRO_ALTAZ_TO_DEC, in5, 5));
        cdb_math_astro_radec_to_altaz(45.0, 20.0, 40.0, -74.0, (int64_t)1700000000.0, &alt2, &az2);
        {
            double in5b[5] = { 45.0, 20.0, 40.0, -74.0, 1700000000.0 };
            TEST_ASSERT_EQUAL_DOUBLE(alt2, call_f64(CDB_FN_ASTRO_RADEC_TO_ALT, in5b, 5));
            TEST_ASSERT_EQUAL_DOUBLE(az2, call_f64(CDB_FN_ASTRO_RADEC_TO_AZ, in5b, 5));
        }
    }
    CHKF(CDB_FN_ASTRO_REFRACTION, cdb_math_astro_refraction(10.0), 10.0);
    CHKF(CDB_FN_ASTRO_ANGULAR_SEP, cdb_math_astro_angular_sep(10.0, 20.0, 11.0, 21.0), 10.0, 20.0, 11.0, 21.0);
}

static void test_call_elec_atmo_fluid(void)
{
    CHKF(CDB_FN_ELEC_THERMISTOR_NTC, cdb_math_elec_thermistor_ntc(10000.0, 10000.0, 3950.0, 25.0),
         10000.0, 10000.0, 3950.0, 25.0);
    CHKF(CDB_FN_ELEC_STEINHART_HART, cdb_math_elec_steinhart_hart(10000.0, 1e-3, 2e-4, 1e-7),
         10000.0, 1e-3, 2e-4, 1e-7);
    CHKF(CDB_FN_ELEC_ADC_VOLTS, cdb_math_elec_adc_volts(512.0, 1024.0, 3.3), 512.0, 1024.0, 3.3);
    CHKF(CDB_FN_ELEC_VOLTAGE_DIVIDER, cdb_math_elec_voltage_divider(5.0, 1000.0, 2000.0), 5.0, 1000.0, 2000.0);
    CHKF(CDB_FN_ELEC_PARALLEL_R, cdb_math_elec_parallel_r(1000.0, 1000.0), 1000.0, 1000.0);
    CHKF(CDB_FN_ELEC_DBM_TO_WATTS, cdb_math_elec_dbm_to_watts(30.0), 30.0);
    CHKF(CDB_FN_ELEC_WATTS_TO_DBM, cdb_math_elec_watts_to_dbm(1.0), 1.0);
    CHKF(CDB_FN_ELEC_RC_CUTOFF, cdb_math_elec_rc_cutoff(1000.0, 1e-6), 1000.0, 1e-6);
    CHKF(CDB_FN_ELEC_LC_RESONANCE, cdb_math_elec_lc_resonance(1e-3, 1e-6), 1e-3, 1e-6);
    CHKF(CDB_FN_ELEC_REACTANCE_C, cdb_math_elec_reactance_c(1000.0, 1e-6), 1000.0, 1e-6);
    CHKF(CDB_FN_ELEC_REACTANCE_L, cdb_math_elec_reactance_l(1000.0, 1e-3), 1000.0, 1e-3);

    CHKF(CDB_FN_ATMO_PRESSURE_TO_ALT, cdb_math_atmo_pressure_to_alt(900.0, 1013.25), 900.0, 1013.25);
    CHKF(CDB_FN_ATMO_ALT_TO_SEALEVEL_P, cdb_math_atmo_alt_to_sealevel_p(900.0, 1000.0, 15.0), 900.0, 1000.0, 15.0);
    CHKF(CDB_FN_ATMO_DEW_POINT, cdb_math_atmo_dew_point(25.0, 60.0), 25.0, 60.0);
    CHKF(CDB_FN_ATMO_VAPOR_PRESSURE, cdb_math_atmo_vapor_pressure(25.0, 60.0), 25.0, 60.0);
    CHKF(CDB_FN_ATMO_HEAT_INDEX, cdb_math_atmo_heat_index(35.0, 70.0), 35.0, 70.0);
    CHKF(CDB_FN_ATMO_WIND_CHILL, cdb_math_atmo_wind_chill(-5.0, 10.0), -5.0, 10.0);
    CHKF(CDB_FN_ATMO_AIR_DENSITY, cdb_math_atmo_air_density(101325.0, 15.0, 50.0), 101325.0, 15.0, 50.0);
    CHKF(CDB_FN_GAS_IDEAL_PRESSURE, cdb_math_gas_ideal_pressure(1.0, 300.0, 0.0224), 1.0, 300.0, 0.0224);

    CHKF(CDB_FN_FLUID_DYNAMIC_PRESSURE, cdb_math_fluid_dynamic_pressure(1.225, 20.0), 1.225, 20.0);
    CHKF(CDB_FN_FLUID_PITOT_AIRSPEED, cdb_math_fluid_pitot_airspeed(102000.0, 101325.0, 1.225),
         102000.0, 101325.0, 1.225);
    CHKF(CDB_FN_FLUID_REYNOLDS, cdb_math_fluid_reynolds(1000.0, 2.0, 0.1, 1e-3), 1000.0, 2.0, 0.1, 1e-3);
    CHKF(CDB_FN_FLUID_HYDROSTATIC_PRESSURE, cdb_math_fluid_hydrostatic_pressure(1000.0, 10.0), 1000.0, 10.0);
    CHKF(CDB_FN_FLUID_VENTURI_FLOW, cdb_math_fluid_venturi_flow(500.0, 1000.0, 0.98, 0.01, 0.005),
         500.0, 1000.0, 0.98, 0.01, 0.005);
    CHKF(CDB_FN_THERMAL_JUNCTION_TEMP, cdb_math_thermal_junction_temp(25.0, 2.0, 40.0), 25.0, 2.0, 40.0);
    CHKF(CDB_FN_THERMAL_RADIATION_POWER, cdb_math_thermal_radiation_power(0.9, 0.01, 350.0), 0.9, 0.01, 350.0);
}

static void test_call_edges(void)
{
    uint8_t buf[256];
    cdb_query_writer w;
    cdb_value out;
    cdb_eval_ctx ctx;
    size_t consumed = 0;

    /* n_args > 8 -> CDB_E_UNSUPPORTED (the fixed args[8] bound). The nine
     * argument expressions must be present so the wire parses before eval
     * rejects the arity. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_call(&w, CDB_FN_SIN, 9));
    {
        int j;
        for (j = 0; j < 9; j++)
            put_lit_f64(&w, (double)j);
    }
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED,
                          cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));

    /* Unknown function ID -> CDB_E_UNSUPPORTED. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_call(&w, 0xEEEEu, 1));
    put_lit_f64(&w, 1.0);
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED,
                          cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));

    /* A NULL argument short-circuits the whole call to NULL. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_call(&w, CDB_FN_SQRT, 1));
    put_lit_null(&w);
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);

    /* to_double over BOOL and non-numeric (default) argument types. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_call(&w, CDB_FN_ABS, 1));
    put_lit_bool(&w, 1);
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));
    TEST_ASSERT_EQUAL_DOUBLE(cdb_math_abs(1.0), out.as.f64);

    cdb_query_writer_init(&w, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_write_expr_call(&w, CDB_FN_ABS, 1));
    put_lit_str(&w, "notanumber");
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));
    TEST_ASSERT_EQUAL_DOUBLE(cdb_math_abs(0.0), out.as.f64);
}

/* ------------------------------------------------------------ arithmetic */

static cdb_status eval_bin_ii(uint8_t op, int64_t l, int64_t r, cdb_value *out)
{
    uint8_t buf[128];
    cdb_query_writer w;
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, op);
    put_lit_int(&w, l);
    put_lit_int(&w, r);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    return eval(buf, cdb_query_writer_len(&w), out);
}

static cdb_status eval_bin_ff(uint8_t op, double l, double r, cdb_value *out)
{
    uint8_t buf[128];
    cdb_query_writer w;
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, op);
    put_lit_f64(&w, l);
    put_lit_f64(&w, r);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    return eval(buf, cdb_query_writer_len(&w), out);
}

static void test_arithmetic_int(void)
{
    cdb_value out;

    TEST_ASSERT_EQUAL_INT(CDB_OK, eval_bin_ii(CDB_BIN_ADD, 7, 5, &out));
    TEST_ASSERT_EQUAL_INT64(12, out.as.i64);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval_bin_ii(CDB_BIN_SUB, 7, 5, &out));
    TEST_ASSERT_EQUAL_INT64(2, out.as.i64);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval_bin_ii(CDB_BIN_MUL, 7, 5, &out));
    TEST_ASSERT_EQUAL_INT64(35, out.as.i64);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval_bin_ii(CDB_BIN_DIV, 20, 4, &out));
    TEST_ASSERT_EQUAL_INT64(5, out.as.i64);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval_bin_ii(CDB_BIN_MOD, 23, 5, &out));
    TEST_ASSERT_EQUAL_INT64(3, out.as.i64);

    /* Divide / modulo by zero yield NULL, never a trap. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval_bin_ii(CDB_BIN_DIV, 20, 0, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval_bin_ii(CDB_BIN_MOD, 20, 0, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);
}

static void test_arithmetic_float(void)
{
    cdb_value out;

    TEST_ASSERT_EQUAL_INT(CDB_OK, eval_bin_ff(CDB_BIN_ADD, 1.5, 2.25, &out));
    TEST_ASSERT_EQUAL_DOUBLE(3.75, out.as.f64);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval_bin_ff(CDB_BIN_SUB, 5.0, 1.25, &out));
    TEST_ASSERT_EQUAL_DOUBLE(3.75, out.as.f64);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval_bin_ff(CDB_BIN_MUL, 2.0, 3.5, &out));
    TEST_ASSERT_EQUAL_DOUBLE(7.0, out.as.f64);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval_bin_ff(CDB_BIN_DIV, 7.0, 2.0, &out));
    TEST_ASSERT_EQUAL_DOUBLE(3.5, out.as.f64);

    /* Float divide-by-zero and float MOD both yield NULL. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval_bin_ff(CDB_BIN_DIV, 7.0, 0.0, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval_bin_ff(CDB_BIN_MOD, 7.0, 2.0, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);

    /* Mixed int/float promotes to float. */
    {
        uint8_t buf[128];
        cdb_query_writer w;
        cdb_query_writer_init(&w, buf, sizeof buf);
        cdb_query_write_expr_binary(&w, CDB_BIN_ADD);
        put_lit_int(&w, 2);
        put_lit_f64(&w, 0.5);
        TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
        TEST_ASSERT_EQUAL_INT(CDB_TYPE_F64, out.type);
        TEST_ASSERT_EQUAL_DOUBLE(2.5, out.as.f64);
    }

    /* NULL operand propagates to NULL. */
    {
        uint8_t buf[128];
        cdb_query_writer w;
        cdb_query_writer_init(&w, buf, sizeof buf);
        cdb_query_write_expr_binary(&w, CDB_BIN_ADD);
        put_lit_null(&w);
        put_lit_int(&w, 1);
        TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
        TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);
    }
}

static void test_string_concat(void)
{
    uint8_t buf[128];
    uint8_t scratch[64];
    cdb_query_writer w;
    cdb_eval_ctx ctx;
    cdb_value out;
    size_t consumed = 0;

    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_ADD);
    put_lit_str(&w, "foo");
    put_lit_str(&w, "bar");
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);

    /* With scratch: concatenated string. */
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    cdb_eval_ctx_set_scratch(&ctx, scratch, sizeof scratch);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_STRING, out.type);
    TEST_ASSERT_EQUAL_size_t(6, out.payload_len);
    TEST_ASSERT_EQUAL_MEMORY("foobar", out.payload, 6);

    /* No scratch at all: eval_scratch_alloc returns NULL -> BUFFER_TOO_SMALL. */
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL,
                          cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));

    /* Scratch present but too small: overflow guard -> BUFFER_TOO_SMALL. */
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    cdb_eval_ctx_set_scratch(&ctx, scratch, 2);
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL,
                          cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));
}

static void test_comparisons(void)
{
    cdb_value out;
    static const uint8_t ops[6] = { CDB_BIN_EQ, CDB_BIN_NE, CDB_BIN_LT, CDB_BIN_LE, CDB_BIN_GT, CDB_BIN_GE };
    /* 3 vs 5: EQ=0 NE=1 LT=1 LE=1 GT=0 GE=0 */
    static const int want[6] = { 0, 1, 1, 1, 0, 0 };
    size_t i;

    for (i = 0; i < 6; i++) {
        TEST_ASSERT_EQUAL_INT(CDB_OK, eval_bin_ii(ops[i], 3, 5, &out));
        TEST_ASSERT_EQUAL_INT(CDB_TYPE_BOOL, out.type);
        TEST_ASSERT_EQUAL_INT(want[i], out.as.boolean);
    }

    /* NULL operand makes a comparison UNKNOWN (NULL). */
    {
        uint8_t buf[128];
        cdb_query_writer w;
        cdb_query_writer_init(&w, buf, sizeof buf);
        cdb_query_write_expr_binary(&w, CDB_BIN_EQ);
        put_lit_null(&w);
        put_lit_int(&w, 1);
        TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
        TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);
    }
}

static void test_logical_short_circuit(void)
{
    uint8_t buf[128];
    cdb_query_writer w;
    cdb_value out;

    /* AND: false && x -> false (right side short-circuited). */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_AND);
    put_lit_bool(&w, 0);
    put_lit_bool(&w, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_BOOL, out.type);
    TEST_ASSERT_EQUAL_INT(0, out.as.boolean);

    /* AND: true && true -> true. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_AND);
    put_lit_bool(&w, 1);
    put_lit_bool(&w, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(1, out.as.boolean);

    /* AND with a NULL operand -> NULL. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_AND);
    put_lit_bool(&w, 1);
    put_lit_null(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);

    /* OR: true || x -> true (short-circuit). */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_OR);
    put_lit_bool(&w, 1);
    put_lit_bool(&w, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(1, out.as.boolean);

    /* OR: false || false -> false. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_OR);
    put_lit_bool(&w, 0);
    put_lit_bool(&w, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(0, out.as.boolean);

    /* OR with a NULL operand and a false -> NULL. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_OR);
    put_lit_bool(&w, 0);
    put_lit_null(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);
}

static void test_string_like_contains(void)
{
    uint8_t buf[192];
    cdb_query_writer w;
    cdb_value out;

    /* LIKE with % and _ wildcards -> match. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_LIKE);
    put_lit_str(&w, "Alpha");
    put_lit_str(&w, "A%h_");
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_BOOL, out.type);
    TEST_ASSERT_EQUAL_INT(1, out.as.boolean);

    /* LIKE no match. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_LIKE);
    put_lit_str(&w, "Alpha");
    put_lit_str(&w, "B%");
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(0, out.as.boolean);

    /* LIKE on a non-string operand -> false. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_LIKE);
    put_lit_int(&w, 1);
    put_lit_str(&w, "1");
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(0, out.as.boolean);

    /* LIKE with a NULL operand -> NULL. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_LIKE);
    put_lit_null(&w);
    put_lit_str(&w, "x");
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);

    /* CONTAINS substring -> true; empty substring -> true. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_CONTAINS);
    put_lit_str(&w, "hello world");
    put_lit_str(&w, "o w");
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(1, out.as.boolean);

    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_CONTAINS);
    put_lit_str(&w, "short");
    put_lit_str(&w, "this is far too long to be contained");
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(0, out.as.boolean);

    /* CONTAINS on a non-string operand -> false. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_CONTAINS);
    put_lit_int(&w, 4);
    put_lit_str(&w, "4");
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(0, out.as.boolean);
}

static void test_unary(void)
{
    uint8_t buf[64];
    cdb_query_writer w;
    cdb_value out;

    /* NOT true -> false. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_unary(&w, CDB_UNARY_NOT);
    put_lit_bool(&w, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(0, out.as.boolean);

    /* NOT null -> null. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_unary(&w, CDB_UNARY_NOT);
    put_lit_null(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);

    /* NEG int / float / null. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_unary(&w, CDB_UNARY_NEG);
    put_lit_int(&w, 9);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT64(-9, out.as.i64);

    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_unary(&w, CDB_UNARY_NEG);
    put_lit_f64(&w, 1.5);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_DOUBLE(-1.5, out.as.f64);

    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_unary(&w, CDB_UNARY_NEG);
    put_lit_null(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);

    /* NEG on a non-numeric operand -> CDB_E_INVALID_ARG. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_unary(&w, CDB_UNARY_NEG);
    put_lit_str(&w, "x");
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, eval(buf, cdb_query_writer_len(&w), &out));

    /* IS NULL / IS NOT NULL. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_unary(&w, CDB_UNARY_IS_NULL);
    put_lit_null(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(1, out.as.boolean);

    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_unary(&w, CDB_UNARY_IS_NOT_NULL);
    put_lit_int(&w, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, eval(buf, cdb_query_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(1, out.as.boolean);
}

static void test_depth_and_budget(void)
{
    uint8_t buf[256];
    cdb_query_writer w;
    cdb_eval_ctx ctx;
    cdb_value out;
    size_t consumed = 0;
    int i;

    /* 40 nested NOTs exceeds CDB_EVAL_MAX_DEPTH (32) -> CDB_E_DEPTH. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    for (i = 0; i < 40; i++)
        cdb_query_write_expr_unary(&w, CDB_UNARY_NOT);
    put_lit_bool(&w, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_DEPTH,
                          cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));

    /* Zero step budget -> CDB_E_OUT_OF_BUDGET on the first step. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    put_lit_int(&w, 1);
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    cdb_eval_ctx_set_budget(&ctx, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_OUT_OF_BUDGET,
                          cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));

    /* A positive budget decrements and succeeds. */
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    cdb_eval_ctx_set_budget(&ctx, 10);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));
    TEST_ASSERT_EQUAL_INT64(1, out.as.i64);
}

static void test_params(void)
{
    uint8_t buf[64];
    cdb_query_writer w;
    cdb_eval_ctx ctx;
    cdb_value out;
    cdb_eval_param params[2];
    size_t consumed = 0;

    memset(params, 0, sizeof params);
    params[0].index = 0;
    cdb_eval_make_int(&params[0].val, 77);
    params[1].name = "pname";
    params[1].name_len = 5;
    params[1].index = 99;
    cdb_eval_make_int(&params[1].val, 88);

    /* Indexed param found. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_param_index(&w, 0);
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    cdb_eval_ctx_set_params(&ctx, params, 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));
    TEST_ASSERT_EQUAL_INT64(77, out.as.i64);

    /* Named param found. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_param_named(&w, "pname", 5);
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    cdb_eval_ctx_set_params(&ctx, params, 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));
    TEST_ASSERT_EQUAL_INT64(88, out.as.i64);

    /* Missing indexed param -> CDB_E_NOT_FOUND. */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_param_index(&w, 42);
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    cdb_eval_ctx_set_params(&ctx, params, 2);
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_eval_expr_wire(&ctx, buf, cdb_query_writer_len(&w), &out, &consumed));
}

/* ------------------------------------------------------------ compare / helpers */

static void ts_val(cdb_value *v, cdb_ts_precision p, int64_t ticks)
{
    memset(v, 0, sizeof *v);
    v->type = CDB_TYPE_TIMESTAMP;
    v->tag = CDB_TAG_TIMESTAMP;
    v->as.ts.precision = p;
    v->as.ts.ticks = ticks;
}

static void test_compare_direct(void)
{
    cdb_value a, b;
    int cmp = 99, is_null = 99;

    /* Bool vs bool. */
    cdb_eval_make_bool(&a, 1);
    cdb_eval_make_bool(&b, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_compare(&a, &b, &cmp, &is_null));
    TEST_ASSERT_EQUAL_INT(0, is_null);
    TEST_ASSERT_TRUE(cmp > 0);

    /* NULL operand. */
    cdb_eval_make_null(&a);
    cdb_eval_make_int(&b, 3);
    cmp = 7;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_compare(&a, &b, &cmp, &is_null));
    TEST_ASSERT_EQUAL_INT(1, is_null);
    TEST_ASSERT_EQUAL_INT(0, cmp);

    /* Timestamps across precisions exercise ts_to_nanos (seconds/millis/micros/nanos). */
    ts_val(&a, CDB_TS_SECONDS, 1);
    ts_val(&b, CDB_TS_MILLIS, 1000); /* both == 1e9 ns */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_compare(&a, &b, &cmp, &is_null));
    TEST_ASSERT_EQUAL_INT(0, cmp);
    ts_val(&a, CDB_TS_MICROS, 1);
    ts_val(&b, CDB_TS_NANOS, 1); /* 1000 ns vs 1 ns */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_compare(&a, &b, &cmp, &is_null));
    TEST_ASSERT_TRUE(cmp > 0);

    /* String comparison: prefix and ordering. */
    {
        cdb_value s1, s2;
        static const uint8_t p1[] = { 'a', 'b' };
        static const uint8_t p2[] = { 'a', 'b', 'c' };
        memset(&s1, 0, sizeof s1);
        memset(&s2, 0, sizeof s2);
        s1.type = s2.type = CDB_TYPE_STRING;
        s1.payload = p1;
        s1.payload_len = 2;
        s2.payload = p2;
        s2.payload_len = 3;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_compare(&s1, &s2, &cmp, &is_null));
        TEST_ASSERT_EQUAL_INT(-1, cmp); /* shorter prefix sorts first */
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_compare(&s2, &s1, &cmp, &is_null));
        TEST_ASSERT_EQUAL_INT(1, cmp);
    }

    /* Binary comparison with a differing byte. */
    {
        cdb_value x, y;
        static const uint8_t bx[] = { 1, 2, 3 };
        static const uint8_t by[] = { 1, 9, 3 };
        memset(&x, 0, sizeof x);
        memset(&y, 0, sizeof y);
        x.type = y.type = CDB_TYPE_BINARY;
        x.payload = bx;
        x.payload_len = 3;
        y.payload = by;
        y.payload_len = 3;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_compare(&x, &y, &cmp, &is_null));
        TEST_ASSERT_EQUAL_INT(-1, cmp);
    }

    /* Incompatible types order by type tag, deterministically. */
    cdb_eval_make_int(&a, 1);
    memset(&b, 0, sizeof b);
    b.type = CDB_TYPE_STRING;
    b.payload_len = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_compare(&a, &b, &cmp, &is_null));
    TEST_ASSERT_EQUAL_INT(0, is_null);
    TEST_ASSERT_EQUAL_INT((int)CDB_TYPE_INT - (int)CDB_TYPE_STRING, cmp);

    /* Argument guard. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_eval_compare(NULL, &b, &cmp, &is_null));
}

static void test_is_truthy_and_makers(void)
{
    cdb_value v;

    cdb_eval_make_bool(&v, 1);
    TEST_ASSERT_TRUE(cdb_eval_is_truthy(&v));
    cdb_eval_make_bool(&v, 0);
    TEST_ASSERT_FALSE(cdb_eval_is_truthy(&v));
    cdb_eval_make_int(&v, 5);
    TEST_ASSERT_TRUE(cdb_eval_is_truthy(&v));
    cdb_eval_make_int(&v, 0);
    TEST_ASSERT_FALSE(cdb_eval_is_truthy(&v));
    cdb_eval_make_f64(&v, 1.0);
    TEST_ASSERT_TRUE(cdb_eval_is_truthy(&v));
    cdb_eval_make_null(&v);
    TEST_ASSERT_FALSE(cdb_eval_is_truthy(&v));
    TEST_ASSERT_TRUE(cdb_eval_is_null(&v));
    TEST_ASSERT_FALSE(cdb_eval_is_truthy(NULL));
    TEST_ASSERT_TRUE(cdb_eval_is_null(NULL));

    /* F32 and STRING truthiness. */
    memset(&v, 0, sizeof v);
    v.type = CDB_TYPE_F32;
    v.as.f32 = 2.0f;
    TEST_ASSERT_TRUE(cdb_eval_is_truthy(&v));
    memset(&v, 0, sizeof v);
    v.type = CDB_TYPE_STRING;
    v.payload_len = 3;
    TEST_ASSERT_TRUE(cdb_eval_is_truthy(&v));
    v.payload_len = 0;
    TEST_ASSERT_FALSE(cdb_eval_is_truthy(&v));

    /* Makers tolerate a NULL out pointer. */
    cdb_eval_make_null(NULL);
    cdb_eval_make_bool(NULL, 1);
    cdb_eval_make_int(NULL, 1);
    cdb_eval_make_f64(NULL, 1.0);
}

static void test_resolve_field(void)
{
    cdb_eval_ctx ctx;
    cdb_value out;
    int found = 0;
    uint8_t rec[256];
    cdb_value_writer vw;
    size_t rlen;

    /* Pseudo-fields with and without the attribute present. */
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_resolve_field(&ctx, "$id", 3, &out, &found));
    TEST_ASSERT_EQUAL_INT(0, found); /* no entry id set */
    cdb_eval_ctx_set_entry_id(&ctx, 1234);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_resolve_field(&ctx, "$id", 3, &out, &found));
    TEST_ASSERT_EQUAL_INT(1, found);
    TEST_ASSERT_EQUAL_INT64(1234, out.as.i64);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_resolve_field(&ctx, "$entry_id", 9, &out, &found));
    TEST_ASSERT_EQUAL_INT(1, found);

    cdb_eval_ctx_set_score(&ctx, 0.75);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_resolve_field(&ctx, "$score", 6, &out, &found));
    TEST_ASSERT_EQUAL_INT(1, found);
    TEST_ASSERT_EQUAL_DOUBLE(0.75, out.as.f64);

    cdb_eval_ctx_set_timestamp(&ctx, 42, CDB_TS_MILLIS);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_resolve_field(&ctx, "$timestamp", 10, &out, &found));
    TEST_ASSERT_EQUAL_INT(1, found);
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_TIMESTAMP, out.type);

    {
        cdb_value vec;
        cdb_eval_make_int(&vec, 7);
        cdb_eval_ctx_set_vector(&ctx, &vec);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_resolve_field(&ctx, "$vector", 7, &out, &found));
        TEST_ASSERT_EQUAL_INT(1, found);
        cdb_eval_ctx_set_vector(&ctx, NULL);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_resolve_field(&ctx, "$vector", 7, &out, &found));
        TEST_ASSERT_EQUAL_INT(0, found);
    }

    /* No record bound -> any plain field is not found. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_resolve_field(&ctx, "1", 1, &out, &found));
    TEST_ASSERT_EQUAL_INT(0, found);

    /* A bound object record: numeric field IDs resolve when no catalog is set. */
    cdb_value_writer_init(&vw, rec, sizeof rec, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&vw);
    cdb_value_field(&vw, 1);
    cdb_value_write_int(&vw, 555);
    cdb_value_field(&vw, 2);
    cdb_value_write_string(&vw, "hi", 2);
    cdb_value_end_object(&vw);
    TEST_ASSERT_EQUAL_INT(CDB_OK, vw.error);
    rlen = cdb_value_writer_len(&vw);
    cdb_eval_ctx_set_record(&ctx, rec, rlen);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_resolve_field(&ctx, "1", 1, &out, &found));
    TEST_ASSERT_EQUAL_INT(1, found);
    TEST_ASSERT_EQUAL_INT64(555, out.as.i64);

    /* A missing field id. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_resolve_field(&ctx, "9", 1, &out, &found));
    TEST_ASSERT_EQUAL_INT(0, found);

    /* A non-numeric segment with no catalog is not found. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_resolve_field(&ctx, "name", 4, &out, &found));
    TEST_ASSERT_EQUAL_INT(0, found);

    /* Argument guard. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_eval_resolve_field(NULL, "1", 1, &out, &found));
}

static cdb_status fake_resolver(void *ud, const char *path, size_t plen, cdb_value *out, int *found)
{
    (void)ud;
    /* Fail closed on NULL out-params before any dereference: a resolver sits on a
     * fallible callback boundary invoked by the evaluator, so it must not blindly
     * write through caller-supplied pointers (CWE-476 null-deref). */
    if (path == NULL || out == NULL || found == NULL)
        return CDB_E_INVALID_ARG;
    if (plen == 3 && memcmp(path, "cnt", 3) == 0) {
        cdb_eval_make_int(out, 999);
        *found = 1;
    } else {
        *found = 0;
    }
    return CDB_OK;
}

static void test_custom_resolver_and_null_guards(void)
{
    cdb_eval_ctx ctx;
    cdb_value out;
    int found = 0;
    size_t consumed = 0;

    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    cdb_eval_ctx_set_custom_resolver(&ctx, fake_resolver, NULL);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_resolve_field(&ctx, "cnt", 3, &out, &found));
    TEST_ASSERT_EQUAL_INT(1, found);
    TEST_ASSERT_EQUAL_INT64(999, out.as.i64);
    /* A path the resolver does not know falls through (not found, no record). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_resolve_field(&ctx, "zzz", 3, &out, &found));
    TEST_ASSERT_EQUAL_INT(0, found);

    /* NULL-context setters are safe no-ops. */
    cdb_eval_ctx_init(NULL, CDB_ORDER_LITTLE, NULL, 0);
    cdb_eval_ctx_set_scratch(NULL, NULL, 0);
    cdb_eval_ctx_reset_scratch(NULL);
    cdb_eval_ctx_set_params(NULL, NULL, 0);
    cdb_eval_ctx_set_record(NULL, NULL, 0);
    cdb_eval_ctx_set_entry_id(NULL, 0);
    cdb_eval_ctx_set_score(NULL, 0.0);
    cdb_eval_ctx_set_timestamp(NULL, 0, CDB_TS_MILLIS);
    cdb_eval_ctx_set_vector(NULL, NULL);
    cdb_eval_ctx_set_budget(NULL, 0);
    cdb_eval_ctx_set_custom_resolver(NULL, NULL, NULL);

    /* Top-level entry-point argument guards. */
    {
        uint8_t buf[16];
        cdb_query_writer w;
        cdb_eval_ctx c2;
        int matched = 0;
        cdb_query_writer_init(&w, buf, sizeof buf);
        put_lit_int(&w, 1);
        cdb_eval_ctx_init(&c2, CDB_ORDER_LITTLE, NULL, 0);
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                              cdb_eval_expr_wire(&c2, NULL, 4, &out, &consumed));
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                              cdb_eval_predicate(&c2, NULL, 4, &matched));
        /* A truthy predicate over a real expression. */
        TEST_ASSERT_EQUAL_INT(CDB_OK,
                              cdb_eval_predicate(&c2, buf, cdb_query_writer_len(&w), &matched));
        TEST_ASSERT_EQUAL_INT(1, matched);
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_call_trig_algebra);
    RUN_TEST(test_call_geo_dsp);
    RUN_TEST(test_call_astro);
    RUN_TEST(test_call_elec_atmo_fluid);
    RUN_TEST(test_call_edges);
    RUN_TEST(test_arithmetic_int);
    RUN_TEST(test_arithmetic_float);
    RUN_TEST(test_string_concat);
    RUN_TEST(test_comparisons);
    RUN_TEST(test_logical_short_circuit);
    RUN_TEST(test_string_like_contains);
    RUN_TEST(test_unary);
    RUN_TEST(test_depth_and_budget);
    RUN_TEST(test_params);
    RUN_TEST(test_compare_direct);
    RUN_TEST(test_is_truthy_and_makers);
    RUN_TEST(test_resolve_field);
    RUN_TEST(test_custom_resolver_and_null_guards);
    return UNITY_END();
}
