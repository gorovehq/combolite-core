/* Coverage set for the scalar math CALL functions in cdb_eval (spec 17 built-in
 * functions) + cdb_math. Drains SELECT <fn>(args) over a seeded row so each
 * CDB_FN_* case, to_double(), and cdb_eval_make_f64 path executes. Covers the
 * standard-math subset (trig, hyperbolic, exp/log, power/root, rounding, erf)
 * whose arities are fixed; domain-safe arguments. Spec 17 (query/eval). */
#define _POSIX_C_SOURCE 200809L

#include "unity.h"
#include "cdb_compiler.h"
#include "cdb_proc.h"
#include "cdb_db.h"
#include "cdb_exec.h"
#include "cdb_faultenv.h"

#include <stdlib.h>
#include <string.h>

#define FCAP (640u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 4096u];
static cdb_faultenv fe;
static cdb_env env;

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[8192];
static uint8_t record_buf[1024];
static uint8_t cat_work[16384];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static uint8_t doc_bufs[16384];
static uint8_t doc_stage[16384];
static uint8_t idx_stage[16384];
static cdb_db_config cfg;
static cdb_db db;

static uint8_t wire[2048];
static uint8_t scratch[64u * 1024u];
static cdb_exec_cursor cur;

void setUp(void) {}
void tearDown(void) {}

static cdb_header hdr(void)
{
    cdb_header h; unsigned i;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    for (i = 0; i < 16; i++) h.db_id[i] = (uint8_t)(0x70 + i);
    return h;
}

static void cfg_init(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena; c.file_capacity = FCAP;
    c.records = env_records; c.records_per_file = 4096;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
    memset(&cfg, 0, sizeof cfg);
    cfg.pager.arena = arena; cfg.pager.arena_size = sizeof arena;
    cfg.pager.nodes = nodes; cfg.pager.node_cap = NODES;
    cfg.pager.free_list = free_list; cfg.pager.free_cap = sizeof free_list / sizeof free_list[0];
    cfg.record_buf = record_buf; cfg.record_buf_size = sizeof record_buf;
    cfg.catalog_work.bytes = cat_work; cfg.catalog_work.bytes_size = sizeof cat_work;
    cfg.catalog_work.entries = cat_entries; cfg.catalog_work.entries_cap = sizeof cat_entries / sizeof cat_entries[0];
    cfg.catalog_page = cat_page;
    cfg.doc_buffers = doc_bufs; cfg.doc_stage = doc_stage; cfg.doc_stage_size = sizeof doc_stage;
    cfg.idx_stage = idx_stage; cfg.idx_stage_size = sizeof idx_stage;
    cfg.aead_alg = CDB_AEAD_AES_256_GCM; cfg.durability = CDB_DURABILITY_FULL;
}

static cdb_status run(const char *script)
{
    uint8_t bc[4096]; size_t bl = 0; cdb_compile_error e; cdb_proc_vm vm; cdb_value out; cdb_status s;
    memset(&e, 0, sizeof e);
    s = cdb_compile_proc(script, strlen(script), NULL, bc, sizeof bc, &bl, &e);
    if (s != CDB_OK) return s;
    cdb_proc_vm_init(&vm, &db, CDB_ORDER_LITTLE, NULL, 0, 1000000);
    return cdb_proc_exec(&vm, bc, bl, &out);
}

static cdb_status drain(const char *q)
{
    size_t len = 0; cdb_compile_error err; cdb_exec_row row; int has = 0; cdb_status s;
    memset(&err, 0, sizeof err);
    s = cdb_compile_query(q, strlen(q), &db.catalog, wire, sizeof wire, &len, &err);
    if (s != CDB_OK) return s;
    s = cdb_exec_open(&cur, &db, wire, len, NULL, 0, scratch, sizeof scratch);
    if (s != CDB_OK) return s;
    while ((s = cdb_exec_next(&cur, &row, &has)) == CDB_OK && has) { /* drain */ }
    cdb_exec_close(&cur);
    return s;
}

#define DOK(q)  TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, drain(q), q)

static void seed(void)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, run("CREATE STORE \"docs\" MODEL document;"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, run("INSERT INTO \"docs\" (\"{\\\"id\\\":1}\", \"k1\");"));
}

static void test_math_functions(void)
{
    cdb_header h = hdr();
    cfg_init();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "mf", &cfg, &h));
    seed();

    /* trigonometric */
    DOK("SELECT sin(0.5) FROM Scan(\"docs\")");
    DOK("SELECT cos(0.5) FROM Scan(\"docs\")");
    DOK("SELECT tan(0.5) FROM Scan(\"docs\")");
    DOK("SELECT asin(0.5) FROM Scan(\"docs\")");
    DOK("SELECT acos(0.5) FROM Scan(\"docs\")");
    DOK("SELECT atan(0.5) FROM Scan(\"docs\")");
    DOK("SELECT atan2(1.0, 1.0) FROM Scan(\"docs\")");
    /* hyperbolic */
    DOK("SELECT sinh(0.5) FROM Scan(\"docs\")");
    DOK("SELECT cosh(0.5) FROM Scan(\"docs\")");
    DOK("SELECT tanh(0.5) FROM Scan(\"docs\")");
    /* angle conversion */
    DOK("SELECT degrees(1.0) FROM Scan(\"docs\")");
    DOK("SELECT radians(90.0) FROM Scan(\"docs\")");
    /* exp / log family */
    DOK("SELECT exp(1.0) FROM Scan(\"docs\")");
    DOK("SELECT ln(2.0) FROM Scan(\"docs\")");
    DOK("SELECT log(2.0) FROM Scan(\"docs\")");
    DOK("SELECT log10(100.0) FROM Scan(\"docs\")");
    DOK("SELECT log2(8.0) FROM Scan(\"docs\")");
    /* power / root */
    DOK("SELECT pow(2.0, 3.0) FROM Scan(\"docs\")");
    DOK("SELECT sqrt(9.0) FROM Scan(\"docs\")");
    DOK("SELECT cbrt(27.0) FROM Scan(\"docs\")");
    DOK("SELECT hypot(3.0, 4.0) FROM Scan(\"docs\")");
    /* rounding / sign / error-function */
    DOK("SELECT abs(5.0) FROM Scan(\"docs\")");
    DOK("SELECT ceil(1.2) FROM Scan(\"docs\")");
    DOK("SELECT floor(1.8) FROM Scan(\"docs\")");
    DOK("SELECT round(1.5) FROM Scan(\"docs\")");
    DOK("SELECT round(3.14159, 2) FROM Scan(\"docs\")");
    DOK("SELECT erf(0.5) FROM Scan(\"docs\")");

    cdb_db_close(&db);
}

/* The domain-specific CALL functions (geo, signal/IQ, astronomy, electronics,
 * atmosphere, fluids) — each a distinct CDB_FN_* case. Arities match the eval
 * dispatch; arguments are finite and type-safe (the formulas are pure, so any
 * finite input drives the case + to_double + make_f64 without erroring). */
static void test_math_domain_functions(void)
{
    cdb_header h = hdr();
    cfg_init();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "md", &cfg, &h));
    seed();

    /* geo / navigation */
    DOK("SELECT haversine(1.0, 2.0, 3.0, 4.0) FROM Scan(\"docs\")");
    DOK("SELECT bearing(1.0, 2.0, 3.0, 4.0) FROM Scan(\"docs\")");
    DOK("SELECT cross_track_distance(1.0, 2.0, 3.0, 4.0, 5.0, 6.0) FROM Scan(\"docs\")");
    /* signal / IQ */
    DOK("SELECT iq_magnitude(1.0, 2.0) FROM Scan(\"docs\")");
    DOK("SELECT iq_phase(1.0, 2.0) FROM Scan(\"docs\")");
    DOK("SELECT iq_demod_fm(1.0, 2.0, 3.0, 4.0) FROM Scan(\"docs\")");
    DOK("SELECT dbfs(0.5) FROM Scan(\"docs\")");
    /* astronomy */
    DOK("SELECT astro_refraction(10.0) FROM Scan(\"docs\")");
    DOK("SELECT astro_angular_sep(1.0, 2.0, 3.0, 4.0) FROM Scan(\"docs\")");
    DOK("SELECT astro_alt(1.0, 2.0, 3.0, 4.0, 5.0, 6.0) FROM Scan(\"docs\")");
    DOK("SELECT astro_az(1.0, 2.0, 3.0, 4.0, 5.0, 6.0) FROM Scan(\"docs\")");
    DOK("SELECT astro_range(1.0, 2.0, 3.0, 4.0, 5.0, 6.0) FROM Scan(\"docs\")");
    DOK("SELECT astro_altaz_to_ra(1.0, 2.0, 3.0, 4.0, 5.0) FROM Scan(\"docs\")");
    DOK("SELECT astro_altaz_to_dec(1.0, 2.0, 3.0, 4.0, 5.0) FROM Scan(\"docs\")");
    DOK("SELECT astro_radec_to_alt(1.0, 2.0, 3.0, 4.0, 5.0) FROM Scan(\"docs\")");
    DOK("SELECT astro_radec_to_az(1.0, 2.0, 3.0, 4.0, 5.0) FROM Scan(\"docs\")");
    /* electronics */
    DOK("SELECT elec_thermistor_ntc(1.0, 2.0, 3.0, 4.0) FROM Scan(\"docs\")");
    DOK("SELECT elec_steinhart_hart(1.0, 2.0, 3.0, 4.0) FROM Scan(\"docs\")");
    DOK("SELECT elec_adc_volts(1.0, 2.0, 3.0) FROM Scan(\"docs\")");
    DOK("SELECT elec_voltage_divider(1.0, 2.0, 3.0) FROM Scan(\"docs\")");
    DOK("SELECT elec_parallel_r(1.0, 2.0) FROM Scan(\"docs\")");
    DOK("SELECT elec_dbm_to_watts(1.0) FROM Scan(\"docs\")");
    DOK("SELECT elec_watts_to_dbm(1.0) FROM Scan(\"docs\")");
    DOK("SELECT elec_rc_cutoff(1.0, 2.0) FROM Scan(\"docs\")");
    DOK("SELECT elec_lc_resonance(1.0, 2.0) FROM Scan(\"docs\")");
    DOK("SELECT elec_reactance_c(1.0, 2.0) FROM Scan(\"docs\")");
    DOK("SELECT elec_reactance_l(1.0, 2.0) FROM Scan(\"docs\")");
    /* atmosphere */
    DOK("SELECT atmo_pressure_to_alt(1.0, 2.0) FROM Scan(\"docs\")");
    DOK("SELECT atmo_alt_to_sealevel_p(1.0, 2.0, 3.0) FROM Scan(\"docs\")");
    DOK("SELECT atmo_dew_point(1.0, 2.0) FROM Scan(\"docs\")");
    DOK("SELECT atmo_vapor_pressure(1.0, 2.0) FROM Scan(\"docs\")");
    DOK("SELECT atmo_heat_index(1.0, 2.0) FROM Scan(\"docs\")");
    /* fluids */
    DOK("SELECT fluid_reynolds(1.0, 2.0, 3.0, 4.0) FROM Scan(\"docs\")");
    DOK("SELECT fluid_dynamic_pressure(1.0, 2.0) FROM Scan(\"docs\")");
    DOK("SELECT fluid_pitot_airspeed(1.0, 2.0, 3.0) FROM Scan(\"docs\")");
    DOK("SELECT fluid_hydrostatic_pressure(1.0, 2.0) FROM Scan(\"docs\")");
    DOK("SELECT fluid_venturi_flow(1.0, 2.0, 3.0, 4.0, 5.0) FROM Scan(\"docs\")");

    cdb_db_close(&db);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_math_functions);
    RUN_TEST(test_math_domain_functions);
    return UNITY_END();
}
