/* Branch-coverage set for the stored-procedure bytecode VM (src/cdb_proc.c).
 *
 * Drives cdb_proc_exec three ways to reach as many branches as possible:
 *  - the cdb_proc_write_* assembler on small well-formed programs (the writer
 *    API and the happy paths of each opcode),
 *  - hand-assembled bytecode with a correct body-length varint (run_body),
 *    to hit every truncation / malformed / bounds guard precisely, and
 *  - executed mutation opcodes against a live document database, to cover the
 *    mutation dispatch, the value-shaping helpers, savepoints and cursors.
 *
 * The document model is built; table / vector / timeseries / link / admin
 * mutations may report CDB_E_UNSUPPORTED (or a logical error) on this build,
 * which these tests tolerate (they only need the case body to execute).
 * Spec 4.5, 11.2, 11.7, 11.12.3; Spec 14.20. */
#define _POSIX_C_SOURCE 200809L

#include "unity.h"
#include "cdb_proc.h"
#include "cdb_query.h"
#include "cdb_db.h"
#include "cdb_doc.h"
#include "cdb_table.h"
#include "cdb_catalog.h"
#include "cdb_eval.h"
#include "cdb_varint.h"
#include "cdb_faultenv.h"
#include "cdb_compiler.h"
#include "combolite/cdb_value.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------ live DB harness
 * (mirrors tests/test_exec_live.c so a document store + scans work) */
#define FCAP (1024u * 1024u)
#define PAGE_LOG2 10u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define DOC_MAX 12288u
#define DBUF (DOC_MAX + PAGE)

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 8192u];
static cdb_faultenv fe;
static cdb_env env;

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[4096];
static uint8_t record_buf[DOC_MAX + 2u * PAGE];
static uint8_t cat_work[24u * 1024u];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static uint8_t doc_buffers[3u * DBUF + 5u * PAGE];
static uint8_t doc_stage[4096];
static uint8_t idx_stage[16u * 1024u];
static uint8_t table_buffers[64u * 1024u];
static cdb_db_config cfg;
static cdb_db db;

void setUp(void) {}
void tearDown(void) {}

static void init_env(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 8192;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
}

static void cfg_init(void)
{
    memset(&cfg, 0, sizeof cfg);
    cfg.pager.arena = arena;
    cfg.pager.arena_size = sizeof arena;
    cfg.pager.nodes = nodes;
    cfg.pager.node_cap = NODES;
    cfg.pager.free_list = free_list;
    cfg.pager.free_cap = sizeof free_list / sizeof free_list[0];
    cfg.record_buf = record_buf;
    cfg.record_buf_size = sizeof record_buf;
    cfg.catalog_work.bytes = cat_work;
    cfg.catalog_work.bytes_size = sizeof cat_work;
    cfg.catalog_work.entries = cat_entries;
    cfg.catalog_work.entries_cap = 512;
    cfg.catalog_page = cat_page;
    cfg.doc_buffers = doc_buffers;
    cfg.doc_stage = doc_stage;
    cfg.doc_stage_size = sizeof doc_stage;
    cfg.idx_stage = idx_stage;
    cfg.idx_stage_size = sizeof idx_stage;
    cfg.table_buffers = table_buffers;
    cfg.doc_max = DOC_MAX;
    cfg.durability = CDB_DURABILITY_FULL;
}

static void db_open(void)
{
    cdb_header h;
    init_env();
    cfg_init();
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x3A, sizeof h.db_id);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "procov", &cfg, &h));
}

static void db_shut(void) { cdb_db_close(&db); }

/* A document store "docs" with field n and two rows {n:10},{n:20}. */
static uint64_t seed_docs(void)
{
    uint64_t store = 0, f_n = 0, entry = 0;
    uint8_t docbuf[128];
    cdb_value_writer w;
    int i;
    const int64_t ns[2] = {10, 20};

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "docs", 4, CDB_MODEL_DOCUMENT, &store));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_catalog_field_id(&db.catalog, store, "n", 1, &f_n));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    for (i = 0; i < 2; i++) {
        cdb_value_writer_init(&w, docbuf, sizeof docbuf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        cdb_value_begin_object(&w);
        cdb_value_field(&w, f_n);
        cdb_value_write_int(&w, ns[i]);
        cdb_value_end_object(&w);
        TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_doc_insert(&db, store, NULL, 0, docbuf, cdb_value_writer_len(&w), &entry));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    return store;
}

/* ------------------------------------------------------------ value encoders */
static size_t v_int(uint8_t *b, size_t cap, int64_t x)
{
    cdb_value_writer w;
    cdb_value_writer_init(&w, b, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_int(&w, x);
    return cdb_value_writer_len(&w);
}
static size_t v_strn(uint8_t *b, size_t cap, const char *s, size_t n)
{
    cdb_value_writer w;
    cdb_value_writer_init(&w, b, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_string(&w, s, n);
    return cdb_value_writer_len(&w);
}
static size_t v_bin(uint8_t *b, size_t cap, const void *p, size_t n)
{
    cdb_value_writer w;
    cdb_value_writer_init(&w, b, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_binary(&w, p, n);
    return cdb_value_writer_len(&w);
}
static size_t v_null(uint8_t *b, size_t cap)
{
    cdb_value_writer w;
    cdb_value_writer_init(&w, b, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_null(&w);
    return cdb_value_writer_len(&w);
}
static size_t v_f64(uint8_t *b, size_t cap, double d)
{
    cdb_value_writer w;
    cdb_value_writer_init(&w, b, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_f64(&w, d);
    return cdb_value_writer_len(&w);
}
static size_t v_bool(uint8_t *b, size_t cap, int v)
{
    cdb_value_writer w;
    cdb_value_writer_init(&w, b, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_bool(&w, v);
    return cdb_value_writer_len(&w);
}

/* ------------------------------------------------------------ body assembler */
typedef struct body {
    uint8_t b[2048];
    size_t n;
} body;
static void b_reset(body *bo) { bo->n = 0; }
static void b_u8(body *bo, uint8_t v)
{
    TEST_ASSERT_TRUE(bo->n < sizeof bo->b);
    bo->b[bo->n++] = v;
}
static void b_bytes(body *bo, const uint8_t *p, size_t k)
{
    TEST_ASSERT_TRUE(bo->n + k <= sizeof bo->b);
    memcpy(bo->b + bo->n, p, k);
    bo->n += k;
}
static void b_var(body *bo, uint64_t v)
{
    uint8_t e[10];
    size_t k = cdb_varint_encode(v, e);
    b_bytes(bo, e, k);
}
static void b_off(body *bo, int16_t off)
{
    b_u8(bo, (uint8_t)((uint16_t)off >> 8));
    b_u8(bo, (uint8_t)off);
}

/* Build header + body-length varint + body, then execute. */
static cdb_status run_body(cdb_db *d, const body *bo, uint8_t n_regs, uint8_t n_params,
                          uint64_t budget, cdb_value *out)
{
    static uint8_t buf[2300];
    cdb_proc_vm vm;
    uint8_t e[10];
    size_t k, off = 0;
    cdb_value tmp;

    memcpy(buf, CDB_PROC_MAGIC, 4);
    buf[4] = CDB_PROC_VERSION;
    buf[5] = 0x00;
    buf[6] = n_regs;
    buf[7] = n_params;
    off = 8;
    k = cdb_varint_encode((uint64_t)bo->n, e);
    memcpy(buf + off, e, k);
    off += k;
    memcpy(buf + off, bo->b, bo->n);
    off += bo->n;

    cdb_proc_vm_init(&vm, d, CDB_ORDER_LITTLE, NULL, 0, budget);
    return cdb_proc_exec(&vm, buf, off, out ? out : &tmp);
}

/* Execute a raw buffer verbatim (for header-level malformed cases). */
static cdb_status run_raw(const uint8_t *buf, size_t len, cdb_db *d)
{
    cdb_proc_vm vm;
    cdb_value out;
    cdb_proc_vm_init(&vm, d, CDB_ORDER_LITTLE, NULL, 0, 1000);
    return cdb_proc_exec(&vm, buf, len, &out);
}

/* ---- one-shot mutation runner over CALL_MUTATION_EX ---- */
enum { A_INT, A_STR, A_BIN, A_NULL, A_F64, A_F32, A_BOOL };
typedef struct av {
    int kind;
    int64_t i;
    double f;
    const void *p;
    size_t n;
} av;
static av aint(int64_t x) { av a; a.kind = A_INT; a.i = x; a.f = 0; a.p = 0; a.n = 0; return a; }
static av astr(const char *s) { av a; a.kind = A_STR; a.i = 0; a.f = 0; a.p = s; a.n = strlen(s); return a; }
static av abin(const void *p, size_t n) { av a; a.kind = A_BIN; a.i = 0; a.f = 0; a.p = p; a.n = n; return a; }
static av anul(void) { av a; a.kind = A_NULL; a.i = 0; a.f = 0; a.p = 0; a.n = 0; return a; }
static av af64(double d) { av a; a.kind = A_F64; a.i = 0; a.f = d; a.p = 0; a.n = 0; return a; }
static av af32(double d) { av a; a.kind = A_F32; a.i = 0; a.f = d; a.p = 0; a.n = 0; return a; }
static av abool(int b) { av a; a.kind = A_BOOL; a.i = b; a.f = 0; a.p = 0; a.n = 0; return a; }

static void emit_lc(body *bo, uint8_t dst, const uint8_t *val, size_t vlen)
{
    b_u8(bo, CDB_BC_LOAD_CONST);
    b_u8(bo, dst);
    b_var(bo, (uint64_t)vlen);
    b_bytes(bo, val, vlen);
}

/* Load regs 0..argc-1 from specs, CALL_MUTATION_EX into reg argc, RETURN it. */
static cdb_status run_mut(cdb_db *d, uint8_t op, const av *args, int argc, cdb_value *out)
{
    body bo;
    uint8_t tmp[256], aregs[16];
    int i;
    b_reset(&bo);
    for (i = 0; i < argc; i++) {
        size_t vl = 0;
        switch (args[i].kind) {
        case A_INT:  vl = v_int(tmp, sizeof tmp, args[i].i); break;
        case A_STR:  vl = v_strn(tmp, sizeof tmp, (const char *)args[i].p, args[i].n); break;
        case A_BIN:  vl = v_bin(tmp, sizeof tmp, args[i].p, args[i].n); break;
        case A_NULL: vl = v_null(tmp, sizeof tmp); break;
        case A_F64:  vl = v_f64(tmp, sizeof tmp, args[i].f); break;
        case A_F32:  {
            cdb_value_writer fw;
            cdb_value_writer_init(&fw, tmp, sizeof tmp, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
            cdb_value_write_f32(&fw, (float)args[i].f);
            vl = cdb_value_writer_len(&fw);
            break;
        }
        case A_BOOL: vl = v_bool(tmp, sizeof tmp, (int)args[i].i); break;
        default: break;
        }
        emit_lc(&bo, (uint8_t)i, tmp, vl);
        aregs[i] = (uint8_t)i;
    }
    b_u8(&bo, CDB_BC_CALL_MUTATION_EX);
    b_u8(&bo, (uint8_t)argc);        /* dst register = argc */
    b_u8(&bo, op);
    b_u8(&bo, (uint8_t)argc);
    b_bytes(&bo, aregs, (size_t)argc);
    b_u8(&bo, CDB_BC_RETURN);
    b_u8(&bo, (uint8_t)argc);
    return run_body(d, &bo, (uint8_t)(argc + 1), 0, 1000000, out);
}

/* ==========================================================================
 * 1. Writer-driven happy paths (cdb_proc_write_* + opcode success branches)
 * ========================================================================== */

static void test_wr_load_const_return(void)
{
    uint8_t bc[128], lit[16];
    size_t ll = v_int(lit, sizeof lit, 42);
    cdb_proc_writer w;
    cdb_proc_vm vm;
    cdb_value ret;
    cdb_proc_writer_init(&w, bc, sizeof bc, 4, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_load_const(&w, 0, lit, ll));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_return(&w, 0));
    cdb_proc_vm_init(&vm, NULL, CDB_ORDER_LITTLE, NULL, 0, 1000);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_exec(&vm, bc, cdb_proc_writer_len(&w), &ret));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, ret.type);
    TEST_ASSERT_EQUAL_INT64(42, ret.as.i64);
}

static void test_wr_param_move_and_loadparam(void)
{
    uint8_t bc[128];
    cdb_proc_writer w;
    cdb_proc_vm vm;
    cdb_value params[1], ret;
    cdb_eval_make_int(&params[0], 999);

    /* MOVE from preloaded param reg, LOAD_PARAM in-range and out-of-range. */
    cdb_proc_writer_init(&w, bc, sizeof bc, 4, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_move(&w, 1, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_load_param(&w, 2, 0)); /* in range */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_load_param(&w, 3, 9)); /* out -> null */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_return(&w, 2));
    cdb_proc_vm_init(&vm, NULL, CDB_ORDER_LITTLE, params, 1, 1000);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_exec(&vm, bc, cdb_proc_writer_len(&w), &ret));
    TEST_ASSERT_EQUAL_INT64(999, ret.as.i64);
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, vm.regs[3].type);
}

static void test_wr_math_functions(void)
{
    struct { uint16_t fn; int argc; double a0, a1; } cases[] = {
        {CDB_FN_SQRT, 1, 9.0, 0}, {CDB_FN_SIN, 1, 0.0, 0}, {CDB_FN_COS, 1, 0.0, 0},
        {CDB_FN_POW, 2, 2.0, 3.0}, {CDB_FN_SIGMOID, 1, 0.0, 0}, {CDB_FN_RELU, 1, -1.0, 0},
        {CDB_FN_GELU, 1, 0.5, 0},
    };
    size_t c;
    for (c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        uint8_t bc[128], l0[16], l1[16];
        size_t n0, n1;
        cdb_proc_writer w;
        cdb_proc_vm vm;
        cdb_value ret;
        uint8_t args[2] = {0, 1};
        n0 = v_f64(l0, sizeof l0, cases[c].a0);
        n1 = v_f64(l1, sizeof l1, cases[c].a1);
        cdb_proc_writer_init(&w, bc, sizeof bc, 4, 0);
        cdb_proc_write_load_const(&w, 0, l0, n0);
        if (cases[c].argc == 2)
            cdb_proc_write_load_const(&w, 1, l1, n1);
        cdb_proc_write_call_math(&w, 2, cases[c].fn, (uint8_t)cases[c].argc, args);
        cdb_proc_write_return(&w, 2);
        cdb_proc_vm_init(&vm, NULL, CDB_ORDER_LITTLE, NULL, 0, 1000);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_exec(&vm, bc, cdb_proc_writer_len(&w), &ret));
        TEST_ASSERT_EQUAL_INT(CDB_TYPE_F64, ret.type);
    }
}

static void test_wr_math_haversine_and_bearing(void)
{
    uint8_t bc[128], l[16];
    size_t ln = v_f64(l, sizeof l, 1.0);
    cdb_proc_writer w;
    cdb_proc_vm vm;
    cdb_value ret;
    uint8_t args[4] = {0, 0, 0, 0};
    cdb_proc_writer_init(&w, bc, sizeof bc, 4, 0);
    cdb_proc_write_load_const(&w, 0, l, ln);
    cdb_proc_write_call_math(&w, 1, CDB_FN_HAVERSINE, 4, args);
    cdb_proc_write_call_math(&w, 2, CDB_FN_BEARING, 4, args);
    cdb_proc_write_return(&w, 2);
    cdb_proc_vm_init(&vm, NULL, CDB_ORDER_LITTLE, NULL, 0, 1000);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_exec(&vm, bc, cdb_proc_writer_len(&w), &ret));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_F64, ret.type);
}

/* Unknown math fn -> null result (default case), and arity guard rejects short. */
static void test_wr_math_unknown_and_arity(void)
{
    uint8_t bc[128];
    cdb_proc_writer w;
    cdb_proc_vm vm;
    cdb_value ret;
    uint8_t a1[1] = {0};

    cdb_proc_writer_init(&w, bc, sizeof bc, 4, 0);
    cdb_proc_write_call_math(&w, 0, 0xFFFFu, 0, NULL); /* unknown fn, argc 0 */
    cdb_proc_write_return(&w, 0);
    cdb_proc_vm_init(&vm, NULL, CDB_ORDER_LITTLE, NULL, 0, 1000);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_exec(&vm, bc, cdb_proc_writer_len(&w), &ret));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, ret.type);

    cdb_proc_writer_init(&w, bc, sizeof bc, 4, 0);
    cdb_proc_write_call_math(&w, 1, CDB_FN_HAVERSINE, 1, a1); /* needs 4 */
    cdb_proc_write_return(&w, 1);
    cdb_proc_vm_init(&vm, NULL, CDB_ORDER_LITTLE, NULL, 0, 1000);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_proc_exec(&vm, bc, cdb_proc_writer_len(&w), &ret));
}

static void test_wr_jump_if_and_halt(void)
{
    uint8_t bc[128], l[16];
    size_t ln = v_int(l, sizeof l, 5);
    cdb_proc_writer w;
    cdb_proc_vm vm;
    cdb_value ret;
    /* truthy reg: jump_if_false not taken (offset 0), jump_if_true taken (offset 0). */
    cdb_proc_writer_init(&w, bc, sizeof bc, 2, 0);
    cdb_proc_write_load_const(&w, 0, l, ln);
    cdb_proc_write_jump_if_false(&w, 0, 0);
    cdb_proc_write_jump_if_true(&w, 0, 0);
    cdb_proc_write_halt(&w);
    cdb_proc_vm_init(&vm, NULL, CDB_ORDER_LITTLE, NULL, 0, 1000);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_exec(&vm, bc, cdb_proc_writer_len(&w), &ret));
}

static void test_wr_budget_infinite_jump(void)
{
    uint8_t bc[128];
    cdb_proc_writer w;
    cdb_proc_vm vm;
    cdb_value ret;
    cdb_proc_writer_init(&w, bc, sizeof bc, 4, 0);
    cdb_proc_write_jump(&w, -3); /* loops back onto itself */
    cdb_proc_vm_init(&vm, NULL, CDB_ORDER_LITTLE, NULL, 0, 10);
    TEST_ASSERT_EQUAL_INT(CDB_E_OUT_OF_BUDGET, cdb_proc_exec(&vm, bc, cdb_proc_writer_len(&w), &ret));
}

static void test_wr_savepoint_needs_tx(void)
{
    uint8_t bc[128];
    cdb_proc_writer w;
    cdb_proc_vm vm;
    cdb_value ret;
    cdb_proc_writer_init(&w, bc, sizeof bc, 4, 0);
    cdb_proc_write_savepoint(&w, 1);
    cdb_proc_write_return(&w, 0);
    cdb_proc_vm_init(&vm, NULL, CDB_ORDER_LITTLE, NULL, 0, 100);
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_proc_exec(&vm, bc, cdb_proc_writer_len(&w), &ret));
}

/* OPEN_CURSOR + NEXT + CLOSE assembled by the writer on a NULL db (empty). */
static void test_wr_cursor_writer_api(void)
{
    uint8_t qw[64], bc[256];
    cdb_query_writer q;
    cdb_proc_writer pw;
    cdb_proc_vm vm;
    cdb_value ret;
    cdb_query_writer_init(&q, qw, sizeof qw);
    cdb_query_writer_begin(&q);
    cdb_query_write_scan(&q, "items", 5);
    cdb_proc_writer_init(&pw, bc, sizeof bc, 8, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_open_cursor(&pw, 0, qw, cdb_query_writer_len(&q)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_cursor_next(&pw, 1, 2, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_cursor_close(&pw, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_return(&pw, 2));
    cdb_proc_vm_init(&vm, NULL, CDB_ORDER_LITTLE, NULL, 0, 1000);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_exec(&vm, bc, cdb_proc_writer_len(&pw), &ret));
}

/* ==========================================================================
 * 2. Header-level and opcode-level malformed / truncation guards (raw/run_body)
 * ========================================================================== */

static void test_raw_header_errors(void)
{
    uint8_t buf[32];
    /* len < header */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, run_raw((const uint8_t *)"CMBP", 4, NULL));
    /* bad magic */
    memset(buf, 0, sizeof buf);
    memcpy(buf, "XXXX", 4);
    buf[4] = CDB_PROC_VERSION; buf[6] = 4;
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_raw(buf, 16, NULL));
    /* bad version */
    memcpy(buf, CDB_PROC_MAGIC, 4);
    buf[4] = 0x99; buf[6] = 4;
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED, run_raw(buf, 16, NULL));
    /* n_regs == 0 */
    buf[4] = CDB_PROC_VERSION; buf[6] = 0;
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_raw(buf, 16, NULL));
    /* n_regs > max */
    buf[6] = (uint8_t)(CDB_PROC_MAX_REGISTERS + 1);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_raw(buf, 16, NULL));
    /* body-length varint absent (exactly 8 bytes) */
    buf[6] = 4;
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_raw(buf, 8, NULL));
    /* body shorter than declared length */
    memcpy(buf, CDB_PROC_MAGIC, 4);
    buf[4] = CDB_PROC_VERSION; buf[5] = 0; buf[6] = 4; buf[7] = 0;
    buf[8] = 5; /* varint says body len 5, but none follows */
    TEST_ASSERT_EQUAL_INT(CDB_E_TRUNCATED, run_raw(buf, 9, NULL));
}

/* Every variable-length opcode with only its tag byte -> TRUNCATED; the two
 * zero-operand opcodes return OK; an unknown opcode is UNSUPPORTED. */
static void test_raw_opcode_truncations(void)
{
    static const uint8_t trunc_ops[] = {
        CDB_BC_LOAD_CONST, CDB_BC_LOAD_PARAM, CDB_BC_MOVE, CDB_BC_JUMP,
        CDB_BC_JUMP_IF_TRUE, CDB_BC_JUMP_IF_FALSE, CDB_BC_CALL_MATH,
        CDB_BC_CALL_MUTATION, CDB_BC_CALL_MUTATION_EX, CDB_BC_OPEN_CURSOR,
        CDB_BC_CURSOR_NEXT, CDB_BC_CURSOR_CLOSE, CDB_BC_RETURN,
        CDB_BC_SAVEPOINT, CDB_BC_ROLLBACK_TO, CDB_BC_RELEASE_SP,
    };
    size_t i;
    body bo;
    for (i = 0; i < sizeof trunc_ops; i++) {
        cdb_status s;
        b_reset(&bo);
        b_u8(&bo, trunc_ops[i]);
        s = run_body(NULL, &bo, 1, 0, 1000, NULL);
        TEST_ASSERT_TRUE_MESSAGE(s == CDB_E_TRUNCATED || s == CDB_E_MALFORMED, "trunc op");
    }
    /* NOP then end -> OK */
    b_reset(&bo); b_u8(&bo, CDB_BC_NOP);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* HALT -> OK */
    b_reset(&bo); b_u8(&bo, CDB_BC_HALT);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* unknown opcode -> UNSUPPORTED */
    b_reset(&bo); b_u8(&bo, 0x7F);
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* empty program -> OK */
    b_reset(&bo);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(NULL, &bo, 1, 0, 1000, NULL));
}

static void test_raw_load_const_variants(void)
{
    body bo;
    /* dst out of range */
    b_reset(&bo); b_u8(&bo, CDB_BC_LOAD_CONST); b_u8(&bo, 5);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* varint (klen) decode fails at end */
    b_reset(&bo); b_u8(&bo, CDB_BC_LOAD_CONST); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* klen points past the end */
    b_reset(&bo); b_u8(&bo, CDB_BC_LOAD_CONST); b_u8(&bo, 0); b_var(&bo, 5);
    TEST_ASSERT_EQUAL_INT(CDB_E_TRUNCATED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* value bytes present but not a decodable value */
    b_reset(&bo); b_u8(&bo, CDB_BC_LOAD_CONST); b_u8(&bo, 0); b_var(&bo, 1); b_u8(&bo, 0x40);
    TEST_ASSERT_NOT_EQUAL(CDB_OK, run_body(NULL, &bo, 1, 0, 1000, NULL));
}

static void test_raw_reg_bounds(void)
{
    body bo;
    /* LOAD_PARAM dst OOR */
    b_reset(&bo); b_u8(&bo, CDB_BC_LOAD_PARAM); b_u8(&bo, 5); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* MOVE dst OOR / src OOR */
    b_reset(&bo); b_u8(&bo, CDB_BC_MOVE); b_u8(&bo, 5); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    b_reset(&bo); b_u8(&bo, CDB_BC_MOVE); b_u8(&bo, 0); b_u8(&bo, 5);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* RETURN src OOR */
    b_reset(&bo); b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 5);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
}

static void test_raw_math_bounds(void)
{
    body bo;
    /* dst OOR */
    b_reset(&bo); b_u8(&bo, CDB_BC_CALL_MATH); b_u8(&bo, 5); b_u8(&bo, 0); b_u8(&bo, 0); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* argc > 8 */
    b_reset(&bo); b_u8(&bo, CDB_BC_CALL_MATH); b_u8(&bo, 0); b_u8(&bo, 0); b_u8(&bo, 0); b_u8(&bo, 9);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* p + argc > end (declared args absent) */
    b_reset(&bo); b_u8(&bo, CDB_BC_CALL_MATH); b_u8(&bo, 0); b_u8(&bo, 0); b_u8(&bo, 0); b_u8(&bo, 5);
    TEST_ASSERT_EQUAL_INT(CDB_E_TRUNCATED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* arg reg OOR */
    b_reset(&bo); b_u8(&bo, CDB_BC_CALL_MATH); b_u8(&bo, 0); b_u8(&bo, 0); b_u8(&bo, 0); b_u8(&bo, 1); b_u8(&bo, 5);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
}

static void test_raw_mutation_bounds(void)
{
    body bo;
    /* CALL_MUTATION reg OOR (dst) */
    b_reset(&bo); b_u8(&bo, CDB_BC_CALL_MUTATION); b_u8(&bo, 5); b_u8(&bo, 1); b_u8(&bo, 0); b_u8(&bo, 0); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* CALL_MUTATION_EX argc > 16 */
    b_reset(&bo); b_u8(&bo, CDB_BC_CALL_MUTATION_EX); b_u8(&bo, 0); b_u8(&bo, 1); b_u8(&bo, 17);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* CALL_MUTATION_EX p + argc > end */
    b_reset(&bo); b_u8(&bo, CDB_BC_CALL_MUTATION_EX); b_u8(&bo, 0); b_u8(&bo, 1); b_u8(&bo, 3);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* CALL_MUTATION_EX dst OOR */
    b_reset(&bo); b_u8(&bo, CDB_BC_CALL_MUTATION_EX); b_u8(&bo, 5); b_u8(&bo, 1); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* CALL_MUTATION_EX arg reg OOR */
    b_reset(&bo); b_u8(&bo, CDB_BC_CALL_MUTATION_EX); b_u8(&bo, 0); b_u8(&bo, 1); b_u8(&bo, 1); b_u8(&bo, 5);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
}

static void test_raw_cursor_bounds(void)
{
    body bo;
    /* OPEN_CURSOR slot OOR */
    b_reset(&bo); b_u8(&bo, CDB_BC_OPEN_CURSOR); b_u8(&bo, 9);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* OPEN_CURSOR varint (qlen) decode fails */
    b_reset(&bo); b_u8(&bo, CDB_BC_OPEN_CURSOR); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* OPEN_CURSOR qlen past end */
    b_reset(&bo); b_u8(&bo, CDB_BC_OPEN_CURSOR); b_u8(&bo, 0); b_var(&bo, 5);
    TEST_ASSERT_EQUAL_INT(CDB_E_TRUNCATED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* CURSOR_NEXT reg OOR */
    b_reset(&bo); b_u8(&bo, CDB_BC_CURSOR_NEXT); b_u8(&bo, 5); b_u8(&bo, 0); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* CURSOR_NEXT slot OOR */
    b_reset(&bo); b_u8(&bo, CDB_BC_CURSOR_NEXT); b_u8(&bo, 0); b_u8(&bo, 0); b_u8(&bo, 9);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* CURSOR_NEXT on inactive slot -> STATE */
    b_reset(&bo); b_u8(&bo, CDB_BC_CURSOR_NEXT); b_u8(&bo, 0); b_u8(&bo, 0); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_STATE, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* CURSOR_CLOSE slot OOR */
    b_reset(&bo); b_u8(&bo, CDB_BC_CURSOR_CLOSE); b_u8(&bo, 9);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* CURSOR_CLOSE on inactive slot -> no-op OK */
    b_reset(&bo); b_u8(&bo, CDB_BC_CURSOR_CLOSE); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(NULL, &bo, 1, 0, 1000, NULL));
}

/* JUMP out of range (forward and backward), and conditional-jump guards. */
static void test_raw_jump_bounds(void)
{
    body bo;
    /* JUMP far forward -> MALFORMED */
    b_reset(&bo); b_u8(&bo, CDB_BC_JUMP); b_off(&bo, 0x7FFF);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* JUMP far backward -> MALFORMED */
    b_reset(&bo); b_u8(&bo, CDB_BC_JUMP); b_off(&bo, (int16_t)0x8000);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* JUMP_IF_TRUE cond reg OOR */
    b_reset(&bo); b_u8(&bo, CDB_BC_JUMP_IF_TRUE); b_u8(&bo, 5); b_off(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
    /* JUMP_IF_FALSE cond reg OOR */
    b_reset(&bo); b_u8(&bo, CDB_BC_JUMP_IF_FALSE); b_u8(&bo, 5); b_off(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
}

/* Unconditional JUMP forward that lands on a later instruction (bounds OK). */
static void test_raw_jump_forward_ok(void)
{
    body bo;
    cdb_value out;
    /* JUMP +1 skips the HALT, lands on RETURN reg0 (null). */
    b_reset(&bo);
    b_u8(&bo, CDB_BC_JUMP); b_off(&bo, 1);
    b_u8(&bo, CDB_BC_HALT);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(NULL, &bo, 1, 0, 1000, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);
}

/* Conditional jumps taken vs not taken (bounds OK), plus taken-but-OOB. */
static void test_raw_cond_jump_behaviour(void)
{
    body bo;
    cdb_value out;
    uint8_t tv[4], fv[4];
    size_t tl = v_bool(tv, sizeof tv, 1), fl = v_bool(fv, sizeof fv, 0);

    /* JUMP_IF_TRUE taken: cond true, +1 skips HALT -> RETURN cond (true). */
    b_reset(&bo);
    emit_lc(&bo, 0, tv, tl);
    b_u8(&bo, CDB_BC_JUMP_IF_TRUE); b_u8(&bo, 0); b_off(&bo, 1);
    b_u8(&bo, CDB_BC_HALT);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(NULL, &bo, 1, 0, 1000, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_BOOL, out.type);
    TEST_ASSERT_TRUE(out.as.boolean);

    /* JUMP_IF_TRUE not taken: cond false -> falls to HALT (ret null). */
    b_reset(&bo);
    emit_lc(&bo, 0, fv, fl);
    b_u8(&bo, CDB_BC_JUMP_IF_TRUE); b_u8(&bo, 0); b_off(&bo, 1);
    b_u8(&bo, CDB_BC_HALT);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(NULL, &bo, 1, 0, 1000, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);

    /* JUMP_IF_FALSE taken: cond false, +1 skips HALT -> RETURN cond (false). */
    b_reset(&bo);
    emit_lc(&bo, 0, fv, fl);
    b_u8(&bo, CDB_BC_JUMP_IF_FALSE); b_u8(&bo, 0); b_off(&bo, 1);
    b_u8(&bo, CDB_BC_HALT);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(NULL, &bo, 1, 0, 1000, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_BOOL, out.type);
    TEST_ASSERT_FALSE(out.as.boolean);

    /* JUMP_IF_FALSE not taken: cond true -> falls to HALT (ret null). */
    b_reset(&bo);
    emit_lc(&bo, 0, tv, tl);
    b_u8(&bo, CDB_BC_JUMP_IF_FALSE); b_u8(&bo, 0); b_off(&bo, 1);
    b_u8(&bo, CDB_BC_HALT);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(NULL, &bo, 1, 0, 1000, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_NULL, out.type);

    /* JUMP_IF_TRUE taken but target OOB -> MALFORMED. */
    b_reset(&bo);
    emit_lc(&bo, 0, tv, tl);
    b_u8(&bo, CDB_BC_JUMP_IF_TRUE); b_u8(&bo, 0); b_off(&bo, 0x7FFF);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));

    /* JUMP_IF_FALSE taken but target OOB -> MALFORMED. */
    b_reset(&bo);
    emit_lc(&bo, 0, fv, fl);
    b_u8(&bo, CDB_BC_JUMP_IF_FALSE); b_u8(&bo, 0); b_off(&bo, 0x7FFF);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, run_body(NULL, &bo, 1, 0, 1000, NULL));
}

/* ==========================================================================
 * 3. Live document-DB mutation coverage
 * ========================================================================== */

/* DOC_INSERT: wrap a non-object string (ensure_doc_object wrap branch),
 * resolve store by name, with/without a summary; autocommit + commit path. */
static void test_live_doc_insert_wrap(void)
{
    cdb_value out;
    av a2[2], a3[3];
    db_open();
    seed_docs();
    a2[0] = astr("docs"); a2[1] = astr("plain text");
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_mut(&db, CDB_MUT_DOC_INSERT, a2, 2, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, out.type);
    /* argc 3, non-null summary */
    a3[0] = astr("docs"); a3[1] = astr("more"); a3[2] = astr("summary");
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_mut(&db, CDB_MUT_DOC_INSERT, a3, 3, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, out.type);
    /* argc 3, null summary (skips the summary branch) */
    a3[2] = anul();
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_mut(&db, CDB_MUT_DOC_INSERT, a3, 3, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, out.type);
    db_shut();
}

/* DOC_INSERT with an already-encoded object payload (object branch) and the
 * store id resolved as an int (resolve_store_id int branch). */
static void test_live_doc_insert_object_and_int_store(void)
{
    cdb_value out;
    uint64_t store;
    uint8_t obj[64];
    cdb_value_writer w;
    av a2[2];
    db_open();
    store = seed_docs();

    cdb_value_writer_init(&w, obj, sizeof obj, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w);
    cdb_value_field(&w, 1);
    cdb_value_write_string(&w, "hi", 2);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);

    a2[0] = aint((int64_t)store);               /* store by id -> INT branch */
    a2[1] = abin(obj, cdb_value_writer_len(&w)); /* valid encoded object */
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_mut(&db, CDB_MUT_DOC_INSERT, a2, 2, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, out.type);
    db_shut();
}

/* DOC_REPLACE / DOC_PATCH (wrap + encoded-array patch) / DOC_DELETE. */
static void test_live_doc_replace_patch_delete(void)
{
    cdb_value out;
    uint64_t store, entry;
    uint8_t docbuf[64], arr[64];
    cdb_value_writer w;
    av a[4];
    db_open();
    store = seed_docs();

    /* make one row to operate on */
    cdb_value_writer_init(&w, docbuf, sizeof docbuf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_object(&w); cdb_value_field(&w, 1); cdb_value_write_string(&w, "x", 1);
    cdb_value_end_object(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_doc_insert(&db, store, NULL, 0, docbuf, cdb_value_writer_len(&w), &entry));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* REPLACE: store, entry, new doc (wrap), summary */
    a[0] = astr("docs"); a[1] = aint((int64_t)entry); a[2] = astr("replaced"); a[3] = astr("sum");
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_mut(&db, CDB_MUT_DOC_REPLACE, a, 4, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, out.type);

    /* PATCH with a non-array string -> ensure_doc_patch wrap branch */
    a[0] = astr("docs"); a[1] = aint((int64_t)entry); a[2] = astr("patchval");
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_mut(&db, CDB_MUT_DOC_PATCH, a, 3, &out));

    /* PATCH with a real encoded array -> array branch */
    cdb_value_writer_init(&w, arr, sizeof arr, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_begin_array(&w); cdb_value_end_array(&w);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    a[2] = abin(arr, cdb_value_writer_len(&w));
    run_mut(&db, CDB_MUT_DOC_PATCH, a, 3, &out); /* status tolerated */

    /* DELETE existing, then DELETE missing (logical NOT_FOUND captured) */
    a[0] = astr("docs"); a[1] = aint((int64_t)entry);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_mut(&db, CDB_MUT_DOC_DELETE, a, 2, &out));
    a[1] = aint(999999);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_mut(&db, CDB_MUT_DOC_DELETE, a, 2, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, out.type);
    TEST_ASSERT_EQUAL_INT64(CDB_E_NOT_FOUND, out.as.i64);
    db_shut();
}

/* resolve_store_id error branches + argc-too-small guard. */
static void test_live_resolve_errors(void)
{
    cdb_value out;
    av a2[2], a1[1];
    db_open();
    seed_docs();

    /* store arg is NULL (not INT/STRING) -> INVALID_ARG (logical, captured) */
    a2[0] = anul(); a2[1] = astr("doc");
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_mut(&db, CDB_MUT_DOC_INSERT, a2, 2, &out));
    TEST_ASSERT_EQUAL_INT64(CDB_E_INVALID_ARG, out.as.i64);

    /* store name not found -> NOT_FOUND (logical, captured); exercises the
     * auto-begin then auto-abort path in the mutation core. */
    a2[0] = astr("nope"); a2[1] = astr("doc");
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_mut(&db, CDB_MUT_DOC_INSERT, a2, 2, &out));
    TEST_ASSERT_EQUAL_INT64(CDB_E_NOT_FOUND, out.as.i64);

    /* argc below the op minimum -> INVALID_ARG */
    a1[0] = astr("docs");
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_mut(&db, CDB_MUT_DOC_INSERT, a1, 1, &out));
    TEST_ASSERT_EQUAL_INT64(CDB_E_INVALID_ARG, out.as.i64);
    db_shut();
}

/* A mutation executed while a transaction is already open: covers the
 * savepoint-marked path in proc_mutation, and the rollback-on-logical-failure
 * branch (a delete of a missing entry). */
static void test_live_mutation_inside_tx(void)
{
    cdb_value out;
    av a2[2];
    db_open();
    seed_docs();

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    a2[0] = astr("docs"); a2[1] = astr("in-tx");
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_mut(&db, CDB_MUT_DOC_INSERT, a2, 2, &out)); /* no autocommit */
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, out.type);

    a2[0] = astr("docs"); /* reuse */
    {
        av d2[2];
        d2[0] = astr("docs"); d2[1] = aint(777777);
        TEST_ASSERT_EQUAL_INT(CDB_OK, run_mut(&db, CDB_MUT_DOC_DELETE, d2, 2, &out));
        TEST_ASSERT_EQUAL_INT64(CDB_E_NOT_FOUND, out.as.i64); /* rolled back to mark */
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    db_shut();
}

/* CREATE_STORE across every model spelling parse_model_type handles. */
static void test_live_create_store_models(void)
{
    static const char *models[] = {
        "document", "doc", "table", "relational", "vector", "vec",
        "timeseries", "ts", "link", "links", "weird"
    };
    cdb_value out;
    size_t i;
    char name[16];
    av a2[2];
    db_open();
    for (i = 0; i < sizeof models / sizeof models[0]; i++) {
        memcpy(name, "s_", 2);
        name[2] = (char)('a' + (int)i);
        name[3] = '\0';
        a2[0] = astr(name);
        a2[1] = astr(models[i]);
        run_mut(&db, CDB_MUT_CREATE_STORE, a2, 2, &out); /* status tolerated */
    }
    /* model given as an int code */
    a2[0] = astr("s_int"); a2[1] = aint(2);
    run_mut(&db, CDB_MUT_CREATE_STORE, a2, 2, &out);
    db_shut();
}

/* LINK_DEF_TYPE across cardinality spellings + LINK add/reinforce/remove. */
static void test_live_link_ops(void)
{
    static const char *cards[] = {"1:1", "1:n", "n:m", "bogus"};
    cdb_value out;
    size_t i;
    char name[16];
    av a3[3], a5[7];
    db_open();
    for (i = 0; i < sizeof cards / sizeof cards[0]; i++) {
        name[0] = 'L'; name[1] = (char)('0' + (int)i); name[2] = '\0';
        a3[0] = astr(name); a3[1] = astr(cards[i]); a3[2] = aint(0);
        run_mut(&db, CDB_MUT_LINK_DEF_TYPE, a3, 3, &out);
    }
    /* cardinality as int + 4-arg form with inverse */
    {
        av a4[4];
        a4[0] = astr("Lint"); a4[1] = aint(1); a4[2] = aint(1); a4[3] = aint(0);
        run_mut(&db, CDB_MUT_LINK_DEF_TYPE, a4, 4, &out);
    }
    /* link add (7 args incl weight f64 + time), reinforce, remove */
    a5[0] = aint(1); a5[1] = aint(0); a5[2] = aint(1);
    a5[3] = aint(0); a5[4] = aint(2); a5[5] = af64(0.5); a5[6] = aint(123);
    run_mut(&db, CDB_MUT_LINK_ADD, a5, 7, &out);
    run_mut(&db, CDB_MUT_LINK_REINFORCE, a5, 7, &out);
    run_mut(&db, CDB_MUT_LINK_REMOVE, a5, 5, &out);
    db_shut();
}

/* Key / principal / permission mutations (parse_rotate_target, parse_pubkey,
 * reg_to_cstr incl. its NULL branch). Statuses tolerated. */
static void test_live_key_and_security_ops(void)
{
    cdb_value out;
    av a[4];
    db_open();
    seed_docs();

    /* ROTATE_KEY: target "master" string + uri string */
    a[0] = astr("master"); a[1] = aint(0); a[2] = astr("env://X");
    run_mut(&db, CDB_MUT_ROTATE_KEY, a, 3, &out);
    /* target "enclave" + null uri (reg_to_cstr NULL branch) */
    a[0] = astr("enclave"); a[1] = aint(1); a[2] = anul();
    run_mut(&db, CDB_MUT_ROTATE_KEY, a, 3, &out);
    /* target as int + unknown string */
    a[0] = aint(0); a[1] = aint(0); a[2] = astr("env://Y");
    run_mut(&db, CDB_MUT_ROTATE_KEY, a, 3, &out);

    run_mut(&db, CDB_MUT_CHECK_ROTATION, NULL, 0, &out);

    /* CREATE/OPEN_ENCLAVE with a kref string, and with a null kref */
    a[0] = aint(5); a[1] = astr("env://K");
    run_mut(&db, CDB_MUT_CREATE_ENCLAVE, a, 2, &out);
    a[0] = aint(5); a[1] = anul();
    run_mut(&db, CDB_MUT_OPEN_ENCLAVE, a, 2, &out);

    /* REGISTER_PRIN: 66-char hex pubkey (hex branch), then a short one */
    a[0] = aint(1); a[1] = aint(0);
    a[2] = astr("02AbCdEf0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789");
    run_mut(&db, CDB_MUT_REGISTER_PRIN, a, 3, &out);
    a[2] = astr("short");
    run_mut(&db, CDB_MUT_REGISTER_PRIN, a, 3, &out);

    /* GRANT_ROLE (4 args) + CHECK_PERM (3 args) */
    a[0] = aint(1); a[1] = aint(2); a[2] = aint(0); a[3] = aint(1);
    run_mut(&db, CDB_MUT_GRANT_ROLE, a, 4, &out);
    a[0] = aint(1); a[1] = aint(0); a[2] = aint(1);
    run_mut(&db, CDB_MUT_CHECK_PERM, a, 3, &out);
    db_shut();
}

/* Timeseries + table + vector mutation cases (tolerant of UNSUPPORTED). */
static void test_live_ts_table_vec_ops(void)
{
    cdb_value out;
    av a[7];
    db_open();
    seed_docs();

    a[0] = astr("docs"); a[1] = astr("cpu");
    run_mut(&db, CDB_MUT_TS_SERIES, a, 2, &out);
    a[0] = astr("docs"); a[1] = aint(1); a[2] = aint(1000); a[3] = af64(42.5);
    run_mut(&db, CDB_MUT_TS_APPEND, a, 4, &out);          /* numeric value -> encode path */
    a[3] = astr("raw");
    run_mut(&db, CDB_MUT_TS_APPEND, a, 4, &out);          /* string value -> passthrough */
    a[0] = astr("docs"); a[1] = aint(1); a[2] = aint(500);
    run_mut(&db, CDB_MUT_TS_DROP_BEFORE, a, 3, &out);
    run_mut(&db, CDB_MUT_TS_RETENTION, a, 3, &out);
    run_mut(&db, CDB_MUT_TS_APPLY_RET, a, 3, &out);
    a[0] = astr("docs"); a[1] = aint(1); a[2] = astr("docs"); a[3] = aint(2);
    a[4] = aint(60); a[5] = aint(0); a[6] = aint(1000);
    run_mut(&db, CDB_MUT_TS_DOWNSAMPLE, a, 7, &out);

    a[0] = astr("docs"); a[1] = astr("{\"r\":1}");
    run_mut(&db, CDB_MUT_TABLE_INSERT, a, 2, &out);
    a[0] = astr("docs"); a[1] = aint(1); a[2] = astr("{\"r\":2}");
    run_mut(&db, CDB_MUT_TABLE_UPDATE, a, 3, &out);
    a[0] = astr("docs"); a[1] = aint(1);
    run_mut(&db, CDB_MUT_TABLE_DELETE, a, 2, &out);

    a[0] = astr("docs"); a[1] = astr("\x00\x01\x02\x03");
    run_mut(&db, CDB_MUT_VEC_INSERT, a, 2, &out);
    a[0] = astr("docs"); a[1] = aint(0); a[2] = aint(0); a[3] = aint(0);
    run_mut(&db, CDB_MUT_VEC_INSERT, a, 4, &out);         /* with source ref */
    a[0] = astr("docs"); a[1] = aint(1);
    run_mut(&db, CDB_MUT_VEC_DELETE, a, 2, &out);
    db_shut();
}

/* Admin / maintenance mutations, schema, drop store, triggers, blob free,
 * an unknown op (default case), argc guards. Statuses tolerated. */
static void test_live_admin_ops(void)
{
    cdb_value out;
    uint64_t store;
    av a[4];
    db_open();
    store = seed_docs();

    a[0] = astr("docs"); a[1] = astr("{\"type\":\"object\"}");
    run_mut(&db, CDB_MUT_ADD_SCHEMA, a, 2, &out);

    a[0] = aint(5000);
    run_mut(&db, CDB_MUT_COMPACT, a, 1, &out);
    run_mut(&db, CDB_MUT_COMPACT, NULL, 0, &out);     /* argc 0 default max_moves */
    run_mut(&db, CDB_MUT_RECLAIM, NULL, 0, &out);
    run_mut(&db, CDB_MUT_RECONCILE, NULL, 0, &out);

    a[0] = aint(7);
    run_mut(&db, CDB_MUT_SET_PEER, a, 1, &out);
    a[0] = astr("slice-bytes");
    run_mut(&db, CDB_MUT_SYNC_IMPORT, a, 1, &out);

    /* trigger register (store resolved) + unregister */
    a[0] = astr("trg"); a[1] = astr("docs"); a[2] = aint(1); a[3] = astr("proc-src");
    run_mut(&db, CDB_MUT_TRIGGER_REG, a, 4, &out);
    a[0] = astr("trg");
    run_mut(&db, CDB_MUT_TRIGGER_UNREG, a, 1, &out);

    /* blob free: page-count form and ref form (int payload -> not blob-ref) */
    a[0] = astr("docs"); a[1] = aint(2); a[2] = aint(1); a[3] = aint(16);
    run_mut(&db, CDB_MUT_BLOB_FREE, a, 4, &out);

    /* drop a real store */
    a[0] = aint((int64_t)store);
    run_mut(&db, CDB_MUT_DROP_STORE, a, 1, &out);

    /* unknown mutation opcode -> default UNSUPPORTED */
    a[0] = astr("docs"); a[1] = astr("x");
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED, run_mut(&db, 0xEE, a, 2, &out));
    db_shut();
}

/* CALL_MUTATION (the 3-register opcode, distinct from CALL_MUTATION_EX). */
static void test_live_call_mutation_3reg(void)
{
    body bo;
    cdb_value out;
    uint8_t s[16], d[16], su[16];
    size_t sn, dn, sun;
    db_open();
    seed_docs();

    sn = v_strn(s, sizeof s, "docs", 4);
    dn = v_strn(d, sizeof d, "doc3", 4);
    sun = v_strn(su, sizeof su, "sm", 2);

    b_reset(&bo);
    emit_lc(&bo, 0, s, sn);   /* store */
    emit_lc(&bo, 1, d, dn);   /* entry reg -> used as doc by DOC_INSERT args[1] */
    emit_lc(&bo, 2, su, sun); /* payload reg -> summary */
    b_u8(&bo, CDB_BC_CALL_MUTATION);
    b_u8(&bo, 3);                 /* dst */
    b_u8(&bo, CDB_MUT_DOC_INSERT);
    b_u8(&bo, 0); b_u8(&bo, 1); b_u8(&bo, 2);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 3);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(&db, &bo, 4, 0, 1000000, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, out.type);
    db_shut();
}

/* Extra branches: the CALL_MUTATION / CALL_MUTATION_EX writer emitters,
 * reg_get_u64 over non-int registers, parse_pubkey raw-copy branch,
 * reg_to_cstr non-null on OPEN_ENCLAVE, and the TS_APPEND value encoders. */
static void test_cov_boosters(void)
{
    cdb_value out;
    uint8_t bc[128], s[16], d[16], su[16];
    size_t sn, dn, sun;
    cdb_proc_writer w;
    cdb_proc_vm vm;
    av a[4];
    db_open();
    seed_docs();

    sn = v_strn(s, sizeof s, "docs", 4);
    dn = v_strn(d, sizeof d, "wrdoc", 5);
    sun = v_strn(su, sizeof su, "s", 1);

    /* CALL_MUTATION writer emitter (3-register form) */
    cdb_proc_writer_init(&w, bc, sizeof bc, 4, 0);
    cdb_proc_write_load_const(&w, 0, s, sn);
    cdb_proc_write_load_const(&w, 1, d, dn);
    cdb_proc_write_load_const(&w, 2, su, sun);
    TEST_ASSERT_EQUAL_INT(CDB_OK,
        cdb_proc_write_call_mutation(&w, 3, CDB_MUT_DOC_INSERT, 0, 1, 2));
    cdb_proc_write_return(&w, 3);
    cdb_proc_vm_init(&vm, &db, CDB_ORDER_LITTLE, NULL, 0, 1000000);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_exec(&vm, bc, cdb_proc_writer_len(&w), &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, out.type);

    /* CALL_MUTATION_EX writer emitter (variable-arg form) */
    {
        uint8_t args[2] = {0, 1};
        cdb_proc_writer_init(&w, bc, sizeof bc, 4, 0);
        cdb_proc_write_load_const(&w, 0, s, sn);
        cdb_proc_write_load_const(&w, 1, d, dn);
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_proc_write_call_mutation_ex(&w, 2, CDB_MUT_DOC_INSERT, 2, args));
        cdb_proc_write_return(&w, 2);
        cdb_proc_vm_init(&vm, &db, CDB_ORDER_LITTLE, NULL, 0, 1000000);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_exec(&vm, bc, cdb_proc_writer_len(&w), &out));
        TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, out.type);
    }

    /* reg_get_u64 over f64 and bool entry registers (DOC_DELETE) */
    a[0] = astr("docs"); a[1] = af64(123456.0);
    run_mut(&db, CDB_MUT_DOC_DELETE, a, 2, &out);
    a[1] = abool(1);
    run_mut(&db, CDB_MUT_DOC_DELETE, a, 2, &out);

    /* parse_pubkey raw-copy branch: a 40-byte (>=33, !=66) pubkey */
    a[0] = aint(2); a[1] = aint(0);
    a[2] = astr("0123456789012345678901234567890123456789");
    run_mut(&db, CDB_MUT_REGISTER_PRIN, a, 3, &out);

    /* reg_to_cstr non-null branch on OPEN_ENCLAVE */
    a[0] = aint(9); a[1] = astr("env://E");
    run_mut(&db, CDB_MUT_OPEN_ENCLAVE, a, 2, &out);

    /* TS_APPEND value encoders: int, f32, bool, and null */
    a[0] = astr("docs"); a[1] = aint(1); a[2] = aint(10); a[3] = aint(7);
    run_mut(&db, CDB_MUT_TS_APPEND, a, 4, &out);
    a[3] = af32(1.5);
    run_mut(&db, CDB_MUT_TS_APPEND, a, 4, &out);
    a[3] = abool(1);
    run_mut(&db, CDB_MUT_TS_APPEND, a, 4, &out);
    a[3] = anul();
    run_mut(&db, CDB_MUT_TS_APPEND, a, 4, &out);

    /* reg_get_u64 fallthrough: a string entry id -> 0 (DOC_DELETE) */
    a[0] = astr("docs"); a[1] = astr("not-a-number");
    run_mut(&db, CDB_MUT_DOC_DELETE, a, 2, &out);

    /* hex_digit non-hex branch: a 66-char pubkey with non-hex chars */
    a[0] = aint(3); a[1] = aint(0);
    a[2] = astr("zz00000000000000000000000000000000000000000000000000000000000000ab");
    run_mut(&db, CDB_MUT_REGISTER_PRIN, a, 3, &out);

    /* parse_rotate_target: a string that is neither "master" nor "enclave" -> 0 */
    a[0] = astr("bogus"); a[1] = aint(0); a[2] = astr("env://Z");
    run_mut(&db, CDB_MUT_ROTATE_KEY, a, 3, &out);

    /* BLOB_FREE with a genuine BLOB_REF register (as.blob branch) */
    {
        cdb_blob_ref ref;
        uint8_t refbuf[64], store_v[16];
        cdb_value_writer rw;
        body bo;
        size_t rl, svn;
        memset(&ref, 0, sizeof ref);
        cdb_value_writer_init(&rw, refbuf, sizeof refbuf, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
        if (cdb_value_write_blob_ref(&rw, &ref) == CDB_OK && rw.error == CDB_OK) {
            rl = cdb_value_writer_len(&rw);
            svn = v_strn(store_v, sizeof store_v, "docs", 4);
            b_reset(&bo);
            emit_lc(&bo, 0, store_v, svn);
            emit_lc(&bo, 1, refbuf, rl);
            {
                uint8_t args2[2] = {0, 1};
                b_u8(&bo, CDB_BC_CALL_MUTATION_EX);
                b_u8(&bo, 2);
                b_u8(&bo, CDB_MUT_BLOB_FREE);
                b_u8(&bo, 2);
                b_bytes(&bo, args2, 2);
                b_u8(&bo, CDB_BC_RETURN);
                b_u8(&bo, 2);
            }
            run_body(&db, &bo, 3, 0, 1000000, &out); /* status tolerated */
        }
    }
    db_shut();
}

/* ==========================================================================
 * 4. Live cursor execution over a real scan
 * ========================================================================== */

/* Build a bare Scan(store) query wire. */
static size_t scan_wire(uint8_t *buf, size_t cap, const char *store, size_t slen)
{
    cdb_query_writer q;
    cdb_query_writer_init(&q, buf, cap);
    cdb_query_writer_begin(&q);
    cdb_query_write_scan(&q, store, slen);
    return cdb_query_writer_len(&q);
}

/* First row via a scan: OPEN, NEXT (has_row true, entry_id branch), CLOSE. */
static void test_live_cursor_first_row(void)
{
    uint8_t wire[64];
    size_t wl;
    body bo;
    cdb_value out;
    db_open();
    seed_docs();
    wl = scan_wire(wire, sizeof wire, "docs", 4);

    b_reset(&bo);
    b_u8(&bo, CDB_BC_OPEN_CURSOR); b_u8(&bo, 0); b_var(&bo, wl); b_bytes(&bo, wire, wl);
    b_u8(&bo, CDB_BC_CURSOR_NEXT); b_u8(&bo, 0); b_u8(&bo, 1); b_u8(&bo, 0);
    b_u8(&bo, CDB_BC_CURSOR_CLOSE); b_u8(&bo, 0);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(&db, &bo, 2, 0, 1000000, &out));
    /* bare scan rows carry no projected fields -> entry_id (INT) */
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, out.type);
    db_shut();
}

/* Exhaust the scan: third NEXT past two rows -> has_row false, dst null. The
 * cursor is left open so the cleanup path closes it. */
static void test_live_cursor_exhaust_and_cleanup(void)
{
    uint8_t wire[64];
    size_t wl;
    body bo;
    cdb_value out;
    db_open();
    seed_docs();
    wl = scan_wire(wire, sizeof wire, "docs", 4);

    b_reset(&bo);
    b_u8(&bo, CDB_BC_OPEN_CURSOR); b_u8(&bo, 0); b_var(&bo, wl); b_bytes(&bo, wire, wl);
    b_u8(&bo, CDB_BC_CURSOR_NEXT); b_u8(&bo, 0); b_u8(&bo, 1); b_u8(&bo, 0);
    b_u8(&bo, CDB_BC_CURSOR_NEXT); b_u8(&bo, 0); b_u8(&bo, 1); b_u8(&bo, 0);
    b_u8(&bo, CDB_BC_CURSOR_NEXT); b_u8(&bo, 0); b_u8(&bo, 1); b_u8(&bo, 0);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 0); /* has_row of 3rd NEXT = false */
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(&db, &bo, 2, 0, 1000000, &out));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_BOOL, out.type);
    TEST_ASSERT_FALSE(out.as.boolean);
    db_shut();
}

/* Re-open the same slot (active-cursor reopen branch) + open a bad store
 * (cdb_exec_open failure branch). */
static void test_live_cursor_reopen_and_badstore(void)
{
    uint8_t wire[64], bad[64];
    size_t wl, bl;
    body bo;
    cdb_value out;
    db_open();
    seed_docs();
    wl = scan_wire(wire, sizeof wire, "docs", 4);

    b_reset(&bo);
    b_u8(&bo, CDB_BC_OPEN_CURSOR); b_u8(&bo, 0); b_var(&bo, wl); b_bytes(&bo, wire, wl);
    b_u8(&bo, CDB_BC_OPEN_CURSOR); b_u8(&bo, 0); b_var(&bo, wl); b_bytes(&bo, wire, wl); /* reopen */
    b_u8(&bo, CDB_BC_CURSOR_NEXT); b_u8(&bo, 0); b_u8(&bo, 1); b_u8(&bo, 0);
    b_u8(&bo, CDB_BC_CURSOR_CLOSE); b_u8(&bo, 0);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(&db, &bo, 2, 0, 1000000, &out));

    /* Bad store -> cdb_exec_open fails inside OPEN_CURSOR. */
    bl = scan_wire(bad, sizeof bad, "nope", 4);
    b_reset(&bo);
    b_u8(&bo, CDB_BC_OPEN_CURSOR); b_u8(&bo, 0); b_var(&bo, bl); b_bytes(&bo, bad, bl);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 0);
    TEST_ASSERT_NOT_EQUAL(CDB_OK, run_body(&db, &bo, 2, 0, 1000000, &out));
    db_shut();
}

/* Projected scan via the compiler: a row with n_fields > 0 (fields[0].val). */
static void test_live_cursor_projected_field(void)
{
    uint8_t wire[256];
    size_t wl = 0;
    cdb_compile_error err;
    body bo;
    cdb_value out;
    cdb_status cs;
    db_open();
    seed_docs();

    memset(&err, 0, sizeof err);
    cs = cdb_compile_query("SELECT n FROM Scan(\"docs\")", 26, &db.catalog,
                           wire, sizeof wire, &wl, &err);
    if (cs != CDB_OK || wl == 0 || wl > 200) {
        /* projection path unavailable on this build/size; skip cleanly */
        db_shut();
        TEST_IGNORE_MESSAGE("projected scan query unavailable");
        return;
    }
    b_reset(&bo);
    b_u8(&bo, CDB_BC_OPEN_CURSOR); b_u8(&bo, 0); b_var(&bo, wl); b_bytes(&bo, wire, wl);
    b_u8(&bo, CDB_BC_CURSOR_NEXT); b_u8(&bo, 0); b_u8(&bo, 1); b_u8(&bo, 0);
    b_u8(&bo, CDB_BC_CURSOR_CLOSE); b_u8(&bo, 0);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(&db, &bo, 2, 0, 1000000, &out));
    /* projected "n" value is an INT (10 or 20) */
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, out.type);
    db_shut();
}

/* ==========================================================================
 * 5. Live savepoint opcodes (need an open transaction)
 * ========================================================================== */

static void test_live_savepoints(void)
{
    body bo;
    db_open();
    seed_docs();

    /* set new (x2), set existing id (move), release found */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    b_reset(&bo);
    b_u8(&bo, CDB_BC_SAVEPOINT); b_u8(&bo, 1);
    b_u8(&bo, CDB_BC_SAVEPOINT); b_u8(&bo, 2);
    b_u8(&bo, CDB_BC_SAVEPOINT); b_u8(&bo, 1); /* existing -> move */
    b_u8(&bo, CDB_BC_RELEASE_SP); b_u8(&bo, 2);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(&db, &bo, 1, 0, 1000000, NULL));
    cdb_tx_abort(&db);

    /* rollback to a set savepoint */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    b_reset(&bo);
    b_u8(&bo, CDB_BC_SAVEPOINT); b_u8(&bo, 5);
    b_u8(&bo, CDB_BC_ROLLBACK_TO); b_u8(&bo, 5);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_body(&db, &bo, 1, 0, 1000000, NULL));
    cdb_tx_abort(&db);

    /* rollback / release of an unknown id -> NOT_FOUND */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    b_reset(&bo);
    b_u8(&bo, CDB_BC_ROLLBACK_TO); b_u8(&bo, 9);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, run_body(&db, &bo, 1, 0, 1000000, NULL));
    b_reset(&bo);
    b_u8(&bo, CDB_BC_RELEASE_SP); b_u8(&bo, 9);
    b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, run_body(&db, &bo, 1, 0, 1000000, NULL));
    cdb_tx_abort(&db);

    /* overflow the savepoint stack: 9 distinct ids -> OUT_OF_BUDGET on the 9th */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    b_reset(&bo);
    {
        uint8_t id;
        for (id = 0; id < CDB_PROC_MAX_SAVEPOINTS + 1u; id++) {
            b_u8(&bo, CDB_BC_SAVEPOINT); b_u8(&bo, id);
        }
        b_u8(&bo, CDB_BC_RETURN); b_u8(&bo, 0);
    }
    TEST_ASSERT_EQUAL_INT(CDB_E_OUT_OF_BUDGET, run_body(&db, &bo, 1, 0, 1000000, NULL));
    cdb_tx_abort(&db);
    db_shut();
}

/* ==========================================================================
 * 6. Writer error paths
 * ========================================================================== */

static void test_writer_error_paths(void)
{
    uint8_t small[9], tiny[4], big[64];
    cdb_proc_writer w;
    size_t n;

    /* NULL writer: no crash, len 0 */
    cdb_proc_writer_init(NULL, small, sizeof small, 4, 0);
    TEST_ASSERT_EQUAL_size_t(0, cdb_proc_writer_len(NULL));

    /* cap too small for the header -> BUFFER_TOO_SMALL */
    cdb_proc_writer_init(&w, tiny, sizeof tiny, 4, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, w.error);

    /* exactly header+1: the next single-byte write overflows (w_b path),
     * and the error is sticky across later writer calls. */
    cdb_proc_writer_init(&w, small, sizeof small, 4, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, w.error);
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_proc_write_return(&w, 0));
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_proc_write_halt(&w));

    /* w_bytes overflow: a const too large for the buffer */
    {
        uint8_t val[40];
        n = v_strn(val, sizeof val, "0123456789012345678901234567890", 31);
        cdb_proc_writer_init(&w, small, sizeof small, 4, 0);
        TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_proc_write_load_const(&w, 0, val, n));
    }

    /* exercise the remaining writer emitters + finish on a roomy buffer */
    cdb_proc_writer_init(&w, big, sizeof big, 4, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_rollback_to(&w, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_release_sp(&w, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_savepoint(&w, 2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_halt(&w));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_writer_finish(&w));
    TEST_ASSERT_TRUE(cdb_proc_writer_len(&w) > CDB_PROC_HEADER_SIZE);
}

int main(void)
{
    UNITY_BEGIN();
    /* writer-driven */
    RUN_TEST(test_wr_load_const_return);
    RUN_TEST(test_wr_param_move_and_loadparam);
    RUN_TEST(test_wr_math_functions);
    RUN_TEST(test_wr_math_haversine_and_bearing);
    RUN_TEST(test_wr_math_unknown_and_arity);
    RUN_TEST(test_wr_jump_if_and_halt);
    RUN_TEST(test_wr_budget_infinite_jump);
    RUN_TEST(test_wr_savepoint_needs_tx);
    RUN_TEST(test_wr_cursor_writer_api);
    /* raw / hand-assembled guards */
    RUN_TEST(test_raw_header_errors);
    RUN_TEST(test_raw_opcode_truncations);
    RUN_TEST(test_raw_load_const_variants);
    RUN_TEST(test_raw_reg_bounds);
    RUN_TEST(test_raw_math_bounds);
    RUN_TEST(test_raw_mutation_bounds);
    RUN_TEST(test_raw_cursor_bounds);
    RUN_TEST(test_raw_jump_bounds);
    RUN_TEST(test_raw_jump_forward_ok);
    RUN_TEST(test_raw_cond_jump_behaviour);
    /* live mutation */
    RUN_TEST(test_live_doc_insert_wrap);
    RUN_TEST(test_live_doc_insert_object_and_int_store);
    RUN_TEST(test_live_doc_replace_patch_delete);
    RUN_TEST(test_live_resolve_errors);
    RUN_TEST(test_live_mutation_inside_tx);
    RUN_TEST(test_live_create_store_models);
    RUN_TEST(test_live_link_ops);
    RUN_TEST(test_live_key_and_security_ops);
    RUN_TEST(test_live_ts_table_vec_ops);
    RUN_TEST(test_live_admin_ops);
    RUN_TEST(test_live_call_mutation_3reg);
    RUN_TEST(test_cov_boosters);
    /* live cursor */
    RUN_TEST(test_live_cursor_first_row);
    RUN_TEST(test_live_cursor_exhaust_and_cleanup);
    RUN_TEST(test_live_cursor_reopen_and_badstore);
    RUN_TEST(test_live_cursor_projected_field);
    /* live savepoints */
    RUN_TEST(test_live_savepoints);
    /* writer errors */
    RUN_TEST(test_writer_error_paths);
    return UNITY_END();
}
