/* Coverage set for cdb_eval: the expression-evaluator branches test_eval_expr /
 * test_eval_edge miss — string concatenation, float arithmetic, int/float
 * divide-and-modulo by zero (null result), float MOD, mixed int/float compare,
 * LIKE/CONTAINS on non-string operands, unary NEG on a float, null propagation
 * through a missing field, and the math CALL functions (incl. null-arg short
 * circuit). Driven through the public query path. Spec 17 (query/eval). */
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
    TEST_ASSERT_EQUAL_INT(CDB_OK, run("INSERT INTO \"docs\" (\"{\\\"id\\\":1,\\\"price\\\":3.5,\\\"qty\\\":4,\\\"name\\\":\\\"Alpha\\\"}\", \"k1\");"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, run("INSERT INTO \"docs\" (\"{\\\"id\\\":2,\\\"price\\\":0.0,\\\"qty\\\":0,\\\"name\\\":\\\"Beta\\\"}\", \"k2\");"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, run("INSERT INTO \"docs\" (\"{\\\"id\\\":3,\\\"price\\\":10.25,\\\"qty\\\":3,\\\"name\\\":\\\"Alps\\\"}\", \"k3\");"));
}

static void test_eval_coverage(void)
{
    cdb_header h = hdr();
    cfg_init();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "ec", &cfg, &h));
    seed();

    /* string concatenation (ADD on two strings) */
    DOK("SELECT name + name FROM Scan(\"docs\")");
    DOK("SELECT name + \"!\" FROM Scan(\"docs\") WHERE id = 1");
    /* float arithmetic (f64 add/sub/mul/div paths) + mixed int/float */
    DOK("SELECT price * 2.0 FROM Scan(\"docs\")");
    DOK("SELECT price - 1 FROM Scan(\"docs\")");
    DOK("SELECT price + qty FROM Scan(\"docs\")");
    DOK("SELECT id FROM Scan(\"docs\") WHERE price > 1.0");
    DOK("SELECT id FROM Scan(\"docs\") WHERE price = 10.25");
    /* mixed int/float comparison (compare coercion) */
    DOK("SELECT id FROM Scan(\"docs\") WHERE qty = 4.0");
    DOK("SELECT id FROM Scan(\"docs\") WHERE id < 2.5");
    /* divide / modulo by zero -> NULL (int and float) */
    DOK("SELECT qty / 0 FROM Scan(\"docs\")");
    DOK("SELECT qty % 0 FROM Scan(\"docs\")");
    DOK("SELECT price / 0.0 FROM Scan(\"docs\")");
    /* float MOD -> NULL branch */
    DOK("SELECT price % 2.0 FROM Scan(\"docs\")");
    /* non-zero int div/mod (the happy counterpart) */
    DOK("SELECT qty / 2 FROM Scan(\"docs\") WHERE qty > 0");
    DOK("SELECT qty % 2 FROM Scan(\"docs\") WHERE qty > 0");
    /* LIKE / CONTAINS on a non-string operand -> false branch */
    DOK("SELECT id FROM Scan(\"docs\") WHERE id LIKE \"1\"");
    DOK("SELECT id FROM Scan(\"docs\") WHERE qty CONTAINS \"4\"");
    /* unary NEG on a float, NOT, and IS [NOT] NULL */
    DOK("SELECT -price FROM Scan(\"docs\")");
    DOK("SELECT id FROM Scan(\"docs\") WHERE NOT (id = 1)");
    DOK("SELECT id FROM Scan(\"docs\") WHERE name IS NOT NULL");
    DOK("SELECT id FROM Scan(\"docs\") WHERE price IS NULL");
    /* null propagation through a missing field (arith on NULL -> NULL -> no match) */
    DOK("SELECT id FROM Scan(\"docs\") WHERE missing + 1 = 2");
    DOK("SELECT missing FROM Scan(\"docs\")");
    /* math CALL functions + null-arg short-circuit */
    DOK("SELECT abs(price) FROM Scan(\"docs\")");
    DOK("SELECT sqrt(price) FROM Scan(\"docs\") WHERE price > 0.0");
    DOK("SELECT round(price) FROM Scan(\"docs\")");
    DOK("SELECT abs(missing) FROM Scan(\"docs\")");
    /* nested boolean with nulls (short-circuit AND/OR over null operands) */
    DOK("SELECT id FROM Scan(\"docs\") WHERE missing = 1 OR id = 2");
    DOK("SELECT id FROM Scan(\"docs\") WHERE price > 0.0 AND missing IS NULL");

    /* cdb_eval_compare paths: bool-vs-bool, incompatible-type fallback */
    DOK("SELECT id FROM Scan(\"docs\") WHERE (id = 1) = (price > 0.0)");  /* bool vs bool */
    DOK("SELECT id FROM Scan(\"docs\") WHERE name = id");                 /* string vs int -> type-tag order */
    DOK("SELECT id FROM Scan(\"docs\") WHERE name < id");
    /* str_like wildcards: '_' single-char and '%' in the middle */
    DOK("SELECT id FROM Scan(\"docs\") WHERE name LIKE \"Al__\"");
    DOK("SELECT id FROM Scan(\"docs\") WHERE name LIKE \"A%a\"");
    /* str_contains empty substring -> always true */
    DOK("SELECT id FROM Scan(\"docs\") WHERE name CONTAINS \"\"");

    cdb_db_close(&db);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_eval_coverage);
    return UNITY_END();
}
