/* Drives cdb_eval's expression-evaluation paths (arithmetic, string match,
 * range, null-test, nested boolean) by draining SELECTs whose WHERE/projection
 * contain real expressions over seeded documents. Complements test_eval_edge
 * (direct value API) and test_query_matrix (operators). Spec 17 (query/eval). */
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
    TEST_ASSERT_EQUAL_INT(CDB_OK, run("INSERT INTO \"docs\" (\"{\\\"id\\\":1,\\\"year\\\":1990,\\\"rank\\\":3,\\\"title\\\":\\\"Alpha\\\"}\", \"k1\");"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, run("INSERT INTO \"docs\" (\"{\\\"id\\\":2,\\\"year\\\":2000,\\\"rank\\\":1,\\\"title\\\":\\\"Beta\\\"}\", \"k2\");"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, run("INSERT INTO \"docs\" (\"{\\\"id\\\":3,\\\"year\\\":2010,\\\"rank\\\":2,\\\"title\\\":\\\"Alps\\\"}\", \"k3\");"));
}

static void test_eval_expressions(void)
{
    cdb_header h = hdr();
    cfg_init();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "ee", &cfg, &h));
    seed();

    /* arithmetic in predicate + projection (eval add/sub/mul paths) */
    DOK("SELECT id FROM Scan(\"docs\") WHERE id + 1 = 2");
    DOK("SELECT id FROM Scan(\"docs\") WHERE year - 1990 > 0");
    DOK("SELECT id FROM Scan(\"docs\") WHERE id * 2 = 4");
    DOK("SELECT year - 1990 FROM Scan(\"docs\")");
    /* string match (eval LIKE/CONTAINS paths) */
    DOK("SELECT id FROM Scan(\"docs\") WHERE title LIKE \"Al%\"");
    DOK("SELECT id FROM Scan(\"docs\") WHERE title CONTAINS \"et\"");
    /* range + null-test + nested boolean (eval range/null/short-circuit) */
    DOK("SELECT id FROM Scan(\"docs\") WHERE id BETWEEN 1 AND 3");
    DOK("SELECT id FROM Scan(\"docs\") WHERE title IS NULL");
    DOK("SELECT id FROM Scan(\"docs\") WHERE id = 1 AND year > 1990 OR rank = 2");
    DOK("SELECT id FROM Scan(\"docs\") WHERE rank <= 2 AND title LIKE \"Al%\"");

    cdb_db_close(&db);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_eval_expressions);
    return UNITY_END();
}
