/* Audit follow-up #56 FR3: CMBQL / bytecode blob create + read opcodes.
 *
 * Red on current main: the ISA has only CDB_MUT_BLOB_FREE and the CMBQL
 * grammar only "free_blob", so there is no way to create or read a blob from
 * the query layer — compiling create_blob/read_blob fails and the opcodes do
 * not exist. Green after the cdb_proc.c + cdb_compiler.c edits: a CMBQL program
 * creates a blob and reads it back through the real cdb_db_blob_* engine, and
 * the opcodes validate their operands and fail closed on malformed input. */
#define _POSIX_C_SOURCE 200809L

#include "unity.h"
#include "cdb_compiler.h"
#include "cdb_db.h"
#include "cdb_faultenv.h"
#include "cdb_proc.h"

#include <string.h>

#define FCAP (512u * 1024u)
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
static uint8_t doc_stage[8192];
static cdb_db_config cfg;
static cdb_db db;

static void init_env(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 4096;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
}

static cdb_header default_header(void)
{
    cdb_header h;
    unsigned i;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    for (i = 0; i < 16; i++)
        h.db_id[i] = (uint8_t)(0x30 + i);
    return h;
}

void setUp(void)
{
    cdb_header h = default_header();
    init_env();
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
    cfg.catalog_work.entries_cap = sizeof cat_entries / sizeof cat_entries[0];
    cfg.catalog_page = cat_page;
    cfg.doc_buffers = doc_bufs;
    cfg.doc_stage = doc_stage;
    cfg.doc_stage_size = sizeof doc_stage;
    cfg.durability = CDB_DURABILITY_FULL;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "test_blob_opcode", &cfg, &h));
}

void tearDown(void)
{
    cdb_db_close(&db);
}

/* Runs a CMBQL program against the test db. The caller owns vm and must keep
 * it alive while reading out_val: a BLOB_READ result is a CDB_TYPE_BINARY value
 * whose bytes live in the VM's own buffer (the same lifetime as cursor rows),
 * so inspecting the result after the VM is destroyed would read freed stack. */
static cdb_status run_script(cdb_proc_vm *vm, const char *script, cdb_value *out_val)
{
    uint8_t bc[4096];
    size_t bc_len = 0;
    cdb_compile_error err;
    cdb_status s;
    memset(&err, 0, sizeof err);
    s = cdb_compile_proc(script, strlen(script), NULL, bc, sizeof bc, &bc_len, &err);
    if (s != CDB_OK)
        return s;
    cdb_proc_vm_init(vm, &db, CDB_ORDER_LITTLE, NULL, 0, 1000000);
    return cdb_proc_exec(vm, bc, bc_len, out_val);
}

/* AC8/AC9: a CMBQL program creates a blob and reads it back, yielding the
 * written content, through the real engine (Flux form). */
static void test_create_then_read_flux(void)
{
    cdb_value ret;
    cdb_proc_vm vm;
    const char *script = "LET $ref = create_blob(store: 1, content: \"blob opcode content!\");\n"
                         "LET $data = read_blob(store: 1, ref: $ref);\n"
                         "RETURN $data;";
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_script(&vm, script, &ret));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_BINARY, ret.type);
    TEST_ASSERT_EQUAL_size_t(strlen("blob opcode content!"), ret.payload_len);
    TEST_ASSERT_EQUAL_MEMORY("blob opcode content!", ret.payload, ret.payload_len);
}

/* Create then free through the query layer: the returned ref is a real,
 * freeable blob reference wired to the engine's free path. */
static void test_create_then_free(void)
{
    cdb_value ret;
    cdb_proc_vm vm;
    const char *script = "LET $ref = create_blob(store: 1, content: \"to be freed\");\n"
                         "LET $st = free_blob(store: 1, page: $ref);\n"
                         "RETURN $st;";
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_script(&vm, script, &ret));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, ret.type);
    TEST_ASSERT_EQUAL_INT64(CDB_OK, ret.as.i64);
}

/* AC10: reading with a non-blob-ref operand fails closed, not out of bounds. */
static void test_read_rejects_bad_ref(void)
{
    cdb_value ret;
    cdb_proc_vm vm;
    /* Passing an integer where a blob ref is required: the opcode must reject
     * it (CDB_E_INVALID_ARG) rather than read unverified/out-of-bounds bytes.
     * The mutation's status is surfaced in the returned value. */
    const char *script = "LET $out = read_blob(store: 1, ref: 12345);\n"
                         "RETURN $out;";
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_script(&vm, script, &ret));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, ret.type);
    TEST_ASSERT_EQUAL_INT64(CDB_E_INVALID_ARG, ret.as.i64);
}

/* An empty blob round-trips through create + read. */
static void test_create_read_empty(void)
{
    cdb_value ret;
    cdb_proc_vm vm;
    const char *script = "LET $ref = create_blob(store: 1, content: \"\");\n"
                         "LET $data = read_blob(store: 1, ref: $ref);\n"
                         "RETURN $data;";
    TEST_ASSERT_EQUAL_INT(CDB_OK, run_script(&vm, script, &ret));
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_BINARY, ret.type);
    TEST_ASSERT_EQUAL_size_t(0, ret.payload_len);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_create_then_read_flux);
    RUN_TEST(test_create_then_free);
    RUN_TEST(test_read_rejects_bad_ref);
    RUN_TEST(test_create_read_empty);
    return UNITY_END();
}
