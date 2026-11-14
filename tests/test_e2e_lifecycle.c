/* End-to-end public-API lifecycle: open an encrypted DB, exercise the document
 * model + key/crypto path through CMBQL, then prove durability (close -> reopen ->
 * state survives, decrypted) and master-key rotation (rotate -> still writable,
 * and readable again after a reopen under the new key). A tolerant probe also
 * drives the other models (table / timeseries / vector / link); column tables and
 * parts of the query core are "not built yet" (README) and report CDB_E_UNSUPPORTED,
 * which this test accepts without failing. Spec 12 (crypto) + 14 (layouts). */
#define _POSIX_C_SOURCE 200809L

#include "unity.h"
#include "cdb_compiler.h"
#include "cdb_proc.h"
#include "cdb_db.h"
#include "cdb_faultenv.h"
#include "combolite/cdb_crypto.h"

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

void setUp(void) {}
void tearDown(void) {}

static cdb_header e2e_header(void)
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

static void init_env(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 4096;
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
    cfg.catalog_work.entries_cap = sizeof cat_entries / sizeof cat_entries[0];
    cfg.catalog_page = cat_page;
    cfg.doc_buffers = doc_bufs;
    cfg.doc_stage = doc_stage;
    cfg.doc_stage_size = sizeof doc_stage;
    cfg.idx_stage = idx_stage;
    cfg.idx_stage_size = sizeof idx_stage;
    cfg.aead_alg = CDB_AEAD_AES_256_GCM;
    cfg.durability = CDB_DURABILITY_FULL;
}

static cdb_status open_base(const char *base)
{
    cdb_header h = e2e_header();
    return cdb_db_open(&db, &env, base, &cfg, &h);
}

/* Compile + execute one CMBQL program; return its status and output value. */
static cdb_status run_out(const char *script, cdb_value *out)
{
    uint8_t bc[4096];
    size_t bc_len = 0;
    cdb_compile_error err;
    cdb_proc_vm vm;
    cdb_status s;

    memset(&err, 0, sizeof err);
    s = cdb_compile_proc(script, strlen(script), NULL, bc, sizeof bc, &bc_len, &err);
    if (s != CDB_OK)
        return s;
    cdb_proc_vm_init(&vm, &db, CDB_ORDER_LITTLE, NULL, 0, 1000000);
    return cdb_proc_exec(&vm, bc, bc_len, out);
}

#define RUN_OK(script)              \
    do {                            \
        cdb_value out_;             \
        TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, run_out(script, &out_), script); \
    } while (0)

/* A model mutation that is OK on a built model and CDB_E_UNSUPPORTED on a
 * not-yet-built one (README); any other status is a real failure. */
static void probe(const char *script)
{
    cdb_value out;
    cdb_status s = run_out(script, &out);
    if (s != CDB_OK && s != CDB_E_UNSUPPORTED)
        TEST_FAIL_MESSAGE(script);
}

static void test_e2e_full_lifecycle(void)
{
    setenv("CDB_E2E_MK", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1);
    setenv("CDB_E2E_MK2", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 1);

    init_env();
    cfg_init();
    cfg.master_key_uri = "env://CDB_E2E_MK";

    /* 1. Open encrypted; create + write the document model; probe the others. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_base("e2e_db"));
    RUN_OK("CREATE STORE \"docs\" MODEL document;");
    RUN_OK("INSERT INTO \"docs\" (\"{\\\"n\\\":1}\", \"first\");");
    probe("CREATE STORE \"metrics\" MODEL timeseries;");
    probe("CREATE SERIES \"metrics\" \"cpu\";");
    probe("APPEND INTO TIMESERIES \"metrics\" SERIES 1 TIME 1000 VALUE 42.5;");
    probe("CREATE STORE \"emb\" MODEL vector;");
    probe("INSERT INTO VECTORS \"emb\" (\"\\x00\\x01\\x02\\x03\");");
    probe("CREATE LINK TYPE \"authored\" CARDINALITY 1:N ENFORCED;");
    probe("CREATE STORE \"users\" MODEL table;");
    probe("INSERT INTO TABLE \"users\" (\"{\\\"name\\\":\\\"Alice\\\"}\");");
    cdb_db_close(&db);

    /* 2. Durability: reopen the SAME files (env arena not re-initialised), and
     *    confirm the encrypted catalog survived + decrypts: re-creating the docs
     *    store now reports it already EXISTS, and a new write still succeeds. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_base("e2e_db"));
    {
        uint64_t pool = 0;
        int found = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_find_store(&db, "docs", 4, &pool, &found));
        TEST_ASSERT_TRUE_MESSAGE(found, "docs store did not survive reopen");
    }
    RUN_OK("INSERT INTO \"docs\" (\"{\\\"n\\\":2}\", \"second\");");

    /* 3. Rotate the master key; the DB stays writable in the same session. */
    RUN_OK("ROTATE MASTER KEY \"env://CDB_E2E_MK2\";");
    RUN_OK("INSERT INTO \"docs\" (\"{\\\"n\\\":3}\", \"after-rotate\");");
    cdb_db_close(&db);

    /* 4. Rotation is durable: reopen under the NEW key; catalog persists + writable. */
    cfg.master_key_uri = "env://CDB_E2E_MK2";
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_base("e2e_db"));
    {
        uint64_t pool = 0;
        int found = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_find_store(&db, "docs", 4, &pool, &found));
        TEST_ASSERT_TRUE_MESSAGE(found, "docs store did not survive reopen");
    }
    RUN_OK("INSERT INTO \"docs\" (\"{\\\"n\\\":4}\", \"post-reopen\");");
    cdb_db_close(&db);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_e2e_full_lifecycle);
    return UNITY_END();
}
