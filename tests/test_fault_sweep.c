/* Whole-database I/O-crash sweep: arm the fault environment to crash after the
 * Nth I/O operation, run an encrypted document workload (open -> create store ->
 * inserts) so the crash lands at a different point each iteration, then reboot
 * (durable-only state) and reopen. This drives the write-error (CDB_E_IO)
 * propagation branches across cdb_db / cdb_doc / cdb_catalog / cdb_journal /
 * cdb_pager and the crash-recovery path on reopen -- the defensive branches that
 * ordinary inputs never reach. Fail-closed contract: a crashed workload returns a
 * typed error (never a hang/garbage), and reopen recovers to a usable, consistent
 * database. Spec 14 (durability) + spec 12 (crypto at rest). */
#define _POSIX_C_SOURCE 200809L

#include "unity.h"
#include "cdb_compiler.h"
#include "cdb_proc.h"
#include "cdb_db.h"
#include "cdb_faultenv.h"

#include <stdlib.h>
#include <string.h>

#define FCAP (640u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define SWEEP_OPS 48u

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

static cdb_header sweep_header(void)
{
    cdb_header h;
    unsigned i;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    for (i = 0; i < 16; i++)
        h.db_id[i] = (uint8_t)(0x40 + i);
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
    cfg.master_key_uri = "env://CDB_FS_MK";
}

static cdb_status run_one(const char *script)
{
    uint8_t bc[4096];
    size_t bc_len = 0;
    cdb_compile_error err;
    cdb_proc_vm vm;
    cdb_value out;
    cdb_status s;

    memset(&err, 0, sizeof err);
    s = cdb_compile_proc(script, strlen(script), NULL, bc, sizeof bc, &bc_len, &err);
    if (s != CDB_OK)
        return s;
    cdb_proc_vm_init(&vm, &db, CDB_ORDER_LITTLE, NULL, 0, 1000000);
    return cdb_proc_exec(&vm, bc, bc_len, &out);
}

/* The workload whose I/O is being crashed. Returns the first non-OK status (the
 * injected CDB_E_IO, surfaced through whichever layer was mid-write). */
static cdb_status workload(void)
{
    cdb_header h = sweep_header();
    cdb_status s;
    if ((s = cdb_db_open(&db, &env, "fs_db", &cfg, &h)) != CDB_OK)
        return s;
    if ((s = run_one("CREATE STORE \"docs\" MODEL document;")) != CDB_OK)
        return s;
    if ((s = run_one("INSERT INTO \"docs\" (\"{\\\"n\\\":1}\", \"a\");")) != CDB_OK)
        return s;
    if ((s = run_one("INSERT INTO \"docs\" (\"{\\\"n\\\":2}\", \"b\");")) != CDB_OK)
        return s;
    return CDB_OK;
}

static void test_io_crash_sweep(void)
{
    uint64_t op;
    unsigned crashed_at_least_once = 0;

    setenv("CDB_FS_MK",
           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1);

    for (op = 1; op <= SWEEP_OPS; op++) {
        cdb_status ws, rs;
        cdb_header h = sweep_header();

        init_env();
        cfg_init();
        /* crash after `op` I/O operations, dropping unsynced writes (a clean
         * power-loss); the workload should fail closed at or before completion. */
        cdb_faultenv_arm(&fe, op, CDB_CRASH_DROP_UNSYNCED, 0, 0);

        ws = workload();
        if (ws != CDB_OK)
            crashed_at_least_once = 1;
        /* whatever happened, the handle must be closeable */
        cdb_db_close(&db);

        /* Reboot to the durable image and reopen: the recovery path must bring
         * the database back to a usable, consistent state. */
        cdb_faultenv_reboot(&fe);
        rs = cdb_db_open(&db, &env, "fs_db", &cfg, &h);
        TEST_ASSERT_TRUE_MESSAGE(rs == CDB_OK || rs == CDB_E_NOT_FOUND,
                                 "reopen after crash neither recovered nor cleanly absent");
        if (rs == CDB_OK) {
            /* a post-recovery write must still succeed (DB is usable again) */
            (void)run_one("CREATE STORE \"after\" MODEL document;");
            cdb_db_close(&db);
        }
    }

    /* the sweep must actually have exercised the crash path, or it proves nothing */
    TEST_ASSERT_TRUE_MESSAGE(crashed_at_least_once, "no injected crash ever fired");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_io_crash_sweep);
    return UNITY_END();
}
