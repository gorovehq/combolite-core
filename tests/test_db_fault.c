/* cdb_db coverage: the open-path argument/config validation branches (each
 * operand of cdb_db_open's guard, and its config-default fill-ins), plus a
 * multi-store crash+reopen recovery sweep that drives the journal-merge / rebase
 * / salts / scrub recovery paths. Spec 14 (durability) + spec 12 (crypto). */
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

static cdb_header hdr(void)
{
    cdb_header h; unsigned i;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    for (i = 0; i < 16; i++) h.db_id[i] = (uint8_t)(0x50 + i);
    return h;
}

static void init_env(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena; c.file_capacity = FCAP;
    c.records = env_records; c.records_per_file = 4096;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
}

static void good_cfg(void)
{
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

/* Each bad config must be rejected with CDB_E_INVALID_ARG (one guard operand each). */
static void test_open_arg_validation(void)
{
    cdb_header h = hdr();
    init_env();
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_open(NULL, &env, "d", &cfg, &h));
    good_cfg();
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_open(&db, NULL, "d", &cfg, &h));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_open(&db, &env, NULL, &cfg, &h));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_open(&db, &env, "d", NULL, &h));
    {
        cdb_db_config b;
        b = cfg; b.apply = NULL; b.doc_buffers = NULL;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_open(&db, &env, "d", &b, &h));
        b = cfg; b.catalog_page = NULL;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_open(&db, &env, "d", &b, &h));
        b = cfg; b.catalog_work.bytes = NULL;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_open(&db, &env, "d", &b, &h));
        b = cfg; b.record_buf = NULL;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_open(&db, &env, "d", &b, &h));
        b = cfg; b.record_buf_size = 1;
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_open(&db, &env, "d", &b, &h));
    }
}

/* Config defaults: durability DEFAULT, normal_sync_every 0, slot_mem NULL are
 * filled in; opening then succeeds (exercises those fill-in branches). */
static void test_open_config_defaults(void)
{
    cdb_header h = hdr();
    init_env();
    good_cfg();
    cfg.durability = CDB_DURABILITY_DEFAULT;
    cfg.normal_sync_every = 0;
    cfg.slot_mem = NULL;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &env, "defdb", &cfg, &h));
    cdb_db_close(&db);
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

/* Multi-store workload crashed at each I/O op, then rebooted + reopened: drives
 * the recovery paths (journal merge, rebase, salts, scrub). */
static void test_crash_recovery_sweep(void)
{
    uint64_t op; unsigned crashed = 0;
    setenv("CDB_DBF_MK",
           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1);
    for (op = 1; op <= 40; op++) {
        cdb_header h = hdr(); cdb_status rs;
        init_env(); good_cfg(); cfg.master_key_uri = "env://CDB_DBF_MK";
        cdb_faultenv_arm(&fe, op, CDB_CRASH_DROP_UNSYNCED, 0, 0);
        if (cdb_db_open(&db, &env, "dbf", &cfg, &h) == CDB_OK) {
            if (run("CREATE STORE \"a\" MODEL document;") != CDB_OK) crashed = 1;
            if (run("CREATE STORE \"b\" MODEL document;") != CDB_OK) crashed = 1;
            if (run("INSERT INTO \"a\" (\"{\\\"n\\\":1}\", \"x\");") != CDB_OK) crashed = 1;
            if (run("INSERT INTO \"b\" (\"{\\\"n\\\":2}\", \"y\");") != CDB_OK) crashed = 1;
            cdb_db_close(&db);
        } else {
            crashed = 1;
        }
        cdb_faultenv_reboot(&fe);
        rs = cdb_db_open(&db, &env, "dbf", &cfg, &h);
        TEST_ASSERT_TRUE_MESSAGE(rs == CDB_OK || rs == CDB_E_NOT_FOUND,
                                 "reopen after crash neither recovered nor cleanly absent");
        if (rs == CDB_OK) {
            (void)run("INSERT INTO \"a\" (\"{\\\"n\\\":3}\", \"z\");");
            cdb_db_close(&db);
        }
    }
    TEST_ASSERT_TRUE_MESSAGE(crashed, "no injected crash ever fired");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_open_arg_validation);
    RUN_TEST(test_open_config_defaults);
    RUN_TEST(test_crash_recovery_sweep);
    return UNITY_END();
}
