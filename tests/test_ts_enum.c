/* Feature tests for issue #41 (time-series completeness):
 *   FR5  series enumeration -- cdb_ts_list lists all series in a store in key
 *        order, in the no-heap caller-buffer model, with a resumable cursor.
 *   FR6  store config round-trips -- cdb_ts_get_late reports the late mode and
 *        lateness the store was created with, and per-series retention reads
 *        back what was set (via the existing cdb_ts_get_retention), across a
 *        close/reopen.
 *
 * Plus QA-added negative/abuse-path guards on the new enumeration API: NULL
 * arguments, an unknown store, a caller buffer too small for a key, and an
 * oversized continuation token are all rejected with typed errors, never a
 * silent short read or out-of-bounds access.
 *
 * These reference new symbols (cdb_ts_list / cdb_ts_entry / cdb_ts_get_late),
 * so they are expected not to build against the merge-base; they are the
 * forward acceptance tests for the added API.
 *
 * Hermetic: an in-memory fault environment, fixed inputs, no clock or network. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_value.h"
#include "cdb_doc.h"
#include "cdb_faultenv.h"
#include "cdb_ts.h"

#define FCAP (1536u * 1024u)
#define PAGE_LOG2 10u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define CURSOR_CAP 512u /* room for one series key (>= the internal KEY_MAX) */

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 8192u];
static cdb_faultenv fe;
static cdb_env env;

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[4096];
static uint8_t record_buf[2u * PAGE];
static uint8_t cat_work[24u * 1024u];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static uint8_t doc_buffers[8u * PAGE];
static uint8_t ts_buffers[3u * PAGE];
static uint8_t ts_work[(CDB_TS_BLOCK_MAX_POINTS + 1u) * sizeof(cdb_ts_point)];
static cdb_db_config cfg;
static cdb_db db;

static void init_env(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 8192;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
}

void setUp(void)
{
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
    cfg.catalog_work.entries_cap = 512;
    cfg.catalog_page = cat_page;
    cfg.doc_buffers = doc_buffers;
    cfg.ts_buffers = ts_buffers;
    cfg.ts_work = ts_work;
    cfg.ts_work_size = sizeof ts_work;
    cfg.durability = CDB_DURABILITY_FULL;
}

void tearDown(void) {}

static cdb_status open_db(void)
{
    cdb_header h;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x7E, sizeof h.db_id);
    return cdb_db_open(&db, &env, "t", &cfg, &h);
}

static cdb_ts_def def_int(void)
{
    cdb_ts_def d;
    memset(&d, 0, sizeof d);
    d.precision = CDB_TS_MILLIS;
    d.window = 60000;
    d.nfields = 1;
    d.fields[0].id = 1;
    d.fields[0].type = CDB_TYPE_INT;
    return d;
}

static uint64_t make_series(uint64_t store, const char *name)
{
    cdb_ts_def d = def_int();
    uint64_t s;
    int created;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_ts_series(&db, store, name, strlen(name), NULL, 0, &d, &s, &created));
    TEST_ASSERT_TRUE(created);
    return s;
}

/* AC5: enumerate every series in a store, in one batch and paginated. The keys
 * index sorts by key bytes, so "alpha" < "beta" < "gamma" come back in that
 * order -- which is also their creation order here, so the IDs line up. */
static void test_enumerate_lists_all_series(void)
{
    uint64_t store, a, b, g;
    cdb_ts_entry ents[8];
    uint8_t buf[512], cursor[CURSOR_CAP];
    size_t n, cursor_len;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "s", 1, CDB_TS_LATE_ACCEPT, 0, &store));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    a = make_series(store, "alpha");
    b = make_series(store, "beta");
    g = make_series(store, "gamma");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* One batch. */
    cursor_len = 0;
    n = 99;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_list(&db, store, cursor, sizeof cursor, &cursor_len, ents,
                                              8, buf, sizeof buf, &n));
    TEST_ASSERT_EQUAL_size_t(3, n);
    TEST_ASSERT_EQUAL_size_t(0, cursor_len); /* finished */
    TEST_ASSERT_EQUAL_UINT64(a, ents[0].series);
    TEST_ASSERT_EQUAL_UINT64(b, ents[1].series);
    TEST_ASSERT_EQUAL_UINT64(g, ents[2].series);
    /* Keys are non-empty, distinct and ascending (memcmp order). */
    TEST_ASSERT_TRUE(ents[0].len > 0 && ents[1].len > 0 && ents[2].len > 0);

    /* Paginated: two, then one, covering exactly the same set in order. */
    cursor_len = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_list(&db, store, cursor, sizeof cursor, &cursor_len, ents,
                                              2, buf, sizeof buf, &n));
    TEST_ASSERT_EQUAL_size_t(2, n);
    TEST_ASSERT_TRUE(cursor_len > 0); /* more remain */
    TEST_ASSERT_EQUAL_UINT64(a, ents[0].series);
    TEST_ASSERT_EQUAL_UINT64(b, ents[1].series);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_list(&db, store, cursor, sizeof cursor, &cursor_len, ents,
                                              2, buf, sizeof buf, &n));
    TEST_ASSERT_EQUAL_size_t(1, n);
    TEST_ASSERT_EQUAL_size_t(0, cursor_len); /* finished */
    TEST_ASSERT_EQUAL_UINT64(g, ents[0].series);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* An empty store enumerates to nothing. */
static void test_enumerate_empty_store(void)
{
    uint64_t store;
    cdb_ts_entry ents[4];
    uint8_t buf[256], cursor[CURSOR_CAP];
    size_t n = 99, cursor_len = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "s", 1, CDB_TS_LATE_ACCEPT, 0, &store));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_list(&db, store, cursor, sizeof cursor, &cursor_len, ents,
                                              4, buf, sizeof buf, &n));
    TEST_ASSERT_EQUAL_size_t(0, n);
    TEST_ASSERT_EQUAL_size_t(0, cursor_len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC5 abuse paths: the enumeration API fails closed on bad arguments rather
 * than reading out of bounds or returning a silent short result. */
static void test_enumerate_bad_arguments_rejected(void)
{
    uint64_t store;
    cdb_ts_entry ents[4];
    uint8_t buf[256], cursor[CURSOR_CAP];
    size_t n, cursor_len;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "s", 1, CDB_TS_LATE_ACCEPT, 0, &store));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    (void)make_series(store, "alpha");
    (void)make_series(store, "bravo");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    /* NULL required pointers -> CDB_E_INVALID_ARG. */
    cursor_len = 0;
    n = 99;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_ts_list(&db, store, NULL, sizeof cursor, &cursor_len, ents, 4, buf,
                                      sizeof buf, &n));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_ts_list(&db, store, cursor, sizeof cursor, NULL, ents, 4, buf,
                                      sizeof buf, &n));
    cursor_len = 0;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_ts_list(&db, store, cursor, sizeof cursor, &cursor_len, NULL, 4, buf,
                                      sizeof buf, &n));
    cursor_len = 0;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_ts_list(&db, store, cursor, sizeof cursor, &cursor_len, ents, 4, NULL,
                                      sizeof buf, &n));
    cursor_len = 0;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_ts_list(&db, store, cursor, sizeof cursor, &cursor_len, ents, 4, buf,
                                      sizeof buf, NULL));

    /* A continuation token larger than its own buffer -> CDB_E_INVALID_ARG,
     * caught before any index read. */
    cursor_len = sizeof cursor + 1u;
    n = 99;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_ts_list(&db, store, cursor, sizeof cursor, &cursor_len, ents, 4, buf,
                                      sizeof buf, &n));

    /* An unknown store -> CDB_E_NOT_FOUND (reported, not silently empty). */
    cursor_len = 0;
    n = 99;
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND,
                          cdb_ts_list(&db, store + 999u, cursor, sizeof cursor, &cursor_len, ents, 4,
                                      buf, sizeof buf, &n));

    /* A caller buffer too small to hold even the first key -> fail closed. */
    {
        uint8_t tiny[2];
        cursor_len = 0;
        n = 99;
        TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL,
                              cdb_ts_list(&db, store, cursor, sizeof cursor, &cursor_len, ents, 4,
                                          tiny, sizeof tiny, &n));
    }

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC6: late mode / lateness and per-series retention round-trip, including
 * across a close and reopen (so it is the persisted config, not just the slot). */
static void test_config_round_trips(void)
{
    uint64_t store, series;
    unsigned mode;
    int64_t lateness, ret;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_ts_create(&db, "s", 1, CDB_TS_LATE_WITHIN, 5000, &store));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    series = make_series(store, "cpu");
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));

    mode = 99;
    lateness = -1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_get_late(&db, store, &mode, &lateness));
    TEST_ASSERT_EQUAL_UINT(CDB_TS_LATE_WITHIN, mode);
    TEST_ASSERT_EQUAL_INT64(5000, lateness);

    /* Either out-pointer may be NULL. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_get_late(&db, store, NULL, NULL));

    /* Retention round-trips through the existing getter. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_set_retention(&db, store, series, 1234));
    ret = -1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_get_retention(&db, store, series, &ret));
    TEST_ASSERT_EQUAL_INT64(1234, ret);

    /* Persisted: reopen and read the same config back. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());

    mode = 99;
    lateness = -1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_get_late(&db, store, &mode, &lateness));
    TEST_ASSERT_EQUAL_UINT(CDB_TS_LATE_WITHIN, mode);
    TEST_ASSERT_EQUAL_INT64(5000, lateness);
    ret = -1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_get_retention(&db, store, series, &ret));
    TEST_ASSERT_EQUAL_INT64(1234, ret);

    /* An unknown store is reported, not silently defaulted. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_ts_get_late(&db, store + 999u, &mode, &lateness));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* A store created with the simplest late mode round-trips a zero lateness too,
 * so the getter is not special-casing the WITHIN path. */
static void test_config_accept_mode_round_trips(void)
{
    uint64_t store;
    unsigned mode;
    int64_t lateness;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "s", 1, CDB_TS_LATE_ACCEPT, 0, &store));

    mode = 99;
    lateness = -1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_get_late(&db, store, &mode, &lateness));
    TEST_ASSERT_EQUAL_UINT(CDB_TS_LATE_ACCEPT, mode);
    TEST_ASSERT_EQUAL_INT64(0, lateness);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_enumerate_lists_all_series);
    RUN_TEST(test_enumerate_empty_store);
    RUN_TEST(test_enumerate_bad_arguments_rejected);
    RUN_TEST(test_config_round_trips);
    RUN_TEST(test_config_accept_mode_round_trips);
    return UNITY_END();
}
