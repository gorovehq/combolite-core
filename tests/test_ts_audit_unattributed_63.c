/* #63 Item 1: creating a time-series series is a schema event, but the ts
 * engine emitted no dedicated CDB_AUDIT_SCHEMA at the series-create site
 * (ts_series_in). The fix mirrors the #37 governance and #54 F2 "emit
 * unattributed" shape: fire the event whenever the audit log is persistable
 * (has_catalog), attributed to the active principal, or with principal 0 when
 * no identity is registered -- never silently drop it (gating on has_identity
 * would fail open, reopening the OWASP A09 gap).
 *
 *   AC1/AC3 a series create under an active identity emits exactly one SCHEMA
 *           event for that (store, series) carrying the real principal id
 *   AC1     the same create with NO identity still emits one SCHEMA for that
 *           (store, series), unattributed (principal 0)
 *
 * Red->green: before the source fix ts_series_in emitted nothing, so the query
 * finds zero SCHEMA events for the new series; after it, exactly one.
 * Deterministic and hermetic (one fault environment, no clock/network/threads). */
#define _POSIX_C_SOURCE 200809L

#include <string.h>

#include "unity.h"
#include "cdb_audit.h"
#include "cdb_db.h"
#include "cdb_faultenv.h"
#include "cdb_ts.h"
#include "combolite/cdb_crypto.h"
#include "combolite/cdb_value.h"

#define FCAP (1024u * 1024u)
#define PAGE_LOG2 10u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u

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
static cdb_identity id;

void setUp(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 8192;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_generate_env(&env, &id, 7, 1));

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
    cfg.signing_policy = CDB_SIGN_AUDIT_ONLY;
    cfg.identity = &id; /* a test may set this to NULL before opening */
}

void tearDown(void)
{
    (void)cdb_db_close(&db);
}

static cdb_status open_db(void)
{
    cdb_header h;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x7E, sizeof h.db_id);
    return cdb_db_open(&db, &env, "t_ts_audit", &cfg, &h);
}

static cdb_ts_def def1(void)
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

/* Counts SCHEMA audit events for exactly this (store, series) and returns the
 * principal of the first match. The chain must verify (unsigned events from a
 * no-identity run must still verify -- principal 0 is not special-cased). */
static size_t count_series_schema(uint64_t store, uint64_t series, uint32_t *first_principal)
{
    cdb_audit_event ev[32];
    uint8_t pbuf[2048];
    size_t count = 0, i, n = 0;
    int valid = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_audit_verify(&db, INT64_MIN, INT64_MAX, &valid));
    TEST_ASSERT_EQUAL_INT(1, valid);
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_audit_query(&db, INT64_MIN, INT64_MAX, pbuf, sizeof pbuf, ev, 32, &count));
    for (i = 0; i < count; i++)
        if (ev[i].event_type == CDB_AUDIT_SCHEMA && ev[i].store_id == store
            && ev[i].entity_id == series) {
            if (n == 0 && first_principal != NULL)
                *first_principal = ev[i].principal_id;
            n++;
        }
    return n;
}

/* Creates a store and one series in it, returning both. */
static void make_series(uint64_t *store, uint64_t *series)
{
    cdb_ts_def d = def1();
    int created = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_ts_create(&db, "m", 1, CDB_TS_LATE_ACCEPT, 0, store));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_ts_series(&db, *store, "cpu", 3, NULL, 0, &d, series, &created));
    TEST_ASSERT_TRUE(created);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
}

/* AC1/AC3: with an active identity the series create emits exactly one SCHEMA
 * event for the new series, attributed to the real principal (7). Red pre-fix:
 * no SCHEMA is emitted for the series, so the count is 0. */
static void test_series_create_schema_attributed(void)
{
    uint64_t store = 0, series = 0;
    uint32_t principal = 0xFFFFFFFFu;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    make_series(&store, &series);
    TEST_ASSERT_EQUAL_size_t(1, count_series_schema(store, series, &principal));
    TEST_ASSERT_EQUAL_UINT32(7, principal);
}

/* AC1: the same create with NO identity still emits one SCHEMA for the series,
 * unattributed (principal 0) -- never gated on has_identity. Red pre-fix: 0. */
static void test_series_create_schema_unattributed(void)
{
    uint64_t store = 0, series = 0;
    uint32_t principal = 0xFFFFFFFFu;
    cfg.identity = NULL; /* no registered principal */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    make_series(&store, &series);
    TEST_ASSERT_EQUAL_size_t(1, count_series_schema(store, series, &principal));
    TEST_ASSERT_EQUAL_UINT32(0, principal); /* unattributed, not dropped */
}

/* A lookup that does not create (NULL def, missing series) emits no SCHEMA: the
 * emit is bound to an actual create (*created == 1), not every series call. */
static void test_lookup_only_emits_no_schema(void)
{
    uint64_t store = 0, series = 0, probe = 0;
    int created = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db());
    make_series(&store, &series);
    /* A pure lookup of a different, non-existent series. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND,
                          cdb_ts_series(&db, store, "gpu", 3, NULL, 0, NULL, &probe, &created));
    /* Still exactly one SCHEMA, for the one real create. */
    TEST_ASSERT_EQUAL_size_t(1, count_series_schema(store, series, NULL));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_series_create_schema_attributed);
    RUN_TEST(test_series_create_schema_unattributed);
    RUN_TEST(test_lookup_only_emits_no_schema);
    return UNITY_END();
}
