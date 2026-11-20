#define _POSIX_C_SOURCE 200809L
/* Coverage set for cdb_overflow: the spill/reclaim/corruption branches the
 * tail-nibblet suite misses. Drives cdb_overflow.h over a faultenv-backed
 * pager with crafted on-disk corruption (wrong page type/flag/store/
 * payload-length/link) and both address widths. Every corrupt or mislinked
 * page is asserted to reject with CDB_E_CORRUPT -- fail-closed, never a silent
 * partial read -- and the tail-nibblet relocation (cdb_overflow_nib_moved) is
 * exercised across all owner kinds. Hermetic: static arenas, no network.
 * Spec 14.15, 16.5. */
#include <stdio.h>
#include <string.h>

#include "unity.h"
#include "cdb_db.h"
#include "cdb_endian.h"
#include "cdb_faultenv.h"
#include "cdb_nib.h"
#include "cdb_overflow.h"
#include "cdb_page.h"

#define FCAP (2048u * 1024u)
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
static uint8_t doc_stage[64u * 1024u];
static uint8_t fts_buffers[DBUF + 2u * PAGE];
static cdb_fts_token fts_tokens[2u * (DOC_MAX + PAGE)];
static cdb_db_config cfg;
static cdb_db db;

static uint8_t data[8u * PAGE];
static uint8_t outbuf[8u * PAGE];
static uint8_t scratch[2u * PAGE];
static uint8_t pagebuf[2u * PAGE];
static uint8_t saved[2u * PAGE];

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
    size_t i;
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
    cfg.doc_max = DOC_MAX;
    cfg.doc_stage = doc_stage;
    cfg.doc_stage_size = sizeof doc_stage;
    cfg.fts_buffers = fts_buffers;
    cfg.fts_tokens = fts_tokens;
    cfg.fts_tokens_cap = sizeof fts_tokens / sizeof fts_tokens[0];
    cfg.durability = CDB_DURABILITY_FULL;

    for (i = 0; i < sizeof data; i++)
        data[i] = (uint8_t)(0x21u + (i % 97u));
}

void tearDown(void)
{
    (void)cdb_db_close(&db);
}

static cdb_status open_db(uint8_t layout_flags, const char *base)
{
    cdb_header h;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = layout_flags;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    memset(h.db_id, 0x55, sizeof h.db_id);
    return cdb_db_open(&db, &env, base, &cfg, &h);
}

/* ------------------------------------------------------------ happy path */

static void test_overflow_roundtrip(void)
{
    cdb_pager *p = &db.pager;
    size_t room, len;
    uint64_t first = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(CDB_LAYOUT_ADDR64, "ovf_rt"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));

    room = cdb_overflow_room(p);
    TEST_ASSERT_TRUE(room > 0);
    len = 2u * room + 7u; /* three pages: full, full, 7-byte tail */
    TEST_ASSERT_EQUAL_UINT64(3u, cdb_overflow_pages(p, len));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_overflow_write(p, 5, data, len, scratch, &first));
    TEST_ASSERT_TRUE(first != 0);

    memset(outbuf, 0, len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_overflow_read(p, first, 5, outbuf, len, pagebuf));
    TEST_ASSERT_EQUAL_MEMORY(data, outbuf, len);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_overflow_free(p, first, 5, len, pagebuf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
}

static void test_overflow_addr32(void)
{
    cdb_pager *p = &db.pager;
    size_t room, len;
    uint64_t first = 0;

    /* layout_flags = 0 selects 32-bit addresses: exercises the 4-byte
     * store_lid / load_lid paths. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(0u, "ovf_32"));
    TEST_ASSERT_EQUAL_UINT(4u, p->addr_width);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));

    room = cdb_overflow_room(p);
    len = room + 20u; /* two pages */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_overflow_write(p, 9, data, len, scratch, &first));

    memset(outbuf, 0, len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_overflow_read(p, first, 9, outbuf, len, pagebuf));
    TEST_ASSERT_EQUAL_MEMORY(data, outbuf, len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
}

/* ------------------------------------------------------------ corruption */

static void test_overflow_corruption(void)
{
    cdb_pager *p = &db.pager;
    size_t room, len, off, plen;
    uint64_t first = 0;
    cdb_page_header h0, h;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(CDB_LAYOUT_ADDR64, "ovf_corrupt"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));

    room = cdb_overflow_room(p);
    len = room + 50u; /* two pages: page0 full (non-last), page1 50-byte tail */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_overflow_write(p, 5, data, len, scratch, &first));

    off = cdb_page_payload_offset(p->fmt);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(p, first, pagebuf, &h0));
    memcpy(saved, pagebuf, p->page_size);
    plen = h0.payload_len;

    /* A: wrong store id. */
    h = h0;
    h.store_id = 777u;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_write(p, first, &h, pagebuf + off, plen));
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_read(p, first, 5, outbuf, len, pagebuf));

    /* B: wrong page type. */
    memcpy(pagebuf, saved, p->page_size);
    h = h0;
    h.type = CDB_PAGE_TYPE_DOCUMENT;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_write(p, first, &h, pagebuf + off, plen));
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_read(p, first, 5, outbuf, len, pagebuf));

    /* C: overflow flag cleared. */
    memcpy(pagebuf, saved, p->page_size);
    h = h0;
    h.flags = (uint8_t)(h0.flags & ~CDB_PAGE_FLAG_OVERFLOW);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_write(p, first, &h, pagebuf + off, plen));
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_read(p, first, 5, outbuf, len, pagebuf));

    /* D: payload length one byte short of what the chain requires. */
    memcpy(pagebuf, saved, p->page_size);
    h = h0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_write(p, first, &h, pagebuf + off, plen - 1u));
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_read(p, first, 5, outbuf, len, pagebuf));

    /* E: a non-last page whose next link has been zeroed. */
    memcpy(pagebuf, saved, p->page_size);
    h = h0;
    memset(pagebuf + off, 0, p->addr_width); /* zero the next-page link */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_write(p, first, &h, pagebuf + off, plen));
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_read(p, first, 5, outbuf, len, pagebuf));

    /* Restore the valid first page, confirm the chain reads cleanly again. */
    memcpy(pagebuf, saved, p->page_size);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_write(p, first, &h0, pagebuf + off, plen));
    memset(outbuf, 0, len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_overflow_read(p, first, 5, outbuf, len, pagebuf));
    TEST_ASSERT_EQUAL_MEMORY(data, outbuf, len);

    /* F: a first page that does not exist -> CDB_E_CORRUPT (not NOT_FOUND). */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_read(p, 999999u, 5, outbuf, len, pagebuf));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
}

/* ------------------------------------------------------------ argument guards */

static void test_overflow_arg_guards(void)
{
    cdb_pager *p = &db.pager;
    uint64_t first = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(CDB_LAYOUT_ADDR64, "ovf_args"));

    /* write: NULL pager, zero length, NULL data. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_overflow_write_db(NULL, NULL, 5, data, 100, scratch, NULL, 0, &first));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_overflow_write(p, 5, data, 0, scratch, &first));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_overflow_write(p, 5, NULL, 100, scratch, &first));

    /* read: first == 0, len == 0, NULL out, NULL pager. */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_read(p, 0, 5, outbuf, 100, pagebuf));
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_read(p, 1, 5, outbuf, 0, pagebuf));
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_read(p, 1, 5, NULL, 100, pagebuf));
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_read_db(NULL, NULL, 1, 5, outbuf, 100, pagebuf));

    /* free: first == 0, len == 0, NULL pager. */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_free(p, 0, 5, 100, pagebuf));
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_free(p, 1, 5, 0, pagebuf));
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_free_db(NULL, NULL, 1, 5, 100, pagebuf));
}

/* ------------------------------------------------------------ tail nibblets */

static void test_overflow_nibblet_tail(void)
{
    cdb_pager *p = &db.pager;
    size_t room, len;
    uint64_t first = 0;
    uint8_t okey[2] = { 0, 0 };

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(CDB_LAYOUT_ADDR64, "ovf_nib"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));

    room = cdb_overflow_room(p);
    (void)room;
    len = 40u; /* whole value fits in a single tail nibblet */
    TEST_ASSERT_TRUE(cdb_nib_fits(&db, len));

    TEST_ASSERT_EQUAL_INT(CDB_OK,
        cdb_overflow_write_db(&db, p, 5, data, len, scratch, okey, sizeof okey, &first));
    TEST_ASSERT_TRUE(cdb_nib_is(first));

    /* Read through the db-aware reader resolves the nibblet. */
    memset(outbuf, 0, len);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_overflow_read_db(&db, p, first, 5, outbuf, len, pagebuf));
    TEST_ASSERT_EQUAL_MEMORY(data, outbuf, len);

    /* The db-less reader cannot resolve a nibblet address -> CDB_E_CORRUPT. */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_read(p, first, 5, outbuf, len, pagebuf));
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_overflow_free(p, first, 5, len, pagebuf));

    /* The db-aware free releases the nibblet. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_overflow_free_db(&db, p, first, 5, len, pagebuf));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
}

static void test_overflow_nib_moved(void)
{
    cdb_pager *p = &db.pager;
    size_t room, len, off;
    uint64_t first = 0, old_addr = 0;
    cdb_page_header h;
    uint8_t okey[9];
    uint8_t bad[5] = { 0 };

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(CDB_LAYOUT_ADDR64, "ovf_moved"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));

    room = cdb_overflow_room(p);
    len = room + 40u; /* one full page linking to a tail nibblet */
    TEST_ASSERT_TRUE(cdb_nib_fits(&db, 40u));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
        cdb_overflow_write_db(&db, p, 5, data, len, scratch, NULL, 0, &first));
    TEST_ASSERT_FALSE(cdb_nib_is(first)); /* first is a real page, not a nibblet */

    /* Recover the stored tail-nibblet address from the first page's next link. */
    off = cdb_page_payload_offset(p->fmt);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(p, first, pagebuf, &h));
    old_addr = cdb_load_u64(pagebuf + off, p->order);
    TEST_ASSERT_TRUE(cdb_nib_is(old_addr));

    okey[0] = CDB_OVERFLOW_OWNER_PREV_PAGE;
    cdb_store_u64(okey + 1, first, CDB_ORDER_BIG);

    /* Guards: NULL db, NULL key, zero key length -> CDB_E_CORRUPT. */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_overflow_nib_moved(NULL, 5, okey, 9, old_addr, old_addr));
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_overflow_nib_moved(&db, 5, NULL, 9, old_addr, old_addr));
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_overflow_nib_moved(&db, 5, okey, 0, old_addr, old_addr));

    /* PREV_PAGE owner with wrong key length. */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_overflow_nib_moved(&db, 5, okey, 5, old_addr, old_addr));

    /* PREV_PAGE owner, but the stored link does not match old_addr -> NOT_FOUND. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND,
                          cdb_overflow_nib_moved(&db, 5, okey, 9, old_addr ^ 1u, 12345u));

    /* PREV_PAGE owner, matching old_addr: relocation updates the link and succeeds. */
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_overflow_nib_moved(&db, 5, okey, 9, old_addr, old_addr));

    /* DOC_REV and COL_CHUNK owners delegate; a bogus back-reference is rejected. */
    {
        uint8_t dkey[5] = { CDB_OVERFLOW_OWNER_DOC_REV, 1, 2, 3, 4 };
        uint8_t ckey[5] = { CDB_OVERFLOW_OWNER_COL_CHUNK, 1, 2, 3, 4 };
        TEST_ASSERT_NOT_EQUAL(CDB_OK,
                              cdb_overflow_nib_moved(&db, 5, dkey, sizeof dkey, old_addr, old_addr));
        TEST_ASSERT_NOT_EQUAL(CDB_OK,
                              cdb_overflow_nib_moved(&db, 5, ckey, sizeof ckey, old_addr, old_addr));
    }

    /* Unknown owner kind -> CDB_E_CORRUPT. */
    bad[0] = 99u;
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_overflow_nib_moved(&db, 5, bad, sizeof bad, old_addr, old_addr));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_overflow_roundtrip);
    RUN_TEST(test_overflow_addr32);
    RUN_TEST(test_overflow_corruption);
    RUN_TEST(test_overflow_arg_guards);
    RUN_TEST(test_overflow_nibblet_tail);
    RUN_TEST(test_overflow_nib_moved);
    return UNITY_END();
}
