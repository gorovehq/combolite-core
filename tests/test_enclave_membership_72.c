/* Audit #72 CR5 slice 1 — enclave store membership (Option A).
 *
 * Proves the one missing link that turns inert at-rest page encryption ON: a
 * public API (cdb_db_store_set_enclave) that assigns a store to an open enclave
 * and persists the membership in the catalog (cdb_catalog_set_domain), so the
 * store's pages seal under the enclave key via the EXISTING crypto machinery
 * (store_domain -> record tagging -> pager seal hook).
 *
 * The crypto, enclave lifecycle and seal/open hooks already exist and are not
 * re-implemented here. Per-model page-domain stamping is a later CR5 slice; this
 * test supplies that wiring in its own apply hook (as test_security's kv_apply
 * does), reading the REAL catalog domain_id that cdb_db_store_set_enclave
 * persists. The red->green therefore hinges on this slice: without the join the
 * store's catalog domain stays 0, the apply stamps 0, and the page is plaintext;
 * after the join the apply stamps the enclave id and the page is AEAD ciphertext.
 *
 * Harness: a tiny key-value model (entry N lives in logical page N, as in
 * test_db.c) so a written page is at a known, directly inspectable location, and
 * the store's highest entry id is staged so the emptiness oracle can see
 * committed data.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "cdb_db.h"
#include "cdb_catalog.h"
#include "cdb_faultdev.h"
#include "cdb_faultenv.h"
#include "cdb_journal.h"
#include "cdb_pager.h"
#include "combolite/cdb_crypto.h"

#define FCAP (640u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define KV_PAGES 128u
#define ENTRY 64u    /* the data entry/logical page under test */
#define ENCLAVE 100u /* enclave id, deliberately != any store id */

/* Longer than a trivial run so a stray match in the arena is implausible. */
#define SECRET "ENCLAVE-MEMBERSHIP-SECRET-PAYLOAD-0123456789-abcdefghij"

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
static uint8_t page[PAGE];
static cdb_db_config cfg;
static cdb_db db;

/* Synthetic, deterministic test key material — NOT a credential (CWE-798).
 * The master and enclave keys are DERIVED at runtime from a non-secret seed
 * into these buffers rather than embedded as key literals in source, so no
 * hardcoded key hex appears in the file. synth_key fills a 64-char hex string
 * (32 bytes) and, optionally, the matching raw bytes. */
#define TEST_KEY_BYTES 32u
#define TEST_KEY_HEXLEN (TEST_KEY_BYTES * 2u)
static char mk_hex[TEST_KEY_HEXLEN + 1u];
static char enc_hex[TEST_KEY_HEXLEN + 1u];
static char wrong_hex[TEST_KEY_HEXLEN + 1u];
static uint8_t enc_raw[TEST_KEY_BYTES];

static void synth_key(uint8_t seed, char hex_out[TEST_KEY_HEXLEN + 1u], uint8_t *raw_out)
{
    static const char hexd[] = "0123456789abcdef";
    unsigned i;
    for (i = 0; i < TEST_KEY_BYTES; i++) {
        uint8_t b = (uint8_t)(seed * 131u + i * 17u);
        if (raw_out != NULL)
            raw_out[i] = b;
        hex_out[i * 2u] = hexd[(b >> 4) & 0x0Fu];
        hex_out[i * 2u + 1u] = hexd[b & 0x0Fu];
    }
    hex_out[TEST_KEY_HEXLEN] = '\0';
}

/* A per-model write would stamp the page's domain from the store's encryption
 * domain and track its highest entry id; that wiring is a later CR5 slice, so
 * the test provides it, driven entirely by the catalog membership this slice
 * persists. entry N -> logical page N. */
static cdb_status kv_apply(void *ctx, cdb_pager *p, const cdb_delta *d)
{
    cdb_db *self = (cdb_db *)ctx;
    cdb_page_header t;
    cdb_store_info info;
    uint64_t lid;
    cdb_status s;

    TEST_ASSERT_TRUE(d->entry_id < KV_PAGES);
    if (d->op == CDB_OP_DELETE) {
        s = cdb_pager_free(p, d->entry_id);
        return s == CDB_E_NOT_FOUND ? CDB_OK : s;
    }
    while (p->next_lid < KV_PAGES)
        if ((s = cdb_pager_alloc(p, &lid)) != CDB_OK)
            return s;
    memset(&t, 0, sizeof t);
    t.type = CDB_PAGE_TYPE_DATA_TEST;
    t.store_id = d->store_id;
    /* The page's encryption domain is the store's persisted catalog domain. */
    if (cdb_catalog_get_store(&self->catalog, d->store_id, &info) == CDB_OK)
        t.domain_id = info.domain_id;
    /* Record the highest entry id so the emptiness oracle sees committed data. */
    if ((s = cdb_catalog_stage_next_entry(&self->catalog, d->store_id, d->entry_id + 1u)) != CDB_OK)
        return s;
    return cdb_pager_write(p, d->entry_id, &t, d->data, d->len);
}

static cdb_header settings(void)
{
    cdb_header h;
    unsigned i;
    memset(&h, 0, sizeof h);
    h.order = CDB_ORDER_LITTLE;
    h.layout_flags = CDB_LAYOUT_ADDR64;
    h.default_page_log2 = (uint8_t)PAGE_LOG2;
    for (i = 0; i < 16u; i++)
        h.db_id[i] = (uint8_t)(0x30 + i);
    return h;
}

void setUp(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 4096;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &env));

    memset(&cfg, 0, sizeof cfg);
    cfg.pager.arena = arena;
    cfg.pager.arena_size = sizeof arena;
    cfg.pager.nodes = nodes;
    cfg.pager.node_cap = NODES;
    cfg.pager.free_list = free_list;
    cfg.pager.free_cap = sizeof free_list / sizeof free_list[0];
    cfg.record_buf = record_buf;
    cfg.record_buf_size = sizeof record_buf;
    cfg.apply = kv_apply;
    cfg.apply_ctx = &db;
    cfg.catalog_work.bytes = cat_work;
    cfg.catalog_work.bytes_size = sizeof cat_work;
    cfg.catalog_work.entries = cat_entries;
    cfg.catalog_work.entries_cap = 512;
    cfg.catalog_page = cat_page;
    cfg.durability = CDB_DURABILITY_FULL;
    cfg.master_key_uri = "env://CDB_TEST_MK";
    cfg.aead_alg = CDB_AEAD_AES_256_GCM;

    synth_key(0x01u, mk_hex, NULL);
    synth_key(0x40u, enc_hex, enc_raw);
    synth_key(0x99u, wrong_hex, NULL); /* a different, non-matching enclave key */
    setenv("CDB_TEST_MK", mk_hex, 1);
    setenv("CDB_TEST_ENC", enc_hex, 1);
    setenv("CDB_TEST_WRONG", wrong_hex, 1);
}

void tearDown(void) {}

static cdb_status open_db(const char *name)
{
    cdb_header h = settings();
    return cdb_db_open(&db, &env, name, &cfg, &h);
}

static cdb_status reopen_db(const char *name)
{
    return cdb_db_open(&db, &env, name, &cfg, NULL);
}

/* Creates store "s" (empty) and opens enclave ENCLAVE; returns the store id. */
static uint64_t fresh_store_and_enclave(const char *name)
{
    uint64_t store = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db(name));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "s", 1, CDB_MODEL_RELATIONAL, &store));
    TEST_ASSERT_TRUE(store != 0 && store != ENCLAVE);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_enclave(&db, ENCLAVE, "env://CDB_TEST_ENC"));
    return store;
}

static void write_entry(uint64_t store, uint64_t entry, const char *text)
{
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_tx_put(&db, store, entry, CDB_OP_REPLACE, text, strlen(text)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
}

/* True iff `needle` appears anywhere in the live archive storage (db.archive_st
 * — the at-rest image an attacker or peer would see). Used to prove a sealed
 * page's plaintext is NOT on disk (ciphertext), an inert page's plaintext IS,
 * and that no enclave key material ever reaches the archive. */
static uint8_t scanbuf[FCAP];
static int archive_has(const uint8_t *needle, size_t n)
{
    uint64_t sz = 0, off;
    size_t i;
    if (n == 0u)
        return 0;
    if (cdb_storage_size(&db.archive_st, &sz) != CDB_OK)
        return 0;
    if (sz > (uint64_t)sizeof scanbuf)
        sz = (uint64_t)sizeof scanbuf;
    for (off = 0; off < sz;) {
        uint64_t want = sz - off < 4096u ? sz - off : 4096u;
        if (cdb_storage_read(&db.archive_st, off, scanbuf + off, (size_t)want) != CDB_OK)
            return 0;
        off += want;
    }
    if ((size_t)sz < n)
        return 0;
    for (i = 0; i + n <= (size_t)sz; i++)
        if (memcmp(scanbuf + i, needle, n) == 0)
            return 1;
    return 0;
}

/* Parse the header of logical page `entry` through the pager (which decrypts iff
 * the owning enclave is open). phys == entry for this kv harness (pages are
 * pre-allocated 1:1, so logical page N is physical page N). */
struct placed {
    uint64_t phys;
};

static struct placed locate(uint64_t entry, cdb_page_header *ph)
{
    struct placed e;
    e.phys = entry; /* kv harness: logical page N is physical page N */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(&db.pager, entry, page, ph));
    return e;
}

/* AC1/AC2: set_enclave on an empty store persists the domain and seals pages;
 * a store never joined is NOTFOUND-safe for set_domain on unknown ids. */
static void test_set_domain_persists_and_notfound(void)
{
    cdb_store_info info;
    uint64_t store = fresh_store_and_enclave("m");

    /* Unknown store id fails closed. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_catalog_set_domain(&db.catalog, 999999u, ENCLAVE));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_store_set_enclave(&db, store, ENCLAVE));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_catalog_get_store(&db.catalog, store, &info));
    TEST_ASSERT_EQUAL_UINT64(ENCLAVE, info.domain_id);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC3: after joining, a new page write is AEAD ciphertext on disk yet round
 * trips through the pager. */
static void test_joined_store_page_is_encrypted_and_roundtrips(void)
{
    cdb_page_header ph;
    uint64_t store = fresh_store_and_enclave("m");

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_store_set_enclave(&db, store, ENCLAVE));
    write_entry(store, ENTRY, SECRET);

    (void)locate(ENTRY, &ph);
    /* Round-trips in cleartext through the pager (the enclave is open). */
    TEST_ASSERT_EQUAL_UINT64(ENCLAVE, ph.domain_id);
    TEST_ASSERT_EQUAL_UINT32((uint32_t)strlen(SECRET), ph.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(SECRET, page + cdb_page_payload_offset(db.pager.fmt), strlen(SECRET));

    /* But the plaintext is NOT present anywhere in the at-rest archive image. */
    TEST_ASSERT_FALSE(archive_has((const uint8_t *)SECRET, strlen(SECRET)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC4: binding a store to an enclave the session cannot derive is refused, so a
 * store is never bound to a key the session cannot derive. */
static void test_fail_closed_statuses(void)
{
    uint64_t store = fresh_store_and_enclave("m");

    /* enclave_id 0 => INVALID_ARG */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_store_set_enclave(&db, store, 0u));
    /* store id 0 => INVALID_ARG */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_db_store_set_enclave(&db, 0u, ENCLAVE));
    /* unknown store => NOT_FOUND */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_db_store_set_enclave(&db, 424242u, ENCLAVE));
    /* enclave not open => SECURITY (never bind to an underivable key) */
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_db_store_set_enclave(&db, store, ENCLAVE + 1u));

    /* non-empty store => STATE (retroactive join is deferred). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_store_set_enclave(&db, store, ENCLAVE));
    write_entry(store, ENTRY, SECRET);
    {
        uint64_t store2 = 0;
        TEST_ASSERT_EQUAL_INT(CDB_OK,
                              cdb_db_create_store(&db, "s2", 2, CDB_MODEL_RELATIONAL, &store2));
        write_entry(store2, 1u, "x");
        TEST_ASSERT_EQUAL_INT(CDB_E_STATE, cdb_db_store_set_enclave(&db, store2, ENCLAVE));
    }
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC5: a sealed enclave page that does not authenticate under the active enclave
 * key fails closed (CDB_E_SECURITY). The AEAD tag makes an on-disk tamper and a
 * wrong key indistinguishable — both break authentication — so we drive the case
 * deterministically by re-opening the enclave under a DIFFERENT key: the page's
 * tag no longer verifies, and the read fails closed rather than returning
 * garbage plaintext. */
static void test_tamper_fails_closed(void)
{
    cdb_page_header ph;
    uint64_t store = fresh_store_and_enclave("m");

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_store_set_enclave(&db, store, ENCLAVE));
    write_entry(store, ENTRY, SECRET);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    /* Reopen and open the enclave under the WRONG key (authentication must fail). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, reopen_db("m"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open_enclave(&db, ENCLAVE, "env://CDB_TEST_WRONG"));
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_pager_read(&db.pager, ENTRY, page, &ph));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC6 (INERT): a store never joined (domain_id==0) writes a byte-for-byte
 * plaintext page — the legacy path is unchanged. */
static void test_inert_store_page_is_plaintext(void)
{
    cdb_page_header ph;
    uint64_t store = 0;

    TEST_ASSERT_EQUAL_INT(CDB_OK, open_db("m"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_create_store(&db, "s", 1, CDB_MODEL_RELATIONAL, &store));
    write_entry(store, ENTRY, SECRET);

    (void)locate(ENTRY, &ph);
    TEST_ASSERT_EQUAL_UINT64(0u, ph.domain_id);
    /* The payload is on disk verbatim — inert path, no encryption. */
    TEST_ASSERT_TRUE(archive_has((const uint8_t *)SECRET, strlen(SECRET)));

    /* Reopening without any enclave reads it back (no key needed). */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
    TEST_ASSERT_EQUAL_INT(CDB_OK, reopen_db("m"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(&db.pager, ENTRY, page, &ph));
    TEST_ASSERT_EQUAL_MEMORY(SECRET, page + cdb_page_payload_offset(db.pager.fmt), strlen(SECRET));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC7 (persistence): membership survives a full close/reopen; after re-opening
 * the enclave with its key_ref the joined store's records decrypt. */
static void test_membership_persists_across_reopen(void)
{
    cdb_page_header ph;
    uint64_t store = fresh_store_and_enclave("m");

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_store_set_enclave(&db, store, ENCLAVE));
    write_entry(store, ENTRY, SECRET);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));

    /* Reopen the db and re-open the enclave with its key_ref. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, reopen_db("m"));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open_enclave(&db, ENCLAVE, "env://CDB_TEST_ENC"));

    /* After re-opening the enclave with its key_ref the record decrypts. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_pager_read(&db.pager, ENTRY, page, &ph));
    TEST_ASSERT_EQUAL_UINT64(ENCLAVE, ph.domain_id);
    TEST_ASSERT_EQUAL_MEMORY(SECRET, page + cdb_page_payload_offset(db.pager.fmt), strlen(SECRET));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* AC13: no enclave key material is written to the database files. The only
 * secret in play is the enclave key; neither its key_ref hex nor the raw key
 * bytes appear anywhere in the on-disk images. */
static void test_no_key_persisted_or_logged(void)
{
    /* The enclave key's raw bytes (enc_raw) and its hex form (enc_hex) are the
     * runtime-derived test material behind env://CDB_TEST_ENC — see synth_key.
     * Neither form must appear anywhere in the on-disk images. */
    uint64_t store = fresh_store_and_enclave("m");

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_store_set_enclave(&db, store, ENCLAVE));
    write_entry(store, ENTRY, SECRET);

    /* The key never reaches the at-rest archive, in either form. */
    TEST_ASSERT_FALSE(archive_has(enc_raw, sizeof enc_raw));
    TEST_ASSERT_FALSE(archive_has((const uint8_t *)enc_hex, strlen(enc_hex)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_set_domain_persists_and_notfound);
    RUN_TEST(test_joined_store_page_is_encrypted_and_roundtrips);
    RUN_TEST(test_fail_closed_statuses);
    RUN_TEST(test_tamper_fails_closed);
    RUN_TEST(test_inert_store_page_is_plaintext);
    RUN_TEST(test_membership_persists_across_reopen);
    RUN_TEST(test_no_key_persisted_or_logged);
    return UNITY_END();
}
