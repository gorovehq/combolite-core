/* #37 FR1: crypto randomness must route through the environment's RNG hook
 * (env->ops->random), not a direct /dev/urandom open, and must fail closed when
 * the env provides no RNG or the RNG reports failure.
 *
 * Red->green: before the fix the crypto entry points opened /dev/urandom with a
 * NULL context, so an injected/stub env RNG was never called (the counter below
 * stayed 0) and a failing env RNG was bypassed. After the fix the _env entry
 * points call the injected hook and fail closed on its failure.
 *
 * Deterministic and hermetic: one fault environment whose random hook is wrapped
 * by a counting/failing shim; no real entropy, clock, or network. */
#define _POSIX_C_SOURCE 200809L

#include <string.h>

#include "unity.h"
#include "cdb_db.h"
#include "cdb_faultenv.h"
#include "combolite/cdb_crypto.h"
#include "combolite/cdb_env.h"

#define FCAP (256u * 1024u)
#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define STORE 1u

static uint8_t env_arena[CDB_FAULTENV_MAX_FILES * 3u * FCAP];
static cdb_fault_record env_records[CDB_FAULTENV_MAX_FILES * 2048u];
static cdb_faultenv fe;
static cdb_env base_env;

/* A shim env that counts and can fail the RNG hook, wrapping the fault env. */
static cdb_env_ops wrapped_ops;
static cdb_env wrapped_env;
static cdb_status (*orig_random)(void *, void *, size_t);
static int rng_calls;
static int rng_fail;

static cdb_status counting_random(void *ctx, void *buf, size_t n)
{
    rng_calls++;
    if (rng_fail)
        return CDB_E_IO;
    return orig_random(ctx, buf, n);
}

static uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
static cdb_pager_node nodes[NODES];
static cdb_free_extent free_list[4096];
static uint8_t record_buf[1024];
static uint8_t cat_work[16384];
static cdb_index_entry cat_entries[512];
static uint8_t cat_page[PAGE];
static cdb_db_config cfg;
static cdb_db db;

#define KV_PAGES 64u

static cdb_status kv_apply(void *ctx, cdb_pager *p, const cdb_delta *d)
{
    cdb_page_header t;
    uint64_t lid;
    cdb_status s;
    (void)ctx;
    if (d->entry_id >= KV_PAGES)
        return CDB_E_INVALID_ARG;
    while (p->next_lid < KV_PAGES)
        if ((s = cdb_pager_alloc(p, &lid)) != CDB_OK)
            return s;
    memset(&t, 0, sizeof t);
    t.type = CDB_PAGE_TYPE_DATA_TEST;
    t.store_id = d->store_id;
    return cdb_pager_write(p, d->entry_id, &t, d->data, d->len);
}

void setUp(void)
{
    cdb_faultenv_config c;
    c.arena = env_arena;
    c.file_capacity = FCAP;
    c.records = env_records;
    c.records_per_file = 2048;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultenv_init(&fe, &c, &base_env));

    wrapped_ops = *base_env.ops;
    orig_random = base_env.ops->random;
    wrapped_ops.random = counting_random;
    wrapped_env = base_env;
    wrapped_env.ops = &wrapped_ops;
    rng_calls = 0;
    rng_fail = 0;

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
    cfg.catalog_work.bytes = cat_work;
    cfg.catalog_work.bytes_size = sizeof cat_work;
    cfg.catalog_work.entries = cat_entries;
    cfg.catalog_work.entries_cap = 512;
    cfg.catalog_page = cat_page;
    cfg.durability = CDB_DURABILITY_FULL;
}

void tearDown(void) {}

static cdb_header settings(void)
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

/* AC1: the env RNG hook is actually invoked by the _env primitives. */
static void test_random_bytes_env_uses_hook(void)
{
    uint8_t buf[16];
    rng_calls = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_random_bytes_env(&wrapped_env, buf, sizeof buf));
    TEST_ASSERT_TRUE(rng_calls >= 1);
}

/* AC2: a failing env RNG fails closed with a typed error, no fallback entropy. */
static void test_random_bytes_env_fail_closed(void)
{
    uint8_t buf[16];
    rng_fail = 1;
    TEST_ASSERT_EQUAL_INT(CDB_E_IO, cdb_crypto_random_bytes_env(&wrapped_env, buf, sizeof buf));
}

/* AC2: no env / no random hook fails closed with CDB_E_SECURITY (never bypassed). */
static void test_random_bytes_env_no_hook_fail_closed(void)
{
    uint8_t buf[16];
    cdb_env_ops no_rng = wrapped_ops;
    cdb_env no_rng_env = wrapped_env;
    no_rng.random = NULL;
    no_rng_env.ops = &no_rng;

    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_crypto_random_bytes_env(NULL, buf, sizeof buf));
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_crypto_random_bytes_env(&no_rng_env, buf, sizeof buf));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_random_bytes_env(&wrapped_env, NULL, 8));
}

/* AC1: key generation routes randomness through the env hook. */
static void test_identity_generate_env_uses_hook(void)
{
    cdb_identity id;
    rng_calls = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_generate_env(&wrapped_env, &id, 7, 1));
    TEST_ASSERT_TRUE(rng_calls >= 1);
    TEST_ASSERT_TRUE(id.public_key[0] == 0x02 || id.public_key[0] == 0x03);
}

static void test_identity_generate_env_no_hook_fail_closed(void)
{
    cdb_identity id;
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_identity_generate_env(NULL, &id, 7, 1));
}

/* AC1: signing (incl. mbedtls blinding) routes randomness through the env hook,
 * and the resulting signature verifies. */
static void test_identity_sign_env_uses_hook(void)
{
    cdb_identity id;
    uint8_t sig[CDB_SIGNATURE_SIZE];
    const char *msg = "governance revision";

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_generate_env(&wrapped_env, &id, 9, 2));
    rng_calls = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_identity_sign_env(&wrapped_env, &id, msg, strlen(msg), sig));
    TEST_ASSERT_TRUE(rng_calls >= 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_verify(id.public_key, msg, strlen(msg), sig));
}

/* AC2: signing fails closed when the env RNG fails. */
static void test_identity_sign_env_fail_closed(void)
{
    cdb_identity id;
    uint8_t sig[CDB_SIGNATURE_SIZE];
    const char *msg = "x";

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_generate_env(&wrapped_env, &id, 9, 2));
    rng_fail = 1;
    TEST_ASSERT_NOT_EQUAL(CDB_OK, cdb_identity_sign_env(&wrapped_env, &id, msg, strlen(msg), sig));
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_identity_sign_env(NULL, &id, msg, strlen(msg), sig));
}

/* AC1: envelope key wrapping draws its nonce from the env hook and round-trips. */
static void test_wrap_key_env_uses_hook(void)
{
    uint8_t mk[32], ek[32], wrapped[CDB_WRAPPED_KEY_SIZE], out[32];
    memset(mk, 0x11, sizeof mk);
    memset(ek, 0x22, sizeof ek);
    rng_calls = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_wrap_key_env(&wrapped_env, mk, ek, wrapped));
    TEST_ASSERT_TRUE(rng_calls >= 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_unwrap_key(mk, wrapped, out));
    TEST_ASSERT_EQUAL_MEMORY(ek, out, 32);
    TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_crypto_wrap_key_env(NULL, mk, ek, wrapped));
}

/* AC1 (core path): a signed commit under CDB_SIGN_EVERY_REVISION routes the
 * signature's randomness through the environment RNG. Pre-fix the commit signer
 * opened /dev/urandom, so this counter stayed 0. */
static void test_db_signed_commit_routes_rng(void)
{
    cdb_identity id;
    cdb_header h = settings();

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_generate_env(&wrapped_env, &id, 101, 1));
    cfg.identity = &id;
    cfg.signing_policy = CDB_SIGN_EVERY_REVISION;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &wrapped_env, "rng_commit", &cfg, &h));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 1, CDB_OP_REPLACE, "v", 1));
    rng_calls = 0; /* isolate the commit's signing from open-time RNG use */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_TRUE(rng_calls >= 1);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

/* Control: with no signing policy the commit does no signing and draws no RNG,
 * confirming the RNG use above is the signature, not incidental. */
static void test_db_unsigned_commit_no_rng(void)
{
    cdb_header h = settings();
    cfg.signing_policy = CDB_SIGN_NONE;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_open(&db, &wrapped_env, "rng_nocommit", &cfg, &h));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_begin(&db, CDB_DURABILITY_FULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_put(&db, STORE, 1, CDB_OP_REPLACE, "v", 1));
    rng_calls = 0;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_tx_commit(&db));
    TEST_ASSERT_EQUAL_INT(0, rng_calls);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_db_close(&db));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_random_bytes_env_uses_hook);
    RUN_TEST(test_random_bytes_env_fail_closed);
    RUN_TEST(test_random_bytes_env_no_hook_fail_closed);
    RUN_TEST(test_identity_generate_env_uses_hook);
    RUN_TEST(test_identity_generate_env_no_hook_fail_closed);
    RUN_TEST(test_identity_sign_env_uses_hook);
    RUN_TEST(test_identity_sign_env_fail_closed);
    RUN_TEST(test_wrap_key_env_uses_hook);
    RUN_TEST(test_db_signed_commit_routes_rng);
    RUN_TEST(test_db_unsigned_commit_no_rng);
    return UNITY_END();
}
