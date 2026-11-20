/* Increment-4 reachable-branch coverage for the crypto module (spec 12),
 * complementing tests/test_crypto_edge.c and tests/test_crypto.c. Drives the
 * remaining REACHABLE invalid-argument guards and key-parsing paths of
 * src/cdb_crypto.c to covered, with exact-status asserts on every negative
 * path (fail-closed contract, master s4 abuse paths):
 *   - cdb_crypto_aead_decrypt NULL tag / NULL ct buffers,
 *   - cdb_crypto_hash_init_hmac / _update / _final NULL guards + len==0,
 *   - parse_key_bytes non-hex-but->=32 fallback (env://),
 *   - cdb_crypto_resolve_key file:// not-found and malformed content,
 *   - cdb_identity_verify NULL guards.
 *
 * The residual uncovered lines of cdb_crypto.c are the vendored-library
 * internal failure returns (e.g. `if (mbedtls_...(...) != 0) return
 * CDB_E_CORRUPT;`, the compile-time CDB_E_STATE size guards, the
 * /dev/urandom-open failure), which the module's own docs/dev
 * /testing-and-coverage.md marks as not reachable without routing the crypto
 * primitives through a fault hook -- a src change, surfaced as a gate request,
 * not made here. */
#define _POSIX_C_SOURCE 200809L

#include "unity.h"
#include "combolite/cdb_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef CDB_TEST_TMPDIR
#define CDB_TEST_TMPDIR "/tmp"
#endif

static const uint8_t KEY[CDB_CRYPTO_KEY_SIZE] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

void setUp(void) {}
void tearDown(void) {}

/* cdb_crypto_aead_decrypt argument guards: each NULL operand of the two guard
 * clauses is exercised independently, asserting the exact status. The matching
 * encrypt guards are already covered by test_crypto_edge. */
static void test_aead_decrypt_invalid_args(void)
{
    uint8_t nonce[CDB_AEAD_NONCE_SIZE] = {0};
    uint8_t ct[8] = {0};
    uint8_t tag[CDB_AEAD_TAG_SIZE] = {0};
    uint8_t pt[8] = {0};

    /* First guard: key / nonce / tag NULL. */
    TEST_ASSERT_EQUAL_INT(
        CDB_E_INVALID_ARG,
        cdb_crypto_aead_decrypt(CDB_AEAD_AES_256_GCM, NULL, nonce, NULL, 0, ct, sizeof ct, tag, pt));
    TEST_ASSERT_EQUAL_INT(
        CDB_E_INVALID_ARG,
        cdb_crypto_aead_decrypt(CDB_AEAD_AES_256_GCM, KEY, NULL, NULL, 0, ct, sizeof ct, tag, pt));
    TEST_ASSERT_EQUAL_INT(
        CDB_E_INVALID_ARG,
        cdb_crypto_aead_decrypt(CDB_AEAD_AES_256_GCM, KEY, nonce, NULL, 0, ct, sizeof ct, NULL, pt));

    /* Second guard: ct_len > 0 with a NULL ciphertext or plaintext buffer. */
    TEST_ASSERT_EQUAL_INT(
        CDB_E_INVALID_ARG,
        cdb_crypto_aead_decrypt(CDB_AEAD_AES_256_GCM, KEY, nonce, NULL, 0, NULL, sizeof ct, tag, pt));
    TEST_ASSERT_EQUAL_INT(
        CDB_E_INVALID_ARG,
        cdb_crypto_aead_decrypt(CDB_AEAD_AES_256_GCM, KEY, nonce, NULL, 0, ct, sizeof ct, tag, NULL));
}

/* Streaming-hash argument guards and the explicit len==0 short-circuit. */
static void test_hash_ctx_guards(void)
{
    cdb_crypto_hash_ctx ctx;
    uint8_t out[CDB_CRYPTO_HASH_SIZE];
    const char *data = "abc";

    memset(&ctx, 0, sizeof ctx);
    memset(out, 0, sizeof out);

    /* hash_init_hmac: NULL ctx, then NULL key. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hash_init_hmac(NULL, KEY));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hash_init_hmac(&ctx, NULL));

    /* hash_update: NULL ctx, then non-empty with NULL data. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hash_update(NULL, data, 3));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_init(&ctx));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hash_update(&ctx, NULL, 3));

    /* hash_update: len == 0 is a no-op success, even with NULL data. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&ctx, NULL, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&ctx, data, 3));

    /* hash_final: NULL ctx, then NULL out. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hash_final(NULL, out));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hash_final(&ctx, NULL));

    /* The context still finalizes correctly after the rejected calls. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_final(&ctx, out));
    cdb_crypto_hash_free(&ctx);
}

/* parse_key_bytes (via resolve_key env://): a >=64-char value that is NOT all
 * hex falls through to the raw-bytes path and takes the first 32 bytes. This
 * drives the "non-hex character -> break" branch of the hex scan. */
static void test_resolve_key_nonhex_raw_fallback(void)
{
    uint8_t key[CDB_CRYPTO_KEY_SIZE];
    /* 64 characters, none of them hex digits: the hex scan breaks immediately,
     * then the raw-32 path copies the first 32 bytes. */
    char val[65];
    memset(val, 'z', 64);
    val[64] = '\0';

    memset(key, 0, sizeof key);
    setenv("CDB_COV2_RAW", val, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_resolve_key("env://CDB_COV2_RAW", 0, NULL, NULL, key));
    /* The first 32 raw bytes were taken verbatim. */
    {
        uint8_t expect[CDB_CRYPTO_KEY_SIZE];
        memset(expect, 'z', sizeof expect);
        TEST_ASSERT_EQUAL_MEMORY(expect, key, sizeof key);
    }
    unsetenv("CDB_COV2_RAW");
}

/* resolve_key file://: a non-existent path is NOT_FOUND, and a file whose
 * contents cannot be parsed as a key is MALFORMED. Both run in dev mode
 * (is_production = 0). */
static void test_resolve_key_file_errors(void)
{
    uint8_t key[CDB_CRYPTO_KEY_SIZE];
    char path[256];
    char uri[300];
    int fd;
    const char *bad = "short";

    memset(key, 0, sizeof key);

    /* Non-existent file -> NOT_FOUND. */
    snprintf(uri, sizeof uri, "file://%s/cdb_cov2_absent_file_zzz", CDB_TEST_TMPDIR);
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_crypto_resolve_key(uri, 0, NULL, NULL, key));

    /* A file with too-few bytes to be a key -> MALFORMED. */
    snprintf(path, sizeof path, "%s/cdb_cov2_keyXXXXXX", CDB_TEST_TMPDIR);
    fd = mkstemp(path);
    TEST_ASSERT_TRUE(fd >= 0);
    TEST_ASSERT_EQUAL_INT((int)strlen(bad), (int)write(fd, bad, strlen(bad)));
    close(fd);
    snprintf(uri, sizeof uri, "file://%s", path);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_crypto_resolve_key(uri, 0, NULL, NULL, key));
    unlink(path);
}

/* cdb_identity_verify argument guards: each NULL operand independently. */
static void test_identity_verify_invalid_args(void)
{
    cdb_identity id;
    uint8_t sig[CDB_SIGNATURE_SIZE];
    const char *msg = "m";

    memset(sig, 0, sizeof sig);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_generate(&id, 1, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_sign(&id, msg, 1, sig));

    /* public_key NULL, sig NULL, and msg_len > 0 with NULL msg. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_identity_verify(NULL, msg, 1, sig));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_identity_verify(id.public_key, msg, 1, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_identity_verify(id.public_key, NULL, 1, sig));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_aead_decrypt_invalid_args);
    RUN_TEST(test_hash_ctx_guards);
    RUN_TEST(test_resolve_key_nonhex_raw_fallback);
    RUN_TEST(test_resolve_key_file_errors);
    RUN_TEST(test_identity_verify_invalid_args);
    return UNITY_END();
}
