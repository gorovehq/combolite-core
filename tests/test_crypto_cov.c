#define _POSIX_C_SOURCE 200809L
/* Coverage set for cdb_crypto: the reachable error, argument-validation and
 * branch paths the existing crypto suites miss (spec 12). Drives
 * cdb_crypto.h directly with synthetic, non-secret key material and fixed
 * vectors; every test asserts a specific status enum or output byte, never a
 * secret value. Hermetic: tmp dir for the file:// provider, no network.
 *
 * NOTE (AC12 / design ADR-003): the few remaining uncovered lines in
 * cdb_crypto.c are measured-unreachable defensive guards (mbedtls primitive
 * internal-failure returns on valid input, compile-time-false size guards, and
 * /dev/urandom open/short-read failure). They cannot be reached from a hermetic
 * unit test without a fault-injection seam; resolving them to literal 100% is a
 * gated src annotation awaiting owner approval and is intentionally not done
 * here. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_crypto.h"

void setUp(void) {}
void tearDown(void) {}

/* ---- AEAD argument-validation failure branches ---- */

static void test_aead_encrypt_arg_guards(void)
{
    uint8_t key[CDB_CRYPTO_KEY_SIZE];
    uint8_t nonce[CDB_AEAD_NONCE_SIZE];
    uint8_t tag[CDB_AEAD_TAG_SIZE];
    uint8_t pt[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t ct[8];

    memset(key, 0x10, sizeof key);
    memset(nonce, 0x20, sizeof nonce);

    /* NULL key / nonce / tag -> CDB_E_INVALID_ARG */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
        cdb_crypto_aead_encrypt(CDB_AEAD_AES_256_GCM, NULL, nonce, NULL, 0, pt, sizeof pt, ct, tag));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
        cdb_crypto_aead_encrypt(CDB_AEAD_AES_256_GCM, key, NULL, NULL, 0, pt, sizeof pt, ct, tag));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
        cdb_crypto_aead_encrypt(CDB_AEAD_AES_256_GCM, key, nonce, NULL, 0, pt, sizeof pt, ct, NULL));

    /* pt_len > 0 but NULL plaintext / ciphertext -> CDB_E_INVALID_ARG */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
        cdb_crypto_aead_encrypt(CDB_AEAD_AES_256_GCM, key, nonce, NULL, 0, NULL, sizeof pt, ct, tag));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
        cdb_crypto_aead_encrypt(CDB_AEAD_AES_256_GCM, key, nonce, NULL, 0, pt, sizeof pt, NULL, tag));

    /* Unknown algorithm -> CDB_E_UNSUPPORTED */
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED,
        cdb_crypto_aead_encrypt(0x99u, key, nonce, NULL, 0, pt, sizeof pt, ct, tag));
}

static void test_aead_decrypt_arg_guards(void)
{
    uint8_t key[CDB_CRYPTO_KEY_SIZE];
    uint8_t nonce[CDB_AEAD_NONCE_SIZE];
    uint8_t tag[CDB_AEAD_TAG_SIZE];
    uint8_t ct[8] = { 0 };
    uint8_t pt[8];

    memset(key, 0x10, sizeof key);
    memset(nonce, 0x20, sizeof nonce);
    memset(tag, 0x30, sizeof tag);

    /* NULL key / nonce / tag -> CDB_E_INVALID_ARG */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
        cdb_crypto_aead_decrypt(CDB_AEAD_AES_256_GCM, NULL, nonce, NULL, 0, ct, sizeof ct, tag, pt));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
        cdb_crypto_aead_decrypt(CDB_AEAD_AES_256_GCM, key, NULL, NULL, 0, ct, sizeof ct, tag, pt));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
        cdb_crypto_aead_decrypt(CDB_AEAD_AES_256_GCM, key, nonce, NULL, 0, ct, sizeof ct, NULL, pt));

    /* ct_len > 0 but NULL ciphertext / plaintext -> CDB_E_INVALID_ARG */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
        cdb_crypto_aead_decrypt(CDB_AEAD_AES_256_GCM, key, nonce, NULL, 0, NULL, sizeof ct, tag, pt));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
        cdb_crypto_aead_decrypt(CDB_AEAD_AES_256_GCM, key, nonce, NULL, 0, ct, sizeof ct, tag, NULL));

    /* Unknown algorithm -> CDB_E_UNSUPPORTED (after the arg checks pass) */
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED,
        cdb_crypto_aead_decrypt(0x99u, key, nonce, NULL, 0, ct, sizeof ct, tag, pt));
}

/* ---- Streaming hash: success paths + argument guards ---- */

static void test_streaming_sha256_matches_oneshot(void)
{
    cdb_crypto_hash_ctx ctx;
    uint8_t streamed[CDB_CRYPTO_HASH_SIZE];
    uint8_t oneshot[CDB_CRYPTO_HASH_SIZE];
    const char *a = "The quick brown fox ";
    const char *b = "jumps over the lazy dog";
    char joined[64];

    snprintf(joined, sizeof joined, "%s%s", a, b);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_init(&ctx));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&ctx, a, strlen(a)));
    /* A zero-length update is a no-op and must not disturb the digest. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&ctx, NULL, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&ctx, b, strlen(b)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_final(&ctx, streamed));
    cdb_crypto_hash_free(&ctx);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_sha256(joined, strlen(joined), oneshot));
    TEST_ASSERT_EQUAL_MEMORY(oneshot, streamed, CDB_CRYPTO_HASH_SIZE);
}

static void test_streaming_hmac_matches_oneshot(void)
{
    cdb_crypto_hash_ctx ctx;
    uint8_t key[CDB_CRYPTO_KEY_SIZE];
    uint8_t streamed[CDB_CRYPTO_HASH_SIZE];
    uint8_t oneshot[CDB_CRYPTO_HASH_SIZE];
    const char *msg = "attributed audit event payload";

    memset(key, 0x5A, sizeof key);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_init_hmac(&ctx, key));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&ctx, msg, strlen(msg)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_final(&ctx, streamed));
    cdb_crypto_hash_free(&ctx);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hmac_sha256(key, msg, strlen(msg), oneshot));
    TEST_ASSERT_EQUAL_MEMORY(oneshot, streamed, CDB_CRYPTO_HASH_SIZE);
}

static void test_streaming_hash_arg_guards(void)
{
    cdb_crypto_hash_ctx ctx;
    uint8_t key[CDB_CRYPTO_KEY_SIZE];
    uint8_t out[CDB_CRYPTO_HASH_SIZE];
    uint8_t data[4] = { 1, 2, 3, 4 };

    memset(key, 0x01, sizeof key);

    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hash_init(NULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hash_init_hmac(NULL, key));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hash_init_hmac(&ctx, NULL));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_init(&ctx));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hash_update(NULL, data, sizeof data));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hash_update(&ctx, NULL, sizeof data));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hash_final(NULL, out));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hash_final(&ctx, NULL));
    cdb_crypto_hash_free(&ctx);

    /* Freeing a NULL context is a safe no-op. */
    cdb_crypto_hash_free(NULL);
}

/* ---- Key provider: raw-byte fallback and file:// error paths ---- */

static void test_resolve_key_raw_fallback(void)
{
    uint8_t key[CDB_CRYPTO_KEY_SIZE];
    /* 64 characters, but not hex: the hex probe fails on the first char and the
     * resolver falls back to copying the first 32 raw bytes. */
    const char *raw64 = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";

    setenv("CDB_TEST_RAW_KEY", raw64, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_resolve_key("env://CDB_TEST_RAW_KEY", 0, NULL, NULL, key));
    /* 'z' == 0x7A: the first 32 raw bytes become the key. */
    TEST_ASSERT_EQUAL_HEX8(0x7A, key[0]);
    TEST_ASSERT_EQUAL_HEX8(0x7A, key[31]);
    unsetenv("CDB_TEST_RAW_KEY");
}

static void test_resolve_key_file_errors(void)
{
    uint8_t key[CDB_CRYPTO_KEY_SIZE];
    const char *missing = "file://" CDB_TEST_TMPDIR "/does_not_exist.key";
    const char *badpath = CDB_TEST_TMPDIR "/malformed.key";
    FILE *f;

    /* Missing file -> CDB_E_NOT_FOUND. */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_crypto_resolve_key(missing, 0, NULL, NULL, key));

    /* Short, non-key content -> CDB_E_MALFORMED. */
    f = fopen(badpath, "wb");
    TEST_ASSERT_NOT_NULL(f);
    fputs("abc\n", f);
    fclose(f);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED,
        cdb_crypto_resolve_key("file://" CDB_TEST_TMPDIR "/malformed.key", 0, NULL, NULL, key));
    remove(badpath);
}

/* ---- Subkey derivation and identity argument guards ---- */

static void test_subkey_arg_guards(void)
{
    uint8_t base[CDB_CRYPTO_KEY_SIZE];
    uint8_t out[CDB_CRYPTO_KEY_SIZE];
    uint8_t salt[CDB_SESSION_SALT_SIZE];

    memset(base, 0xA5, sizeof base);
    memset(salt, 0x01, sizeof salt);

    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_derive_subkey(NULL, CDB_SUBKEY_PAGE, NULL, out));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_derive_subkey(base, CDB_SUBKEY_PAGE, NULL, NULL));
    /* An out-of-range purpose is rejected. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_derive_subkey(base, (cdb_subkey_purpose)0, NULL, out));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_derive_subkey(base, (cdb_subkey_purpose)99, NULL, out));
    /* A salt is only valid for the page subkey. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_derive_subkey(base, CDB_SUBKEY_SEAL, salt, out));
}

static void test_identity_arg_guards(void)
{
    cdb_identity id;
    uint8_t sig[CDB_SIGNATURE_SIZE];
    uint8_t pub[CDB_IDENTITY_PUBKEY_SIZE];
    const char *msg = "msg";

    memset(sig, 0, sizeof sig);
    memset(pub, 0, sizeof pub);

    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_identity_generate(NULL, 1, 1));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_generate(&id, 1, 1));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_identity_sign(NULL, msg, 3, sig));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_identity_sign(&id, msg, 3, NULL));
    /* msg_len > 0 with NULL msg is rejected before any hashing. */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_identity_sign(&id, NULL, 3, sig));

    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_identity_verify(NULL, msg, 3, sig));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_identity_verify(pub, msg, 3, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_identity_verify(pub, NULL, 3, sig));
}

/* ---- Random bytes and nonce helpers ---- */

static void test_random_and_misc(void)
{
    uint8_t buf[16];

    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_random_bytes(NULL, sizeof buf));
    memset(buf, 0, sizeof buf);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_random_bytes(buf, sizeof buf));

    /* wipe of a NULL buffer / zero length is a safe no-op. */
    cdb_crypto_wipe(NULL, 16);
    cdb_crypto_wipe(buf, 0);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_aead_encrypt_arg_guards);
    RUN_TEST(test_aead_decrypt_arg_guards);
    RUN_TEST(test_streaming_sha256_matches_oneshot);
    RUN_TEST(test_streaming_hmac_matches_oneshot);
    RUN_TEST(test_streaming_hash_arg_guards);
    RUN_TEST(test_resolve_key_raw_fallback);
    RUN_TEST(test_resolve_key_file_errors);
    RUN_TEST(test_subkey_arg_guards);
    RUN_TEST(test_identity_arg_guards);
    RUN_TEST(test_random_and_misc);
    return UNITY_END();
}
