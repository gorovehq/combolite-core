/* Edge / error / branch coverage for the crypto module (spec 12): invalid-arg
 * guards, AEAD tamper + wrong-key failures, streaming hashes, every subkey
 * purpose + salt rules, the key-provider URI schemes (env/file/custom), raw vs
 * hex key parsing, unwrap failure, and identity verify failure. Complements
 * test_crypto.c (happy paths); drives cdb_crypto.c toward full coverage. */
#define _POSIX_C_SOURCE 200809L

#include "unity.h"
#include "combolite/cdb_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setUp(void) {}
void tearDown(void) {}

static const uint8_t KEY[CDB_CRYPTO_KEY_SIZE] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

static void test_aead_invalid_args(void)
{
    uint8_t nonce[CDB_AEAD_NONCE_SIZE] = {0};
    uint8_t ct[8], tag[CDB_AEAD_TAG_SIZE], pt[8] = {0};

    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
        cdb_crypto_aead_encrypt(CDB_AEAD_AES_256_GCM, NULL, nonce, NULL, 0, pt, sizeof pt, ct, tag));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
        cdb_crypto_aead_encrypt(CDB_AEAD_AES_256_GCM, KEY, NULL, NULL, 0, pt, sizeof pt, ct, tag));
    /* pt_len > 0 but no in/out buffer */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
        cdb_crypto_aead_encrypt(CDB_AEAD_AES_256_GCM, KEY, nonce, NULL, 0, NULL, 8, ct, tag));
    /* unsupported algorithm id */
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED,
        cdb_crypto_aead_encrypt(0xFFu, KEY, nonce, NULL, 0, pt, sizeof pt, ct, tag));
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED,
        cdb_crypto_aead_decrypt(0xFFu, KEY, nonce, NULL, 0, ct, sizeof ct, tag, pt));
}

static void test_aead_tamper_and_wrongkey(void)
{
    uint8_t nonce[CDB_AEAD_NONCE_SIZE];
    uint8_t ct[16], tag[CDB_AEAD_TAG_SIZE], out[16];
    const uint8_t pt[16] = { 0xDE, 0xAD, 0xBE, 0xEF, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    uint8_t wrong[CDB_CRYPTO_KEY_SIZE];
    unsigned alg;

    cdb_crypto_make_nonce(7, 42, nonce);
    memcpy(wrong, KEY, sizeof wrong);
    wrong[0] ^= 0xFF;

    for (alg = CDB_AEAD_AES_256_GCM; alg <= CDB_AEAD_CHACHA20_POLY1305; alg++) {
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_crypto_aead_encrypt(alg, KEY, nonce, NULL, 0, pt, sizeof pt, ct, tag));
        /* round trip */
        TEST_ASSERT_EQUAL_INT(CDB_OK,
            cdb_crypto_aead_decrypt(alg, KEY, nonce, NULL, 0, ct, sizeof ct, tag, out));
        TEST_ASSERT_EQUAL_MEMORY(pt, out, sizeof pt);
        /* tampered tag fails */
        tag[0] ^= 0x01;
        TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
            cdb_crypto_aead_decrypt(alg, KEY, nonce, NULL, 0, ct, sizeof ct, tag, out));
        tag[0] ^= 0x01;
        /* wrong key fails */
        TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
            cdb_crypto_aead_decrypt(alg, wrong, nonce, NULL, 0, ct, sizeof ct, tag, out));
    }
}

static void test_hash_streaming_matches_oneshot(void)
{
    const char *a = "hello, ";
    const char *b = "combolite";
    char whole[32];
    uint8_t one[CDB_CRYPTO_HASH_SIZE], stream[CDB_CRYPTO_HASH_SIZE];
    cdb_crypto_hash_ctx ctx;

    snprintf(whole, sizeof whole, "%s%s", a, b);

    /* plain SHA-256 streaming == one-shot */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_sha256(whole, strlen(whole), one));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_init(&ctx));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&ctx, a, strlen(a)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&ctx, b, strlen(b)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_final(&ctx, stream));
    cdb_crypto_hash_free(&ctx);
    TEST_ASSERT_EQUAL_MEMORY(one, stream, CDB_CRYPTO_HASH_SIZE);

    /* HMAC streaming == one-shot */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hmac_sha256(KEY, whole, strlen(whole), one));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_init_hmac(&ctx, KEY));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&ctx, a, strlen(a)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_update(&ctx, b, strlen(b)));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hash_final(&ctx, stream));
    cdb_crypto_hash_free(&ctx);
    TEST_ASSERT_EQUAL_MEMORY(one, stream, CDB_CRYPTO_HASH_SIZE);

    /* invalid args */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hash_init(NULL));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_sha256(NULL, 1, one));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_hmac_sha256(KEY, NULL, 1, one));
}

static void test_derive_subkey_purposes_and_salt(void)
{
    uint8_t salt[CDB_SESSION_SALT_SIZE];
    uint8_t page1[CDB_CRYPTO_KEY_SIZE], page2[CDB_CRYPTO_KEY_SIZE], integ[CDB_CRYPTO_KEY_SIZE];
    cdb_subkey_purpose p;

    memset(salt, 0xA5, sizeof salt);

    /* every purpose derives a key */
    for (p = CDB_SUBKEY_PAGE; p <= CDB_SUBKEY_REPL_NONCE; p++) {
        uint8_t k[CDB_CRYPTO_KEY_SIZE];
        const uint8_t *s = (p == CDB_SUBKEY_PAGE) ? salt : NULL;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_derive_subkey(KEY, p, s, k));
    }
    /* page subkey is salted and salt changes the result */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_derive_subkey(KEY, CDB_SUBKEY_PAGE, salt, page1));
    salt[0] ^= 0xFF;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_derive_subkey(KEY, CDB_SUBKEY_PAGE, salt, page2));
    TEST_ASSERT_TRUE(memcmp(page1, page2, CDB_CRYPTO_KEY_SIZE) != 0);
    /* integrity subkey differs from a page subkey */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_derive_subkey(KEY, CDB_SUBKEY_INTEGRITY, NULL, integ));
    TEST_ASSERT_TRUE(memcmp(page1, integ, CDB_CRYPTO_KEY_SIZE) != 0);

    /* salt is only valid for the page purpose */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
        cdb_crypto_derive_subkey(KEY, CDB_SUBKEY_INTEGRITY, salt, integ));
    /* unknown purpose + null args */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_derive_subkey(KEY, (cdb_subkey_purpose)999, NULL, integ));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_derive_subkey(NULL, CDB_SUBKEY_PAGE, salt, integ));
}

static void test_wrap_unwrap_and_failure(void)
{
    uint8_t master[CDB_CRYPTO_KEY_SIZE], enclave[CDB_CRYPTO_KEY_SIZE];
    uint8_t wrapped[CDB_WRAPPED_KEY_SIZE], out[CDB_CRYPTO_KEY_SIZE], wrong[CDB_CRYPTO_KEY_SIZE];

    memset(master, 0x11, sizeof master);
    memset(enclave, 0x77, sizeof enclave);
    memcpy(wrong, master, sizeof wrong);
    wrong[1] ^= 0xFF;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_wrap_key(master, enclave, wrapped));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_unwrap_key(master, wrapped, out));
    TEST_ASSERT_EQUAL_MEMORY(enclave, out, CDB_CRYPTO_KEY_SIZE);
    /* wrong master key fails authentication */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_crypto_unwrap_key(wrong, wrapped, out));
    /* invalid args */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_wrap_key(NULL, enclave, wrapped));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_unwrap_key(master, NULL, out));
}

static cdb_status fake_provider(const char *uri, uint8_t key_out[CDB_CRYPTO_KEY_SIZE], void *user_data)
{
    (void)uri;
    (void)user_data;
    memset(key_out, 0x5A, CDB_CRYPTO_KEY_SIZE);
    return CDB_OK;
}

static void test_resolve_key_schemes(void)
{
    uint8_t key[CDB_CRYPTO_KEY_SIZE];
    char path[] = "/tmp/cdb_edge_keyXXXXXX";
    int fd;
    const char *hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /* env:// hex */
    setenv("CDB_EDGE_K", hex, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_resolve_key("env://CDB_EDGE_K", 0, NULL, NULL, key));
    /* env:// missing var */
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_crypto_resolve_key("env://CDB_EDGE_MISSING", 0, NULL, NULL, key));
    /* env:// malformed (too short, not hex, not 32 raw) */
    setenv("CDB_EDGE_BAD", "short", 1);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_crypto_resolve_key("env://CDB_EDGE_BAD", 0, NULL, NULL, key));

    /* file:// refused in production, allowed (dev) otherwise */
    fd = mkstemp(path);
    TEST_ASSERT_TRUE(fd >= 0);
    TEST_ASSERT_EQUAL_INT((int)strlen(hex), (int)write(fd, hex, strlen(hex)));
    close(fd);
    {
        char uri[64];
        snprintf(uri, sizeof uri, "file://%s", path);
        TEST_ASSERT_EQUAL_INT(CDB_E_SECURITY, cdb_crypto_resolve_key(uri, 1, NULL, NULL, key));
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_resolve_key(uri, 0, NULL, NULL, key));
    }
    unlink(path);

    /* custom provider + unsupported scheme */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_resolve_key("vault://x", 0, fake_provider, NULL, key));
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED, cdb_crypto_resolve_key("vault://x", 0, NULL, NULL, key));
    /* invalid args */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_resolve_key(NULL, 0, NULL, NULL, key));
}

static void test_identity_sign_verify_failure(void)
{
    cdb_identity id;
    uint8_t sig[CDB_SIGNATURE_SIZE];
    const char *msg = "sign me";

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_generate(&id, 101, 7));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_sign(&id, msg, strlen(msg), sig));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_identity_verify(id.public_key, msg, strlen(msg), sig));
    /* tampered message fails */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_identity_verify(id.public_key, "sign ME", strlen(msg), sig));
    /* tampered signature fails */
    sig[0] ^= 0xFF;
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_identity_verify(id.public_key, msg, strlen(msg), sig));
    /* invalid args */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_identity_generate(NULL, 1, 1));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_identity_sign(NULL, msg, strlen(msg), sig));
}

static void test_random_and_wipe(void)
{
    uint8_t buf[32];
    memset(buf, 0, sizeof buf);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_random_bytes(buf, sizeof buf));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_crypto_random_bytes(NULL, 8));
    /* wipe clears */
    memset(buf, 0xFF, sizeof buf);
    cdb_crypto_wipe(buf, sizeof buf);
    {
        uint8_t zero[32] = {0};
        TEST_ASSERT_EQUAL_MEMORY(zero, buf, sizeof buf);
    }
    cdb_crypto_wipe(NULL, 0); /* no-op, must not crash */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_aead_invalid_args);
    RUN_TEST(test_aead_tamper_and_wrongkey);
    RUN_TEST(test_hash_streaming_matches_oneshot);
    RUN_TEST(test_derive_subkey_purposes_and_salt);
    RUN_TEST(test_wrap_unwrap_and_failure);
    RUN_TEST(test_resolve_key_schemes);
    RUN_TEST(test_identity_sign_verify_failure);
    RUN_TEST(test_random_and_wipe);
    return UNITY_END();
}
