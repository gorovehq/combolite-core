/* Golden / known-answer tests (KAT) for the crypto artifact (critical path):
 * fixed input -> fixed expected output, to catch any silent change in the
 * primitives. SHA-256 vectors are the published standard (external validation);
 * the HMAC vector is a captured reference (regression golden). Spec 12 (crypto). */
#include "unity.h"
#include "combolite/cdb_crypto.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* FIPS 180-4 / standard SHA-256 test vectors. */
static void test_sha256_known_answers(void)
{
    uint8_t h[CDB_CRYPTO_HASH_SIZE];
    /* SHA-256("abc") */
    static const uint8_t abc[CDB_CRYPTO_HASH_SIZE] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_sha256("abc", 3, h));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(abc, h, CDB_CRYPTO_HASH_SIZE);
    /* SHA-256("") */
    static const uint8_t empty[CDB_CRYPTO_HASH_SIZE] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55 };
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_sha256("", 0, h));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(empty, h, CDB_CRYPTO_HASH_SIZE);
}

/* HMAC-SHA256 with a fixed 32-byte key (0x11 repeated) over "abc": captured
 * reference golden -- any change in the HMAC path is caught. */
static void test_hmac_sha256_golden(void)
{
    uint8_t key[CDB_CRYPTO_KEY_SIZE];
    uint8_t mac[CDB_CRYPTO_HASH_SIZE];
    static const uint8_t want[CDB_CRYPTO_HASH_SIZE] = {
        0x80,0x94,0xa4,0xaa,0x03,0x11,0xce,0xad,0xd6,0x2b,0xd4,0xb1,0x7f,0xa7,0x6c,0xb0,
        0x06,0x6c,0xff,0x4f,0x12,0x5c,0xbf,0xc6,0x4d,0xea,0x5b,0xab,0x24,0x93,0xf2,0xcd };
    memset(key, 0x11, sizeof key);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_crypto_hmac_sha256(key, (const uint8_t *)"abc", 3, mac));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, mac, CDB_CRYPTO_HASH_SIZE);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_sha256_known_answers);
    RUN_TEST(test_hmac_sha256_golden);
    return UNITY_END();
}
