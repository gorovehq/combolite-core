#include <string.h>

#include "unity.h"
#include "combolite/cdb_crypto.h"
#include "cdb_crc32c.h"
#include "cdb_endian.h"
#include "cdb_page.h"

void setUp(void) {}
void tearDown(void) {}

static cdb_page_header sample(void)
{
    cdb_page_header h;
    memset(&h, 0, sizeof h);
    h.type = CDB_PAGE_TYPE_DATA_TEST;
    h.layout_version = 1;
    h.flags = 0x02;
    h.key_version = 3;
    h.payload_len = 5;
    h.write_seq = UINT64_C(0x0102030405060708);
    h.logical_id = 1234;
    h.store_id = 7;
    h.domain_id = 9;
    h.extent_pos = 2;
    return h;
}

static void roundtrip(cdb_page_format fmt, size_t page_size, cdb_byte_order order)
{
    static uint8_t page[4096];
    cdb_page_header h = sample(), back;
    memset(page, 0, page_size);
    memcpy(page + cdb_page_payload_offset(fmt), "hello", 5);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_seal(page, page_size, fmt, order, CDB_CHECKSUM_CRC32C, &h));
    TEST_ASSERT_EQUAL_HEX8(0xC0, page[0]);
    TEST_ASSERT_EQUAL_HEX8(0xDB, page[1]);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_open(page, page_size, fmt, order, CDB_CHECKSUM_CRC32C, &back));
    TEST_ASSERT_EQUAL_UINT16(h.type, back.type);
    TEST_ASSERT_EQUAL_UINT64(h.write_seq, back.write_seq);
    TEST_ASSERT_EQUAL_UINT64(h.logical_id, back.logical_id);
    TEST_ASSERT_EQUAL_UINT64(h.store_id, back.store_id);
    TEST_ASSERT_EQUAL_UINT64(h.domain_id, back.domain_id);
    TEST_ASSERT_EQUAL_UINT32(h.payload_len, back.payload_len);
    TEST_ASSERT_EQUAL_UINT16(h.extent_pos, back.extent_pos);
    TEST_ASSERT_EQUAL_MEMORY("hello", page + cdb_page_payload_offset(fmt), 5);
}

static void test_sizes(void)
{
    TEST_ASSERT_EQUAL_size_t(56, cdb_page_header_size(CDB_PAGE_FMT_FULL64));
    TEST_ASSERT_EQUAL_size_t(40, cdb_page_header_size(CDB_PAGE_FMT_FULL32));
    TEST_ASSERT_EQUAL_size_t(28, cdb_page_header_size(CDB_PAGE_FMT_COMPACT));
    /* The store ID slot is the format's ID width (spec 14.2.7). */
    TEST_ASSERT_EQUAL_size_t(64, cdb_page_payload_offset(CDB_PAGE_FMT_FULL64));
    TEST_ASSERT_EQUAL_size_t(44, cdb_page_payload_offset(CDB_PAGE_FMT_FULL32));
    TEST_ASSERT_EQUAL_size_t(30, cdb_page_payload_offset(CDB_PAGE_FMT_COMPACT));
    TEST_ASSERT_EQUAL_size_t(4096 - 80, cdb_page_capacity(CDB_PAGE_FMT_FULL64, 4096));
    TEST_ASSERT_EQUAL_size_t(1024 - 60, cdb_page_capacity(CDB_PAGE_FMT_FULL32, 1024));
    TEST_ASSERT_EQUAL_size_t(512 - 38, cdb_page_capacity(CDB_PAGE_FMT_COMPACT, 512));
    TEST_ASSERT_EQUAL_size_t(0, cdb_page_capacity(CDB_PAGE_FMT_COMPACT, 2048)); /* compact is for small pages */
}

static void test_roundtrips(void)
{
    roundtrip(CDB_PAGE_FMT_FULL64, 4096, CDB_ORDER_LITTLE);
    roundtrip(CDB_PAGE_FMT_FULL64, 512, CDB_ORDER_BIG);
    roundtrip(CDB_PAGE_FMT_FULL32, 1024, CDB_ORDER_LITTLE);
    roundtrip(CDB_PAGE_FMT_COMPACT, 512, CDB_ORDER_BIG);
}

static void test_detects_damage(void)
{
    static uint8_t page[1024];
    cdb_page_header h = sample(), back;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_seal(page, sizeof page, CDB_PAGE_FMT_FULL64, CDB_ORDER_LITTLE,
                                                CDB_CHECKSUM_CRC32C, &h));
    page[300] ^= 0x01; /* payload */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_page_open(page, sizeof page, CDB_PAGE_FMT_FULL64,
                                                       CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C, &back));
    page[300] ^= 0x01;
    page[30] ^= 0x80; /* header */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_page_open(page, sizeof page, CDB_PAGE_FMT_FULL64,
                                                       CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C, &back));
}

static void test_overflow_in_narrow_formats(void)
{
    static uint8_t page[512];
    cdb_page_header h = sample();
    h.logical_id = 70000; /* does not fit in 16 bits */
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_page_seal(page, sizeof page, CDB_PAGE_FMT_COMPACT,
                                                        CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C, &h));
    h = sample();
    h.store_id = UINT64_C(1) << 32;
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_page_seal(page, sizeof page, CDB_PAGE_FMT_FULL32,
                                                        CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C, &h));
    h = sample();
    h.payload_len = 1000;
    TEST_ASSERT_EQUAL_INT(CDB_E_OVERFLOW, cdb_page_seal(page, sizeof page, CDB_PAGE_FMT_FULL64,
                                                        CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C, &h));
}

static void test_unknown_checksum(void)
{
    static uint8_t page[512];
    cdb_page_header h = sample();
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED, cdb_page_seal(page, sizeof page, CDB_PAGE_FMT_FULL64,
                                                           CDB_ORDER_LITTLE, 9, &h));
}

static void test_encrypted_page_roundtrip(void)
{
    static uint8_t page[4096];
    uint8_t key[32];
    cdb_page_header h = sample(), back;
    size_t hsize = cdb_page_payload_offset(CDB_PAGE_FMT_FULL64);

    memset(key, 0x88, sizeof(key));
    memset(page, 0, sizeof(page));
    h.domain_id = 42; /* Encrypted enclave domain */
    h.salt_index = 1;
    h.write_seq = 1001;
    memcpy(page + hsize, "Super secret database enclave payload bytes", 43);
    h.payload_len = 43;

    /* Seal with AES-256-GCM */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_seal_crypto(page, sizeof(page), CDB_PAGE_FMT_FULL64,
                                                      CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C,
                                                      CDB_AEAD_AES_256_GCM, key, CDB_TRACK_ARCHIVE_PAGE, &h));

    /* Ciphertext must not match original plaintext */
    TEST_ASSERT_NOT_EQUAL(0, memcmp(page + hsize, "Super secret database enclave payload bytes", 43));

    /* Open and decrypt */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_open_crypto(page, sizeof(page), CDB_PAGE_FMT_FULL64,
                                                      CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C,
                                                      CDB_AEAD_AES_256_GCM, key, CDB_TRACK_ARCHIVE_PAGE, &back));
    TEST_ASSERT_EQUAL_UINT64(42, back.domain_id);
    TEST_ASSERT_EQUAL_UINT64(7, back.store_id); /* from the encrypted slot */
    TEST_ASSERT_EQUAL_MEMORY("Super secret database enclave payload bytes", page + hsize, 43);

    /* Wrong key fails */
    key[0] ^= 0x01;
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_page_open_crypto(page, sizeof(page), CDB_PAGE_FMT_FULL64,
                                                             CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C,
                                                             CDB_AEAD_AES_256_GCM, key, CDB_TRACK_ARCHIVE_PAGE, &back));
    key[0] ^= 0x01;

    /* Seal with ChaCha20-Poly1305 */
    memcpy(page + hsize, "ChaCha encrypted page", 21);
    h.payload_len = 21;
    h.write_seq = 1002;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_seal_crypto(page, sizeof(page), CDB_PAGE_FMT_FULL64,
                                                      CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C,
                                                      CDB_AEAD_CHACHA20_POLY1305, key, CDB_TRACK_ARCHIVE_PAGE, &h));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_open_crypto(page, sizeof(page), CDB_PAGE_FMT_FULL64,
                                                      CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C,
                                                      CDB_AEAD_CHACHA20_POLY1305, key, CDB_TRACK_ARCHIVE_PAGE, &back));
    TEST_ASSERT_EQUAL_MEMORY("ChaCha encrypted page", page + hsize, 21);
}

static void test_tamper_evident_page_roundtrip(void)
{
    static uint8_t page[4096];
    uint8_t integrity_key[32];
    cdb_page_header h = sample(), back;
    size_t hsize = cdb_page_payload_offset(CDB_PAGE_FMT_FULL64);

    memset(integrity_key, 0x55, sizeof(integrity_key));
    memset(page, 0, sizeof(page));
    h.domain_id = 0; /* Public page */
    h.flags |= CDB_PAGE_FLAG_TAMPER_EVIDENT;
    memcpy(page + hsize, "Public governance page content", 30);
    h.payload_len = 30;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_seal_crypto(page, sizeof(page), CDB_PAGE_FMT_FULL64,
                                                      CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C,
                                                      CDB_AEAD_NONE, integrity_key, CDB_TRACK_ARCHIVE_PAGE, &h));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_open_crypto(page, sizeof(page), CDB_PAGE_FMT_FULL64,
                                                      CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C,
                                                      CDB_AEAD_NONE, integrity_key, CDB_TRACK_ARCHIVE_PAGE, &back));
    TEST_ASSERT_TRUE(back.flags & CDB_PAGE_FLAG_TAMPER_EVIDENT);
    TEST_ASSERT_EQUAL_MEMORY("Public governance page content", page + hsize, 30);

    /* Tampering with page body is detected */
    page[hsize + 5] ^= 0x01;
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_page_open_crypto(page, sizeof(page), CDB_PAGE_FMT_FULL64,
                                                             CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C,
                                                             CDB_AEAD_NONE, integrity_key, CDB_TRACK_ARCHIVE_PAGE, &back));
}

/* The slot repeats a public page's store; a page whose header and slot
 * disagree is corrupt, and the on-disk length counts the slot. */
static void test_store_slot_public(void)
{
    static uint8_t page[1024];
    cdb_page_header h = sample(), back;
    size_t ts = cdb_page_trailer_size(CDB_PAGE_FMT_FULL64);

    memset(page, 0, sizeof page);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_seal(page, sizeof page, CDB_PAGE_FMT_FULL64, CDB_ORDER_LITTLE,
                                                CDB_CHECKSUM_CRC32C, &h));
    TEST_ASSERT_EQUAL_UINT64(7, cdb_load_u64(page + 32, CDB_ORDER_LITTLE)); /* header store */
    TEST_ASSERT_EQUAL_UINT64(7, cdb_load_u64(page + 56, CDB_ORDER_LITTLE)); /* slot */
    TEST_ASSERT_EQUAL_UINT32(5 + 8, cdb_load_u32(page + 12, CDB_ORDER_LITTLE));

    cdb_store_u64(page + 56, 8, CDB_ORDER_LITTLE); /* a slot that disagrees, checksum still good */
    cdb_store_u32(page + sizeof page - ts, cdb_crc32c(page, sizeof page - ts), CDB_ORDER_LITTLE);
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT, cdb_page_open(page, sizeof page, CDB_PAGE_FMT_FULL64,
                                                       CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C, &back));
}

/* An encrypted page's header holds store 0 and the salt index; a public page
 * naming a salt is malformed; compact files refuse encryption for now. */
static void test_store_slot_hidden_and_salt(void)
{
    static uint8_t page[1024];
    uint8_t key[32];
    cdb_page_header h = sample(), back;
    size_t ts = cdb_page_trailer_size(CDB_PAGE_FMT_FULL64);

    memset(key, 0x31, sizeof key);
    memset(page, 0, sizeof page);
    h.domain_id = 42;
    h.salt_index = 3;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_seal_crypto(page, sizeof page, CDB_PAGE_FMT_FULL64, CDB_ORDER_BIG,
                                                      CDB_CHECKSUM_CRC32C, CDB_AEAD_AES_256_GCM, key, CDB_TRACK_ARCHIVE_PAGE, &h));
    TEST_ASSERT_EQUAL_UINT64(0, cdb_load_u64(page + 32, CDB_ORDER_BIG));
    TEST_ASSERT_EQUAL_UINT16(3, cdb_load_u16(page + 50, CDB_ORDER_BIG));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_peek(page, sizeof page, CDB_PAGE_FMT_FULL64, CDB_ORDER_BIG, &back));
    TEST_ASSERT_EQUAL_UINT64(0, back.store_id);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_open_crypto(page, sizeof page, CDB_PAGE_FMT_FULL64, CDB_ORDER_BIG,
                                                      CDB_CHECKSUM_CRC32C, CDB_AEAD_AES_256_GCM, key, CDB_TRACK_ARCHIVE_PAGE, &back));
    TEST_ASSERT_EQUAL_UINT64(7, back.store_id);
    TEST_ASSERT_EQUAL_UINT16(3, back.salt_index);

    /* Sealing refuses a public page with a salt or an encrypted one without;
     * a public page given one on disk is malformed. */
    h = sample();
    h.salt_index = 3;
    memset(page, 0, sizeof page);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_page_seal(page, sizeof page, CDB_PAGE_FMT_FULL64, CDB_ORDER_LITTLE,
                                                           CDB_CHECKSUM_CRC32C, &h));
    h.salt_index = 0;
    h.domain_id = 42;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_page_seal_crypto(page, sizeof page, CDB_PAGE_FMT_FULL64,
                                                                  CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C,
                                                                  CDB_AEAD_AES_256_GCM, key,
                                                                  CDB_TRACK_ARCHIVE_PAGE, &h));
    h = sample();
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_seal(page, sizeof page, CDB_PAGE_FMT_FULL64, CDB_ORDER_LITTLE,
                                                CDB_CHECKSUM_CRC32C, &h));
    cdb_store_u16(page + 50, 3, CDB_ORDER_LITTLE);
    cdb_store_u32(page + sizeof page - ts, cdb_crc32c(page, sizeof page - ts), CDB_ORDER_LITTLE);
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_page_open(page, sizeof page, CDB_PAGE_FMT_FULL64,
                                                         CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C, &back));

    h = sample();
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED, cdb_page_seal_crypto(page, 512, CDB_PAGE_FMT_COMPACT, CDB_ORDER_LITTLE,
                                                                  CDB_CHECKSUM_CRC32C, CDB_AEAD_AES_256_GCM,
                                                                  key, CDB_TRACK_ARCHIVE_PAGE, &h));
}

/* #72 CR5 Slice A (AC6): the on-disk marker identifies an encrypted page by
 * its domain_id and salt index, a legacy plaintext page (domain 0, no salt)
 * still opens, and an encrypted page that is downgraded or whose tag fails
 * fails closed with no silent plaintext fallback. */
static void test_page_marker_version_compat(void)
{
    static uint8_t page[1024];
    static uint8_t downgraded[1024];
    uint8_t key[32];
    cdb_page_header h, back;
    size_t hsize = cdb_page_payload_offset(CDB_PAGE_FMT_FULL64);
    const char *secret = "enclave-marked-page";

    memset(key, 0x5A, sizeof key);

    /* A legacy plaintext page: domain 0, no salt; opens and reads as before. */
    h = sample();
    h.domain_id = 0;
    h.salt_index = 0;
    memset(page, 0, sizeof page);
    memcpy(page + hsize, "legacy", 6);
    h.payload_len = 6;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_seal(page, sizeof page, CDB_PAGE_FMT_FULL64,
                                                CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C, &h));
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_page_peek(page, sizeof page, CDB_PAGE_FMT_FULL64, CDB_ORDER_LITTLE, &back));
    TEST_ASSERT_EQUAL_UINT64(0, back.domain_id);
    TEST_ASSERT_EQUAL_UINT16(0, back.salt_index); /* plaintext marker */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_open(page, sizeof page, CDB_PAGE_FMT_FULL64,
                                                CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C, &back));
    TEST_ASSERT_EQUAL_MEMORY("legacy", page + hsize, 6);

    /* An encrypted page: domain != 0 with a salt index; identifiable by peek
     * alone, and its store is hidden behind the encryption. */
    h = sample();
    h.domain_id = 42;
    h.salt_index = 1;
    h.write_seq = 7;
    memset(page, 0, sizeof page);
    memcpy(page + hsize, secret, strlen(secret));
    h.payload_len = (uint32_t)strlen(secret);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_seal_crypto(page, sizeof page, CDB_PAGE_FMT_FULL64,
                                                       CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C,
                                                       CDB_AEAD_AES_256_GCM, key,
                                                       CDB_TRACK_ARCHIVE_PAGE, &h));
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_page_peek(page, sizeof page, CDB_PAGE_FMT_FULL64, CDB_ORDER_LITTLE, &back));
    TEST_ASSERT_EQUAL_UINT64(42, back.domain_id);
    TEST_ASSERT_NOT_EQUAL(0, back.salt_index);  /* encrypted marker */
    TEST_ASSERT_EQUAL_UINT64(0, back.store_id); /* store hidden behind the encryption */
    TEST_ASSERT_NOT_EQUAL(0, memcmp(page + hsize, secret, strlen(secret))); /* ciphertext */

    /* Downgrade: zero the salt marker to coax a plaintext read. Fails closed
     * (malformed) and never returns plaintext. */
    memcpy(downgraded, page, sizeof downgraded);
    cdb_store_u16(downgraded + 50, 0, CDB_ORDER_LITTLE); /* the salt_index field (spec 14.2.8) */
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED,
                          cdb_page_open_crypto(downgraded, sizeof downgraded, CDB_PAGE_FMT_FULL64,
                                               CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C,
                                               CDB_AEAD_AES_256_GCM, key, CDB_TRACK_ARCHIVE_PAGE,
                                               &back));

    /* Tamper the ciphertext: fails closed (auth failure); no plaintext. The
     * codec reports it as CDB_E_CORRUPT — the pager layer elevates an enclave
     * page's auth failure to CDB_E_SECURITY at its trust boundary (ADR-002). */
    page[hsize + 2] ^= 0x40;
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_page_open_crypto(page, sizeof page, CDB_PAGE_FMT_FULL64,
                                               CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C,
                                               CDB_AEAD_AES_256_GCM, key, CDB_TRACK_ARCHIVE_PAGE,
                                               &back));
    TEST_ASSERT_NOT_EQUAL(0, memcmp(page + hsize, secret, strlen(secret))); /* no plaintext */
}

/* #72 CR5 Slice A (AC7): the compact format's 8-byte trailer cannot hold a
 * 16-byte AEAD tag, so a compact enclave page is refused (CDB_E_UNSUPPORTED),
 * never written unprotected; the full format encrypts. Compact-page enclave
 * encryption is deferred (see cdb_page.c protection(), docs/BACKLOG.md). */
static void test_compact_enclave_encrypt_refused(void)
{
    static uint8_t page[512];
    uint8_t key[32];
    cdb_page_header h;

    memset(key, 0x11, sizeof key);

    h = sample();
    h.domain_id = 42;
    h.salt_index = 1;
    h.payload_len = 4;
    memset(page, 0, sizeof page);
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED,
                          cdb_page_seal_crypto(page, sizeof page, CDB_PAGE_FMT_COMPACT,
                                               CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C,
                                               CDB_AEAD_AES_256_GCM, key, CDB_TRACK_ARCHIVE_PAGE,
                                               &h));

    /* The same enclave page in the full format encrypts fine. */
    h = sample();
    h.domain_id = 42;
    h.salt_index = 1;
    h.payload_len = 4;
    memset(page, 0, sizeof page);
    memcpy(page + cdb_page_payload_offset(CDB_PAGE_FMT_FULL64), "ok!!", 4);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_page_seal_crypto(page, sizeof page, CDB_PAGE_FMT_FULL64,
                                                       CDB_ORDER_LITTLE, CDB_CHECKSUM_CRC32C,
                                                       CDB_AEAD_AES_256_GCM, key,
                                                       CDB_TRACK_ARCHIVE_PAGE, &h));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_sizes);
    RUN_TEST(test_roundtrips);
    RUN_TEST(test_detects_damage);
    RUN_TEST(test_overflow_in_narrow_formats);
    RUN_TEST(test_unknown_checksum);
    RUN_TEST(test_encrypted_page_roundtrip);
    RUN_TEST(test_tamper_evident_page_roundtrip);
    RUN_TEST(test_store_slot_public);
    RUN_TEST(test_store_slot_hidden_and_salt);
    RUN_TEST(test_page_marker_version_compat);
    RUN_TEST(test_compact_enclave_encrypt_refused);
    return UNITY_END();
}
