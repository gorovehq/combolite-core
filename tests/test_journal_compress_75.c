/* #75 SLICE 1: delta-journal body compression.
 *
 * Mirrors the test_journal.c faultdev fixture. Exercises the journal layer
 * directly by setting the handle's codec_env/compress/page_size fields (the
 * same state cdb_db's journal_setup_codec fills in), so the on-disk record
 * size can be asserted inside the journal boundary.
 *
 * Coverage:
 *   AC1 a large compressible payload stores smaller than plaintext and
 *       round-trips (red->green: pre-slice it stores at full plaintext size);
 *   AC2 an incompressible / tiny payload stores raw (flag clear), never larger;
 *   AC3 with encryption a compressible payload round-trips through
 *       compress-then-encrypt and the on-disk body is encrypted AND smaller;
 *   AC4 a tampered compressed+encrypted record fails closed;
 *   AC5 an old-format (unflagged) record reads with no decompression;
 *   AC6 a record that claims compressed but cannot decompress fails closed;
 *   AC7 with no env allocator append falls open to raw (no hard dependency). */
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "combolite/cdb_crypto.h"
#include "combolite/cdb_env.h"
#include "cdb_codec.h"
#include "cdb_crc32c.h"
#include "cdb_endian.h"
#include "cdb_faultdev.h"
#include "cdb_journal.h"
#include "cdb_varint.h"

/* Red->green sentinel. The #75 slice adds CDB_RECORD_FLAG_BODY_CODEC to
 * cdb_journal.h together with the cdb_journal.codec_env/compress/page_size
 * fields. Detect the slice by that macro so this one test source COMPILES
 * against both the pre-slice tree (to demonstrate the documented RED: a
 * compressible payload is stored at full plaintext size, flag clear) and the
 * post-slice tree (GREEN: it is stored compressed and round-trips). Without
 * this guard the test references symbols absent on base and the red build is a
 * compile error, which the harness cannot score as a behavioral red. */
#ifdef CDB_RECORD_FLAG_BODY_CODEC
#define JC75_SLICE_PRESENT 1
#else
#define JC75_SLICE_PRESENT 0
/* Fallback so the flag-bit assertions still compile against base; the value
 * matches the slice's bit, and on base the bit is simply never set. */
#define CDB_RECORD_FLAG_BODY_CODEC 0x40u
#endif

#define CAP 65536u
#define RECORD_OFFSET CDB_JOURNAL_HEADER_SIZE /* the first record sits right after the header */

static uint8_t current[CAP], durable[CAP], log_data[CAP], buf[16384];
static cdb_fault_record log_records[64];
static cdb_faultdev dev;
static cdb_storage st;
static cdb_journal j;

/* A minimal env exposing only an allocator, so the journal's codec work memory
 * has somewhere to come from (as the real database env does). */
static void *t_alloc(void *ctx, size_t n)
{
    (void)ctx;
    return malloc(n);
}

static void t_free(void *ctx, void *p)
{
    (void)ctx;
    free(p);
}

static const cdb_env_ops codec_ops = {.alloc = t_alloc, .free = t_free};
static const cdb_env codec_env = {&codec_ops, NULL, NULL, NULL};

static cdb_journal_header jh(void)
{
    cdb_journal_header h;
    memset(&h, 0, sizeof h);
    h.type_id = CDB_COMPANION_MAIN_JOURNAL;
    memset(h.db_id, 0x5A, sizeof h.db_id);
    h.unsealed_seq = 7;
    h.first_seq = 1;
    return h;
}

void setUp(void)
{
    cdb_faultdev_config c;
    cdb_journal_header h = jh();
    memset(&c, 0, sizeof c);
    c.current = current;
    c.durable = durable;
    c.capacity = CAP;
    c.log = log_records;
    c.log_cap = 64;
    c.log_data = log_data;
    c.log_data_cap = CAP;
    c.geometry.program_unit = 1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_faultdev_init(&dev, &c, &st));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_journal_create(&j, &st, CDB_ORDER_LITTLE, &h));
}

void tearDown(void) {}

/* Turns on body compression on the live handle with the given env. On the
 * pre-slice tree the handle has no such fields: this is a no-op, so compression
 * stays off and the feature assertions below go RED. */
static void enable_compression(const cdb_env *env)
{
#if JC75_SLICE_PRESENT
    j.codec_env = env;
    j.compress = 1;
    j.page_size = 4096;
#else
    (void)env;
#endif
}

/* 4 KiB of a short repeating pattern: highly compressible. */
static void fill_compressible(uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        p[i] = (uint8_t)('A' + (i % 7));
}

/* A deterministic pseudo-random fill: not compressible (never saves 1/8). */
static void fill_incompressible(uint8_t *p, size_t n)
{
    uint32_t x = 0x1234567u;
    size_t i;
    for (i = 0; i < n; i++) {
        x = x * 1103515245u + 12345u;
        p[i] = (uint8_t)(x >> 24);
    }
}

/* The body_len field (bytes 4..7) of the record stored at offset. */
static uint32_t stored_body_len(uint64_t offset)
{
    uint8_t raw[CDB_RECORD_HEADER_SIZE];
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_storage_read(&j.st, offset, raw, sizeof raw));
    return cdb_load_u32(raw + 4, j.order);
}

/* The flags byte (byte 3) of the record stored at offset. */
static uint8_t stored_flags(uint64_t offset)
{
    uint8_t raw[CDB_RECORD_HEADER_SIZE];
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_storage_read(&j.st, offset, raw, sizeof raw));
    return raw[3];
}

static void append_plain(uint8_t flags, const uint8_t *payload, uint32_t len)
{
    cdb_record r;
    memset(&r, 0, sizeof r);
    r.kind = CDB_RECORD_DATA;
    r.flags = flags;
    r.tx_id = 3;
    r.store_id = 1;
    r.entry_id = 9;
    r.payload = payload;
    r.payload_len = len;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_journal_append(&j, &r, buf, sizeof buf));
}

/* AC1: a compressible payload is stored smaller than plaintext and round-trips.
 * Red->green: against the pre-slice code body_len == plaintext length and the
 * flag is clear, so both the "smaller" and "flag set" assertions fail. */
static void test_compressible_payload_stored_smaller_and_roundtrips(void)
{
    uint8_t payload[4096];
    cdb_record r;
    uint64_t next;
    if (!cdb_codec_available(CDB_CODEC_LZMA2))
        TEST_IGNORE_MESSAGE("LZMA2 codec not built");
    fill_compressible(payload, sizeof payload);
    enable_compression(&codec_env);
    append_plain(0, payload, sizeof payload);

    TEST_ASSERT_TRUE(stored_flags(RECORD_OFFSET) & CDB_RECORD_FLAG_BODY_CODEC);
    TEST_ASSERT_TRUE(stored_body_len(RECORD_OFFSET) < sizeof payload);

    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_journal_read(&j, RECORD_OFFSET, buf, sizeof buf, &r, &next));
    TEST_ASSERT_EQUAL_UINT32(sizeof payload, r.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, r.payload, sizeof payload);
    /* The returned view is plaintext: the codec flag is cleared. */
    TEST_ASSERT_FALSE(r.flags & CDB_RECORD_FLAG_BODY_CODEC);
}

/* AC2: incompressible and tiny payloads stay raw (flag clear, never larger)
 * and round-trip byte-for-byte. */
static void test_incompressible_payload_stored_raw_roundtrips(void)
{
    uint8_t payload[4096];
    const uint8_t tiny[2] = {0x7Fu, 0x42u};
    cdb_record r;
    uint64_t next;
    enable_compression(&codec_env);

    fill_incompressible(payload, sizeof payload);
    append_plain(0, payload, sizeof payload);
    TEST_ASSERT_FALSE(stored_flags(RECORD_OFFSET) & CDB_RECORD_FLAG_BODY_CODEC);
    TEST_ASSERT_EQUAL_UINT32(sizeof payload, stored_body_len(RECORD_OFFSET));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_journal_read(&j, RECORD_OFFSET, buf, sizeof buf, &r, &next));
    TEST_ASSERT_EQUAL_UINT32(sizeof payload, r.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, r.payload, sizeof payload);

    /* A tiny payload is below the worth-trying threshold: also stored raw. */
    append_plain(0, tiny, sizeof tiny);
    TEST_ASSERT_FALSE(stored_flags(next) & CDB_RECORD_FLAG_BODY_CODEC);
    TEST_ASSERT_EQUAL_UINT32(sizeof tiny, stored_body_len(next));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_journal_read(&j, next, buf, sizeof buf, &r, &next));
    TEST_ASSERT_EQUAL_UINT32(sizeof tiny, r.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(tiny, r.payload, sizeof tiny);
}

/* AC3: with encryption a compressible payload round-trips through
 * compress-then-encrypt; the stored body is encrypted (not the plaintext) AND
 * smaller than plaintext (compression happened before encryption). */
static void test_crypto_compress_roundtrip_smaller_and_encrypted(void)
{
    uint8_t payload[4096], body[4096];
    cdb_record r, rr;
    uint64_t next;
    uint8_t key[32];
    uint32_t body_len;
    if (!cdb_codec_available(CDB_CODEC_LZMA2))
        TEST_IGNORE_MESSAGE("LZMA2 codec not built");
    memset(key, 0x33, sizeof key);
    fill_compressible(payload, sizeof payload);
    enable_compression(&codec_env);

    memset(&r, 0, sizeof r);
    r.kind = CDB_RECORD_DATA;
    r.flags = CDB_RECORD_FLAG_ENCRYPTED;
    r.tx_id = 5;
    r.store_id = 10;
    r.entry_id = 101;
    r.domain_id = 42;
    r.payload = payload;
    r.payload_len = sizeof payload;
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_journal_append_crypto(&j, &r, buf, sizeof buf, CDB_AEAD_AES_256_GCM, key));

    body_len = stored_body_len(RECORD_OFFSET);
    TEST_ASSERT_TRUE(body_len < sizeof payload); /* compressed before encryption */
    /* The stored body is ciphertext, not the plaintext payload. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_storage_read(&j.st, RECORD_OFFSET + CDB_RECORD_HEADER_SIZE,
                                                   body, body_len));
    TEST_ASSERT_TRUE(memcmp(body, payload, body_len) != 0);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_journal_read_crypto(&j, RECORD_OFFSET, buf, sizeof buf, &rr,
                                                          &next, CDB_AEAD_AES_256_GCM, key));
    TEST_ASSERT_EQUAL_UINT32(sizeof payload, rr.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, rr.payload, sizeof payload);
    TEST_ASSERT_EQUAL_UINT64(10, rr.store_id);
    TEST_ASSERT_EQUAL_UINT64(101, rr.entry_id);
    TEST_ASSERT_EQUAL_UINT64(42, rr.domain_id);
}

/* AC4: a tampered compressed+encrypted record fails closed on read. */
static void test_tampered_crypto_compressed_fails_closed(void)
{
    uint8_t payload[4096];
    cdb_record r, rr;
    uint64_t next;
    uint8_t key[32];
    cdb_status s;
    if (!cdb_codec_available(CDB_CODEC_LZMA2))
        TEST_IGNORE_MESSAGE("LZMA2 codec not built");
    memset(key, 0x55, sizeof key);
    fill_compressible(payload, sizeof payload);
    enable_compression(&codec_env);

    memset(&r, 0, sizeof r);
    r.kind = CDB_RECORD_DATA;
    r.flags = CDB_RECORD_FLAG_ENCRYPTED;
    r.tx_id = 6;
    r.store_id = 11;
    r.entry_id = 102;
    r.domain_id = 42;
    r.payload = payload;
    r.payload_len = sizeof payload;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_journal_append_crypto(&j, &r, buf, sizeof buf,
                                                            CDB_AEAD_CHACHA20_POLY1305, key));

    /* Flip one byte of the stored (compressed-then-encrypted) body. */
    current[RECORD_OFFSET + CDB_RECORD_HEADER_SIZE + 1] ^= 0xFFu;

    s = cdb_journal_read_crypto(&j, RECORD_OFFSET, buf, sizeof buf, &rr, &next,
                                CDB_AEAD_CHACHA20_POLY1305, key);
    TEST_ASSERT_TRUE(s == CDB_E_CORRUPT || s == CDB_E_SECURITY);
}

/* AC5: an old-format record (flag clear, payload stored raw) reads correctly
 * with no decompression attempted. */
static void test_unflagged_record_reads_without_decompress(void)
{
    uint8_t payload[4096];
    cdb_record r;
    uint64_t next;
    fill_compressible(payload, sizeof payload);
    /* Compression disabled: the record is written raw, flag clear, as before.
     * (On base the fields are absent; the default is already "raw", so this AC
     * is correctly green on both trees — it proves back-compat, not the feature.) */
#if JC75_SLICE_PRESENT
    j.codec_env = &codec_env;
    j.compress = 0;
    j.page_size = 4096;
#endif
    append_plain(0, payload, sizeof payload);

    TEST_ASSERT_FALSE(stored_flags(RECORD_OFFSET) & CDB_RECORD_FLAG_BODY_CODEC);
    TEST_ASSERT_EQUAL_UINT32(sizeof payload, stored_body_len(RECORD_OFFSET));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_journal_read(&j, RECORD_OFFSET, buf, sizeof buf, &r, &next));
    TEST_ASSERT_EQUAL_UINT32(sizeof payload, r.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, r.payload, sizeof payload);
}

/* AC6: a record marked compressed whose body cannot decompress (here a stated
 * plaintext length past the bomb-guard ceiling) fails closed with CDB_E_CORRUPT.
 * The record is hand-built with a valid CRC so the guard, not the CRC, rejects
 * it. */
static void test_claims_compressed_but_corrupt_fails_closed(void)
{
    uint8_t rec[128];
    uint8_t vbuf[CDB_VARINT_MAX_LEN];
    cdb_record r;
    uint64_t next;
    size_t vn, size;
    uint32_t body_len;

    memset(rec, 0, sizeof rec);
    /* A varint stating a plaintext length far beyond the bomb-guard ceiling. */
    vn = cdb_varint_encode((uint64_t)0x7FFFFFFFu, vbuf);
    body_len = (uint32_t)vn;
    size = CDB_RECORD_HEADER_SIZE + body_len + CDB_RECORD_TRAILER_SIZE;

    rec[0] = 0xC0u;
    rec[1] = 0xDEu;
    rec[2] = CDB_RECORD_DATA;
    rec[3] = CDB_RECORD_FLAG_BODY_CODEC; /* claims compressed, flag only */
    cdb_store_u32(rec + 4, body_len, j.order);
    cdb_store_u64(rec + 8, 1, j.order);  /* seq */
    cdb_store_u64(rec + 24, 1, j.order); /* store_id */
    cdb_store_u64(rec + 32, 9, j.order); /* entry_id */
    memcpy(rec + CDB_RECORD_HEADER_SIZE, vbuf, vn);
    cdb_store_u32(rec + size - CDB_RECORD_TRAILER_SIZE,
                  cdb_crc32c(rec, size - CDB_RECORD_TRAILER_SIZE), j.order);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_storage_program(&j.st, RECORD_OFFSET, rec, size));

#if JC75_SLICE_PRESENT
    j.codec_env = &codec_env;
    j.compress = 1;
    j.page_size = 4096;
    /* Post-slice: the 0x40 flag drives decompression, which fails closed on a
     * stated plaintext length past the bomb-guard ceiling (CDB_E_CORRUPT). */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_journal_read(&j, RECORD_OFFSET, buf, sizeof buf, &r, &next));
#else
    /* Pre-slice: read ignores the (unknown) 0x40 flag and returns the body raw
     * with CDB_OK, so the fail-closed assertion is RED until the slice lands. */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_journal_read(&j, RECORD_OFFSET, buf, sizeof buf, &r, &next));
#endif
}

/* AC7: with no env allocator, append falls open to an uncompressed record
 * (flag clear) that still round-trips: the slice adds no hard env dependency. */
static void test_no_codec_or_env_falls_open(void)
{
    uint8_t payload[4096];
    cdb_record r;
    uint64_t next;
    fill_compressible(payload, sizeof payload);
    /* Compression requested, but no env allocator is wired (fail open). On base
     * the fields are absent; append is raw regardless, so this AC is green on
     * both trees — it proves the slice adds no hard env dependency. */
#if JC75_SLICE_PRESENT
    j.codec_env = NULL;
    j.compress = 1;
    j.page_size = 4096;
#endif
    append_plain(0, payload, sizeof payload);

    TEST_ASSERT_FALSE(stored_flags(RECORD_OFFSET) & CDB_RECORD_FLAG_BODY_CODEC);
    TEST_ASSERT_EQUAL_UINT32(sizeof payload, stored_body_len(RECORD_OFFSET));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_journal_read(&j, RECORD_OFFSET, buf, sizeof buf, &r, &next));
    TEST_ASSERT_EQUAL_UINT32(sizeof payload, r.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, r.payload, sizeof payload);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_compressible_payload_stored_smaller_and_roundtrips);
    RUN_TEST(test_incompressible_payload_stored_raw_roundtrips);
    RUN_TEST(test_crypto_compress_roundtrip_smaller_and_encrypted);
    RUN_TEST(test_tampered_crypto_compressed_fails_closed);
    RUN_TEST(test_unflagged_record_reads_without_decompress);
    RUN_TEST(test_claims_compressed_but_corrupt_fails_closed);
    RUN_TEST(test_no_codec_or_env_falls_open);
    return UNITY_END();
}
