/* Delta journal (spec 14.4).
 *
 * This module only reads and writes the bytes of one journal file. It does
 * not decide when to sync, which journal to replay, or what a record means;
 * cdb_db does that. Records are written with storage "program" calls
 * (write without a barrier), so a record is durable only after the caller's
 * next sync. A crash can therefore leave a torn last record, which readers
 * detect by its marker, length or CRC and treat as the end of the journal. */
#include <string.h>

#include "combolite/cdb_crypto.h"
#include "cdb_codec.h"
#include "cdb_crc32c.h"
#include "cdb_endian.h"
#include "cdb_journal.h"
#include "cdb_journal_internal.h"
#include "cdb_varint.h"

/* #75: body compression bounds. The on-stack scratch holds either the
 * compressed output (append) or a copy of the compressed input (read); the
 * plaintext ceiling bounds a decompression bomb (CWE-190/-787). Both mirror
 * the doc-body path (DOC_COMP_SCRATCH). Payloads larger than the scratch
 * simply store raw (fail open). */
#define JOURNAL_COMP_SCRATCH 16384u
#define JOURNAL_COMP_MAX JOURNAL_COMP_SCRATCH

/* "\x89CDBCMP\n", the companion-file magic (spec 14.4.1). */
static const uint8_t journal_magic[8] = {0x89, 0x43, 0x44, 0x42, 0x43, 0x4D, 0x50, 0x0A};

/* Every record starts with the marker C0 DE (spec 14.4.2). */
#define RECORD_MARKER_0 0xC0u
#define RECORD_MARKER_1 0xDEu
#define JOURNAL_EPOCH 1u

/* Encodes the 80-byte companion header (spec 14.4.1) and writes it at
 * offset 0. */
cdb_status cdb_companion_write_header(const cdb_storage *st, cdb_byte_order order,
                                      const cdb_journal_header *hdr)
{
    uint8_t h[CDB_JOURNAL_HEADER_SIZE];

    /* Reserved bytes (14..15 and 72..75) stay zero. */
    memset(h, 0, sizeof h);
    memcpy(h, journal_magic, sizeof journal_magic);
    h[8] = (uint8_t)order;
    h[9] = (uint8_t)JOURNAL_EPOCH;
    cdb_store_u16(h + 10, hdr->type_id, order);
    cdb_store_u16(h + 12, hdr->slot, order);
    memcpy(h + 16, hdr->db_id, 16);
    cdb_store_u64(h + 32, hdr->unsealed_seq, order);
    cdb_store_u64(h + 40, hdr->first_seq, order);
    cdb_store_u64(h + 48, hdr->domain_id, order);
    memcpy(h + 56, hdr->salt, 16);
    cdb_store_u32(h + 76, cdb_crc32c(h, 76), order);
    return cdb_storage_program(st, 0, h, sizeof h);
}

/* The handle starts with no records: the first record goes right after the
 * header and gets sequence hdr->first_seq. */
cdb_status cdb_journal_create(cdb_journal *j, const cdb_storage *st, cdb_byte_order order,
                              const cdb_journal_header *hdr)
{
    cdb_status s;

    if ((s = cdb_companion_write_header(st, order, hdr)) != CDB_OK)
        return s;
    memset(j, 0, sizeof *j);
    j->st = *st;
    j->order = order;
    j->hdr = *hdr;
    j->end = CDB_JOURNAL_HEADER_SIZE;
    j->next_seq = hdr->first_seq;
    return CDB_OK;
}

/* Reads and checks the companion header. Errors: CDB_E_CORRUPT for a short
 * file, wrong magic, a byte order different from the archive's, or a bad
 * CRC; CDB_E_UNSUPPORTED for another epoch; CDB_E_MALFORMED when reserved
 * bytes 14..15 or 72..75 are not zero. Matching the database ID and the unsealed
 * sequence is left to the caller. j->end is set to just after the header:
 * the caller finds the true end by reading records until one fails. */
cdb_status cdb_journal_open(cdb_journal *j, const cdb_storage *st, cdb_byte_order order)
{
    uint8_t h[CDB_JOURNAL_HEADER_SIZE];
    cdb_status s;
    size_t i;

    if ((s = cdb_storage_read(st, 0, h, sizeof h)) != CDB_OK)
        return s == CDB_E_TRUNCATED ? CDB_E_CORRUPT : s;
    /* The CRC is checked after magic and byte order, so the CRC is read in
     * the right byte order. */
    if (memcmp(h, journal_magic, sizeof journal_magic) != 0 || h[8] != (uint8_t)order)
        return CDB_E_CORRUPT;
    if (cdb_load_u32(h + 76, order) != cdb_crc32c(h, 76))
        return CDB_E_CORRUPT;
    if (h[9] != JOURNAL_EPOCH)
        return CDB_E_UNSUPPORTED;
    for (i = 14; i < 16; i++)
        if (h[i])
            return CDB_E_MALFORMED;
    for (i = 72; i < 76; i++)
        if (h[i])
            return CDB_E_MALFORMED;
    memset(j, 0, sizeof *j);
    j->st = *st;
    j->order = order;
    j->hdr.type_id = cdb_load_u16(h + 10, order);
    j->hdr.slot = cdb_load_u16(h + 12, order);
    memcpy(j->hdr.db_id, h + 16, 16);
    j->hdr.unsealed_seq = cdb_load_u64(h + 32, order);
    j->hdr.first_seq = cdb_load_u64(h + 40, order);
    j->hdr.domain_id = cdb_load_u64(h + 48, order);
    memcpy(j->hdr.salt, h + 56, 16);
    j->end = CDB_JOURNAL_HEADER_SIZE;
    j->next_seq = j->hdr.first_seq;
    return CDB_OK;
}

cdb_status cdb_journal_size_add(size_t a, size_t b, size_t *out_sum)
{
    if (out_sum == NULL)
        return CDB_E_INVALID_ARG;
    if (a > SIZE_MAX - b)
        return CDB_E_OVERFLOW;
    *out_sum = a + b;
    return CDB_OK;
}

/* Total bytes of a record on disk: header, payload, trailer. #23/F6: reject a
 * payload_len whose size arithmetic would overflow size_t (CWE-190) before any
 * caller's bound/CRC check. The fixed overhead is a small compile-time
 * constant, so only the payload add can overflow. */
cdb_status cdb_journal_record_size(uint32_t payload_len, size_t *out_size)
{
    return cdb_journal_size_add((size_t)(CDB_RECORD_HEADER_SIZE + CDB_RECORD_TRAILER_SIZE),
                                (size_t)payload_len, out_size);
}

/* #75: a codec work handle using the journal's env allocator when it has one
 * (as doc_codec_mem does). Without an env allocator m->env stays NULL and the
 * callers treat that as "store raw" / "cannot read compressed" (fail open). */
static void journal_codec_mem(const cdb_journal *j, cdb_codec_mem *m)
{
    memset(m, 0, sizeof *m);
    if (j->codec_env != NULL && j->codec_env->ops != NULL && j->codec_env->ops->alloc != NULL
        && j->codec_env->ops->free != NULL)
        m->env = j->codec_env;
}

/* #75: tries to compress in_len bytes of in into out (out_cap bytes). Returns
 * 1 with *clen set only when compression is enabled, an env allocator is
 * present, the codec is available and worth trying, the input and its bound fit
 * the scratch, and the result saves at least 1/8; otherwise 0 (store raw).
 * Mirrors doc_try_compress; fail-open to today's uncompressed behaviour. */
static int journal_try_compress(const cdb_journal *j, const uint8_t *in, size_t in_len, uint8_t *out,
                                size_t out_cap, size_t *clen)
{
    cdb_codec_mem m;
    size_t packed = 0;
    if (!j->compress || in_len == 0)
        return 0;
    if (!cdb_codec_available(CDB_CODEC_LZMA2))
        return 0;
    if (in_len > JOURNAL_COMP_SCRATCH || cdb_codec_bound(in_len) > out_cap)
        return 0;
    if (!cdb_codec_worth_trying(in_len, j->page_size, 0))
        return 0;
    journal_codec_mem(j, &m);
    if (m.env == NULL) /* no env allocator wired: fail open, never risk the no-scratch path */
        return 0;
    if (cdb_codec_compress(&m, CDB_CODEC_LZMA2, in, in_len, out, out_cap, &packed) != CDB_OK)
        return 0;
    if (!cdb_codec_keeps(in_len, packed))
        return 0;
    *clen = packed;
    return 1;
}

/* #75: r->payload points at the stored (compressed) op+model body of
 * r->payload_len bytes inside the caller's buf; decompress it back into that
 * same slot and repoint r->payload/r->payload_len at the plaintext. Called
 * only after the record is verified/decrypted and stripped of its hidden-target
 * varints and #65 principal suffix, so r->payload is the compressed body alone.
 * Fail-closed and bounded: an unavailable codec, a compressed length past the
 * scratch, a stated plaintext length past the ceiling or the remaining buffer,
 * or a damaged stream is CDB_E_CORRUPT (TB2 decompression-bomb guard,
 * CWE-190/-787). */
static cdb_status journal_decompress_payload(const cdb_journal *j, cdb_record *r, uint8_t *buf,
                                             size_t buf_size)
{
    cdb_codec_mem m;
    uint8_t cbuf[JOURNAL_COMP_SCRATCH];
    size_t plain = 0, out = 0, off, avail;
    uint8_t *dest;
    cdb_status s;

    if (!cdb_codec_available(CDB_CODEC_LZMA2))
        return CDB_E_CORRUPT;
    if (r->payload_len == 0 || r->payload_len > sizeof cbuf)
        return CDB_E_CORRUPT;
    if ((s = cdb_codec_length(r->payload, r->payload_len, &plain)) != CDB_OK)
        return CDB_E_CORRUPT;
    /* r->payload always points into buf (both read branches set it so). */
    off = (size_t)(r->payload - buf);
    dest = buf + off;
    avail = buf_size - off;
    if (plain > JOURNAL_COMP_MAX || plain > avail)
        return CDB_E_CORRUPT;
    /* Copy the compressed bytes out before writing dest: dest aliases the
     * source, so decompressing in place would corrupt the input mid-stream. */
    memcpy(cbuf, r->payload, r->payload_len);
    journal_codec_mem(j, &m);
    if ((s = cdb_codec_decompress(&m, CDB_CODEC_LZMA2, cbuf, r->payload_len, dest, avail, &out))
        != CDB_OK)
        return CDB_E_CORRUPT;
    r->payload = dest;
    r->payload_len = (uint32_t)out;
    r->flags = (uint8_t)(r->flags & ~CDB_RECORD_FLAG_BODY_CODEC); /* returned view is plaintext */
    return CDB_OK;
}

/* Builds the record in buf (header at offset 0, payload at offset 48, then
 * the trailer) and writes it at the journal's end. The trailer is the
 * CRC32C over header and payload, padded with 12 zero bytes; the space is
 * sized for a future AEAD tag (spec 14.4.2). The handle's end and sequence
 * advance only if the write succeeds.
 *
 * #75: the op+model payload is optionally compressed before assembly, gated
 * like the doc-body path; on success the body carries the compressed bytes and
 * the record is marked CDB_RECORD_FLAG_BODY_CODEC. Compression runs on the
 * plaintext before the body is AEAD-encrypted, so the stored order is
 * compress-then-encrypt and the CRC/AEAD covers the compressed(-then-encrypted)
 * bytes. If the gate is not met the payload is written raw with the flag clear
 * (fail open, never larger than plaintext). */
cdb_status cdb_journal_append_crypto(cdb_journal *j, cdb_record *r, uint8_t *buf, size_t buf_size,
                                     unsigned aead_alg, const uint8_t *key)
{
    int hide = (r->flags & CDB_RECORD_FLAG_ENCRYPTED) != 0;
    /* #65: an attributed record appends the writer's principal as an 8-byte
     * body suffix, so the fixed body overhead grows by sizeof(uint64_t). */
    int has_principal = (r->flags & CDB_RECORD_FLAG_PRINCIPAL) != 0;
    size_t princ = has_principal ? sizeof(uint64_t) : 0u;
    size_t ids = hide ? cdb_varint_size(r->store_id) + cdb_varint_size(r->entry_id) : 0u;
    /* #75: start from the caller's plaintext payload; the compression gate may
     * replace it with the compressed form. The incoming CDB_RECORD_FLAG_BODY_CODEC
     * bit is cleared so append is authoritative: a record read back (flag set)
     * and re-appended compresses afresh or stores raw, never mislabels raw bytes. */
    const uint8_t *src = r->payload;
    uint32_t plen = r->payload_len;
    uint8_t flags = (uint8_t)(r->flags & ~CDB_RECORD_FLAG_BODY_CODEC);
    uint8_t cbuf[JOURNAL_COMP_SCRATCH];
    size_t packed = 0;
    uint32_t body_len;
    size_t size;
    uint8_t *p = buf;
    uint8_t *trailer;
    cdb_status s;

    if (journal_try_compress(j, r->payload, r->payload_len, cbuf, sizeof cbuf, &packed)) {
        src = cbuf;
        plen = (uint32_t)packed;
        flags |= CDB_RECORD_FLAG_BODY_CODEC;
    }

    if (plen > UINT32_MAX - ids - princ)
        return CDB_E_OVERFLOW;
    body_len = (uint32_t)(plen + ids + princ);
    /* #23/F6: overflow-checked sizing before the buffer bound (CWE-190). */
    s = cdb_journal_record_size(body_len, &size);
    if (s != CDB_OK)
        return s; /* CDB_E_OVERFLOW on a 32-bit size_t wrap */
    if (size > buf_size)
        return CDB_E_BUFFER_TOO_SMALL;
    if (hide && r->domain_id == 0)
        return CDB_E_INVALID_ARG;
    r->seq = j->next_seq;
    /* 48-byte header (spec 14.4.2); bytes 44..47 are reserved, left zero. */
    memset(p, 0, CDB_RECORD_HEADER_SIZE);
    p[0] = RECORD_MARKER_0;
    p[1] = RECORD_MARKER_1;
    p[2] = r->kind;
    p[3] = flags;
    cdb_store_u32(p + 4, body_len, j->order);
    cdb_store_u64(p + 8, r->seq, j->order);
    cdb_store_u64(p + 16, r->tx_id, j->order);
    cdb_store_u64(p + 24, hide ? r->domain_id : r->store_id, j->order);
    cdb_store_u64(p + 32, hide ? 0u : r->entry_id, j->order);
    cdb_store_u32(p + 40, r->key_version, j->order);
    /* #75: src is the plaintext (may alias buf) or the stack-local compressed
     * form; memmove handles the aliasing either way. */
    if (plen)
        memmove(p + CDB_RECORD_HEADER_SIZE + ids, src, plen);
    if (hide) { /* the real target, inside the encryption (spec 14.4.2) */
        size_t n = cdb_varint_encode(r->store_id, p + CDB_RECORD_HEADER_SIZE);
        cdb_varint_encode(r->entry_id, p + CDB_RECORD_HEADER_SIZE + n);
    }
    /* #65: the writer's principal as the body's 8-byte tail, after the payload
     * and any hidden-target varints; covered by the trailer CRC / AEAD tag. */
    if (has_principal)
        cdb_store_u64(p + CDB_RECORD_HEADER_SIZE + ids + plen, r->principal, j->order);

    trailer = p + size - CDB_RECORD_TRAILER_SIZE;

    if (hide) {
        uint8_t nonce[CDB_AEAD_NONCE_SIZE];
        uint32_t track_id = ((uint32_t)j->hdr.slot << 16) | (uint32_t)j->hdr.type_id;
        if (key == NULL || aead_alg == CDB_AEAD_NONE)
            return CDB_E_INVALID_ARG;
        cdb_crypto_make_nonce(track_id, r->seq, nonce);
        s = cdb_crypto_aead_encrypt(aead_alg, key, nonce, p, CDB_RECORD_HEADER_SIZE,
                                    p + CDB_RECORD_HEADER_SIZE, body_len,
                                    p + CDB_RECORD_HEADER_SIZE, trailer);
        if (s != CDB_OK)
            return s;
    } else {
        memset(trailer, 0, CDB_RECORD_TRAILER_SIZE);
        cdb_store_u32(trailer, cdb_crc32c(p, size - CDB_RECORD_TRAILER_SIZE), j->order);
    }

    if ((s = cdb_storage_program(&j->st, j->end, p, size)) != CDB_OK)
        return s;
    j->end += size;
    j->next_seq++;
    return CDB_OK;
}

cdb_status cdb_journal_append(cdb_journal *j, cdb_record *r, uint8_t *buf, size_t buf_size)
{
    return cdb_journal_append_crypto(j, r, buf, buf_size, CDB_AEAD_NONE, NULL);
}

cdb_status cdb_journal_read_crypto(cdb_journal *j, uint64_t offset, uint8_t *buf, size_t buf_size,
                                   cdb_record *r, uint64_t *next, unsigned aead_alg,
                                   const uint8_t *key)
{
    uint32_t payload_len;
    size_t size;
    uint8_t *trailer;
    cdb_status s;

    if (buf_size < CDB_RECORD_HEADER_SIZE + CDB_RECORD_TRAILER_SIZE)
        return CDB_E_BUFFER_TOO_SMALL;
    /* Past the end of the file this gives CDB_E_TRUNCATED: the clean end. */
    if ((s = cdb_storage_read(&j->st, offset, buf, CDB_RECORD_HEADER_SIZE)) != CDB_OK)
        return s;
    if (buf[0] != RECORD_MARKER_0 || buf[1] != RECORD_MARKER_1)
        return CDB_E_CORRUPT;
    /* A garbage length cannot make us read past buf: anything bigger than
     * the buffer is rejected before the second read. */
    payload_len = cdb_load_u32(buf + 4, j->order);
    /* #23/F6: reject a length whose size arithmetic overflows size_t (CWE-190)
     * before the buffer bound. On-disk provenance -> CDB_E_CORRUPT. */
    if (cdb_journal_record_size(payload_len, &size) != CDB_OK)
        return CDB_E_CORRUPT;
    if (size > buf_size)
        return CDB_E_CORRUPT; /* larger than any record we would write */
    if ((s = cdb_storage_read(&j->st, offset + CDB_RECORD_HEADER_SIZE, buf + CDB_RECORD_HEADER_SIZE,
                              size - CDB_RECORD_HEADER_SIZE))
        != CDB_OK)
        return s;

    trailer = buf + size - CDB_RECORD_TRAILER_SIZE;

    /* Verified: decode the header. r->payload points into buf. */
    memset(r, 0, sizeof *r);
    r->kind = buf[2];
    r->flags = buf[3];
    r->payload_len = payload_len;
    r->seq = cdb_load_u64(buf + 8, j->order);
    r->tx_id = cdb_load_u64(buf + 16, j->order);
    r->store_id = cdb_load_u64(buf + 24, j->order);
    r->entry_id = cdb_load_u64(buf + 32, j->order);
    r->key_version = cdb_load_u32(buf + 40, j->order);
    r->payload = buf + CDB_RECORD_HEADER_SIZE;

    if (r->flags & CDB_RECORD_FLAG_ENCRYPTED) {
        uint8_t nonce[CDB_AEAD_NONCE_SIZE];
        uint32_t track_id = ((uint32_t)j->hdr.slot << 16) | (uint32_t)j->hdr.type_id;
        /* #65: the op+model payload after the hidden-target varints and before
         * the optional 8-byte principal suffix. */
        uint32_t body = payload_len;
        if (key == NULL || aead_alg == CDB_AEAD_NONE)
            return CDB_E_SECURITY;
        cdb_crypto_make_nonce(track_id, r->seq, nonce);
        s = cdb_crypto_aead_decrypt(aead_alg, key, nonce, buf, CDB_RECORD_HEADER_SIZE,
                                    buf + CDB_RECORD_HEADER_SIZE, payload_len, trailer,
                                    buf + CDB_RECORD_HEADER_SIZE);
        if (s != CDB_OK)
            return CDB_E_CORRUPT;
        /* #65: strip the principal suffix (length-checked) before decoding the
         * front varints, fail-closed on a FLAG_PRINCIPAL body too short to hold it. */
        if (r->flags & CDB_RECORD_FLAG_PRINCIPAL) {
            if (body < sizeof(uint64_t))
                return CDB_E_CORRUPT;
            body -= (uint32_t)sizeof(uint64_t);
            r->principal = cdb_load_u64(r->payload + body, j->order);
        }
        /* The hidden target: two shortest-form varints (spec 14.4.2). */
        {
            uint64_t store, entry;
            size_t n1, n2;
            if (cdb_varint_decode(r->payload, body, &store, &n1) != CDB_OK
                || cdb_varint_decode(r->payload + n1, body - n1, &entry, &n2) != CDB_OK
                || r->entry_id != 0 || r->store_id == 0)
                return CDB_E_CORRUPT;
            r->domain_id = r->store_id;
            r->store_id = store;
            r->entry_id = entry;
            r->payload += n1 + n2;
            r->payload_len = body - (uint32_t)(n1 + n2);
        }
    } else {
        size_t i;
        if (cdb_load_u32(trailer, j->order) != cdb_crc32c(buf, size - CDB_RECORD_TRAILER_SIZE))
            return CDB_E_CORRUPT;
        /* The 12 padding bytes after the CRC must be zero. */
        for (i = size - CDB_RECORD_TRAILER_SIZE + 4; i < size; i++)
            if (buf[i])
                return CDB_E_CORRUPT;
        /* #65: strip the plaintext principal suffix (length-checked), fail-closed
         * when a FLAG_PRINCIPAL body is too short to carry it. */
        if (r->flags & CDB_RECORD_FLAG_PRINCIPAL) {
            if (payload_len < sizeof(uint64_t))
                return CDB_E_CORRUPT;
            r->payload_len = payload_len - (uint32_t)sizeof(uint64_t);
            r->principal = cdb_load_u64(buf + CDB_RECORD_HEADER_SIZE + r->payload_len, j->order);
        }
    }

    /* #75: verify/decrypt and strip ran first; r->payload/r->payload_len is now
     * the (possibly compressed) op+model body. Decompress iff the record is
     * marked, fail-closed on a bad or over-large stream (decrypt-then-decompress,
     * the inverse of append's compress-then-encrypt). An unflagged (old-format)
     * record is returned untouched. */
    if (r->flags & CDB_RECORD_FLAG_BODY_CODEC) {
        if ((s = journal_decompress_payload(j, r, buf, buf_size)) != CDB_OK)
            return s;
    }

    *next = offset + size;
    return CDB_OK;
}

cdb_status cdb_journal_read(cdb_journal *j, uint64_t offset, uint8_t *buf, size_t buf_size,
                            cdb_record *r, uint64_t *next)
{
    return cdb_journal_read_crypto(j, offset, buf, buf_size, r, next, CDB_AEAD_NONE, NULL);
}

/* Commit record payload (spec 14.4.4): commit number, timestamp, principal,
 * delta count, track mask, then the signature length. The base encode always
 * writes signature length 0; only under CDB_SIGN_EVERY_REVISION does the
 * committer (src/cdb_db.c tx_commit_locked) append a signature and overwrite
 * this field. #42 FR4.6 DEFER: in the default policy the commit record is
 * unsigned and its principal is whatever the caller passes (0 today), so
 * commits are not attributed or integrity-signed by default; capturing the
 * principal and signing every commit ties to the #40 signed-revision work and
 * its recovery-principal follow-up (documented, not changed; docs/BACKLOG.md). */
void cdb_commit_encode(const cdb_commit_info *c, uint8_t out[CDB_COMMIT_PAYLOAD_SIZE],
                       cdb_byte_order order)
{
    cdb_store_u64(out, c->commit_number, order);
    cdb_store_u64(out + 8, c->timestamp, order);
    cdb_store_u64(out + 16, c->principal, order);
    cdb_store_u32(out + 24, c->delta_count, order);
    cdb_store_u32(out + 28, c->track_mask, order);
    cdb_store_u16(out + 32, 0, order); /* unsigned unless the committer re-signs (spec 12.5) */
}

/* Decodes a commit record's payload. CDB_E_MALFORMED if r is not a commit
 * record, or if the payload length does not equal 34 plus the signature
 * length it declares. A signature, if present, is accepted but not checked. */
cdb_status cdb_commit_decode(const cdb_record *r, cdb_commit_info *c, cdb_byte_order order)
{
    uint16_t sig_len;
    if (r->kind != CDB_RECORD_COMMIT || r->payload_len < CDB_COMMIT_PAYLOAD_SIZE)
        return CDB_E_MALFORMED;
    c->commit_number = cdb_load_u64(r->payload, order);
    c->timestamp = cdb_load_u64(r->payload + 8, order);
    c->principal = cdb_load_u64(r->payload + 16, order);
    c->delta_count = cdb_load_u32(r->payload + 24, order);
    c->track_mask = cdb_load_u32(r->payload + 28, order);
    sig_len = cdb_load_u16(r->payload + 32, order);
    if ((uint32_t)CDB_COMMIT_PAYLOAD_SIZE + sig_len != r->payload_len)
        return CDB_E_MALFORMED;
    return CDB_OK;
}
