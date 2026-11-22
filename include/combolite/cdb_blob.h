/* Streaming API & Content-Addressed Blob Storage (spec 8.4, 14.15).
 *
 * Allows writing and reading large arbitrary binary content piece by piece
 * without holding the whole object in memory at once. Blobs are stored
 * across overflow pages (type 0x0007), content-addressed by SHA-256 (or
 * HMAC-SHA-256 in an enclave). */
#ifndef COMBOLITE_CDB_BLOB_H
#define COMBOLITE_CDB_BLOB_H

#include <stddef.h>
#include <stdint.h>

#include "combolite/cdb_common.h"
#include "combolite/cdb_crypto.h"

/* Forward declarations */
struct cdb_pager;
struct cdb_db;

/* Read-time integrity-verification mode (spec 14.15, issue #39).
 *
 * A content-addressed store must verify what it returns, so verification is
 * the DEFAULT: both CDB_BLOB_VERIFY and CDB_BLOB_VERIFY_DEFAULT verify the
 * SHA-256 / HMAC-SHA-256 chain on read. Only the explicit CDB_BLOB_NO_VERIFY
 * sentinel opts out. The parameter keeps its int type and position, so every
 * existing caller (all pass 1) still verifies; a caller that passed 0 now
 * verifies too (the fix) rather than returning unverified bytes silently. */
#define CDB_BLOB_VERIFY_DEFAULT 0 /* default: verify */
#define CDB_BLOB_VERIFY 1         /* explicit: verify */
#define CDB_BLOB_NO_VERIFY 2      /* explicit opt-out: skip verification */

/* Blob reference (spec 14.15). */
typedef struct cdb_blob_ref {
    uint8_t hash[CDB_CRYPTO_HASH_SIZE]; /* Cryptographic SHA-256 / HMAC-SHA-256 */
    uint64_t total_len;                 /* Total content length in bytes */
    uint64_t first_page;                /* Logical ID of first page (0x0007); 0 if empty */
    uint64_t page_count;                /* Total number of pages occupied */
    uint32_t flags;                     /* Bit 0: external file; Bit 1: enclave */
} cdb_blob_ref;

/* Streaming blob writer context. Fixed size, zero heap allocation. */
typedef struct cdb_blob_writer {
    struct cdb_pager *pager;
    uint64_t store_id;
    cdb_crypto_hash_ctx hash_ctx;
    uint64_t first_page;
    uint64_t curr_page;
    uint64_t page_count;
    uint64_t total_bytes;
    size_t page_room;
    size_t curr_page_fill;
    uint8_t *scratch; /* Exactly p->page_size bytes */
    int is_enclave;
    int is_open;
    void *db; /* the cdb_db whose lock cdb_db_blob_* calls take; NULL outside one */
} cdb_blob_writer;

/* Begins streaming write of a blob owned by store_id. scratch must hold
 * p->page_size bytes. If enclave_key is non-NULL, the content hash is
 * computed as HMAC-SHA-256 under the key; otherwise standard SHA-256 is used. */
cdb_status cdb_blob_write_begin(struct cdb_pager *p, uint64_t store_id, uint8_t *scratch,
                                const uint8_t *enclave_key, cdb_blob_writer *w);

/* Appends len bytes from data to the streaming blob. */
cdb_status cdb_blob_write_chunk(cdb_blob_writer *w, const void *data, size_t len);

/* Finalizes the blob stream, writes out the final page, computes the final hash,
 * and fills out_ref. scratch is no longer in use once this returns. */
cdb_status cdb_blob_write_end(cdb_blob_writer *w, cdb_blob_ref *out_ref);

/* Aborts an in-progress blob stream, releasing all pages allocated so far. */
cdb_status cdb_blob_write_abort(cdb_blob_writer *w);

/* Streaming blob reader context. Fixed size, zero heap allocation. */
typedef struct cdb_blob_reader {
    struct cdb_pager *pager;
    uint64_t store_id;
    cdb_blob_ref ref;
    uint64_t curr_page;
    uint64_t next_page;
    uint64_t bytes_remaining;
    size_t curr_offset_in_page;
    size_t curr_page_bytes;
    cdb_crypto_hash_ctx hash_ctx;
    uint8_t *page_buf; /* Exactly p->page_size bytes */
    int verify_hash;
    int is_open;
    void *db; /* the cdb_db whose lock cdb_db_blob_* calls take; NULL outside one */
} cdb_blob_reader;

/* Begins streaming read of a blob. page_buf must hold p->page_size bytes.
 * verify_hash selects the integrity mode (see CDB_BLOB_* above): the content
 * hash is verified against ref->hash upon reaching EOF UNLESS the caller
 * passes CDB_BLOB_NO_VERIFY. Verification is the default — a corrupt or
 * substituted chain with a matching total_len is rejected, not returned.
 * Every page's length and link are checked exactly as the chain walks,
 * regardless of the verify mode. If enclave_key is non-NULL, the hash is
 * verified using HMAC-SHA-256. */
cdb_status cdb_blob_read_begin(struct cdb_pager *p, uint64_t store_id, const cdb_blob_ref *ref,
                               uint8_t *page_buf, int verify_hash, const uint8_t *enclave_key,
                               cdb_blob_reader *r);

/* Reads up to cap bytes into dest. *out_len receives the number of bytes read.
 * When EOF is reached (*out_len == 0 and remaining == 0), if verify_hash was
 * requested, the content hash is verified; if mismatch, returns CDB_E_CORRUPT. */
cdb_status cdb_blob_read_chunk(cdb_blob_reader *r, void *dest, size_t cap, size_t *out_len);

/* Finishes reading. */
cdb_status cdb_blob_read_end(cdb_blob_reader *r);

/* Releases every page of the blob at ref->first_page. page_buf is p->page_size.
 * Raw release with no deduplication/refcount: the chain is always freed. The
 * content-addressed, refcounted path is cdb_blob_free_db. */
cdb_status cdb_blob_free(struct cdb_pager *p, uint64_t store_id, const cdb_blob_ref *ref,
                         uint8_t *page_buf);

/* ---- Content-addressed, deduplicated, refcounted blob storage (issue #39) ----
 *
 * The _db variants add a persistent dedup index (a B+tree rooted at the
 * catalog root's dedup_root slot, keyed by domain || content-hash). Identical
 * content is stored once; a per-domain refcount tracks how many references
 * share a chain. They preserve the no-heap / caller-buffer model and borrow
 * the database's catalog work memory, taken under the database lock by the
 * cdb_db_blob_* wrappers. domain is the encryption domain of store_id
 * (store_domain in cdb_db.c); public blobs share domain 0, enclave blobs are
 * keyed under the enclave id so digests never alias across domains. */

/* Finalizes the streaming write, then deduplicates by content hash: if the
 * hash already exists in the domain, the just-written chain is released, the
 * stored reference's refcount is incremented, and out_ref is set to the
 * canonical stored chain; otherwise the new chain is recorded with refcount 1.
 * Empty blobs are never deduplicated. CDB_E_OVERFLOW if the refcount would
 * saturate. */
cdb_status cdb_blob_write_end_db(struct cdb_db *db, cdb_blob_writer *w, uint64_t domain,
                                 cdb_blob_ref *out_ref);

/* Releases one reference to the blob at ref. If the content is deduplicated,
 * the refcount is decremented and the pages are released only when it reaches
 * zero; the dedup entry is then removed. A ref with no dedup record (legacy or
 * non-deduplicated) is released directly. CDB_E_OVERFLOW if ref->total_len
 * exceeds SIZE_MAX (guards the size_t conversion against silent truncation). */
cdb_status cdb_blob_free_db(struct cdb_db *db, uint64_t store_id, uint64_t domain,
                            const cdb_blob_ref *ref, uint8_t *page_buf);

/* Internal test hook (#39 regression): forwards to the static size-fit check
 * so a test can exercise the total_len > SIZE_MAX guard deterministically on
 * any platform (on an LP64 host SIZE_MAX == UINT64_MAX makes it otherwise
 * unreachable). Not part of the public blob API. */
cdb_status cdb_blob_len_within_for_test(uint64_t total_len, uint64_t size_max);

#endif /* COMBOLITE_CDB_BLOB_H */
