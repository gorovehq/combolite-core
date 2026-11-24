/* Streaming API & Content-Addressed Blob Storage (spec 8.4, 14.15).
 *
 * Overflow chains of type 0x0007, content-addressed with SHA-256 or HMAC-SHA-256. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "combolite/cdb_blob.h"
#include "combolite/cdb_env.h"
#include "combolite/cdb_storage.h"
#include "cdb_db.h"
#include "cdb_endian.h"
#include "cdb_index.h"
#include "cdb_overflow.h"
#include "cdb_page.h"
#include "cdb_pager.h"

/* Dedup index entry layout (issue #39): key = domain(8, big-endian) ||
 * content hash(32); value = refcount, first_page, page_count, total_len
 * (u64 each), then flags (u32), in the pager's byte order. Fixed sizes so the
 * value always stays inline in the leaf. */
#define BLOB_DEDUP_KEY_LEN (8u + CDB_CRYPTO_HASH_SIZE)
#define BLOB_DEDUP_VAL_LEN 36u

static uint64_t load_lid(const cdb_pager *p, const uint8_t *b)
{
    return p->addr_width == 8 ? cdb_load_u64(b, p->order) : cdb_load_u32(b, p->order);
}

static void store_lid(const cdb_pager *p, uint8_t *b, uint64_t lid)
{
    if (p->addr_width == 8)
        cdb_store_u64(b, lid, p->order);
    else
        cdb_store_u32(b, (uint32_t)lid, p->order);
}

cdb_status cdb_blob_write_begin(cdb_pager *p, uint64_t store_id, uint8_t *scratch,
                                const uint8_t *enclave_key, cdb_blob_writer *w)
{
    cdb_status s;
    if (p == NULL || scratch == NULL || w == NULL)
        return CDB_E_INVALID_ARG;

    memset(w, 0, sizeof *w);
    w->pager = p;
    w->store_id = store_id;
    w->scratch = scratch;
    w->page_room = cdb_overflow_room(p);
    if (w->page_room == 0)
        return CDB_E_INVALID_ARG;

    if (enclave_key != NULL) {
        w->is_enclave = 1;
        s = cdb_crypto_hash_init_hmac(&w->hash_ctx, enclave_key);
    } else {
        s = cdb_crypto_hash_init(&w->hash_ctx);
    }
    if (s != CDB_OK)
        return s;

    w->is_open = 1;
    return CDB_OK;
}

cdb_status cdb_blob_write_chunk(cdb_blob_writer *w, const void *data, size_t len)
{
    const uint8_t *src = (const uint8_t *)data;
    cdb_status s;

    if (w == NULL || !w->is_open)
        return CDB_E_STATE;
    if (len == 0)
        return CDB_OK;
    if (data == NULL)
        return CDB_E_INVALID_ARG;

    if ((s = cdb_crypto_hash_update(&w->hash_ctx, data, len)) != CDB_OK)
        return s;

    if (w->first_page == 0) {
        if ((s = cdb_pager_alloc(w->pager, &w->first_page)) != CDB_OK)
            return s;
        w->curr_page = w->first_page;
        w->page_count = 1;
    }

    while (len > 0) {
        size_t avail = w->page_room - w->curr_page_fill;
        if (avail == 0) {
            uint64_t next = 0;
            cdb_page_header t;
            if ((s = cdb_pager_alloc(w->pager, &next)) != CDB_OK)
                return s;

            store_lid(w->pager, w->scratch, next);
            memset(&t, 0, sizeof t);
            t.type = CDB_PAGE_TYPE_OVERFLOW;
            t.flags = CDB_PAGE_FLAG_OVERFLOW;
            t.store_id = w->store_id;

            s = cdb_pager_write(w->pager, w->curr_page, &t, w->scratch,
                                (uint32_t)(w->pager->addr_width + w->curr_page_fill));
            if (s != CDB_OK)
                return s;

            w->curr_page = next;
            w->curr_page_fill = 0;
            w->page_count++;
            avail = w->page_room;
        }

        size_t take = len < avail ? len : avail;
        memcpy(w->scratch + w->pager->addr_width + w->curr_page_fill, src, take);
        w->curr_page_fill += take;
        w->total_bytes += take;
        src += take;
        len -= take;
    }

    return CDB_OK;
}

cdb_status cdb_blob_write_end(cdb_blob_writer *w, cdb_blob_ref *out_ref)
{
    cdb_status s;

    if (w == NULL || !w->is_open || out_ref == NULL)
        return CDB_E_INVALID_ARG;

    memset(out_ref, 0, sizeof *out_ref);

    if (w->total_bytes == 0) {
        out_ref->first_page = 0;
        out_ref->page_count = 0;
        out_ref->total_len = 0;
        if (w->first_page != 0) {
            cdb_pager_free(w->pager, w->first_page);
            w->first_page = 0;
            w->curr_page = 0;
        }
    } else {
        cdb_page_header t;
        store_lid(w->pager, w->scratch, 0); /* 0 marks the end of the chain */
        memset(&t, 0, sizeof t);
        t.type = CDB_PAGE_TYPE_OVERFLOW;
        t.flags = CDB_PAGE_FLAG_OVERFLOW;
        t.store_id = w->store_id;

        s = cdb_pager_write(w->pager, w->curr_page, &t, w->scratch,
                            (uint32_t)(w->pager->addr_width + w->curr_page_fill));
        if (s != CDB_OK)
            return s;

        out_ref->first_page = w->first_page;
        out_ref->page_count = w->page_count;
        out_ref->total_len = w->total_bytes;
    }

    if (w->is_enclave)
        out_ref->flags |= 0x02u;

    s = cdb_crypto_hash_final(&w->hash_ctx, out_ref->hash);
    cdb_crypto_hash_free(&w->hash_ctx);
    w->is_open = 0;
    return s;
}

cdb_status cdb_blob_write_abort(cdb_blob_writer *w)
{
    if (w == NULL || !w->is_open)
        return CDB_OK;

    if (w->first_page != 0) {
        uint64_t lid = w->first_page;
        while (lid != 0 && lid != w->curr_page) {
            cdb_page_header h;
            uint64_t next = 0;
            cdb_status s = cdb_pager_read(w->pager, lid, w->scratch, &h);
            if (s == CDB_OK) {
                const uint8_t *pl = w->scratch + cdb_page_payload_offset(w->pager->fmt);
                next = load_lid(w->pager, pl);
            }
            cdb_pager_free(w->pager, lid);
            lid = next;
        }
        if (w->curr_page != 0)
            cdb_pager_free(w->pager, w->curr_page);
    }

    cdb_crypto_hash_free(&w->hash_ctx);
    w->is_open = 0;
    return CDB_OK;
}

/* Loads and validates the chain page lid into r->page_buf. The expected part
 * length and end-of-chain flag follow from bytes_remaining (the content left
 * from this page onward), exactly as the overflow reader derives them, so a
 * malformed interior page is rejected whether or not hashing is enabled. */
static cdb_status blob_load_page(cdb_blob_reader *r, uint64_t lid)
{
    cdb_pager *p = r->pager;
    size_t room = cdb_overflow_room(p);
    uint64_t rem = r->bytes_remaining;
    size_t part = (rem < (uint64_t)room) ? (size_t)rem : room;
    int last = rem <= (uint64_t)room;
    uint64_t next = 0;
    const uint8_t *body;
    cdb_status s =
        cdb_overflow_chain_page(p, lid, r->store_id, part, last, r->page_buf, &next, &body);
    if (s != CDB_OK)
        return s;
    r->curr_page = lid;
    r->next_page = next;
    r->curr_page_bytes = part;
    r->curr_offset_in_page = 0;
    return CDB_OK;
}

cdb_status cdb_blob_read_begin(cdb_pager *p, uint64_t store_id, const cdb_blob_ref *ref,
                               uint8_t *page_buf, int verify_hash, const uint8_t *enclave_key,
                               cdb_blob_reader *r)
{
    cdb_status s;
    int do_verify;
    if (p == NULL || ref == NULL || page_buf == NULL || r == NULL)
        return CDB_E_INVALID_ARG;

    /* Verify-by-default: only the explicit opt-out sentinel skips it. */
    do_verify = (verify_hash != CDB_BLOB_NO_VERIFY);

    memset(r, 0, sizeof *r);
    r->pager = p;
    r->store_id = store_id;
    r->ref = *ref;
    r->page_buf = page_buf;
    r->verify_hash = do_verify;
    r->bytes_remaining = ref->total_len;
    r->curr_page = ref->first_page;

    if (do_verify) {
        if (enclave_key != NULL)
            s = cdb_crypto_hash_init_hmac(&r->hash_ctx, enclave_key);
        else
            s = cdb_crypto_hash_init(&r->hash_ctx);
        if (s != CDB_OK)
            return s;
    }

    if (ref->total_len == 0) {
        if (do_verify) {
            uint8_t h[CDB_CRYPTO_HASH_SIZE];
            r->verify_hash = 0;
            if ((s = cdb_crypto_hash_final(&r->hash_ctx, h)) != CDB_OK)
                return s;
            if (memcmp(h, ref->hash, CDB_CRYPTO_HASH_SIZE) != 0)
                return CDB_E_CORRUPT;
        }
        r->is_open = 1;
        return CDB_OK;
    }

    if (ref->first_page == 0)
        return CDB_E_CORRUPT;

    /* Read and validate the first page of the chain (tight length + link). */
    if ((s = blob_load_page(r, ref->first_page)) != CDB_OK)
        return s;
    r->is_open = 1;
    return CDB_OK;
}

cdb_status cdb_blob_read_chunk(cdb_blob_reader *r, void *dest, size_t cap, size_t *out_len)
{
    uint8_t *dst = (uint8_t *)dest;
    cdb_status s;

    if (r == NULL || !r->is_open || out_len == NULL)
        return CDB_E_INVALID_ARG;
    if (cap > 0 && dest == NULL)
        return CDB_E_INVALID_ARG;

    *out_len = 0;
    if (r->bytes_remaining == 0 || cap == 0) {
        if (r->bytes_remaining == 0 && r->verify_hash) {
            uint8_t h[CDB_CRYPTO_HASH_SIZE];
            r->verify_hash = 0;
            if ((s = cdb_crypto_hash_final(&r->hash_ctx, h)) != CDB_OK)
                return s;
            if (memcmp(h, r->ref.hash, CDB_CRYPTO_HASH_SIZE) != 0)
                return CDB_E_CORRUPT;
        }
        return CDB_OK;
    }

    while (cap > 0 && r->bytes_remaining > 0) {
        if (r->curr_offset_in_page == r->curr_page_bytes) {
            if (r->next_page == 0)
                return CDB_E_CORRUPT; /* truncated chain */
            if ((s = blob_load_page(r, r->next_page)) != CDB_OK)
                return s;
        }

        size_t avail = r->curr_page_bytes - r->curr_offset_in_page;
        size_t take = cap < avail ? cap : avail;
        if ((uint64_t)take > r->bytes_remaining)
            take = (size_t)r->bytes_remaining;

        const uint8_t *pl =
            r->page_buf + cdb_page_payload_offset(r->pager->fmt) + r->pager->addr_width;
        memcpy(dst, pl + r->curr_offset_in_page, take);

        if (r->verify_hash) {
            if ((s = cdb_crypto_hash_update(&r->hash_ctx, dst, take)) != CDB_OK)
                return s;
        }

        r->curr_offset_in_page += take;
        r->bytes_remaining -= take;
        *out_len += take;
        dst += take;
        cap -= take;
    }

    if (r->bytes_remaining == 0 && r->verify_hash) {
        uint8_t h[CDB_CRYPTO_HASH_SIZE];
        r->verify_hash = 0;
        if ((s = cdb_crypto_hash_final(&r->hash_ctx, h)) != CDB_OK)
            return s;
        if (memcmp(h, r->ref.hash, CDB_CRYPTO_HASH_SIZE) != 0)
            return CDB_E_CORRUPT;
    }

    return CDB_OK;
}

cdb_status cdb_blob_read_end(cdb_blob_reader *r)
{
    if (r == NULL || !r->is_open)
        return CDB_OK;

    cdb_crypto_hash_free(&r->hash_ctx);
    r->is_open = 0;
    return CDB_OK;
}

/* Rejects a total_len that would not fit a size_t, guarding the uint64 ->
 * size_t conversion against silent truncation (issue #39, FR5). size_max is a
 * runtime argument so the comparison is between two uint64 values (no
 * tautological-constant warning on an LP64 host) and the guard is testable on
 * any platform via cdb_blob_len_within_for_test. */
static cdb_status blob_len_within(uint64_t total_len, uint64_t size_max)
{
    return total_len > size_max ? CDB_E_OVERFLOW : CDB_OK;
}

cdb_status cdb_blob_len_within_for_test(uint64_t total_len, uint64_t size_max)
{
    return blob_len_within(total_len, size_max);
}

/* ---------------------------------- external-file-backed blobs (#56 FR1) --- */

/* Lowercase-hex encodes n bytes into out (needs 2n+1 bytes, terminated). */
static void blob_hex_encode(const uint8_t *in, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[2u * i] = d[in[i] >> 4];
        out[2u * i + 1u] = d[in[i] & 0x0Fu];
    }
    out[2u * n] = '\0';
}

/* Builds the content-addressed external-file path for a content hash under the
 * database working directory. CDB_E_INVALID_ARG if it would not fit. */
static cdb_status blob_ext_path(const cdb_db *db, const uint8_t hash[CDB_CRYPTO_HASH_SIZE],
                                char *path, size_t cap)
{
    char hex[2u * CDB_CRYPTO_HASH_SIZE + 1u];
    int n;
    blob_hex_encode(hash, CDB_CRYPTO_HASH_SIZE, hex);
    n = snprintf(path, cap, "%s/blob.%s.ext", db->workdir, hex);
    if (n < 0 || (size_t)n >= cap)
        return CDB_E_INVALID_ARG;
    return CDB_OK;
}

/* Hashes len bytes into out: HMAC-SHA-256 under enclave_key when set, else
 * SHA-256. Keeps the external integrity oracle identical to the page-chain one
 * (#39), so an enclave digest never aliases a public one. */
static cdb_status blob_ext_hash(const void *data, size_t len, const uint8_t *enclave_key,
                                uint8_t out[CDB_CRYPTO_HASH_SIZE])
{
    if (enclave_key != NULL)
        return cdb_crypto_hmac_sha256(enclave_key, data, len, out);
    return cdb_crypto_sha256(data, len, out);
}

cdb_status cdb_blob_store_external_db(cdb_db *db, uint64_t store_id, const void *data, size_t len,
                                      const uint8_t *enclave_key, cdb_blob_ref *out_ref)
{
    cdb_status s;
    uint8_t hash[CDB_CRYPTO_HASH_SIZE];
    char path[CDB_DB_PATH_MAX];
    cdb_storage st;
    (void)store_id; /* external files are content-addressed, not page-owned */

    if (db == NULL || out_ref == NULL || (len > 0 && data == NULL))
        return CDB_E_INVALID_ARG;
    if (db->env.ops == NULL || db->env.ops->open == NULL || db->env.ops->sync_dir == NULL)
        return CDB_E_UNSUPPORTED;
    if ((s = blob_ext_hash(data, len, enclave_key, hash)) != CDB_OK)
        return s;
    if ((s = blob_ext_path(db, hash, path, sizeof path)) != CDB_OK)
        return s;

    memset(out_ref, 0, sizeof *out_ref);
    memcpy(out_ref->hash, hash, CDB_CRYPTO_HASH_SIZE);
    out_ref->total_len = len;
    out_ref->first_page = 0;
    out_ref->page_count = 0;
    out_ref->flags = 0x01u | (enclave_key != NULL ? 0x02u : 0u);

    /* Atomic create-or-claim: an existing content-addressed file already holds
     * exactly these bytes, so the store is a durable no-op (dedup). */
    s = db->env.ops->open(db->env.ctx, path, CDB_ENV_CREATE | CDB_ENV_EXCL, &st);
    if (s == CDB_E_EXISTS)
        return CDB_OK;
    if (s != CDB_OK)
        return s;
    s = (len > 0) ? cdb_storage_program(&st, 0, data, len) : CDB_OK;
    if (s == CDB_OK)
        s = cdb_storage_sync(&st);
    cdb_storage_close(&st);
    if (s != CDB_OK) {
        if (db->env.ops->remove != NULL)
            db->env.ops->remove(db->env.ctx, path); /* best-effort: drop a partial file */
        return s;
    }
    return db->env.ops->sync_dir(db->env.ctx, db->workdir);
}

cdb_status cdb_blob_read_external_db(cdb_db *db, const cdb_blob_ref *ref, int verify_hash,
                                     const uint8_t *enclave_key, void *dest, size_t cap,
                                     size_t *out_len)
{
    cdb_status s;
    char path[CDB_DB_PATH_MAX];
    cdb_storage st;
    uint64_t fsize = 0;
    size_t len;
    uint8_t hash[CDB_CRYPTO_HASH_SIZE];
    int do_verify;

    if (db == NULL || ref == NULL || out_len == NULL)
        return CDB_E_INVALID_ARG;
    if (cap > 0 && dest == NULL)
        return CDB_E_INVALID_ARG;
    if (!(ref->flags & 0x01u))
        return CDB_E_INVALID_ARG; /* not an external-file blob */
    if (db->env.ops == NULL || db->env.ops->open == NULL)
        return CDB_E_UNSUPPORTED;
    *out_len = 0;
    do_verify = (verify_hash != CDB_BLOB_NO_VERIFY);
    if ((s = blob_len_within(ref->total_len, SIZE_MAX)) != CDB_OK)
        return s;
    len = (size_t)ref->total_len;
    if (len > cap)
        return CDB_E_BUFFER_TOO_SMALL;
    if ((s = blob_ext_path(db, ref->hash, path, sizeof path)) != CDB_OK)
        return s;

    s = db->env.ops->open(db->env.ctx, path, CDB_ENV_READONLY, &st);
    if (s != CDB_OK)
        return s; /* a missing file is reported CDB_E_NOT_FOUND by the env */

    /* Fail closed on any size mismatch BEFORE reading: a truncated or grown
     * external file is rejected whole, never partially returned (TB1). */
    s = cdb_storage_size(&st, &fsize);
    if (s == CDB_OK && fsize != ref->total_len)
        s = CDB_E_CORRUPT;
    if (s == CDB_OK && len > 0)
        s = cdb_storage_read(&st, 0, dest, len);
    cdb_storage_close(&st);
    if (s != CDB_OK)
        return s;

    /* Verify-on-read (#39 reuse): the external bytes must hash to ref->hash.
     * A same-size but altered or substituted file is rejected here. */
    if (do_verify) {
        if ((s = blob_ext_hash(dest, len, enclave_key, hash)) != CDB_OK)
            return s;
        if (memcmp(hash, ref->hash, CDB_CRYPTO_HASH_SIZE) != 0)
            return CDB_E_CORRUPT;
    }
    *out_len = len;
    return CDB_OK;
}

cdb_status cdb_blob_external_path_for_test(cdb_db *db, const cdb_blob_ref *ref, char *out,
                                           size_t cap)
{
    if (db == NULL || ref == NULL || out == NULL)
        return CDB_E_INVALID_ARG;
    return blob_ext_path(db, ref->hash, out, cap);
}

cdb_status cdb_blob_free(cdb_pager *p, uint64_t store_id, const cdb_blob_ref *ref,
                         uint8_t *page_buf)
{
    cdb_status s;
    if (p == NULL || ref == NULL || page_buf == NULL)
        return CDB_E_INVALID_ARG;
    if (ref->first_page == 0 || ref->total_len == 0)
        return CDB_OK;
    if ((s = blob_len_within(ref->total_len, SIZE_MAX)) != CDB_OK)
        return s;

    return cdb_overflow_free(p, ref->first_page, store_id, (size_t)ref->total_len, page_buf);
}

/* ---------------------------------- content-addressed dedup index (#39) --- */

/* Builds the 40-byte dedup key: domain (8, big-endian) || content hash. */
static void blob_dedup_key(uint64_t domain, const uint8_t hash[CDB_CRYPTO_HASH_SIZE], uint8_t *key)
{
    cdb_store_u64(key, domain, CDB_ORDER_BIG);
    memcpy(key + 8, hash, CDB_CRYPTO_HASH_SIZE);
}

/* Encodes a dedup value: refcount then the canonical chain locator. */
static void blob_dedup_val_encode(uint8_t *v, uint64_t refc, uint64_t first_page,
                                  uint64_t page_count, uint64_t total_len, uint32_t flags,
                                  cdb_byte_order o)
{
    cdb_store_u64(v, refc, o);
    cdb_store_u64(v + 8, first_page, o);
    cdb_store_u64(v + 16, page_count, o);
    cdb_store_u64(v + 24, total_len, o);
    cdb_store_u32(v + 32, flags, o);
}

/* Opens the per-database dedup index rooted at catroot.dedup_root, creating it
 * (and recording its root in the catalog root slot) when create is set and it
 * does not exist yet. *have is 0 when there is none and create is 0. Mirrors
 * the lazy-provision pattern of the salt table. */
static cdb_status blob_dedup_open(cdb_db *db, cdb_index *ix, int create, int *have)
{
    cdb_status s;
    *have = 0;
    if (db->cfg.catalog_work.bytes == NULL)
        return CDB_E_STATE; /* the dedup index needs catalog work memory */
    if (db->pager.catroot.dedup_root != 0) {
        if ((s = cdb_index_open(ix, &db->pager, db->pager.catroot.dedup_root,
                                &db->cfg.catalog_work))
            != CDB_OK)
            return s;
        *have = 1;
        return CDB_OK;
    }
    if (!create)
        return CDB_OK;
    if ((s = cdb_index_create(ix, &db->pager, 0, CDB_INDEX_FLAG_UNIQUE, &db->cfg.catalog_work))
        != CDB_OK)
        return s;
    {
        cdb_catroot r = db->pager.catroot;
        r.dedup_root = ix->root; /* durable with the next pager commit */
        cdb_pager_set_catroot(&db->pager, &r);
    }
    *have = 1;
    return CDB_OK;
}

cdb_status cdb_blob_write_end_db(cdb_db *db, cdb_blob_writer *w, uint64_t domain,
                                 cdb_blob_ref *out_ref)
{
    cdb_status s;
    cdb_index ix;
    int have, found;
    uint8_t key[BLOB_DEDUP_KEY_LEN], val[BLOB_DEDUP_VAL_LEN];
    size_t vlen;
    uint64_t store_id, refc;
    uint8_t *page;

    if (db == NULL || w == NULL || out_ref == NULL)
        return CDB_E_INVALID_ARG;

    store_id = w->store_id;
    page = w->scratch; /* reusable as a page buffer once the stream is finalized */

    /* Finalize the transient chain and compute the content hash. */
    if ((s = cdb_blob_write_end(w, out_ref)) != CDB_OK)
        return s;
    if (out_ref->total_len == 0)
        return CDB_OK; /* empty blobs are not deduplicated */

    blob_dedup_key(domain, out_ref->hash, key);
    if ((s = blob_dedup_open(db, &ix, 1, &have)) != CDB_OK)
        return s;
    if ((s = cdb_index_get(&ix, key, sizeof key, val, sizeof val, &vlen, &found)) != CDB_OK)
        return s;

    if (found) {
        uint64_t stored_first, stored_count;
        if (vlen != BLOB_DEDUP_VAL_LEN)
            return CDB_E_CORRUPT;
        refc = cdb_load_u64(val, db->pager.order);
        stored_first = cdb_load_u64(val + 8, db->pager.order);
        stored_count = cdb_load_u64(val + 16, db->pager.order);
        if (refc == 0 || stored_first == 0)
            return CDB_E_CORRUPT; /* a corrupt dedup entry */
        if (refc == UINT64_MAX)
            return CDB_E_OVERFLOW; /* saturate, never wrap (fail closed) */

        /* Bump and persist the refcount BEFORE releasing the duplicate chain,
         * so a failure between the two leaks storage rather than losing data. */
        blob_dedup_val_encode(val, refc + 1u, stored_first, stored_count,
                              cdb_load_u64(val + 24, db->pager.order),
                              cdb_load_u32(val + 32, db->pager.order), db->pager.order);
        if ((s = cdb_index_put(&ix, key, sizeof key, val, sizeof val)) != CDB_OK)
            return s;

        /* Release the just-written duplicate chain and return the stored ref. */
        if ((s = blob_len_within(out_ref->total_len, SIZE_MAX)) != CDB_OK)
            return s;
        if ((s = cdb_overflow_free(&db->pager, out_ref->first_page, store_id,
                                   (size_t)out_ref->total_len, page))
            != CDB_OK)
            return s;
        out_ref->first_page = stored_first;
        out_ref->page_count = stored_count;
        return CDB_OK;
    }

    /* First copy of this content in the domain: record refcount 1. */
    blob_dedup_val_encode(val, 1u, out_ref->first_page, out_ref->page_count, out_ref->total_len,
                          out_ref->flags, db->pager.order);
    return cdb_index_put(&ix, key, sizeof key, val, sizeof val);
}

cdb_status cdb_blob_free_db(cdb_db *db, uint64_t store_id, uint64_t domain, const cdb_blob_ref *ref,
                            uint8_t *page_buf)
{
    cdb_status s;
    cdb_index ix;
    int have, found;
    uint8_t key[BLOB_DEDUP_KEY_LEN], val[BLOB_DEDUP_VAL_LEN];
    size_t vlen;
    uint64_t refc;

    if (db == NULL || ref == NULL || page_buf == NULL)
        return CDB_E_INVALID_ARG;
    if (ref->first_page == 0 || ref->total_len == 0)
        return CDB_OK;
    if ((s = blob_len_within(ref->total_len, SIZE_MAX)) != CDB_OK)
        return s; /* guard the size_t conversion (FR5) */

    blob_dedup_key(domain, ref->hash, key);
    if ((s = blob_dedup_open(db, &ix, 0, &have)) != CDB_OK)
        return s;

    if (have) {
        if ((s = cdb_index_get(&ix, key, sizeof key, val, sizeof val, &vlen, &found)) != CDB_OK)
            return s;
        if (found) {
            if (vlen != BLOB_DEDUP_VAL_LEN)
                return CDB_E_CORRUPT;
            refc = cdb_load_u64(val, db->pager.order);
            if (refc == 0)
                return CDB_E_CORRUPT; /* a corrupt dedup entry */
            if (refc > 1u) {
                /* Still referenced: decrement and keep the pages. */
                blob_dedup_val_encode(val, refc - 1u, cdb_load_u64(val + 8, db->pager.order),
                                      cdb_load_u64(val + 16, db->pager.order),
                                      cdb_load_u64(val + 24, db->pager.order),
                                      cdb_load_u32(val + 32, db->pager.order), db->pager.order);
                return cdb_index_put(&ix, key, sizeof key, val, sizeof val);
            }
            /* Last reference: drop the entry and release the chain. */
            if ((s = cdb_index_delete(&ix, key, sizeof key, &found)) != CDB_OK)
                return s;
            return cdb_overflow_free(&db->pager, ref->first_page, store_id, (size_t)ref->total_len,
                                     page_buf);
        }
    }

    /* No dedup record (legacy or non-deduplicated ref): release directly. */
    return cdb_overflow_free(&db->pager, ref->first_page, store_id, (size_t)ref->total_len,
                             page_buf);
}
