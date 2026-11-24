/* Reconciled-write-set ring (#60 B1). See cdb_wsring.h for the contract and
 * the fail-closed safety invariant. */
#include "cdb_wsring.h"

#include <string.h>

#include "cdb_crc32c.h"
#include "cdb_endian.h"

/* Header field offsets (spec 14.22). */
#define WSR_OFF_MAGIC 0u
#define WSR_OFF_VERSION 4u
#define WSR_OFF_CAP 8u
#define WSR_OFF_COUNT 12u
#define WSR_OFF_HEAD 16u
#define WSR_OFF_FLOOR 24u
#define WSR_OFF_TOP 32u
#define WSR_OFF_HDR_CRC 60u /* CRC32C over bytes [0, 60) */

/* Entry field offsets within a CDB_WSRING_ENTRY_SIZE record. */
#define WSR_E_SEQ 0u
#define WSR_E_STORE 8u
#define WSR_E_ENTRY 16u
#define WSR_E_KEY_TAG 24u
#define WSR_E_KIND 32u
#define WSR_E_CRC 36u /* CRC32C over bytes [0, 36) */

/* The decoded, validated ring header -- an in-memory view, never trusted
 * beyond what decode_header checked. */
struct wsr_hdr {
    uint32_t cap;
    uint32_t count;
    uint32_t head;
    uint64_t floor_seq;
    uint64_t top_seq;
};

/* How many entries fit a region of len bytes, capped at the named maximum. */
static uint32_t region_cap(size_t len)
{
    size_t fit;
    if (len < CDB_WSRING_MIN_REGION)
        return 0;
    fit = (len - CDB_WSRING_HDR_SIZE) / CDB_WSRING_ENTRY_SIZE;
    if (fit > CDB_WSRING_MAX_ENTRIES)
        fit = CDB_WSRING_MAX_ENTRIES;
    return (uint32_t)fit;
}

/* Parses and fully validates the ring header. Fail-closed: any bad magic,
 * unknown version, out-of-range field, or CRC mismatch is an error, so a torn
 * or old-format region is never read as a valid (empty-or-covering) ring. */
static cdb_status decode_header(const uint8_t *region, size_t len, cdb_byte_order order,
                                struct wsr_hdr *h)
{
    uint32_t stored_crc, calc_crc, max_cap;
    uint16_t version;

    if (region == NULL || len < CDB_WSRING_HDR_SIZE)
        return CDB_E_CORRUPT;
    if (region[WSR_OFF_MAGIC + 0] != CDB_WSRING_MAGIC0
        || region[WSR_OFF_MAGIC + 1] != CDB_WSRING_MAGIC1
        || region[WSR_OFF_MAGIC + 2] != CDB_WSRING_MAGIC2
        || region[WSR_OFF_MAGIC + 3] != CDB_WSRING_MAGIC3)
        return CDB_E_CORRUPT;
    version = cdb_load_u16(region + WSR_OFF_VERSION, order);
    if (version != CDB_WSRING_FORMAT_VERSION)
        return CDB_E_UNSUPPORTED; /* a format this build does not understand */

    stored_crc = cdb_load_u32(region + WSR_OFF_HDR_CRC, order);
    calc_crc = cdb_crc32c(region, WSR_OFF_HDR_CRC);
    if (stored_crc != calc_crc)
        return CDB_E_CORRUPT;

    h->cap = cdb_load_u32(region + WSR_OFF_CAP, order);
    h->count = cdb_load_u32(region + WSR_OFF_COUNT, order);
    h->head = cdb_load_u32(region + WSR_OFF_HEAD, order);
    h->floor_seq = cdb_load_u64(region + WSR_OFF_FLOOR, order);
    h->top_seq = cdb_load_u64(region + WSR_OFF_TOP, order);

    max_cap = region_cap(len);
    if (h->cap == 0 || h->cap > max_cap)
        return CDB_E_CORRUPT;
    if (h->count > h->cap)
        return CDB_E_CORRUPT;
    if (h->head >= h->cap)
        return CDB_E_CORRUPT;
    if (h->floor_seq > h->top_seq)
        return CDB_E_CORRUPT;
    return CDB_OK;
}

/* Writes the header image back, recomputing its CRC. */
static void encode_header(uint8_t *region, cdb_byte_order order, const struct wsr_hdr *h)
{
    uint32_t crc;
    region[WSR_OFF_MAGIC + 0] = CDB_WSRING_MAGIC0;
    region[WSR_OFF_MAGIC + 1] = CDB_WSRING_MAGIC1;
    region[WSR_OFF_MAGIC + 2] = CDB_WSRING_MAGIC2;
    region[WSR_OFF_MAGIC + 3] = CDB_WSRING_MAGIC3;
    cdb_store_u16(region + WSR_OFF_VERSION, (uint16_t)CDB_WSRING_FORMAT_VERSION, order);
    cdb_store_u16(region + 6, 0, order);
    cdb_store_u32(region + WSR_OFF_CAP, h->cap, order);
    cdb_store_u32(region + WSR_OFF_COUNT, h->count, order);
    cdb_store_u32(region + WSR_OFF_HEAD, h->head, order);
    cdb_store_u32(region + 20, 0, order);
    cdb_store_u64(region + WSR_OFF_FLOOR, h->floor_seq, order);
    cdb_store_u64(region + WSR_OFF_TOP, h->top_seq, order);
    memset(region + 40, 0, 20);
    crc = cdb_crc32c(region, WSR_OFF_HDR_CRC);
    cdb_store_u32(region + WSR_OFF_HDR_CRC, crc, order);
}

static uint8_t *entry_ptr(uint8_t *region, uint32_t slot)
{
    return region + CDB_WSRING_HDR_SIZE + (size_t)slot * CDB_WSRING_ENTRY_SIZE;
}

static const uint8_t *entry_cptr(const uint8_t *region, uint32_t slot)
{
    return region + CDB_WSRING_HDR_SIZE + (size_t)slot * CDB_WSRING_ENTRY_SIZE;
}

static void write_entry(uint8_t *e, cdb_byte_order order, uint64_t seq, const cdb_wsring_key *k)
{
    uint32_t crc;
    cdb_store_u64(e + WSR_E_SEQ, seq, order);
    cdb_store_u64(e + WSR_E_STORE, k->store, order);
    cdb_store_u64(e + WSR_E_ENTRY, k->kind == CDB_WSRING_KIND_DATA ? k->entry : 0, order);
    cdb_store_u64(e + WSR_E_KEY_TAG, k->kind == CDB_WSRING_KIND_KEYHASH ? k->key_tag : 0, order);
    e[WSR_E_KIND] = k->kind;
    e[33] = 0;
    e[34] = 0;
    e[35] = 0;
    crc = cdb_crc32c(e, WSR_E_CRC);
    cdb_store_u32(e + WSR_E_CRC, crc, order);
}

/* Reads and CRC-validates one entry. Fail-closed: a torn entry (CRC mismatch)
 * or unknown kind is CDB_E_CORRUPT so it can never be silently skipped out of
 * the intersection range. */
static cdb_status read_entry(const uint8_t *e, cdb_byte_order order, uint64_t *seq,
                             cdb_wsring_key *k)
{
    uint32_t stored_crc = cdb_load_u32(e + WSR_E_CRC, order);
    uint32_t calc_crc = cdb_crc32c(e, WSR_E_CRC);
    if (stored_crc != calc_crc)
        return CDB_E_CORRUPT;
    *seq = cdb_load_u64(e + WSR_E_SEQ, order);
    k->store = cdb_load_u64(e + WSR_E_STORE, order);
    k->entry = cdb_load_u64(e + WSR_E_ENTRY, order);
    k->key_tag = cdb_load_u64(e + WSR_E_KEY_TAG, order);
    k->kind = e[WSR_E_KIND];
    if (k->kind != CDB_WSRING_KIND_DATA && k->kind != CDB_WSRING_KIND_KEYHASH)
        return CDB_E_CORRUPT;
    return CDB_OK;
}

static int keys_match(const cdb_wsring_key *a, const cdb_wsring_key *b)
{
    if (a->kind != b->kind || a->store != b->store)
        return 0;
    if (a->kind == CDB_WSRING_KIND_DATA)
        return a->entry == b->entry;
    return a->key_tag == b->key_tag; /* CDB_WSRING_KIND_KEYHASH */
}

cdb_status cdb_wsring_format(uint8_t *region, size_t len, cdb_byte_order order, uint32_t *cap_out)
{
    struct wsr_hdr h;
    uint32_t cap = region_cap(len);
    if (region == NULL || cap == 0)
        return CDB_E_INVALID_ARG;
    h.cap = cap;
    h.count = 0;
    h.head = 0;
    h.floor_seq = 0;
    h.top_seq = 0;
    /* Zero the entry area so a never-written slot is a clean (if CRC-invalid)
     * region, not stale bytes from a prior tenant. */
    memset(region + CDB_WSRING_HDR_SIZE, 0, (size_t)cap * CDB_WSRING_ENTRY_SIZE);
    encode_header(region, order, &h);
    if (cap_out != NULL)
        *cap_out = cap;
    return CDB_OK;
}

cdb_status cdb_wsring_append(uint8_t *region, size_t len, cdb_byte_order order, uint64_t seq,
                             const cdb_wsring_key *keys, size_t nkeys)
{
    struct wsr_hdr h;
    size_t i;
    cdb_status s;

    if (region == NULL || (nkeys > 0 && keys == NULL))
        return CDB_E_INVALID_ARG;
    if ((s = decode_header(region, len, order, &h)) != CDB_OK)
        return s;
    /* The reconcile frontier only advances (R-A single-writer, monotonic). */
    if (seq < h.top_seq || seq == 0)
        return CDB_E_INVALID_ARG;

    for (i = 0; i < nkeys; i++) {
        uint32_t slot;
        const cdb_wsring_key *k = &keys[i];
        if (k->kind != CDB_WSRING_KIND_DATA && k->kind != CDB_WSRING_KIND_KEYHASH)
            return CDB_E_INVALID_ARG;
        if (h.count == h.cap) {
            /* Evict oldest-first; its tag raises floor_seq so any range that
             * includes an evicted seq fails coverage (fail-closed). */
            uint64_t ev_seq = cdb_load_u64(entry_cptr(region, h.head) + WSR_E_SEQ, order);
            if (ev_seq > h.floor_seq)
                h.floor_seq = ev_seq;
            h.head = (h.head + 1u) % h.cap;
            h.count--;
        }
        slot = (h.head + h.count) % h.cap;
        write_entry(entry_ptr(region, slot), order, seq, k);
        h.count++;
    }
    h.top_seq = seq; /* seq >= old top_seq, checked above */
    encode_header(region, order, &h);
    return CDB_OK;
}

int cdb_wsring_covers(const uint8_t *region, size_t len, cdb_byte_order order, uint64_t base,
                      uint64_t current)
{
    struct wsr_hdr h;
    if (decode_header(region, len, order, &h) != CDB_OK)
        return 0; /* absent/old/torn -> not covered (fail-closed) */
    if (current <= base)
        return 0; /* no straddle to prove */
    if (h.floor_seq > base)
        return 0; /* part of the range was evicted */
    if (h.top_seq < current)
        return 0; /* the frontier has not reached current */
    return 1;
}

cdb_status cdb_wsring_straddle_disjoint(const uint8_t *region, size_t len, cdb_byte_order order,
                                        const cdb_wsring_key *own, size_t nown, uint64_t base,
                                        uint64_t current, int *allow)
{
    struct wsr_hdr h;
    uint32_t j;

    if (allow == NULL)
        return CDB_E_INVALID_ARG;
    *allow = 0; /* fail-closed default: the committer rejects on 0 */

    if (nown > 0 && own == NULL)
        return CDB_OK; /* ambiguous input -> stay rejected */
    if (!cdb_wsring_covers(region, len, order, base, current))
        return CDB_OK; /* incomplete coverage / absent / torn -> rejected */
    if (decode_header(region, len, order, &h) != CDB_OK)
        return CDB_OK; /* re-decode guard (covers already checked) */

    /* Scan every retained entry (bounded by count <= cap <= CDB_WSRING_MAX_ENTRIES).
     * Validate each entry's CRC before trusting its seq, so a torn entry can
     * never be silently filtered out of the (base, current] range. */
    for (j = 0; j < h.count; j++) {
        uint32_t slot = (h.head + j) % h.cap;
        uint64_t eseq;
        cdb_wsring_key ek;
        size_t i;
        if (read_entry(entry_cptr(region, slot), order, &eseq, &ek) != CDB_OK)
            return CDB_OK; /* torn/corrupt entry -> rejected */
        if (eseq <= base || eseq > current)
            continue; /* outside the straddle range */
        for (i = 0; i < nown; i++) {
            if (keys_match(&ek, &own[i]))
                return CDB_OK; /* reconciled-away overlap -> rejected */
        }
    }
    *allow = 1; /* proven covered and disjoint */
    return CDB_OK;
}
