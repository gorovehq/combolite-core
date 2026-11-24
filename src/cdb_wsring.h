/* Reconciled-write-set ring (#60 B1, spec 5.9.4 / 14.22).
 *
 * A bounded, append-only, format-versioned record of the write-set keys of
 * every transaction a reconcile has folded into the archive, each tagged with
 * the committed_seq at which it was reconciled. It lets coordinate_commit
 * narrow the blanket "committed_seq moved -> COLLISION" gate: a committer whose
 * disjoint write set merely straddles a peer reconcile can be ALLOWED, while a
 * writer whose write set was reconciled away (so check_slot_collisions can no
 * longer see it) is still REJECTED.
 *
 * SAFETY (the #33 no-silent-loss invariant): every operation is FAIL-CLOSED.
 * The gate proves disjointness only when the ring provably covers the straddle
 * range AND no key intersects; absence, incomplete coverage, a torn/corrupt
 * region, an old format, or any error -> reject (never admit). A false
 * collision is retryable; a silently-admitted reconciled overlap is data loss.
 *
 * The ring is a pure structure over a caller-provided byte region (in the
 * archive it is a pinned page region rooted by a header anchor and published
 * durably by the same pager commit that raises committed_seq; in tests it is a
 * plain buffer). It is written only by the single reconciling baton holder and
 * read by committers from a read-only archive snapshot. A committer that reads
 * a half-published or torn region takes the conservative fallback.
 */
#ifndef CDB_WSRING_H
#define CDB_WSRING_H

#include <stddef.h>
#include <stdint.h>

#include "combolite/cdb_common.h"

/* On-disk identity and versioning (spec 14.22). A reader that predates the ring
 * never finds the header anchor and uses the conservative gate; a reader on a
 * newer major version it does not understand treats the region as absent
 * (fail-closed). */
#define CDB_WSRING_MAGIC0 'W'
#define CDB_WSRING_MAGIC1 'S'
#define CDB_WSRING_MAGIC2 'R'
#define CDB_WSRING_MAGIC3 '1'
#define CDB_WSRING_FORMAT_VERSION 1u

/* Fixed on-disk sizes (bytes). The header and each entry carry their own
 * CRC32C so a torn write is detected and rejected rather than trusted. */
#define CDB_WSRING_HDR_SIZE 64u
#define CDB_WSRING_ENTRY_SIZE 40u

/* Hard upper bound on retained entries (R-B: the intersection scan is bounded
 * by the ring size, which is bounded by this named cap; no loop is unbounded by
 * external state). The usable cap is min(this, entries that fit the region). A
 * flood of reconciles evicts oldest-first and raises floor_seq, degrading the
 * gate to conservative rejection (safe, retryable) -- never unbounded growth or
 * an unbounded scan. */
#define CDB_WSRING_MAX_ENTRIES 4096u

/* Minimum region to hold the header and at least one entry. */
#define CDB_WSRING_MIN_REGION (CDB_WSRING_HDR_SIZE + CDB_WSRING_ENTRY_SIZE)

/* A write-set key, as recorded and as matched. A (store, entry) data key and a
 * unique-index key hash are distinct kinds and never match across kinds. */
#define CDB_WSRING_KIND_DATA 0u    /* (store, entry) data record */
#define CDB_WSRING_KIND_KEYHASH 1u /* (store, key_tag) unique-index write-key */

typedef struct cdb_wsring_key {
    uint64_t store;
    uint64_t entry;   /* significant for CDB_WSRING_KIND_DATA */
    uint64_t key_tag; /* significant for CDB_WSRING_KIND_KEYHASH */
    uint8_t kind;
} cdb_wsring_key;

/* Formats a fresh, empty ring over region[0, len) (count=0, floor_seq=0,
 * top_seq=0). CDB_E_INVALID_ARG if the region is too small. The usable cap is
 * returned in *cap_out when non-NULL. */
cdb_status cdb_wsring_format(uint8_t *region, size_t len, cdb_byte_order order, uint32_t *cap_out);

/* Appends a reconcile batch, tagged with committed_seq seq, that folded the
 * keys[0, nkeys) write-set keys into the archive. Single-writer (baton holder)
 * only. Evicts oldest-first to make room, raising floor_seq to the highest
 * evicted tag so coverage of any range including an evicted seq fails closed.
 *
 * seq must be >= the ring's current top_seq (the reconcile frontier only
 * advances); a lower seq, a corrupt region, or a too-small region is
 * CDB_E_INVALID_ARG / CDB_E_CORRUPT and the ring is left for the caller to reformat.
 * nkeys==0 still advances top_seq (a reconcile that folded no key-bearing
 * record), recording that the frontier reached seq. */
cdb_status cdb_wsring_append(uint8_t *region, size_t len, cdb_byte_order order, uint64_t seq,
                             const cdb_wsring_key *keys, size_t nkeys);

/* 1 iff the ring decodes cleanly AND provably covers (base, current]:
 * current > base, floor_seq <= base (nothing in the range was evicted), and
 * top_seq >= current (the frontier reached current). 0 otherwise, including any
 * decode/CRC/structure error (fail-closed). */
int cdb_wsring_covers(const uint8_t *region, size_t len, cdb_byte_order order, uint64_t base,
                      uint64_t current);

/* The gate decision. Sets *allow = 1 ONLY when the ring provably covers
 * (base, current] AND no retained entry tagged in (base, current] matches any
 * of own[0, nown). Otherwise *allow = 0. *allow defaults to 0 and is set to 0
 * on every error/ambiguity path (incomplete coverage, absent/torn/corrupt
 * region, old/unknown format) -- the committer must reject on *allow == 0.
 * Returns CDB_OK unless a caller contract is violated (NULL out); the decision
 * is carried entirely in *allow so the caller cannot accidentally admit on a
 * non-OK status. */
cdb_status cdb_wsring_straddle_disjoint(const uint8_t *region, size_t len, cdb_byte_order order,
                                        const cdb_wsring_key *own, size_t nown, uint64_t base,
                                        uint64_t current, int *allow);

#endif
