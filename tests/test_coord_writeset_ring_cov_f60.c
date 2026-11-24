/* #60 B1 -- QA coverage + abuse companion for the reconciled-write-set ring
 * (spec 5.9.4 / 14.22). Disjoint from the implementation's red->green oracle
 * (test_coord_writeset_ring_f60.c): this file targets the branches and
 * adversarial paths that prove the FAIL-CLOSED #33 no-silent-loss invariant
 * holds even against a forged header, a wrapped ring, a torn wrapped entry, a
 * keyless (frontier-only) reconcile, and multi-key write sets.
 *
 * SAFETY CONTRACT UNDER TEST (negated form -- every one must REJECT):
 *   - a header whose CRC was recomputed after forging a structurally-impossible
 *     field (cap=0, cap>fit, count>cap, head>=cap, floor>top) -> CDB_E_CORRUPT
 *     on decode -> gate rejects (an attacker who re-seals the CRC still cannot
 *     admit),
 *   - an overlap that lands at a WRAPPED physical slot after eviction -> still
 *     caught (the scan reads the circular buffer correctly),
 *   - a torn entry at a wrapped slot -> whole decision rejected, never skipped,
 *   - append onto an old/forged archive -> propagates the typed error
 *     (UNSUPPORTED / CORRUPT), never silently advances the frontier,
 *   - a malformed batch (bad kind mid-batch) -> rejected WITHOUT advancing the
 *     frontier (no partial record).
 * And the one ALLOW that must hold: a provably covered, disjoint straddle --
 * including when the only in-range reconcile folded no keys at all.
 *
 * Pure, single-process, deterministic, hermetic: no network, clock, RNG, or
 * shared state. On the pre-fix merge-base cdb_wsring does not exist -> this TU
 * does not build (red); on the fix it builds and passes (green). */
#include <string.h>

#include "unity.h"

#include "cdb_crc32c.h"
#include "cdb_endian.h"
#include "cdb_wsring.h"

/* Header/entry offsets mirrored from cdb_wsring.c (spec 14.22) so the abuse
 * tests can forge a field and re-seal the header CRC. If the layout ever
 * changes these must change with it -- a drift here is itself a caught defect. */
#define HOFF_VERSION 4u
#define HOFF_CAP 8u
#define HOFF_COUNT 12u
#define HOFF_HEAD 16u
#define HOFF_FLOOR 24u
#define HOFF_TOP 32u
#define HOFF_HDR_CRC 60u
#define EOFF_SEQ 0u
#define EOFF_STORE 8u

/* cap = (224 - 64) / 40 = 4: small enough to force eviction and wrap-around. */
#define REGION_LEN 224u
#define REGION_CAP 4u

void setUp(void)
{
}
void tearDown(void)
{
}

static cdb_wsring_key dkey(uint64_t store, uint64_t entry)
{
    cdb_wsring_key k;
    k.store = store;
    k.entry = entry;
    k.key_tag = 0;
    k.kind = CDB_WSRING_KIND_DATA;
    return k;
}

static cdb_wsring_key hkey(uint64_t store, uint64_t tag)
{
    cdb_wsring_key k;
    k.store = store;
    k.entry = 0;
    k.key_tag = tag;
    k.kind = CDB_WSRING_KIND_KEYHASH;
    return k;
}

static int allow_of(const uint8_t *region, size_t len, cdb_byte_order order,
                    const cdb_wsring_key *own, size_t nown, uint64_t base, uint64_t current)
{
    int allow = -1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_straddle_disjoint(region, len, order, own, nown, base,
                                                               current, &allow));
    TEST_ASSERT_TRUE(allow == 0 || allow == 1); /* never a third state */
    return allow;
}

/* Recompute and store the header CRC over [0, 60) so a forged field passes the
 * CRC check and must be caught by the structural range checks instead. */
static void reseal_header(uint8_t *region, cdb_byte_order order)
{
    uint32_t crc = cdb_crc32c(region, HOFF_HDR_CRC);
    cdb_store_u32(region + HOFF_HDR_CRC, crc, order);
}

/* Flip one byte in the STORE field of whichever physical slot currently holds
 * seq target_seq (used to corrupt an entry after the ring has wrapped). */
static int corrupt_entry_with_seq(uint8_t *region, cdb_byte_order order, uint64_t target_seq)
{
    uint32_t slot;
    for (slot = 0; slot < REGION_CAP; slot++) {
        uint8_t *e = region + CDB_WSRING_HDR_SIZE + (size_t)slot * CDB_WSRING_ENTRY_SIZE;
        if (cdb_load_u64(e + EOFF_SEQ, order) == target_seq) {
            e[EOFF_STORE] ^= 0xFFu;
            return 1;
        }
    }
    return 0;
}

/* --- format edge: exact minimum region is a usable cap-1 ring --- */

static void test_format_min_region_cap_one(void)
{
    uint8_t region[CDB_WSRING_MIN_REGION];
    cdb_wsring_key a = dkey(1, 10), b = dkey(1, 11), own = dkey(2, 2);
    uint32_t cap = 0;
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_wsring_format(region, CDB_WSRING_MIN_REGION, CDB_ORDER_LITTLE, &cap));
    TEST_ASSERT_EQUAL_UINT32(1u, cap);
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_wsring_append(region, CDB_WSRING_MIN_REGION, CDB_ORDER_LITTLE, 5, &a, 1));
    TEST_ASSERT_EQUAL_INT(1, cdb_wsring_covers(region, CDB_WSRING_MIN_REGION, CDB_ORDER_LITTLE, 4, 5));
    /* the single slot holds seq 5; appending seq 6 evicts it -> floor rises to 5 */
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_wsring_append(region, CDB_WSRING_MIN_REGION, CDB_ORDER_LITTLE, 6, &b, 1));
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(region, CDB_WSRING_MIN_REGION, CDB_ORDER_LITTLE, 4, 6));
    TEST_ASSERT_EQUAL_INT(1, cdb_wsring_covers(region, CDB_WSRING_MIN_REGION, CDB_ORDER_LITTLE, 5, 6));
    TEST_ASSERT_EQUAL_INT(1, allow_of(region, CDB_WSRING_MIN_REGION, CDB_ORDER_LITTLE, &own, 1, 5, 6));
}

/* --- append contract: NULL/invalid inputs fail closed --- */

static void test_append_rejects_null_and_bad_kind(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key good = dkey(1, 1), bad = dkey(1, 2);
    cdb_wsring_key batch[2];
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    /* NULL region */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_wsring_append(NULL, REGION_LEN, CDB_ORDER_LITTLE, 5, &good, 1));
    /* NULL keys with nkeys > 0 */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 5, NULL, 1));
    /* an unknown kind anywhere in the batch is refused, and -- the point -- the
     * frontier must NOT advance: a malformed batch records nothing. */
    batch[0] = good;
    batch[1] = bad;
    batch[1].kind = 0x7Fu; /* neither DATA nor KEYHASH */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 5, batch, 2));
    /* top_seq is still 0 -> nothing is covered, and a fresh seq-5 append still
     * works (the earlier failure left the frontier at 0, not at 5). */
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 0, 5));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 5, &good, 1));
}

/* --- frontier-only (keyless) reconcile advances coverage but folds no key --- */

static void test_keyless_reconcile_advances_frontier_and_allows(void)
{
    /* A reconcile that folded no key-bearing record still advances top_seq, so a
     * straddling disjoint committer is ALLOWED (the range is covered and the
     * only thing in it carries no key to intersect). */
    uint8_t region[REGION_LEN];
    cdb_wsring_key own = dkey(1, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 5, NULL, 0));
    TEST_ASSERT_EQUAL_INT(1, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 4, 5));
    TEST_ASSERT_EQUAL_INT(1, allow_of(region, REGION_LEN, CDB_ORDER_LITTLE, &own, 1, 4, 5));
    /* a lower seq is still refused after a keyless bump (monotonic frontier) */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 4, NULL, 0));
}

/* --- empty own write set is trivially disjoint when covered --- */

static void test_empty_own_set_is_disjoint_when_covered(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key a = dkey(1, 10);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 6, &a, 1));
    /* nown == 0 with own == NULL does not trip the NULL guard; nothing to
     * intersect -> allowed on a covered range. */
    TEST_ASSERT_EQUAL_INT(1, allow_of(region, REGION_LEN, CDB_ORDER_LITTLE, NULL, 0, 4, 6));
    /* ...but an uncovered empty set is still rejected (coverage comes first). */
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, REGION_LEN, CDB_ORDER_LITTLE, NULL, 0, 4, 7));
}

/* --- multi-key own set: one hit rejects, all-disjoint allows --- */

static void test_multikey_own_set_detection_not_relaxed(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key rec = dkey(3, 30);
    cdb_wsring_key hit[3], miss[3];
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 6, &rec, 1));
    /* one of three own keys collides with the reconciled (3,30) -> reject */
    hit[0] = dkey(9, 1);
    hit[1] = dkey(3, 30);
    hit[2] = hkey(3, 30); /* same numbers but KEYHASH kind: must NOT rescue it */
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, REGION_LEN, CDB_ORDER_LITTLE, hit, 3, 4, 6));
    /* all three disjoint -> allow */
    miss[0] = dkey(9, 1);
    miss[1] = dkey(3, 31);
    miss[2] = hkey(3, 30);
    TEST_ASSERT_EQUAL_INT(1, allow_of(region, REGION_LEN, CDB_ORDER_LITTLE, miss, 3, 4, 6));
}

/* --- multi-key batch appended at one seq --- */

static void test_multikey_batch_one_seq(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key batch[3];
    cdb_wsring_key hit = dkey(2, 20), miss = dkey(2, 99);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    batch[0] = dkey(2, 20);
    batch[1] = dkey(2, 21);
    batch[2] = hkey(2, 0xFEu);
    /* three keys folded at committed_seq 7 in one reconcile */
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 7, batch, 3));
    TEST_ASSERT_EQUAL_INT(1, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 6, 7));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, REGION_LEN, CDB_ORDER_LITTLE, &hit, 1, 6, 7));
    TEST_ASSERT_EQUAL_INT(1, allow_of(region, REGION_LEN, CDB_ORDER_LITTLE, &miss, 1, 6, 7));
}

/* --- wrap-around: an overlap at a wrapped physical slot is still caught --- */

static void test_wraparound_overlap_still_detected(void)
{
    /* Fill cap=4 then evict past it so head wraps; the live entries (5..8) sit at
     * wrapped physical slots. An own key reconciled away at seq 7 (a wrapped
     * slot) must still be REJECTED, while a disjoint key is ALLOWED. This proves
     * the circular scan reads wrapped slots -- a silent wrap bug would admit the
     * #33 data-loss case. */
    uint8_t region[REGION_LEN];
    cdb_wsring_key k, own_hit = dkey(1, 7), own_ok = dkey(1, 99);
    uint64_t seq;
    for (seq = 0; seq < 1; seq++) /* keep -Wunused-but-set quiet on some toolchains */
        (void)seq;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    for (seq = 1; seq <= 8; seq++) {
        k = dkey(1, seq);
        TEST_ASSERT_EQUAL_INT(CDB_OK,
                              cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, seq, &k, 1));
    }
    /* floor rose to 4 (seqs 1..4 evicted); live range is (4, 8]. */
    TEST_ASSERT_EQUAL_INT(1, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 4, 8));
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 3, 8));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, REGION_LEN, CDB_ORDER_LITTLE, &own_hit, 1, 4, 8));
    TEST_ASSERT_EQUAL_INT(1, allow_of(region, REGION_LEN, CDB_ORDER_LITTLE, &own_ok, 1, 4, 8));
}

static void test_wraparound_torn_entry_rejects(void)
{
    /* As above, but corrupt the wrapped entry that holds seq 7. The scan must
     * CRC-validate every slot it crosses and fail closed, never skip the torn
     * entry out of the range (which would hide the overlap). */
    uint8_t region[REGION_LEN];
    cdb_wsring_key k, own_ok = dkey(1, 99);
    uint64_t seq;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    for (seq = 1; seq <= 8; seq++) {
        k = dkey(1, seq);
        TEST_ASSERT_EQUAL_INT(CDB_OK,
                              cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, seq, &k, 1));
    }
    TEST_ASSERT_EQUAL_INT(1, corrupt_entry_with_seq(region, CDB_ORDER_LITTLE, 7));
    /* header still validates -> covers() is true... */
    TEST_ASSERT_EQUAL_INT(1, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 4, 8));
    /* ...but the per-entry CRC check in the scan rejects the whole decision, even
     * for a genuinely-disjoint own key. */
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, REGION_LEN, CDB_ORDER_LITTLE, &own_ok, 1, 4, 8));
}

/* --- forged header: CRC re-sealed but a structural field is impossible --- */

static void forge_and_assert_rejected(uint32_t off, uint64_t val, int is_u64)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key a = dkey(1, 10), own = dkey(2, 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 6, &a, 1));
    if (is_u64)
        cdb_store_u64(region + off, val, CDB_ORDER_LITTLE);
    else
        cdb_store_u32(region + off, (uint32_t)val, CDB_ORDER_LITTLE);
    reseal_header(region, CDB_ORDER_LITTLE); /* CRC now matches the forged field */
    /* decode's range checks (not the CRC) must catch it -> fail closed */
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 4, 6));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, REGION_LEN, CDB_ORDER_LITTLE, &own, 1, 4, 6));
    /* and the write path refuses to append onto a structurally-corrupt header */
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 7, &a, 1));
}

static void test_forged_header_cap_zero_rejected(void)
{
    forge_and_assert_rejected(HOFF_CAP, 0, 0);
}
static void test_forged_header_cap_over_fit_rejected(void)
{
    forge_and_assert_rejected(HOFF_CAP, REGION_CAP + 1u, 0);
}
static void test_forged_header_count_over_cap_rejected(void)
{
    forge_and_assert_rejected(HOFF_COUNT, REGION_CAP + 1u, 0);
}
static void test_forged_header_head_ge_cap_rejected(void)
{
    forge_and_assert_rejected(HOFF_HEAD, REGION_CAP, 0);
}
static void test_forged_header_floor_over_top_rejected(void)
{
    /* top_seq == 6 after the append; floor 7 > top -> corrupt */
    forge_and_assert_rejected(HOFF_FLOOR, 7, 1);
}

/* --- old/unknown format on the WRITE path propagates the typed error --- */

static void test_append_on_unknown_format_propagates_unsupported(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key a = dkey(1, 10);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 6, &a, 1));
    /* bump to a version this build predates (checked before the CRC in decode) */
    cdb_store_u16(region + HOFF_VERSION, (uint16_t)(CDB_WSRING_FORMAT_VERSION + 1u),
                  CDB_ORDER_LITTLE);
    TEST_ASSERT_EQUAL_INT(CDB_E_UNSUPPORTED,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 7, &a, 1));
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 4, 6));
}

/* --- tiny / too-small regions --- */

static void test_subheader_region_rejected(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key own = dkey(1, 1);
    size_t tiny = CDB_WSRING_HDR_SIZE - 1u;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 6, &own, 1));
    /* a length that cannot even hold the header decodes as corrupt -> rejected */
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(region, tiny, CDB_ORDER_LITTLE, 4, 6));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, tiny, CDB_ORDER_LITTLE, &own, 1, 4, 6));
    TEST_ASSERT_EQUAL_INT(CDB_E_CORRUPT,
                          cdb_wsring_append(region, tiny, CDB_ORDER_LITTLE, 7, &own, 1));
}

static void test_null_region_straddle_rejected(void)
{
    cdb_wsring_key own = dkey(1, 1);
    /* a NULL region is a decode error -> covers 0, allow 0, status still OK so
     * the decision is carried only in *allow (the caller cannot admit on it). */
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(NULL, REGION_LEN, CDB_ORDER_LITTLE, 4, 6));
    TEST_ASSERT_EQUAL_INT(0, allow_of(NULL, REGION_LEN, CDB_ORDER_LITTLE, &own, 1, 4, 6));
}

/* --- own == NULL with nown > 0 is ambiguous -> rejected, status OK --- */

static void test_null_own_with_count_is_rejected_not_errored(void)
{
    uint8_t region[REGION_LEN];
    int allow = -1;
    cdb_wsring_key a = dkey(1, 10);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 6, &a, 1));
    /* nown=1 but own=NULL: the gate stays rejected (allow=0) and returns OK -- a
     * committer that forgot to pass its keys must not be admitted. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_straddle_disjoint(region, REGION_LEN, CDB_ORDER_LITTLE,
                                                               NULL, 1, 4, 6, &allow));
    TEST_ASSERT_EQUAL_INT(0, allow);
}

/* --- big-endian forged-header path (byte-order independence of the guard) --- */

static void test_forged_header_big_endian_rejected(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key a = dkey(1, 10), own = dkey(2, 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_BIG, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_append(region, REGION_LEN, CDB_ORDER_BIG, 6, &a, 1));
    cdb_store_u32(region + HOFF_COUNT, REGION_CAP + 1u, CDB_ORDER_BIG); /* count > cap */
    cdb_store_u32(region + HOFF_HDR_CRC, cdb_crc32c(region, HOFF_HDR_CRC), CDB_ORDER_BIG);
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_BIG, 4, 6));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, REGION_LEN, CDB_ORDER_BIG, &own, 1, 4, 6));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_format_min_region_cap_one);
    RUN_TEST(test_append_rejects_null_and_bad_kind);
    RUN_TEST(test_keyless_reconcile_advances_frontier_and_allows);
    RUN_TEST(test_empty_own_set_is_disjoint_when_covered);
    RUN_TEST(test_multikey_own_set_detection_not_relaxed);
    RUN_TEST(test_multikey_batch_one_seq);
    RUN_TEST(test_wraparound_overlap_still_detected);
    RUN_TEST(test_wraparound_torn_entry_rejects);
    RUN_TEST(test_forged_header_cap_zero_rejected);
    RUN_TEST(test_forged_header_cap_over_fit_rejected);
    RUN_TEST(test_forged_header_count_over_cap_rejected);
    RUN_TEST(test_forged_header_head_ge_cap_rejected);
    RUN_TEST(test_forged_header_floor_over_top_rejected);
    RUN_TEST(test_append_on_unknown_format_propagates_unsupported);
    RUN_TEST(test_subheader_region_rejected);
    RUN_TEST(test_null_region_straddle_rejected);
    RUN_TEST(test_null_own_with_count_is_rejected_not_errored);
    RUN_TEST(test_forged_header_big_endian_rejected);
    return UNITY_END();
}
