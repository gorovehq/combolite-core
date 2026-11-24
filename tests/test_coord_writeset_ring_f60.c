/* #60 B1 -- deterministic red->green oracle for the reconciled-write-set ring
 * intersection + coverage logic (spec 5.9.4 / 14.22). Pure, single-process,
 * drivable without the coordinator. Proves the two halves of the safety
 * contract that let coordinate_commit narrow its blanket collision gate:
 *
 *   - a disjoint write set that merely straddles a reconcile is ALLOWED when
 *     the ring provably covers the range, and
 *   - every unsafe case is FAIL-CLOSED (rejected): a real/reconciled-away
 *     overlap, incomplete coverage (eviction/overflow), a torn/corrupt region,
 *     and an old/unknown format.
 *
 * On the pre-fix merge-base the ring module does not exist, so this test does
 * not build -- red; on the fix it builds and passes -- green. */
#include <string.h>

#include "unity.h"

#include "cdb_wsring.h"

void setUp(void)
{
}
void tearDown(void)
{
}

/* cap = (224 - 64) / 40 = 4 entries: small enough to force eviction/overflow. */
#define REGION_LEN 224u
#define REGION_CAP 4u

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

static int allow_of(const uint8_t *region, cdb_byte_order order, const cdb_wsring_key *own,
                    size_t nown, uint64_t base, uint64_t current)
{
    int allow = -1;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_straddle_disjoint(region, REGION_LEN, order, own, nown,
                                                               base, current, &allow));
    TEST_ASSERT_TRUE(allow == 0 || allow == 1);
    return allow;
}

/* --- format & monotonic append contract --- */

static void test_format_reports_cap_and_rejects_tiny_region(void)
{
    uint8_t region[REGION_LEN];
    uint32_t cap = 0;
    uint8_t tiny[CDB_WSRING_MIN_REGION - 1u];

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, &cap));
    TEST_ASSERT_EQUAL_UINT32(REGION_CAP, cap);
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_wsring_format(tiny, sizeof tiny, CDB_ORDER_LITTLE, NULL));
}

static void test_append_frontier_is_monotonic(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key k = dkey(1, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 5, &k, 1));
    /* seq below the frontier, or 0, is refused (single-writer, advances only). */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 4, &k, 1));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 0, &k, 1));
    /* equal frontier is allowed (one commit folds many txs at one seq). */
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 5, &k, 1));
}

/* --- the core narrowing: disjoint ALLOW, overlap REJECT --- */

static void test_disjoint_straddle_is_allowed(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key a = dkey(1, 10), b = dkey(1, 11), own = dkey(2, 99);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 5, &a, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 6, &b, 1));
    TEST_ASSERT_EQUAL_INT(1, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 4, 6));
    TEST_ASSERT_EQUAL_INT(1, allow_of(region, CDB_ORDER_LITTLE, &own, 1, 4, 6));
}

static void test_reconciled_overlap_still_rejected(void)
{
    /* The cardinal #33 case: own's key WAS reconciled away by a peer between
     * base and now -- it is in the ring at a seq in range -> still rejected. */
    uint8_t region[REGION_LEN];
    cdb_wsring_key a = dkey(1, 10), b = dkey(1, 11), own = dkey(1, 11);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 5, &a, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 6, &b, 1));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, CDB_ORDER_LITTLE, &own, 1, 4, 6));
}

static void test_keyhash_overlap_rejected_crosskind_allowed(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key rec = hkey(7, 0xABCu);
    cdb_wsring_key same = hkey(7, 0xABCu), other = hkey(7, 0xDEFu), crosskind = dkey(7, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 5, &rec, 1));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, CDB_ORDER_LITTLE, &same, 1, 4, 5));
    TEST_ASSERT_EQUAL_INT(1, allow_of(region, CDB_ORDER_LITTLE, &other, 1, 4, 5));
    /* a data key and a key-hash never match, even with the same store. */
    TEST_ASSERT_EQUAL_INT(1, allow_of(region, CDB_ORDER_LITTLE, &crosskind, 1, 4, 5));
}

static void test_range_is_half_open_low_closed_high(void)
{
    /* (base, current]: an entry at seq == base is in the committer's own base
     * view (excluded); one at seq == current is a straddle (included). */
    uint8_t region[REGION_LEN];
    cdb_wsring_key a = dkey(1, 10), b = dkey(1, 11), own_a = dkey(1, 10), own_b = dkey(1, 11);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 5, &a, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 6, &b, 1));
    /* seq 5 excluded at base=5: own matching it is allowed. */
    TEST_ASSERT_EQUAL_INT(1, allow_of(region, CDB_ORDER_LITTLE, &own_a, 1, 5, 6));
    /* seq 6 == current included: own matching it is rejected. */
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, CDB_ORDER_LITTLE, &own_b, 1, 5, 6));
}

/* --- fail-closed: coverage --- */

static void test_no_straddle_is_rejected(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key a = dkey(1, 10), own = dkey(2, 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 6, &a, 1));
    /* current <= base: nothing to prove, not an ALLOW path. */
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 6, 6));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, CDB_ORDER_LITTLE, &own, 1, 6, 6));
}

static void test_frontier_short_of_current_is_rejected(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key a = dkey(1, 10), own = dkey(2, 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 6, &a, 1));
    /* top_seq == 6 but current == 7: the ring has not recorded through 7. */
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 4, 7));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, CDB_ORDER_LITTLE, &own, 1, 4, 7));
}

static void test_eviction_raises_floor_and_rejects_below(void)
{
    /* Fill the cap, then one more append evicts the oldest and raises floor_seq;
     * a base below floor can no longer be proven disjoint -> rejected even
     * though the own key is genuinely disjoint (AC4). */
    uint8_t region[REGION_LEN];
    cdb_wsring_key keys[REGION_CAP], extra = dkey(1, 5), own = dkey(9, 9);
    uint32_t i;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    for (i = 0; i < REGION_CAP; i++) {
        keys[i] = dkey(1, i + 1u);
        TEST_ASSERT_EQUAL_INT(
            CDB_OK, cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 10u + i, &keys[i], 1));
    }
    /* seqs 10..13 retained, floor still 0. */
    TEST_ASSERT_EQUAL_INT(1, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 9, 13));
    /* append seq 14 evicts seq 10 -> floor rises to 10. */
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 14, &extra, 1));
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 9, 14));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, CDB_ORDER_LITTLE, &own, 1, 9, 14));
    /* base exactly at the floor is covered again (floor <= base). */
    TEST_ASSERT_EQUAL_INT(1, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 10, 14));
    TEST_ASSERT_EQUAL_INT(1, allow_of(region, CDB_ORDER_LITTLE, &own, 1, 10, 14));
}

static void test_batch_overflow_raises_floor_to_self(void)
{
    /* A single reconcile batch larger than the cap cannot be fully retained:
     * floor_seq rises to the batch's own seq, so no older base is covered
     * (ring-overflow conservative reject, AC4). */
    uint8_t region[REGION_LEN];
    cdb_wsring_key big[REGION_CAP + 2u], own = dkey(5, 5);
    uint32_t i;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    for (i = 0; i < REGION_CAP + 2u; i++)
        big[i] = dkey(2, i + 1u);
    TEST_ASSERT_EQUAL_INT(
        CDB_OK, cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 20, big, REGION_CAP + 2u));
    /* nothing below 20 is provable (part of 20's own write set was evicted). */
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 19, 20));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, CDB_ORDER_LITTLE, &own, 1, 19, 20));
}

/* --- fail-closed: corruption / absence / old format --- */

static void test_absent_ring_is_rejected(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key own = dkey(1, 1);
    memset(region, 0, sizeof region); /* never formatted: no magic */
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 1, 2));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, CDB_ORDER_LITTLE, &own, 1, 1, 2));
}

static void test_torn_header_is_rejected(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key a = dkey(1, 10), own = dkey(2, 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 6, &a, 1));
    region[24] ^= 0xFFu; /* flip a floor_seq byte: header CRC now fails */
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 4, 6));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, CDB_ORDER_LITTLE, &own, 1, 4, 6));
}

static void test_torn_entry_is_rejected_not_skipped(void)
{
    /* A torn entry must reject the whole decision, never be silently filtered
     * out of the range (which could hide a real overlap). */
    uint8_t region[REGION_LEN];
    cdb_wsring_key a = dkey(1, 10), b = dkey(1, 11), own = dkey(2, 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 5, &a, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 6, &b, 1));
    /* corrupt the first entry's store field; header still validates. */
    region[CDB_WSRING_HDR_SIZE + 8u] ^= 0xFFu;
    /* covers() looks only at the header, so it still reports covered... */
    TEST_ASSERT_EQUAL_INT(1, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 4, 6));
    /* ...but the intersection scan validates every entry CRC and fails closed. */
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, CDB_ORDER_LITTLE, &own, 1, 4, 6));
}

static void test_old_or_unknown_format_is_rejected(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key a = dkey(1, 10), own = dkey(2, 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_wsring_append(region, REGION_LEN, CDB_ORDER_LITTLE, 6, &a, 1));
    region[4] = (uint8_t)(CDB_WSRING_FORMAT_VERSION + 1u); /* a version this build predates */
    TEST_ASSERT_EQUAL_INT(0, cdb_wsring_covers(region, REGION_LEN, CDB_ORDER_LITTLE, 4, 6));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, CDB_ORDER_LITTLE, &own, 1, 4, 6));
}

/* --- byte-order independence --- */

static void test_big_endian_round_trip(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key a = dkey(1, 10), b = dkey(1, 11), own_ok = dkey(2, 99), own_hit = dkey(1, 11);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_BIG, NULL));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_append(region, REGION_LEN, CDB_ORDER_BIG, 5, &a, 1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_append(region, REGION_LEN, CDB_ORDER_BIG, 6, &b, 1));
    TEST_ASSERT_EQUAL_INT(1, allow_of(region, CDB_ORDER_BIG, &own_ok, 1, 4, 6));
    TEST_ASSERT_EQUAL_INT(0, allow_of(region, CDB_ORDER_BIG, &own_hit, 1, 4, 6));
}

/* --- caller-contract guards --- */

static void test_null_allow_is_rejected_contract(void)
{
    uint8_t region[REGION_LEN];
    cdb_wsring_key own = dkey(1, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_wsring_format(region, REGION_LEN, CDB_ORDER_LITTLE, NULL));
    TEST_ASSERT_EQUAL_INT(
        CDB_E_INVALID_ARG,
        cdb_wsring_straddle_disjoint(region, REGION_LEN, CDB_ORDER_LITTLE, &own, 1, 1, 2, NULL));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_format_reports_cap_and_rejects_tiny_region);
    RUN_TEST(test_append_frontier_is_monotonic);
    RUN_TEST(test_disjoint_straddle_is_allowed);
    RUN_TEST(test_reconciled_overlap_still_rejected);
    RUN_TEST(test_keyhash_overlap_rejected_crosskind_allowed);
    RUN_TEST(test_range_is_half_open_low_closed_high);
    RUN_TEST(test_no_straddle_is_rejected);
    RUN_TEST(test_frontier_short_of_current_is_rejected);
    RUN_TEST(test_eviction_raises_floor_and_rejects_below);
    RUN_TEST(test_batch_overflow_raises_floor_to_self);
    RUN_TEST(test_absent_ring_is_rejected);
    RUN_TEST(test_torn_header_is_rejected);
    RUN_TEST(test_torn_entry_is_rejected_not_skipped);
    RUN_TEST(test_old_or_unknown_format_is_rejected);
    RUN_TEST(test_big_endian_round_trip);
    RUN_TEST(test_null_allow_is_rejected_contract);
    return UNITY_END();
}
