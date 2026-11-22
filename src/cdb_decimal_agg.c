/* Exact big-integer DECIMAL aggregation for time-series downsampling.
 *
 * Magnitudes are fixed arrays of CDB_DEC_LIMBS little-endian 32-bit limbs
 * (mag[0] least significant). Values are sign + magnitude. All arithmetic is
 * unsigned on the limbs (no signed-overflow undefined behaviour); any carry or
 * borrow out of the top limb, or an input too large to parse, is reported as
 * CDB_E_OVERFLOW. See cdb_decimal_agg.h and docs/adr/0003 for the design. */
#include "cdb_decimal_agg.h"

#include <string.h>

#define LIMBS ((size_t)CDB_DEC_LIMBS)
#define MAG_BYTES (LIMBS * 4u) /* big-endian byte width of a full magnitude */

/* ---- magnitude primitives (all over exactly LIMBS limbs) ---------------- */

static int mag_is_zero(const uint32_t *a)
{
    size_t i;
    for (i = 0; i < LIMBS; i++) {
        if (a[i] != 0)
            return 0;
    }
    return 1;
}

static int mag_cmp(const uint32_t *a, const uint32_t *b)
{
    size_t i;
    for (i = LIMBS; i-- > 0;) {
        if (a[i] != b[i])
            return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

/* a += b; CDB_E_OVERFLOW on carry out of the top limb. */
static cdb_status mag_add(uint32_t *a, const uint32_t *b)
{
    uint64_t carry = 0;
    size_t i;
    for (i = 0; i < LIMBS; i++) {
        uint64_t s = (uint64_t)a[i] + (uint64_t)b[i] + carry;
        a[i] = (uint32_t)(s & 0xFFFFFFFFu);
        carry = s >> 32;
    }
    return carry != 0 ? CDB_E_OVERFLOW : CDB_OK;
}

/* a -= b, assuming a >= b (checked by the caller). */
static void mag_sub(uint32_t *a, const uint32_t *b)
{
    uint64_t borrow = 0;
    size_t i;
    for (i = 0; i < LIMBS; i++) {
        uint64_t cur = (uint64_t)a[i];
        uint64_t sub = (uint64_t)b[i] + borrow;
        if (cur >= sub) {
            a[i] = (uint32_t)(cur - sub);
            borrow = 0;
        } else {
            a[i] = (uint32_t)(cur + 0x100000000ULL - sub);
            borrow = 1;
        }
    }
}

/* a += add (a small constant); CDB_E_OVERFLOW on carry out of the top limb. */
static cdb_status mag_add_u32(uint32_t *a, uint32_t add)
{
    uint64_t carry = (uint64_t)add;
    size_t i;
    for (i = 0; i < LIMBS && carry != 0; i++) {
        uint64_t s = (uint64_t)a[i] + carry;
        a[i] = (uint32_t)(s & 0xFFFFFFFFu);
        carry = s >> 32;
    }
    return carry != 0 ? CDB_E_OVERFLOW : CDB_OK;
}

/* a *= m (m < 2^32); CDB_E_OVERFLOW on carry out of the top limb. */
static cdb_status mag_mul_small(uint32_t *a, uint32_t m)
{
    uint64_t carry = 0;
    size_t i;
    for (i = 0; i < LIMBS; i++) {
        uint64_t prod = (uint64_t)a[i] * (uint64_t)m + carry;
        a[i] = (uint32_t)(prod & 0xFFFFFFFFu);
        carry = prod >> 32;
    }
    return carry != 0 ? CDB_E_OVERFLOW : CDB_OK;
}

/* a *= 10^k. A zero magnitude is unchanged for any k (so a huge k cannot spin;
 * a non-zero magnitude overflows the fixed capacity within a few hundred
 * multiplies and fails closed). */
static cdb_status mag_mul_pow10(uint32_t *a, uint64_t k)
{
    uint64_t i;
    if (mag_is_zero(a))
        return CDB_OK;
    for (i = 0; i < k; i++) {
        cdb_status s = mag_mul_small(a, 10u);
        if (s != CDB_OK)
            return s;
    }
    return CDB_OK;
}

/* Quotient = *a / d, in place; returns the remainder (d must be non-zero).
 * Bit-by-bit long division: the running remainder stays below d (< 2^64), so
 * the shift-in needs one extra bit, tracked in `carry`. */
static uint64_t mag_divmod_u64(uint32_t *a, uint64_t d)
{
    uint32_t q[CDB_DEC_LIMBS];
    uint64_t rem = 0;
    size_t bit;
    memset(q, 0, sizeof q);
    for (bit = MAG_BYTES * 8u; bit-- > 0;) {
        size_t limb = bit >> 5;
        unsigned off = (unsigned)(bit & 31u);
        uint32_t b = (a[limb] >> off) & 1u;
        uint64_t carry = rem >> 63;
        rem = (rem << 1) | (uint64_t)b;
        if (carry != 0 || rem >= d) {
            rem -= d; /* correct mod 2^64 even when carry wrapped the shift */
            q[limb] |= (uint32_t)(1u << off);
        }
    }
    memcpy(a, q, sizeof q);
    return rem;
}

/* ---- parse / emit big-endian two's complement ------------------------- */

/* Parses shortest big-endian two's complement into sign + magnitude.
 * CDB_E_OVERFLOW if the magnitude needs more than LIMBS limbs. */
static cdb_status be_to_sign_mag(const uint8_t *be, size_t len, uint32_t *mag, int *neg)
{
    uint8_t tmp[CDB_DEC_MAX_BYTES];
    int negative;
    size_t i;

    if (len == 0 || len > CDB_DEC_MAX_BYTES)
        return CDB_E_OVERFLOW;

    negative = (be[0] & 0x80u) != 0;
    memcpy(tmp, be, len);
    if (negative) {
        /* Two's-complement negate to recover the magnitude bytes. */
        unsigned carry = 1;
        for (i = len; i-- > 0;) {
            unsigned v = (unsigned)(uint8_t)~tmp[i] + carry;
            tmp[i] = (uint8_t)(v & 0xFFu);
            carry = v >> 8;
        }
    }

    memset(mag, 0, MAG_BYTES);
    for (i = 0; i < len; i++) {
        uint8_t bval = tmp[len - 1 - i]; /* i == 0 is least significant */
        size_t limb = i >> 2;
        unsigned shift = (unsigned)((i & 3u) * 8u);
        if (bval != 0 && limb >= LIMBS)
            return CDB_E_OVERFLOW;
        if (limb < LIMBS)
            mag[limb] |= (uint32_t)((uint32_t)bval << shift);
    }

    *neg = (negative && !mag_is_zero(mag)) ? 1 : 0;
    return CDB_OK;
}

/* Minimal big-endian magnitude bytes into out (>= MAG_BYTES); returns the
 * length (>= 1; a zero magnitude yields a single 0x00). */
static size_t mag_be_bytes(const uint32_t *mag, uint8_t *out)
{
    size_t i, start, len;
    for (i = 0; i < MAG_BYTES; i++) {
        size_t src = MAG_BYTES - 1 - i;
        size_t limb = src >> 2;
        unsigned off = (unsigned)((src & 3u) * 8u);
        out[i] = (uint8_t)((mag[limb] >> off) & 0xFFu);
    }
    start = 0;
    while (start + 1 < MAG_BYTES && out[start] == 0)
        start++;
    len = MAG_BYTES - start;
    memmove(out, out + start, len);
    return len;
}

/* Emits a sign + magnitude as a canonical shortest big-endian two's-complement
 * unscaled integer. */
static cdb_status emit_canonical(const uint32_t *mag, int neg, uint8_t *out, size_t cap,
                                 size_t *out_len)
{
    uint8_t magb[MAG_BYTES];
    uint8_t work[MAG_BYTES + 1u];
    size_t mlen, wlen, s, len;

    mlen = mag_be_bytes(mag, magb);
    if (mlen == 1 && magb[0] == 0) {
        if (cap < 1)
            return CDB_E_BUFFER_TOO_SMALL;
        out[0] = 0;
        *out_len = 1;
        return CDB_OK;
    }

    /* Build a sign-extended width of mlen+1, then strip to canonical. */
    work[0] = 0x00;
    memcpy(work + 1, magb, mlen);
    wlen = mlen + 1;
    if (neg) {
        unsigned carry = 1;
        for (s = 0; s < wlen; s++)
            work[s] = (uint8_t)(~work[s]);
        for (s = wlen; s-- > 0;) {
            unsigned v = (unsigned)work[s] + carry;
            work[s] = (uint8_t)(v & 0xFFu);
            carry = v >> 8;
            if (carry == 0)
                break;
        }
    }

    s = 0;
    while (wlen - s >= 2) {
        uint8_t b0 = work[s];
        uint8_t b1 = work[s + 1];
        if (b0 == 0x00 && !(b1 & 0x80u))
            s++;
        else if (b0 == 0xFF && (b1 & 0x80u))
            s++;
        else
            break;
    }
    len = wlen - s;
    if (len > cap)
        return CDB_E_BUFFER_TOO_SMALL;
    memcpy(out, work + s, len);
    *out_len = len;
    return CDB_OK;
}

/* ---- signed accumulation and decimal comparison ----------------------- */

/* acc (sign-magnitude) += add (sign-magnitude). */
static cdb_status signed_add(uint32_t *acc, int *acc_neg, const uint32_t *add, int add_neg)
{
    int c;
    if (mag_is_zero(add))
        return CDB_OK;
    if (mag_is_zero(acc)) {
        memcpy(acc, add, MAG_BYTES);
        *acc_neg = add_neg;
        return CDB_OK;
    }
    if (*acc_neg == add_neg)
        return mag_add(acc, add);

    c = mag_cmp(acc, add);
    if (c == 0) {
        memset(acc, 0, MAG_BYTES);
        *acc_neg = 0;
        return CDB_OK;
    }
    if (c > 0) {
        mag_sub(acc, add); /* |acc| > |add|; sign unchanged */
    } else {
        uint32_t tmp[CDB_DEC_LIMBS];
        memcpy(tmp, add, MAG_BYTES);
        mag_sub(tmp, acc); /* result = |add| - |acc| */
        memcpy(acc, tmp, MAG_BYTES);
        *acc_neg = add_neg;
    }
    return CDB_OK;
}

/* Compares two DECIMAL values (sign and scale aware). *result is -1, 0 or 1.
 * Alignment multiplies the smaller-scale side up to the common scale; if that
 * overflows the capacity, that side is numerically larger in magnitude (the
 * other side, already at the common scale, fits), which decides the order. */
static cdb_status dec_value_cmp(const uint8_t *a, size_t al, uint64_t as, const uint8_t *b,
                                size_t bl, uint64_t bs, int *result)
{
    uint32_t am[CDB_DEC_LIMBS];
    uint32_t bm[CDB_DEC_LIMBS];
    int an, bn, a_over = 0, b_over = 0, az, bz, ane, bne, magc;
    uint64_t common;
    cdb_status s;

    s = be_to_sign_mag(a, al, am, &an);
    if (s != CDB_OK)
        return s;
    s = be_to_sign_mag(b, bl, bm, &bn);
    if (s != CDB_OK)
        return s;

    common = as > bs ? as : bs;
    if (as < common && mag_mul_pow10(am, common - as) != CDB_OK)
        a_over = 1;
    if (bs < common && mag_mul_pow10(bm, common - bs) != CDB_OK)
        b_over = 1;

    az = (!a_over && mag_is_zero(am));
    bz = (!b_over && mag_is_zero(bm));
    ane = (an && !az);
    bne = (bn && !bz);

    if (a_over)
        magc = 1;
    else if (b_over)
        magc = -1;
    else
        magc = mag_cmp(am, bm);

    if (ane != bne)
        *result = ane ? -1 : 1;
    else
        *result = ane ? -magc : magc;
    return CDB_OK;
}

/* ---- public API -------------------------------------------------------- */

void cdb_decimal_agg_reset(cdb_decimal_agg *st)
{
    if (st != NULL)
        memset(st, 0, sizeof *st);
}

cdb_status cdb_decimal_agg_add(cdb_decimal_agg *st, uint64_t scale, const uint8_t *unscaled_be,
                               size_t len)
{
    uint32_t in_mag[CDB_DEC_LIMBS];
    uint32_t add_mag[CDB_DEC_LIMBS];
    int in_neg, cmp;
    cdb_status s;

    if (st == NULL || unscaled_be == NULL || len == 0)
        return CDB_E_INVALID_ARG;
    if (len > CDB_DEC_MAX_BYTES)
        return CDB_E_OVERFLOW;

    s = be_to_sign_mag(unscaled_be, len, in_mag, &in_neg);
    if (s != CDB_OK)
        return s;

    if (!st->have) {
        memcpy(st->sum_mag, in_mag, MAG_BYTES);
        st->sum_neg = in_neg;
        st->sum_scale = scale;
        memcpy(st->min_be, unscaled_be, len);
        st->min_len = len;
        st->min_scale = scale;
        memcpy(st->max_be, unscaled_be, len);
        st->max_len = len;
        st->max_scale = scale;
        st->count = 1;
        st->have = 1;
        return CDB_OK;
    }

    /* Align scales for the running sum, then add. */
    if (scale > st->sum_scale) {
        s = mag_mul_pow10(st->sum_mag, scale - st->sum_scale);
        if (s != CDB_OK)
            return s;
        st->sum_scale = scale;
        memcpy(add_mag, in_mag, MAG_BYTES);
    } else {
        memcpy(add_mag, in_mag, MAG_BYTES);
        s = mag_mul_pow10(add_mag, st->sum_scale - scale);
        if (s != CDB_OK)
            return s;
    }
    s = signed_add(st->sum_mag, &st->sum_neg, add_mag, in_neg);
    if (s != CDB_OK)
        return s;

    s = dec_value_cmp(unscaled_be, len, scale, st->min_be, st->min_len, st->min_scale, &cmp);
    if (s != CDB_OK)
        return s;
    if (cmp < 0) {
        memcpy(st->min_be, unscaled_be, len);
        st->min_len = len;
        st->min_scale = scale;
    }

    s = dec_value_cmp(unscaled_be, len, scale, st->max_be, st->max_len, st->max_scale, &cmp);
    if (s != CDB_OK)
        return s;
    if (cmp > 0) {
        memcpy(st->max_be, unscaled_be, len);
        st->max_len = len;
        st->max_scale = scale;
    }

    st->count++;
    return CDB_OK;
}

cdb_status cdb_decimal_agg_sum(const cdb_decimal_agg *st, uint64_t *scale, uint8_t *out, size_t cap,
                               size_t *out_len)
{
    if (st == NULL || scale == NULL || out == NULL || out_len == NULL)
        return CDB_E_INVALID_ARG;
    if (!st->have)
        return CDB_E_INVALID_ARG;
    *scale = st->sum_scale;
    return emit_canonical(st->sum_mag, st->sum_neg, out, cap, out_len);
}

cdb_status cdb_decimal_agg_min(const cdb_decimal_agg *st, uint64_t *scale, uint8_t *out, size_t cap,
                               size_t *out_len)
{
    if (st == NULL || scale == NULL || out == NULL || out_len == NULL)
        return CDB_E_INVALID_ARG;
    if (!st->have)
        return CDB_E_INVALID_ARG;
    if (st->min_len > cap)
        return CDB_E_BUFFER_TOO_SMALL;
    memcpy(out, st->min_be, st->min_len);
    *out_len = st->min_len;
    *scale = st->min_scale;
    return CDB_OK;
}

cdb_status cdb_decimal_agg_max(const cdb_decimal_agg *st, uint64_t *scale, uint8_t *out, size_t cap,
                               size_t *out_len)
{
    if (st == NULL || scale == NULL || out == NULL || out_len == NULL)
        return CDB_E_INVALID_ARG;
    if (!st->have)
        return CDB_E_INVALID_ARG;
    if (st->max_len > cap)
        return CDB_E_BUFFER_TOO_SMALL;
    memcpy(out, st->max_be, st->max_len);
    *out_len = st->max_len;
    *scale = st->max_scale;
    return CDB_OK;
}

cdb_status cdb_decimal_agg_avg(const cdb_decimal_agg *st, uint64_t *scale, uint8_t *out, size_t cap,
                               size_t *out_len)
{
    uint32_t q[CDB_DEC_LIMBS];
    uint64_t rem, cnt, half;
    int roundup, neg;

    if (st == NULL || scale == NULL || out == NULL || out_len == NULL)
        return CDB_E_INVALID_ARG;
    if (!st->have || st->count == 0)
        return CDB_E_INVALID_ARG;

    cnt = st->count;
    memcpy(q, st->sum_mag, MAG_BYTES);
    rem = mag_divmod_u64(q, cnt);

    /* Round half-to-even at the bucket's maximum input scale (ADR-0003). */
    half = cnt / 2u;
    roundup = 0;
    if ((cnt & 1u) != 0) {
        if (rem > half)
            roundup = 1;
    } else if (rem > half) {
        roundup = 1;
    } else if (rem == half) {
        if ((q[0] & 1u) != 0) /* tie: round to the even quotient */
            roundup = 1;
    }
    if (roundup) {
        cdb_status s = mag_add_u32(q, 1u);
        if (s != CDB_OK)
            return s;
    }

    neg = (st->sum_neg && !mag_is_zero(q)) ? 1 : 0;
    *scale = st->sum_scale;
    return emit_canonical(q, neg, out, cap, out_len);
}
