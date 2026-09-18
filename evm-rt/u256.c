/* A port of `guests-compiled/evm-core/src/u256.rs`, function by function (see u256.h). Every
 * operation computes into a local and stores last, so the result may alias an operand. */
#include "u256.h"

static const u256 ZERO = {{0, 0, 0, 0, 0, 0, 0, 0}};
static const u256 ONE = {{1, 0, 0, 0, 0, 0, 0, 0}};

/* ---- construction and inspection ---- */

void u256_from_u32(u256 *r, uint32_t v) {
    u256 t = ZERO;
    t.l[0] = v;
    *r = t;
}

void u256_from_u64(u256 *r, uint64_t v) {
    u256 t = ZERO;
    t.l[0] = (uint32_t)v;
    t.l[1] = (uint32_t)(v >> 32);
    *r = t;
}

void u256_from_be_bytes(u256 *r, const uint8_t *b) {
    u256 t;
    for (int i = 0; i < 8; i++) {
        const uint8_t *p = b + 28 - 4 * i;
        t.l[i] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
    }
    *r = t;
}

void u256_to_be_bytes(uint8_t *b, const u256 *a) {
    u256 t = *a;
    for (int i = 0; i < 8; i++) {
        uint8_t *p = b + 28 - 4 * i;
        p[0] = (uint8_t)(t.l[i] >> 24);
        p[1] = (uint8_t)(t.l[i] >> 16);
        p[2] = (uint8_t)(t.l[i] >> 8);
        p[3] = (uint8_t)t.l[i];
    }
}

void u256_from_be_slice(u256 *r, const uint8_t *b, uint32_t n) {
    uint32_t take = n > 32 ? 32 : n; /* a longer slice keeps its low 32 bytes */
    uint8_t full[32];
    for (int i = 0; i < 32; i++) full[i] = 0;
    for (uint32_t i = 0; i < take; i++) full[32 - take + i] = b[n - take + i];
    u256_from_be_bytes(r, full);
}

int u256_is_zero(const u256 *a) {
    uint32_t acc = 0;
    for (int i = 0; i < 8; i++) acc |= a->l[i];
    return acc == 0;
}

int u256_is_neg(const u256 *a) { return (int)(a->l[7] >> 31); }

uint32_t u256_low_u32(const u256 *a) { return a->l[0]; }

uint64_t u256_low_u64(const u256 *a) { return (uint64_t)a->l[0] | (uint64_t)a->l[1] << 32; }

int u256_hi_zero(const u256 *a) {
    uint32_t acc = 0;
    for (int i = 1; i < 8; i++) acc |= a->l[i];
    return acc == 0;
}

uint32_t u256_sat_u32(const u256 *a) { return u256_hi_zero(a) ? a->l[0] : 0xffffffffu; }

static uint32_t clz32(uint32_t x) {
    /* x != 0; a loop rather than __builtin_clz, which may lower to a libcall on RV32IM */
    uint32_t n = 0;
    if (!(x & 0xffff0000u)) { n += 16; x <<= 16; }
    if (!(x & 0xff000000u)) { n += 8; x <<= 8; }
    if (!(x & 0xf0000000u)) { n += 4; x <<= 4; }
    if (!(x & 0xc0000000u)) { n += 2; x <<= 2; }
    if (!(x & 0x80000000u)) { n += 1; }
    return n;
}

uint32_t u256_bit_len(const u256 *a) {
    for (int i = 7; i >= 0; i--)
        if (a->l[i] != 0) return 32 * (uint32_t)i + 32 - clz32(a->l[i]);
    return 0;
}

uint32_t u256_byte_len(const u256 *a) { return (u256_bit_len(a) + 7) / 8; }

/* ---- add, sub, mul ---- */

/* The sum and its carry out of bit 255 (U256::add_carry). */
static uint32_t add_carry(u256 *r, const u256 *a, const u256 *b) {
    u256 t;
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t s = (uint64_t)a->l[i] + b->l[i] + c;
        t.l[i] = (uint32_t)s;
        c = s >> 32;
    }
    *r = t;
    return (uint32_t)c;
}

void u256_add(u256 *r, const u256 *a, const u256 *b) { (void)add_carry(r, a, b); }

void u256_sub(u256 *r, const u256 *a, const u256 *b) {
    u256 t;
    uint32_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t d = (uint64_t)a->l[i] - b->l[i] - borrow;
        t.l[i] = (uint32_t)d;
        borrow = (uint32_t)(d >> 63); /* the i64 `d < 0` of the Rust */
    }
    *r = t;
}

/* 8x8 -> 16 limbs, the full 512-bit product (mul_wide). */
static void mul_wide(uint32_t w[16], const uint32_t a[8], const uint32_t b[8]) {
    for (int i = 0; i < 16; i++) w[i] = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t c = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t t = (uint64_t)a[i] * b[j] + w[i + j] + c;
            w[i + j] = (uint32_t)t;
            c = t >> 32;
        }
        w[i + 8] = (uint32_t)c;
    }
}

void u256_mul(u256 *r, const u256 *a, const u256 *b) {
    /* Only the low 8 limbs survive, so only the products that reach them are formed. */
    u256 t = ZERO;
    for (int i = 0; i < 8; i++) {
        uint64_t c = 0;
        for (int j = 0; i + j < 8; j++) {
            uint64_t p = (uint64_t)a->l[i] * b->l[j] + t.l[i + j] + c;
            t.l[i + j] = (uint32_t)p;
            c = p >> 32;
        }
    }
    *r = t;
}

/* ---- division: Knuth's algorithm D (knuth_divrem) ---- */

static int significant_limbs(const uint32_t *v, int n) {
    while (n > 0 && v[n - 1] == 0) n--;
    return n;
}

/* `n` (nlen <= 16 limbs) by the non-zero `d`: the quotient's low 8 limbs into q, the remainder
 * into rem. */
static void knuth_divrem(const uint32_t *n, int nlen, const uint32_t d[8], uint32_t q[8],
                         uint32_t rem[8]) {
    for (int i = 0; i < 8; i++) q[i] = rem[i] = 0;
    int dn = significant_limbs(d, 8);
    int m = significant_limbs(n, nlen);
    if (m < dn) {
        for (int i = 0; i < m; i++) rem[i] = n[i];
        return;
    }
    if (dn == 1) {
        uint64_t d0 = d[0], r = 0;
        for (int i = m - 1; i >= 0; i--) {
            uint64_t cur = r << 32 | n[i];
            if (i < 8) q[i] = (uint32_t)(cur / d0);
            r = cur % d0;
        }
        rem[0] = (uint32_t)r;
        return;
    }

    uint32_t s = clz32(d[dn - 1]);
    uint32_t dv[8] = {0};
    for (int i = dn - 1; i >= 0; i--) {
        uint32_t hi = d[i] << s;
        uint32_t lo = (s > 0 && i > 0) ? d[i - 1] >> (32 - s) : 0;
        dv[i] = hi | lo;
    }
    uint32_t un[17] = {0};
    for (int i = m - 1; i >= 0; i--) {
        uint32_t hi = n[i] << s;
        uint32_t lo = (s > 0 && i > 0) ? n[i - 1] >> (32 - s) : 0;
        un[i] = hi | lo;
    }
    un[m] = s > 0 ? n[m - 1] >> (32 - s) : 0;

    for (int j = m - dn; j >= 0; j--) {
        uint64_t num = (uint64_t)un[j + dn] << 32 | un[j + dn - 1];
        uint64_t qhat = num / dv[dn - 1];
        uint64_t rhat = num % dv[dn - 1];
        while ((qhat >> 32) != 0 || qhat * dv[dn - 2] > (rhat << 32 | un[j + dn - 2])) {
            qhat -= 1;
            rhat += dv[dn - 1];
            if ((rhat >> 32) != 0) break;
        }
        uint64_t carry = 0;
        int64_t borrow = 0;
        for (int i = 0; i < dn; i++) {
            uint64_t p = qhat * dv[i] + carry;
            carry = p >> 32;
            int64_t t = (int64_t)un[i + j] - borrow - (int64_t)(uint32_t)p;
            un[i + j] = (uint32_t)t;
            borrow = t < 0;
        }
        int64_t t = (int64_t)un[j + dn] - (int64_t)carry - borrow;
        un[j + dn] = (uint32_t)t;
        if (t < 0) {
            qhat -= 1;
            uint64_t c = 0;
            for (int i = 0; i < dn; i++) {
                uint64_t sum = (uint64_t)un[i + j] + dv[i] + c;
                un[i + j] = (uint32_t)sum;
                c = sum >> 32;
            }
            un[j + dn] = (uint32_t)((uint64_t)un[j + dn] + c);
        }
        if (j < 8) q[j] = (uint32_t)qhat;
    }

    for (int i = 0; i < dn; i++) {
        uint32_t lo = un[i] >> s;
        uint32_t hi = s > 0 ? un[i + 1] << (32 - s) : 0;
        rem[i] = lo | hi;
    }
}

void u256_div(u256 *r, const u256 *a, const u256 *b) {
    if (u256_is_zero(b)) { *r = ZERO; return; }
    u256 q, rem;
    knuth_divrem(a->l, 8, b->l, q.l, rem.l);
    *r = q;
}

void u256_mod(u256 *r, const u256 *a, const u256 *b) {
    if (u256_is_zero(b)) { *r = ZERO; return; }
    u256 q, rem;
    knuth_divrem(a->l, 8, b->l, q.l, rem.l);
    *r = rem;
}

static void neg(u256 *r, const u256 *a) { u256_sub(r, &ZERO, a); }

/* The magnitude; MIN's negation wraps to MIN, which is what makes MIN / -1 = MIN. */
static void abs256(u256 *r, const u256 *a) {
    if (u256_is_neg(a)) neg(r, a); else *r = *a;
}

void u256_sdiv(u256 *r, const u256 *a, const u256 *b) {
    if (u256_is_zero(b)) { *r = ZERO; return; }
    int flip = u256_is_neg(a) != u256_is_neg(b);
    u256 x, y, q;
    abs256(&x, a);
    abs256(&y, b);
    u256_div(&q, &x, &y);
    if (flip) neg(&q, &q);
    *r = q;
}

void u256_smod(u256 *r, const u256 *a, const u256 *b) {
    if (u256_is_zero(b)) { *r = ZERO; return; }
    int flip = u256_is_neg(a);
    u256 x, y, m;
    abs256(&x, a);
    abs256(&y, b);
    u256_mod(&m, &x, &y);
    if (flip) neg(&m, &m);
    *r = m;
}

void u256_addmod(u256 *r, const u256 *a, const u256 *b, const u256 *m) {
    if (u256_is_zero(m)) { *r = ZERO; return; }
    u256 s, q, rem;
    uint32_t wide[16] = {0};
    uint32_t c = add_carry(&s, a, b);
    for (int i = 0; i < 8; i++) wide[i] = s.l[i];
    wide[8] = c;
    knuth_divrem(wide, 16, m->l, q.l, rem.l);
    *r = rem;
}

void u256_mulmod(u256 *r, const u256 *a, const u256 *b, const u256 *m) {
    if (u256_is_zero(m)) { *r = ZERO; return; }
    u256 q, rem;
    uint32_t wide[16];
    mul_wide(wide, a->l, b->l);
    knuth_divrem(wide, 16, m->l, q.l, rem.l);
    *r = rem;
}

void u256_exp(u256 *r, const u256 *base, const u256 *e) {
    u256 acc = ONE, b = *base, ex = *e;
    uint32_t bits = u256_bit_len(&ex);
    for (uint32_t i = 0; i < bits; i++) {
        if ((ex.l[i / 32] >> (i % 32)) & 1) u256_mul(&acc, &acc, &b);
        u256_mul(&b, &b, &b);
    }
    *r = acc;
}

/* ---- comparison and bitwise ---- */

int u256_lt_p(const u256 *a, const u256 *b) {
    for (int i = 7; i >= 0; i--)
        if (a->l[i] != b->l[i]) return a->l[i] < b->l[i];
    return 0;
}

int u256_slt_p(const u256 *a, const u256 *b) {
    if (u256_is_neg(a) != u256_is_neg(b)) return u256_is_neg(a);
    return u256_lt_p(a, b);
}

int u256_eq_p(const u256 *a, const u256 *b) {
    uint32_t acc = 0;
    for (int i = 0; i < 8; i++) acc |= a->l[i] ^ b->l[i];
    return acc == 0;
}

void u256_lt(u256 *r, const u256 *a, const u256 *b) { u256_from_u32(r, (uint32_t)u256_lt_p(a, b)); }
void u256_gt(u256 *r, const u256 *a, const u256 *b) { u256_from_u32(r, (uint32_t)u256_lt_p(b, a)); }
void u256_slt(u256 *r, const u256 *a, const u256 *b) { u256_from_u32(r, (uint32_t)u256_slt_p(a, b)); }
void u256_sgt(u256 *r, const u256 *a, const u256 *b) { u256_from_u32(r, (uint32_t)u256_slt_p(b, a)); }
void u256_eq(u256 *r, const u256 *a, const u256 *b) { u256_from_u32(r, (uint32_t)u256_eq_p(a, b)); }
void u256_iszero(u256 *r, const u256 *a) { u256_from_u32(r, (uint32_t)u256_is_zero(a)); }

void u256_and(u256 *r, const u256 *a, const u256 *b) {
    for (int i = 0; i < 8; i++) r->l[i] = a->l[i] & b->l[i]; /* limb-wise: aliasing is safe */
}
void u256_or(u256 *r, const u256 *a, const u256 *b) {
    for (int i = 0; i < 8; i++) r->l[i] = a->l[i] | b->l[i];
}
void u256_xor(u256 *r, const u256 *a, const u256 *b) {
    for (int i = 0; i < 8; i++) r->l[i] = a->l[i] ^ b->l[i];
}
void u256_not(u256 *r, const u256 *a) {
    for (int i = 0; i < 8; i++) r->l[i] = ~a->l[i];
}

/* ---- shifts, BYTE, SIGNEXTEND ---- */

/* The shift amount when it is below 256, else 256 (every "n >= 256" branch). */
static uint32_t amount(const u256 *n) {
    return (u256_hi_zero(n) && n->l[0] < 256) ? n->l[0] : 256;
}

static void shl_by(u256 *r, const u256 *x, uint32_t n) {
    if (n >= 256) { *r = ZERO; return; }
    uint32_t words = n / 32, bits = n % 32;
    u256 t = ZERO;
    for (int i = 7; i >= (int)words; i--) {
        uint32_t lo = x->l[i - words] << bits;
        uint32_t hi = (bits > 0 && i - (int)words > 0) ? x->l[i - words - 1] >> (32 - bits) : 0;
        t.l[i] = lo | hi;
    }
    *r = t;
}

static void shr_by(u256 *r, const u256 *x, uint32_t n) {
    if (n >= 256) { *r = ZERO; return; }
    uint32_t words = n / 32, bits = n % 32;
    u256 t = ZERO;
    for (uint32_t i = 0; i < 8 - words; i++) {
        uint32_t lo = x->l[i + words] >> bits;
        uint32_t hi = (bits > 0 && i + words + 1 < 8) ? x->l[i + words + 1] << (32 - bits) : 0;
        t.l[i] = lo | hi;
    }
    *r = t;
}

void u256_shl(u256 *r, const u256 *x, const u256 *n) { shl_by(r, x, amount(n)); }

void u256_shr(u256 *r, const u256 *x, const u256 *n) { shr_by(r, x, amount(n)); }

void u256_sar(u256 *r, const u256 *x, const u256 *n) {
    int negv = u256_is_neg(x);
    uint32_t k = amount(n);
    if (k >= 256) {
        u256 fill;
        for (int i = 0; i < 8; i++) fill.l[i] = negv ? 0xffffffffu : 0;
        *r = fill;
        return;
    }
    u256 t;
    shr_by(&t, x, k);
    if (negv) {
        /* the top k bits: MAX << (256 - k), zero when k = 0 */
        u256 max, fill;
        for (int i = 0; i < 8; i++) max.l[i] = 0xffffffffu;
        shl_by(&fill, &max, 256 - k);
        u256_or(&t, &t, &fill);
    }
    *r = t;
}

void u256_byte(u256 *r, const u256 *x, const u256 *i) {
    if (!u256_hi_zero(i) || i->l[0] >= 32) { *r = ZERO; return; }
    uint32_t k = 31 - i->l[0]; /* counted from the least significant */
    u256_from_u32(r, (x->l[k / 4] >> (8 * (k % 4))) & 0xff);
}

void u256_signextend(u256 *r, const u256 *x, const u256 *b) {
    if (!u256_hi_zero(b) || b->l[0] >= 31) { *r = *x; return; }
    uint32_t bit = b->l[0] * 8 + 7; /* the sign bit of byte b */
    u256 mask;                      /* bits 0..=bit: (1 << (bit + 1)) - 1 */
    shl_by(&mask, &ONE, bit + 1);
    u256_sub(&mask, &mask, &ONE);
    u256 t = *x;
    if ((t.l[bit / 32] >> (bit % 32)) & 1) {
        for (int i = 0; i < 8; i++) t.l[i] |= ~mask.l[i];
    } else {
        for (int i = 0; i < 8; i++) t.l[i] &= mask.l[i];
    }
    *r = t;
}
