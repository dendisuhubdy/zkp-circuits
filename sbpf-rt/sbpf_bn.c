/* See sbpf_bn.h. */
#include "sbpf_bn.h"

void bn_set_u32(bn *r, uint32_t x) {
    r->v[0] = x;
    for (int i = 1; i < 8; i++) r->v[i] = 0;
}

void bn_from_be(bn *r, const uint8_t b[32]) {
    for (int i = 0; i < 8; i++) {
        const uint8_t *p = b + 28 - 4 * i;
        r->v[i] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
    }
}

void bn_from_le(bn *r, const uint8_t b[32]) {
    for (int i = 0; i < 8; i++) {
        const uint8_t *p = b + 4 * i;
        r->v[i] = (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0];
    }
}

void bn_to_be(uint8_t b[32], const bn *a) {
    for (int i = 0; i < 8; i++) {
        uint8_t *p = b + 28 - 4 * i;
        uint32_t w = a->v[i];
        p[0] = (uint8_t)(w >> 24), p[1] = (uint8_t)(w >> 16), p[2] = (uint8_t)(w >> 8), p[3] = (uint8_t)w;
    }
}

int bn_cmp(const bn *a, const bn *b) {
    for (int i = 7; i >= 0; i--) {
        if (a->v[i] != b->v[i]) return a->v[i] < b->v[i] ? -1 : 1;
    }
    return 0;
}

int bn_is_zero(const bn *a) {
    uint32_t x = 0;
    for (int i = 0; i < 8; i++) x |= a->v[i];
    return x == 0;
}

int bn_bit(const bn *a, int i) { return (int)((a->v[i >> 5] >> (i & 31)) & 1); }

uint32_t bn_add_raw(bn *r, const bn *a, const bn *b) {
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) {
        c += (uint64_t)a->v[i] + b->v[i];
        r->v[i] = (uint32_t)c;
        c >>= 32;
    }
    return (uint32_t)c;
}

uint32_t bn_sub_raw(bn *r, const bn *a, const bn *b) {
    uint32_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t d = (uint64_t)a->v[i] - b->v[i] - borrow;
        r->v[i] = (uint32_t)d;
        borrow = (uint32_t)(d >> 63);
    }
    return borrow;
}

void bn_add(bn *r, const bn *a, const bn *b, const bn_mod *M) {
    uint32_t c = bn_add_raw(r, a, b);
    if (c || bn_cmp(r, &M->m) >= 0) bn_sub_raw(r, r, &M->m);
}

void bn_sub(bn *r, const bn *a, const bn *b, const bn_mod *M) {
    if (bn_sub_raw(r, a, b)) bn_add_raw(r, r, &M->m);
}

void bn_neg(bn *r, const bn *a, const bn_mod *M) {
    bn z;
    bn_set_u32(&z, 0);
    bn_sub(r, &z, a, M);
}

void bn_mul(bn *r, const bn *a, const bn *b, const bn_mod *M) {
    uint32_t t[10];
    for (int i = 0; i < 10; i++) t[i] = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t x;
        uint32_t c = 0;
        for (int j = 0; j < 8; j++) {
            x = (uint64_t)a->v[j] * b->v[i] + t[j] + c;
            t[j] = (uint32_t)x;
            c = (uint32_t)(x >> 32);
        }
        x = (uint64_t)t[8] + c;
        t[8] = (uint32_t)x;
        t[9] = (uint32_t)(x >> 32);
        uint32_t m = t[0] * M->n0;
        x = (uint64_t)m * M->m.v[0] + t[0];
        c = (uint32_t)(x >> 32);
        for (int j = 1; j < 8; j++) {
            x = (uint64_t)m * M->m.v[j] + t[j] + c;
            t[j - 1] = (uint32_t)x;
            c = (uint32_t)(x >> 32);
        }
        x = (uint64_t)t[8] + c;
        t[7] = (uint32_t)x;
        t[8] = t[9] + (uint32_t)(x >> 32);
    }
    bn out;
    for (int i = 0; i < 8; i++) out.v[i] = t[i];
    if (t[8] != 0 || bn_cmp(&out, &M->m) >= 0) bn_sub_raw(&out, &out, &M->m);
    *r = out;
}

void bn_mod_init(bn_mod *M, const bn *m) {
    M->m = *m;
    /* Newton's iteration for m^-1 mod 2^32: m m = 1 mod 8 for odd m, so m is right to 3 bits and
     * each step doubles that. */
    uint32_t inv = m->v[0];
    for (int i = 0; i < 4; i++) inv *= 2 - m->v[0] * inv;
    M->n0 = 0u - inv;
    /* R^2 mod m by 512 modular doublings of 1, and R mod m after the first 256. */
    bn x;
    bn_set_u32(&x, 1);
    for (int i = 0; i < 512; i++) {
        if (i == 256) M->one = x;
        bn_add(&x, &x, &x, M);
    }
    M->r2 = x;
}

void bn_to_mont(bn *r, const bn *a, const bn_mod *M) { bn_mul(r, a, &M->r2, M); }

void bn_from_mont(bn *r, const bn *a, const bn_mod *M) {
    bn one;
    bn_set_u32(&one, 1);
    bn_mul(r, a, &one, M);
}

void bn_pow(bn *r, const bn *a, const bn *e, const bn_mod *M) {
    bn acc = M->one;
    for (int i = 255; i >= 0; i--) {
        bn_mul(&acc, &acc, &acc, M);
        if (bn_bit(e, i)) bn_mul(&acc, &acc, a, M);
    }
    *r = acc;
}

void bn_inv(bn *r, const bn *a, const bn_mod *M) {
    bn e, two;
    bn_set_u32(&two, 2);
    bn_sub_raw(&e, &M->m, &two);
    bn_pow(r, a, &e, M);
}

void bn_reduce512_le(bn *r, const uint8_t x[64], const bn_mod *M) {
    bn lo, hi, t;
    bn_from_le(&lo, x);
    bn_from_le(&hi, x + 32);
    bn_to_mont(&lo, &lo, M); /* lo R */
    bn_to_mont(&hi, &hi, M); /* hi R */
    bn_to_mont(&hi, &hi, M); /* hi R^2 = (hi R) R: Montgomery form of hi 2^256 */
    bn_add(&t, &lo, &hi, M); /* (lo + hi 2^256) R */
    bn_from_mont(r, &t, M);
}
