/* alt_bn128 (BN254): the EVM's precompiles 6, 7 and 8 (EIP-196, EIP-197), over evm_bn.c's
 * Montgomery arithmetic mod p. Reference-style and slow on purpose: affine and Jacobian formulas
 * written out, F_p^12 as polynomials, the pairing as the optimal ate Miller loop followed by a
 * plain final exponentiation by (p^12 - 1) / r. No precomputed tables beyond the constants below.
 *
 * The model is py_ecc's `bn128` (the Ethereum Foundation's reference, whose `bn128_pairing` is the
 * same algorithm), with its representation of the field tower:
 *
 *   F_p^2  = F_p[i] / (i^2 + 1)
 *   F_p^12 = F_p[w] / (w^12 - 18 w^6 + 82), so w^6 = 9 + i, and a + b i in F_p^2 is
 *            (a - 9 b) + b w^6 in F_p^12.
 *   G1: y^2 = x^3 + 3 over F_p. G2: the twist y^2 = x^3 + 3 / (9 + i) over F_p^2, carried into
 *   E(F_p^12) by (x, y) -> (x w^2, y w^3).
 *
 * Each Miller-loop line is py_ecc's `linefunc` evaluated with the twisted point's coordinates:
 * for a slope m on the twist the untwisted slope is m w, so the line through R = (xr, yr) at
 * P = (xp, yp) is m w (xp - xr w^2) - (yp - yr w^3) = -yp + (m xp) w + (yr - m xr) w^3, and a
 * vertical line is xp - xr w^2. The Frobenius images py_ecc takes as Q^p are, on the twist,
 * (conj(x) g3, conj(y) g2) with g3 = (9 + i)^((p - 1) / 3), g2 = (9 + i)^((p - 1) / 2).
 *
 * Encodings (EIP-196/197): a G1 point is x || y, a G2 point x_im || x_re || y_im || y_re, each a
 * 32-byte big-endian integer that must be below p; all zeros is the point at infinity; any other
 * point must be on its curve, and a G2 point must be in the order-r subgroup (r Q = O), as
 * go-ethereum checks. A scalar is any 256-bit integer.
 *
 * Constants (little-endian limbs), all derived from p, r and 9 + i:
 *   p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
 *   r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 *   the ate loop count 6u + 2 = 29793968203157093288 (65 bits; py_ecc's log_ate_loop_count 63)
 *   FINAL_EXP = (p^12 - 1) / r, 2790 bits, big-endian bytes.
 */
#include "evm_bn.h"
#include "precompiles.h"

static const bn BP = {{0xd87cfd47, 0x3c208c16, 0x6871ca8d, 0x97816a91, 0x8181585d, 0xb85045b6,
                       0xe131a029, 0x30644e72}};
static const bn BR = {{0xf0000001, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6,
                       0xe131a029, 0x30644e72}};
static const bn P_MINUS_1_OVER_3 = {{0x4829a9c2, 0x69602eb2, 0xcd7b4384, 0xdd2b2385, 0x808072c9,
                                     0xe81ac1e7, 0xa065e00d, 0x10216f7b}};
static const bn P_MINUS_1_OVER_2 = {{0x6c3e7ea3, 0x9e10460b, 0xb438e546, 0xcbc0b548, 0x40c0ac2e,
                                     0xdc2822db, 0x7098d014, 0x18322739}};
static const uint64_t ATE_LOOP_COUNT = 0x9d797039be763ba8ull; /* 6u + 2 without its bit 64 */

static const uint8_t FINAL_EXP[349] = {
    0x2f, 0x4b, 0x6d, 0xc9, 0x70, 0x20, 0xfd, 0xda, 0xdf, 0x10, 0x7d, 0x20, 0xbc, 0x84, 0x2d, 0x43,
    0xbf, 0x63, 0x69, 0xb1, 0xff, 0x6a, 0x1c, 0x71, 0x01, 0x5f, 0x3f, 0x7b, 0xe2, 0xe1, 0xe3, 0x0a,
    0x73, 0xbb, 0x94, 0xfe, 0xc0, 0xda, 0xf1, 0x54, 0x66, 0xb2, 0x38, 0x3a, 0x5d, 0x3e, 0xc3, 0xd1,
    0x5a, 0xd5, 0x24, 0xd8, 0xf7, 0x0c, 0x54, 0xef, 0xee, 0x1b, 0xd8, 0xc3, 0xb2, 0x13, 0x77, 0xe5,
    0x63, 0xa0, 0x9a, 0x1b, 0x70, 0x58, 0x87, 0xe7, 0x2e, 0xce, 0xad, 0xde, 0xa3, 0x79, 0x03, 0x64,
    0xa6, 0x1f, 0x67, 0x6b, 0xaa, 0xf9, 0x77, 0x87, 0x0e, 0x88, 0xd5, 0xc6, 0xc8, 0xfe, 0xf0, 0x78,
    0x13, 0x61, 0xe4, 0x43, 0xae, 0x77, 0xf5, 0xb6, 0x3a, 0x2a, 0x22, 0x64, 0x48, 0x7f, 0x29, 0x40,
    0xa8, 0xb1, 0xdd, 0xb3, 0xd1, 0x50, 0x62, 0xcd, 0x0f, 0xb2, 0x01, 0x5d, 0xfc, 0x66, 0x68, 0x44,
    0x9a, 0xed, 0x3c, 0xc4, 0x8a, 0x82, 0xd0, 0xd6, 0x02, 0xd2, 0x68, 0xc7, 0xda, 0xab, 0x6a, 0x41,
    0x29, 0x4c, 0x0c, 0xc4, 0xeb, 0xe5, 0x66, 0x45, 0x68, 0xdf, 0xc5, 0x0e, 0x16, 0x48, 0xa4, 0x5a,
    0x4a, 0x1e, 0x3a, 0x51, 0x95, 0x84, 0x6a, 0x3e, 0xd0, 0x11, 0xa3, 0x37, 0xa0, 0x20, 0x88, 0xec,
    0x80, 0xe0, 0xeb, 0xae, 0x87, 0x55, 0xcf, 0xe1, 0x07, 0xac, 0xf3, 0xaa, 0xfb, 0x40, 0x49, 0x4e,
    0x40, 0x6f, 0x80, 0x42, 0x16, 0xbb, 0x10, 0xcf, 0x43, 0x0b, 0x0f, 0x37, 0x85, 0x6b, 0x42, 0xdb,
    0x8d, 0xc5, 0x51, 0x47, 0x24, 0xee, 0x93, 0xdf, 0xb1, 0x08, 0x26, 0xf0, 0xdd, 0x4a, 0x03, 0x64,
    0xb9, 0x58, 0x02, 0x91, 0xd2, 0xcd, 0x65, 0x66, 0x48, 0x14, 0xfd, 0xe3, 0x7c, 0xa8, 0x0b, 0xb4,
    0xea, 0x44, 0xea, 0xcc, 0x5e, 0x64, 0x1b, 0xba, 0xdf, 0x42, 0x3f, 0x9a, 0x2c, 0xbf, 0x81, 0x3b,
    0x8d, 0x14, 0x5d, 0xa9, 0x00, 0x29, 0xba, 0xee, 0x7d, 0xda, 0xdd, 0xa7, 0x1c, 0x7f, 0x38, 0x11,
    0xc4, 0x10, 0x52, 0x62, 0x94, 0x5b, 0xba, 0x16, 0x68, 0xc3, 0xbe, 0x69, 0xa3, 0xc2, 0x30, 0x97,
    0x4d, 0x83, 0x56, 0x18, 0x41, 0xd7, 0x66, 0xf9, 0xc9, 0xd5, 0x70, 0xbb, 0x7f, 0xbe, 0x04, 0xc7,
    0xe8, 0xa6, 0xc3, 0xc7, 0x60, 0xc0, 0xde, 0x81, 0xde, 0xf3, 0x56, 0x92, 0xda, 0x36, 0x11, 0x02,
    0xb6, 0xb9, 0xb2, 0xb9, 0x18, 0x83, 0x7f, 0xa9, 0x78, 0x96, 0xe8, 0x4a, 0xbb, 0x40, 0xa4, 0xef,
    0xb7, 0xe5, 0x45, 0x23, 0xa4, 0x86, 0x96, 0x4b, 0x64, 0xca, 0x86, 0xf1, 0x20};

/* ---- F_p (Montgomery form throughout) ---- */

static bn_mod F;
static bn ONE_M, THREE_M, NINE_M, M18, M82; /* 1, 3, 9, 18, 82 in Montgomery form */
static int ready;

static void fp_const(bn *r, uint32_t v) {
    bn_set_u32(r, v);
    bn_to_mont(r, r, &F);
}

/* ---- F_p^2 ---- */

typedef struct {
    bn a, b; /* a + b i */
} fp2;

static void fp2_add(fp2 *r, const fp2 *x, const fp2 *y) {
    bn_add(&r->a, &x->a, &y->a, &F);
    bn_add(&r->b, &x->b, &y->b, &F);
}

static void fp2_sub(fp2 *r, const fp2 *x, const fp2 *y) {
    bn_sub(&r->a, &x->a, &y->a, &F);
    bn_sub(&r->b, &x->b, &y->b, &F);
}

static void fp2_neg(fp2 *r, const fp2 *x) {
    bn_neg(&r->a, &x->a, &F);
    bn_neg(&r->b, &x->b, &F);
}

static void fp2_mul(fp2 *r, const fp2 *x, const fp2 *y) {
    bn t0, t1, t2, t3;
    bn_mul(&t0, &x->a, &y->a, &F);
    bn_mul(&t1, &x->b, &y->b, &F);
    bn_mul(&t2, &x->a, &y->b, &F);
    bn_mul(&t3, &x->b, &y->a, &F);
    bn_sub(&r->a, &t0, &t1, &F);
    bn_add(&r->b, &t2, &t3, &F);
}

static void fp2_mul_fp(fp2 *r, const fp2 *x, const bn *k) {
    bn_mul(&r->a, &x->a, k, &F);
    bn_mul(&r->b, &x->b, k, &F);
}

static void fp2_conj(fp2 *r, const fp2 *x) {
    r->a = x->a;
    bn_neg(&r->b, &x->b, &F);
}

static int fp2_is_zero(const fp2 *x) { return bn_is_zero(&x->a) && bn_is_zero(&x->b); }

static int fp2_eq(const fp2 *x, const fp2 *y) {
    return bn_cmp(&x->a, &y->a) == 0 && bn_cmp(&x->b, &y->b) == 0;
}

/* 1 / (a + b i) = (a - b i) / (a^2 + b^2); 0 maps to 0. */
static void fp2_inv(fp2 *r, const fp2 *x) {
    bn n, t;
    bn_mul(&n, &x->a, &x->a, &F);
    bn_mul(&t, &x->b, &x->b, &F);
    bn_add(&n, &n, &t, &F);
    bn_inv(&n, &n, &F);
    bn_mul(&r->a, &x->a, &n, &F);
    bn_mul(&t, &x->b, &n, &F);
    bn_neg(&r->b, &t, &F);
}

static void fp2_pow(fp2 *r, const fp2 *x, const bn *e) {
    fp2 acc;
    acc.a = ONE_M;
    bn_set_u32(&acc.b, 0);
    for (int i = 255; i >= 0; i--) {
        fp2_mul(&acc, &acc, &acc);
        if (bn_bit(e, i)) fp2_mul(&acc, &acc, x);
    }
    *r = acc;
}

static fp2 TWIST_B, G3, G2C; /* 3 / (9 + i); (9 + i)^((p-1)/3); (9 + i)^((p-1)/2) */
static int pairing_ready;

/* F_p and its small constants: what add and mul need. */
static void setup(void) {
    if (ready) return;
    bn_mod_init(&F, &BP);
    fp_const(&ONE_M, 1);
    fp_const(&THREE_M, 3);
    fp_const(&NINE_M, 9);
    fp_const(&M18, 18);
    fp_const(&M82, 82);
    ready = 1;
}

/* The twist's constants, derived from 9 + i (two F_p^2 powers and an inverse): the pairing's. */
static void setup_pairing(void) {
    setup();
    if (pairing_ready) return;
    fp2 xi;
    xi.a = NINE_M;
    xi.b = ONE_M;
    fp2_inv(&TWIST_B, &xi);
    fp2_mul_fp(&TWIST_B, &TWIST_B, &THREE_M);
    fp2_pow(&G3, &xi, &P_MINUS_1_OVER_3);
    fp2_pow(&G2C, &xi, &P_MINUS_1_OVER_2);
    pairing_ready = 1;
}

/* ---- Jacobian points, a = 0, over F_p (G1) and F_p^2 (G2): dbl-2009-l and add-2007-bl, as
 * evm_secp256k1.c has them over F_p ---- */

typedef struct {
    bn X, Y, Z;
    int inf;
} g1j;

static void g1_double(g1j *r, const g1j *p) {
    if (p->inf || bn_is_zero(&p->Y)) {
        r->inf = 1;
        return;
    }
    bn a, b, c, d, e, f, t, X3, Z3;
    bn_mul(&a, &p->X, &p->X, &F);
    bn_mul(&b, &p->Y, &p->Y, &F);
    bn_mul(&c, &b, &b, &F);
    bn_add(&t, &p->X, &b, &F);
    bn_mul(&t, &t, &t, &F);
    bn_sub(&t, &t, &a, &F);
    bn_sub(&t, &t, &c, &F);
    bn_add(&d, &t, &t, &F);
    bn_add(&e, &a, &a, &F);
    bn_add(&e, &e, &a, &F);
    bn_mul(&f, &e, &e, &F);
    bn_mul(&Z3, &p->Y, &p->Z, &F);
    bn_add(&Z3, &Z3, &Z3, &F);
    bn_sub(&X3, &f, &d, &F);
    bn_sub(&X3, &X3, &d, &F);
    bn_sub(&t, &d, &X3, &F);
    bn_mul(&t, &e, &t, &F);
    bn_add(&c, &c, &c, &F);
    bn_add(&c, &c, &c, &F);
    bn_add(&c, &c, &c, &F);
    bn_sub(&r->Y, &t, &c, &F);
    r->X = X3;
    r->Z = Z3;
    r->inf = 0;
}

static void g1_add(g1j *r, const g1j *p, const g1j *q) {
    if (p->inf) {
        *r = *q;
        return;
    }
    if (q->inf) {
        *r = *p;
        return;
    }
    bn z1z1, z2z2, u1, u2, s1, s2, h, rr, t, i, j, v, X3, Y3, Z3;
    bn_mul(&z1z1, &p->Z, &p->Z, &F);
    bn_mul(&z2z2, &q->Z, &q->Z, &F);
    bn_mul(&u1, &p->X, &z2z2, &F);
    bn_mul(&u2, &q->X, &z1z1, &F);
    bn_mul(&s1, &p->Y, &q->Z, &F);
    bn_mul(&s1, &s1, &z2z2, &F);
    bn_mul(&s2, &q->Y, &p->Z, &F);
    bn_mul(&s2, &s2, &z1z1, &F);
    bn_sub(&h, &u2, &u1, &F);
    bn_sub(&rr, &s2, &s1, &F);
    if (bn_is_zero(&h)) {
        if (bn_is_zero(&rr)) g1_double(r, p);
        else r->inf = 1;
        return;
    }
    bn_add(&i, &h, &h, &F);
    bn_mul(&i, &i, &i, &F);
    bn_mul(&j, &h, &i, &F);
    bn_add(&rr, &rr, &rr, &F);
    bn_mul(&v, &u1, &i, &F);
    bn_mul(&X3, &rr, &rr, &F);
    bn_sub(&X3, &X3, &j, &F);
    bn_sub(&X3, &X3, &v, &F);
    bn_sub(&X3, &X3, &v, &F);
    bn_sub(&t, &v, &X3, &F);
    bn_mul(&Y3, &rr, &t, &F);
    bn_mul(&t, &s1, &j, &F);
    bn_add(&t, &t, &t, &F);
    bn_sub(&Y3, &Y3, &t, &F);
    bn_add(&t, &p->Z, &q->Z, &F);
    bn_mul(&t, &t, &t, &F);
    bn_sub(&t, &t, &z1z1, &F);
    bn_sub(&t, &t, &z2z2, &F);
    bn_mul(&Z3, &t, &h, &F);
    r->X = X3;
    r->Y = Y3;
    r->Z = Z3;
    r->inf = 0;
}

typedef struct {
    fp2 X, Y, Z;
    int inf;
} g2j;

static void g2_double(g2j *r, const g2j *p) {
    if (p->inf || fp2_is_zero(&p->Y)) {
        r->inf = 1;
        return;
    }
    fp2 a, b, c, d, e, f, t, X3, Z3;
    fp2_mul(&a, &p->X, &p->X);
    fp2_mul(&b, &p->Y, &p->Y);
    fp2_mul(&c, &b, &b);
    fp2_add(&t, &p->X, &b);
    fp2_mul(&t, &t, &t);
    fp2_sub(&t, &t, &a);
    fp2_sub(&t, &t, &c);
    fp2_add(&d, &t, &t);
    fp2_add(&e, &a, &a);
    fp2_add(&e, &e, &a);
    fp2_mul(&f, &e, &e);
    fp2_mul(&Z3, &p->Y, &p->Z);
    fp2_add(&Z3, &Z3, &Z3);
    fp2_sub(&X3, &f, &d);
    fp2_sub(&X3, &X3, &d);
    fp2_sub(&t, &d, &X3);
    fp2_mul(&t, &e, &t);
    fp2_add(&c, &c, &c);
    fp2_add(&c, &c, &c);
    fp2_add(&c, &c, &c);
    fp2_sub(&r->Y, &t, &c);
    r->X = X3;
    r->Z = Z3;
    r->inf = 0;
}

static void g2_add(g2j *r, const g2j *p, const g2j *q) {
    if (p->inf) {
        *r = *q;
        return;
    }
    if (q->inf) {
        *r = *p;
        return;
    }
    fp2 z1z1, z2z2, u1, u2, s1, s2, h, rr, t, i, j, v, X3, Y3, Z3;
    fp2_mul(&z1z1, &p->Z, &p->Z);
    fp2_mul(&z2z2, &q->Z, &q->Z);
    fp2_mul(&u1, &p->X, &z2z2);
    fp2_mul(&u2, &q->X, &z1z1);
    fp2_mul(&s1, &p->Y, &q->Z);
    fp2_mul(&s1, &s1, &z2z2);
    fp2_mul(&s2, &q->Y, &p->Z);
    fp2_mul(&s2, &s2, &z1z1);
    fp2_sub(&h, &u2, &u1);
    fp2_sub(&rr, &s2, &s1);
    if (fp2_is_zero(&h)) {
        if (fp2_is_zero(&rr)) g2_double(r, p);
        else r->inf = 1;
        return;
    }
    fp2_add(&i, &h, &h);
    fp2_mul(&i, &i, &i);
    fp2_mul(&j, &h, &i);
    fp2_add(&rr, &rr, &rr);
    fp2_mul(&v, &u1, &i);
    fp2_mul(&X3, &rr, &rr);
    fp2_sub(&X3, &X3, &j);
    fp2_sub(&X3, &X3, &v);
    fp2_sub(&X3, &X3, &v);
    fp2_sub(&t, &v, &X3);
    fp2_mul(&Y3, &rr, &t);
    fp2_mul(&t, &s1, &j);
    fp2_add(&t, &t, &t);
    fp2_sub(&Y3, &Y3, &t);
    fp2_add(&t, &p->Z, &q->Z);
    fp2_mul(&t, &t, &t);
    fp2_sub(&t, &t, &z1z1);
    fp2_sub(&t, &t, &z2z2);
    fp2_mul(&Z3, &t, &h);
    r->X = X3;
    r->Y = Y3;
    r->Z = Z3;
    r->inf = 0;
}

/* ---- decoding ---- */

/* A 32-byte big-endian coordinate below p, into Montgomery form; 0 if it is not below p. */
static int coord(bn *r, const uint8_t b[32]) {
    bn_from_be(r, b);
    if (bn_cmp(r, &BP) >= 0) return 0;
    bn_to_mont(r, r, &F);
    return 1;
}

/* A G1 point (affine, Montgomery): 0 invalid, 1 ok; `*inf` for all zeros. */
static int g1_decode(bn *x, bn *y, int *inf, const uint8_t in[64]) {
    if (!coord(x, in) || !coord(y, in + 32)) return 0;
    *inf = bn_is_zero(x) && bn_is_zero(y);
    if (*inf) return 1;
    bn l, rh;
    bn_mul(&l, y, y, &F);
    bn_mul(&rh, x, x, &F);
    bn_mul(&rh, &rh, x, &F);
    bn_add(&rh, &rh, &THREE_M, &F);
    return bn_cmp(&l, &rh) == 0;
}

static void g1_encode(uint8_t out[64], const g1j *p) {
    if (p->inf) {
        for (int i = 0; i < 64; i++) out[i] = 0;
        return;
    }
    bn zi, zi2, ax, ay;
    bn_inv(&zi, &p->Z, &F);
    bn_mul(&zi2, &zi, &zi, &F);
    bn_mul(&ax, &p->X, &zi2, &F);
    bn_mul(&zi2, &zi2, &zi, &F);
    bn_mul(&ay, &p->Y, &zi2, &F);
    bn_from_mont(&ax, &ax, &F);
    bn_from_mont(&ay, &ay, &F);
    bn_to_be(out, &ax);
    bn_to_be(out + 32, &ay);
}

static void g1_jac(g1j *r, const bn *x, const bn *y, int inf) {
    r->X = *x;
    r->Y = *y;
    r->Z = ONE_M;
    r->inf = inf;
}

/* [k] Q over the bits of the plain 256-bit k, most significant first. */
static void g2_mul(g2j *r, const g2j *q, const bn *k) {
    g2j acc;
    acc.inf = 1;
    for (int i = 255; i >= 0; i--) {
        g2_double(&acc, &acc);
        if (bn_bit(k, i)) g2_add(&acc, &acc, q);
    }
    *r = acc;
}

/* A G2 point (affine, Montgomery): 0 invalid (a coordinate >= p, off the twist, or outside the
 * order-r subgroup), 1 ok; `*inf` for all zeros. */
static int g2_decode(fp2 *x, fp2 *y, int *inf, const uint8_t in[128]) {
    if (!coord(&x->b, in) || !coord(&x->a, in + 32) || !coord(&y->b, in + 64) || !coord(&y->a, in + 96))
        return 0;
    *inf = fp2_is_zero(x) && fp2_is_zero(y);
    if (*inf) return 1;
    fp2 l, rh;
    fp2_mul(&l, y, y);
    fp2_mul(&rh, x, x);
    fp2_mul(&rh, &rh, x);
    fp2_add(&rh, &rh, &TWIST_B);
    if (!fp2_eq(&l, &rh)) return 0;
    g2j q, rq;
    q.X = *x;
    q.Y = *y;
    q.Z.a = ONE_M;
    bn_set_u32(&q.Z.b, 0);
    q.inf = 0;
    g2_mul(&rq, &q, &BR);
    return rq.inf;
}

/* ---- 6, 7: add and mul ---- */

uint32_t evm_bn256_add(const uint8_t in[128], uint8_t out[64]) {
    setup();
    bn x1, y1, x2, y2;
    int i1, i2;
    if (!g1_decode(&x1, &y1, &i1, in) || !g1_decode(&x2, &y2, &i2, in + 64)) return PC_FAIL;
    g1j a, b, r;
    g1_jac(&a, &x1, &y1, i1);
    g1_jac(&b, &x2, &y2, i2);
    g1_add(&r, &a, &b);
    g1_encode(out, &r);
    return PC_OK;
}

uint32_t evm_bn256_mul(const uint8_t in[96], uint8_t out[64]) {
    setup();
    bn x, y, k;
    int inf;
    if (!g1_decode(&x, &y, &inf, in)) return PC_FAIL;
    bn_from_be(&k, in + 64);
    g1j q, acc;
    g1_jac(&q, &x, &y, inf);
    acc.inf = 1;
    for (int i = 255; i >= 0; i--) {
        g1_double(&acc, &acc);
        if (bn_bit(&k, i)) g1_add(&acc, &acc, &q);
    }
    g1_encode(out, &acc);
    return PC_OK;
}

/* ---- F_p^12 = F_p[w] / (w^12 - 18 w^6 + 82) ---- */

typedef struct {
    bn c[12];
} fp12;

static void fp12_one(fp12 *r) {
    for (int i = 0; i < 12; i++) bn_set_u32(&r->c[i], 0);
    r->c[0] = ONE_M;
}

static void fp12_mul(fp12 *r, const fp12 *x, const fp12 *y) {
    bn t[23], p;
    for (int i = 0; i < 23; i++) bn_set_u32(&t[i], 0);
    for (int i = 0; i < 12; i++) {
        if (bn_is_zero(&x->c[i])) continue;
        for (int j = 0; j < 12; j++) {
            if (bn_is_zero(&y->c[j])) continue;
            bn_mul(&p, &x->c[i], &y->c[j], &F);
            bn_add(&t[i + j], &t[i + j], &p, &F);
        }
    }
    /* w^k = 18 w^(k-6) - 82 w^(k-12), top down. */
    for (int k = 22; k >= 12; k--) {
        if (bn_is_zero(&t[k])) continue;
        bn_mul(&p, &t[k], &M18, &F);
        bn_add(&t[k - 6], &t[k - 6], &p, &F);
        bn_mul(&p, &t[k], &M82, &F);
        bn_sub(&t[k - 12], &t[k - 12], &p, &F);
    }
    for (int i = 0; i < 12; i++) r->c[i] = t[i];
}

/* r += e(v) w^k: a + b i is (a - 9 b) + b w^6; k <= 5. */
static void fp12_add_fp2(fp12 *r, const fp2 *v, int k) {
    bn t;
    bn_mul(&t, &v->b, &NINE_M, &F);
    bn_sub(&t, &v->a, &t, &F);
    bn_add(&r->c[k], &r->c[k], &t, &F);
    bn_add(&r->c[k + 6], &r->c[k + 6], &v->b, &F);
}

static int fp12_is_one(const fp12 *x) {
    if (bn_cmp(&x->c[0], &ONE_M) != 0) return 0;
    for (int i = 1; i < 12; i++)
        if (!bn_is_zero(&x->c[i])) return 0;
    return 1;
}

/* ---- the Miller loop ---- */

typedef struct {
    fp2 x, y;
    int inf;
} g2a;

/* f *= the line through R and Q (Q = R: the tangent) at P, and R = R + Q; py_ecc's
 * `linefunc(R, Q, P)` then `add(R, Q)` (or `double(R)`), with the slope shared. */
static void step(fp12 *f, g2a *R, const g2a *Q, const bn *xp, const bn *yp) {
    if (R->inf || Q->inf) {
        /* Unreachable for an order-r Q (R = [k] Q with 0 < k < r); py_ecc would fail. */
        if (R->inf) *R = *Q;
        return;
    }
    fp2 m, t, u;
    fp12 l;
    for (int i = 0; i < 12; i++) bn_set_u32(&l.c[i], 0);
    if (!fp2_eq(&R->x, &Q->x)) {
        fp2_sub(&t, &Q->y, &R->y);
        fp2_sub(&u, &Q->x, &R->x);
        fp2_inv(&u, &u);
        fp2_mul(&m, &t, &u);
    } else if (fp2_eq(&R->y, &Q->y) && !fp2_is_zero(&R->y)) {
        fp2_mul(&t, &R->x, &R->x);
        fp2_mul_fp(&t, &t, &THREE_M);
        fp2_add(&u, &R->y, &R->y);
        fp2_inv(&u, &u);
        fp2_mul(&m, &t, &u);
    } else {
        /* Vertical: xp - xr w^2, and R + Q is the point at infinity. */
        l.c[0] = *xp;
        fp2_neg(&t, &R->x);
        fp12_add_fp2(&l, &t, 2);
        fp12_mul(f, f, &l);
        R->inf = 1;
        return;
    }
    /* -yp + (m xp) w + (yr - m xr) w^3 */
    bn_neg(&l.c[0], yp, &F);
    fp2_mul_fp(&t, &m, xp);
    fp12_add_fp2(&l, &t, 1);
    fp2_mul(&t, &m, &R->x);
    fp2_sub(&t, &R->y, &t);
    fp12_add_fp2(&l, &t, 3);
    fp12_mul(f, f, &l);
    /* R + Q: x3 = m^2 - xr - xq, y3 = m (xr - x3) - yr. */
    fp2 x3;
    fp2_mul(&x3, &m, &m);
    fp2_sub(&x3, &x3, &R->x);
    fp2_sub(&x3, &x3, &Q->x);
    fp2_sub(&t, &R->x, &x3);
    fp2_mul(&t, &m, &t);
    fp2_sub(&R->y, &t, &R->y);
    R->x = x3;
}

static void miller(fp12 *f, const g2a *Q, const bn *xp, const bn *yp) {
    g2a R = *Q;
    for (int i = 63; i >= 0; i--) {
        fp12_mul(f, f, f);
        g2a R0 = R;
        step(f, &R, &R0, xp, yp);
        if (ATE_LOOP_COUNT >> i & 1) step(f, &R, Q, xp, yp);
    }
    g2a Q1, nQ2;
    fp2_conj(&Q1.x, &Q->x);
    fp2_mul(&Q1.x, &Q1.x, &G3);
    fp2_conj(&Q1.y, &Q->y);
    fp2_mul(&Q1.y, &Q1.y, &G2C);
    Q1.inf = 0;
    fp2_conj(&nQ2.x, &Q1.x);
    fp2_mul(&nQ2.x, &nQ2.x, &G3);
    fp2_conj(&nQ2.y, &Q1.y);
    fp2_mul(&nQ2.y, &nQ2.y, &G2C);
    fp2_neg(&nQ2.y, &nQ2.y);
    nQ2.inf = 0;
    step(f, &R, &Q1, xp, yp);
    step(f, &R, &nQ2, xp, yp);
}

uint32_t evm_bn256_pairing(const uint8_t *in, uint32_t n, uint32_t *one) {
    setup_pairing();
    fp12 f;
    fp12_one(&f);
    for (uint32_t k = 0; k < n; k++) {
        const uint8_t *e = in + 192 * k;
        bn xp, yp;
        int pinf, qinf;
        g2a Q;
        if (!g1_decode(&xp, &yp, &pinf, e)) return PC_FAIL;
        if (!g2_decode(&Q.x, &Q.y, &qinf, e + 64)) return PC_FAIL;
        Q.inf = 0;
        if (pinf || qinf) continue; /* e(P, Q) = 1 */
        /* Each Miller loop from 1 (it squares its accumulator), then into the product. */
        fp12 fk;
        fp12_one(&fk);
        miller(&fk, &Q, &xp, &yp);
        fp12_mul(&f, &f, &fk);
    }
    /* The final exponentiation, square and multiply over FINAL_EXP's bits. */
    fp12 acc;
    fp12_one(&acc);
    for (uint32_t i = 0; i < sizeof FINAL_EXP; i++) {
        for (int b = 7; b >= 0; b--) {
            fp12_mul(&acc, &acc, &acc);
            if (FINAL_EXP[i] >> b & 1) fp12_mul(&acc, &acc, &f);
        }
    }
    *one = (uint32_t)fp12_is_one(&acc);
    return PC_OK;
}
