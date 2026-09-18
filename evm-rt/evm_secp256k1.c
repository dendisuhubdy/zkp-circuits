/* Copied from sbpf-rt at 4f50932 (sbpf-rt/sbpf_secp256k1.c), renamed with the evm_ prefix; the two
 * copies are to be deduplicated into one shared C directory once feat/sbpf2rv and feat/evm2rv have
 * both merged. The curve arithmetic is unchanged. What differs is the entry point: it is
 * `evm_secp256k1_recover` (precompiles.h), with a plain 0/1 result in place of Solana's error
 * codes and no syscall wrapper; the EVM's own rules (v is 27 or 28, a failure is an empty output,
 * not an error) are ecrecover's in precompiles.c, which calls this with recid = v - 27.
 *
 * The original header comment follows.
 *
 * secp256k1 public-key recovery, as Solana's `sol_secp256k1_recover` does it over libsecp256k1
 * (`Signature::parse_standard_slice`, `RecoveryId::parse`, `recover`): Q = r^-1 (s R - e G), with R
 * the curve point whose x is r + (recid >> 1) n and whose y has recid's low bit as its parity. The
 * field (mod p) and the scalars (mod n) are `sbpf_bn.c`'s Montgomery arithmetic; points are
 * Jacobian (a = 0), and u1 G + u2 R is one shared doubling chain (Straus/Shamir). No tables; the
 * curve constants below are the only data. `test/crypto_vectors.h` has the known answers
 * (go-ethereum's ecrecover vector, OpenSSL-signed vectors, every rejection). */
#include "evm_bn.h"
#include "precompiles.h"

#define SECP_OK 0
#define SECP_FAIL 1

/* Little-endian limbs: p = 2^256 - 2^32 - 977, n the group order, G the generator (SEC 2). */
static const bn SP = {{0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                       0xffffffff, 0xffffffff}};
static const bn SN = {{0xd0364141, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6, 0xfffffffe, 0xffffffff,
                       0xffffffff, 0xffffffff}};
static const bn GX = {{0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb, 0xce870b07, 0x55a06295,
                       0xf9dcbbac, 0x79be667e}};
static const bn GY = {{0xfb10d4b8, 0x9c47d08f, 0xa6855419, 0xfd17b448, 0x0e1108a8, 0x5da4fbfc,
                       0x26a3c465, 0x483ada77}};

typedef struct {
    bn X, Y, Z; /* x = X/Z^2, y = Y/Z^3; Montgomery form */
    int inf;
} gej;

/* dbl-2009-l. */
static void gej_double(gej *r, const gej *p, const bn_mod *F) {
    if (p->inf || bn_is_zero(&p->Y)) {
        r->inf = 1;
        return;
    }
    bn a, b, c, d, e, f, t;
    bn_mul(&a, &p->X, &p->X, F);
    bn_mul(&b, &p->Y, &p->Y, F);
    bn_mul(&c, &b, &b, F);
    bn_add(&t, &p->X, &b, F);
    bn_mul(&t, &t, &t, F);
    bn_sub(&t, &t, &a, F);
    bn_sub(&t, &t, &c, F);
    bn_add(&d, &t, &t, F);  /* D = 2((X + B)^2 - A - C) */
    bn_add(&e, &a, &a, F);
    bn_add(&e, &e, &a, F);  /* E = 3A */
    bn_mul(&f, &e, &e, F);  /* F = E^2 */
    bn Z3;
    bn_mul(&Z3, &p->Y, &p->Z, F);
    bn_add(&Z3, &Z3, &Z3, F); /* Z3 = 2 Y Z */
    bn X3;
    bn_sub(&X3, &f, &d, F);
    bn_sub(&X3, &X3, &d, F); /* X3 = F - 2D */
    bn_sub(&t, &d, &X3, F);
    bn_mul(&t, &e, &t, F);
    bn_add(&c, &c, &c, F);
    bn_add(&c, &c, &c, F);
    bn_add(&c, &c, &c, F); /* 8C */
    bn_sub(&r->Y, &t, &c, F); /* Y3 = E (D - X3) - 8C */
    r->X = X3;
    r->Z = Z3;
    r->inf = 0;
}

/* add-2007-bl, with the two cases it cannot take: P = Q (double) and P = -Q (infinity). */
static void gej_add(gej *r, const gej *p, const gej *q, const bn_mod *F) {
    if (p->inf) {
        *r = *q;
        return;
    }
    if (q->inf) {
        *r = *p;
        return;
    }
    bn z1z1, z2z2, u1, u2, s1, s2, h, rr, t;
    bn_mul(&z1z1, &p->Z, &p->Z, F);
    bn_mul(&z2z2, &q->Z, &q->Z, F);
    bn_mul(&u1, &p->X, &z2z2, F);
    bn_mul(&u2, &q->X, &z1z1, F);
    bn_mul(&s1, &p->Y, &q->Z, F);
    bn_mul(&s1, &s1, &z2z2, F);
    bn_mul(&s2, &q->Y, &p->Z, F);
    bn_mul(&s2, &s2, &z1z1, F);
    bn_sub(&h, &u2, &u1, F);
    bn_sub(&rr, &s2, &s1, F);
    if (bn_is_zero(&h)) {
        if (bn_is_zero(&rr)) gej_double(r, p, F);
        else r->inf = 1;
        return;
    }
    bn i, j, v;
    bn_add(&i, &h, &h, F);
    bn_mul(&i, &i, &i, F);  /* I = (2H)^2 */
    bn_mul(&j, &h, &i, F);  /* J = H I */
    bn_add(&rr, &rr, &rr, F); /* r = 2 (S2 - S1) */
    bn_mul(&v, &u1, &i, F); /* V = U1 I */
    bn X3, Y3, Z3;
    bn_mul(&X3, &rr, &rr, F);
    bn_sub(&X3, &X3, &j, F);
    bn_sub(&X3, &X3, &v, F);
    bn_sub(&X3, &X3, &v, F); /* X3 = r^2 - J - 2V */
    bn_sub(&t, &v, &X3, F);
    bn_mul(&Y3, &rr, &t, F);
    bn_mul(&t, &s1, &j, F);
    bn_add(&t, &t, &t, F);
    bn_sub(&Y3, &Y3, &t, F); /* Y3 = r (V - X3) - 2 S1 J */
    bn_add(&t, &p->Z, &q->Z, F);
    bn_mul(&t, &t, &t, F);
    bn_sub(&t, &t, &z1z1, F);
    bn_sub(&t, &t, &z2z2, F);
    bn_mul(&Z3, &t, &h, F);  /* Z3 = ((Z1 + Z2)^2 - Z1Z1 - Z2Z2) H */
    r->X = X3;
    r->Y = Y3;
    r->Z = Z3;
    r->inf = 0;
}

uint32_t evm_secp256k1_recover(const uint8_t hash[32], uint32_t recid, const uint8_t sig[64],
                               uint8_t out[64]) {
    /* `recovery_id.try_into::<u8>()` then `RecoveryId::parse`: anything but 0..3. */
    if (recid > 3) return SECP_FAIL;
    bn r, s, e;
    bn_from_be(&r, sig);
    bn_from_be(&s, sig + 32);
    /* `parse_standard_slice` refuses r or s >= n; `recover` refuses either being zero. */
    if (bn_cmp(&r, &SN) >= 0 || bn_cmp(&s, &SN) >= 0 || bn_is_zero(&r) || bn_is_zero(&s))
        return SECP_FAIL;

    bn_mod F, N;
    bn_mod_init(&F, &SP);
    bn_mod_init(&N, &SN);

    /* R: x = r (+ n), which must be a field element; y = sqrt(x^3 + 7) with recid's parity. */
    bn x = r;
    if (recid & 2) {
        if (bn_add_raw(&x, &r, &SN)) return SECP_FAIL;
        if (bn_cmp(&x, &SP) >= 0) return SECP_FAIL;
    }
    bn xm, y2, y, t, seven, exp;
    bn_to_mont(&xm, &x, &F);
    bn_mul(&y2, &xm, &xm, &F);
    bn_mul(&y2, &y2, &xm, &F);
    bn_set_u32(&seven, 7);
    bn_to_mont(&seven, &seven, &F);
    bn_add(&y2, &y2, &seven, &F);
    /* (p + 1) / 4, since p = 3 mod 4. */
    bn_set_u32(&t, 1);
    bn_add_raw(&exp, &SP, &t);
    for (int i = 0; i < 8; i++) exp.v[i] = (exp.v[i] >> 2) | (i < 7 ? exp.v[i + 1] << 30 : 0);
    bn_pow(&y, &y2, &exp, &F);
    bn_mul(&t, &y, &y, &F);
    if (bn_cmp(&t, &y2) != 0) return SECP_FAIL;
    bn plain;
    bn_from_mont(&plain, &y, &F);
    if ((plain.v[0] & 1) != (uint32_t)(recid & 1)) bn_neg(&y, &y, &F);

    /* e = hash mod n (one subtraction: hash < 2^256 < 2n); u1 = -e / r, u2 = s / r mod n. */
    bn_from_be(&e, hash);
    if (bn_cmp(&e, &SN) >= 0) bn_sub_raw(&e, &e, &SN);
    bn rinv, u1, u2;
    bn_to_mont(&rinv, &r, &N);
    bn_inv(&rinv, &rinv, &N);
    bn_to_mont(&u1, &e, &N);
    bn_mul(&u1, &u1, &rinv, &N);
    bn_neg(&u1, &u1, &N);
    bn_from_mont(&u1, &u1, &N);
    bn_to_mont(&u2, &s, &N);
    bn_mul(&u2, &u2, &rinv, &N);
    bn_from_mont(&u2, &u2, &N);

    /* Q = u1 G + u2 R. */
    gej G, R, GR, Q;
    bn_to_mont(&G.X, &GX, &F);
    bn_to_mont(&G.Y, &GY, &F);
    G.Z = F.one;
    G.inf = 0;
    R.X = xm;
    R.Y = y;
    R.Z = F.one;
    R.inf = 0;
    gej_add(&GR, &G, &R, &F);
    Q.inf = 1;
    for (int i = 255; i >= 0; i--) {
        gej_double(&Q, &Q, &F);
        int a = bn_bit(&u1, i), b = bn_bit(&u2, i);
        if (a && b) gej_add(&Q, &Q, &GR, &F);
        else if (a) gej_add(&Q, &Q, &G, &F);
        else if (b) gej_add(&Q, &Q, &R, &F);
    }
    if (Q.inf) return SECP_FAIL;

    /* Affine: x = X / Z^2, y = Y / Z^3. */
    bn zi, zi2, ax, ay;
    bn_inv(&zi, &Q.Z, &F);
    bn_mul(&zi2, &zi, &zi, &F);
    bn_mul(&ax, &Q.X, &zi2, &F);
    bn_mul(&zi2, &zi2, &zi, &F);
    bn_mul(&ay, &Q.Y, &zi2, &F);
    bn_from_mont(&ax, &ax, &F);
    bn_from_mont(&ay, &ay, &F);
    bn_to_be(out, &ax);
    bn_to_be(out + 32, &ay);
    return SECP_OK;
}
