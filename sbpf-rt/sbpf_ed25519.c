/* Ed25519 verification (RFC 8032 §5.1.7), written after the RFC's own §6 reference code: point
 * decoding with its `recover_x`, extended twisted-Edwards coordinates with its unified `point_add`
 * (complete on this curve, so it doubles too), and the cofactorless check [S]B = R + [k]A — here as
 * [S]B + [k](-A) = R with one shared doubling chain (Straus/Shamir), the same equation. SHA-512 is
 * in this file, software; the field is `sbpf_bn.c`'s Montgomery arithmetic mod 2^255 - 19, the
 * scalars are reduced mod L the same way. No tables; the curve constants below are the only data.
 * `test/crypto_vectors.h` has the known answers (RFC 8032 §7.1 among them). */
#include "sbpf_bn.h"
#include "sbpf_rt.h"

/* ---- SHA-512 (FIPS 180-4) --------------------------------------------------------------------- */

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
};

typedef struct {
    uint64_t h[8];
    uint8_t block[128];
    uint32_t fill;
    uint64_t len;
} sha512_ctx;

static uint64_t ror64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static void sha512_block(sha512_ctx *s, const uint8_t *b) {
    uint64_t w[80], v[8];
    for (int i = 0; i < 16; i++) {
        uint64_t x = 0;
        for (int j = 0; j < 8; j++) x = x << 8 | b[8 * i + j];
        w[i] = x;
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ror64(w[i - 15], 1) ^ ror64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ror64(w[i - 2], 19) ^ ror64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    for (int i = 0; i < 8; i++) v[i] = s->h[i];
    for (int i = 0; i < 80; i++) {
        uint64_t S1 = ror64(v[4], 14) ^ ror64(v[4], 18) ^ ror64(v[4], 41);
        uint64_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        uint64_t t1 = v[7] + S1 + ch + K512[i] + w[i];
        uint64_t S0 = ror64(v[0], 28) ^ ror64(v[0], 34) ^ ror64(v[0], 39);
        uint64_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        v[7] = v[6], v[6] = v[5], v[5] = v[4], v[4] = v[3] + t1;
        v[3] = v[2], v[2] = v[1], v[1] = v[0], v[0] = t1 + S0 + maj;
    }
    for (int i = 0; i < 8; i++) s->h[i] += v[i];
}

static void sha512_init(sha512_ctx *s) {
    static const uint64_t iv[8] = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull,
                                   0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
                                   0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
    for (int i = 0; i < 8; i++) s->h[i] = iv[i];
    s->fill = 0;
    s->len = 0;
}

static void sha512_update(sha512_ctx *s, const uint8_t *p, uint32_t n) {
    s->len += n;
    for (uint32_t i = 0; i < n; i++) {
        s->block[s->fill++] = p[i];
        if (s->fill == 128) {
            sha512_block(s, s->block);
            s->fill = 0;
        }
    }
}

/* Messages here are far below 2^61 bytes, so the 128-bit length's top half is zero. */
static void sha512_finish(sha512_ctx *s, uint8_t out[64]) {
    uint64_t bits = s->len * 8;
    s->block[s->fill++] = 0x80;
    if (s->fill > 112) {
        while (s->fill < 128) s->block[s->fill++] = 0;
        sha512_block(s, s->block);
        s->fill = 0;
    }
    while (s->fill < 120) s->block[s->fill++] = 0;
    for (int i = 0; i < 8; i++) s->block[120 + i] = (uint8_t)(bits >> (56 - 8 * i));
    sha512_block(s, s->block);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) out[8 * i + j] = (uint8_t)(s->h[i] >> (56 - 8 * j));
}

/* ---- the curve -------------------------------------------------------------------------------- */

/* Little-endian limbs. p = 2^255 - 19; L = 2^252 + 27742317777372353535851937790883648493;
 * d = -121665/121666 mod p; sqrt(-1) = 2^((p-1)/4) mod p; B = (Bx, 4/5), Bx even. Each was
 * computed from that definition (Python big integers) and any error fails every RFC 8032 vector. */
static const bn P25519 = {{0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                           0xffffffff, 0x7fffffff}};
static const bn L25519 = {{0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de, 0x00000000, 0x00000000,
                           0x00000000, 0x10000000}};
static const bn D25519 = {{0x135978a3, 0x75eb4dca, 0x4141d8ab, 0x00700a4d, 0x7779e898, 0x8cc74079,
                           0x2b6ffe73, 0x52036cee}};
static const bn SQRTM1 = {{0x4a0ea0b0, 0xc4ee1b27, 0xad2fe478, 0x2f431806, 0x3dfbd7a7, 0x2b4d0099,
                           0x4fc1df0b, 0x2b832480}};
static const bn BX = {{0x8f25d51a, 0xc9562d60, 0x9525a7b2, 0x692cc760, 0xfdd6dc5c, 0xc0a4e231,
                       0xcd6e53fe, 0x216936d3}};
static const bn BY = {{0x66666658, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666,
                       0x66666666, 0x66666666}};

typedef struct {
    bn X, Y, Z, T; /* x = X/Z, y = Y/Z, xy = T/Z; Montgomery form */
} ge;

typedef struct {
    bn_mod F;   /* mod p */
    bn d2;      /* 2d, Montgomery */
} ed_ctx;

/* RFC 8032 §6 `point_add`: complete on this curve (a = -1, d not a square), so it also doubles and
 * takes the identity (0, 1, 1, 0). */
static void ge_add(ge *r, const ge *p, const ge *q, const ed_ctx *c) {
    const bn_mod *F = &c->F;
    bn a, b, t, u, e, f, g, h;
    bn_sub(&t, &p->Y, &p->X, F);
    bn_sub(&u, &q->Y, &q->X, F);
    bn_mul(&a, &t, &u, F);
    bn_add(&t, &p->Y, &p->X, F);
    bn_add(&u, &q->Y, &q->X, F);
    bn_mul(&b, &t, &u, F);
    bn_mul(&t, &p->T, &q->T, F);
    bn_mul(&t, &t, &c->d2, F); /* C = 2 d T1 T2 */
    bn_mul(&u, &p->Z, &q->Z, F);
    bn_add(&u, &u, &u, F); /* D = 2 Z1 Z2 */
    bn_sub(&e, &b, &a, F);
    bn_sub(&f, &u, &t, F);
    bn_add(&g, &u, &t, F);
    bn_add(&h, &b, &a, F);
    bn_mul(&r->X, &e, &f, F);
    bn_mul(&r->Y, &g, &h, F);
    bn_mul(&r->T, &e, &h, F);
    bn_mul(&r->Z, &f, &g, F);
}

/* RFC 8032 §6 `point_decompress` / `recover_x`: y must be canonical (< p); x^2 = (y^2 - 1) /
 * (d y^2 + 1) must have a root; x = 0 with the sign bit set is refused. Returns 0 on success. */
static int ge_decode(ge *r, const uint8_t s[32], const ed_ctx *c) {
    const bn_mod *F = &c->F;
    uint8_t b[32];
    for (int i = 0; i < 32; i++) b[i] = s[i];
    int sign = b[31] >> 7;
    b[31] &= 0x7f;
    bn y, y2, u, v, x2, x, e, t, one, d;
    bn_from_le(&y, b);
    if (bn_cmp(&y, &F->m) >= 0) return 1;
    bn_to_mont(&y, &y, F);
    one = F->one;
    bn_to_mont(&d, &D25519, F);
    bn_mul(&y2, &y, &y, F);
    bn_sub(&u, &y2, &one, F);
    bn_mul(&v, &y2, &d, F);
    bn_add(&v, &v, &one, F);
    bn_inv(&t, &v, F);
    bn_mul(&x2, &u, &t, F);
    if (bn_is_zero(&x2)) {
        if (sign) return 1;
        bn_set_u32(&x, 0);
    } else {
        /* x = x2^((p+3)/8); (p + 3) / 8 = 2^252 - 2. */
        bn_set_u32(&e, 0);
        e.v[7] = 0x10000000;
        bn_set_u32(&t, 2);
        bn_sub_raw(&e, &e, &t);
        bn_pow(&x, &x2, &e, F);
        bn_mul(&t, &x, &x, F);
        if (bn_cmp(&t, &x2) != 0) {
            bn sq;
            bn_to_mont(&sq, &SQRTM1, F);
            bn_mul(&x, &x, &sq, F);
            bn_mul(&t, &x, &x, F);
            if (bn_cmp(&t, &x2) != 0) return 1;
        }
        bn plain;
        bn_from_mont(&plain, &x, F);
        if ((int)(plain.v[0] & 1) != sign) bn_neg(&x, &x, F);
    }
    r->X = x;
    r->Y = y;
    r->Z = one;
    bn_mul(&r->T, &x, &y, F);
    return 0;
}

/* X1 Z2 = X2 Z1 and Y1 Z2 = Y2 Z1. */
static int ge_eq(const ge *p, const ge *q, const ed_ctx *c) {
    bn a, b;
    bn_mul(&a, &p->X, &q->Z, &c->F);
    bn_mul(&b, &q->X, &p->Z, &c->F);
    if (bn_cmp(&a, &b) != 0) return 0;
    bn_mul(&a, &p->Y, &q->Z, &c->F);
    bn_mul(&b, &q->Y, &p->Z, &c->F);
    return bn_cmp(&a, &b) == 0;
}

uint32_t sbpf_ed25519_verify(const uint8_t pk[32], const uint8_t *msg, uint32_t len,
                             const uint8_t sig[64]) {
    ed_ctx c;
    bn_mod_init(&c.F, &P25519);
    bn_to_mont(&c.d2, &D25519, &c.F);
    bn_add(&c.d2, &c.d2, &c.d2, &c.F);

    ge A, R;
    if (ge_decode(&A, pk, &c)) return 1;
    if (ge_decode(&R, sig, &c)) return 1;
    bn S;
    bn_from_le(&S, sig + 32);
    if (bn_cmp(&S, &L25519) >= 0) return 1;

    /* k = SHA-512(R || A || M) mod L. */
    uint8_t hash[64];
    sha512_ctx h;
    sha512_init(&h);
    sha512_update(&h, sig, 32);
    sha512_update(&h, pk, 32);
    sha512_update(&h, msg, len);
    sha512_finish(&h, hash);
    bn_mod Lm;
    bn_mod_init(&Lm, &L25519);
    bn k;
    bn_reduce512_le(&k, hash, &Lm);

    /* Q = [S]B + [k](-A), one doubling per bit, adding B, -A or B - A. */
    ge B, nA, BnA, Q;
    bn_to_mont(&B.X, &BX, &c.F);
    bn_to_mont(&B.Y, &BY, &c.F);
    B.Z = c.F.one;
    bn_mul(&B.T, &B.X, &B.Y, &c.F);
    nA = A;
    bn_neg(&nA.X, &A.X, &c.F);
    bn_neg(&nA.T, &A.T, &c.F);
    ge_add(&BnA, &B, &nA, &c);
    bn_set_u32(&Q.X, 0);
    Q.Y = c.F.one;
    Q.Z = c.F.one;
    bn_set_u32(&Q.T, 0);
    for (int i = 255; i >= 0; i--) {
        ge_add(&Q, &Q, &Q, &c);
        int sb = bn_bit(&S, i), kb = bn_bit(&k, i);
        if (sb && kb) ge_add(&Q, &Q, &BnA, &c);
        else if (sb) ge_add(&Q, &Q, &B, &c);
        else if (kb) ge_add(&Q, &Q, &nA, &c);
    }
    return ge_eq(&Q, &R, &c) ? 0 : 1;
}

/* The syscall shape: public key, message, signature translated in that order. */
uint64_t sbpf_sys_ed25519_verify(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r5;
    const uint8_t *pk = sbpf_tr_ro(r1, 32);
    if (r3 > 0xffffffffull) sbpf_trap(SBPF_HALT_ACCESS_VIOLATION, r3);
    const uint8_t *msg = sbpf_tr_ro(r2, r3);
    const uint8_t *sig = sbpf_tr_ro(r4, 64);
    return sbpf_ed25519_verify(pk, msg, (uint32_t)r3, sig);
}
