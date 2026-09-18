/* The precompiles' gas, dispatch, and the four that need no curve: sha256, ripemd160, identity,
 * modexp, blake2f; ecrecover's EVM wrapper over evm_secp256k1.c. See precompiles.h. */
#include "precompiles.h"
#include "evm_rt.h"

#if defined(__riscv) && __riscv_xlen == 32
#include "guest.h"
#endif

static uint64_t words32(uint64_t n) { return (n + 31) / 32; }

static void copy(uint8_t *d, const uint8_t *s, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) d[i] = s[i];
}

static void zero(uint8_t *d, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) d[i] = 0;
}

/* `in` right-padded with zeros to `n` bytes (the EVM reads past a precompile's input as zero). */
static void padded(uint8_t *d, uint32_t n, const uint8_t *in, uint32_t len) {
    uint32_t k = len < n ? len : n;
    copy(d, in, k);
    zero(d + k, n - k);
}

/* ---- 2: SHA-256 (FIPS 180-4) over the 24-word compression ---------------------------------- */

#if defined(__riscv) && __riscv_xlen == 32
/* The coprocessor: `rand_sha256_compress` takes the 24 words' word address (guest.h). */
void evm_sha256_compress(uint32_t w[24]) { rand_sha256_compress(w); }
#endif

static void sha_block(uint32_t w[24], const uint8_t *b) {
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)b[4 * i] << 24 | (uint32_t)b[4 * i + 1] << 16 | (uint32_t)b[4 * i + 2] << 8 |
               b[4 * i + 3];
    evm_sha256_compress(w);
}

void evm_sha256(const uint8_t *in, uint32_t len, uint8_t out[32]) {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint32_t w[24] __attribute__((aligned(4)));
    for (int i = 0; i < 8; i++) w[16 + i] = iv[i];
    uint32_t off = 0;
    for (; off + 64 <= len; off += 64) sha_block(w, in + off);
    uint8_t last[128];
    uint32_t rest = len - off;
    copy(last, in + off, rest);
    zero(last + rest, 128 - rest);
    last[rest] = 0x80;
    uint32_t n = rest < 56 ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) last[n - 1 - i] = (uint8_t)(bits >> (8 * i));
    sha_block(w, last);
    if (n == 128) sha_block(w, last + 64);
    for (int i = 0; i < 8; i++) {
        uint32_t v = w[16 + i];
        out[4 * i] = (uint8_t)(v >> 24), out[4 * i + 1] = (uint8_t)(v >> 16);
        out[4 * i + 2] = (uint8_t)(v >> 8), out[4 * i + 3] = (uint8_t)v;
    }
}

/* ---- 3: RIPEMD-160 (Dobbertin, Bosselaers, Preneel; the reference description) -------------- */

static uint32_t rol32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static uint32_t rmd_f(int j, uint32_t x, uint32_t y, uint32_t z) {
    switch (j / 16) {
    case 0: return x ^ y ^ z;
    case 1: return (x & y) | (~x & z);
    case 2: return (x | ~y) ^ z;
    case 3: return (x & z) | (y & ~z);
    default: return x ^ (y | ~z);
    }
}

static const uint8_t RMD_R[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5,
    2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4,
    13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};
static const uint8_t RMD_RP[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12,
    4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5,
    12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};
static const uint8_t RMD_S[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9,
    11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9,
    8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};
static const uint8_t RMD_SP[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7,
    6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6,
    14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};
static const uint32_t RMD_K[5] = {0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e};
static const uint32_t RMD_KP[5] = {0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000};

static void rmd_block(uint32_t h[5], const uint8_t *b) {
    uint32_t x[16];
    for (int i = 0; i < 16; i++)
        x[i] = (uint32_t)b[4 * i] | (uint32_t)b[4 * i + 1] << 8 | (uint32_t)b[4 * i + 2] << 16 |
               (uint32_t)b[4 * i + 3] << 24;
    uint32_t al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
    uint32_t ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];
    for (int j = 0; j < 80; j++) {
        uint32_t t = rol32(al + rmd_f(j, bl, cl, dl) + x[RMD_R[j]] + RMD_K[j / 16], RMD_S[j]) + el;
        al = el, el = dl, dl = rol32(cl, 10), cl = bl, bl = t;
        t = rol32(ar + rmd_f(79 - j, br, cr, dr) + x[RMD_RP[j]] + RMD_KP[j / 16], RMD_SP[j]) + er;
        ar = er, er = dr, dr = rol32(cr, 10), cr = br, br = t;
    }
    uint32_t t = h[1] + cl + dr;
    h[1] = h[2] + dl + er;
    h[2] = h[3] + el + ar;
    h[3] = h[4] + al + br;
    h[4] = h[0] + bl + cr;
    h[0] = t;
}

void evm_ripemd160(const uint8_t *in, uint32_t len, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
    uint32_t off = 0;
    for (; off + 64 <= len; off += 64) rmd_block(h, in + off);
    uint8_t last[128];
    uint32_t rest = len - off;
    copy(last, in + off, rest);
    zero(last + rest, 128 - rest);
    last[rest] = 0x80;
    uint32_t n = rest < 56 ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) last[n - 8 + i] = (uint8_t)(bits >> (8 * i)); /* little-endian */
    rmd_block(h, last);
    if (n == 128) rmd_block(h, last + 64);
    for (int i = 0; i < 20; i++) out[i] = (uint8_t)(h[i / 4] >> (8 * (i % 4)));
}

/* ---- 9: BLAKE2b's F (RFC 7693 section 3.2, EIP-152) --------------------------------------- */

static const uint64_t B2_IV[8] = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull,
                                  0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
                                  0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
static const uint8_t B2_SIGMA[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

static uint64_t ror64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

#define B2_G(a, b, c, d, x, y)                                                                     \
    do {                                                                                           \
        v[a] = v[a] + v[b] + (x);                                                                  \
        v[d] = ror64(v[d] ^ v[a], 32);                                                             \
        v[c] = v[c] + v[d];                                                                        \
        v[b] = ror64(v[b] ^ v[c], 24);                                                             \
        v[a] = v[a] + v[b] + (y);                                                                  \
        v[d] = ror64(v[d] ^ v[a], 16);                                                             \
        v[c] = v[c] + v[d];                                                                        \
        v[b] = ror64(v[b] ^ v[c], 63);                                                             \
    } while (0)

void evm_blake2f(uint32_t rounds, uint64_t h[8], const uint64_t m[16], const uint64_t t[2], int final) {
    uint64_t v[16];
    for (int i = 0; i < 8; i++) v[i] = h[i], v[8 + i] = B2_IV[i];
    v[12] ^= t[0];
    v[13] ^= t[1];
    if (final) v[14] = ~v[14];
    for (uint32_t r = 0; r < rounds; r++) {
        const uint8_t *s = B2_SIGMA[r % 10];
        B2_G(0, 4, 8, 12, m[s[0]], m[s[1]]);
        B2_G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        B2_G(2, 6, 10, 14, m[s[4]], m[s[5]]);
        B2_G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        B2_G(0, 5, 10, 15, m[s[8]], m[s[9]]);
        B2_G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        B2_G(2, 7, 8, 13, m[s[12]], m[s[13]]);
        B2_G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[8 + i];
}

static uint64_t le64(const uint8_t *p) {
    uint64_t x = 0;
    for (int i = 7; i >= 0; i--) x = x << 8 | p[i];
    return x;
}

/* EIP-152: exactly 213 bytes — rounds (4, big-endian), h (64), m (128), t (16), f (1, 0 or 1). */
static uint32_t blake2f(const uint8_t *in, uint32_t len, uint8_t *out, uint32_t *out_len) {
    if (len != 213 || in[212] > 1) return PC_FAIL;
    uint32_t rounds = (uint32_t)in[0] << 24 | (uint32_t)in[1] << 16 | (uint32_t)in[2] << 8 | in[3];
    uint64_t h[8], m[16], t[2];
    for (int i = 0; i < 8; i++) h[i] = le64(in + 4 + 8 * i);
    for (int i = 0; i < 16; i++) m[i] = le64(in + 68 + 8 * i);
    t[0] = le64(in + 196);
    t[1] = le64(in + 204);
    evm_blake2f(rounds, h, m, t, in[212]);
    for (int i = 0; i < 64; i++) out[i] = (uint8_t)(h[i / 8] >> (8 * (i % 8)));
    *out_len = 64;
    return PC_OK;
}

/* ---- 5: modexp (EIP-198; gas EIP-2565) ---------------------------------------------------------
 * Numbers are little-endian arrays of 32-bit limbs, at most MX limbs (PC_MODEXP_MAX_BYTES). The
 * product of two residues is reduced by Knuth's algorithm D (TAOCP 4.3.1) against the modulus
 * normalised once; the exponent is read bit by bit from the input, most significant first. */

#define MX (PC_MODEXP_MAX_BYTES / 4)

/* The input's byte at `off` (a u64: offsets reach 96 + 2^32 + 2^32), zero past its end. */
static uint8_t in_byte(const uint8_t *in, uint32_t len, uint64_t off) { return off < len ? in[off] : 0; }

/* One of the three 32-byte length words as a u64, UINT64_MAX when it does not fit one (the gas
 * is then UINT64_MAX too, and the cap is exceeded). */
static uint64_t len_word(const uint8_t *in, uint32_t len, uint32_t at) {
    uint64_t v = 0;
    for (uint32_t i = 0; i < 32; i++) {
        uint8_t b = in_byte(in, len, at + i);
        if (i < 24 && b) return UINT64_MAX;
        if (i >= 24) v = v << 8 | b;
    }
    return v;
}

/* The big-endian bytes [off, off + n) of the input (zero-padded) into `r`'s `nl` limbs. */
static void mx_load(uint32_t *r, uint32_t nl, const uint8_t *in, uint32_t len, uint64_t off, uint32_t n) {
    for (uint32_t i = 0; i < nl; i++) r[i] = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t k = n - 1 - i; /* the byte's significance */
        r[k / 4] |= (uint32_t)in_byte(in, len, off + i) << (8 * (k % 4));
    }
}

/* Significant limbs of `a` (0 for zero). */
static uint32_t mx_top(const uint32_t *a, uint32_t n) {
    while (n && a[n - 1] == 0) n--;
    return n;
}

/* r (n + m limbs) = a (n limbs) * b (m limbs). */
static void mx_mul(uint32_t *r, const uint32_t *a, uint32_t n, const uint32_t *b, uint32_t m) {
    for (uint32_t i = 0; i < n + m; i++) r[i] = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t c = 0;
        for (uint32_t j = 0; j < m; j++) {
            c += (uint64_t)a[i] * b[j] + r[i + j];
            r[i + j] = (uint32_t)c;
            c >>= 32;
        }
        r[i + m] = (uint32_t)c;
    }
}

typedef struct {
    uint32_t vn[MX]; /* the modulus shifted left by s: its top limb has the high bit set */
    uint32_t n;      /* its significant limbs, >= 1 */
    int s;
} mx_mod;

/* u (un limbs, un <= 2 MX, destroyed) mod the modulus, into r (M->n limbs). */
static void mx_rem(uint32_t *r, uint32_t *u, uint32_t un, const mx_mod *M) {
    static uint32_t w[2 * MX + 1];
    uint32_t n = M->n;
    const uint32_t *vn = M->vn;
    int s = M->s;
    if (un < n) {
        for (uint32_t i = 0; i < n; i++) r[i] = i < un ? u[i] : 0;
        return;
    }
    if (n == 1) {
        /* A one-limb divisor: the remainder by long division, 64 bits by 32. */
        uint32_t d = vn[0] >> s;
        uint64_t rem = 0;
        for (uint32_t i = un; i-- > 0;) rem = ((rem << 32) | u[i]) % d;
        r[0] = (uint32_t)rem;
        return;
    }
    /* w = u << s, one limb longer. */
    w[un] = s ? u[un - 1] >> (32 - s) : 0;
    for (uint32_t i = un - 1; i > 0; i--) w[i] = s ? (u[i] << s) | (u[i - 1] >> (32 - s)) : u[i];
    w[0] = u[0] << s;
    for (uint32_t j = un - n + 1; j-- > 0;) {
        uint64_t num = (uint64_t)w[j + n] << 32 | w[j + n - 1];
        uint64_t qhat = num / vn[n - 1];
        uint64_t rhat = num % vn[n - 1];
        while (qhat >> 32 || qhat * vn[n - 2] > (rhat << 32 | w[j + n - 2])) {
            qhat--;
            rhat += vn[n - 1];
            if (rhat >> 32) break;
        }
        /* w[j .. j + n] -= qhat * vn */
        uint64_t borrow = 0, carry = 0;
        for (uint32_t i = 0; i < n; i++) {
            uint64_t p = qhat * vn[i] + carry;
            carry = p >> 32;
            uint64_t t = (uint64_t)w[i + j] - (uint32_t)p - borrow;
            w[i + j] = (uint32_t)t;
            borrow = (t >> 32) & 1;
        }
        uint64_t t = (uint64_t)w[j + n] - carry - borrow;
        w[j + n] = (uint32_t)t;
        if (t >> 63) {
            /* Overshot by one: add the divisor back. */
            uint64_t c = 0;
            for (uint32_t i = 0; i < n; i++) {
                c += (uint64_t)w[i + j] + vn[i];
                w[i + j] = (uint32_t)c;
                c >>= 32;
            }
            w[j + n] += (uint32_t)c;
        }
    }
    for (uint32_t i = 0; i < n; i++) r[i] = s ? (w[i] >> s) | (w[i + 1] << (32 - s)) : w[i];
}

static uint32_t mx_base[MX], mx_modv[MX], mx_acc[MX], mx_prod[2 * MX];
static mx_mod mx_M;

/* acc = acc * b mod M (acc and b M->n limbs). */
static void mx_mulmod(uint32_t *acc, const uint32_t *b) {
    uint32_t n = mx_M.n;
    mx_mul(mx_prod, acc, n, b, n);
    mx_rem(acc, mx_prod, 2 * n, &mx_M);
}

/* floor(a b / 3), or UINT64_MAX when that does not fit a u64 (go-ethereum's big.Int rule). */
static uint64_t mul_div3_sat(uint64_t a, uint64_t b) {
    /* The 128-bit product as four 32-bit limbs, then a long division by 3. */
    uint32_t x[2] = {(uint32_t)a, (uint32_t)(a >> 32)}, y[2] = {(uint32_t)b, (uint32_t)(b >> 32)};
    uint32_t p[4] = {0, 0, 0, 0};
    for (int i = 0; i < 2; i++) {
        uint64_t c = 0;
        for (int j = 0; j < 2; j++) {
            c += (uint64_t)x[i] * y[j] + p[i + j];
            p[i + j] = (uint32_t)c;
            c >>= 32;
        }
        p[i + 2] = (uint32_t)c;
    }
    uint32_t q[4];
    uint64_t r = 0;
    for (int i = 3; i >= 0; i--) {
        uint64_t cur = r << 32 | p[i];
        q[i] = (uint32_t)(cur / 3);
        r = cur % 3;
    }
    if (q[3] | q[2]) return UINT64_MAX;
    return (uint64_t)q[1] << 32 | q[0];
}

static uint64_t modexp_gas(const uint8_t *in, uint32_t len) {
    uint64_t bl = len_word(in, len, 0), el = len_word(in, len, 32), ml = len_word(in, len, 64);
    /* The exponent's head: its first min(el, 32) bytes, as a number; msb = its bit length - 1,
     * 0 when it is zero (go-ethereum, the execution specs). Past the input it is zero. */
    uint64_t head_len = el < 32 ? el : 32;
    uint32_t msb = 0;
    if (bl < len) {
        uint64_t base_end = 96 + bl;
        for (uint64_t i = 0; i < head_len; i++) {
            uint8_t b = in_byte(in, len, base_end + i);
            if (b) {
                uint32_t bits = 0;
                while (b >> bits) bits++;
                msb = (uint32_t)(8 * (head_len - 1 - i)) + bits - 1;
                break;
            }
        }
    }
    uint64_t iter;
    if (el <= 32) iter = msb;
    /* Where 8 (el - 32) + msb would not fit a u64, iter is clamped to UINT64_MAX. go-ethereum
     * computes the exact big-integer value, so the two can differ - but only where both are at
     * least floor((2^64 - 1) / 3) (words >= 1 here: words = 0 gives the 200 minimum in both),
     * which no call can pay: the gas limit is one u32 word of the input (abi.rs), so the gas
     * passed is below 2^32 and the call fails the same way, consuming the same gas passed. */
    else if (el - 32 > (UINT64_MAX - 255) / 8) iter = UINT64_MAX;
    else iter = 8 * (el - 32) + msb;
    if (iter < 1) iter = 1;
    uint64_t maxl = bl > ml ? bl : ml;
    uint64_t words = maxl / 8 + ((maxl & 7) != 0);
    /* words >= 2^32: mc = words^2 >= 2^64 does not fit, and the exact gas is at least
     * floor(2^64 / 3) (iter >= 1). Saturating it to UINT64_MAX differs from go-ethereum's exact
     * value, but, as above, only at a level no call can pay (the gas passed is below 2^32). */
    if (words > 0xffffffffull) return UINT64_MAX;
    uint64_t g = mul_div3_sat(words * words, iter);
    return g < PC_MODEXP_MIN ? PC_MODEXP_MIN : g;
}

static uint32_t modexp(const uint8_t *in, uint32_t len, uint8_t *out, uint32_t *out_len) {
    uint64_t bl = len_word(in, len, 0), el = len_word(in, len, 32), ml = len_word(in, len, 64);
    *out_len = 0;
    if (bl == 0 && ml == 0) return PC_OK;
    /* The base and the modulus are held in MX limbs; the exponent is not held at all (it is read
     * bit by bit from the input below), so its length is not capped. */
    if (bl > PC_MODEXP_MAX_BYTES || ml > PC_MODEXP_MAX_BYTES) return PC_TOO_BIG;
    uint32_t nb = (uint32_t)bl, nm = (uint32_t)ml;
    uint32_t mlimbs = (nm + 3) / 4, blimbs = (nb + 3) / 4;
    /* The modulus starts after the exponent. An exponent reaching past the input puts it wholly in
     * the zero padding: offset `len` reads the same, and cannot overflow. */
    uint64_t moff = el >= len ? (uint64_t)len : 96 + (uint64_t)nb + el;
    mx_load(mx_modv, MX, in, len, moff, nm);
    zero(out, nm);
    *out_len = nm;
    uint32_t n = mx_top(mx_modv, mlimbs ? mlimbs : 1);
    if (n == 0) return PC_OK; /* mod 0: zeros */
    /* Normalise the modulus. */
    int s = 0;
    while (!(mx_modv[n - 1] << s & 0x80000000u)) s++;
    mx_M.n = n;
    mx_M.s = s;
    for (uint32_t i = n; i-- > 0;)
        mx_M.vn[i] = s && i ? (mx_modv[i] << s) | (mx_modv[i - 1] >> (32 - s)) : mx_modv[i] << s;
    /* base mod M */
    mx_load(mx_prod, 2 * MX, in, len, 96, nb);
    mx_rem(mx_base, mx_prod, blimbs > n ? blimbs : n, &mx_M);
    /* acc = 1 mod M */
    for (uint32_t i = 0; i < 2 * MX; i++) mx_prod[i] = 0;
    mx_prod[0] = 1;
    mx_rem(mx_acc, mx_prod, n, &mx_M);
    uint64_t e0 = 96 + (uint64_t)nb;
    int started = 0;
    /* el * 8 steps: RequiredGas is at least 8 (el - 32) / 3, so an affordable call (gas below 2^32)
     * has el below 2^31 and this loop is bounded by the gas paid. */
    for (uint64_t i = 0; i < el; i++) {
        uint8_t b = in_byte(in, len, e0 + i);
        for (int k = 7; k >= 0; k--) {
            if (started) mx_mulmod(mx_acc, mx_acc);
            if (b >> k & 1) {
                mx_mulmod(mx_acc, mx_base);
                started = 1;
            }
        }
    }
    /* Big-endian, left-padded to the modulus length. */
    for (uint32_t k = 0; k < nm; k++) {
        uint32_t limb = k / 4;
        out[nm - 1 - k] = limb < n ? (uint8_t)(mx_acc[limb] >> (8 * (k % 4))) : 0;
    }
    return PC_OK;
}

/* ---- 1: ecrecover (Yellow Paper appendix E; go-ethereum's ecrecover.Run) --------------------- */

static uint32_t ecrecover(const uint8_t *in, uint32_t len, uint8_t *out, uint32_t *out_len) {
    uint8_t buf[128];
    padded(buf, 128, in, len);
    *out_len = 0;
    /* v: the whole word must be 27 or 28. r and s: 0 < r, s < n (evm_secp256k1_recover checks). */
    for (int i = 32; i < 63; i++)
        if (buf[i]) return PC_OK;
    if (buf[63] != 27 && buf[63] != 28) return PC_OK;
    uint8_t key[64];
    if (evm_secp256k1_recover(buf, buf[63] - 27u, buf + 64, key) != 0) return PC_OK;
    uint8_t h[32];
    evm_keccak256(evm_host, key, 64, h);
    zero(out, 12);
    copy(out + 12, h + 12, 20);
    *out_len = 32;
    return PC_OK;
}

/* ---- gas and dispatch ------------------------------------------------------------------------ */

uint64_t evm_precompile_gas(uint32_t addr, const uint8_t *in, uint32_t len) {
    switch (addr) {
    case 1: return PC_ECRECOVER_GAS;
    case 2: return PC_SHA256_BASE + PC_SHA256_WORD * words32(len);
    case 3: return PC_RIPEMD160_BASE + PC_RIPEMD160_WORD * words32(len);
    case 4: return PC_IDENTITY_BASE + PC_IDENTITY_WORD * words32(len);
    case 5: return modexp_gas(in, len);
    case 6: return PC_BN256_ADD_GAS;
    case 7: return PC_BN256_MUL_GAS;
    case 8: return PC_BN256_PAIRING_BASE + (uint64_t)PC_BN256_PAIRING_PAIR * (len / 192);
    case 9:
        /* go-ethereum: a wrong length costs 0 (and then fails). */
        if (len != 213) return 0;
        return (uint64_t)PC_BLAKE2F_ROUND *
               ((uint32_t)in[0] << 24 | (uint32_t)in[1] << 16 | (uint32_t)in[2] << 8 | in[3]);
    default: return 0;
    }
}

uint32_t evm_precompile_run(uint32_t addr, const uint8_t *in, uint32_t len, uint8_t *out,
                            uint32_t *out_len) {
    *out_len = 0;
    switch (addr) {
    case 1: return ecrecover(in, len, out, out_len);
    case 2:
        evm_sha256(in, len, out);
        *out_len = 32;
        return PC_OK;
    case 3:
        zero(out, 12);
        evm_ripemd160(in, len, out + 12);
        *out_len = 32;
        return PC_OK;
    case 4:
        copy(out, in, len);
        *out_len = len;
        return PC_OK;
    case 5: return modexp(in, len, out, out_len);
    case 6: {
        uint8_t buf[128];
        padded(buf, 128, in, len);
        if (evm_bn256_add(buf, out) != PC_OK) return PC_FAIL;
        *out_len = 64;
        return PC_OK;
    }
    case 7: {
        uint8_t buf[96];
        padded(buf, 96, in, len);
        if (evm_bn256_mul(buf, out) != PC_OK) return PC_FAIL;
        *out_len = 64;
        return PC_OK;
    }
    case 8: {
        if (len % 192 != 0) return PC_FAIL;
        uint32_t one = 0;
        if (evm_bn256_pairing(in, len / 192, &one) != PC_OK) return PC_FAIL;
        zero(out, 32);
        out[31] = (uint8_t)one;
        *out_len = 32;
        return PC_OK;
    }
    case 9: return blake2f(in, len, out, out_len);
    default: return PC_FAIL;
    }
}
