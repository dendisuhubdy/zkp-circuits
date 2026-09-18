/* The u256 library against (1) the interpreter's own answers (`u256_vectors.h`, generated from
 * `evm_core::u256::U256` by research/tests/evm_rt.rs), every vector also re-run with the result
 * aliasing each operand; and (2) hand-derived cases for the brief's edges, computed here
 * independently of both implementations. */
#include <string.h>
#include "test.h"
#include "u256_vectors.h"

typedef void (*bin_fn)(u256 *, const u256 *, const u256 *);

static bin_fn binary_op(unsigned op) {
    switch (op) {
    case V_ADD: return u256_add;
    case V_SUB: return u256_sub;
    case V_MUL: return u256_mul;
    case V_DIV: return u256_div;
    case V_MOD: return u256_mod;
    case V_SDIV: return u256_sdiv;
    case V_SMOD: return u256_smod;
    case V_EXP: return u256_exp;
    case V_SIGNEXTEND: return u256_signextend;
    case V_LT: return u256_lt;
    case V_GT: return u256_gt;
    case V_SLT: return u256_slt;
    case V_SGT: return u256_sgt;
    case V_EQ: return u256_eq;
    case V_AND: return u256_and;
    case V_OR: return u256_or;
    case V_XOR: return u256_xor;
    case V_BYTE: return u256_byte;
    case V_SHL: return u256_shl;
    case V_SHR: return u256_shr;
    case V_SAR: return u256_sar;
    default: return 0;
    }
}

static const char *op_name(unsigned op) {
    static const char *names[] = {"?", "ADD", "SUB", "MUL", "DIV", "MOD", "SDIV", "SMOD", "ADDMOD",
                                  "MULMOD", "EXP", "SIGNEXTEND", "LT", "GT", "SLT", "SGT", "EQ",
                                  "ISZERO", "AND", "OR", "XOR", "NOT", "BYTE", "SHL", "SHR",
                                  "SAR", "BIT_LEN", "BYTE_LEN"};
    return op < sizeof names / sizeof *names ? names[op] : "?";
}

/* Run one vector three ways: into a fresh result, over operand a, over operand b (and c). */
static void run_vector(size_t k) {
    unsigned op = U256_VECTORS[k].op;
    u256 a = t_hex(U256_VALUES[U256_VECTORS[k].a]);
    u256 b = t_hex(U256_VALUES[U256_VECTORS[k].b]);
    u256 c = t_hex(U256_VALUES[U256_VECTORS[k].c]);
    u256 want = t_hex(U256_VECTORS[k].r);
    u256 got[4];
    int n = 0;
    if (op == V_ADDMOD || op == V_MULMOD) {
        void (*f)(u256 *, const u256 *, const u256 *, const u256 *) =
            op == V_ADDMOD ? u256_addmod : u256_mulmod;
        f(&got[n++], &a, &b, &c);
        got[n] = a; f(&got[n], &got[n], &b, &c); n++;
        got[n] = b; f(&got[n], &a, &got[n], &c); n++;
        got[n] = c; f(&got[n], &a, &b, &got[n]); n++;
    } else if (op == V_ISZERO || op == V_NOT) {
        void (*f)(u256 *, const u256 *) = op == V_ISZERO ? u256_iszero : u256_not;
        f(&got[n++], &a);
        got[n] = a; f(&got[n], &got[n]); n++;
    } else if (op == V_BIT_LEN) {
        u256_from_u32(&got[n++], u256_bit_len(&a));
    } else if (op == V_BYTE_LEN) {
        u256_from_u32(&got[n++], u256_byte_len(&a));
    } else {
        bin_fn f = binary_op(op);
        f(&got[n++], &a, &b);
        got[n] = a; f(&got[n], &got[n], &b); n++;
        got[n] = b; f(&got[n], &a, &got[n]); n++;
    }
    for (int i = 0; i < n; i++) {
        if (!t_eq(&got[i], &want)) {
            fprintf(stderr, "vector %zu: %s (form %d)\n", k, op_name(op), i);
            t_print("a", &a); t_print("b", &b); t_print("c", &c);
            t_print("want", &want); t_print("got", &got[i]);
        }
        CHECK(t_eq(&got[i], &want));
    }
}

/* ---- hand-derived cases ---- */

static u256 W(uint32_t v) { u256 r; u256_from_u32(&r, v); return r; }
static u256 MAXV(void) { u256 r; memset(&r, 0xff, sizeof r); return r; }
static u256 MINV(void) { u256 r = W(0); r.l[7] = 0x80000000u; return r; }
static u256 NEG(uint32_t v) { u256 z = W(0), x = W(v), r; u256_sub(&r, &z, &x); return r; }

#define EXPECT2(f, a, b, want)                                                                 \
    do {                                                                                       \
        u256 x_ = (a), y_ = (b), w_ = (want), r_;                                              \
        f(&r_, &x_, &y_);                                                                      \
        if (!t_eq(&r_, &w_)) { t_print(#f " got", &r_); t_print("want", &w_); }                \
        CHECK(t_eq(&r_, &w_));                                                                 \
    } while (0)

static void hand_arithmetic(void) {
    u256 max = MAXV(), min = MINV();
    EXPECT2(u256_add, W(2), W(3), W(5));
    EXPECT2(u256_add, max, W(1), W(0));
    EXPECT2(u256_add, W(0xffffffffu), W(1), t_hex("100000000"));
    EXPECT2(u256_sub, W(0), W(1), max);
    EXPECT2(u256_sub, t_hex("100000000"), W(1), W(0xffffffffu));
    EXPECT2(u256_mul, W(0xffffffffu), W(0xffffffffu), t_hex("fffffffe00000001"));
    EXPECT2(u256_mul, max, max, W(1));
    EXPECT2(u256_mul, t_hex("100000000000000000000000000000000"),
            t_hex("100000000000000000000000000000000"), W(0));
    /* Division by zero is 0 for all four, and for ADDMOD/MULMOD's modulus. */
    EXPECT2(u256_div, W(7), W(0), W(0));
    EXPECT2(u256_mod, W(7), W(0), W(0));
    EXPECT2(u256_sdiv, max, W(0), W(0));
    EXPECT2(u256_smod, max, W(0), W(0));
    EXPECT2(u256_div, W(7), W(2), W(3));
    EXPECT2(u256_mod, W(7), W(2), W(1));
    EXPECT2(u256_div, max, max, W(1));
    EXPECT2(u256_div, W(1), max, W(0));
    /* SDIV truncates toward zero; MIN / -1 = MIN; SMOD takes the dividend's sign. */
    EXPECT2(u256_sdiv, min, max, min);
    EXPECT2(u256_smod, min, max, W(0));
    EXPECT2(u256_sdiv, NEG(7), W(2), NEG(3));
    EXPECT2(u256_sdiv, W(7), NEG(2), NEG(3));
    EXPECT2(u256_sdiv, NEG(7), NEG(2), W(3));
    EXPECT2(u256_smod, NEG(7), W(2), NEG(1));
    EXPECT2(u256_smod, W(7), NEG(2), W(1));
    EXPECT2(u256_sdiv, min, W(1), min);
    {
        u256 r, m = W(0), a = max, b = W(1), seven = W(7), twelve = W(12);
        u256_addmod(&r, &a, &b, &m); CHECK(u256_is_zero(&r));
        u256_mulmod(&r, &a, &a, &m); CHECK(u256_is_zero(&r));
        /* the true 257-bit sum: 2^256 mod 7 = 2 (2^3 = 1 mod 7, 256 = 3·85 + 1); wrapped it is 0 */
        u256_addmod(&r, &a, &b, &seven); CHECK(r.l[0] == 2 && u256_hi_zero(&r));
        /* (2^256 - 1)^2 mod 12: 2^256 = 4 (mod 12), so 3^2 = 9 */
        u256_mulmod(&r, &a, &a, &twelve); CHECK(r.l[0] == 9 && u256_hi_zero(&r));
    }
    EXPECT2(u256_exp, W(2), W(255), min);
    EXPECT2(u256_exp, W(2), W(256), W(0));
    EXPECT2(u256_exp, W(3), W(0), W(1));
    EXPECT2(u256_exp, W(0), W(0), W(1));
    EXPECT2(u256_exp, W(0), W(5), W(0));
    EXPECT2(u256_exp, max, W(3), max);
    EXPECT2(u256_exp, W(3), W(5), W(243));
}

static void hand_compare_bitwise(void) {
    u256 max = MAXV(), min = MINV();
    EXPECT2(u256_lt, W(1), W(2), W(1));
    EXPECT2(u256_lt, max, W(0), W(0));
    EXPECT2(u256_gt, max, W(0), W(1));
    EXPECT2(u256_slt, max, W(0), W(1));   /* -1 < 0 */
    EXPECT2(u256_sgt, W(0), min, W(1));
    EXPECT2(u256_slt, min, max, W(1));
    EXPECT2(u256_sgt, min, min, W(0));
    EXPECT2(u256_eq, max, max, W(1));
    EXPECT2(u256_eq, min, W(0), W(0));
    EXPECT2(u256_and, max, W(0x1234), W(0x1234));
    EXPECT2(u256_or, min, W(1), t_hex("8000000000000000000000000000000000000000000000000000000000000001"));
    EXPECT2(u256_xor, max, max, W(0));
    u256 r, z = W(0);
    u256_not(&r, &z); CHECK(t_eq(&r, &max));
    u256_iszero(&r, &z); CHECK(t_eq(&r, &(u256){{1}}));
    u256_iszero(&r, &min); CHECK(u256_is_zero(&r));
}

static void hand_shifts(void) {
    u256 max = MAXV(), min = MINV(), one = W(1);
    u256 big = t_hex("100000000"); /* 2^32: the low limb is 0, the amount is still >= 256 */
    EXPECT2(u256_shl, one, W(0), one);
    EXPECT2(u256_shl, one, W(255), min);
    EXPECT2(u256_shl, one, W(256), W(0));
    EXPECT2(u256_shl, max, big, W(0));
    EXPECT2(u256_shl, max, W(4), t_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0"));
    EXPECT2(u256_shl, W(0xabcdef01u), W(36), t_hex("abcdef01000000000"));
    EXPECT2(u256_shr, min, W(0), min);
    EXPECT2(u256_shr, min, W(255), one);
    EXPECT2(u256_shr, max, W(256), W(0));
    EXPECT2(u256_shr, max, big, W(0));
    EXPECT2(u256_shr, t_hex("abcdef01000000000"), W(36), W(0xabcdef01u));
    EXPECT2(u256_sar, min, W(0), min);
    EXPECT2(u256_sar, min, W(255), max);
    EXPECT2(u256_sar, min, W(256), max);
    EXPECT2(u256_sar, min, big, max);
    EXPECT2(u256_sar, min, W(4), t_hex("f800000000000000000000000000000000000000000000000000000000000000"));
    EXPECT2(u256_sar, W(0x7f), W(255), W(0));
    EXPECT2(u256_sar, W(0x7f), W(256), W(0));
    EXPECT2(u256_sar, NEG(16), W(4), NEG(1));
}

/* BYTE and SIGNEXTEND at every byte, the expected values built byte by byte here. */
static void hand_bytes(void) {
    uint8_t be[32];
    for (int j = 0; j < 32; j++) be[j] = (uint8_t)(j + 1); /* byte j from the top is j + 1 */
    u256 x, r;
    u256_from_be_bytes(&x, be);
    for (uint32_t i = 0; i < 32; i++) {
        u256 idx = W(i);
        u256_byte(&r, &x, &idx);
        CHECK(r.l[0] == i + 1 && u256_hi_zero(&r));
    }
    u256 idx32 = W(32), big = t_hex("10000000000000000");
    u256_byte(&r, &x, &idx32); CHECK(u256_is_zero(&r));
    u256_byte(&r, &x, &big); CHECK(u256_is_zero(&r));

    /* SIGNEXTEND(b, x): the bytes above byte b (counted from the least significant) become 0xff
     * or 0x00 by bit 7 of byte b; b >= 31 is the identity. */
    const uint8_t fills[3] = {0xa5, 0x5a, 0x80};
    for (int f = 0; f < 3; f++) {
        for (int k = 0; k < 32; k++) be[k] = (uint8_t)(fills[f] ^ (k * 7));
        u256_from_be_bytes(&x, be);
        for (uint32_t b = 0; b < 40; b++) {
            uint8_t want[32];
            memcpy(want, be, 32);
            if (b < 31) {
                int sign = be[31 - b] >> 7;
                for (int k = 0; k < (int)(31 - b); k++) want[k] = sign ? 0xff : 0x00;
            }
            u256 w, bb = W(b);
            u256_from_be_bytes(&w, want);
            u256_signextend(&r, &x, &bb);
            if (!t_eq(&r, &w)) { fprintf(stderr, "signextend b=%u fill=%d\n", b, f); t_print("got", &r); t_print("want", &w); }
            CHECK(t_eq(&r, &w));
        }
        u256 hugeb = MAXV();
        u256_signextend(&r, &x, &hugeb); CHECK(t_eq(&r, &x));
    }
}

static void hand_conversions(void) {
    uint8_t be[32], out[32];
    for (int j = 0; j < 32; j++) be[j] = (uint8_t)(0xf0 ^ j);
    u256 x;
    u256_from_be_bytes(&x, be);
    CHECK(x.l[0] == ((uint32_t)be[28] << 24 | (uint32_t)be[29] << 16 | (uint32_t)be[30] << 8 | be[31]));
    CHECK(x.l[7] == ((uint32_t)be[0] << 24 | (uint32_t)be[1] << 16 | (uint32_t)be[2] << 8 | be[3]));
    u256_to_be_bytes(out, &x);
    CHECK(memcmp(out, be, 32) == 0);
    uint8_t imm[3] = {0x12, 0x34, 0x56};
    u256_from_be_slice(&x, imm, 3); CHECK(x.l[0] == 0x123456 && u256_hi_zero(&x));
    u256_from_be_slice(&x, imm, 0); CHECK(u256_is_zero(&x));
    u256_from_be_slice(&x, be, 32); CHECK(memcmp((u256_to_be_bytes(out, &x), out), be, 32) == 0);
    u256_from_u64(&x, 0x0123456789abcdefull);
    CHECK(x.l[0] == 0x89abcdefu && x.l[1] == 0x01234567u && u256_low_u64(&x) == 0x0123456789abcdefull);
    CHECK(u256_low_u32(&x) == 0x89abcdefu);
    CHECK(u256_sat_u32(&x) == 0xffffffffu);
    u256 small = W(77), max = MAXV(), min = MINV();
    CHECK(u256_sat_u32(&small) == 77 && u256_hi_zero(&small));
    CHECK(!u256_hi_zero(&x));
    CHECK(u256_bit_len(&small) == 7 && u256_byte_len(&small) == 1);
    CHECK(u256_bit_len(&max) == 256 && u256_byte_len(&max) == 32);
    CHECK(u256_bit_len(&min) == 256 && u256_is_neg(&min) && !u256_is_neg(&small));
    u256 z = W(0);
    CHECK(u256_bit_len(&z) == 0 && u256_byte_len(&z) == 0);
    CHECK(u256_lt_p(&small, &max) && !u256_lt_p(&max, &small));
    CHECK(u256_slt_p(&max, &small) && u256_eq_p(&max, &max) && !u256_eq_p(&max, &min));
}

int u256_tests(void) {
    size_t n = sizeof U256_VECTORS / sizeof *U256_VECTORS;
    for (size_t k = 0; k < n; k++) run_vector(k);
    hand_arithmetic();
    hand_compare_bitwise();
    hand_shifts();
    hand_bytes();
    hand_conversions();
    printf("u256: %zu interpreter vectors (each also run aliased), hand cases\n", n);
    return 0;
}
