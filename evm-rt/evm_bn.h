/* Copied from sbpf-rt at 4f50932 (sbpf-rt/sbpf_bn.h), renamed with the evm_ prefix; the two copies
 * are to be deduplicated into one shared C directory once feat/sbpf2rv and feat/evm2rv have both
 * merged. Only this comment, the include guard and the "internal to" line differ.
 *
 * 256-bit modular arithmetic for sbpf-rt's software signature checks: eight 32-bit limbs,
 * little-endian, Montgomery multiplication (CIOS) with 64-bit products — the RV32IM `mul`/`mulhu`
 * pair, no 128-bit type, no compiler-runtime call. Generic over any odd modulus below 2^256, which
 * is all four the two curves need (secp256k1's p and n, Curve25519's p and the Ed25519 order L).
 * No tables: a modulus's Montgomery constants are derived from it by `bn_mod_init`. Not constant
 * time (a proof has no timing channel). Internal to evm-rt (ecrecover, the alt_bn128 precompiles). */
#ifndef EVM_BN_H
#define EVM_BN_H
#include <stdint.h>

typedef struct {
    uint32_t v[8];
} bn;

typedef struct {
    bn m;        /* the modulus, odd */
    uint32_t n0; /* -m^-1 mod 2^32 */
    bn r2;       /* R^2 mod m, R = 2^256 */
    bn one;      /* R mod m: 1 in Montgomery form */
} bn_mod;

void bn_mod_init(bn_mod *M, const bn *m);

void bn_from_be(bn *r, const uint8_t b[32]);
void bn_from_le(bn *r, const uint8_t b[32]);
void bn_to_be(uint8_t b[32], const bn *a);
void bn_set_u32(bn *r, uint32_t x);
int bn_cmp(const bn *a, const bn *b); /* -1, 0, 1 */
int bn_is_zero(const bn *a);
int bn_bit(const bn *a, int i);
/* r = a + b as plain 256-bit integers; returns the carry out. */
uint32_t bn_add_raw(bn *r, const bn *a, const bn *b);
/* r = a - b; returns the borrow out. */
uint32_t bn_sub_raw(bn *r, const bn *a, const bn *b);

/* Modular, operands < m (either domain, since + and - do not care). */
void bn_add(bn *r, const bn *a, const bn *b, const bn_mod *M);
void bn_sub(bn *r, const bn *a, const bn *b, const bn_mod *M);
void bn_neg(bn *r, const bn *a, const bn_mod *M);

/* Montgomery: r = a b R^-1 mod m, for a < 2^256 and b < m (or a < m and b < 2^256). */
void bn_mul(bn *r, const bn *a, const bn *b, const bn_mod *M);
void bn_to_mont(bn *r, const bn *a, const bn_mod *M);   /* a < 2^256: r = a R mod m */
void bn_from_mont(bn *r, const bn *a, const bn_mod *M); /* r = a R^-1 mod m, fully reduced */
/* r = a^e (a in Montgomery form, e plain), in Montgomery form. */
void bn_pow(bn *r, const bn *a, const bn *e, const bn_mod *M);
/* r = a^-1 by Fermat (m prime), Montgomery in and out; 0 maps to 0. */
void bn_inv(bn *r, const bn *a, const bn_mod *M);
/* r = the 512-bit little-endian x mod m, plain. */
void bn_reduce512_le(bn *r, const uint8_t x[64], const bn_mod *M);
#endif
