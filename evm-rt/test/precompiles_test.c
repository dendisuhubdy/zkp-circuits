/* The nine precompiles against their known answers (precompile_vectors.h: go-ethereum's test data,
 * FIPS 180-2, Bosselaers' RIPEMD-160 suite, and the rejections gen_precompile_vectors.py derives
 * from the EIPs; the source of each is in the vector). For every vector: `evm_precompile_gas` is
 * the vector's gas, and `evm_precompile_run` succeeds with exactly the expected output, or fails
 * when the vector says the input is invalid. Plus the pieces the vectors reach only indirectly:
 * modexp's gas at the u64 edges and its PC_TOO_BIG cap, blake2f's rounds, and sha256's padding
 * at every length around a block. ecrecover hashes the key through `evm_keccak256`, which the
 * host suite makes a real Keccak-256 (test/host_keccak.c) while this file runs. */
#include <stdlib.h>
#include <string.h>
#include "test.h"
#include "../precompiles.h"
#include "precompile_vectors.h"

extern int t_real_keccak;

static uint8_t *unhex(const char *s, uint32_t *n) {
    size_t l = strlen(s);
    *n = (uint32_t)(l / 2);
    uint8_t *b = malloc(*n + 1);
    for (uint32_t i = 0; i < *n; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        b[i] = (uint8_t)v;
    }
    return b;
}

static uint8_t out[PC_OUT_MAX];

static void the_vectors(void) {
    uint32_t per_addr[10] = {0};
    for (size_t k = 0; k < sizeof PC_VECTORS / sizeof *PC_VECTORS; k++) {
        const pc_vector *v = &PC_VECTORS[k];
        uint32_t in_len, want_len;
        uint8_t *in = unhex(v->in, &in_len);
        uint8_t *want = unhex(v->out, &want_len);
        uint64_t gas = evm_precompile_gas(v->addr, in, in_len);
        if (gas != v->gas)
            fprintf(stderr, "  %u %s: gas %llu, want %llu\n", v->addr, v->name,
                    (unsigned long long)gas, v->gas);
        CHECK(gas == v->gas);
        uint32_t out_len = 0xdead;
        uint32_t r = evm_precompile_run(v->addr, in, in_len, out, &out_len);
        int good = v->ok ? (r == PC_OK && out_len == want_len && memcmp(out, want, want_len) == 0)
                         : r == PC_FAIL;
        if (!good) fprintf(stderr, "  %u %s (%s): r %u, out_len %u\n", v->addr, v->name, v->source, r, out_len);
        CHECK(good);
        per_addr[v->addr]++;
        free(in);
        free(want);
    }
    for (int a = 1; a <= 9; a++) CHECK(per_addr[a] >= 4); /* every precompile has vectors */
}

/* sha256 of every length 0..200 against a second padding written here, over the same compression
 * (the vectors fix the compression; this pins the padding at each block boundary). */
static void sha256_every_length(void) {
    static const uint8_t abc_digest[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    uint8_t d[32];
    evm_sha256((const uint8_t *)"abc", 3, d);
    CHECK(memcmp(d, abc_digest, 32) == 0);
    uint8_t msg[200];
    for (int i = 0; i < 200; i++) msg[i] = (uint8_t)(i * 7 + 1);
    for (uint32_t n = 0; n <= 200; n++) {
        /* The reference: whole padded message, block by block. */
        uint8_t pad[320];
        memset(pad, 0, sizeof pad);
        memcpy(pad, msg, n);
        pad[n] = 0x80;
        uint32_t blocks = (n + 9 + 63) / 64;
        uint64_t bits = (uint64_t)n * 8;
        for (int i = 0; i < 8; i++) pad[blocks * 64 - 1 - i] = (uint8_t)(bits >> (8 * i));
        uint32_t w[24] = {0};
        static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
        for (int i = 0; i < 8; i++) w[16 + i] = iv[i];
        for (uint32_t b = 0; b < blocks; b++) {
            for (int i = 0; i < 16; i++) {
                const uint8_t *p = pad + 64 * b + 4 * i;
                w[i] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
            }
            evm_sha256_compress(w);
        }
        uint8_t want[32];
        for (int i = 0; i < 8; i++)
            for (int j = 0; j < 4; j++) want[4 * i + j] = (uint8_t)(w[16 + i] >> (24 - 8 * j));
        evm_sha256(msg, n, d);
        CHECK(memcmp(d, want, 32) == 0);
    }
}

static void put_word(uint8_t *p, uint64_t v) {
    memset(p, 0, 32);
    for (int i = 0; i < 8; i++) p[31 - i] = (uint8_t)(v >> (8 * i));
}

/* modexp's gas where the vectors do not reach: lengths past u64, a zero exponent head, the
 * saturation; and the runtime's cap. */
static void modexp_edges(void) {
    uint8_t in[96 + 8];
    memset(in, 0, sizeof in);
    /* base length 2^64 (a u256 whose high limbs are set): RequiredGas saturates. */
    in[31 - 8] = 1;
    CHECK(evm_precompile_gas(5, in, 96) == UINT64_MAX);
    /* exponent length 2^40, the others 1: 8 (2^40 - 32) iterations, mc 1: 8 (2^40 - 32) / 3. */
    memset(in, 0, sizeof in);
    in[31] = 1;
    put_word(in + 32, 1ull << 40);
    in[95] = 1;
    CHECK_EQ_U64(evm_precompile_gas(5, in, 96), (8 * ((1ull << 40) - 32)) / 3);
    /* exponent length 33 with a zero head: msb 0, so 8 iterations, max(200, 8/3) = 200. */
    put_word(in + 32, 33);
    CHECK_EQ_U64(evm_precompile_gas(5, in, 96), 200);
    /* mod length 2^32: mc = (2^29)^2 = 2^58, iterations 1: 2^58/3. */
    put_word(in + 32, 1);
    put_word(in + 64, 1ull << 32);
    CHECK_EQ_U64(evm_precompile_gas(5, in, 96), (1ull << 58) / 3);
    /* ... times 2^7 iterations overflows u64: saturates. */
    put_word(in + 32, 32);
    uint8_t in2[96 + 1 + 32];
    memcpy(in2, in, 96);
    in2[96] = 0;
    memset(in2 + 97, 0, 32);
    in2[97] = 0xff; /* exponent head 0xff00..: msb 255 */
    CHECK(evm_precompile_gas(5, in2, sizeof in2) == UINT64_MAX);
    /* The cap: a 1025-byte modulus is PC_TOO_BIG, 1024 runs. */
    static uint8_t big[96 + 1 + 1 + 1025];
    memset(big, 0, sizeof big);
    put_word(big, 1);
    put_word(big + 32, 1);
    put_word(big + 64, 1025);
    big[96] = 3;
    big[97] = 2;
    big[96 + 2 + 1024 - 1] = 7; /* the last byte of a 1024-byte modulus */
    uint32_t n;
    CHECK(evm_precompile_run(5, big, sizeof big, out, &n) == PC_TOO_BIG);
    put_word(big + 64, 1024);
    CHECK(evm_precompile_run(5, big, sizeof big - 1, out, &n) == PC_OK && n == 1024 && out[1023] == 2);
    put_word(big, 1025);
    put_word(big + 64, 1);
    CHECK(evm_precompile_run(5, big, 96, out, &n) == PC_TOO_BIG);
    put_word(big, 1);
    put_word(big + 32, 1025);
    CHECK(evm_precompile_run(5, big, 96, out, &n) == PC_TOO_BIG);
}

/* blake2f: the rounds count is the gas; with zero rounds, t = 0 and f = 0, F is h ^ h ^ IV = IV
 * (RFC 7693's initialisation vector, little-endian), whatever h is. */
static void blake2f_rounds(void) {
    uint8_t in[213];
    memset(in, 0, sizeof in);
    in[0] = 0x01; in[1] = 0x02; in[2] = 0x03; in[3] = 0x04;
    CHECK_EQ_U64(evm_precompile_gas(9, in, 213), 0x01020304);
    in[0] = in[1] = in[2] = 0;
    in[3] = 0;
    for (int i = 0; i < 64; i++) in[4 + i] = (uint8_t)(i + 1);
    uint32_t n;
    static const uint8_t iv0[8] = {0x08, 0xc9, 0xbc, 0xf3, 0x67, 0xe6, 0x09, 0x6a};
    static const uint8_t iv7[8] = {0x79, 0x21, 0x7e, 0x13, 0x19, 0xcd, 0xe0, 0x5b};
    CHECK(evm_precompile_run(9, in, 213, out, &n) == PC_OK && n == 64);
    CHECK(memcmp(out, iv0, 8) == 0 && memcmp(out + 56, iv7, 8) == 0);
    in[212] = 2;
    CHECK(evm_precompile_run(9, in, 213, out, &n) == PC_FAIL);
}

/* Addresses outside 1..9 are not precompiles: no gas, a failure. */
static void outside(void) {
    uint32_t n;
    CHECK(evm_precompile_gas(0, out, 0) == 0 && evm_precompile_gas(10, out, 0) == 0);
    CHECK(evm_precompile_run(0, out, 0, out + 1, &n) == PC_FAIL);
    CHECK(evm_precompile_run(10, out, 0, out + 1, &n) == PC_FAIL);
}

int precompile_tests(void) {
    t_real_keccak = 1;
    the_vectors();
    sha256_every_length();
    modexp_edges();
    blake2f_rounds();
    outside();
    t_real_keccak = 0;
    return 0;
}
