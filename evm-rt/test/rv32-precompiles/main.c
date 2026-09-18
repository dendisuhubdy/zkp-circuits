/* The precompiles on the machine: a C guest (`rand-guest build --lang c evm-rt/test/rv32-precompiles
 * --max-words 65535`) that includes evm-rt's sources, so the RV32 paths the host suite cannot reach
 * run on the emulator — sha256 over the SHA-256 coprocessor (`rand_sha256_compress`), ecrecover's
 * Keccak over the Keccak coprocessor — and each precompile's cycles can be counted.
 * `rand-guest/tests/evm_precompiles.rs` drives it with known answers from
 * test/precompile_vectors.h.
 *
 * Input words (bytes packed four to a word, little-endian, the last word zero-padded):
 *   mode 1, a known answer: [1, addr, in_len, in..., want_ok, want_len, want...]
 *     out[0] the run's PC_* code   out[1] the output length   out[2] 1 if the result is the
 *     answer (PC_OK and the bytes when want_ok, PC_FAIL otherwise)   out[3], out[4] RequiredGas,
 *     low and high word   out[5..7] the output's first 12 bytes, big-endian words
 *   mode 2, an operation n times, for the cycle estimates of the precompiles past the largest
 *     tier: [2, op, n] with op 0 nothing, 1 bn_mul, 2 bn_add, 3 bn_sub (mod the alt_bn128 p,
 *     Montgomery), 4 the F_p^12 multiplication; out[0] = n.
 */
#include "guest.h"
#include "../../evm_rt.h"
#include "../../precompiles.h"
#include "../../u256.c"
#include "../../evm_rt.c"
#include "../../precompiles.c"
#include "../../evm_bn.c"
#include "../../evm_secp256k1.c"
#include "../../evm_bn254.c"

/* Keccak-256 over the machine's Keccak-f permutation — evm-core's `keccak256`, in C. */
void evm_keccak256(void *h, const uint8_t *p, uint32_t n, uint8_t *o) {
    (void)h;
    static uint32_t st[50] __attribute__((aligned(4)));
    uint8_t block[136];
    for (int i = 0; i < 50; i++) st[i] = 0;
    for (;;) {
        uint32_t take = n < 136 ? n : 136;
        for (uint32_t i = 0; i < 136; i++) block[i] = i < take ? p[i] : 0;
        if (take < 136) {
            block[take] ^= 0x01;
            block[135] ^= 0x80;
        }
        for (int i = 0; i < 34; i++)
            st[i] ^= (uint32_t)block[4 * i] | (uint32_t)block[4 * i + 1] << 8 |
                     (uint32_t)block[4 * i + 2] << 16 | (uint32_t)block[4 * i + 3] << 24;
        rand_keccak(st);
        if (take < 136) break;
        p += 136;
        n -= 136;
    }
    for (int i = 0; i < 32; i++) o[i] = (uint8_t)(st[i / 4] >> (8 * (i % 4)));
}
/* Storage is never touched here. */
uint32_t evm_sload(void *t, void *h, const uint32_t *s, uint32_t *o) {
    (void)t, (void)h, (void)s, (void)o;
    return EVM_HALT_NO_WITNESS;
}
uint32_t evm_sstore(void *t, void *h, const uint32_t *s, const uint32_t *v) {
    (void)t, (void)h, (void)s, (void)v;
    return EVM_HALT_NO_WITNESS;
}

static uint32_t idx;
static uint32_t next(void) { return rand_read_input(idx++); }

static void read_bytes(uint8_t *b, uint32_t n) {
    uint32_t w = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (i % 4 == 0) w = next();
        b[i] = (uint8_t)(w >> (8 * (i % 4)));
    }
}

static uint8_t in_buf[4096], want_buf[1024], out_buf[PC_OUT_MAX];

static void kat(void) {
    uint32_t addr = next();
    uint32_t in_len = next();
    read_bytes(in_buf, in_len);
    uint32_t want_ok = next();
    uint32_t want_len = next();
    read_bytes(want_buf, want_len);
    uint64_t gas = evm_precompile_gas(addr, in_buf, in_len);
    uint32_t out_len = 0;
    uint32_t r = evm_precompile_run(addr, in_buf, in_len, out_buf, &out_len);
    uint32_t match;
    if (want_ok) {
        match = r == PC_OK && out_len == want_len;
        for (uint32_t i = 0; match && i < want_len; i++) match = out_buf[i] == want_buf[i];
    } else {
        match = r == PC_FAIL;
    }
    rand_write_output(0, r);
    rand_write_output(1, out_len);
    rand_write_output(2, match);
    rand_write_output(3, (uint32_t)gas);
    rand_write_output(4, (uint32_t)(gas >> 32));
    for (int k = 0; k < 3; k++) {
        uint32_t v = 0;
        for (int j = 0; j < 4; j++) v = v << 8 | (4 * k + j < (int)out_len ? out_buf[4 * k + j] : 0);
        rand_write_output(5 + k, v);
    }
}

static void bench(void) {
    uint32_t op = next(), n = next();
    setup();
    static bn a, b, c;
    static fp12 x, y;
    for (int i = 0; i < 8; i++) a.v[i] = 0x01234567u * (uint32_t)(i + 1), b.v[i] = 0x89abcdefu ^ (uint32_t)i;
    a.v[7] &= 0x0fffffff, b.v[7] &= 0x0fffffff;
    for (int i = 0; i < 12; i++) x.c[i] = a, y.c[i] = b;
    for (uint32_t k = 0; k < n; k++) {
        switch (op) {
        case 1: bn_mul(&c, &a, &b, &F); a = c; break;
        case 2: bn_add(&c, &a, &b, &F); a = c; break;
        case 3: bn_sub(&c, &a, &b, &F); a = c; break;
        case 4: fp12_mul(&x, &x, &y); break;
        default: __asm__ volatile("" ::: "memory"); break;
        }
    }
    rand_write_output(0, n + (a.v[0] & 0) + (x.c[0].v[0] & 0));
}

void main(void) {
    uint32_t mode = next();
    if (mode == 1) kat();
    else bench();
    rand_halt();
}
