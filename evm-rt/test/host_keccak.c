/* A real Keccak-256 for the host suite (the original Keccak padding, 0x01, as the EVM's KECCAK256
 * and `evm-core`'s `keccak256` use): the stub `evm_keccak256` in mem_test.c hands its input here
 * while `t_real_keccak` is set, so ecrecover's address (precompiles_test.c, call_test.c) is the
 * real one. Keccak-f[1600] from the reference description (keccak.team), 64-bit lanes. */
#include <stdint.h>
#include <string.h>

int t_real_keccak;

static const uint64_t RC[24] = {
    0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808aull, 0x8000000080008000ull,
    0x000000000000808bull, 0x0000000080000001ull, 0x8000000080008081ull, 0x8000000000008009ull,
    0x000000000000008aull, 0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000aull,
    0x000000008000808bull, 0x800000000000008bull, 0x8000000000008089ull, 0x8000000000008003ull,
    0x8000000000008002ull, 0x8000000000000080ull, 0x000000000000800aull, 0x800000008000000aull,
    0x8000000080008081ull, 0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull};
static const int ROT[25] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
                            25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};

static uint64_t rol(uint64_t x, int n) { return n ? (x << n) | (x >> (64 - n)) : x; }

static void keccak_f(uint64_t a[25]) {
    for (int r = 0; r < 24; r++) {
        uint64_t c[5], d[5], b[25];
        for (int x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (int x = 0; x < 5; x++) d[x] = c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1);
        for (int i = 0; i < 25; i++) a[i] ^= d[i % 5];
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rol(a[x + 5 * y], ROT[x + 5 * y]);
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        a[0] ^= RC[r];
    }
}

void t_keccak256(const uint8_t *p, uint32_t n, uint8_t out[32]) {
    uint64_t a[25];
    memset(a, 0, sizeof a);
    uint8_t block[136];
    for (;;) {
        uint32_t take = n < 136 ? n : 136;
        memset(block, 0, sizeof block);
        memcpy(block, p, take);
        if (take < 136) {
            block[take] ^= 0x01;
            block[135] ^= 0x80;
        }
        for (int i = 0; i < 17; i++) {
            uint64_t w = 0;
            for (int j = 0; j < 8; j++) w |= (uint64_t)block[8 * i + j] << (8 * j);
            a[i] ^= w;
        }
        keccak_f(a);
        if (take < 136) break;
        p += 136;
        n -= 136;
    }
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(a[i / 8] >> (8 * (i % 8)));
}
