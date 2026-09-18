/* The host's half of sbpf-rt: the two things the runtime takes from the machine on RV32 and a host
 * build (these tests, `sbpf2rv`'s differential fuzzing) has to supply itself.
 *
 *  * `sbpf_rt_enter`/`sbpf_rt_unwind` over libc's setjmp — the runtime is freestanding and carries
 *    its own RV32 pair; the contract is the same: run `entry`, a normal return is EXIT with r0, any
 *    `sbpf_trap` comes back here with its code.
 *  * `sbpf_sha256_compress`, FIPS 180-4's compression function in portable C, standing in for the
 *    SHA-256 coprocessor `rand_sha256_compress` reaches (the same 24-word layout).
 */
#include <setjmp.h>
#include "../sbpf_rt.h"

#if !(defined(__riscv) && __riscv_xlen == 32)
static jmp_buf host_jb;

uint32_t sbpf_rt_enter(sbpf_fn entry, uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4,
                       uint64_t r5, uint64_t *r0) {
    sbpf_halt_code = SBPF_HALT_EXIT;
    sbpf_halt_arg = 0;
    if (setjmp(host_jb) == 0) {
        uint64_t v = entry(r1, r2, r3, r4, r5);
        *r0 = v;
        return SBPF_HALT_EXIT;
    }
    return sbpf_halt_code;
}

void sbpf_rt_unwind(void) { longjmp(host_jb, 1); }

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void sbpf_sha256_compress(uint32_t w24[24]) {
    uint32_t w[64], s[8];
    for (int i = 0; i < 16; i++) w[i] = w24[i];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    for (int i = 0; i < 8; i++) s[i] = w24[16 + i];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ror(s[4], 6) ^ ror(s[4], 11) ^ ror(s[4], 25);
        uint32_t ch = (s[4] & s[5]) ^ (~s[4] & s[6]);
        uint32_t t1 = s[7] + S1 + ch + K[i] + w[i];
        uint32_t S0 = ror(s[0], 2) ^ ror(s[0], 13) ^ ror(s[0], 22);
        uint32_t maj = (s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]);
        uint32_t t2 = S0 + maj;
        s[7] = s[6]; s[6] = s[5]; s[5] = s[4]; s[4] = s[3] + t1;
        s[3] = s[2]; s[2] = s[1]; s[1] = s[0]; s[0] = t1 + t2;
    }
    for (int i = 0; i < 8; i++) w24[16 + i] += s[i];
}
#endif
