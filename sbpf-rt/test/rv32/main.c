/* sbpf-rt on the machine itself: a C guest (`rand-guest build --lang c sbpf-rt/test/rv32`) that
 * includes the runtime's sources, so the RV32 paths the host suite cannot reach — the hand-written
 * `sbpf_setjmp`/`sbpf_longjmp` and `sol_sha256` on the SHA-256 coprocessor — execute on the
 * emulator, and so the software signature checks can be measured in cycles.
 * `rand-guest/tests/sbpf_rt.rs` builds and runs it. Neither signature check fits the machine's
 * largest tier (2^20 cycles), so they run only in modes 1 and 2, which that test measures with the
 * emulator's own cycle cap raised.
 *
 * Private input word 0 selects what runs (the cycle counts of modes 1 and 2 minus mode 3's are the
 * two checks' costs):
 *   0  the checks below, eight output words:
 *        0  halt codes, 4 bits each: DIV_BY_ZERO 3 (from six frames deep) | ACCESS_VIOLATION 1 |
 *           TRAP 10 | UNKNOWN_SYSCALL 4 | EXIT 0 (low nibble first)         = 0x04a13
 *        1  the access violation's address, low word: input offset 121     = 121
 *        2  s1-s11, pinned here, intact after the unwinds (0xbad if not)   = 0x5a5a1234
 *        3  sol_sha256("abc") through the coprocessor, first word          = 0xba7816bf
 *        4  sol_sha256 of the 56-byte two-block message, first word        = 0x248d6a61
 *        5  memmove up 100 bytes then alloc twice: input[103] | 2nd alloc offset << 8 = 0x863
 *        6  sol_memcmp_ of 5 against 9, the i32 it writes                   = 0xfffffffc
 *        7  the unknown syscall's payload: sol_invoke_signed_c's hash       = 0xa22b9c85
 *   1  one secp256k1 recover (go-ethereum's vector): output 0 the key's first word = 0xe32df428
 *   2  one ed25519 verify (RFC 8032 TEST 1): output 0 the result (valid, 0), output 1 the same
 *      signature with one S bit flipped (invalid, 1)
 *   3  neither: the baseline
 */
#include "guest.h"
#include "../../sbpf_rt.h"
#include "../../sbpf_rt.c"
#include "../../sbpf_bn.c"
#include "../../sbpf_ed25519.c"
#include "../../sbpf_secp256k1.c"

static uint8_t stack_r[SBPF_STACK_BYTES], heap_r[SBPF_HEAP_BYTES], input_r[128];

static void regions(void) {
    for (int i = 0; i < 128; i++) input_r[i] = (uint8_t)i;
    sbpf_r.text = input_r; /* unused here */
    sbpf_r.text_va = SBPF_REGION_PROGRAM;
    sbpf_r.text_len = 0;
    sbpf_r.rodata = input_r;
    sbpf_r.rodata_va = SBPF_REGION_PROGRAM;
    sbpf_r.rodata_len = 0;
    sbpf_r.stack = stack_r;
    sbpf_r.heap = heap_r;
    sbpf_r.input = input_r;
    sbpf_r.input_len = sizeof input_r;
    sbpf_rt_reset();
}

static volatile uint32_t sink;
__attribute__((noinline)) static uint64_t deep(uint64_t n, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
    volatile uint64_t keep = n * 3 + b;
    if (n == 0) {
        /* Dirty every callee-saved register but s0 (saved by this frame's prologue and never
         * restored, since the trap skips the epilogue): only the longjmp can put them back. */
        __asm__ volatile("li s1, 0x11\n li s2, 0x22\n li s3, 0x33\n li s4, 0x44\n li s5, 0x55\n"
                         "li s6, 0x66\n li s7, 0x77\n li s8, 0x88\n li s9, 0x99\n li s10, 0xaa\n"
                         "li s11, 0xbb" ::: "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9",
                         "s10", "s11");
        sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0);
    }
    uint64_t r = deep(n - 1, b, c, d, e);
    sink += (uint32_t)keep;
    return r + keep;
}
static uint64_t bad_load(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
    (void)b, (void)c, (void)d, (void)e;
    return sbpf_load(a, 8);
}
static uint64_t ret7(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
    (void)a, (void)b, (void)c, (void)d, (void)e;
    return 7;
}
static uint64_t unknown(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
    return sbpf_syscall(0xa22b9c85u, a, b, c, d, e); /* sol_invoke_signed_c */
}

static void put_pair(uint8_t *p, uint64_t ptr, uint64_t len) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(ptr >> (8 * i)), p[8 + i] = (uint8_t)(len >> (8 * i));
}
static uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void hex(uint8_t *out, const char *h, int n) {
    for (int i = 0; i < n; i++) {
        int v = 0;
        for (int j = 0; j < 2; j++) {
            char c = h[2 * i + j];
            v = v * 16 + (c <= '9' ? c - '0' : c - 'a' + 10);
        }
        out[i] = (uint8_t)v;
    }
}

static uint32_t secp(void) {
    uint8_t h[32], sig[65], key[64];
    hex(h, "ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008", 32);
    hex(sig, "90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc9301", 65);
    if (sbpf_secp256k1_recover(h, sig[64], sig, key) != 0) return 0xbad;
    return be32(key);
}
static uint32_t ed(int flip) {
    uint8_t pk[32], sig[64];
    hex(pk, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", 32);
    hex(sig, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", 64);
    if (flip) sig[40] ^= 1;
    return sbpf_ed25519_verify(pk, (const uint8_t *)"", 0, sig);
}

int main(void) {
    uint32_t mode = rand_read_input(0);
    uint32_t out[8] = {0};
    if (mode == 1) {
        out[0] = secp();
    } else if (mode == 2) {
        out[0] = ed(0);
        out[1] = ed(1);
    } else if (mode == 0) {
        uint64_t r0 = 0;
        uint32_t codes = 0;
        register uint32_t s1 __asm__("s1") = 0x5a5a1234;
        __asm__ volatile("" : "+r"(s1));
        regions();
        codes |= sbpf_rt_enter(deep, 5, 1, 0, 0, 0, &r0);
        codes |= sbpf_rt_enter(bad_load, SBPF_REGION_INPUT + 121, 0, 0, 0, 0, &r0) << 4;
        out[1] = (uint32_t)sbpf_halt_arg;
        codes |= sbpf_rt_enter(sbpf_sys_abort, 0, 0, 0, 0, 0, &r0) << 8;
        codes |= sbpf_rt_enter(unknown, 0, 0, 0, 0, 0, &r0) << 12;
        out[7] = (uint32_t)sbpf_halt_arg;
        codes |= sbpf_rt_enter(ret7, 0, 0, 0, 0, 0, &r0) << 16;
        if (r0 != 7) codes = 0xbad;
        out[0] = codes;
        __asm__ volatile("" : "+r"(s1));
        out[2] = s1 == 0x5a5a1234 ? s1 : 0xbad;

        regions();
        input_r[32] = 'a', input_r[33] = 'b', input_r[34] = 'c';
        put_pair(input_r, SBPF_REGION_INPUT + 32, 3);
        sbpf_rt_enter(sbpf_sys_sha256, SBPF_REGION_INPUT, 1, SBPF_REGION_INPUT + 64, 0, 0, &r0);
        out[3] = be32(input_r + 64);
        const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        for (int i = 0; i < 56; i++) heap_r[i] = (uint8_t)m[i];
        put_pair(input_r, SBPF_REGION_HEAP, 56);
        sbpf_rt_enter(sbpf_sys_sha256, SBPF_REGION_INPUT, 1, SBPF_REGION_INPUT + 64, 0, 0, &r0);
        out[4] = be32(input_r + 64);

        regions();
        sbpf_rt_enter(sbpf_sys_memmove, SBPF_REGION_INPUT + 4, SBPF_REGION_INPUT, 100, 0, 0, &r0);
        uint64_t a1 = 0, a2 = 0;
        sbpf_rt_enter(sbpf_sys_alloc_free, 1, 0, 0, 0, 0, &a1);
        sbpf_rt_enter(sbpf_sys_alloc_free, 1, 0, 0, 0, 0, &a2);
        out[5] = input_r[103] | (uint32_t)(a2 - SBPF_REGION_HEAP) << 8;
        if (a1 != SBPF_REGION_HEAP) out[5] = 0xbad;

        input_r[0] = 5, input_r[64] = 9;
        sbpf_rt_enter(sbpf_sys_memcmp, SBPF_REGION_INPUT, SBPF_REGION_INPUT + 64, 8,
                      SBPF_REGION_INPUT + 100, 0, &r0);
        out[6] = (uint32_t)input_r[100] | (uint32_t)input_r[101] << 8 | (uint32_t)input_r[102] << 16 |
                 (uint32_t)input_r[103] << 24;
    }
    for (int i = 0; i < 8; i++) rand_write_output((uint32_t)i, out[i]);
    rand_halt();
}
