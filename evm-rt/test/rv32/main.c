/* The runtime on the machine itself: a C guest (`rand-guest build --lang c evm-rt/test/rv32`)
 * that includes the runtime's sources, so the RV32 path the host suite cannot reach — the
 * hand-written `evm_rt_setjmp`/`evm_rt_longjmp` in evm_rt.c — is executed on the emulator.
 * `rand-guest/tests/evm_rt.rs` builds and runs it and checks the eight outputs:
 *
 *   0  the five halt codes, 4 bits each: OOB 12 (from six frames deep) | STOP 1 | RETURN 2 |
 *      OUT_OF_GAS 4 | NO_WITNESS 10                                  = 0x000a421c
 *   1  gas_used of the OOB run: the whole limit                       = 1000000
 *   2  gas_used of the STOP run: one word of expansion                = 3
 *   3  gas_used of the RETURN run: SSTORE set + one word              = 20003
 *   4  the RETURN data's last byte | its length << 8                  = 0x407
 *   5  s1-s11, pinned in main, all intact after the five unwinds (the
 *      OOB one from under a frame that overwrote them), 0xbad if not  = 0x5a5a1234
 *   6  2^255 / 3, low limb (the u256 library on the target)           = 0xaaaaaaaa
 *   7  (2^255)^2 mod 1000003, the 512-bit MULMOD on the target        = 0xea1b3 (958899)
 */
#include "guest.h"
#include "../../evm_rt.h"
#include "../../u256.c"
#include "../../evm_rt.c"

/* The Rust FFI is not linked into this guest: minimal stand-ins. */
void evm_keccak256(void *h, const uint8_t *p, uint32_t n, uint8_t *o) {
    (void)h;
    for (int i = 0; i < 32; i++) o[i] = (uint8_t)(i + n + (n ? p[0] : 0));
}
static uint32_t slots[8];
uint32_t evm_sload(void *t, void *h, const uint32_t *s, uint32_t *o) {
    (void)t; (void)h;
    if (s[0] == 99) return EVM_HALT_NO_WITNESS;
    for (int i = 0; i < 8; i++) o[i] = 0;
    o[0] = slots[s[0] & 7];
    return 0;
}
uint32_t evm_sstore(void *t, void *h, const uint32_t *s, const uint32_t *v) {
    (void)t; (void)h;
    slots[s[0] & 7] = v[0];
    return 0;
}

static volatile uint32_t sink;
/* Nested frames that keep values live across calls, then an out-of-bounds MSTORE at the bottom:
 * the unwind has to come back through all of them. */
__attribute__((noinline)) static void deep(uint32_t n) {
    u256 a, b;
    u256_from_u32(&a, n);
    u256_from_u32(&b, 3);
    u256_mul(&a, &a, &b);
    if (n == 0) {
        /* Dirty every callee-saved register but s0 (saved by this frame's prologue, never
         * restored, since the halt skips the epilogue): only the longjmp can put them back. */
        __asm__ volatile("li s1, 0x11\n li s2, 0x22\n li s3, 0x33\n li s4, 0x44\n li s5, 0x55\n"
                         "li s6, 0x66\n li s7, 0x77\n li s8, 0x88\n li s9, 0x99\n li s10, 0xaa\n"
                         "li s11, 0xbb"
                         ::: "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11");
        evm_mstore(MAX_MEMORY_BYTES, &b);
    }
    deep(n - 1);
    sink += a.l[0];
}
static void e_oob(void) { deep(5); }
static void e_stop(void) {
    u256 v;
    u256_from_u32(&v, 0xabcdef);
    evm_mstore(0, &v);
}
static void e_ret(void) {
    u256 v, s, r;
    u256_from_u32(&v, 7);
    u256_from_u32(&s, 1);
    evm_storage_store(&s, &v);
    evm_storage_load(&s, &r);
    evm_mstore(0, &r);
    evm_return(28, 4);
}
static void e_oog(void) { evm_charge(1000001); }
static void e_nowit(void) {
    u256 s, r;
    u256_from_u32(&s, 99);
    evm_storage_load(&s, &r);
}

static const uint8_t code[1] = {0};

static uint32_t go(void (*entry)(void), uint64_t *used) {
    evm_rt_init(code, 1, code, 0, 1000000);
    uint32_t h = evm_rt_enter(entry);
    *used = evm_gas_used();
    return h;
}

void main(void) {
    /* Values pinned in s1-s11 for the whole run; every unwind must hand them back. */
    register uint32_t r1 __asm__("s1") = 0x5a5a1201, r2 __asm__("s2") = 0x5a5a1202;
    register uint32_t r3 __asm__("s3") = 0x5a5a1203, r4 __asm__("s4") = 0x5a5a1204;
    register uint32_t r5 __asm__("s5") = 0x5a5a1205, r6 __asm__("s6") = 0x5a5a1206;
    register uint32_t r7 __asm__("s7") = 0x5a5a1207, r8 __asm__("s8") = 0x5a5a1208;
    register uint32_t r9 __asm__("s9") = 0x5a5a1209, r10 __asm__("s10") = 0x5a5a120a;
    register uint32_t r11 __asm__("s11") = 0x5a5a120b;
    __asm__ volatile("" : "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5), "+r"(r6), "+r"(r7),
                     "+r"(r8), "+r"(r9), "+r"(r10), "+r"(r11));
    uint64_t g_oob, g_stop, g_ret, g_oog, g_nw;
    uint32_t h = go(e_oob, &g_oob);
    h |= go(e_stop, &g_stop) << 4;
    h |= go(e_ret, &g_ret) << 8;
    uint32_t ret = (uint32_t)evm_ret[3] | evm_ret_len << 8;
    h |= go(e_oog, &g_oog) << 12;
    h |= go(e_nowit, &g_nw) << 16;
    __asm__ volatile("" : "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5), "+r"(r6), "+r"(r7),
                     "+r"(r8), "+r"(r9), "+r"(r10), "+r"(r11));
    uint32_t kept = (r1 == 0x5a5a1201) & (r2 == 0x5a5a1202) & (r3 == 0x5a5a1203) &
                    (r4 == 0x5a5a1204) & (r5 == 0x5a5a1205) & (r6 == 0x5a5a1206) &
                    (r7 == 0x5a5a1207) & (r8 == 0x5a5a1208) & (r9 == 0x5a5a1209) &
                    (r10 == 0x5a5a120a) & (r11 == 0x5a5a120b);
    rand_write_output(0, h);
    rand_write_output(1, (uint32_t)g_oob);
    rand_write_output(2, (uint32_t)g_stop);
    rand_write_output(3, (uint32_t)g_ret);
    rand_write_output(4, ret);
    rand_write_output(5, kept ? 0x5a5a1234u : 0xbadu);
    u256 a, b, m, r;
    u256_from_u32(&a, 2);
    u256_from_u32(&b, 255);
    u256_exp(&a, &a, &b);
    u256_from_u32(&b, 3);
    u256_div(&r, &a, &b);
    rand_write_output(6, r.l[0]);
    u256_from_u32(&m, 1000003);
    u256_mulmod(&r, &a, &a, &m);
    rand_write_output(7, r.l[0]);
    rand_halt();
}
