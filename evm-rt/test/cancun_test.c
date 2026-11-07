/* The post-Shanghai opcodes' runtime (`evm_cancun.c`) against `interp.rs`'s arms: MCOPY's
 * per-word gas, its expansion over max(dst, src) + len and memmove on overlap, its len_arg and
 * zero-length rules; TLOAD/TSTORE's table — empty after `evm_transient_begin`, the last store
 * winning, a zero store to a new key taking no entry, and the capacity halt (OutOfBounds) at
 * MAX_TRANSIENT_SLOTS + 1 non-zero keys; and CLZ (`u256_clz`). Static gas (MCOPY's 3,
 * TLOAD/TSTORE's 100, CLZ's 5) is the block head's, so none of it is charged here. */
#include <string.h>
#include "test.h"

static uint64_t expansion(uint64_t w) { return 3 * w + w * w / 512; }

static const uint8_t CODE[1] = {0x00};

static void init(uint64_t gas) { CHECK(evm_rt_init(CODE, 1, CODE, 0, gas) == EVM_HALT_OK); }

static uint32_t a0, a1, a2;
static u256 k0, v0, r0;

static void b_mcopy(void) { evm_mcopy(a0, a1, a2); }
static void b_mstore(void) { evm_mstore(a0, &v0); }
static void b_tload(void) { evm_tload(&k0, &r0); }
static void b_tload_alias(void) { r0 = k0; evm_tload(&r0, &r0); }
static void b_tstore(void) { evm_tstore(&k0, &v0); }

static uint32_t run(void (*f)(void)) { return evm_rt_enter(f); }

/* mem[0..32) = 1, 2, ..., 32 with msize 32. */
static void ramp(void) {
    for (int i = 0; i < 32; i++) evm_memory[i] = (uint8_t)(i + 1);
    evm_msize = 32;
}

static void mcopy(void) {
    uint8_t want[32];
    /* Forward overlap, [1, 9) <- [0, 8): memmove, not a forward byte loop. */
    init(1000000);
    ramp();
    a0 = 1; a1 = 0; a2 = 8;
    CHECK(run(b_mcopy) == EVM_HALT_STOP);
    for (int i = 0; i < 32; i++) want[i] = (uint8_t)(i + 1);
    memmove(want + 1, want, 8);
    CHECK(memcmp(evm_memory, want, 32) == 0);
    CHECK(evm_memory[8] == 8 && evm_memory[9] == 10);
    CHECK_EQ_U64(evm_gas_used(), 3); /* one word, no expansion */
    /* Backward overlap, [0, 8) <- [1, 9). */
    init(1000000);
    ramp();
    a0 = 0; a1 = 1; a2 = 8;
    CHECK(run(b_mcopy) == EVM_HALT_STOP);
    for (int i = 0; i < 32; i++) want[i] = (uint8_t)(i + 1);
    memmove(want, want + 1, 8);
    CHECK(memcmp(evm_memory, want, 32) == 0);
    CHECK(evm_memory[7] == 9 && evm_memory[8] == 9);
    /* The expansion is over the farther range, the source's included: MCOPY(0, 0x40, 1). */
    init(1000000);
    ramp();
    a0 = 0; a1 = 0x40; a2 = 1;
    CHECK(run(b_mcopy) == EVM_HALT_STOP);
    CHECK(evm_msize == 96 && evm_memory[0] == 0);
    CHECK_EQ_U64(evm_gas_used(), 3 + expansion(3) - expansion(1));
    /* MCOPY(0x40, 0, 33): two words copied, memory 1 -> 4 words. */
    init(1000000);
    ramp();
    a0 = 0x40; a1 = 0; a2 = 33;
    CHECK(run(b_mcopy) == EVM_HALT_STOP);
    CHECK(evm_msize == 128 && evm_memory[0x40] == 1 && evm_memory[0x40 + 31] == 32 && evm_memory[0x60] == 0);
    CHECK_EQ_U64(evm_gas_used(), 3 * 2 + expansion(4) - expansion(1));
    /* A zero length pays nothing and touches nothing, whatever the offsets. */
    init(1000);
    a0 = 0xffffffffu; a1 = 0xffffffffu; a2 = 0;
    CHECK(run(b_mcopy) == EVM_HALT_STOP && evm_gas_used() == 0 && evm_msize == 0);
    /* A length past the memory is out of bounds before any gas (len_arg). */
    init(0);
    a0 = 0; a1 = 0; a2 = MAX_MEMORY_BYTES + 1;
    CHECK(run(b_mcopy) == EVM_HALT_OUT_OF_BOUNDS);
    init(0);
    a2 = 0xffffffffu;
    CHECK(run(b_mcopy) == EVM_HALT_OUT_OF_BOUNDS);
    /* Either range ending past the memory is out of bounds (a saturated offset included). */
    init(1000000);
    a0 = MAX_MEMORY_BYTES; a1 = 0; a2 = 1;
    CHECK(run(b_mcopy) == EVM_HALT_OUT_OF_BOUNDS);
    init(1000000);
    a0 = 0; a1 = 0xffffffffu; a2 = 1;
    CHECK(run(b_mcopy) == EVM_HALT_OUT_OF_BOUNDS);
    /* The whole memory onto itself shifted by one word: the last word ends at the top. (The
     * other suites write `evm_memory` directly, past msize, so start from the zeroed memory a
     * run sees.) */
    memset(evm_memory, 0, MAX_MEMORY_BYTES);
    init(1000000);
    a0 = 0; v0 = t_hex("abcd");
    CHECK(run(b_mstore) == EVM_HALT_STOP);
    a0 = 32; a1 = 0; a2 = MAX_MEMORY_BYTES - 32;
    CHECK(run(b_mcopy) == EVM_HALT_STOP);
    CHECK(evm_msize == MAX_MEMORY_BYTES && evm_memory[62] == 0xab && evm_memory[63] == 0xcd);
    CHECK(evm_memory[30] == 0xab && evm_memory[MAX_MEMORY_BYTES - 1] == 0);
    /* The word gas is charged before the expansion: enough for the words only is out of gas. */
    init(3);
    a0 = 0; a1 = 0; a2 = 1;
    CHECK(run(b_mcopy) == EVM_HALT_OUT_OF_GAS);
    CHECK(evm_msize == 0);
}

static void transient(void) {
    init(1000);
    evm_transient_begin();
    /* An unset key reads zero; the result may alias the key. */
    k0 = t_hex("1");
    CHECK(run(b_tload) == EVM_HALT_STOP && u256_is_zero(&r0));
    v0 = t_hex("2a");
    CHECK(run(b_tstore) == EVM_HALT_STOP);
    CHECK(run(b_tload) == EVM_HALT_STOP && t_eq(&r0, &v0));
    CHECK(run(b_tload_alias) == EVM_HALT_STOP && t_eq(&r0, &v0));
    /* A key differing in a high limb is another key. */
    k0 = t_hex("1000000000000000000000000000000000000000000000000000000000000001");
    CHECK(run(b_tload) == EVM_HALT_STOP && u256_is_zero(&r0));
    /* The last store wins. */
    k0 = t_hex("1"); v0 = t_hex("7");
    CHECK(run(b_tstore) == EVM_HALT_STOP);
    CHECK(run(b_tload) == EVM_HALT_STOP && t_eq(&r0, &v0));
    CHECK_EQ_U64(evm_gas_used(), 0); /* TLOAD/TSTORE's 100 is static */
    /* A new call starts empty. */
    evm_transient_begin();
    CHECK(run(b_tload) == EVM_HALT_STOP && u256_is_zero(&r0));

    /* The table: MAX_TRANSIENT_SLOTS non-zero keys fit, one more halts OutOfBounds. */
    init(1000);
    evm_transient_begin();
    v0 = t_hex("1");
    for (uint32_t k = 1; k <= MAX_TRANSIENT_SLOTS; k++) {
        u256_from_u32(&k0, k);
        CHECK(run(b_tstore) == EVM_HALT_STOP);
    }
    /* Full: overwriting a held key and storing zero under a new one still succeed. */
    k0 = t_hex("1"); v0 = t_hex("5");
    CHECK(run(b_tstore) == EVM_HALT_STOP);
    k0 = t_hex("1000"); v0 = t_hex("0");
    CHECK(run(b_tstore) == EVM_HALT_STOP);
    CHECK(run(b_tload) == EVM_HALT_STOP && u256_is_zero(&r0));
    k0 = t_hex("1");
    CHECK(run(b_tload) == EVM_HALT_STOP && t_eq(&r0, &(u256){{5, 0, 0, 0, 0, 0, 0, 0}}));
    k0 = t_hex("1001"); v0 = t_hex("9");
    CHECK(run(b_tstore) == EVM_HALT_OUT_OF_BOUNDS);
    CHECK_EQ_U64(evm_gas_used(), 1000); /* an exceptional halt consumes the limit */
    /* A zero over a held key keeps its entry (and reads zero). */
    init(1000);
    evm_transient_begin();
    k0 = t_hex("3"); v0 = t_hex("3");
    CHECK(run(b_tstore) == EVM_HALT_STOP);
    v0 = t_hex("0");
    CHECK(run(b_tstore) == EVM_HALT_STOP);
    CHECK(run(b_tload) == EVM_HALT_STOP && u256_is_zero(&r0));
}

static void clz(void) {
    static const struct { const char *x; uint32_t n; } cases[] = {
        {"0", 256}, {"1", 255}, {"80", 248}, {"ffffffff", 224}, {"100000000", 223},
        {"ffffffffffffffffffffffffffffffff", 128},
        {"4000000000000000000000000000000000000000000000000000000000000000", 1},
        {"8000000000000000000000000000000000000000000000000000000000000000", 0},
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0},
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        u256 x = t_hex(cases[i].x), r, want;
        u256_from_u32(&want, cases[i].n);
        u256_clz(&r, &x);
        CHECK(t_eq(&r, &want));
        u256_clz(&x, &x); /* aliased */
        CHECK(t_eq(&x, &want));
    }
}

int cancun_tests(void) {
    mcopy();
    transient();
    clz();
    printf("cancun: done\n");
    return 0;
}
