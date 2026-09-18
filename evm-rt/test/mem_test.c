/* The memory model, the gas counter and the halt path against `interp.rs`'s rules: memory
 * expansion `3·words + words²/512` charged on the high-water mark, the bounds (`MAX_MEMORY_BYTES`,
 * `len_arg`, zero-length ranges), copies and CALLDATALOAD with zero padding at every boundary,
 * KECCAK256/EXP/LOGn/SSTORE's dynamic gas, RETURN/REVERT, and "an exceptional halt consumes the
 * whole limit". The Rust FFI (`ffi.rs`) is not linked on the host: `evm_keccak256`, `evm_sload`
 * and `evm_sstore` are recording stubs below. */
#include <string.h>
#include "test.h"

/* ---- FFI stubs ---- */
static void *stub_host_seen;
static const uint8_t *stub_ptr;
static uint32_t stub_len, stub_calls;

void evm_keccak256(void *host, const uint8_t *ptr, uint32_t len, uint8_t *out) {
    stub_host_seen = host;
    stub_ptr = ptr;
    stub_len = len;
    stub_calls++;
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(i ^ len); /* a recognisable digest */
}

/* A four-slot store keyed by the low limb; slot 99 has no witness, slot 98 a bad one. */
static uint32_t store_val[4][8];
static uint32_t sstore_calls;
uint32_t evm_sload(void *tree, void *host, const uint32_t *slot, uint32_t *out) {
    (void)tree; (void)host;
    if (slot[0] == 99) return EVM_HALT_NO_WITNESS;
    if (slot[0] == 98) return EVM_HALT_BAD_WITNESS;
    memcpy(out, store_val[slot[0] & 3], 32);
    return 0;
}
uint32_t evm_sstore(void *tree, void *host, const uint32_t *slot, const uint32_t *value) {
    (void)tree; (void)host;
    sstore_calls++;
    memcpy(store_val[slot[0] & 3], value, 32);
    return 0;
}

/* ---- helpers: each case runs a body under evm_rt_enter and reads the halt ---- */
static const uint8_t CODE[5] = {0x60, 0x01, 0x60, 0x02, 0x01};
static uint8_t calldata[36];

static void init(uint64_t gas) {
    for (int i = 0; i < 36; i++) calldata[i] = (uint8_t)(i + 1);
    CHECK(evm_rt_init(CODE, sizeof CODE, calldata, sizeof calldata, gas) == EVM_HALT_OK);
}

static uint64_t expansion(uint64_t w) { return 3 * w + w * w / 512; } /* the formula, by hand */

static uint32_t a0, a1, a2, ret32;
static u256 v0, v1, topics[4];

static uint32_t run(void (*f)(void)) {
    return evm_rt_enter(f);
}

static void b_mexpand(void) { ret32 = evm_mexpand(a0, a1); }
static void b_mstore(void) { evm_mstore(a0, &v0); }
static void b_mload(void) { evm_mload(a0, &v1); }
static void b_mstore8(void) { evm_mstore8(a0, a1); }
static void b_cdl(void) { evm_calldataload(a0, &v1); }
static void b_cdcopy(void) { evm_copy_calldata(a0, a1, a2); }
static void b_codecopy(void) { evm_copy_code(a0, a1, a2); }
static void b_rdcopy(void) { evm_copy_returndata(a0, a1, a2); }
static void b_keccak(void) { evm_keccak(a0, a1, &v1); }
static void b_exp(void) { evm_exp(&v1, &v0, &v1); }
static void b_log(void) { evm_log(a2, a0, a1, topics); }
static void b_charge(void) { evm_charge(a0); }
static void b_sload(void) { evm_storage_load(&v0, &v1); }
static void b_sstore(void) { evm_storage_store(&v0, &v1); }
static void b_return(void) { evm_return(a0, a1); }
static void b_revert(void) { evm_revert(a0, a1); }
static void b_trap(void) { evm_halt(EVM_HALT_TRAP, 0xf1); }
static void b_nothing(void) {}

/* ---- the cases ---- */

static void gas_counter_and_halts(void) {
    init(5);
    a0 = 5;
    CHECK(run(b_charge) == EVM_HALT_STOP); /* exactly the remaining gas is fine */
    CHECK_EQ_U64(evm_gas, 0);
    CHECK_EQ_U64(evm_gas_used(), 5);
    init(5);
    a0 = 6;
    CHECK(run(b_charge) == EVM_HALT_OUT_OF_GAS);
    CHECK_EQ_U64(evm_gas_used(), 5); /* an exceptional halt consumes the limit */
    init(100);
    CHECK(run(b_nothing) == EVM_HALT_STOP && evm_halt_code == EVM_HALT_STOP);
    CHECK_EQ_U64(evm_gas_used(), 0);
    init(100);
    CHECK(run(b_trap) == EVM_HALT_TRAP && evm_halt_arg == 0xf1);
    CHECK_EQ_U64(evm_gas_used(), 100);
}

static void expansion_gas(void) {
    /* One expansion from zero to w words costs exactly the formula. */
    static const uint32_t ws[] = {1, 2, 3, 22, 23, 32, 511, 512, 513, 724, 1024, 2047, 2048};
    for (size_t i = 0; i < sizeof ws / sizeof *ws; i++) {
        init(1000000);
        a0 = 0; a1 = ws[i] * 32;
        CHECK(run(b_mexpand) == EVM_HALT_STOP && ret32 == 0);
        CHECK_EQ_U64(evm_gas_used(), expansion(ws[i]));
        CHECK(evm_msize == ws[i] * 32);
    }
    CHECK_EQ_U64(expansion(2048), 14336); /* the whole 64 KiB */
    /* Growing in steps pays the difference each time: the total is the final size's cost. */
    init(1000000);
    for (uint32_t w = 1; w <= 2048; w = w * 3 + 1) {
        a0 = w * 32 - 1; a1 = 1;
        CHECK(run(b_mexpand) == EVM_HALT_STOP && ret32 == w * 32 - 1);
        CHECK_EQ_U64(evm_gas_used(), expansion(w));
    }
    /* Touching memory below the high-water mark is free; an unaligned end rounds up. */
    init(1000000);
    a0 = 31; a1 = 1; v0 = t_hex("1234");
    CHECK(run(b_mstore8) == EVM_HALT_STOP && evm_msize == 32);
    CHECK_EQ_U64(evm_gas_used(), 3);
    a0 = 1;
    CHECK(run(b_mstore) == EVM_HALT_STOP && evm_msize == 64);
    CHECK_EQ_U64(evm_gas_used(), expansion(2));
    a0 = 0;
    CHECK(run(b_mload) == EVM_HALT_STOP && evm_msize == 64);
    CHECK_EQ_U64(evm_gas_used(), expansion(2));
    /* Too little gas for the expansion is out of gas, and msize does not move. */
    init(expansion(3) - 1);
    a0 = 64; a1 = 32;
    CHECK(run(b_mexpand) == EVM_HALT_OUT_OF_GAS);
    CHECK(evm_msize == 0);
}

static void memory_bounds(void) {
    /* A zero-length range touches nothing and pays nothing, whatever its offset. */
    init(1000);
    a0 = 0xffffffffu; a1 = 0;
    CHECK(run(b_mexpand) == EVM_HALT_STOP && ret32 == 0 && evm_msize == 0);
    CHECK_EQ_U64(evm_gas_used(), 0);
    /* The last word of the 64 KiB is addressable; one byte past it is out of bounds. */
    init(1000000);
    a0 = MAX_MEMORY_BYTES - 32; a1 = 32;
    CHECK(run(b_mexpand) == EVM_HALT_STOP && evm_msize == MAX_MEMORY_BYTES);
    init(1000000);
    a0 = MAX_MEMORY_BYTES - 31;
    CHECK(run(b_mstore) == EVM_HALT_OUT_OF_BOUNDS);
    CHECK_EQ_U64(evm_gas_used(), 1000000);
    init(1000000);
    a0 = MAX_MEMORY_BYTES; a1 = 7;
    CHECK(run(b_mstore8) == EVM_HALT_OUT_OF_BOUNDS);
    /* offset + len wrapping a u32 is out of bounds, not a small range. */
    init(1000000);
    a0 = 0xfffffff0u;
    CHECK(run(b_mload) == EVM_HALT_OUT_OF_BOUNDS);
    init(1000000);
    a0 = 0xffffffffu; a1 = 1;
    CHECK(run(b_mexpand) == EVM_HALT_OUT_OF_BOUNDS);
    /* A 2^32 offset saturates to UINT32_MAX (u256_sat_u32) and is out of bounds, not offset 0. */
    init(1000000);
    u256 off = t_hex("100000000");
    a0 = u256_sat_u32(&off);
    CHECK(run(b_mstore) == EVM_HALT_OUT_OF_BOUNDS);
}

static void mload_mstore(void) {
    init(1000000);
    uint8_t be[32];
    for (int i = 0; i < 32; i++) be[i] = (uint8_t)(0x40 + i);
    u256_from_be_bytes(&v0, be);
    a0 = 0;
    CHECK(run(b_mstore) == EVM_HALT_STOP);
    CHECK(memcmp(evm_memory, be, 32) == 0); /* big-endian in memory */
    a0 = 1;
    CHECK(run(b_mload) == EVM_HALT_STOP);
    uint8_t want[32];
    memcpy(want, be + 1, 31);
    want[31] = 0; /* the byte past the stored word reads as zero */
    u256 w;
    u256_from_be_bytes(&w, want);
    CHECK(t_eq(&v1, &w));
    a0 = 40; a1 = 0x1ab; /* MSTORE8 keeps the low byte */
    CHECK(run(b_mstore8) == EVM_HALT_STOP && evm_memory[40] == 0xab && evm_memory[41] == 0);
    /* A fresh init clears what the last run dirtied. */
    CHECK(evm_rt_init(CODE, sizeof CODE, calldata, sizeof calldata, 1000) == EVM_HALT_OK);
    CHECK(evm_msize == 0 && evm_sp == 0 && evm_ret_len == 0 && evm_n_logs == 0);
    int clean = 1;
    for (int i = 0; i < 128; i++) clean &= evm_memory[i] == 0;
    CHECK(clean);
}

static void calldata_and_copies(void) {
    init(1000000);
    a0 = 0;
    CHECK(run(b_cdl) == EVM_HALT_STOP);
    CHECK(v1.l[7] == 0x01020304u && v1.l[0] == 0x1d1e1f20u);
    a0 = 4;
    CHECK(run(b_cdl) == EVM_HALT_STOP && v1.l[7] == 0x05060708u && v1.l[0] == 0x21222324u);
    a0 = 20; /* bytes 21..36 then 16 zeros */
    CHECK(run(b_cdl) == EVM_HALT_STOP && v1.l[7] == 0x15161718u && v1.l[4] == 0x21222324u && v1.l[3] == 0 &&
          v1.l[2] == 0 && v1.l[0] == 0);
    a0 = 36;
    CHECK(run(b_cdl) == EVM_HALT_STOP && u256_is_zero(&v1));
    a0 = 0xffffffffu; /* no wrap back to the start */
    CHECK(run(b_cdl) == EVM_HALT_STOP && u256_is_zero(&v1));
    CHECK_EQ_U64(evm_gas_used(), 0); /* CALLDATALOAD's 3 is static */

    /* CALLDATACOPY: 3 per word + expansion, zero-padded past the end. */
    init(1000000);
    memset(evm_memory, 0xee, 16);  /* what the copy must overwrite (and msize is still 0) */
    a0 = 0; a1 = 30; a2 = 10;
    CHECK(run(b_cdcopy) == EVM_HALT_STOP);
    CHECK(evm_memory[0] == 31 && evm_memory[5] == 36 && evm_memory[6] == 0 && evm_memory[9] == 0);
    CHECK(evm_memory[10] == 0xee); /* only len bytes are written */
    CHECK_EQ_U64(evm_gas_used(), 3 * 1 + expansion(1));
    a0 = 32; a1 = 0xffffffffu; a2 = 33; /* all padding, the source index never wraps */
    CHECK(run(b_cdcopy) == EVM_HALT_STOP);
    int zeros = 1;
    for (int i = 32; i < 65; i++) zeros &= evm_memory[i] == 0;
    CHECK(zeros);
    CHECK_EQ_U64(evm_gas_used(), 3 * 1 + expansion(1) + 3 * 2 + (expansion(3) - expansion(1)));
    /* A zero length pays no word or expansion gas, at any destination. */
    init(1000);
    a0 = 0xffffffffu; a1 = 0; a2 = 0;
    CHECK(run(b_cdcopy) == EVM_HALT_STOP && evm_gas_used() == 0 && evm_msize == 0);
    /* A length past MAX_MEMORY_BYTES is out of bounds before any gas is charged (len_arg). */
    init(0);
    a0 = 0; a1 = 0; a2 = MAX_MEMORY_BYTES + 1;
    CHECK(run(b_cdcopy) == EVM_HALT_OUT_OF_BOUNDS);
    init(0);
    a2 = 0xffffffffu;
    CHECK(run(b_cdcopy) == EVM_HALT_OUT_OF_BOUNDS);
    /* The word gas is charged before the expansion: enough for the words only is out of gas. */
    init(3);
    a0 = 0; a1 = 0; a2 = 1;
    CHECK(run(b_cdcopy) == EVM_HALT_OUT_OF_GAS);

    /* CODECOPY: the same rule over the code. */
    init(1000000);
    a0 = 0; a1 = 3; a2 = 4;
    CHECK(run(b_codecopy) == EVM_HALT_STOP);
    CHECK(evm_memory[0] == 0x02 && evm_memory[1] == 0x01 && evm_memory[2] == 0 && evm_memory[3] == 0);
    CHECK_EQ_U64(evm_gas_used(), 3 + expansion(1));

    /* RETURNDATACOPY: the buffer is always empty. */
    init(1000);
    a0 = 5; a1 = 7; a2 = 0;
    CHECK(run(b_rdcopy) == EVM_HALT_STOP && evm_gas_used() == 0 && evm_msize == 0);
    a2 = 1;
    CHECK(run(b_rdcopy) == EVM_HALT_TRAP && evm_halt_arg == 0x3e);
}

static void keccak_exp(void) {
    int host_token;
    init(1000000);
    evm_host = &host_token;
    evm_memory[0] = 0x11;
    a0 = 0; a1 = 33;
    stub_calls = 0;
    CHECK(run(b_keccak) == EVM_HALT_STOP);
    CHECK(stub_calls == 1 && stub_ptr == evm_memory && stub_len == 33 && stub_host_seen == &host_token);
    CHECK_EQ_U64(evm_gas_used(), 30 + 6 * 2 + expansion(2));
    /* the digest's bytes, big-endian: byte i is i ^ 33 */
    CHECK(v1.l[7] == ((0u ^ 33) << 24 | (1u ^ 33) << 16 | (2u ^ 33) << 8 | (3u ^ 33)));
    CHECK((v1.l[0] & 0xff) == (31u ^ 33));
    /* The empty hash still pays the 30, at any offset. */
    init(1000);
    evm_host = &host_token;
    a0 = 0xffffffffu; a1 = 0;
    CHECK(run(b_keccak) == EVM_HALT_STOP && stub_len == 0);
    CHECK_EQ_U64(evm_gas_used(), 30);
    init(29);
    CHECK(run(b_keccak) == EVM_HALT_OUT_OF_GAS);
    init(1000);
    a0 = 0; a1 = MAX_MEMORY_BYTES + 1;
    CHECK(run(b_keccak) == EVM_HALT_OUT_OF_BOUNDS);

    /* EXP: 10 + 50 per significant exponent byte. */
    init(1000000);
    v0 = t_hex("3"); v1 = t_hex("0");
    CHECK(run(b_exp) == EVM_HALT_STOP && v1.l[0] == 1);
    CHECK_EQ_U64(evm_gas_used(), 10);
    init(1000000);
    v0 = t_hex("2"); v1 = t_hex("100"); /* 2^256 = 0, a two-byte exponent */
    CHECK(run(b_exp) == EVM_HALT_STOP && u256_is_zero(&v1));
    CHECK_EQ_U64(evm_gas_used(), 10 + 50 * 2);
    init(1000000);
    v0 = t_hex("3"); memset(&v1, 0xff, sizeof v1);
    CHECK(run(b_exp) == EVM_HALT_STOP);
    CHECK_EQ_U64(evm_gas_used(), 10 + 50 * 32);
    init(59);
    v1 = t_hex("1");
    CHECK(run(b_exp) == EVM_HALT_OUT_OF_GAS);
}

static void logs(void) {
    init(1000000);
    for (uint32_t i = 0; i < 4; i++) u256_from_u32(&topics[i], 100 + i);
    a0 = 0; a1 = 40; a2 = 2;
    CHECK(run(b_log) == EVM_HALT_STOP);
    CHECK(evm_n_logs == 1 && evm_logs[0].n_topics == 2);
    /* stack order, deepest first: topic 0 is topics[n-1] */
    CHECK(evm_logs[0].topics[0].l[0] == 101 && evm_logs[0].topics[1].l[0] == 100);
    CHECK(u256_is_zero(&evm_logs[0].topics[2]));
    CHECK_EQ_U64(evm_gas_used(), 375 + 375 * 2 + 8 * 40 + expansion(2));
    for (int i = 1; i < MAX_LOGS; i++) {
        a0 = 0xffffffffu; a1 = 0; a2 = 0;
        CHECK(run(b_log) == EVM_HALT_STOP);
    }
    CHECK(evm_n_logs == MAX_LOGS);
    CHECK(run(b_log) == EVM_HALT_OUT_OF_BOUNDS); /* the ninth */
    init(374 + 375);
    a0 = 0; a1 = 0; a2 = 1;
    CHECK(run(b_log) == EVM_HALT_OUT_OF_GAS && evm_n_logs == 0);
    init(1000000);
    a1 = MAX_MEMORY_BYTES + 1; a2 = 0;
    CHECK(run(b_log) == EVM_HALT_OUT_OF_BOUNDS);
}

static void storage(void) {
    memset(store_val, 0, sizeof store_val);
    init(1000000);
    v0 = t_hex("1"); v1 = t_hex("5");
    sstore_calls = 0;
    CHECK(run(b_sstore) == EVM_HALT_STOP && sstore_calls == 1);
    CHECK_EQ_U64(evm_gas_used(), G_SSTORE_SET); /* zero -> non-zero */
    v1 = t_hex("6");
    CHECK(run(b_sstore) == EVM_HALT_STOP);
    CHECK_EQ_U64(evm_gas_used(), G_SSTORE_SET + G_SSTORE_RESET);
    v1 = t_hex("0");
    CHECK(run(b_sstore) == EVM_HALT_STOP); /* clearing: reset, no refund */
    CHECK_EQ_U64(evm_gas_used(), G_SSTORE_SET + 2 * G_SSTORE_RESET);
    v0 = t_hex("2"); v1 = t_hex("0");
    CHECK(run(b_sstore) == EVM_HALT_STOP); /* zero -> zero */
    CHECK_EQ_U64(evm_gas_used(), G_SSTORE_SET + 3 * G_SSTORE_RESET);
    v0 = t_hex("1"); store_val[1][0] = 42;
    CHECK(run(b_sload) == EVM_HALT_STOP && v1.l[0] == 42);
    CHECK_EQ_U64(evm_gas_used(), G_SSTORE_SET + 3 * G_SSTORE_RESET); /* SLOAD's 2100 is static */
    v0 = t_hex("63"); /* 99: no witness */
    CHECK(run(b_sload) == EVM_HALT_NO_WITNESS);
    init(1000000);
    v0 = t_hex("62"); v1 = t_hex("1"); sstore_calls = 0;
    CHECK(run(b_sstore) == EVM_HALT_BAD_WITNESS && sstore_calls == 0);
    /* Out of gas for the write: the tree is never written. */
    init(G_SSTORE_SET - 1);
    v0 = t_hex("3"); v1 = t_hex("1"); sstore_calls = 0;
    CHECK(run(b_sstore) == EVM_HALT_OUT_OF_GAS && sstore_calls == 0);
}

static void return_revert(void) {
    init(1000000);
    for (int i = 0; i < 40; i++) evm_memory[i] = (uint8_t)i;
    evm_msize = 64; /* as if the contract had written there */
    a0 = 3; a1 = 5;
    CHECK(run(b_return) == EVM_HALT_RETURN);
    CHECK(evm_ret_len == 5 && evm_ret[0] == 3 && evm_ret[4] == 7);
    CHECK_EQ_U64(evm_gas_used(), 0); /* nothing expanded; gas is left on the table */
    init(1000000);
    a0 = 0; a1 = 64;
    CHECK(run(b_revert) == EVM_HALT_REVERT && evm_ret_len == 64);
    CHECK_EQ_U64(evm_gas_used(), expansion(2));
    init(1000);
    a0 = 0xffffffffu; a1 = 0;
    CHECK(run(b_return) == EVM_HALT_RETURN && evm_ret_len == 0 && evm_gas_used() == 0);
    init(1000000);
    a0 = 0; a1 = MAX_RETURN_BYTES;
    CHECK(run(b_return) == EVM_HALT_RETURN && evm_ret_len == MAX_RETURN_BYTES);
    init(1000000);
    a1 = MAX_RETURN_BYTES + 1;
    CHECK(run(b_return) == EVM_HALT_OUT_OF_BOUNDS);
    CHECK_EQ_U64(evm_gas_used(), 1000000);
}

static void init_caps(void) {
    static uint8_t big[MAX_CODE_BYTES + 1];
    CHECK(evm_rt_init(big, MAX_CODE_BYTES, calldata, 36, 10) == EVM_HALT_OK);
    CHECK(evm_rt_init(big, MAX_CODE_BYTES + 1, calldata, 36, 10) == EVM_HALT_OUT_OF_BOUNDS);
    CHECK(evm_rt_init(CODE, 5, big, MAX_CALLDATA_BYTES, 10) == EVM_HALT_OK);
    CHECK(evm_rt_init(CODE, 5, big, MAX_CALLDATA_BYTES + 1, 10) == EVM_HALT_OUT_OF_BOUNDS);
    CHECK(evm_code_len == 5 && evm_gas == 10 && evm_gas_limit == 10);
}

int mem_tests(void) {
    gas_counter_and_halts();
    expansion_gas();
    memory_bounds();
    mload_mstore();
    calldata_and_copies();
    keccak_exp();
    logs();
    storage();
    return_revert();
    init_caps();
    printf("mem: done\n");
    return 0;
}
