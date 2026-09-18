/* `evm_call` (a translated CALL/CALLCODE/DELEGATECALL/STATICCALL) and the return-data buffer,
 * against the Shanghai rules the controller's ruling 4 lists, each case worked by hand:
 *
 *   the target is the low 160 bits of the address word; 1..9 run the precompile, anything else
 *   halts Trap(op); a nonzero value on CALL/CALLCODE halts Trap(op) (no balance model);
 *   the charge is 100 (a precompile is always warm, EIP-2929), then the args and ret regions'
 *   expansion; the gas passed is min(requested, all but one 64th of what is left);
 *   a precompile costing more than that, or rejecting its input, fails the call: 0 pushed, the
 *   gas passed consumed, the return data emptied; otherwise 1 pushed, the precompile's cost
 *   consumed, the return data replaced by the output and min(retLen, outLen) bytes of it copied
 *   to retOff.
 *
 * RETURNDATASIZE/RETURNDATACOPY over the buffer (EIP-211, `evm_copy_returndata_buf`): before any
 * call the interpreter's rule (a zero length is a no-op wherever it points, any other length
 * traps); after one, a copy past the buffer halts OutOfBounds, a zero length included. */
#include <string.h>
#include "test.h"
#include "../precompiles.h"

extern int t_real_keccak;

static const uint8_t CODE[1] = {0x00};
static uint64_t after_; /* evm_call's gas_after */

static void init(uint64_t gas) {
    CHECK(evm_rt_init(CODE, 1, CODE, 0, gas) == EVM_HALT_OK);
    evm_calls_begin();
    after_ = 0;
}

static uint32_t op_, a0, a1, a2;
static u256 *args;

static void b_call(void) { evm_call(op_, args, after_); }
static void b_rdcopy(void) { evm_copy_returndata_buf(a0, a1, a2); }

/* Push the operands the way the stack holds them (the deepest first) and point `args` at them:
 * CALL/CALLCODE: retLen, retOff, argsLen, argsOff, value, addr, gas (the top). */
static void setup(uint32_t op, u256 gas, u256 addr, u256 value, uint32_t in_off, uint32_t in_len,
                  uint32_t ret_off, uint32_t ret_len) {
    op_ = op;
    evm_sp = 3; /* something underneath, untouched */
    for (int i = 0; i < 3; i++) u256_from_u32(&evm_stack[i], 0x5a5a0000u + (uint32_t)i);
    args = &evm_stack[evm_sp];
    u256_from_u32(&evm_stack[evm_sp++], ret_len);
    u256_from_u32(&evm_stack[evm_sp++], ret_off);
    u256_from_u32(&evm_stack[evm_sp++], in_len);
    u256_from_u32(&evm_stack[evm_sp++], in_off);
    if (op == 0xf1 || op == 0xf2) evm_stack[evm_sp++] = value;
    evm_stack[evm_sp++] = addr;
    evm_stack[evm_sp++] = gas;
}

static u256 w(uint32_t v) {
    u256 r;
    u256_from_u32(&r, v);
    return r;
}

static uint64_t expansion(uint64_t words) { return 3 * words + words * words / 512; }

static void identity_staticcall(void) {
    /* STATICCALL(gas 1000, 4, argsOff 0, argsLen 40, retOff 64, retLen 50): memory is two
     * words after the args' expansion (40 bytes), four after the ret region's (114 bytes);
     * identity costs 15 + 3·2 = 21. */
    init(100000);
    for (int i = 0; i < 40; i++) evm_memory[i] = (uint8_t)(i + 1);
    setup(0xfa, w(1000), w(4), w(0), 0, 40, 64, 50);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP);
    CHECK(u256_low_u32(&args[0]) == 1 && u256_hi_zero(&args[0]) && args[0].l[1] == 0);
    CHECK_EQ_U64(evm_gas_used(), 100 + expansion(4) + 21);
    CHECK(evm_msize == 128);
    CHECK(evm_rdata_len == 40 && memcmp(evm_rdata, evm_memory, 40) == 0);
    CHECK(memcmp(evm_memory + 64, evm_memory, 40) == 0); /* min(50, 40) bytes copied */
    CHECK(evm_memory[104] == 0 && evm_memory[113] == 0);
    CHECK(evm_stack[0].l[0] == 0x5a5a0000u && evm_stack[2].l[0] == 0x5a5a0002u);
    /* retLen shorter than the output: only retLen bytes land; the buffer holds all 40. */
    init(100000);
    for (int i = 0; i < 40; i++) evm_memory[i] = (uint8_t)(i + 1);
    setup(0xfa, w(1000), w(4), w(0), 0, 40, 100, 3);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && args[0].l[0] == 1);
    CHECK(evm_memory[100] == 1 && evm_memory[102] == 3 && evm_memory[103] == 0);
    CHECK(evm_rdata_len == 40);
}

static void every_call_opcode_dispatches(void) {
    static const uint32_t ops[4] = {0xf1, 0xf2, 0xf4, 0xfa};
    for (int k = 0; k < 4; k++) {
        init(100000);
        memcpy(evm_memory, "abc", 3);
        setup(ops[k], w(1000), w(2), w(0), 0, 3, 32, 32);
        CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && args[0].l[0] == 1);
        /* sha256("abc"), FIPS 180-2 B.1; 60 + 12 gas; memory 2 words. */
        CHECK(evm_memory[32] == 0xba && evm_memory[63] == 0xad && evm_rdata_len == 32);
        CHECK_EQ_U64(evm_gas_used(), 100 + expansion(2) + 72);
    }
}

static void the_target(void) {
    /* The low 160 bits: bits above them are ignored, so 2^200 + 4 is identity... */
    init(100000);
    u256 a = w(4);
    a.l[6] = 0x100;
    setup(0xfa, w(1000), a, w(0), 0, 0, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && args[0].l[0] == 1);
    CHECK_EQ_U64(evm_gas_used(), 100 + 15);
    /* ... but any bit inside them is another address: 2^32 + 4, 2^159 + 4, 0 and 10 trap. */
    u256 targets[4] = {w(4), w(4), w(0), w(10)};
    targets[0].l[1] = 1;
    targets[1].l[4] = 0x80000000u;
    for (int k = 0; k < 4; k++) {
        for (uint32_t op = 0xf1; op <= 0xfa; op = op == 0xf2 ? 0xf4 : op == 0xf4 ? 0xfa : op + 1) {
            init(100000);
            setup(op, w(1000), targets[k], w(0), 0, 0, 0, 0);
            CHECK(evm_rt_enter(b_call) == EVM_HALT_TRAP && evm_halt_arg == op);
            CHECK_EQ_U64(evm_gas_used(), 100000);
        }
    }
}

static void value(void) {
    /* CALL/CALLCODE with a nonzero value: Trap(op), even to a precompile. */
    for (uint32_t op = 0xf1; op <= 0xf2; op++) {
        init(100000);
        setup(op, w(1000), w(4), w(1), 0, 0, 0, 0);
        CHECK(evm_rt_enter(b_call) == EVM_HALT_TRAP && evm_halt_arg == op);
        CHECK_EQ_U64(evm_gas_used(), 100000);
        u256 big = w(0);
        big.l[7] = 0x80000000u;
        init(100000);
        setup(op, w(1000), w(4), big, 0, 0, 0, 0);
        CHECK(evm_rt_enter(b_call) == EVM_HALT_TRAP && evm_halt_arg == op);
    }
}

static void gas_passed(void) {
    /* Requested less than the cost: the call fails, the requested gas is gone. */
    init(100000);
    setup(0xfa, w(2999), w(1), w(0), 0, 0, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && u256_is_zero(&args[0]));
    CHECK_EQ_U64(evm_gas_used(), 100 + 2999);
    CHECK(evm_rdata_len == 0);
    /* Requested exactly the cost: ecrecover over an all-zero input (v = 0) succeeds, empty. */
    init(100000);
    setup(0xfa, w(3000), w(1), w(0), 0, 0, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && args[0].l[0] == 1);
    CHECK_EQ_U64(evm_gas_used(), 100 + 3000);
    /* All but one 64th: 3140 - 100 = 3040 left, 3040 - 47 = 2993 passed < 3000. */
    u256 huge = w(0);
    huge.l[7] = 0xffffffffu;
    init(3140);
    setup(0xfa, huge, w(1), w(0), 0, 0, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && u256_is_zero(&args[0]));
    CHECK_EQ_U64(evm_gas, 47);
    /* 3149 - 100 = 3049, 3049 - 47 = 3002 passed >= 3000: success, 49 left. */
    init(3149);
    setup(0xfa, huge, w(1), w(0), 0, 0, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && args[0].l[0] == 1);
    CHECK_EQ_U64(evm_gas, 49);
    /* gas_after: the block head took 640 for the ops after the call, which the EVM still has.
     * 3789 - 640 = 3149 in the counter: 3049 after the 100; the EVM's 3689 passes 3689 - 57 =
     * 3632 >= 3000: success, 3149 - 100 - 3000 = 49 left in the counter. */
    init(3789);
    evm_gas -= 640;
    after_ = 640;
    setup(0xfa, huge, w(1), w(0), 0, 0, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && args[0].l[0] == 1);
    CHECK_EQ_U64(evm_gas, 49);
    /* A success charges its cost against the counter the same way. And a failing call passing
     * more than the counter holds: the EVM would have 57 left against the 640 the rest of its
     * block costs, so it runs out; here, at once. */
    init(3789);
    evm_gas -= 640;
    after_ = 640;
    setup(0xfa, huge, w(6), w(0), 0, 0, 0, 0); /* bn256 add of two infinities: 150 */
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && args[0].l[0] == 1);
    CHECK_EQ_U64(evm_gas, 3149 - 100 - 150);
    init(3789);
    evm_gas -= 640;
    after_ = 640;
    evm_memory[31] = 1;
    evm_memory[63] = 3; /* (1, 3): off the curve, the call fails and consumes 3632 > 3049 */
    setup(0xfa, huge, w(6), w(0), 0, 64, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_OUT_OF_GAS);
    CHECK_EQ_U64(evm_gas_used(), 3789);
    /* The 100 itself: out of gas. */
    init(99);
    setup(0xfa, w(0), w(4), w(0), 0, 0, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_OUT_OF_GAS);
    CHECK_EQ_U64(evm_gas_used(), 99);
    /* Identity with a zero-length input costs 15; gas 0 requested fails it. */
    init(1000);
    setup(0xfa, w(0), w(4), w(0), 0, 0, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && u256_is_zero(&args[0]));
    CHECK_EQ_U64(evm_gas_used(), 100);
}

static void invalid_input(void) {
    /* bn256 add of (1, 3), off the curve: the call fails and consumes what it was passed. */
    init(100000);
    memset(evm_memory, 0, 128);
    evm_memory[31] = 1;
    evm_memory[63] = 3;
    setup(0xfa, w(5000), w(6), w(0), 0, 128, 0, 64);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && u256_is_zero(&args[0]));
    CHECK_EQ_U64(evm_gas_used(), 100 + expansion(4) + 5000);
    CHECK(evm_rdata_len == 0);
    CHECK(evm_memory[31] == 1 && evm_memory[63] == 3); /* the ret region is not written */
    /* ecrecover with v = 29 is a success with no output (the EVM's rule, not a failure). */
    init(100000);
    memset(evm_memory, 0, 128);
    evm_memory[63] = 29;
    evm_memory[95] = 1;
    evm_memory[127] = 1;
    setup(0xfa, w(5000), w(1), w(0), 0, 128, 0, 32);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && args[0].l[0] == 1);
    CHECK_EQ_U64(evm_gas_used(), 100 + expansion(4) + 3000);
    CHECK(evm_rdata_len == 0 && evm_memory[63] == 29);
}

static void memory_regions(void) {
    /* A zero-length region is not expanded, whatever its offset. */
    init(100000);
    setup(0xfa, w(1000), w(4), w(0), 0xffffffffu, 0, 0xfffffff0u, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && args[0].l[0] == 1);
    CHECK(evm_msize == 0);
    CHECK_EQ_U64(evm_gas_used(), 115);
    /* A region past the memory is OutOfBounds, the interpreter's rule for every range. */
    init(100000);
    setup(0xfa, w(1000), w(4), w(0), 0, 0, MAX_MEMORY_BYTES, 1);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_OUT_OF_BOUNDS);
    init(100000);
    setup(0xfa, w(1000), w(4), w(0), 0, MAX_MEMORY_BYTES + 1, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_OUT_OF_BOUNDS);
    /* The ret region's expansion is paid even when the call fails. */
    init(100000);
    setup(0xfa, w(0), w(4), w(0), 0, 0, 0, 320);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && u256_is_zero(&args[0]));
    CHECK_EQ_U64(evm_gas_used(), 100 + expansion(10));
}

static void modexp_over_the_cap(void) {
    /* An affordable modexp with a 1025-byte modulus: the runtime's cap, OutOfBounds. */
    init(10000000);
    memset(evm_memory, 0, 96);
    evm_memory[31] = 1;
    evm_memory[63] = 1;
    evm_memory[94] = 0x04;
    evm_memory[95] = 0x01; /* 1025 */
    setup(0xfa, w(1000000), w(5), w(0), 0, 96, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_OUT_OF_BOUNDS);
    /* The same call without the gas for it fails normally: RequiredGas (129^2 / 3 = 5547)
     * comes first. */
    init(10000000);
    memset(evm_memory, 0, 96);
    evm_memory[31] = 1;
    evm_memory[63] = 1;
    evm_memory[94] = 0x04;
    evm_memory[95] = 0x01;
    setup(0xfa, w(5546), w(5), w(0), 0, 96, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && u256_is_zero(&args[0]));
}

static void returndata(void) {
    /* Before any call: the interpreter's rule. */
    init(1000);
    a0 = 0; a1 = 5; a2 = 0;
    CHECK(evm_rt_enter(b_rdcopy) == EVM_HALT_STOP);
    CHECK_EQ_U64(evm_gas_used(), 0);
    a1 = 0; a2 = 1;
    CHECK(evm_rt_enter(b_rdcopy) == EVM_HALT_TRAP && evm_halt_arg == 0x3e);
    /* After a call returning 40 bytes (identity). */
    init(100000);
    for (int i = 0; i < 40; i++) evm_memory[i] = (uint8_t)(0x80 + i);
    setup(0xfa, w(1000), w(4), w(0), 0, 40, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && evm_rdata_len == 40);
    uint64_t used = evm_gas_used();
    a0 = 100; a1 = 8; a2 = 32; /* bytes 8..40 to 100: 3 per word, memory to 132 -> 5 words */
    CHECK(evm_rt_enter(b_rdcopy) == EVM_HALT_STOP);
    CHECK(evm_memory[100] == 0x88 && evm_memory[131] == 0xa7);
    CHECK_EQ_U64(evm_gas_used() - used, 3 + expansion(5) - expansion(2));
    a0 = 0; a1 = 40; a2 = 0; /* the end exactly: fine */
    CHECK(evm_rt_enter(b_rdcopy) == EVM_HALT_STOP);
    a1 = 41; a2 = 0; /* past it, even empty: EIP-211 */
    CHECK(evm_rt_enter(b_rdcopy) == EVM_HALT_OUT_OF_BOUNDS);
    CHECK_EQ_U64(evm_gas_used(), 100000);
    init(100000);
    setup(0xfa, w(1000), w(4), w(0), 0, 40, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP);
    a0 = 0; a1 = 9; a2 = 32;
    CHECK(evm_rt_enter(b_rdcopy) == EVM_HALT_OUT_OF_BOUNDS);
    init(100000);
    setup(0xfa, w(1000), w(4), w(0), 0, 40, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP);
    a0 = 0; a1 = 0xffffffffu; a2 = 2;
    CHECK(evm_rt_enter(b_rdcopy) == EVM_HALT_OUT_OF_BOUNDS);
    /* A failed call empties the buffer; a later call replaces it; evm_calls_begin resets it. */
    init(100000);
    setup(0xfa, w(1000), w(4), w(0), 0, 40, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && evm_rdata_len == 40);
    setup(0xfa, w(0), w(4), w(0), 0, 40, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && evm_rdata_len == 0);
    a0 = 0; a1 = 1; a2 = 0;
    CHECK(evm_rt_enter(b_rdcopy) == EVM_HALT_OUT_OF_BOUNDS);
    init(100000);
    setup(0xfa, w(1000), w(4), w(0), 0, 7, 0, 0);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && evm_rdata_len == 7);
    evm_calls_begin();
    CHECK(evm_rdata_len == 0);
    a0 = 0; a1 = 5; a2 = 0; /* the interpreter's rule again */
    CHECK(evm_rt_enter(b_rdcopy) == EVM_HALT_STOP);
}

/* ecrecover through a call, the whole path: geth's ValidKey, address 0xa94f53...ebf0b. */
static void ecrecover_call(void) {
    static const char *in =
        "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
        "000000000000000000000000000000000000000000000000000000000000001c"
        "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
        "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549";
    init(100000);
    for (int i = 0; i < 128; i++) {
        unsigned v;
        sscanf(in + 2 * i, "%2x", &v);
        evm_memory[i] = (uint8_t)v;
    }
    setup(0xfa, w(3000), w(1), w(0), 0, 128, 128, 32);
    CHECK(evm_rt_enter(b_call) == EVM_HALT_STOP && args[0].l[0] == 1);
    CHECK(evm_rdata_len == 32 && evm_memory[128 + 11] == 0 && evm_memory[128 + 12] == 0xa9 &&
          evm_memory[128 + 31] == 0x0b);
    CHECK_EQ_U64(evm_gas_used(), 100 + expansion(5) + 3000);
}

int call_tests(void) {
    t_real_keccak = 1;
    identity_staticcall();
    every_call_opcode_dispatches();
    the_target();
    value();
    gas_passed();
    invalid_input();
    memory_regions();
    modexp_over_the_cap();
    returndata();
    ecrecover_call();
    t_real_keccak = 0;
    return 0;
}
