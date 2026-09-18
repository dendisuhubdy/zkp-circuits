/* sbpf-rt's host suite: the runtime compiled for the host and checked against what `sbpf-core`'s
 * `memory.rs`/`syscalls.rs` do, case by case, plus the known answers for the software SHA-256
 * padding, Ed25519 and secp256k1.
 *
 *   cc -O1 -Wall -Wextra -o /tmp/sbpf_rt_test test/host_test.c test/host_glue.c sbpf_rt.c \
 *      sbpf_bn.c sbpf_ed25519.c sbpf_secp256k1.c && /tmp/sbpf_rt_test
 *
 * (from `sbpf-rt/`; add `-DSBPF_USIZE_MAX=0xffffffffu` for the RV32 guest's 32-bit `usize`, under
 * which a length above u32::MAX faults with the *length* as its address, as `usize_of` makes it).
 * `research/tests/sbpf_rt.rs` builds and runs both variants, and separately runs every syscall and
 * region access through the interpreter itself next to this runtime (`test/driver.c`): the
 * expectations below are hand-derived from the Rust, the differential test is what proves them.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../sbpf_rt.h"
#include "crypto_vectors.h"

#ifndef SBPF_USIZE_MAX
#define SBPF_USIZE_MAX SIZE_MAX
#endif

static int failures, checks;
#define CHECK(cond, ...)                                                   \
    do {                                                                   \
        checks++;                                                          \
        if (!(cond)) {                                                     \
            failures++;                                                    \
            printf("FAIL %s:%d: %s — ", __FILE__, __LINE__, #cond);        \
            printf(__VA_ARGS__);                                           \
            printf("\n");                                                  \
        }                                                                  \
    } while (0)

/* ---- the machine ---------------------------------------------------------------------------- */

static uint8_t text[64], rodata[256], stack[SBPF_STACK_BYTES], heap[SBPF_HEAP_BYTES], input[128];

/* SBPF v1's shape: the rodata span starts before the text and contains it. */
static void layout_v1(void) {
    for (int i = 0; i < 256; i++) rodata[i] = (uint8_t)(0xa0 ^ i);
    memset(stack, 0, sizeof stack);
    memset(heap, 0, sizeof heap);
    for (int i = 0; i < 128; i++) input[i] = (uint8_t)i;
    sbpf_r.rodata = rodata;
    sbpf_r.rodata_va = SBPF_REGION_PROGRAM + 0x100;
    sbpf_r.rodata_len = sizeof rodata;
    sbpf_r.text = rodata + 0x20;
    sbpf_r.text_va = SBPF_REGION_PROGRAM + 0x120;
    sbpf_r.text_len = 64;
    sbpf_r.stack = stack;
    sbpf_r.heap = heap;
    sbpf_r.input = input;
    sbpf_r.input_len = sizeof input;
    sbpf_rt_reset();
}

/* The text *outside* the rodata span, right after it, so the fallback to the text is what serves a
 * load there, and a load straddling the two spans is covered by neither. */
static void layout_split(void) {
    layout_v1();
    for (int i = 0; i < 64; i++) text[i] = (uint8_t)(0x50 + i);
    sbpf_r.text = text;
    sbpf_r.text_va = SBPF_REGION_PROGRAM + 0x200; /* rodata is 0x100..0x200 */
    sbpf_r.text_len = sizeof text;
}

typedef struct {
    uint32_t code;
    uint64_t arg; /* the halt payload, or r0 when code is EXIT */
} outcome;

static outcome call(sbpf_fn f, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
    uint64_t r0 = 0xdeadbeef;
    uint32_t code = sbpf_rt_enter(f, a, b, c, d, e, &r0);
    outcome o = {code, code == SBPF_HALT_EXIT ? r0 : sbpf_halt_arg};
    return o;
}
/* Functions, not macros: each evaluates its outcome (one call) exactly once. */
static int OK(outcome o, uint64_t v) { return o.code == SBPF_HALT_EXIT && o.arg == v; }
static int HALT(outcome o, uint32_t c, uint64_t a) { return o.code == c && o.arg == a; }
static int AV(outcome o, uint64_t a) { return HALT(o, SBPF_HALT_ACCESS_VIOLATION, a); }

static uint64_t f_load(uint64_t addr, uint64_t size, uint64_t c, uint64_t d, uint64_t e) {
    (void)c, (void)d, (void)e;
    return sbpf_load(addr, (uint32_t)size);
}
static uint64_t f_store(uint64_t addr, uint64_t size, uint64_t v, uint64_t d, uint64_t e) {
    (void)d, (void)e;
    sbpf_store(addr, (uint32_t)size, v);
    return 0;
}
static uint64_t f_tr_ro(uint64_t addr, uint64_t len, uint64_t c, uint64_t d, uint64_t e) {
    (void)c, (void)d, (void)e;
    return (uint64_t)(uintptr_t)sbpf_tr_ro(addr, len);
}
static uint64_t f_tr_rw(uint64_t addr, uint64_t len, uint64_t c, uint64_t d, uint64_t e) {
    (void)c, (void)d, (void)e;
    return (uint64_t)(uintptr_t)sbpf_tr_rw(addr, len);
}
#define LOAD(a, n) call(f_load, (a), (n), 0, 0, 0)
#define STORE(a, n, v) call(f_store, (a), (n), (v), 0, 0)
#define IN(off) (SBPF_REGION_INPUT + (uint64_t)(off))
#define HEAP(off) (SBPF_REGION_HEAP + (uint64_t)(off))
#define STK(off) (SBPF_REGION_STACK + (uint64_t)(off))
#define PROG(off) (SBPF_REGION_PROGRAM + (uint64_t)(off))

static uint64_t le(const uint8_t *p, int n) {
    uint64_t v = 0;
    for (int i = 0; i < n; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* ---- regions ---------------------------------------------------------------------------------- */

static void test_regions(void) {
    layout_v1();
    /* Every width, little-endian, zero-extended; no alignment rule. */
    CHECK(OK(LOAD(IN(1), 1), 1), "b");
    CHECK(OK(LOAD(IN(1), 2), 0x0201), "h");
    CHECK(OK(LOAD(IN(3), 4), 0x06050403), "w");
    CHECK(OK(LOAD(IN(5), 8), 0x0c0b0a0908070605ull), "dw");
    /* The last byte of a region, and one past it: the fault names the access's start. */
    CHECK(OK(LOAD(IN(120), 8), le(input + 120, 8)), "input end");
    CHECK(AV(LOAD(IN(121), 8), IN(121)), "input end + 1");
    CHECK(AV(LOAD(IN(128), 1), IN(128)), "input one past");
    CHECK(OK(LOAD(STK(SBPF_STACK_BYTES - 8), 8), 0), "stack end");
    CHECK(AV(LOAD(STK(SBPF_STACK_BYTES - 7), 8), STK(SBPF_STACK_BYTES - 7)), "stack end + 1");
    CHECK(OK(LOAD(HEAP(SBPF_HEAP_BYTES - 1), 1), 0), "heap end");
    CHECK(AV(LOAD(HEAP(SBPF_HEAP_BYTES), 1), HEAP(SBPF_HEAP_BYTES)), "heap past");
    /* An offset whose end passes 2^32: a fault, never a wrap back into the region. */
    CHECK(AV(LOAD(IN(0xffffffffull), 8), IN(0xffffffffull)), "offset wrap");
    CHECK(AV(LOAD(IN(0xfffffffcull), 8), IN(0xfffffffcull)), "offset wrap 2");
    /* No region 0, 5, or anything above. */
    CHECK(AV(LOAD(0x10, 1), 0x10), "region 0");
    CHECK(AV(LOAD(0x500000000ull, 1), 0x500000000ull), "region 5");
    CHECK(AV(LOAD(0xffffffff00000000ull, 1), 0xffffffff00000000ull), "region ffffffff");
    CHECK(AV(STORE(0x500000000ull, 1, 1), 0x500000000ull), "store region 5");

    /* Stores write the low `size` bytes and nothing else. */
    CHECK(OK(STORE(IN(10), 2, 0x1122334455667788ull), 0), "sh");
    CHECK(input[10] == 0x88 && input[11] == 0x77 && input[12] == 12, "sh bytes");
    CHECK(OK(STORE(IN(120), 8, 0x0102030405060708ull), 0), "sdw end");
    CHECK(le(input + 120, 8) == 0x0102030405060708ull, "sdw end bytes");
    CHECK(AV(STORE(IN(121), 8, 0), IN(121)), "sdw past");
    CHECK(input[121] == 7, "a faulting store writes nothing");
    CHECK(OK(STORE(STK(0), 4, 0xaabbccdd), 0) && le(stack, 4) == 0xaabbccdd, "stack store");
    CHECK(OK(STORE(HEAP(7), 1, 0x1ff), 0) && heap[7] == 0xff && heap[8] == 0, "heap store");

    /* The program region: rodata first, then the text; read-only however well bounded. */
    CHECK(OK(LOAD(PROG(0x100), 1), 0xa0), "rodata start");
    CHECK(AV(LOAD(PROG(0xff), 1), PROG(0xff)), "before rodata");
    CHECK(OK(LOAD(PROG(0x1f8), 8), le(rodata + 0xf8, 8)), "rodata end");
    CHECK(AV(LOAD(PROG(0x1f9), 8), PROG(0x1f9)), "rodata end + 1");
    CHECK(OK(LOAD(PROG(0x120), 8), le(rodata + 0x20, 8)), "text inside rodata");
    CHECK(AV(STORE(PROG(0x120), 1, 0), PROG(0x120)), "store to text");
    CHECK(AV(STORE(PROG(0x100), 8, 0), PROG(0x100)), "store to rodata");

    layout_split();
    CHECK(OK(LOAD(PROG(0x200), 8), le(text, 8)), "text past rodata");
    CHECK(OK(LOAD(PROG(0x238), 8), le(text + 56, 8)), "text end");
    CHECK(AV(LOAD(PROG(0x239), 8), PROG(0x239)), "text end + 1");
    /* Straddling the two spans: each covers part, neither covers all. */
    CHECK(AV(LOAD(PROG(0x1fc), 8), PROG(0x1fc)), "straddle");
    CHECK(OK(LOAD(PROG(0x1fc), 4), le(rodata + 0xfc, 4)), "rodata tail");

    /* Zero-length translations: legal at or inside the end, a fault past it or outside a region. */
    layout_v1();
    CHECK(OK(call(f_tr_rw, IN(128), 0, 0, 0, 0), (uintptr_t)(input + 128)), "empty at end");
    CHECK(AV(call(f_tr_rw, IN(129), 0, 0, 0, 0), IN(129)), "empty past end");
    CHECK(AV(call(f_tr_ro, 0x10, 0, 0, 0, 0), 0x10), "empty region 0");
    CHECK(OK(call(f_tr_ro, PROG(0x200), 0, 0, 0, 0), (uintptr_t)(rodata + 0x100)), "empty rodata end");
    CHECK(AV(call(f_tr_rw, PROG(0x100), 0, 0, 0, 0), PROG(0x100)), "empty write to program");
    /* A 64-bit length that overflows the end. */
    CHECK(AV(call(f_tr_ro, IN(1), UINT64_MAX, 0, 0, 0), IN(1)), "len overflow");
    CHECK(AV(call(f_tr_ro, PROG(0x100), UINT64_MAX, 0, 0, 0), PROG(0x100)), "len overflow prog");
}

/* ---- the trap path ---------------------------------------------------------------------------- */

static int depth_reached;
static uint64_t deep(uint64_t n, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
    volatile uint64_t keep = n * 3 + b;
    depth_reached++;
    if (n == 0) sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0);
    uint64_t r = deep(n - 1, b, c, d, e);
    return r + keep;
}
static uint64_t ret_sum(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
    return a + b + c + d + e;
}

static void test_traps(void) {
    layout_v1();
    CHECK(OK(call(ret_sum, 1, 2, 3, 4, 5), 15), "a normal return is EXIT with r0");
    CHECK(sbpf_halt_code == SBPF_HALT_EXIT, "no halt recorded");
    depth_reached = 0;
    CHECK(HALT(call(deep, 6, 1, 0, 0, 0), SBPF_HALT_DIV_BY_ZERO, 0), "a trap six frames down");
    CHECK(depth_reached == 7, "every frame ran");
    CHECK(OK(call(ret_sum, 7, 0, 0, 0, 0), 7), "the next run starts clean");
    CHECK(sbpf_halt_arg == 0, "arg cleared");
    sbpf_rt_reset();
    CHECK(sbpf_budget == SBPF_MAX_INSTRUCTIONS && sbpf_heap_used == 0, "reset");
}

/* ---- the syscalls ----------------------------------------------------------------------------- */

static void test_memcpy_memmove(void) {
    layout_v1();
    CHECK(OK(call(sbpf_sys_memcpy, IN(64), IN(0), 32, 0, 0), 0), "memcpy");
    for (int i = 0; i < 32; i++) CHECK(input[64 + i] == i, "memcpy byte %d", i);
    /* Touching is not overlapping; one byte of overlap in either direction is. */
    layout_v1();
    CHECK(OK(call(sbpf_sys_memcpy, IN(8), IN(0), 8, 0, 0), 0) && input[8] == 0, "touching");
    CHECK(HALT(call(sbpf_sys_memcpy, IN(7), IN(0), 8, 0, 0), SBPF_HALT_TRAP, SBPF_TRAP_MEMCPY_OVERLAP),
          "overlap up");
    CHECK(HALT(call(sbpf_sys_memcpy, IN(0), IN(7), 8, 0, 0), SBPF_HALT_TRAP, SBPF_TRAP_MEMCPY_OVERLAP),
          "overlap down");
    CHECK(input[7] == 7, "a refused copy writes nothing");
    /* Overlap is checked before either range: an overlapping copy out of every region still
     * traps, not faults. */
    CHECK(HALT(call(sbpf_sys_memcpy, 0x10, 0x11, 8, 0, 0), SBPF_HALT_TRAP, SBPF_TRAP_MEMCPY_OVERLAP),
          "overlap before bounds");
    /* The source is checked first, then the destination. */
    CHECK(AV(call(sbpf_sys_memcpy, 0x10, IN(200), 8, 0, 0), IN(200)), "bad src first");
    CHECK(AV(call(sbpf_sys_memcpy, IN(121), IN(0), 8, 0, 0), IN(121)), "bad dst");
    CHECK(input[121] == 121, "a faulting copy writes nothing");
    CHECK(AV(call(sbpf_sys_memcpy, PROG(0x100), IN(0), 8, 0, 0), PROG(0x100)), "into rodata");
    CHECK(OK(call(sbpf_sys_memcpy, IN(0), PROG(0x100), 8, 0, 0), 0) && input[0] == 0xa0, "from rodata");
    /* Zero bytes at a region's end is fine; past it is not. */
    CHECK(OK(call(sbpf_sys_memcpy, IN(128), IN(0), 0, 0, 0), 0), "empty at end");
    CHECK(AV(call(sbpf_sys_memcpy, IN(129), IN(0), 0, 0, 0), IN(129)), "empty past end");

    /* memmove: both directions, across more than one of the interpreter's 64-byte chunks. */
    layout_v1();
    CHECK(OK(call(sbpf_sys_memmove, IN(4), IN(0), 100, 0, 0), 0), "memmove up");
    for (int i = 0; i < 100; i++) CHECK(input[4 + i] == i, "memmove up byte %d", i);
    CHECK(input[0] == 0 && input[3] == 3 && input[104] == 104, "memmove up edges");
    layout_v1();
    CHECK(OK(call(sbpf_sys_memmove, IN(0), IN(4), 100, 0, 0), 0), "memmove down");
    for (int i = 0; i < 100; i++) CHECK(input[i] == i + 4, "memmove down byte %d", i);
    CHECK(input[100] == 100, "memmove down edge");
    layout_v1();
    CHECK(OK(call(sbpf_sys_memmove, IN(60), IN(0), 68, 0, 0), 0), "memmove far up");
    for (int i = 0; i < 68; i++) CHECK(input[60 + i] == i, "memmove far up byte %d", i);
    layout_v1();
    CHECK(OK(call(sbpf_sys_memmove, IN(0), IN(0), 128, 0, 0), 0) && input[127] == 127, "exact");
    CHECK(AV(call(sbpf_sys_memmove, IN(0), IN(64), 100, 0, 0), IN(64)), "memmove past");
    /* Across regions: heap to input and back. */
    layout_v1();
    CHECK(OK(call(sbpf_sys_memmove, HEAP(100), IN(0), 128, 0, 0), 0) && heap[227] == 127, "to heap");
    CHECK(OK(call(sbpf_sys_memset, IN(0), 0, 128, 0, 0), 0), "clear");
    CHECK(OK(call(sbpf_sys_memmove, IN(0), HEAP(100), 128, 0, 0), 0) && input[99] == 99, "from heap");
}

static void test_memset(void) {
    layout_v1();
    CHECK(OK(call(sbpf_sys_memset, IN(0), 0x1ab, 8, 0, 0), 0), "memset");
    CHECK(input[0] == 0xab && input[7] == 0xab && input[8] == 8, "memset takes the low byte");
    CHECK(OK(call(sbpf_sys_memset, IN(0), 0xab, 0, 0, 0), 0), "memset 0");
    CHECK(AV(call(sbpf_sys_memset, IN(126), 0xab, 4, 0, 0), IN(126)), "memset past");
    CHECK(input[126] == 126, "atomic");
    CHECK(AV(call(sbpf_sys_memset, 0, 0xab, 4, 0, 0), 0), "memset region 0");
    CHECK(AV(call(sbpf_sys_memset, PROG(0x100), 0, 1, 0, 0), PROG(0x100)), "memset rodata");
#if SBPF_USIZE_MAX == 0xffffffffu
    /* RV32: a length that is not a usize faults with the length itself (`usize_of`). */
    CHECK(AV(call(sbpf_sys_memset, IN(0), 0xab, 1ull << 40, 0, 0), 1ull << 40), "memset huge (rv32)");
#else
    CHECK(AV(call(sbpf_sys_memset, IN(0), 0xab, 1ull << 40, 0, 0), IN(0)), "memset huge (64-bit)");
#endif
}

static void test_memcmp(void) {
    layout_v1();
    input[0] = 5, input[64] = 9;
    CHECK(OK(call(sbpf_sys_memcmp, IN(0), IN(64), 8, IN(100), 0), 0), "memcmp lt");
    CHECK((int32_t)le(input + 100, 4) == -4, "negative: 5 - 9 = %d", (int32_t)le(input + 100, 4));
    input[0] = 0xff, input[64] = 0;
    CHECK(OK(call(sbpf_sys_memcmp, IN(0), IN(64), 8, IN(100), 0), 0), "memcmp gt");
    CHECK((int32_t)le(input + 100, 4) == 255, "unsigned bytes: 0xff - 0 = 255");
    input[0] = 0, input[64] = 0xff;
    CHECK(OK(call(sbpf_sys_memcmp, IN(0), IN(64), 8, IN(100), 0), 0), "memcmp -255");
    CHECK((int32_t)le(input + 100, 4) == -255, "0 - 0xff = -255");
    layout_v1();
    for (int i = 0; i < 32; i++) input[64 + i] = (uint8_t)i;
    CHECK(OK(call(sbpf_sys_memcmp, IN(0), IN(64), 32, IN(100), 0), 0), "memcmp eq");
    CHECK(le(input + 100, 4) == 0, "eq writes 0");
    /* The first difference past the 64-byte chunk boundary. */
    layout_v1();
    memcpy(input + 64, input, 64);
    input[70] = 0xff;
    CHECK(OK(call(sbpf_sys_memcmp, IN(0), IN(64), 64, IN(0), 0), 0), "late");
    CHECK((int32_t)le(input, 4) == 6 - 0xff, "late diff %d", (int32_t)le(input, 4));
    /* All three ranges before any byte is read or written: a, b, then the 4-byte result. */
    layout_v1();
    input[0] = 5, input[64] = 9;
    CHECK(AV(call(sbpf_sys_memcmp, IN(0), IN(64), 8, IN(126), 0), IN(126)), "bad out");
    CHECK(input[126] == 126, "no partial result");
    CHECK(AV(call(sbpf_sys_memcmp, IN(0), IN(64), 100, IN(100), 0), IN(64)), "b short");
    CHECK(AV(call(sbpf_sys_memcmp, IN(100), IN(0), 100, IN(0), 0), IN(100)), "a short");
    CHECK(AV(call(sbpf_sys_memcmp, IN(0), IN(0), 8, PROG(0x100), 0), PROG(0x100)), "out in rodata");
    CHECK(OK(call(sbpf_sys_memcmp, PROG(0x100), PROG(0x100), 8, IN(0), 0), 0) && le(input, 4) == 0,
          "compare rodata");
}

static void test_alloc(void) {
    layout_v1();
    CHECK(OK(call(sbpf_sys_alloc_free, 1, 0, 0, 0, 0), HEAP(0)), "first");
    CHECK(sbpf_heap_used == 1, "cursor %u", sbpf_heap_used);
    CHECK(OK(call(sbpf_sys_alloc_free, 1, 0, 0, 0, 0), HEAP(8)), "8-aligned second");
    CHECK(OK(call(sbpf_sys_alloc_free, 0, 0, 0, 0, 0), HEAP(16)), "zero bytes: an aligned address");
    CHECK(sbpf_heap_used == 16, "zero bytes still aligns the cursor: %u", sbpf_heap_used);
    CHECK(OK(call(sbpf_sys_alloc_free, 9, 0, 0, 0, 0), HEAP(16)), "9");
    CHECK(OK(call(sbpf_sys_alloc_free, 8, HEAP(16), 0, 0, 0), 0), "free is a no-op returning 0");
    CHECK(sbpf_heap_used == 25, "free moved nothing");
    CHECK(OK(call(sbpf_sys_alloc_free, SBPF_HEAP_BYTES - 32, 0, 0, 0, 0), HEAP(32)), "to the end");
    CHECK(OK(call(sbpf_sys_alloc_free, 1, 0, 0, 0, 0), 0), "full: null");
    CHECK(OK(call(sbpf_sys_alloc_free, 0, 0, 0, 0, 0), HEAP(SBPF_HEAP_BYTES)), "full: zero fits");
    sbpf_rt_reset();
    CHECK(OK(call(sbpf_sys_alloc_free, SBPF_HEAP_BYTES, 0, 0, 0, 0), HEAP(0)), "whole heap");
    sbpf_rt_reset();
    CHECK(OK(call(sbpf_sys_alloc_free, SBPF_HEAP_BYTES + 1, 0, 0, 0, 0), 0), "heap + 1");
    CHECK(sbpf_heap_used == 0, "a failed allocation moves nothing");
    /* A size whose low 32 bits are small: on RV32 `a as usize` truncates it, and only the
     * `a <= HEAP_BYTES` guard refuses it — the guard is not optional. */
    CHECK(OK(call(sbpf_sys_alloc_free, (1ull << 32) + 8, 0, 0, 0, 0), 0), "2^32 + 8");
    CHECK(OK(call(sbpf_sys_alloc_free, UINT64_MAX, 0, 0, 0, 0), 0), "u64 max");
}

static void test_logs_and_traps(void) {
    layout_v1();
    CHECK(OK(call(sbpf_sys_log, IN(0), 13, 0, 0, 0), 0), "log");
    CHECK(AV(call(sbpf_sys_log, IN(120), 9, 0, 0, 0), IN(120)), "log past");
    CHECK(OK(call(sbpf_sys_log, IN(128), 0, 0, 0, 0), 0), "log empty at end");
    CHECK(OK(call(sbpf_sys_log, PROG(0x100), 8, 0, 0, 0), 0), "log rodata");
#if SBPF_USIZE_MAX == 0xffffffffu
    CHECK(AV(call(sbpf_sys_log, IN(0), 1ull << 32, 0, 0, 0), 1ull << 32), "log huge (rv32)");
#else
    CHECK(AV(call(sbpf_sys_log, IN(0), 1ull << 32, 0, 0, 0), IN(0)), "log huge (64-bit)");
#endif
    CHECK(OK(call(sbpf_sys_log_pubkey, IN(96), 0, 0, 0, 0), 0), "pubkey");
    CHECK(AV(call(sbpf_sys_log_pubkey, IN(97), 0, 0, 0, 0), IN(97)), "pubkey past");
    CHECK(OK(call(sbpf_sys_log_64, 1, 2, 3, 4, 5), 0), "log_64");
    CHECK(OK(call(sbpf_sys_log_compute_units, 0x10, 0, 0, 0, 0), 0), "cu");
    CHECK(HALT(call(sbpf_sys_abort, 0, 0, 0, 0, 0), SBPF_HALT_TRAP, SBPF_TRAP_ABORT), "abort");
    CHECK(HALT(call(sbpf_sys_panic, IN(0), 4, 1, 1, 0), SBPF_HALT_TRAP, SBPF_TRAP_SOL_PANIC), "panic");
    /* `sol_panic_` does not look at its arguments. */
    CHECK(HALT(call(sbpf_sys_panic, 0, 1ull << 40, 0, 0, 0), SBPF_HALT_TRAP, SBPF_TRAP_SOL_PANIC),
          "panic, bad args");
}

static uint64_t f_syscall(uint64_t h, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return sbpf_syscall((uint32_t)h, a, b, c, d, 0);
}

static void test_dispatch(void) {
    layout_v1();
    CHECK(OK(call(f_syscall, SBPF_SYSCALL_SOL_MEMSET_, IN(0), 7, 4, 0), 0) && input[3] == 7, "memset");
    CHECK(HALT(call(f_syscall, SBPF_SYSCALL_ABORT, 0, 0, 0, 0), SBPF_HALT_TRAP, SBPF_TRAP_ABORT), "abort");
    CHECK(OK(call(f_syscall, SBPF_SYSCALL_SOL_ALLOC_FREE_, 8, 0, 0, 0), HEAP(0)), "alloc");
    CHECK(HALT(call(f_syscall, 1, 0, 0, 0, 0), SBPF_HALT_UNKNOWN_SYSCALL, 1), "hash 1");
    CHECK(HALT(call(f_syscall, SBPF_SYSCALL_SOL_SECP256K1_RECOVER, 0, 0, 0, 0), SBPF_HALT_UNKNOWN_SYSCALL,
               SBPF_SYSCALL_SOL_SECP256K1_RECOVER),
          "secp256k1 is not the interpreter's");
    /* sol_invoke_signed_c: CPI is an unknown syscall like any other. */
    CHECK(HALT(call(f_syscall, 0xa22b9c85u, 0, 0, 0, 0), SBPF_HALT_UNKNOWN_SYSCALL, 0xa22b9c85u), "cpi");
}

/* ---- sol_sha256 ------------------------------------------------------------------------------- */

static void put_pair(uint8_t *p, uint64_t ptr, uint64_t len) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(ptr >> (8 * i)), p[8 + i] = (uint8_t)(len >> (8 * i));
}
static int hex_eq(const uint8_t *b, const char *hex) {
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1 || b[i] != v) return 0;
    }
    return 1;
}
#define ABC "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
#define EMPTY "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define TWO_BLOCKS "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
#define MILLION_A "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"

static void test_sha256(void) {
    layout_v1();
    /* "abc" as two pieces, across two regions: (input "ab", heap "c"). */
    memset(input, 0, sizeof input);
    input[32] = 'a', input[33] = 'b';
    heap[0] = 'c';
    put_pair(input, IN(32), 2);
    put_pair(input + 16, HEAP(0), 1);
    CHECK(OK(call(sbpf_sys_sha256, IN(0), 2, IN(64), 0, 0), 0), "abc");
    CHECK(hex_eq(input + 64, ABC), "sha256(abc)");
    CHECK(OK(call(sbpf_sys_sha256, IN(0), 0, IN(64), 0, 0), 0) && hex_eq(input + 64, EMPTY), "no pairs");
    put_pair(input, IN(32), 0);
    CHECK(OK(call(sbpf_sys_sha256, IN(0), 1, IN(64), 0, 0), 0) && hex_eq(input + 64, EMPTY), "empty pair");
    /* 56 bytes: the length no longer fits the first block, so the padding takes a second. */
    const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    memcpy(heap + 100, m, 56);
    put_pair(input, HEAP(100), 56);
    CHECK(OK(call(sbpf_sys_sha256, IN(0), 1, IN(64), 0, 0), 0) && hex_eq(input + 64, TWO_BLOCKS), "56");
    /* The same 56 bytes as seven 8-byte pairs laid out in the heap. */
    for (int i = 0; i < 7; i++) put_pair(heap + 200 + 16 * i, HEAP(100 + 8 * i), 8);
    CHECK(OK(call(sbpf_sys_sha256, HEAP(200), 7, IN(64), 0, 0), 0) && hex_eq(input + 64, TWO_BLOCKS),
          "56 in pieces");
    /* A million 'a's: a thousand pairs over one 1000-byte buffer (FIPS 180-2's long vector),
     * whole blocks and partial ones interleaved. The pair list lives in the stack region. */
    memset(heap + 1024, 'a', 1000);
    for (int i = 0; i < 1000; i++) put_pair(stack + 16 * i, HEAP(1024), 1000);
    CHECK(OK(call(sbpf_sys_sha256, STK(0), 1000, IN(64), 0, 0), 0) && hex_eq(input + 64, MILLION_A),
          "a million a");
    /* The checks, in the interpreter's order: the pair array, the result, then each pair's data. */
    layout_v1();
    put_pair(input, IN(200), 1);
    CHECK(AV(call(sbpf_sys_sha256, IN(120), 1, IN(200), 0, 0), IN(120)), "pairs past end first");
    CHECK(AV(call(sbpf_sys_sha256, IN(0), 1, IN(100), 0, 0), IN(100)), "result second");
    CHECK(AV(call(sbpf_sys_sha256, IN(0), 1, IN(64), 0, 0), IN(200)), "data third");
    CHECK(input[64] == 64, "nothing written on a fault");
    CHECK(AV(call(sbpf_sys_sha256, IN(0), 1, PROG(0x100), 0, 0), PROG(0x100)), "result in rodata");
    /* pairs * 16 overflowing the usize is a fault at the pair array. */
    CHECK(AV(call(sbpf_sys_sha256, IN(0), SBPF_USIZE_MAX / 16 + 1, IN(64), 0, 0), IN(0)),
          "pair count overflow");
#if SBPF_USIZE_MAX == 0xffffffffu
    CHECK(AV(call(sbpf_sys_sha256, IN(0), 1ull << 32, IN(64), 0, 0), 1ull << 32), "pairs huge (rv32)");
    put_pair(input, IN(32), 1ull << 32);
    CHECK(AV(call(sbpf_sys_sha256, IN(0), 1, IN(64), 0, 0), 1ull << 32), "pair len huge (rv32)");
#endif
}

/* ---- the crypto known answers ----------------------------------------------------------------- */

static void test_ed25519(void) {
    int n = (int)(sizeof ED25519_VECTORS / sizeof ED25519_VECTORS[0]);
    for (int i = 0; i < n; i++) {
        const ed25519_vector *v = &ED25519_VECTORS[i];
        uint32_t r = sbpf_ed25519_verify(v->pk, v->msg, v->msg_len, v->sig);
        CHECK(r == (v->valid ? 0u : 1u), "ed25519 %s: got %u", v->name, r);
    }
    /* Through the syscall wrapper: RFC TEST 3 laid out in the input region. */
    const ed25519_vector *t3 = &ED25519_VECTORS[2];
    layout_v1();
    memcpy(input, t3->pk, 32);
    memcpy(input + 32, t3->sig, 64);
    memcpy(input + 96, t3->msg, 2);
    CHECK(OK(call(sbpf_sys_ed25519_verify, IN(0), IN(96), 2, IN(32), 0), 0), "wrapper valid");
    CHECK(OK(call(sbpf_sys_ed25519_verify, IN(0), IN(96), 1, IN(32), 0), 1), "wrapper short msg");
    CHECK(AV(call(sbpf_sys_ed25519_verify, IN(100), IN(96), 2, IN(32), 0), IN(100)), "wrapper bad pk");
    CHECK(AV(call(sbpf_sys_ed25519_verify, IN(0), IN(96), 40, IN(32), 0), IN(96)), "wrapper bad msg");
    CHECK(AV(call(sbpf_sys_ed25519_verify, IN(0), IN(96), 2, IN(96), 0), IN(96)), "wrapper bad sig");
    printf("  ed25519: %d vectors\n", n);
}

static void test_secp256k1(void) {
    int n = (int)(sizeof SECP256K1_VECTORS / sizeof SECP256K1_VECTORS[0]);
    for (int i = 0; i < n; i++) {
        const secp256k1_vector *v = &SECP256K1_VECTORS[i];
        uint8_t out[64];
        memset(out, 0, 64);
        uint32_t r = sbpf_secp256k1_recover(v->hash, v->recid, v->sig, out);
        CHECK(r == v->code, "secp256k1 %s: code %u, want %u", v->name, r, (unsigned)v->code);
        CHECK(memcmp(out, v->pubkey, 64) == 0, "secp256k1 %s: key", v->name);
    }
    /* Through the syscall wrapper: the go-ethereum vector. */
    const secp256k1_vector *g = &SECP256K1_VECTORS[0];
    layout_v1();
    memcpy(input, g->hash, 32);
    memcpy(input + 32, g->sig, 64);
    memset(heap, 0xee, 64);
    CHECK(OK(call(sbpf_sys_secp256k1_recover, IN(0), g->recid, IN(32), HEAP(0), 0), 0), "wrapper");
    CHECK(memcmp(heap, g->pubkey, 64) == 0, "wrapper key");
    memset(heap, 0xee, 64);
    CHECK(OK(call(sbpf_sys_secp256k1_recover, IN(0), 4, IN(32), HEAP(0), 0), 2), "wrapper recid");
    CHECK(heap[0] == 0xee, "an error writes nothing");
    /* Agave's order: hash, signature, result. */
    CHECK(AV(call(sbpf_sys_secp256k1_recover, IN(100), 9, IN(100), IN(100), 0), IN(100)), "hash first");
    CHECK(AV(call(sbpf_sys_secp256k1_recover, IN(0), 9, IN(100), PROG(0x100), 0), IN(100)), "sig second");
    CHECK(AV(call(sbpf_sys_secp256k1_recover, IN(0), 9, IN(32), PROG(0x100), 0), PROG(0x100)), "result third");
    printf("  secp256k1: %d vectors\n", n);
}

int main(void) {
    test_regions();
    test_traps();
    test_memcpy_memmove();
    test_memset();
    test_memcmp();
    test_alloc();
    test_logs_and_traps();
    test_dispatch();
    test_sha256();
    test_ed25519();
    test_secp256k1();
    printf("%d checks, %d failures (usize max %#llx)\n", checks, failures,
           (unsigned long long)SBPF_USIZE_MAX);
    return failures != 0;
}
