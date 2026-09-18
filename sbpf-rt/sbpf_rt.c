/* sbpf-rt: regions, traps, the twelve syscalls and SHA-256's padding. See sbpf_rt.h; every
 * function here names the `sbpf-core` code it ports. Freestanding: no libc. */
#include "sbpf_rt.h"

#if defined(__riscv) && __riscv_xlen == 32
#include "guest.h"
#endif

/* `usize` on the machine the interpreter runs on. The guest is RV32, where `usize_of` refuses a
 * length above u32::MAX (faulting with the length as the address); on a 64-bit host every u64 is a
 * usize and the same length faults later, at the bounds check, with the pointer. A translated
 * program must agree with the interpreter *on the same machine*, so this follows the target's own
 * `size_t`; the host suite also builds with `-DSBPF_USIZE_MAX=0xffffffffu` to check the RV32 path. */
#ifndef SBPF_USIZE_MAX
#define SBPF_USIZE_MAX SIZE_MAX
#endif

sbpf_regions sbpf_r;
int64_t sbpf_budget;
uint32_t sbpf_heap_used;
uint32_t sbpf_halt_code;
uint64_t sbpf_halt_arg;

void sbpf_rt_reset(void) {
    sbpf_budget = SBPF_MAX_INSTRUCTIONS;
    sbpf_heap_used = 0;
    sbpf_halt_code = SBPF_HALT_EXIT;
    sbpf_halt_arg = 0;
}

void sbpf_trap(uint32_t halt_code, uint64_t arg) {
    sbpf_halt_code = halt_code;
    sbpf_halt_arg = arg;
    sbpf_rt_unwind();
}

/* ---- memory.rs ------------------------------------------------------------------------------- */

/* `Memory::slice`: the region is the top 32 bits, the offset the low 32. `end = off + len` is
 * computed in 64 bits, where it cannot wrap unless `len` is within 2^32 of u64::MAX — the
 * `checked_add` failure, which is the same AccessViolation(addr). */
static const uint8_t *slice(uint64_t addr, uint64_t len, int writable) {
    uint64_t off = addr & 0xffffffffull;
    if (len > UINT64_MAX - off) sbpf_trap(SBPF_HALT_ACCESS_VIOLATION, addr);
    uint64_t end = off + len;
    uint8_t *base;
    uint64_t size;
    switch (addr >> 32) {
    case 1: {
        if (writable) break;
        /* Two overlapping spans; the read-only run first, then the text. */
        uint64_t rbase = sbpf_r.rodata_va & 0xffffffffull;
        if (off >= rbase && end <= rbase + sbpf_r.rodata_len) return sbpf_r.rodata + (off - rbase);
        uint64_t tbase = sbpf_r.text_va & 0xffffffffull;
        if (off >= tbase && end <= tbase + sbpf_r.text_len) return sbpf_r.text + (off - tbase);
        break;
    }
    case 2:
        base = sbpf_r.stack, size = SBPF_STACK_BYTES;
        goto bounded;
    case 3:
        base = sbpf_r.heap, size = SBPF_HEAP_BYTES;
        goto bounded;
    case 4:
        base = sbpf_r.input, size = sbpf_r.input_len;
    bounded:
        if (end <= size) return base + off;
        break;
    default:
        break;
    }
    sbpf_trap(SBPF_HALT_ACCESS_VIOLATION, addr);
}

const uint8_t *sbpf_tr_ro(uint64_t addr, uint64_t len) { return slice(addr, len, 0); }
uint8_t *sbpf_tr_rw(uint64_t addr, uint64_t len) { return (uint8_t *)slice(addr, len, 1); }

uint64_t sbpf_load(uint64_t addr, uint32_t size) {
    if (size > 8) size = 8;
    const uint8_t *p = slice(addr, size, 0);
    uint64_t v = 0;
    for (uint32_t i = 0; i < size; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

void sbpf_store(uint64_t addr, uint32_t size, uint64_t v) {
    if (size > 8) size = 8;
    uint8_t *p = (uint8_t *)slice(addr, size, 1);
    for (uint32_t i = 0; i < size; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* `(regs[r] as i64).wrapping_add(off as i64) as u64`. */
static uint64_t at(uint64_t base, int32_t off) { return base + (uint64_t)(int64_t)off; }

uint64_t sbpf_ld1(uint64_t base, int32_t off) { return sbpf_load(at(base, off), 1); }
uint64_t sbpf_ld2(uint64_t base, int32_t off) { return sbpf_load(at(base, off), 2); }
uint64_t sbpf_ld4(uint64_t base, int32_t off) { return sbpf_load(at(base, off), 4); }
uint64_t sbpf_ld8(uint64_t base, int32_t off) { return sbpf_load(at(base, off), 8); }
void sbpf_st1(uint64_t base, int32_t off, uint64_t v) { sbpf_store(at(base, off), 1, v); }
void sbpf_st2(uint64_t base, int32_t off, uint64_t v) { sbpf_store(at(base, off), 2, v); }
void sbpf_st4(uint64_t base, int32_t off, uint64_t v) { sbpf_store(at(base, off), 4, v); }
void sbpf_st8(uint64_t base, int32_t off, uint64_t v) { sbpf_store(at(base, off), 8, v); }

/* `Memory::nonoverlapping`. */
static int nonoverlapping(uint64_t a, uint64_t b, uint64_t n) {
    return a > b ? a - b >= n : b - a >= n;
}

/* ---- syscalls.rs ----------------------------------------------------------------------------- */

/* `usize_of`: a guest length as a usize, or AccessViolation(n) — the length, not a pointer. */
static uint64_t usize_of(uint64_t n) {
#if SBPF_USIZE_MAX < 0xffffffffffffffffull
    if (n > (uint64_t)SBPF_USIZE_MAX) sbpf_trap(SBPF_HALT_ACCESS_VIOLATION, n);
#endif
    return n;
}

uint64_t sbpf_sys_abort(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r1, (void)r2, (void)r3, (void)r4, (void)r5;
    sbpf_trap(SBPF_HALT_TRAP, SBPF_TRAP_ABORT);
}

uint64_t sbpf_sys_panic(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r1, (void)r2, (void)r3, (void)r4, (void)r5;
    sbpf_trap(SBPF_HALT_TRAP, SBPF_TRAP_SOL_PANIC);
}

/* The log family writes nothing, but its pointer arguments are still translated. */
uint64_t sbpf_sys_log(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r3, (void)r4, (void)r5;
    slice(r1, usize_of(r2), 0);
    return 0;
}

uint64_t sbpf_sys_log_pubkey(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r2, (void)r3, (void)r4, (void)r5;
    slice(r1, 32, 0);
    return 0;
}

uint64_t sbpf_sys_log_64(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r1, (void)r2, (void)r3, (void)r4, (void)r5;
    return 0;
}

uint64_t sbpf_sys_log_compute_units(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r1, (void)r2, (void)r3, (void)r4, (void)r5;
    return 0;
}

/* `SOL_MEMCPY | SOL_MEMMOVE`: the length is a usize first, then memcpy's overlap refusal (before
 * either range is translated), then the source range, then the destination. The copy runs
 * backwards exactly when the destination is the higher of two overlapping ranges — the
 * interpreter's 64-byte chunks through a buffer give the same bytes as this byte loop in either
 * direction, since each chunk is read whole before it is written. */
static uint64_t copy(uint64_t dst, uint64_t src, uint64_t c, int is_memcpy) {
    uint64_t n = usize_of(c);
    if (is_memcpy && !nonoverlapping(dst, src, c)) sbpf_trap(SBPF_HALT_TRAP, SBPF_TRAP_MEMCPY_OVERLAP);
    const uint8_t *s = slice(src, n, 0);
    uint8_t *d = (uint8_t *)slice(dst, n, 1);
    if (dst > src && !nonoverlapping(dst, src, c)) {
        for (uint64_t i = n; i > 0; i--) d[i - 1] = s[i - 1];
    } else {
        for (uint64_t i = 0; i < n; i++) d[i] = s[i];
    }
    return 0;
}

uint64_t sbpf_sys_memcpy(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r4, (void)r5;
    return copy(r1, r2, r3, 1);
}

uint64_t sbpf_sys_memmove(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r4, (void)r5;
    return copy(r1, r2, r3, 0);
}

uint64_t sbpf_sys_memset(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r4, (void)r5;
    uint64_t n = usize_of(r3);
    uint8_t *d = (uint8_t *)slice(r1, n, 1);
    for (uint64_t i = 0; i < n; i++) d[i] = (uint8_t)r2;
    return 0;
}

/* `SOL_MEMCMP(a, b, n, result)`: a, b and the four result bytes are all translated before a byte is
 * read; the result is the signed difference of the first unequal (unsigned) bytes, or 0, written
 * as a little-endian i32. */
uint64_t sbpf_sys_memcmp(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r5;
    uint64_t n = usize_of(r3);
    const uint8_t *a = slice(r1, n, 0);
    const uint8_t *b = slice(r2, n, 0);
    slice(r4, 4, 1);
    int32_t result = 0;
    for (uint64_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            result = (int32_t)a[i] - (int32_t)b[i];
            break;
        }
    }
    /* Translated again for the write: the interpreter's `slice_mut(d, 4)` after the loop. */
    uint8_t *d = (uint8_t *)slice(r4, 4, 1);
    uint32_t u = (uint32_t)result;
    for (int i = 0; i < 4; i++) d[i] = (uint8_t)(u >> (8 * i));
    return 0;
}

/* `SOL_ALLOC_FREE(size, free_addr)`: a bump allocator; a free (non-zero second argument) is a no-op
 * returning 0, an allocation 8-aligns the cursor and returns null if it does not fit. The
 * `size <= HEAP_BYTES` guard is on the whole u64: on RV32 `a as usize` truncates, and only the
 * guard stops a size like 2^32 + 8 from being taken for 8. */
uint64_t sbpf_sys_alloc_free(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r3, (void)r4, (void)r5;
    if (r2 != 0) return 0;
    uint64_t base = ((uint64_t)sbpf_heap_used + 7) & ~(uint64_t)7;
    if (r1 > SBPF_HEAP_BYTES) return 0;
    uint64_t end = base + r1;
    if (end > SBPF_HEAP_BYTES) return 0;
    sbpf_heap_used = (uint32_t)end;
    return SBPF_REGION_HEAP + base;
}

/* ---- SHA-256 (lib.rs `Sha256`) ------------------------------------------------------------------
 * The padding and chaining over `sbpf_sha256_compress`, byte-identical to `sbpf_core::Sha256` (and
 * to `guest_sdk::sha256`): words 0..16 the block as big-endian words, 16..24 the running state. */
typedef struct {
    uint32_t buf[24];
    uint8_t block[64];
    uint32_t fill;
    uint64_t len;
} sha256_ctx;

static void sha_init(sha256_ctx *s) {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    for (int i = 0; i < 8; i++) s->buf[16 + i] = iv[i];
    s->fill = 0;
    s->len = 0;
}

static void sha_block(sha256_ctx *s, const uint8_t *b) {
    for (int i = 0; i < 16; i++)
        s->buf[i] = (uint32_t)b[4 * i] << 24 | (uint32_t)b[4 * i + 1] << 16 |
                    (uint32_t)b[4 * i + 2] << 8 | (uint32_t)b[4 * i + 3];
    sbpf_sha256_compress(s->buf);
}

static void sha_update(sha256_ctx *s, const uint8_t *p, uint64_t n) {
    s->len += n;
    uint64_t off = 0;
    if (s->fill != 0) {
        uint64_t take = 64 - s->fill < n ? 64 - s->fill : n;
        for (uint64_t i = 0; i < take; i++) s->block[s->fill + i] = p[i];
        s->fill += (uint32_t)take;
        off = take;
        if (s->fill == 64) {
            sha_block(s, s->block);
            s->fill = 0;
        }
    }
    while (off + 64 <= n) {
        sha_block(s, p + off);
        off += 64;
    }
    for (uint64_t i = off; i < n; i++) s->block[i - off] = p[i];
    if (off < n) s->fill = (uint32_t)(n - off);
}

static void sha_finish(sha256_ctx *s, uint8_t out[32]) {
    uint32_t rest = s->fill;
    for (uint32_t i = rest; i < 64; i++) s->block[i] = 0;
    s->block[rest] = 0x80;
    if (rest >= 56) {
        sha_block(s, s->block);
        for (int i = 0; i < 64; i++) s->block[i] = 0;
    }
    uint64_t bits = s->len * 8;
    for (int i = 0; i < 8; i++) s->block[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    sha_block(s, s->block);
    for (int i = 0; i < 8; i++) {
        uint32_t w = s->buf[16 + i];
        out[4 * i] = (uint8_t)(w >> 24), out[4 * i + 1] = (uint8_t)(w >> 16);
        out[4 * i + 2] = (uint8_t)(w >> 8), out[4 * i + 3] = (uint8_t)w;
    }
}

#if defined(__riscv) && __riscv_xlen == 32
/* The coprocessor: `rand_sha256_compress` takes the 24 words' *word* address (guest.h). */
void sbpf_sha256_compress(uint32_t w[24]) { rand_sha256_compress(w); }
#endif

/* `SOL_SHA256(vals, vals_len, result)`: the pair count is a usize, `16 * count` must not overflow
 * one (AccessViolation(vals) if it does), then the whole pair array and the 32-byte result are
 * translated; then each pair's length is a usize and its data is translated and hashed in turn. The
 * digest is written last. */
uint64_t sbpf_sys_sha256(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r4, (void)r5;
    uint64_t pairs = usize_of(r2);
    if (pairs > (uint64_t)SBPF_USIZE_MAX / 16) sbpf_trap(SBPF_HALT_ACCESS_VIOLATION, r1);
    const uint8_t *vals = slice(r1, pairs * 16, 0);
    slice(r3, 32, 1);
    sha256_ctx s;
    sha_init(&s);
    for (uint64_t p = 0; p < pairs; p++) {
        const uint8_t *pair = vals + 16 * p;
        uint64_t ptr = 0, len = 0;
        for (int i = 0; i < 8; i++) {
            ptr |= (uint64_t)pair[i] << (8 * i);
            len |= (uint64_t)pair[8 + i] << (8 * i);
        }
        len = usize_of(len);
        sha_update(&s, slice(ptr, len, 0), len);
    }
    uint8_t digest[32];
    sha_finish(&s, digest);
    uint8_t *out = (uint8_t *)slice(r3, 32, 1);
    for (int i = 0; i < 32; i++) out[i] = digest[i];
    return 0;
}

/* ---- dispatch -------------------------------------------------------------------------------- */

uint64_t sbpf_syscall(uint32_t hash, uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    switch (hash) {
    case SBPF_SYSCALL_ABORT: return sbpf_sys_abort(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_PANIC_: return sbpf_sys_panic(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_LOG_: return sbpf_sys_log(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_LOG_64_: return sbpf_sys_log_64(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_LOG_COMPUTE_UNITS_: return sbpf_sys_log_compute_units(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_LOG_PUBKEY: return sbpf_sys_log_pubkey(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_MEMCPY_: return sbpf_sys_memcpy(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_MEMMOVE_: return sbpf_sys_memmove(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_MEMSET_: return sbpf_sys_memset(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_MEMCMP_: return sbpf_sys_memcmp(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_ALLOC_FREE_: return sbpf_sys_alloc_free(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_SHA256: return sbpf_sys_sha256(r1, r2, r3, r4, r5);
    default: sbpf_trap(SBPF_HALT_UNKNOWN_SYSCALL, hash);
    }
}

/* ---- the non-local exit, RV32 ------------------------------------------------------------------
 * A minimal setjmp/longjmp over what the ILP32 calling convention makes callee-saved: ra, sp and
 * s0-s11 (this machine has no float registers). `sbpf_rt_enter` is the only frame that ever calls
 * `sbpf_setjmp`, and it stays live for the whole run, so the jump always lands in a live frame. */
#if defined(__riscv) && __riscv_xlen == 32
__attribute__((returns_twice)) int sbpf_setjmp(uint32_t *buf);
__attribute__((noreturn)) void sbpf_longjmp(uint32_t *buf, int v);

__asm__(".section .text.sbpf_setjmp,\"ax\",@progbits\n"
        ".globl sbpf_setjmp\n"
        ".type sbpf_setjmp,@function\n"
        ".p2align 2\n"
        "sbpf_setjmp:\n"
        "  sw ra, 0(a0)\n  sw sp, 4(a0)\n  sw s0, 8(a0)\n  sw s1, 12(a0)\n"
        "  sw s2, 16(a0)\n  sw s3, 20(a0)\n  sw s4, 24(a0)\n  sw s5, 28(a0)\n"
        "  sw s6, 32(a0)\n  sw s7, 36(a0)\n  sw s8, 40(a0)\n  sw s9, 44(a0)\n"
        "  sw s10, 48(a0)\n  sw s11, 52(a0)\n"
        "  li a0, 0\n"
        "  ret\n"
        ".size sbpf_setjmp, .-sbpf_setjmp\n"
        ".section .text.sbpf_longjmp,\"ax\",@progbits\n"
        ".globl sbpf_longjmp\n"
        ".type sbpf_longjmp,@function\n"
        ".p2align 2\n"
        "sbpf_longjmp:\n"
        "  lw ra, 0(a0)\n  lw sp, 4(a0)\n  lw s0, 8(a0)\n  lw s1, 12(a0)\n"
        "  lw s2, 16(a0)\n  lw s3, 20(a0)\n  lw s4, 24(a0)\n  lw s5, 28(a0)\n"
        "  lw s6, 32(a0)\n  lw s7, 36(a0)\n  lw s8, 40(a0)\n  lw s9, 44(a0)\n"
        "  lw s10, 48(a0)\n  lw s11, 52(a0)\n"
        "  seqz a0, a1\n"
        "  add a0, a0, a1\n" /* setjmp's second return is never 0 */
        "  ret\n"
        ".size sbpf_longjmp, .-sbpf_longjmp\n"
        ".text\n");

static uint32_t sbpf_jmp[14];

uint32_t sbpf_rt_enter(sbpf_fn entry, uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4,
                       uint64_t r5, uint64_t *r0) {
    sbpf_halt_code = SBPF_HALT_EXIT;
    sbpf_halt_arg = 0;
    if (sbpf_setjmp(sbpf_jmp) == 0) {
        uint64_t v = entry(r1, r2, r3, r4, r5);
        *r0 = v;
        return SBPF_HALT_EXIT;
    }
    return sbpf_halt_code;
}

void sbpf_rt_unwind(void) { sbpf_longjmp(sbpf_jmp, 1); }
#endif
