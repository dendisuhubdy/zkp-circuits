/* sbpf-rt: regions, traps, the eighteen syscalls and the two hashes' padding. See sbpf_rt.h; every
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
int32_t sbpf_budget;
uint32_t sbpf_heap_used;
uint32_t sbpf_cu;
uint32_t sbpf_return_len;
uint32_t sbpf_halt_code;
uint64_t sbpf_halt_arg;

void sbpf_rt_reset(void) {
    sbpf_budget = SBPF_MAX_INSTRUCTIONS;
    sbpf_heap_used = 0;
    sbpf_cu = 0;
    sbpf_return_len = 0;
    sbpf_halt_code = SBPF_HALT_EXIT;
    sbpf_halt_arg = 0;
}

void sbpf_trap(uint32_t halt_code, uint64_t arg) {
    sbpf_halt_code = halt_code;
    sbpf_halt_arg = arg;
    sbpf_rt_unwind();
}

uint32_t sbpf_rt_settle(uint32_t code) {
    if (code == SBPF_HALT_EXIT && sbpf_budget < (int32_t)sbpf_cu) {
        sbpf_halt_code = SBPF_HALT_INSTRUCTION_LIMIT;
        sbpf_halt_arg = 0;
        return SBPF_HALT_INSTRUCTION_LIMIT;
    }
    return code;
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

/* The narrow entries return and take 32 bits: a 1-, 2- or 4-byte load is zero-extended, so its
 * high word is zero and the caller, told so by the type, need not carry it; a narrow store writes
 * only the value's low bytes, so the caller need not pass the rest. */
uint32_t sbpf_ld1(uint64_t base, int32_t off) { return (uint32_t)sbpf_load(at(base, off), 1); }
uint32_t sbpf_ld2(uint64_t base, int32_t off) { return (uint32_t)sbpf_load(at(base, off), 2); }
uint32_t sbpf_ld4(uint64_t base, int32_t off) { return (uint32_t)sbpf_load(at(base, off), 4); }
uint64_t sbpf_ld8(uint64_t base, int32_t off) { return sbpf_load(at(base, off), 8); }
void sbpf_st1(uint64_t base, int32_t off, uint32_t v) { sbpf_store(at(base, off), 1, v); }
void sbpf_st2(uint64_t base, int32_t off, uint32_t v) { sbpf_store(at(base, off), 2, v); }
void sbpf_st4(uint64_t base, int32_t off, uint32_t v) { sbpf_store(at(base, off), 4, v); }
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

/* `Vm::consume` for the length-dependent part of a syscall's charge (see `sbpf_cu`): refuses a
 * charge that would take the syscalls' total past the budget, so `sbpf_cu` never exceeds it. */
static void charge(uint64_t units) {
    if (units > (uint64_t)(SBPF_MAX_INSTRUCTIONS - sbpf_cu)) {
        sbpf_cu = SBPF_MAX_INSTRUCTIONS; /* Agave zeroes what is left when a charge fails */
        sbpf_trap(SBPF_HALT_INSTRUCTION_LIMIT, 0);
    }
    sbpf_cu += (uint32_t)units;
}

/* `mem_op_extra`: what a memory syscall over `n` bytes costs above its base. `n` is a usize by now
 * (`usize_of`), so on RV32 the division is the machine's own 32-bit one. */
static uint64_t mem_op_extra(uint64_t n) {
    size_t units = (size_t)n / SBPF_CU_BYTES_PER_UNIT;
    return units > SBPF_CU_MEM_OP_BASE ? units - SBPF_CU_MEM_OP_BASE : 0;
}

uint32_t sbpf_base_cost(uint32_t hash) {
    switch (hash) {
    case SBPF_SYSCALL_SOL_LOG_:
    case SBPF_SYSCALL_SOL_LOG_64_:
    case SBPF_SYSCALL_SOL_LOG_COMPUTE_UNITS_:
    case SBPF_SYSCALL_SOL_LOG_PUBKEY:
    case SBPF_SYSCALL_SOL_SET_RETURN_DATA:
    case SBPF_SYSCALL_SOL_GET_RETURN_DATA: return SBPF_CU_SYSCALL_BASE;
    case SBPF_SYSCALL_SOL_MEMCPY_:
    case SBPF_SYSCALL_SOL_MEMMOVE_:
    case SBPF_SYSCALL_SOL_MEMSET_:
    case SBPF_SYSCALL_SOL_MEMCMP_: return SBPF_CU_MEM_OP_BASE;
    case SBPF_SYSCALL_SOL_SHA256:
    case SBPF_SYSCALL_SOL_KECCAK256: return SBPF_CU_HASH_BASE;
    case SBPF_SYSCALL_SOL_GET_CLOCK_SYSVAR: return SBPF_CU_SYSVAR_BASE + SBPF_CLOCK_BYTES;
    case SBPF_SYSCALL_SOL_GET_RENT_SYSVAR: return SBPF_CU_SYSVAR_BASE + SBPF_RENT_STRUCT_BYTES;
    case SBPF_SYSCALL_SOL_GET_SYSVAR: return SBPF_CU_SYSVAR_BASE + SBPF_CU_MEM_OP_BASE;
    default: return 0;
    }
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
    uint64_t n = usize_of(r2);
    if (n > SBPF_CU_SYSCALL_BASE) charge(n - SBPF_CU_SYSCALL_BASE);
    slice(r1, n, 0);
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
    charge(mem_op_extra(n));
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
    charge(mem_op_extra(n));
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
    charge(mem_op_extra(n));
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

/* ---- Keccak-256 (lib.rs `Keccak256`) -----------------------------------------------------------
 * The sponge over `sbpf_keccak_f`: rate 136 bytes, each byte XORed into the state word it belongs
 * to, `0x01 … 0x80` padding, the digest the state's first 32 bytes. */
typedef struct {
    uint32_t st[50];
    uint32_t fill;
} keccak_ctx;

static void keccak_xor(keccak_ctx *k, uint32_t at, uint8_t b) { k->st[at >> 2] ^= (uint32_t)b << (8 * (at & 3)); }

static void keccak_init(keccak_ctx *k) {
    for (int i = 0; i < 50; i++) k->st[i] = 0;
    k->fill = 0;
}

static void keccak_update(keccak_ctx *k, const uint8_t *p, uint64_t n) {
    for (uint64_t i = 0; i < n; i++) {
        keccak_xor(k, k->fill, p[i]);
        if (++k->fill == 136) {
            sbpf_keccak_f(k->st);
            k->fill = 0;
        }
    }
}

static void keccak_finish(keccak_ctx *k, uint8_t out[32]) {
    keccak_xor(k, k->fill, 0x01);
    keccak_xor(k, 135, 0x80);
    sbpf_keccak_f(k->st);
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(k->st[i >> 2] >> (8 * (i & 3)));
}

#if defined(__riscv) && __riscv_xlen == 32
/* The coprocessor: `rand_keccak` takes the 50 words' *word* address (guest.h). */
void sbpf_keccak_f(uint32_t st[50]) { rand_keccak(st); }
#endif

/* `hash_slices`, for `SOL_SHA256(vals, vals_len, result)` and `SOL_KECCAK256`: the pair count is a
 * usize, `16 * count` must not overflow one (AccessViolation(vals) if it does), then the whole pair
 * array and the 32-byte result are translated; then each pair's length is a usize, the slice is
 * charged `max(10, len / 2)`, and its data is translated and hashed in turn. The digest is written
 * last. Always inlined, so each syscall carries only its own hash. */
static inline __attribute__((always_inline)) uint64_t hash_slices(uint64_t r1, uint64_t r2, uint64_t r3,
                                                                  int keccak) {
    uint64_t pairs = usize_of(r2);
    if (pairs > (uint64_t)SBPF_USIZE_MAX / 16) sbpf_trap(SBPF_HALT_ACCESS_VIOLATION, r1);
    const uint8_t *vals = slice(r1, pairs * 16, 0);
    slice(r3, 32, 1);
    sha256_ctx s;
    keccak_ctx k;
    if (keccak) keccak_init(&k);
    else sha_init(&s);
    for (uint64_t p = 0; p < pairs; p++) {
        const uint8_t *pair = vals + 16 * p;
        uint64_t ptr = 0, len = 0;
        for (int i = 0; i < 8; i++) {
            ptr |= (uint64_t)pair[i] << (8 * i);
            len |= (uint64_t)pair[8 + i] << (8 * i);
        }
        len = usize_of(len);
        size_t units = (size_t)len / 2;
        charge(units > SBPF_CU_MEM_OP_BASE ? units : SBPF_CU_MEM_OP_BASE);
        const uint8_t *data = slice(ptr, len, 0);
        if (keccak) keccak_update(&k, data, len);
        else sha_update(&s, data, len);
    }
    uint8_t digest[32];
    if (keccak) keccak_finish(&k, digest);
    else sha_finish(&s, digest);
    uint8_t *out = (uint8_t *)slice(r3, 32, 1);
    for (int i = 0; i < 32; i++) out[i] = digest[i];
    return 0;
}

uint64_t sbpf_sys_sha256(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r4, (void)r5;
    return hash_slices(r1, r2, r3, 0);
}

uint64_t sbpf_sys_keccak256(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r4, (void)r5;
    return hash_slices(r1, r2, r3, 1);
}

/* ---- return data ----------------------------------------------------------------------------- */

/* `SOL_SET_RETURN_DATA(data, len)`: the length is a usize and is charged `len / 250`; more than
 * `SBPF_MAX_RETURN_DATA` traps; a zero length clears without translating the pointer. */
uint64_t sbpf_sys_set_return_data(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r3, (void)r4, (void)r5;
    uint64_t n = usize_of(r2);
    charge((size_t)n / SBPF_CU_BYTES_PER_UNIT);
    if (n > SBPF_MAX_RETURN_DATA) sbpf_trap(SBPF_HALT_TRAP, SBPF_TRAP_RETURN_DATA_TOO_LARGE);
    if (n != 0) {
        const uint8_t *src = slice(r1, n, 0);
        for (uint64_t i = 0; i < n; i++) sbpf_r.return_data[i] = src[i];
    }
    sbpf_return_len = (uint32_t)n;
    return 0;
}

/* `SOL_GET_RETURN_DATA(data, len, program_id)`: `min(len, set)` bytes and the program id, both
 * ranges translated before either is written and refused if they overlap; nothing is translated
 * when nothing is copied. Returns the number of bytes set. */
uint64_t sbpf_sys_get_return_data(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r4, (void)r5;
    uint64_t set = sbpf_return_len;
    uint64_t n = r2 < set ? r2 : set;
    if (n != 0) {
        charge(((size_t)n + 32) / SBPF_CU_BYTES_PER_UNIT);
        uint8_t *d = (uint8_t *)slice(r1, n, 1);
        uint8_t *id = (uint8_t *)slice(r3, 32, 1);
        if (!(r1 > r3 ? r1 - r3 >= 32 : r3 - r1 >= n)) sbpf_trap(SBPF_HALT_TRAP, SBPF_TRAP_RETURN_DATA_OVERLAP);
        for (uint64_t i = 0; i < n; i++) d[i] = sbpf_r.return_data[i];
        for (int i = 0; i < 32; i++) id[i] = sbpf_r.program_id[i];
    }
    return set;
}

/* ---- sysvars --------------------------------------------------------------------------------- */

/* `SOL_GET_CLOCK_SYSVAR | SOL_GET_RENT_SYSVAR`: the address must be 8-aligned (AccessViolation),
 * then `size` bytes are translated, then the block must be present; `fields` bytes come from the
 * block at `from` and the rest of the struct (Rent's padding) is zero. */
static uint64_t sysvar_struct(uint64_t addr, uint32_t from, uint32_t fields, uint32_t size) {
    if (addr & 7) sbpf_trap(SBPF_HALT_ACCESS_VIOLATION, addr);
    uint8_t *d = (uint8_t *)slice(addr, size, 1);
    if (sbpf_r.sysvars_len != SBPF_SYSVAR_BYTES) sbpf_trap(SBPF_HALT_TRAP, SBPF_TRAP_SYSVAR_UNAVAILABLE);
    for (uint32_t i = 0; i < size; i++) d[i] = i < fields ? sbpf_r.sysvars[from + i] : 0;
    return 0;
}

uint64_t sbpf_sys_get_clock_sysvar(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r2, (void)r3, (void)r4, (void)r5;
    return sysvar_struct(r1, 0, SBPF_CLOCK_BYTES, SBPF_CLOCK_BYTES);
}

uint64_t sbpf_sys_get_rent_sysvar(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r2, (void)r3, (void)r4, (void)r5;
    return sysvar_struct(r1, SBPF_CLOCK_BYTES, SBPF_RENT_BYTES, SBPF_RENT_STRUCT_BYTES);
}

/* `syscalls::CLOCK_ID` and `RENT_ID` differ only in bytes 4..28; the first four and the last four
 * are `06 a7 d5 17` and zeros in both. */
static const uint8_t sysvar_ids[2][24] = {
    {24, 199, 116, 201, 40, 86, 99, 152, 105, 29, 94, 182, 139, 94, 184, 163, 155, 75, 109, 92, 115, 85, 91, 33},
    {25, 44, 92, 81, 33, 140, 201, 76, 61, 74, 241, 127, 88, 218, 238, 8, 155, 161, 253, 68, 227, 219, 217, 138},
};

/* Which sysvar `id` names: 0 for Clock, 1 for Rent, -1 for anything else. */
static int sysvar_index(const uint8_t *id) {
    static const uint8_t head[4] = {6, 167, 213, 23};
    for (int i = 0; i < 4; i++)
        if (id[i] != head[i] || id[28 + i] != 0) return -1;
    for (int which = 0; which < 2; which++) {
        int same = 1;
        for (int i = 0; i < 24; i++) same &= id[4 + i] == sysvar_ids[which][i];
        if (same) return which;
    }
    return -1;
}

/* `SOL_GET_SYSVAR(sysvar_id, var, offset, length)`: the length is a usize and is charged; the id
 * and the destination are translated; `offset + length` must not overflow (AccessViolation(offset));
 * an id other than Clock's or Rent's, or an absent block, traps; a range past the sysvar's end
 * returns 1 and writes nothing. */
uint64_t sbpf_sys_get_sysvar(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    (void)r5;
    uint64_t n = usize_of(r4);
    charge(mem_op_extra(n));
    int which = sysvar_index(slice(r1, 32, 0));
    uint8_t *d = (uint8_t *)slice(r2, n, 1);
    if (r4 > UINT64_MAX - r3) sbpf_trap(SBPF_HALT_ACCESS_VIOLATION, r3);
    if (which < 0 || sbpf_r.sysvars_len != SBPF_SYSVAR_BYTES) sbpf_trap(SBPF_HALT_TRAP, SBPF_TRAP_SYSVAR_UNAVAILABLE);
    uint32_t from = which ? SBPF_CLOCK_BYTES : 0;
    uint32_t len = which ? SBPF_RENT_BYTES : SBPF_CLOCK_BYTES;
    if (r3 + r4 > len) return 1;
    for (uint64_t i = 0; i < n; i++) d[i] = sbpf_r.sysvars[from + r3 + i];
    return 0;
}

/* ---- dispatch -------------------------------------------------------------------------------- */

uint64_t sbpf_syscall(uint32_t hash, uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {
    charge(sbpf_base_cost(hash));
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
    case SBPF_SYSCALL_SOL_KECCAK256: return sbpf_sys_keccak256(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_SET_RETURN_DATA: return sbpf_sys_set_return_data(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_GET_RETURN_DATA: return sbpf_sys_get_return_data(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_GET_CLOCK_SYSVAR: return sbpf_sys_get_clock_sysvar(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_GET_RENT_SYSVAR: return sbpf_sys_get_rent_sysvar(r1, r2, r3, r4, r5);
    case SBPF_SYSCALL_SOL_GET_SYSVAR: return sbpf_sys_get_sysvar(r1, r2, r3, r4, r5);
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
