/* The C guest runtime: the handful of functions clang calls on its own even under
 * `-ffreestanding -fno-builtin`, which do not exist on this machine otherwise (there is no libc
 * and no compiler-rt). `rand-guest build --lang c` writes this file next to `guest.h` and
 * `start.S`, compiles it with the same flags as the guest and links it into every C guest; with
 * `--gc-sections` only the functions a guest actually calls reach its image.
 *
 *  - `memcpy`, `memmove`, `memset`, `memcmp`: a struct copy or assignment, a large zero
 *    initialiser, and `__builtin_mem*` all lower to calls to these; `-fno-builtin` stops the
 *    compiler *recognising* them, not *emitting* them.
 *  - `__udivdi3`, `__umoddi3`, `__divdi3`, `__moddi3`: RV32IM divides 32-bit values only, so every
 *    64-bit `/` and `%` by a value not known at compile time is a call to one of these.
 *
 * Each is written so that it cannot itself compile to a libcall — byte loops (the compiler may not
 * turn them back into `memcpy`/`memset` under `-fno-builtin`) and shift-subtract division, whose
 * 64-bit shifts, compares and subtracts RV32IM does inline. `llvm-nm` on the object shows no
 * undefined symbols. None of this is fast; a guest that copies or divides in a hot loop should do
 * it in words. */
#include <stddef.h>
#include <stdint.h>

void *memcpy(void *restrict dst, const void *restrict src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    if (d < s) {
        for (size_t i = 0; i < n; i++) {
            d[i] = s[i];
        }
    } else {
        for (size_t i = n; i > 0; i--) {
            d[i - 1] = s[i - 1];
        }
    }
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    unsigned char *d = dst;
    for (size_t i = 0; i < n; i++) {
        d[i] = (unsigned char)c;
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = a, *y = b;
    for (size_t i = 0; i < n; i++) {
        if (x[i] != y[i]) {
            return x[i] < y[i] ? -1 : 1;
        }
    }
    return 0;
}

/* Restoring shift-subtract division, one quotient bit per step, most significant first. Division
 * by zero gives quotient all ones and remainder `n`, RISC-V's own `divu`/`remu` convention. */
static uint64_t udivmod64(uint64_t n, uint64_t d, uint64_t *rem) {
    if (d == 0) {
        *rem = n;
        return ~(uint64_t)0;
    }
    uint64_t q = 0, r = 0;
    for (int i = 63; i >= 0; i--) {
        r = (r << 1) | ((n >> i) & 1);
        if (r >= d) {
            r -= d;
            q |= (uint64_t)1 << i;
        }
    }
    *rem = r;
    return q;
}

uint64_t __udivdi3(uint64_t n, uint64_t d) {
    uint64_t r;
    return udivmod64(n, d, &r);
}

uint64_t __umoddi3(uint64_t n, uint64_t d) {
    uint64_t r;
    udivmod64(n, d, &r);
    return r;
}

/* C's truncating division: the quotient's sign is the operands' signs combined, the remainder's
 * is the dividend's. Magnitudes are taken as unsigned so `INT64_MIN` negates without overflow. */
int64_t __divdi3(int64_t n, int64_t d) {
    uint64_t un = n < 0 ? -(uint64_t)n : (uint64_t)n;
    uint64_t ud = d < 0 ? -(uint64_t)d : (uint64_t)d;
    uint64_t r;
    uint64_t q = udivmod64(un, ud, &r);
    return (int64_t)((n < 0) != (d < 0) ? -q : q);
}

int64_t __moddi3(int64_t n, int64_t d) {
    uint64_t un = n < 0 ? -(uint64_t)n : (uint64_t)n;
    uint64_t ud = d < 0 ? -(uint64_t)d : (uint64_t)d;
    uint64_t r;
    udivmod64(un, ud, &r);
    return (int64_t)(n < 0 ? -r : r);
}
