/* The Rand zkVM syscall wrappers for a C guest — the C twin of `guest-sdk/src/lib.rs`, which is
 * the authority for every register here. The ABI (`research/docs/01-isa.md`): the syscall number
 * in `a7`, the first argument in `a0`, a second argument in `a1`, a returned word in `a0`.
 *
 * `rand-guest build --lang c` copies this header next to the objects it builds and puts that
 * directory on the include path, so a guest writes `#include "guest.h"` and carries no copy of
 * its own.
 */
#ifndef RAND_GUEST_H
#define RAND_GUEST_H
#include <stdint.h>
#include <stddef.h>

#define RAND_SYS_HALT 0
#define RAND_SYS_WRITE_OUTPUT 1
#define RAND_SYS_READ_INPUT 2
#define RAND_SYS_POSEIDON2 3
#define RAND_SYS_KECCAK 4
#define RAND_SYS_SHA256 5
#define RAND_SYS_READ_PUBLIC 6

/* Private input word `idx`, bound to the proof's `H_IN` commitment. `idx >= n_in` can never be
 * satisfied. (`guest_sdk::read_input`.) */
static inline uint32_t rand_read_input(uint32_t idx) {
    register uint32_t a0 __asm__("a0") = idx;
    register uint32_t a7 __asm__("a7") = RAND_SYS_READ_INPUT;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
    return a0;
}

/* Public input word `idx`, committed to the unsalted `H_PUB` anyone can recompute.
 * (`guest_sdk::read_public`.) */
static inline uint32_t rand_read_public(uint32_t idx) {
    register uint32_t a0 __asm__("a0") = idx;
    register uint32_t a7 __asm__("a7") = RAND_SYS_READ_PUBLIC;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
    return a0;
}

/* Output slot in `a0`, the word in `a1`. (`guest_sdk::write_output`.) */
static inline void rand_write_output(uint32_t slot, uint32_t word) {
    register uint32_t a0 __asm__("a0") = slot;
    register uint32_t a1 __asm__("a1") = word;
    register uint32_t a7 __asm__("a7") = RAND_SYS_WRITE_OUTPUT;
    __asm__ volatile("ecall" : : "r"(a0), "r"(a1), "r"(a7) : "memory");
}

/* `ptr`: a 4-byte-aligned pointer to `n` words hashed in place by the `POSEIDON2` sponge,
 * `ptr..ptr+8` overwritten with the digest; `n <= 4096` (`isa::POSEIDON2_MAX_WORDS`).
 *
 * The syscall takes a **word** address in `a0` (the `MEM_ADDR` convention), so this divides the
 * byte pointer by 4 exactly as `guest_sdk::poseidon2` does — passing the byte pointer straight
 * through would hash the words at four times the intended address. The count is in `a1`. */
static inline void rand_poseidon2(uint32_t *ptr, uint32_t n) {
    register uint32_t a0 __asm__("a0") = (uint32_t)(uintptr_t)ptr / 4;
    register uint32_t a1 __asm__("a1") = n;
    register uint32_t a7 __asm__("a7") = RAND_SYS_POSEIDON2;
    __asm__ volatile("ecall" : : "r"(a0), "r"(a1), "r"(a7) : "memory");
}

/* `ptr`: a 4-byte-aligned pointer to 50 words holding a Keccak-f[1600] state, permuted in place.
 * A **word** address in `a0`, the same convention as `rand_poseidon2`. (`guest_sdk::keccak`.) */
static inline void rand_keccak(uint32_t *ptr) {
    register uint32_t a0 __asm__("a0") = (uint32_t)(uintptr_t)ptr / 4;
    register uint32_t a7 __asm__("a7") = RAND_SYS_KECCAK;
    __asm__ volatile("ecall" : : "r"(a0), "r"(a7) : "memory");
}

/* `ptr`: a 4-byte-aligned pointer to 24 words — the message block as sixteen big-endian-valued
 * words at `0..16`, the chaining state at `16..24`, which one call overwrites. A **word** address
 * in `a0`, the same convention as `rand_keccak`. (`guest_sdk::sha256_compress`.) */
static inline void rand_sha256_compress(uint32_t *ptr) {
    register uint32_t a0 __asm__("a0") = (uint32_t)(uintptr_t)ptr / 4;
    register uint32_t a7 __asm__("a7") = RAND_SYS_SHA256;
    __asm__ volatile("ecall" : : "r"(a0), "r"(a7) : "memory");
}

/* Halts the machine. The trailing `for (;;)` is `guest_sdk::halt`'s `loop {}`, and is there for
 * its reason: telling the compiler the `ecall` does not return makes LLVM synthesise a trap word
 * (`csrrw x0, cycle, x0`) that `Instr::decode` rejects, so the function never returns because it
 * loops, not because it promises to. */
__attribute__((noreturn)) static inline void rand_halt(void) {
    register uint32_t a7 __asm__("a7") = RAND_SYS_HALT;
    __asm__ volatile("ecall" : : "r"(a7) : "memory");
    for (;;) {
    }
}
#endif
