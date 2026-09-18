/* sbpf-rt's software signature checks: `sbpf_ed25519.c` and `sbpf_secp256k1.c` (over `sbpf_bn.c`).
 * Not part of a translated program — the interpreter implements neither syscall, so `sbpf_syscall`
 * traps on both hashes and sbpf2rv's shim never links these files. Kept apart from `sbpf_rt.h` so a
 * translation's header carries nothing it cannot call. */
#ifndef SBPF_CRYPTO_H
#define SBPF_CRYPTO_H
#include "sbpf_rt.h"

/* ---- software signature checks, beyond the interpreter --------------------------------------
 * NOT part of `syscalls::SUPPORTED`: the interpreter halts `UnknownSyscall` on both hashes, so a
 * translation that must match it word for word routes them to `sbpf_syscall`'s trap, not here. They
 * exist to be measured (spec §5: the coprocessor backlog) and for a later, deliberate widening of
 * the syscall set. Pure C, reference-style (Montgomery arithmetic on 8 x 32-bit limbs with 64-bit
 * products, `sbpf_bn.c`), no tables, not constant time — a proof has no timing channel. */
#define SBPF_SYSCALL_SOL_SECP256K1_RECOVER 0x17e40350u /* sol_secp256k1_recover (Solana's) */
#define SBPF_SYSCALL_SOL_ED25519_VERIFY 0x1a72106bu    /* sol_ed25519_verify (not a Solana name:
                                                          Solana verifies Ed25519 in a native
                                                          program, not a syscall) */

/* `sol_secp256k1_recover`'s result codes (Solana's `Secp256k1RecoverError`, returned in r0). */
#define SBPF_SECP256K1_OK 0
#define SBPF_SECP256K1_INVALID_HASH 1 /* never: any 32 bytes are a message */
#define SBPF_SECP256K1_INVALID_RECOVERY_ID 2
#define SBPF_SECP256K1_INVALID_SIGNATURE 3

/* Solana's `sol_secp256k1_recover` over libsecp256k1 `parse_standard_slice`: `hash` is the 32-byte
 * big-endian message (reduced mod n), `recid` must be 0..3 (a u64 that is not a u8, or is >= 4, is
 * INVALID_RECOVERY_ID), `sig` is r || s big-endian with 0 < r, s < n (high s accepted), and x = r +
 * (recid >> 1) n must be < p and on the curve. On success writes the 64-byte uncompressed key x || y
 * (no 0x04 prefix) and returns 0; otherwise `out` is untouched. */
uint32_t sbpf_secp256k1_recover(const uint8_t hash[32], uint64_t recid, const uint8_t sig[64],
                                uint8_t out[64]);
/* RFC 8032 §5.1.7 as its §6 reference code checks it: A and R must decode (canonical y < p, x
 * recoverable, x = 0 only with sign bit 0), S < L, and [S]B = R + [k]A with k = SHA-512(R || A || M)
 * mod L (cofactorless). Returns 0 if the signature verifies, 1 if not. */
uint32_t sbpf_ed25519_verify(const uint8_t pk[32], const uint8_t *msg, uint32_t len,
                             const uint8_t sig[64]);
/* The syscall-shaped wrappers: pointers are region addresses, translated first (AccessViolation on
 * a miss, as Solana's `translate_slice` faults). secp256k1: r1 hash (32, read), r2 recid, r3 sig
 * (64, read), r4 result (64, written), translated in Agave's order hash, sig, result; r0 the code.
 * ed25519: r1 public key (32), r2 message, r3 its length (above u32::MAX: AccessViolation(r3)),
 * r4 signature (64), translated in that order; r0 0 valid, 1 not. */
uint64_t sbpf_sys_secp256k1_recover(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_ed25519_verify(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);

#endif
