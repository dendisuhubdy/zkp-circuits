/* The nine Shanghai precompiles (addresses 1-9), in software: what a translated contract's CALL,
 * CALLCODE, DELEGATECALL or STATICCALL to one of them runs (`evm_call` in evm_rt.c).
 *
 *   1 ecrecover     evm_secp256k1.c (secp256k1 recovery over evm_bn.c) + Keccak through `ffi.rs`
 *   2 sha256        here, one compression per block: on RV32 the machine's SHA-256 coprocessor
 *                   (`rand_sha256_compress`), on the host a portable C compression (test/host_jmp.c)
 *   3 ripemd160     here
 *   4 identity      here
 *   5 modexp        here (EIP-198 semantics, EIP-2565 gas), arbitrary-width limbs
 *   6 bn256 add     evm_bn254.c (EIP-196)
 *   7 bn256 mul     evm_bn254.c (EIP-196)
 *   8 bn256 pairing evm_bn254.c (EIP-197): the optimal ate Miller loop and a plain final
 *                   exponentiation, over reference field arithmetic
 *   9 blake2f       here (EIP-152)
 *
 * The authority is go-ethereum's `core/vm/contracts.go` (the Berlin/Istanbul set Shanghai runs)
 * with the EIPs named; the known answers are its test data (test/precompile_vectors.h).
 *
 * **Gas** is `RequiredGas`: computed from the input alone, before anything runs; the caller
 * (`evm_call`) fails the call when it exceeds the gas passed. The constants are prefixed `PC_`,
 * not `G_`: `G_*` in evm_rt.h is interp.rs's table, compared name for name by research's tests.
 *
 * **Failure.** `evm_precompile_run` returns PC_OK with the output, PC_FAIL when the input is
 * invalid under the precompile's own rules (the EVM's call then fails: status word 0 pushed, all
 * the gas passed consumed, no return data), or PC_TOO_BIG for a modexp whose base, exponent or
 * modulus is longer than PC_MODEXP_MAX_BYTES - the runtime's own cap, like interp.rs's
 * MAX_MEMORY_BYTES, which `evm_call` turns into Halt::OutOfBounds. An ecrecover that cannot
 * recover a key is PC_OK with an empty output, as in the EVM.
 *
 * Freestanding: <stdint.h> only. Not constant time: a proof has no timing channel.
 */
#ifndef EVM_PRECOMPILES_H
#define EVM_PRECOMPILES_H
#include <stdint.h>

#define PC_FIRST 1
#define PC_LAST 9

/* go-ethereum's params/protocol_params.go (the Istanbul/Berlin values Shanghai charges). */
#define PC_ECRECOVER_GAS 3000
#define PC_SHA256_BASE 60
#define PC_SHA256_WORD 12
#define PC_RIPEMD160_BASE 600
#define PC_RIPEMD160_WORD 120
#define PC_IDENTITY_BASE 15
#define PC_IDENTITY_WORD 3
#define PC_MODEXP_MIN 200          /* EIP-2565 */
#define PC_BN256_ADD_GAS 150       /* EIP-1108 */
#define PC_BN256_MUL_GAS 6000      /* EIP-1108 */
#define PC_BN256_PAIRING_BASE 45000 /* EIP-1108 */
#define PC_BN256_PAIRING_PAIR 34000 /* EIP-1108 */
#define PC_BLAKE2F_ROUND 1         /* EIP-152 */

/* The runtime's cap on each of modexp's three lengths (1 KiB: 8192-bit operands, the largest
 * go-ethereum's vectors use). Over it, an affordable call halts OutOfBounds instead of running. */
#define PC_MODEXP_MAX_BYTES 1024

/* The largest output: identity's, whose input is a memory range (interp.rs's MAX_MEMORY_BYTES). */
#define PC_OUT_MAX 65536

#define PC_OK 0
#define PC_FAIL 1
#define PC_TOO_BIG 2

/* RequiredGas of precompile `addr` (1..9) over `in`; saturates at UINT64_MAX. */
uint64_t evm_precompile_gas(uint32_t addr, const uint8_t *in, uint32_t len);

/* Run precompile `addr` (1..9) over `in`: on PC_OK the output is `out[0..*out_len)` (`out` has
 * room for PC_OUT_MAX bytes and must not overlap `in`). */
uint32_t evm_precompile_run(uint32_t addr, const uint8_t *in, uint32_t len, uint8_t *out,
                            uint32_t *out_len);

/* ---- the pieces, for the tests and the cycle measurements ---- */

/* One SHA-256 compression of 24 words: 0..16 the block as big-endian-valued words, 16..24 the
 * chaining state, updated in place (`guest_sdk::sha256_compress`'s layout). RV32: precompiles.c,
 * over the coprocessor; host: test/host_jmp.c, portable C. */
void evm_sha256_compress(uint32_t w[24]);
void evm_sha256(const uint8_t *in, uint32_t len, uint8_t out[32]);
void evm_ripemd160(const uint8_t *in, uint32_t len, uint8_t out[20]);
/* EIP-152's F: h (8 words), m (16 words), t (2 words), final flag, `rounds` rounds; h in place. */
void evm_blake2f(uint32_t rounds, uint64_t h[8], const uint64_t m[16], const uint64_t t[2], int final);

/* secp256k1 recovery (evm_secp256k1.c): `hash` the 32-byte message, `recid` 0 or 1, `sig` r || s
 * big-endian with 0 < r, s < n. Writes the 64-byte key x || y and returns 0, or returns nonzero
 * when there is no key (r is not an x on the curve, or the result is the point at infinity). */
uint32_t evm_secp256k1_recover(const uint8_t hash[32], uint32_t recid, const uint8_t sig[64],
                               uint8_t out[64]);

/* alt_bn128 (evm_bn254.c): EIP-196/197 over the encodings; each returns PC_OK or PC_FAIL. */
uint32_t evm_bn256_add(const uint8_t in[128], uint8_t out[64]);
uint32_t evm_bn256_mul(const uint8_t in[96], uint8_t out[64]);
/* `n` pairs of 192 bytes; `*one` is set to 1 when the product of the pairings is 1. */
uint32_t evm_bn256_pairing(const uint8_t *in, uint32_t n, uint32_t *one);
#endif
