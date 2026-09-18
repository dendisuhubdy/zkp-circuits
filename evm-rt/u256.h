/* The EVM's 256-bit word for translated contracts: eight little-endian 32-bit limbs and the
 * arithmetic the opcodes need. Every routine is a port of `guests-compiled/evm-core/src/u256.rs`
 * (the interpreter's `U256`), function by function, so a translated contract computes exactly
 * what the interpreter computes; `research/tests/evm_rt.rs` generates `test/u256_vectors.h` from
 * that Rust type and `test/u256_test.c` checks this library against it.
 *
 * Freestanding C for RV32IM: only <stdint.h>/<stddef.h>, no 128-bit types. A 32x32->64 product
 * lowers to `mul`/`mulhu`; the division's 64-by-32 quotient estimate lowers to `__udivdi3` /
 * `__umoddi3` (the interpreter's Rust lowers to the same compiler-builtins calls).
 *
 * Calling convention. Every operation writes its result through the first pointer and reads its
 * operands through the rest; **the result may alias any operand** (the emitter writes results
 * over the stack slot an operand came from). The operand order is the Rust receiver first:
 *
 *   opcode      stack top ... (the interpreter pops a, then b, then c)   C call
 *   ADD..SMOD   a, b                      u256_add(r, a, b)  = a op b
 *   ADDMOD      a, b, m                   u256_addmod(r, a, b, m)
 *   EXP         base, e                   u256_exp(r, base, e)
 *   SIGNEXTEND  b, x                      u256_signextend(r, x, b)   (note: x first)
 *   LT GT SLT SGT EQ   a, b               u256_lt(r, a, b) = (a < b) ...
 *   ISZERO NOT  a                         u256_iszero(r, a), u256_not(r, a)
 *   AND OR XOR  a, b                      u256_and(r, a, b)
 *   BYTE        i, x                      u256_byte(r, x, i)         (note: x first)
 *   SHL SHR SAR n, x                      u256_shl(r, x, n)          (note: x first)
 */
#ifndef EVM_RT_U256_H
#define EVM_RT_U256_H
#include <stdint.h>
#include <stddef.h>

/* Limb 0 is the least significant 32 bits — `U256`'s layout and the FFI's (`ffi.rs`). */
typedef struct { uint32_t l[8]; } u256;

/* ---- construction and inspection (U256::from_u32, from_u64, from_be_bytes, ...) ---- */
void u256_from_u32(u256 *r, uint32_t v);
void u256_from_u64(u256 *r, uint64_t v);
/* 32 big-endian bytes in, little-endian limbs out; `b` needs no alignment. */
void u256_from_be_bytes(u256 *r, const uint8_t *b);
void u256_to_be_bytes(uint8_t *b, const u256 *a);
/* A `PUSHn` immediate: `n <= 32` big-endian bytes, right-aligned (U256::from_be_slice). */
void u256_from_be_slice(u256 *r, const uint8_t *b, uint32_t n);
int u256_is_zero(const u256 *a);          /* predicate (U256::is_zero) */
int u256_is_neg(const u256 *a);           /* bit 255 */
uint32_t u256_low_u32(const u256 *a);
uint64_t u256_low_u64(const u256 *a);
/* Limbs 1..8 all zero (U256::fits_u32): what `JUMP` checks before it looks at the low limb. */
int u256_hi_zero(const u256 *a);
/* The low limb, or UINT32_MAX when the value does not fit a u32. **The form every offset and
 * length the runtime takes must be passed in** (not `u256_low_u32`): the runtime's u32
 * parameters are these saturated values, and saturation keeps each interpreter check intact — a
 * value too wide for a u32 and UINT32_MAX itself are both past every memory, calldata and code
 * bound, both non-zero, and both fail `len_arg`. */
uint32_t u256_sat_u32(const u256 *a);
uint32_t u256_bit_len(const u256 *a);     /* highest set bit + 1; 0 for 0 */
uint32_t u256_byte_len(const u256 *a);    /* EXP's gas wants this */

/* ---- the opcodes ---- */
void u256_add(u256 *r, const u256 *a, const u256 *b);
void u256_sub(u256 *r, const u256 *a, const u256 *b);
void u256_mul(u256 *r, const u256 *a, const u256 *b);
void u256_div(u256 *r, const u256 *a, const u256 *b);   /* x / 0 = 0 */
void u256_mod(u256 *r, const u256 *a, const u256 *b);   /* x % 0 = 0 (U256::rem) */
void u256_sdiv(u256 *r, const u256 *a, const u256 *b);  /* toward zero; MIN / -1 = MIN */
void u256_smod(u256 *r, const u256 *a, const u256 *b);  /* the dividend's sign */
void u256_addmod(u256 *r, const u256 *a, const u256 *b, const u256 *m);  /* 257-bit sum; m=0 -> 0 */
void u256_mulmod(u256 *r, const u256 *a, const u256 *b, const u256 *m);  /* 512-bit product */
void u256_exp(u256 *r, const u256 *base, const u256 *e);                 /* 0^0 = 1 */
void u256_signextend(u256 *r, const u256 *x, const u256 *b);             /* b >= 31: identity */
void u256_lt(u256 *r, const u256 *a, const u256 *b);
void u256_gt(u256 *r, const u256 *a, const u256 *b);
void u256_slt(u256 *r, const u256 *a, const u256 *b);
void u256_sgt(u256 *r, const u256 *a, const u256 *b);
void u256_eq(u256 *r, const u256 *a, const u256 *b);
void u256_iszero(u256 *r, const u256 *a);
void u256_and(u256 *r, const u256 *a, const u256 *b);
void u256_or(u256 *r, const u256 *a, const u256 *b);
void u256_xor(u256 *r, const u256 *a, const u256 *b);
void u256_not(u256 *r, const u256 *a);
void u256_byte(u256 *r, const u256 *x, const u256 *i);   /* byte i from the most significant */
void u256_shl(u256 *r, const u256 *x, const u256 *n);    /* n >= 256 -> 0 */
void u256_shr(u256 *r, const u256 *x, const u256 *n);    /* n >= 256 -> 0 */
void u256_sar(u256 *r, const u256 *x, const u256 *n);    /* n >= 256 -> the sign */

/* The predicates behind LT/SLT, for the emitter's JUMPI-free comparisons (U256::lt, slt). */
int u256_lt_p(const u256 *a, const u256 *b);
int u256_slt_p(const u256 *a, const u256 *b);
int u256_eq_p(const u256 *a, const u256 *b);

#endif
