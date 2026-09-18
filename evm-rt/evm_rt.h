/* The runtime a translated contract (`evm2rv`'s `contract.c`) runs on: the stack, memory with its
 * expansion accounting, the gas counter, the return buffer, the logs, the halt path, and the
 * calls into the interpreter's own Rust storage tree and Keccak (`evm-core`'s `ffi.rs`).
 *
 * The authority for every rule here is `guests-compiled/evm-core/src/interp.rs`: the limits, the
 * `G_*` constants (copied by name — `research/tests/evm_rt.rs` compares them to the Rust text),
 * the memory model of its `Buffers` and `Interpreter::mem`, the copy and log rules, and the
 * `Halt` variants, which travel as `ffi.rs`'s halt codes (the same test compares the two tables).
 *
 * **Who charges what.** The block head charges the interpreter's `static_gas(op)` for every
 * opcode in the block (`evm_charge`). A runtime call charges exactly what the interpreter charges
 * *inside* that opcode's arm, in the same order: the per-word and expansion terms of the copies
 * and `KECCAK256` (`KECCAK256`'s 30 included — its static gas is 0), all of `LOGn`'s gas (its
 * static gas is 0), `EXP`'s 10 + 50/byte, and `SSTORE`'s set/reset. `SLOAD`'s 2100 is static.
 *
 * **Offsets and lengths** are saturated u32s: pass `u256_sat_u32(&operand)` (see u256.h), never
 * the bare low limb, or an offset of 2^32 would alias offset 0. Only offsets and lengths: a
 * *value* — MSTORE8's byte — is `u256_low_u32(&value)`, unsaturated, since only its low byte is
 * stored (saturating it would turn 0x1_00000012 into 0xff).
 *
 * **Halting.** `evm_halt` never returns: it records the code, its argument and the gas, and
 * unwinds to `evm_rt_enter`. An exceptional halt (every code but STOP/RETURN/REVERT) consumes
 * the whole limit, as the interpreter's does.
 */
#ifndef EVM_RT_H
#define EVM_RT_H
#include <stdint.h>
#include <stddef.h>
#include "u256.h"

/* ---- the halt codes: `evm-core/src/ffi.rs`'s table, exactly (0 = no halt) ---- */
#define EVM_HALT_OK 0
#define EVM_HALT_STOP 1
#define EVM_HALT_RETURN 2
#define EVM_HALT_REVERT 3
#define EVM_HALT_OUT_OF_GAS 4
#define EVM_HALT_STACK_UNDERFLOW 5
#define EVM_HALT_STACK_OVERFLOW 6
#define EVM_HALT_BAD_JUMP 7
#define EVM_HALT_INVALID 8
#define EVM_HALT_TRAP 9 /* Halt::Trap(op): the opcode is the halt's argument */
#define EVM_HALT_NO_WITNESS 10
#define EVM_HALT_BAD_WITNESS 11
#define EVM_HALT_OUT_OF_BOUNDS 12

/* ---- the interpreter's limits (interp.rs) ---- */
#define STACK_LIMIT 1024
#define MAX_MEMORY_BYTES 65536
#define MAX_CODE_BYTES 24576
#define MAX_CALLDATA_BYTES 4096
#define MAX_RETURN_BYTES 1024
#define MAX_LOGS 8
#define MAX_TOPICS 4

/* ---- the Shanghai schedule, interp.rs's constants by name ---- */
#define G_BASE 2
#define G_VERYLOW 3
#define G_LOW 5
#define G_MID 8
#define G_HIGH 10
#define G_JUMPDEST 1
#define G_EXP 10
#define G_EXP_BYTE 50
#define G_KECCAK256 30
#define G_KECCAK256_WORD 6
#define G_SLOAD 2100
#define G_SSTORE_SET 20000
#define G_SSTORE_RESET 2900
#define G_LOG 375
#define G_LOG_TOPIC 375
#define G_LOG_DATA 8
#define G_COPY_WORD 3
#define G_MEMORY 3

/* ---- the state (in .bss; the embedder fills the inputs through evm_rt_init) ---- */
extern u256 evm_stack[STACK_LIMIT];
extern uint32_t evm_sp;
extern uint64_t evm_gas;        /* remaining */
extern uint64_t evm_gas_limit;
extern uint8_t evm_memory[MAX_MEMORY_BYTES];
extern uint32_t evm_msize;      /* the highest touched byte rounded up to 32: MSIZE */

extern const uint8_t *evm_code;
extern uint32_t evm_code_len;
extern const uint8_t *evm_calldata;
extern uint32_t evm_calldata_len;

/* The call's environment: `Env`'s three words, which the embedder (a translated contract's shim)
 * writes after `evm_rt_init` from the decoded call. ADDRESS, CALLER and CALLVALUE push them;
 * ORIGIN pushes `evm_caller` (one call, no relayer: the spec's §3). */
extern u256 evm_address;
extern u256 evm_caller;
extern u256 evm_callvalue;

/* The opaque pointers `ffi.rs` takes: the `*mut StorageTree` and the `*mut HostBox`. */
extern void *evm_tree;
extern void *evm_host;

/* RETURN/REVERT data. */
extern uint8_t evm_ret[MAX_RETURN_BYTES];
extern uint32_t evm_ret_len;

/* One log's topics (interp.rs's `Log`: the data is paid for and dropped). */
typedef struct {
    uint32_t n_topics;
    u256 topics[MAX_TOPICS];
} evm_log_t;
extern evm_log_t evm_logs[MAX_LOGS];
extern uint32_t evm_n_logs;

/* Why the run ended: an EVM_HALT_* code (EVM_HALT_OK while running) and a trap's opcode. */
extern uint32_t evm_halt_code;
extern uint32_t evm_halt_arg;

/* Reset for one call — `Interpreter::new`. Clears only the memory the previous run dirtied (the
 * interpreter's `dirty_mem` rule), zeroes the stack depth, the return data and the logs, and sets
 * the gas. Returns EVM_HALT_OUT_OF_BOUNDS when the code or the calldata is over its cap — the
 * interpreter's `pre_halt`: the embedder reports that halt with gas_used 0 and runs nothing. */
uint32_t evm_rt_init(const uint8_t *code, uint32_t code_len, const uint8_t *calldata,
                     uint32_t calldata_len, uint64_t gas_limit);

/* Run `entry` (the translated contract's `evm_entry`) until it halts; returns the halt code,
 * EVM_HALT_STOP if `entry` returns. On RV32 this is the runtime's own setjmp; a host build
 * (tests) links its own `evm_rt_enter`/`evm_rt_unwind` (test/host_jmp.c). */
uint32_t evm_rt_enter(void (*entry)(void));
__attribute__((noreturn)) void evm_rt_unwind(void);

/* gas_limit - remaining: the Outcome's gas_used once the run has halted. */
uint64_t evm_gas_used(void);

/* ---- the calls a translated contract makes ---- */
__attribute__((noreturn)) void evm_halt(uint32_t halt_code, uint32_t arg);

void evm_charge(uint64_t g);                          /* traps OutOfGas */
/* `Interpreter::mem`: resolve a range, charge its expansion, bump msize; returns the start.
 * A zero-length range touches nothing and pays nothing, whatever its offset. */
uint32_t evm_mexpand(uint32_t offset, uint32_t len);
void evm_mload(uint32_t off, u256 *r);
void evm_mstore(uint32_t off, const u256 *v);
/* MSTORE8: `off` saturated, `b` = u256_low_u32(&value) (NOT saturated); the low byte is stored. */
void evm_mstore8(uint32_t off, uint32_t b);
void evm_calldataload(uint32_t off, u256 *r);         /* zero-padded */
/* CALLDATACOPY / CODECOPY: G_COPY_WORD per word, the expansion, then zero-padded bytes. */
void evm_copy_calldata(uint32_t dst, uint32_t src, uint32_t len);
void evm_copy_code(uint32_t dst, uint32_t src, uint32_t len);
/* RETURNDATACOPY in a contract with no call-family opcode, which can never have made a call: the
 * interpreter's rule — the buffer is empty, a zero length is a no-op and any other traps
 * (Halt::Trap(0x3e)); nothing is charged here and memory is not touched. */
void evm_copy_returndata(uint32_t dst, uint32_t src, uint32_t len);
/* KECCAK256: G_KECCAK256 + G_KECCAK256_WORD per word, the expansion, then `ffi.rs`'s hash. */
void evm_keccak(uint32_t off, uint32_t len, u256 *r);
/* EXP: G_EXP + G_EXP_BYTE per significant byte of `e`, then the power. `r` may alias. */
void evm_exp(u256 *r, const u256 *base, const u256 *e);
/* LOGn: G_LOG + G_LOG_TOPIC·n, the data (8/byte, bounds, expansion), then the log. `topics`
 * points at the n topics in stack order — the deepest first, so topic i is topics[n-1-i]; in the
 * stage-one stack that is `&evm_stack[evm_sp - 2 - n]` with the offset and size still above. */
void evm_log(uint32_t n_topics, uint32_t off, uint32_t len, const u256 *topics);
/* SLOAD / SSTORE through `ffi.rs` (`evm_sload`/`evm_sstore`); a storage failure halts with its
 * code. SSTORE reads the pre-value first and charges G_SSTORE_SET or G_SSTORE_RESET on it. */
void evm_storage_load(const u256 *slot, u256 *r);
void evm_storage_store(const u256 *slot, const u256 *value);
/* RETURN / REVERT: the data (bounds, MAX_RETURN_BYTES, expansion) into evm_ret, then the halt. */
__attribute__((noreturn)) void evm_return(uint32_t off, uint32_t len);
__attribute__((noreturn)) void evm_revert(uint32_t off, uint32_t len);

/* ---- calls: the precompiles (precompiles.h) and the return-data buffer (evm_call.c) ----
 *
 * The interpreter traps on the whole call family, so there is no oracle there: a translated
 * contract is a strict superset of it, and the rules are Shanghai's (go-ethereum's opCall family
 * and RunPrecompiledContract; the controller's Task 5 rulings), as below. A contract that makes
 * no call runs exactly as before: the emitter uses none of this for it.
 *
 * `evm_call(op, a)`: CALL (0xf1), CALLCODE (0xf2), DELEGATECALL (0xf4) or STATICCALL (0xfa), with
 * `a = &evm_stack[evm_sp - n]` (n = 7 for CALL/CALLCODE, 6 for the other two), so `a[n-1]` is the
 * top: gas, address, [value,] argsOffset, argsLength, retOffset, retLength from the top down. The
 * success flag replaces a[0]; the caller then drops n - 1 words.
 *   1. The target is the low 160 bits of the address word. Anything but 1..9 halts Trap(op): a
 *      proof carries one contract (the interpreter's trap, kept).
 *   2. CALL/CALLCODE with a nonzero value halt Trap(op): there is no balance model.
 *   3. 100 gas (EIP-2929's warm access: a precompile is always warm), then the args region's and
 *      the ret region's expansion (offsets and lengths saturated, `Interpreter::mem`'s rules).
 *   4. The gas passed is min(requested, all but one 64th of what is left) (EIP-150). What is
 *      left is `evm_gas + gas_after`: the block head has already taken the static gas of the ops
 *      after the call in its block (`GAS` adds the same `gas_after` back), and the EVM has not.
 *   5. If the precompile's RequiredGas exceeds it, or the precompile rejects its input, the call
 *      fails: 0, the gas passed consumed, the return data emptied, the ret region untouched.
 *      Otherwise 1, RequiredGas consumed (the rest of the gas passed stays), the return data is
 *      the output and its first min(retLength, output length) bytes are copied to retOffset.
 *      A modexp over PC_MODEXP_MAX_BYTES that it can afford halts OutOfBounds (the runtime's cap).
 *   Consuming more than `evm_gas` halts OutOfGas here: the EVM would then have less left than the
 *   rest of the block's static gas and run out before the block's end — the block-head rule's
 *   same status 2 and gas_used = limit.
 * Its static gas (the block head's) is 0; everything above is charged here. */
#define EVM_CALL_WARM_ACCESS 100
#define EVM_RETURNDATA_MAX 65536
extern uint8_t evm_rdata[EVM_RETURNDATA_MAX];
extern uint32_t evm_rdata_len; /* RETURNDATASIZE, in a contract with a call-family opcode */
extern uint32_t evm_rdata_live; /* a call has been made this run */
/* The top of `evm_entry` in a contract with a call-family opcode: no call made, no return data. */
void evm_calls_begin(void);
void evm_call(uint32_t op, u256 *a, uint64_t gas_after);
/* RETURNDATACOPY in a contract with a call-family opcode. Before its first call, the
 * interpreter's rule (`evm_copy_returndata`); after it, EIP-211: src + len past the buffer halts
 * OutOfBounds (a zero length included), else G_COPY_WORD per word, the expansion and the bytes. */
void evm_copy_returndata_buf(uint32_t dst, uint32_t src, uint32_t len);

/* ---- the Rust side (`evm-core/src/ffi.rs`, feature `ffi`) ---- */
uint32_t evm_sload(void *tree, void *host, const uint32_t *slot, uint32_t *out);
uint32_t evm_sstore(void *tree, void *host, const uint32_t *slot, const uint32_t *value);
void evm_keccak256(void *host, const uint8_t *ptr, uint32_t len, uint8_t *out);

#endif
