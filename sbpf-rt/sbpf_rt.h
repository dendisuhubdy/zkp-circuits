/* sbpf-rt: the runtime an `sbpf2rv`-translated program calls — the C twin of `sbpf-core`'s
 * `memory.rs` (the four regions, `load`/`store`), `interp.rs` (`Halt`) and `syscalls.rs` (the
 * eighteen implemented syscalls). Those three files are the authority for every behaviour here; this
 * is a one-for-one port, not a reimplementation from Solana's documentation, because the translated
 * program's public output must equal the interpreter's on every input, failing ones included.
 *
 * Freestanding: `<stdint.h>`/`<stddef.h>` only, no libc, no host header. It compiles for the
 * machine with the toolchain's flags (`rand-guest`'s `clang_flags`); on RV32 `sol_sha256` reaches
 * the SHA-256 coprocessor through `guest.h` and the trap path is this runtime's own setjmp. A host
 * build (the tests, `sbpf2rv`'s differential fuzzing) links `test/host_glue.c` for both instead.
 *
 * Files: `sbpf_rt.c` (regions, traps, the eighteen syscalls, the two hashes' padding) is all a translated
 * program needs. `sbpf_bn.c` + `sbpf_ed25519.c` and `sbpf_bn.c` + `sbpf_secp256k1.c` are the
 * software signature checks, each in its own file so its cycle cost is measurable on its own,
 * declared in `sbpf_crypto.h`; see the note there before wiring either into a translation.
 */
#ifndef SBPF_RT_H
#define SBPF_RT_H
#include <stddef.h>
#include <stdint.h>

/* ---- the machine's constants (`memory.rs`, `interp.rs`) ----------------------------------------
 * `research/tests/sbpf_rt.rs` compares every one of these with the Rust constant it names. */
#define SBPF_REGION_PROGRAM 0x100000000ull /* memory::REGION_PROGRAM */
#define SBPF_REGION_STACK 0x200000000ull   /* memory::REGION_STACK */
#define SBPF_REGION_HEAP 0x300000000ull    /* memory::REGION_HEAP */
#define SBPF_REGION_INPUT 0x400000000ull   /* memory::REGION_INPUT */
#define SBPF_STACK_FRAME 4096              /* memory::STACK_FRAME */
#define SBPF_MAX_CALL_DEPTH 8              /* memory::MAX_CALL_DEPTH */
#define SBPF_STACK_BYTES 32768             /* memory::STACK_BYTES */
#define SBPF_HEAP_BYTES 32768              /* memory::HEAP_BYTES */
#define SBPF_MAX_INSTRUCTIONS 200000       /* interp::MAX_INSTRUCTIONS */
#define SBPF_MAX_RETURN_DATA 1024          /* interp::MAX_RETURN_DATA */
#define SBPF_SYSVAR_BYTES 57               /* interp::SYSVAR_BYTES */
#define SBPF_CLOCK_BYTES 40                /* interp::CLOCK_BYTES */
#define SBPF_RENT_BYTES 17                 /* interp::RENT_BYTES */
#define SBPF_RENT_STRUCT_BYTES 24          /* syscalls::RENT_STRUCT_BYTES */

/* ---- compute units (`syscalls.rs`: Agave's `SVMTransactionExecutionCost` defaults) ------------- */
#define SBPF_CU_SYSCALL_BASE 100           /* syscalls::CU_SYSCALL_BASE */
#define SBPF_CU_MEM_OP_BASE 10             /* syscalls::CU_MEM_OP_BASE */
#define SBPF_CU_BYTES_PER_UNIT 250         /* syscalls::CU_BYTES_PER_UNIT */
#define SBPF_CU_HASH_BASE 85               /* syscalls::CU_HASH_BASE */
#define SBPF_CU_SYSVAR_BASE 100            /* syscalls::CU_SYSVAR_BASE */

/* ---- `Halt`, by declaration order ------------------------------------------------------------
 * One code per `interp::Halt` variant, numbered in the enum's declaration order, so the shim maps a
 * code back with a table. `research/tests/sbpf_rt.rs` parses this block and `interp.rs`'s enum and
 * fails if either gains, loses or reorders a variant. `SBPF_HALT_EXIT` (0) is "no halt": the run
 * returned normally and `r0` is its result. The payload each variant carries travels in
 * `sbpf_halt_arg`: the faulting address (AccessViolation), the opcode byte (BadInsn), the hash
 * (UnknownSyscall), an `SBPF_TRAP_*` index (Trap), and 0 for the rest. */
#define SBPF_HALT_EXIT 0
#define SBPF_HALT_ACCESS_VIOLATION 1
#define SBPF_HALT_BAD_INSN 2
#define SBPF_HALT_DIV_BY_ZERO 3
#define SBPF_HALT_UNKNOWN_SYSCALL 4
#define SBPF_HALT_CALL_DEPTH 5
#define SBPF_HALT_INSTRUCTION_LIMIT 6
#define SBPF_HALT_BAD_ELF 7
#define SBPF_HALT_BAD_JUMP 8
#define SBPF_HALT_STACK_OVERFLOW 9
#define SBPF_HALT_TRAP 10

/* `Halt::Trap(&'static str)`'s strings, by index — every `Halt::Trap("…")` `syscalls.rs` raises, in
 * the order it first raises them (the drift test checks both the strings and the order). */
#define SBPF_TRAP_ABORT 0           /* "abort" */
#define SBPF_TRAP_SOL_PANIC 1       /* "sol_panic_" */
#define SBPF_TRAP_MEMCPY_OVERLAP 2  /* "sol_memcpy_ overlap" */
#define SBPF_TRAP_RETURN_DATA_TOO_LARGE 3 /* "return data too large" */
#define SBPF_TRAP_RETURN_DATA_OVERLAP 4   /* "return data overlap" */
#define SBPF_TRAP_SYSVAR_UNAVAILABLE 5    /* "sysvar unavailable" */

/* ---- the syscall hashes (`syscalls.rs`: murmur3-32, seed 0, of the name) ----------------------
 * The eighteen `syscalls::SUPPORTED` lists, in its order; each has an `sbpf_sys_<name>` below, where
 * `<name>` is the syscall's name with a leading `sol_` and a trailing `_` removed. */
#define SBPF_SYSCALL_ABORT 0xb6fc1a11u                 /* abort */
#define SBPF_SYSCALL_SOL_PANIC_ 0x686093bbu            /* sol_panic_ */
#define SBPF_SYSCALL_SOL_LOG_ 0x207559bdu              /* sol_log_ */
#define SBPF_SYSCALL_SOL_LOG_64_ 0x5c2a3178u           /* sol_log_64_ */
#define SBPF_SYSCALL_SOL_LOG_COMPUTE_UNITS_ 0x52ba5096u /* sol_log_compute_units_ */
#define SBPF_SYSCALL_SOL_LOG_PUBKEY 0x7ef088cau        /* sol_log_pubkey */
#define SBPF_SYSCALL_SOL_MEMCPY_ 0x717cc4a3u           /* sol_memcpy_ */
#define SBPF_SYSCALL_SOL_MEMMOVE_ 0x434371f8u          /* sol_memmove_ */
#define SBPF_SYSCALL_SOL_MEMSET_ 0x3770fb22u           /* sol_memset_ */
#define SBPF_SYSCALL_SOL_MEMCMP_ 0x5fdcde31u           /* sol_memcmp_ */
#define SBPF_SYSCALL_SOL_ALLOC_FREE_ 0x83f00e8fu       /* sol_alloc_free_ */
#define SBPF_SYSCALL_SOL_SHA256 0x11f49d86u            /* sol_sha256 */
#define SBPF_SYSCALL_SOL_KECCAK256 0xd7793abbu         /* sol_keccak256 */
#define SBPF_SYSCALL_SOL_SET_RETURN_DATA 0xa226d3ebu   /* sol_set_return_data */
#define SBPF_SYSCALL_SOL_GET_RETURN_DATA 0x5d2245e4u   /* sol_get_return_data */
#define SBPF_SYSCALL_SOL_GET_CLOCK_SYSVAR 0xd56b5fe9u  /* sol_get_clock_sysvar */
#define SBPF_SYSCALL_SOL_GET_RENT_SYSVAR 0xbf7188f6u   /* sol_get_rent_sysvar */
#define SBPF_SYSCALL_SOL_GET_SYSVAR 0x13c1b505u        /* sol_get_sysvar */

/* ---- the regions ----------------------------------------------------------------------------
 * `memory::Memory`, as pointers: set by the shim before entry, from the loaded `Program` and the
 * interpreter's own `Memory` (so the stack, heap and input are the `Workspace`'s bytes, and a
 * translated program's writes land exactly where the interpreter's would). `stack` is
 * `SBPF_STACK_BYTES` long and `heap` `SBPF_HEAP_BYTES`. `text_va`/`rodata_va` are full virtual
 * addresses; only their low 32 bits (the offset in the program region) are used, as `memory.rs`'s
 * `offset_of(self.rodata_base)` does. In SBPF v1 the rodata span contains the text, and a load is
 * served by the rodata span first, then the text. */
typedef struct {
    const uint8_t *text;
    uint64_t text_va;
    uint32_t text_len;
    const uint8_t *rodata;
    uint64_t rodata_va;
    uint32_t rodata_len;
    uint8_t *stack;
    uint8_t *heap;
    uint8_t *input;
    uint32_t input_len;
    /* `abi::CallEnv`: the sysvar block from the public tape (`sysvars_len` is 0 or
     * `SBPF_SYSVAR_BYTES`), the running program's id (32 bytes), and the `SBPF_MAX_RETURN_DATA`-byte
     * buffer `sol_set_return_data` writes — the harness's own, so what it hashes is what was set. */
    const uint8_t *sysvars;
    uint32_t sysvars_len;
    const uint8_t *program_id;
    uint8_t *return_data;
} sbpf_regions;
extern sbpf_regions sbpf_r;

/* Compute units remaining, as the emitted code counts them. `sbpf_rt_reset` sets it to
 * `SBPF_MAX_INSTRUCTIONS`; the emitted code subtracts each basic block's charge — its instructions
 * and the fixed cost of the syscall that ends it — at the block's head (sbpf2rv keeps a
 * function-local copy, handed over through this variable around every call and return) and traps
 * InstructionLimit when it has gone negative at a head that checks: a function's entry, a block
 * that closes a loop, a block ending in `exit` (sbpf2rv/src/emit.rs, `choose_checked`). So a run
 * that crosses the limit halts at the next such head rather than at the instruction, and until
 * then may fault with another kind; the status (2) and the eight public words are the
 * interpreter's, since an exceptional halt publishes the pre-state whatever its kind. 32 bits: the
 * budget is 200 000 and a run goes below zero by fewer units than its unchecked blocks charge. */
extern int32_t sbpf_budget;
/* The compute units the syscalls have charged beyond what the emitted code already has. A syscall's
 * charge is `syscalls::base_cost(hash)` plus a length-dependent part: the translation folds the
 * base into the charge of the block the call ends (it is a constant, so it costs no code), and
 * the syscall adds the rest here, trapping InstructionLimit once this alone would pass
 * `SBPF_MAX_INSTRUCTIONS`. The emitted code's own checks do not see it, so `sbpf_rt_settle` makes
 * the exact comparison when the program returns: a run that spent more than the budget in total
 * halts InstructionLimit there, where the interpreter halted at the charge that crossed it. The
 * status (2) and the public words are the interpreter's either way.
 * `sbpf_syscall` — dispatch by hash, which the emitted code never uses — charges the base as well,
 * so a caller of it alone sees the interpreter's whole meter. */
extern uint32_t sbpf_cu;
/* `Vm::return_len`: bytes of `sbpf_r.return_data` set by `sol_set_return_data`. */
extern uint32_t sbpf_return_len;
/* `Vm::heap_used`: the bump allocator's cursor, bytes handed out by `sol_alloc_free_`. */
extern uint32_t sbpf_heap_used;
/* Why the run stopped: an `SBPF_HALT_*` code (EXIT while running or after a normal return) and the
 * variant's payload. */
extern uint32_t sbpf_halt_code;
extern uint64_t sbpf_halt_arg;

/* The per-run state a fresh `Vm::new` has: heap cursor 0, full budget, nothing charged, no return
 * data, no halt. The regions are the caller's to set. */
void sbpf_rt_reset(void);
/* The end of a run: `code` is what `sbpf_rt_enter` returned. A normal return whose total charge —
 * the emitted code's (`SBPF_MAX_INSTRUCTIONS - sbpf_budget`) plus the syscalls' (`sbpf_cu`) — is
 * over the budget becomes InstructionLimit; anything else is returned unchanged. */
uint32_t sbpf_rt_settle(uint32_t code);

/* ---- the trap path --------------------------------------------------------------------------
 * `sbpf_trap` records the halt and unwinds to the frame `sbpf_rt_enter` is running in, which then
 * returns the code. On RV32 this is the runtime's own setjmp/longjmp over ra, sp and s0-s11 (the
 * whole ILP32 callee-saved set: there are no float registers); a host build links
 * `test/host_glue.c`'s pair over libc instead. Only C frames lie between the two, so nothing is
 * skipped that needed unwinding. */
typedef uint64_t (*sbpf_fn)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
/* Runs `entry(r1..r5)`. Returns `SBPF_HALT_EXIT` with `*r0` set if it returns, else the halt code
 * (`sbpf_halt_arg` holds the payload, `*r0` is untouched). */
uint32_t sbpf_rt_enter(sbpf_fn entry, uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4,
                       uint64_t r5, uint64_t *r0);
__attribute__((noreturn)) void sbpf_rt_unwind(void);
__attribute__((noreturn)) void sbpf_trap(uint32_t halt_code, uint64_t arg);

/* ---- memory (`Memory::slice`, `slice_mut`, `load`, `store`) ----------------------------------
 * `sbpf_tr_ro(addr, len)`: a host pointer to `addr..addr+len` if every byte is inside one readable
 * region, else AccessViolation(addr). `sbpf_tr_rw`: the same over the writable regions (stack,
 * heap, input: the program region is never writable). A zero `len` is checked like any other: the
 * offset must still lie at or inside its region's end. No alignment rule. */
const uint8_t *sbpf_tr_ro(uint64_t addr, uint64_t len);
uint8_t *sbpf_tr_rw(uint64_t addr, uint64_t len);
/* A 1-, 2-, 4- or 8-byte little-endian load, zero-extended; a store of `v`'s low `size` bytes. A
 * `size` above 8 is taken as 8 (no caller passes one; the clamp keeps the byte loop inside a u64). */
uint64_t sbpf_load(uint64_t addr, uint32_t size);
void sbpf_store(uint64_t addr, uint32_t size, uint64_t v);
/* The emitted `ldx`/`st`/`stx`: one entry per width taking the base register and the instruction's
 * offset, so the address is `interp.rs`'s `(base as i64).wrapping_add(off as i64) as u64`, computed
 * once here rather than at every one of the translated program's thousands of access sites. The
 * fault payload is that wrapped address, as the interpreter's is. The narrow loads return 32 bits
 * (the value is zero-extended, so the high word is zero and the type says so) and the narrow stores
 * take 32 (only the low bytes are written). */
uint32_t sbpf_ld1(uint64_t base, int32_t off);
uint32_t sbpf_ld2(uint64_t base, int32_t off);
uint32_t sbpf_ld4(uint64_t base, int32_t off);
uint64_t sbpf_ld8(uint64_t base, int32_t off);
void sbpf_st1(uint64_t base, int32_t off, uint32_t v);
void sbpf_st2(uint64_t base, int32_t off, uint32_t v);
void sbpf_st4(uint64_t base, int32_t off, uint32_t v);
void sbpf_st8(uint64_t base, int32_t off, uint64_t v);

/* ---- the syscalls ---------------------------------------------------------------------------
 * `syscalls::dispatch`, one function per arm: arguments in r1..r5, the result is r0. Each checks
 * every range it will touch before it touches any (a syscall does all of its work or none), and
 * faults exactly where the interpreter does, with the same payload. */
uint64_t sbpf_sys_abort(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_panic(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_log(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_log_64(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_log_compute_units(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_log_pubkey(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_memcpy(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_memmove(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_memset(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_memcmp(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_alloc_free(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_sha256(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_keccak256(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_set_return_data(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_get_return_data(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_get_clock_sysvar(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_get_rent_sysvar(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
uint64_t sbpf_sys_get_sysvar(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
/* `syscalls::base_cost`: the part of a syscall's charge that depends only on which it is. */
uint32_t sbpf_base_cost(uint32_t hash);
/* The whole of `dispatch`: the base charge, then the eighteen above by hash, anything else UnknownSyscall(hash) — CPI
 * (`sol_invoke_signed_*`) and the two crypto syscalls of `sbpf_crypto.h` included, since the
 * interpreter implements none of them. */
uint64_t sbpf_syscall(uint32_t hash, uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);

/* One SHA-256 compression of the 24-word `SYS_SHA256` argument (`Host::sha256_compress`): words
 * 0..16 the block as big-endian-valued words, 16..24 the chaining state, updated in place. On RV32
 * `sbpf_rt.c` defines it over `rand_sha256_compress`; a host build links a portable one. */
void sbpf_sha256_compress(uint32_t w[24]);
/* One Keccak-f[1600] permutation of the 25 lanes as 50 little-endian words, low word first
 * (`Host::keccak_f`). On RV32 `sbpf_rt.c` defines it over `rand_keccak`; a host build links a
 * portable one. */
void sbpf_keccak_f(uint32_t st[50]);

#endif
