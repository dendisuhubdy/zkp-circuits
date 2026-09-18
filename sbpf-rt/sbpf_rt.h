/* sbpf-rt: the runtime an `sbpf2rv`-translated program calls — the C twin of `sbpf-core`'s
 * `memory.rs` (the four regions, `load`/`store`), `interp.rs` (`Halt`) and `syscalls.rs` (the
 * twelve implemented syscalls). Those three files are the authority for every behaviour here; this
 * is a one-for-one port, not a reimplementation from Solana's documentation, because the translated
 * program's public output must equal the interpreter's on every input, failing ones included.
 *
 * Freestanding: `<stdint.h>`/`<stddef.h>` only, no libc, no host header. It compiles for the
 * machine with the toolchain's flags (`rand-guest`'s `clang_flags`); on RV32 `sol_sha256` reaches
 * the SHA-256 coprocessor through `guest.h` and the trap path is this runtime's own setjmp. A host
 * build (the tests, `sbpf2rv`'s differential fuzzing) links `test/host_glue.c` for both instead.
 *
 * Files: `sbpf_rt.c` (regions, traps, the twelve syscalls, SHA-256's padding) is all a translated
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

/* ---- the syscall hashes (`syscalls.rs`: murmur3-32, seed 0, of the name) ----------------------
 * The twelve `syscalls::SUPPORTED` lists, in its order; each has an `sbpf_sys_<name>` below, where
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
} sbpf_regions;
extern sbpf_regions sbpf_r;

/* Instructions remaining. `sbpf_rt_reset` sets it to `SBPF_MAX_INSTRUCTIONS`; the emitted code
 * subtracts each basic block's length at the block's head (sbpf2rv keeps a function-local copy,
 * handed over through this variable around every call and return) and traps InstructionLimit when
 * it goes negative — at that block's head, or, for a block whose check sbpf2rv defers to its
 * successors, at the head of the next block (sbpf2rv/src/emit.rs, `choose_checked`). Either way the
 * halt kind may differ from the interpreter's, which counts one instruction at a time, only in the
 * block that crosses the limit: a fault part-way through it may be reported as InstructionLimit, or
 * (deferred) the other way round. The status (2) and the eight public words are equal, since an
 * exceptional halt publishes the pre-state whatever its kind. */
extern int64_t sbpf_budget;
/* `Vm::heap_used`: the bump allocator's cursor, bytes handed out by `sol_alloc_free_`. */
extern uint32_t sbpf_heap_used;
/* Why the run stopped: an `SBPF_HALT_*` code (EXIT while running or after a normal return) and the
 * variant's payload. */
extern uint32_t sbpf_halt_code;
extern uint64_t sbpf_halt_arg;

/* The per-run state a fresh `Vm::new` has: heap cursor 0, full budget, no halt. The regions are the
 * caller's to set. */
void sbpf_rt_reset(void);

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
 * fault payload is that wrapped address, as the interpreter's is. */
uint64_t sbpf_ld1(uint64_t base, int32_t off);
uint64_t sbpf_ld2(uint64_t base, int32_t off);
uint64_t sbpf_ld4(uint64_t base, int32_t off);
uint64_t sbpf_ld8(uint64_t base, int32_t off);
void sbpf_st1(uint64_t base, int32_t off, uint64_t v);
void sbpf_st2(uint64_t base, int32_t off, uint64_t v);
void sbpf_st4(uint64_t base, int32_t off, uint64_t v);
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
/* The whole of `dispatch`: the twelve above by hash, anything else UnknownSyscall(hash) — CPI
 * (`sol_invoke_signed_*`) and the two crypto syscalls of `sbpf_crypto.h` included, since the
 * interpreter implements none of them. */
uint64_t sbpf_syscall(uint32_t hash, uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);

/* One SHA-256 compression of the 24-word `SYS_SHA256` argument (`Host::sha256_compress`): words
 * 0..16 the block as big-endian-valued words, 16..24 the chaining state, updated in place. On RV32
 * `sbpf_rt.c` defines it over `rand_sha256_compress`; a host build links a portable one. */
void sbpf_sha256_compress(uint32_t w[24]);

#endif
