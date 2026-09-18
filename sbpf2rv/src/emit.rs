//! The emitter: a [`Scan`] of a loaded [`Program`] becomes one C file, `program.c`, that
//! `sbpf-rt` (`sbpf-rt/sbpf_rt.h`) runs. One C function per sBPF function, one C label per basic
//! block, one C statement per instruction — spec §3's table, with `interp.rs` as the authority for
//! every semantic the table leaves open.
//!
//! # The calling convention
//!
//! Every sBPF function is
//!
//! ```c
//! SBPF_FN f_<pc>(uint64_t r0, …, uint64_t r9, uint64_t r10);   /* static sbpf_ret, minsize */
//! typedef struct { uint64_t r0, r1, r2, r3, r4, r5; } sbpf_ret;
//! ```
//!
//! which is wider than spec §3's `f_<pc>(r1..r5)` returning `r0`, because `interp.rs`'s call is
//! wider: a call copies nothing and clears nothing, so the callee starts with *every* register the
//! caller had (`r0` and `r6..r9` included — a program may read them before writing them), and on
//! `exit` only `r6..r9` and `r10` are restored (`push_frame`/`EXIT`), so the caller continues with
//! the callee's final `r0..r5`; `r6..r10` are the caller's own C locals, which a C call cannot
//! touch, so their restoration is free. `r10` goes in already advanced by one `STACK_FRAME`
//! (`push_frame`). A program may write `r10` (`interp.rs` rejects only a register number above
//! 10), so it is an ordinary local like the rest. A call site passes only the registers the callee
//! may read before writing and copies back only those it may write (0 for the rest — the callee
//! cannot tell): see `Calls`.
//!
//! The call depth is the global `sbpf_depth`: `SBPF_CALL`/`SBPF_CALLX` increment it and trap
//! `CallDepth` when it reaches `SBPF_MAX_CALL_DEPTH` — `push_frame`'s check, made before the target
//! is fetched (so a call to a bad target still checks depth first, then traps `BadJump`) — and
//! decrement it on return. A `callx` target is looked up at run time by `sbpf_callx_target`, a
//! `switch` over every function the scan knows ([`Scan::callx_targets`]) keyed by `interp.rs:426`'s
//! own arithmetic, `(addr - text_va) / 8`; anything else is `BadJump` (a bad fetch). A function
//! whose entry lies inside another's code is not emitted on its own but as an extra entry of that
//! one (see `Hosts`).
//!
//! # The instruction budget
//!
//! `interp.rs` counts one per instruction (an `lddw` once, a syscall once, a call and an exit once
//! each) and halts `InstructionLimit` before the 200 001st. The emitted code charges each basic
//! block's whole count at the block's head ([`emit_block_head`]) and traps when the budget goes
//! negative — the amended Global Constraint: the halt lands at the head of the block that would
//! cross the limit, and only in that block may its kind differ from the interpreter's. The budget
//! is a function-local `budget`, handed over through `sbpf-rt`'s `sbpf_budget` around every call
//! and return, and every function has one shared `L_limit` trap. Some blocks defer their check to
//! their successors (`choose_checked`), which keeps the same guarantee. A block's count is its
//! instructions plus whatever failed fetch ends it: a register or opcode the interpreter refuses
//! before dispatch still ran the meter ([`TrapKind::BadInsn`] — the instruction is charged but not
//! translated), running off the end of the text is one more meter tick for the fetch that fails,
//! and so is the scanner's shared bad-target block. A call whose *return* slot is outside the text
//! is not: `exit`'s own `slot_at` fails inside the callee's step, so that path is translated inline
//! after the call with nothing charged.
//!
//! # Memory
//!
//! Every load and store is a call into `sbpf-rt`: `sbpf_ld<N>(base, off)` / `sbpf_st<N>(base, off,
//! v)`, `memory.rs`'s `load`/`store` at `interp.rs`'s wrapped `base + off`, which is also the fault
//! payload. There is no alignment rule, so a pointer cast would be wrong on this machine. No stack
//! access is folded: the stack is one flat region a program may address through any register (and
//! `r10` itself may be written), so a folded check would have to re-derive `memory.rs`'s whole
//! bound anyway.
//!
//! # Size
//!
//! The machine's program cap (65 535 words) is what a whole SPL program runs into first: the
//! committed SPL Token ELF's ~12 000 reachable instructions translate to about twice that as plain
//! C at the toolchain's `-Os`. Everything above except the calling convention's width exists to
//! fit it, measured on that ELF (words of RV32, program.c alone): the per-width access entries
//! (−6k), the function-local budget with one trap label (−30k), `minsize` on every translated
//! function (−6k), merging functions that are copies of another's tail (−8k), call-site liveness
//! (−1.7k) and deferred checks (−3.8k). None changes the public output; only the deferred checks
//! change anything observable at all — the halt kind, in the block that crosses the limit.

use crate::scan::{Block, Function, Scan, Term, TrapKind};
use sbpf_core::elf::Program;
use sbpf_core::isa::{self, opc, Class, Insn};
use sbpf_core::syscalls;
use std::fmt::Write as _;

/// `syscalls::SUPPORTED`'s twelve, each with the `sbpf-rt` function that implements it
/// (`sbpf_rt.h`: `sbpf_sys_<name>` with a leading `sol_` and a trailing `_` dropped). Any other hash
/// is emitted as the interpreter's own `Halt::UnknownSyscall(hash)`.
pub const SYSCALLS: [(u32, &str); 12] = [
    (syscalls::ABORT, "sbpf_sys_abort"),
    (syscalls::SOL_PANIC, "sbpf_sys_panic"),
    (syscalls::SOL_LOG, "sbpf_sys_log"),
    (syscalls::SOL_LOG_64, "sbpf_sys_log_64"),
    (
        syscalls::SOL_LOG_COMPUTE_UNITS,
        "sbpf_sys_log_compute_units",
    ),
    (syscalls::SOL_LOG_PUBKEY, "sbpf_sys_log_pubkey"),
    (syscalls::SOL_MEMCPY, "sbpf_sys_memcpy"),
    (syscalls::SOL_MEMMOVE, "sbpf_sys_memmove"),
    (syscalls::SOL_MEMSET, "sbpf_sys_memset"),
    (syscalls::SOL_MEMCMP, "sbpf_sys_memcmp"),
    (syscalls::SOL_ALLOC_FREE, "sbpf_sys_alloc_free"),
    (syscalls::SOL_SHA256, "sbpf_sys_sha256"),
];

/// The C entry point the shim calls: `uint32_t sbpf_entry(uint64_t *r0)`.
pub const ENTRY_SYMBOL: &str = "sbpf_entry";

/// What [`emit_program`] produced, and the counts the CLI reports.
pub struct Emitted {
    pub c: String,
    pub functions: usize,
    pub blocks: usize,
    /// Logical instructions translated, summed over every function's blocks (a body two functions
    /// share is counted, and emitted, once per function).
    pub instructions: usize,
}

/// A C `int` literal for `k`. `i32::MIN` has no literal of its own (`2147483648` is not an `int`),
/// so it is written as the difference C's own `INT_MIN` uses.
fn int_lit(k: i32) -> String {
    if k == i32::MIN {
        "(-2147483647 - 1)".into()
    } else {
        k.to_string()
    }
}

/// `k` sign-extended to 64 bits and used unsigned — `imm as i64 as u64` in `interp.rs`. A
/// non-negative `k` is its own literal; a negative one converts through the cast, which C defines
/// as the value modulo 2^64.
fn u64imm(k: i32) -> String {
    if k >= 0 {
        k.to_string()
    } else {
        format!("(uint64_t){}", int_lit(k))
    }
}

/// `k as u32`.
fn u32imm(k: i32) -> String {
    if k >= 0 {
        k.to_string()
    } else {
        format!("(uint32_t){}", int_lit(k))
    }
}

/// `k` sign-extended, compared signed.
fn s64imm(k: i32) -> String {
    int_lit(k)
}

fn reg(r: u8) -> String {
    format!("r{r}")
}

/// `pc + 1 + off`.
fn jump_target(pc: usize, off: i16) -> i64 {
    pc as i64 + 1 + off as i64
}

fn div_by_zero() -> String {
    "sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0);".into()
}

/// The condition of a conditional jump, without the `if`.
pub fn emit_cond(i: &Insn) -> String {
    let d = reg(i.dst);
    let (s, uimm, simm) = (reg(i.src), u64imm(i.imm), s64imm(i.imm));
    match i.opc {
        opc::JEQ_IMM => format!("{d} == {uimm}"),
        opc::JEQ_REG => format!("{d} == {s}"),
        opc::JNE_IMM => format!("{d} != {uimm}"),
        opc::JNE_REG => format!("{d} != {s}"),
        opc::JGT_IMM => format!("{d} > {uimm}"),
        opc::JGT_REG => format!("{d} > {s}"),
        opc::JGE_IMM => format!("{d} >= {uimm}"),
        opc::JGE_REG => format!("{d} >= {s}"),
        opc::JLT_IMM => format!("{d} < {uimm}"),
        opc::JLT_REG => format!("{d} < {s}"),
        opc::JLE_IMM => format!("{d} <= {uimm}"),
        opc::JLE_REG => format!("{d} <= {s}"),
        opc::JSET_IMM => format!("({d} & {uimm}) != 0"),
        opc::JSET_REG => format!("({d} & {s}) != 0"),
        opc::JSGT_IMM => format!("(int64_t){d} > {simm}"),
        opc::JSGT_REG => format!("(int64_t){d} > (int64_t){s}"),
        opc::JSGE_IMM => format!("(int64_t){d} >= {simm}"),
        opc::JSGE_REG => format!("(int64_t){d} >= (int64_t){s}"),
        opc::JSLT_IMM => format!("(int64_t){d} < {simm}"),
        opc::JSLT_REG => format!("(int64_t){d} < (int64_t){s}"),
        opc::JSLE_IMM => format!("(int64_t){d} <= {simm}"),
        opc::JSLE_REG => format!("(int64_t){d} <= (int64_t){s}"),
        other => panic!("emit_cond: {other:#04x} is not a conditional jump"),
    }
}

/// `lddw`: one statement for both slots. `hi` is the second slot, or `None` if the first is the
/// text's last — then the interpreter's fetch of the high half fails before the register is
/// written (`Halt::BadJump`).
pub fn emit_lddw(lo: &Insn, hi: Option<&Insn>) -> String {
    match hi {
        Some(hi) => format!("r{} = {:#018x}ull;", lo.dst, isa::lddw_imm64(*lo, *hi)),
        None => "sbpf_trap(SBPF_HALT_BAD_JUMP, 0);".into(),
    }
}

/// The C for one instruction at slot `pc`, as spec §3's table has it. `pc` matters only to the
/// jumps (`goto L_<pc + 1 + off>`) and the internal call (`f_<pc + 1 + imm>`); the function emitter
/// takes their resolved targets from the scan's [`Term`] instead. `lddw` is [`emit_lddw`]'s.
pub fn emit_insn(pc: usize, i: &Insn) -> String {
    let (d, s) = (reg(i.dst), reg(i.src));
    let k = i.imm;
    // The 64-bit and 32-bit forms' right-hand operand, register or immediate.
    let is_reg = i.opc & 0x08 != 0;
    let y64 = if is_reg { s.clone() } else { u64imm(k) };
    let y32 = if is_reg {
        format!("(uint32_t){s}")
    } else {
        u32imm(k)
    };
    let shift = |mask: u32| {
        if is_reg {
            format!("({s} & {mask})")
        } else {
            format!("({k} & {mask})")
        }
    };
    match i.opc {
        // ---- loads and stores ----
        opc::LD_DW_IMM => panic!("emit_insn: lddw spans two slots; use emit_lddw"),
        opc::LD_B_REG => format!("{d} = sbpf_ld1({s}, {});", i.off),
        opc::LD_H_REG => format!("{d} = sbpf_ld2({s}, {});", i.off),
        opc::LD_W_REG => format!("{d} = sbpf_ld4({s}, {});", i.off),
        opc::LD_DW_REG => format!("{d} = sbpf_ld8({s}, {});", i.off),
        opc::ST_B_IMM => format!("sbpf_st1({d}, {}, {});", i.off, u64imm(k)),
        opc::ST_H_IMM => format!("sbpf_st2({d}, {}, {});", i.off, u64imm(k)),
        opc::ST_W_IMM => format!("sbpf_st4({d}, {}, {});", i.off, u64imm(k)),
        opc::ST_DW_IMM => format!("sbpf_st8({d}, {}, {});", i.off, u64imm(k)),
        opc::ST_B_REG => format!("sbpf_st1({d}, {}, {s});", i.off),
        opc::ST_H_REG => format!("sbpf_st2({d}, {}, {s});", i.off),
        opc::ST_W_REG => format!("sbpf_st4({d}, {}, {s});", i.off),
        opc::ST_DW_REG => format!("sbpf_st8({d}, {}, {s});", i.off),

        // ---- 32-bit: add, sub and mul sign-extend their result ----
        opc::ADD32_IMM | opc::ADD32_REG => format!("{d} = (uint64_t)(int64_t)(int32_t)((uint32_t){d} + {y32});"),
        opc::SUB32_IMM | opc::SUB32_REG => format!("{d} = (uint64_t)(int64_t)(int32_t)((uint32_t){d} - {y32});"),
        opc::MUL32_IMM | opc::MUL32_REG => format!("{d} = (uint64_t)(int64_t)(int32_t)((uint32_t){d} * {y32});"),
        // ---- … and everything else zero-extends ----
        opc::DIV32_IMM | opc::MOD32_IMM if k == 0 => div_by_zero(),
        opc::DIV32_IMM => format!("{d} = (uint32_t)((uint32_t){d} / {y32});"),
        opc::MOD32_IMM => format!("{d} = (uint32_t)((uint32_t){d} % {y32});"),
        opc::DIV32_REG => format!(
            "if ((uint32_t){s} == 0) sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0); {d} = (uint32_t)((uint32_t){d} / {y32});"
        ),
        opc::MOD32_REG => format!(
            "if ((uint32_t){s} == 0) sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0); {d} = (uint32_t)((uint32_t){d} % {y32});"
        ),
        opc::OR32_IMM | opc::OR32_REG => format!("{d} = (uint32_t)((uint32_t){d} | {y32});"),
        opc::AND32_IMM | opc::AND32_REG => format!("{d} = (uint32_t)((uint32_t){d} & {y32});"),
        opc::XOR32_IMM | opc::XOR32_REG => format!("{d} = (uint32_t)((uint32_t){d} ^ {y32});"),
        opc::LSH32_IMM | opc::LSH32_REG => format!("{d} = (uint32_t)((uint32_t){d} << {});", shift(31)),
        opc::RSH32_IMM | opc::RSH32_REG => format!("{d} = (uint32_t)((uint32_t){d} >> {});", shift(31)),
        opc::ARSH32_IMM | opc::ARSH32_REG => format!("{d} = (uint32_t)((int32_t){d} >> {});", shift(31)),
        opc::NEG32 => format!("{d} = (uint32_t)-(uint32_t){d};"),
        opc::MOV32_IMM => format!("{d} = {};", u32imm(k)),
        opc::MOV32_REG => format!("{d} = (uint32_t){s};"),
        opc::LE => match k {
            16 => format!("{d} = (uint16_t){d};"),
            32 => format!("{d} = (uint32_t){d};"),
            64 => format!("(void){d};"),
            _ => format!("sbpf_trap(SBPF_HALT_BAD_INSN, {:#04x});", opc::LE),
        },
        opc::BE => match k {
            16 => format!("{d} = __builtin_bswap16((uint16_t){d});"),
            32 => format!("{d} = __builtin_bswap32((uint32_t){d});"),
            64 => format!("{d} = __builtin_bswap64({d});"),
            _ => format!("sbpf_trap(SBPF_HALT_BAD_INSN, {:#04x});", opc::BE),
        },

        // ---- 64-bit ----
        opc::ADD64_IMM | opc::ADD64_REG => format!("{d} = {d} + {y64};"),
        opc::SUB64_IMM | opc::SUB64_REG => format!("{d} = {d} - {y64};"),
        opc::MUL64_IMM | opc::MUL64_REG => format!("{d} = {d} * {y64};"),
        opc::DIV64_IMM | opc::MOD64_IMM if k == 0 => div_by_zero(),
        opc::DIV64_IMM => format!("{d} = {d} / {y64};"),
        opc::MOD64_IMM => format!("{d} = {d} % {y64};"),
        opc::DIV64_REG => format!("if ({s} == 0) sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0); {d} = {d} / {s};"),
        opc::MOD64_REG => format!("if ({s} == 0) sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0); {d} = {d} % {s};"),
        opc::OR64_IMM | opc::OR64_REG => format!("{d} = {d} | {y64};"),
        opc::AND64_IMM | opc::AND64_REG => format!("{d} = {d} & {y64};"),
        opc::XOR64_IMM | opc::XOR64_REG => format!("{d} = {d} ^ {y64};"),
        opc::LSH64_IMM | opc::LSH64_REG => format!("{d} = {d} << {};", shift(63)),
        opc::RSH64_IMM | opc::RSH64_REG => format!("{d} = {d} >> {};", shift(63)),
        opc::ARSH64_IMM | opc::ARSH64_REG => format!("{d} = (uint64_t)((int64_t){d} >> {});", shift(63)),
        opc::NEG64 => format!("{d} = -{d};"),
        opc::MOV64_IMM => format!("{d} = {};", u64imm(k)),
        opc::MOV64_REG => format!("{d} = {s};"),

        // ---- control flow ----
        opc::JA => format!("goto L_{};", jump_target(pc, i.off)),
        opc::CALL_IMM if i.src == 1 => emit_syscall(k as u32),
        // Out of context (no scan), a call passes and copies back every register: the conservative
        // form of what the function emitter narrows by liveness.
        opc::CALL_IMM => format!("SBPF_CALL(f_{}{}, {});", pc as i64 + 1 + k as i64, call_args(R0_R9), copy_back(R0_R5)),
        opc::CALL_REG => format!("SBPF_CALLX(r{}, {}, {});", k as u32, call_args(R0_R9), copy_back(R0_R5)),
        opc::EXIT => "SBPF_RETURN();".into(),
        o if isa::classify(o) == Some(Class::Jmp) => {
            format!("if ({}) goto L_{};", emit_cond(i), jump_target(pc, i.off))
        }
        other => format!("sbpf_trap(SBPF_HALT_BAD_INSN, {other:#04x});"),
    }
}

/// A syscall by hash: the runtime's function for a supported one, the interpreter's
/// `UnknownSyscall(hash)` for anything else (CPI included — spec §5, amended).
fn emit_syscall(hash: u32) -> String {
    match SYSCALLS.iter().find(|(h, _)| *h == hash) {
        Some((_, f)) => format!("r0 = {f}(r1, r2, r3, r4, r5);"),
        None => format!("sbpf_trap(SBPF_HALT_UNKNOWN_SYSCALL, {hash:#010x}u);"),
    }
}

/// The budget charge at the head of a block of `n` counted instructions.
pub fn emit_block_head(n: usize) -> String {
    format!("if ((budget -= {n}) < 0) goto L_limit;")
}

/// The charge of a block whose check is deferred to its successors (see `choose_checked`).
pub fn emit_block_charge(n: usize) -> String {
    format!("budget -= {n};")
}

/// The successors of `b` inside its function (a call's callee is not one).
fn successors(b: &EBlock, n_slots: usize) -> Vec<usize> {
    match b.term {
        Term::Fallthrough(n) | Term::Jump(n) | Term::Syscall { next: n, .. } => vec![n],
        Term::CondJump { taken, not } => vec![taken, not],
        Term::Call { next, .. } | Term::CallX { next } if next < n_slots => vec![next],
        _ => vec![],
    }
}

/// Which blocks check the budget at their head; the rest only charge it. A block may skip its check
/// when every block it can hand control to checks, it has no edge to or from another unchecked
/// block, and it does not end in `exit` or a call (whose callee's blocks would run before any
/// check). Then if the limit is crossed inside an unchecked block `X`, `X` runs to its end (it may
/// fault there — a halt kind that differs from the interpreter's only in `X`, the block that crosses
/// the limit, as the amended Global Constraint allows) and the next block's check halts
/// `InstructionLimit`; the status and the eight public words are the interpreter's either way, since
/// every exceptional halt publishes the pre-state. No run the interpreter completes within the limit
/// is ever charged more than it has executed, so none is halted. What this buys is size: a check is
/// three RV32 words in a large function (a branch over a jump to the shared trap), a charge none
/// (clang folds it into the next check's constant), and the SPL Token program does not fit the
/// machine's 65 535-word program cap with a check at every one of its ~3 500 block heads.
fn choose_checked(blocks: &[EBlock], n_slots: usize) -> Vec<bool> {
    use std::collections::BTreeMap;
    let index: BTreeMap<usize, usize> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start, i))
        .collect();
    let succ: Vec<Vec<usize>> = blocks
        .iter()
        .map(|b| {
            successors(b, n_slots)
                .into_iter()
                .filter_map(|pc| index.get(&pc).copied())
                .collect()
        })
        .collect();
    let mut pred: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    for (i, ss) in succ.iter().enumerate() {
        for &j in ss {
            pred[j].push(i);
        }
    }
    let mut checked = vec![true; blocks.len()];
    for (i, b) in blocks.iter().enumerate() {
        let eligible = !matches!(b.term, Term::Exit | Term::Call { .. } | Term::CallX { .. })
            && !succ[i].contains(&i)
            && succ[i].iter().chain(&pred[i]).all(|&j| checked[j]);
        if eligible {
            checked[i] = false;
        }
    }
    checked
}

/// The fixed part of `program.c` before the functions.
const PRELUDE: &str = r#"/* Generated by sbpf2rv from an sBPF ELF — do not edit; re-run sbpf2rv instead.
 * The translation's rules are sbpf2rv/src/emit.rs's module docs; the runtime is sbpf-rt/sbpf_rt.h. */
#include "sbpf_rt.h"

/* r0..r5 as a callee leaves them: `interp.rs`'s `exit` restores only r6..r10. */
typedef struct {
    uint64_t r0, r1, r2, r3, r4, r5;
} sbpf_ret;
typedef sbpf_ret (*sbpf_callee)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                uint64_t, uint64_t, uint64_t, uint64_t);

/* Every translated function is size-optimised: the image's program-word cap, not speed, is what a
 * whole SPL program runs into first. The toolchain's flags are unchanged; this is per function. */
#define SBPF_FN __attribute__((minsize)) static sbpf_ret

/* The call depth: frames pushed and not yet popped (`Vm::depth`). */
static uint32_t sbpf_depth;
/* Which entry of a merged function to start at: 0 for its own, else the entry's pc + 1. Set
 * immediately before a call and cleared by the callee's first statement. */
static uint32_t sbpf_sel;

/* `push_frame`: the depth check comes first; the callee gets the caller's registers (those it may
 * read before writing: sbpf2rv/src/emit.rs, "register liveness across calls"), r10 one frame up;
 * the caller continues with the callee's r0..r5 (those it may write) and its own r6..r10. The
 * instruction budget lives in each function's local `budget` and is handed over through
 * `sbpf_budget` around the call. `call` is the whole call expression, `copy` the copy-back. */
#define SBPF_DEPTH_PUSH() \
    do { \
        if (++sbpf_depth == SBPF_MAX_CALL_DEPTH) sbpf_trap(SBPF_HALT_CALL_DEPTH, 0); \
    } while (0)
#define SBPF_CALL(call, copy) \
    do { \
        SBPF_DEPTH_PUSH(); \
        sbpf_budget = budget; \
        sbpf_ret x_ = call; \
        budget = (int32_t)sbpf_budget; \
        sbpf_depth--; \
        copy \
    } while (0)
/* `callx`: the address is read, the frame pushed, then the target fetched (`interp.rs`). */
#define SBPF_CALLX(a, args, copy) \
    do { \
        uint64_t a_ = (a); \
        SBPF_DEPTH_PUSH(); \
        sbpf_callee f_ = sbpf_callx_target(a_); \
        sbpf_budget = budget; \
        sbpf_ret x_ = f_ args; \
        budget = (int32_t)sbpf_budget; \
        sbpf_depth--; \
        copy \
    } while (0)
/* An internal call whose target is not code: the frame push (and its depth check) still runs. */
#define SBPF_CALL_BAD_TARGET() \
    do { \
        SBPF_DEPTH_PUSH(); \
        sbpf_trap(SBPF_HALT_BAD_JUMP, 0); \
    } while (0)
/* `exit`. */
#define SBPF_RETURN() \
    do { \
        sbpf_budget = budget; \
        return (sbpf_ret){r0, r1, r2, r3, r4, r5}; \
    } while (0)

"#;

const PARAMS: &str = "uint64_t r0, uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r6, uint64_t r7, uint64_t r8, uint64_t r9, uint64_t r10";

/// One block as emitted: the scanner's, possibly split at a merged function's entry.
struct EBlock {
    start: usize,
    end: usize,
    /// `(pc, instruction)`, in order.
    insns: Vec<(usize, Insn)>,
    term: Term,
}

/// The instruction-start pcs of `b`, paired with their instructions.
fn with_pcs(b: &Block) -> Vec<(usize, Insn)> {
    let mut pc = b.start;
    b.insns
        .iter()
        .map(|i| {
            let here = pc;
            pc += if i.opc == opc::LD_DW_IMM { 2 } else { 1 };
            (here, *i)
        })
        .collect()
}

/// Merged functions. The scan gives every function its own copy of everything reachable from its
/// entry, so a function whose entry lies inside another's code (the SPL Token ELF has chains of
/// them: 11560 falls into 11565, which falls into 11571, …) is a byte-for-byte duplicate of that
/// code from that point on — and code reachable from a pc is the same whichever function reaches
/// it, since every edge is resolved per pc. Such a function is emitted once, as an extra entry label
/// of its *host*: the function containing its entry with the most code (ties to the lowest entry).
/// A call to it sets `sbpf_sel` and calls the host, which starts at the label. Nothing observable
/// changes: the same code runs from the same pc with the same registers, frame and depth; only the
/// block boundaries — where the budget is checked — may differ, and both are basic blocks.
struct Hosts {
    /// `host[entry]` for every function (a host maps to itself).
    host: std::collections::BTreeMap<usize, usize>,
}

impl Hosts {
    fn new(scan: &Scan) -> Hosts {
        use std::collections::{BTreeMap, BTreeSet};
        let starts: BTreeMap<usize, BTreeSet<usize>> = scan
            .functions
            .iter()
            .map(|f| {
                (
                    f.entry,
                    f.blocks
                        .iter()
                        .flat_map(|b| with_pcs(b).into_iter().map(|(pc, _)| pc))
                        .collect(),
                )
            })
            .collect();
        let mut host = BTreeMap::new();
        for g in &scan.functions {
            let best = scan
                .functions
                .iter()
                .filter(|f| f.entry == g.entry || starts[&f.entry].contains(&g.entry))
                .max_by_key(|f| (starts[&f.entry].len(), std::cmp::Reverse(f.entry)))
                .map_or(g.entry, |f| f.entry);
            host.insert(g.entry, best);
        }
        Hosts { host }
    }

    fn host_of(&self, f: usize) -> usize {
        self.host[&f]
    }

    fn members_of(&self, h: usize) -> Vec<usize> {
        self.host
            .iter()
            .filter(|(g, hh)| **hh == h && **g != h)
            .map(|(g, _)| *g)
            .collect()
    }

    /// The C expression naming the function to call for sBPF function `f`.
    fn callee(&self, f: usize) -> String {
        let h = self.host_of(f);
        if h == f {
            format!("f_{f}")
        } else {
            format!("(sbpf_sel = {}u, f_{h})", f + 1)
        }
    }
}

/// `program.c` for `scan` of `program`.
pub fn emit_program(program: &Program<'_>, scan: &Scan) -> Emitted {
    let n_slots = program.text.len() / 8;
    let hosts = Hosts::new(scan);
    let calls = Calls::new(scan);
    let mut c = String::from(PRELUDE);
    let mut blocks = 0;
    let mut instructions = 0;

    c.push_str("static sbpf_callee sbpf_callx_target(uint64_t addr);\n");
    let emitted: Vec<&Function> = scan
        .functions
        .iter()
        .filter(|f| hosts.host_of(f.entry) == f.entry)
        .collect();
    for f in &emitted {
        let _ = writeln!(c, "SBPF_FN f_{}({});", f.entry, PARAMS);
    }
    c.push('\n');

    for f in &emitted {
        let (b, n) = emit_function(&mut c, program, n_slots, f, &hosts, &calls);
        blocks += b;
        instructions += n;
    }

    // callx: `interp.rs:426`'s `(addr - text_va) / 8`, then the fetch — a known function, or BadJump.
    // A slot above u32::MAX is no function's; checking that first lets the switch be 32-bit.
    c.push_str(
        "static sbpf_callee sbpf_callx_target(uint64_t addr) {\n    uint64_t slot = (addr - sbpf_r.text_va) / 8;\n    \
         if (slot >> 32) sbpf_trap(SBPF_HALT_BAD_JUMP, 0);\n    switch ((uint32_t)slot) {\n",
    );
    for t in &scan.callx_targets {
        let h = hosts.host_of(*t);
        if h == *t {
            let _ = writeln!(c, "    case {t}: return f_{t};");
        } else {
            let _ = writeln!(c, "    case {t}: sbpf_sel = {}u; return f_{h};", t + 1);
        }
    }
    c.push_str("    default: sbpf_trap(SBPF_HALT_BAD_JUMP, 0);\n    }\n}\n\n");

    // The entry: `Vm::new`'s registers — r1 the input region, r10 the top of frame 0, the rest zero.
    let _ = write!(
        c,
        "static uint64_t sbpf_entry_fn(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5) {{\n    \
         return {callee}(0, r1, r2, r3, r4, r5, 0, 0, 0, 0, SBPF_REGION_STACK + SBPF_STACK_FRAME).r0;\n}}\n\n\
         /* Runs the program over the regions the caller put in `sbpf_r`, after `sbpf_rt_reset`. Returns an\n \
         * SBPF_HALT_* code (`sbpf_halt_arg` holds its payload); SBPF_HALT_EXIT sets `*r0`. */\n\
         uint32_t {ENTRY_SYMBOL}(uint64_t *r0) {{\n    \
         sbpf_depth = 0;\n    \
         sbpf_sel = 0;\n    \
         return sbpf_rt_enter(sbpf_entry_fn, SBPF_REGION_INPUT, 0, 0, 0, 0, r0);\n}}\n",
        callee = hosts.callee(scan.entry)
    );

    Emitted {
        c,
        functions: scan.functions.len(),
        blocks,
        instructions,
    }
}

/// One host function: its blocks, split at every merged member's entry, entry block first.
/// Returns the blocks and instructions emitted.
fn emit_function(
    c: &mut String,
    program: &Program<'_>,
    n_slots: usize,
    f: &Function,
    hosts: &Hosts,
    calls: &Calls,
) -> (usize, usize) {
    let members = hosts.members_of(f.entry);
    let mut eblocks: Vec<EBlock> = Vec::new();
    for b in &f.blocks {
        let pcs = with_pcs(b);
        let mut cur = EBlock {
            start: b.start,
            end: b.end,
            insns: Vec::new(),
            term: b.term,
        };
        for (pc, i) in pcs {
            if pc != cur.start && members.contains(&pc) {
                let prefix_end = cur.insns.last().map_or(cur.start, |(p, _)| *p);
                let prefix = EBlock {
                    start: cur.start,
                    end: prefix_end,
                    insns: std::mem::take(&mut cur.insns),
                    term: Term::Fallthrough(pc),
                };
                eblocks.push(prefix);
                cur.start = pc;
            }
            cur.insns.push((pc, i));
        }
        eblocks.push(cur);
    }

    let checked = choose_checked(&eblocks, n_slots);

    let _ = writeln!(c, "SBPF_FN f_{}({}) {{", f.entry, PARAMS);
    c.push_str("    int32_t budget = (int32_t)sbpf_budget;\n");
    if !members.is_empty() {
        c.push_str("    uint32_t sel = sbpf_sel;\n    sbpf_sel = 0;\n    switch (sel) {\n");
        for m in &members {
            let _ = writeln!(c, "    case {}u: goto L_{m};", m + 1);
        }
        c.push_str("    }\n");
    }
    // The entry block first, so the function starts where it should whatever lies before it.
    let entry = eblocks.iter().position(|b| b.start == f.entry);
    let order = entry
        .into_iter()
        .chain((0..eblocks.len()).filter(|i| Some(*i) != entry));
    let mut n = 0;
    for i in order {
        n += eblocks[i].insns.len();
        emit_block(c, program, n_slots, &eblocks[i], checked[i], hosts, calls);
    }
    c.push_str("L_limit:\n    sbpf_trap(SBPF_HALT_INSTRUCTION_LIMIT, 0);\n}\n\n");
    (eblocks.len(), n)
}

fn emit_block(
    c: &mut String,
    program: &Program<'_>,
    n_slots: usize,
    b: &EBlock,
    checked: bool,
    hosts: &Hosts,
    calls: &Calls,
) {
    let _ = writeln!(c, "L_{}:", b.start);
    let mut lines: Vec<String> = Vec::new();
    let synthetic = b.insns.is_empty() && b.start >= n_slots;

    // Every instruction but a control-flow terminator, which the `Term` translates below.
    let body_len = match b.insns.last() {
        Some((_, last)) if is_control(last) => b.insns.len() - 1,
        _ => b.insns.len(),
    };
    for (pc, insn) in &b.insns[..body_len] {
        if insn.opc == opc::LD_DW_IMM {
            let hi = (pc + 1 < n_slots).then(|| isa::decode(slot(program.text, pc + 1)));
            lines.push(emit_lddw(insn, hi.as_ref()));
        } else {
            lines.push(emit_insn(*pc, insn));
        }
    }
    let last = b.insns.last().map(|(_, i)| i);

    // What the block costs: its instructions, plus the fetch that fails at its end, if one does.
    let extra = match b.term {
        Term::Trap(TrapKind::BadInsn(_)) => 1, // the refused instruction ran the meter, not itself
        Term::Trap(TrapKind::BadJump) if synthetic => 1, // the failed fetch
        Term::Trap(TrapKind::BadJump) => match last {
            // Both fail inside their own step: the call's target fetch, the lddw's second slot.
            Some(l) if l.opc == opc::CALL_IMM => 0,
            Some(l) if l.opc == opc::LD_DW_IMM && b.end + 1 >= n_slots => 0,
            // Anything else ran, and the next step's fetch fails.
            _ => 1,
        },
        _ => 0,
    };
    let cost = b.insns.len() + extra;
    if cost > 0 {
        if checked {
            let _ = writeln!(c, "    {}", emit_block_head(cost));
        } else {
            let _ = writeln!(c, "    {}", emit_block_charge(cost));
        }
    }
    for l in lines {
        let _ = writeln!(c, "    {l}");
    }

    let goto = |t: usize| format!("goto L_{t};");
    // After a call returns: the return slot, or — if it is not in the text — the interpreter's
    // `exit` failing to fetch it (charged nothing more: see the module docs).
    let after_call = |next: usize| {
        if next >= n_slots {
            "sbpf_trap(SBPF_HALT_BAD_JUMP, 0);".to_string()
        } else {
            goto(next)
        }
    };
    let term: Vec<String> = match b.term {
        Term::Fallthrough(next) => vec![goto(next)],
        Term::Jump(t) => vec![goto(t)],
        Term::CondJump { taken, not } => {
            let i = last.expect("a conditional jump ends its block");
            vec![format!("if ({}) {}", emit_cond(i), goto(taken)), goto(not)]
        }
        Term::Exit => vec!["SBPF_RETURN();".into()],
        Term::Call { target, next } => vec![
            format!(
                "SBPF_CALL({}{}, {});",
                hosts.callee(target),
                call_args(calls.live_in[&target]),
                copy_back(calls.modified[&target])
            ),
            after_call(next),
        ],
        Term::Syscall { hash, next } => vec![emit_syscall(hash), goto(next)],
        Term::CallX { next } => {
            let i = last.expect("a callx ends its block");
            vec![
                format!(
                    "SBPF_CALLX(r{}, {}, {});",
                    i.imm as u32,
                    call_args(calls.callx_live),
                    copy_back(calls.callx_mod)
                ),
                after_call(next),
            ]
        }
        Term::Trap(TrapKind::BadInsn(o)) => {
            vec![format!("sbpf_trap(SBPF_HALT_BAD_INSN, {o:#04x});")]
        }
        Term::Trap(TrapKind::BadJump) => match last {
            Some(l) if l.opc == opc::CALL_IMM && l.src == 0 => {
                vec!["SBPF_CALL_BAD_TARGET();".into()]
            }
            _ => vec!["sbpf_trap(SBPF_HALT_BAD_JUMP, 0);".into()],
        },
    };
    for l in term {
        let _ = writeln!(c, "    {l}");
    }
}

/// A jump, call or exit — an instruction the block's [`Term`] translates, not the body.
fn is_control(i: &Insn) -> bool {
    matches!(
        isa::classify(i.opc),
        Some(Class::Jmp | Class::Call | Class::Exit)
    )
}

fn slot(text: &[u8], pc: usize) -> u64 {
    let b = &text[pc * 8..pc * 8 + 8];
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

// ---- register liveness across calls -----------------------------------------------------------

/// A set of registers `r0..r10`, bit `n` for `rn`.
type Regs = u16;

const R0_R5: Regs = 0x3f;
const R1_R5: Regs = 0x3e;
const R0_R9: Regs = 0x3ff;

fn bit(r: u8) -> Regs {
    1 << r
}

/// What one instruction reads and writes, as register sets (bit `n` for `rn`) — `interp.rs`'s
/// semantics opcode by opcode, never inferred from an encoding bit: the ALU/JMP source bit
/// (`0x08`) does not carry over to the stores (`stxb` 0x73 and `stxw` 0x63 have it clear, `st`
/// immediates 0x6a and 0x7a have it set). Calls, `callx` and `exit` read and write nothing *here*:
/// the block's [`Term`] carries their effect (liveness takes a call's reads from the callee, and
/// `callx`'s register from its immediate). An opcode `isa::classify` does not assign is never
/// executed (the scanner traps before it), so it is empty too.
pub fn use_def(i: &Insn) -> (u16, u16) {
    use opc::*;
    let (d, s) = (bit(i.dst), bit(i.src));
    match i.opc {
        LD_DW_IMM => (0, d),
        LD_B_REG | LD_H_REG | LD_W_REG | LD_DW_REG => (s, d),
        ST_B_IMM | ST_H_IMM | ST_W_IMM | ST_DW_IMM => (d, 0),
        ST_B_REG | ST_H_REG | ST_W_REG | ST_DW_REG => (d | s, 0),
        MOV32_IMM | MOV64_IMM => (0, d),
        MOV32_REG | MOV64_REG => (s, d),
        NEG32 | NEG64 | LE | BE => (d, d),
        ADD32_IMM | SUB32_IMM | MUL32_IMM | DIV32_IMM | OR32_IMM | AND32_IMM | LSH32_IMM
        | RSH32_IMM | MOD32_IMM | XOR32_IMM | ARSH32_IMM | ADD64_IMM | SUB64_IMM | MUL64_IMM
        | DIV64_IMM | OR64_IMM | AND64_IMM | LSH64_IMM | RSH64_IMM | MOD64_IMM | XOR64_IMM
        | ARSH64_IMM => (d, d),
        ADD32_REG | SUB32_REG | MUL32_REG | DIV32_REG | OR32_REG | AND32_REG | LSH32_REG
        | RSH32_REG | MOD32_REG | XOR32_REG | ARSH32_REG | ADD64_REG | SUB64_REG | MUL64_REG
        | DIV64_REG | OR64_REG | AND64_REG | LSH64_REG | RSH64_REG | MOD64_REG | XOR64_REG
        | ARSH64_REG => (d | s, d),
        JA => (0, 0),
        JEQ_IMM | JGT_IMM | JGE_IMM | JLT_IMM | JLE_IMM | JSET_IMM | JNE_IMM | JSGT_IMM
        | JSGE_IMM | JSLT_IMM | JSLE_IMM => (d, 0),
        JEQ_REG | JGT_REG | JGE_REG | JLT_REG | JLE_REG | JSET_REG | JNE_REG | JSGT_REG
        | JSGE_REG | JSLT_REG | JSLE_REG => (d | s, 0),
        CALL_IMM | CALL_REG | EXIT => (0, 0),
        _ => (0, 0),
    }
}

/// Which registers a call must pass and copy back. `interp.rs`'s callee sees every register the
/// caller had and hands back `r0..r5` as it left them; but a register the callee (transitively)
/// never reads before writing need not be passed — the callee gets 0 there instead of the
/// caller's value, and cannot tell — and one it never writes need not be copied back, since the
/// caller's own value is what it would have received. So: `live_in[f]`, the registers `r0..r9`
/// possibly read before written from `f`'s entry (every path to an `exit` reading what that exit
/// hands back and the caller copies), and `modified[f]`, the registers of `r0..r5` possibly written before it returns.
/// Both are least fixpoints over the call graph, `callx` taken as a call to every known function.
/// `r10` is always passed.
struct Calls {
    live_in: std::collections::BTreeMap<usize, Regs>,
    modified: std::collections::BTreeMap<usize, Regs>,
    callx_live: Regs,
    callx_mod: Regs,
}

impl Calls {
    fn new(scan: &Scan) -> Calls {
        use std::collections::BTreeMap;
        let mut modified: BTreeMap<usize, Regs> =
            scan.functions.iter().map(|f| (f.entry, 0)).collect();
        let targets = &scan.callx_targets;
        loop {
            let callx_mod = targets.iter().fold(0, |m, t| m | modified[t]);
            let mut changed = false;
            for f in &scan.functions {
                let mut m = 0;
                for b in &f.blocks {
                    for i in &b.insns {
                        m |= use_def(i).1;
                    }
                    m |= match b.term {
                        Term::Call { target, .. } => modified[&target],
                        Term::CallX { .. } => callx_mod,
                        Term::Syscall { .. } => bit(0),
                        _ => 0,
                    };
                }
                let m = m & R0_R5;
                if m != modified[&f.entry] {
                    modified.insert(f.entry, m);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let callx_mod = targets.iter().fold(0, |m, t| m | modified[t]);

        let mut live_in: BTreeMap<usize, Regs> =
            scan.functions.iter().map(|f| (f.entry, 0)).collect();
        loop {
            let callx_live = targets.iter().fold(0, |m, t| m | live_in[t]);
            let mut changed = false;
            for f in &scan.functions {
                let l = live_at_entry(f, &live_in, callx_live, modified[&f.entry]);
                if l != live_in[&f.entry] {
                    live_in.insert(f.entry, l);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let callx_live = targets.iter().fold(0, |m, t| m | live_in[t]);
        Calls {
            live_in,
            modified,
            callx_live,
            callx_mod,
        }
    }
}

/// Backward liveness over `f`'s blocks: the registers read before written from its entry. `exit`
/// reads `at_exit`, what a caller copies back. (Not `r0` unconditionally: if `f` never writes it,
/// no caller copies it back, and the entry's own caller, `sbpf_entry_fn`, passes the interpreter's
/// initial 0 whatever `f` reads.)
fn live_at_entry(
    f: &Function,
    live_in: &std::collections::BTreeMap<usize, Regs>,
    callx_live: Regs,
    at_exit: Regs,
) -> Regs {
    use std::collections::BTreeMap;
    let index: BTreeMap<usize, usize> = f
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start, i))
        .collect();
    let mut live: Vec<Regs> = vec![0; f.blocks.len()];
    loop {
        let mut changed = false;
        for (k, b) in f.blocks.iter().enumerate().rev() {
            let succ = |pc: usize| index.get(&pc).map_or(0, |&j| live[j]);
            // At the terminator.
            let mut l: Regs = match b.term {
                Term::Fallthrough(n) | Term::Jump(n) => succ(n),
                Term::CondJump { taken, not } => succ(taken) | succ(not),
                Term::Exit => at_exit,
                // A call may leave any register as it was, so it kills nothing.
                Term::Call { target, next } => succ(next) | live_in[&target],
                Term::CallX { next } => {
                    let r = b.insns.last().map_or(0, |i| bit(i.imm as u8));
                    succ(next) | callx_live | r
                }
                Term::Syscall { next, .. } => (succ(next) & !bit(0)) | R1_R5,
                Term::Trap(_) => 0,
            };
            // The body, backwards (a control-flow terminator's own reads are its `Term`'s above,
            // except a conditional jump's comparison, which `use_def` gives).
            for i in b.insns.iter().rev() {
                let (u, d) = use_def(i);
                l = (l & !d) | u;
            }
            if l != live[k] {
                live[k] = l;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    index.get(&f.entry).map_or(0, |&j| live[j]) & R0_R9
}

/// A call's argument list: each of `r0..r9` if `live`, else `0`; `r10` one frame up.
fn call_args(live: Regs) -> String {
    let mut a: Vec<String> = (0..10u8)
        .map(|r| {
            if live & bit(r) != 0 {
                format!("r{r}")
            } else {
                "0".into()
            }
        })
        .collect();
    a.push("r10 + SBPF_STACK_FRAME".into());
    format!("({})", a.join(", "))
}

/// The copy-back after a call: `rN = x_.rN;` for each of `r0..r5` in `modified`.
fn copy_back(modified: Regs) -> String {
    (0..6u8)
        .filter(|r| modified & bit(*r) != 0)
        .map(|r| format!("r{r} = x_.r{r};"))
        .collect::<Vec<_>>()
        .join(" ")
}
