//! The scanner: recovers functions, basic blocks and control-flow edges from a loaded sBPF
//! program. Nothing is refused: whatever this scanner cannot fully account for statically is
//! translated as code that traps at runtime, exactly as the interpreter would if that code were
//! ever reached — see "Warnings, not refusals" below.
//!
//! # Internal calls versus syscalls
//!
//! `sbpf_core::elf::load` normalises every `call imm` site so the encoding alone says what it is
//! (see `elf.rs`'s and `interp.rs`'s module docs): `src == 0` is a slot-relative internal call
//! (`target = pc + 1 + imm`) and `src == 1` is a syscall whose `imm` is the murmur3-32 hash of its
//! name. This scanner reads exactly that convention — it never re-derives it from relocations,
//! since a [`Program`] built by [`Program::from_text`] (as every test here does) never had any.
//!
//! # Warnings, not refusals
//!
//! Parity with the interpreter on every vector is the spec's binding requirement (spec §1), and
//! every check this section is about — a syscall hash, a register nibble, an opcode byte, a static
//! jump/call target — is one the interpreter itself only makes when it *executes* the instruction
//! in question (`interp.rs::step`'s per-instruction `Halt::BadInsn`/`Halt::BadJump`, and
//! `dispatch`'s `Halt::UnknownSyscall`). None of it happens at load (`elf.rs::load` validates the
//! ELF container — headers, sections, relocations — never per-instruction semantics). So a real,
//! otherwise-loadable ELF can contain any of this on a path no vector this translator is asked to
//! prove ever takes: the committed SPL Token ELF calls two syscalls (`sol_set_return_data`,
//! `sol_get_sysvar`) neither implemented, from instruction handlers the `Transfer` vector never
//! reaches (`research/tests/sbpf_elf.rs`) — confirmed by scanning it (see the task-2 report's fix
//! notes). Refusing the whole program over any of this would break parity in the other direction:
//! a program the interpreter runs successfully would become untranslatable.
//!
//! So none of it is a hard refusal (there is, as of this ruling, no `Refusal` type in this module
//! at all — `scan` cannot fail). Instead, every such site becomes an ordinary [`Term`] the block
//! it is in ends with, and a [`Warning`] recording why:
//!
//! - A bad register (`dst`/`src` naming `r11..r15`) or an opcode `isa::classify` does not assign:
//!   [`Warning::RegisterOutOfRange`] / [`Warning::UnknownOpcode`], and the instruction's block ends
//!   in [`Term::Trap`]`(`[`TrapKind::BadInsn`]`)` — exactly `interp.rs`'s `Halt::BadInsn(opc)`.
//! - A `ja`/conditional-jump/internal-`call` target outside the text, or one landing on a slot
//!   that is not the start of an instruction (the second slot of an `lddw`), or simply falling off
//!   the end of the text after the last instruction: [`Warning::JumpOutOfText`], and
//!   [`Term::Trap`]`(`[`TrapKind::BadJump`]`)` — `interp.rs`'s `Halt::BadJump`. A conditional
//!   jump's two edges are resolved independently (see [`resolve_edge`]): a bad `taken` target does
//!   not stop the `not`-taken side from being real code, and vice versa, since only whichever side
//!   actually runs would ever reach the interpreter's own check.
//! - An unrecognised syscall hash, or one naming a cross-program-invocation call: unchanged from
//!   the previous ruling — [`Warning::UnknownSyscall`] / [`Warning::Cpi`], and an ordinary
//!   [`Term::Syscall`] (Task 4 emits a runtime trap for it instead of a real call).
//!
//! A bad jump/call *target* has nowhere well-formed to point a [`Term`]'s `usize` field at (there
//! is no C label for a pc outside the text), so every such edge across one [`Function`] is
//! redirected to one synthetic pc shared by the whole function — one past its text's last real pc
//! — where [`scan`] plants a single `Block` with no instructions and `term:
//! Term::Trap(TrapKind::BadJump)`. See [`resolve_edge`].

use sbpf_core::elf::Program;
use sbpf_core::isa::{self, opc, Class, Insn};
use sbpf_core::syscalls;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

/// One sBPF function: the entrypoint and every call target found by the scan, in slots from the
/// start of the text (`Program::entry_pc`'s units).
#[derive(Clone, Debug)]
pub struct Function {
    pub entry: usize,
    pub blocks: Vec<Block>,
}

/// One basic block: `[start, end]` inclusive, both pcs in slots — `end` is the pc of the block's
/// last instruction (its terminator, if it has one; the instruction right before a forced split
/// otherwise). `insns` holds one entry per *logical* instruction (an `lddw` contributes one entry
/// even though it occupies two slots), in program order, including the terminator's own
/// instruction when `term` is anything but [`Term::Fallthrough`]. The one exception is the
/// synthetic shared trap block a bad edge can redirect to (see the module docs): `start == end`,
/// `insns` is empty, and `term` is always `Term::Trap(TrapKind::BadJump)`.
#[derive(Clone, Debug)]
pub struct Block {
    pub start: usize,
    pub end: usize,
    pub insns: Vec<Insn>,
    pub term: Term,
}

/// How a block ends, and where control goes next. Every field naming a pc is in slots.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Term {
    /// Not a branch: the block ends here only because the next pc is some other block's start
    /// (a forward or backward jump target landing mid-stream).
    Fallthrough(usize),
    /// `ja`.
    Jump(usize),
    /// Any of the 22 conditional jumps.
    CondJump { taken: usize, not: usize },
    /// `exit`.
    Exit,
    /// `call imm`, `src == 0`: an internal call. Execution resumes at `next` on return.
    Call { target: usize, next: usize },
    /// `call imm`, `src == 1`: a syscall named by `hash`, `murmur3_32` of its name. Execution
    /// resumes at `next` on return. `hash` may or may not be in `syscalls::SUPPORTED` — a hash
    /// this scanner cannot place (unknown, or a CPI name) is still a `Term::Syscall`, with the pc
    /// recorded in [`Scan::warnings`] instead of refusing the scan (see the module docs); Task 4
    /// emits a real call for a supported hash and a runtime trap for anything else.
    Syscall { hash: u32, next: usize },
    /// `callx` (`call reg`, i.e. `isa::opc::CALL_REG`): the target is a register value, unknown
    /// statically. Execution resumes at `next` on return; the possible targets are
    /// [`Scan::callx_targets`].
    CallX { next: usize },
    /// The interpreter would halt unconditionally executing this pc — no successor. Paired with a
    /// [`Warning`] at the same pc explaining why, except at the one synthetic shared block a bad
    /// jump/call *target* redirects to (see the module docs), which carries no `Warning` of its
    /// own — the warning lives at whichever real instruction's edge was redirected here.
    Trap(TrapKind),
}

/// The exact `interp.rs::Halt` a [`Term::Trap`] stands in for, so Task 4 can emit the identical
/// runtime trap without cross-referencing [`Scan::warnings`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrapKind {
    /// `Halt::BadInsn(opc)`: a `dst`/`src` nibble above `r10` (including `callx`'s register-number
    /// immediate), or a byte `isa::classify` does not assign to any v1 class.
    BadInsn(u8),
    /// `Halt::BadJump`: a static jump/call target outside the text, landing on a slot that is not
    /// the start of an instruction, or simply running off the end of the text.
    BadJump,
}

/// The whole scan: every function reachable from the entrypoint (transitively, through internal
/// calls), and the static approximation of every `callx`'s possible target.
#[derive(Clone, Debug)]
pub struct Scan {
    /// `functions[0]` is always the entrypoint's function (`functions[0].entry == entry`); every
    /// other function follows, sorted ascending by its entry pc. Discovery order (which call site
    /// found a function first) is not preserved.
    pub functions: Vec<Function>,
    /// `program.entry_pc` — also `functions[0].entry`.
    pub entry: usize,
    /// Every function entry, sorted and deduplicated: `callx`'s target is a runtime register
    /// value, so the emitter's `switch` (spec §3) covers the whole known function set rather than
    /// one statically-determined pc.
    pub callx_targets: Vec<usize>,
    /// Every pc the scan could not fully verify statically — still translated (as a runtime trap
    /// if the pc is ever actually reached; see the module docs), but worth a diagnostic, since it
    /// means the source ELF's proof coverage does not extend to whatever contains it.
    pub warnings: Vec<Warning>,
}

/// A pc the scan could not fully verify statically — translated anyway, as a runtime trap if
/// reached, rather than refusing the whole program over it (see the module docs).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Warning {
    /// `hash` names neither a `syscalls::SUPPORTED` entry nor a [`CPI_NAMES`] entry — the runtime
    /// has no implementation for it at all (mirrors `Halt::UnknownSyscall` in `interp.rs`).
    UnknownSyscall { pc: usize, hash: u32 },
    /// `hash` matches `murmur3_32` of a cross-program-invocation name. CPI is a multi-program
    /// model this translator does not support (spec §5), but an unreached CPI call must not block
    /// a program that never takes that path, so it is translated the same as any other
    /// unrecognised syscall: a runtime trap, with the name recorded here for diagnostics.
    Cpi { pc: usize, name: &'static str },
    /// A `dst`/`src` nibble naming `r11..r15` (which do not exist), or `callx`'s register-number
    /// immediate above `r10`. `opc` is the instruction's own opcode byte, for `TrapKind::BadInsn`.
    RegisterOutOfRange { pc: usize, opc: u8 },
    /// A byte `isa::classify` does not assign to any v1 class.
    UnknownOpcode { pc: usize, opc: u8 },
    /// A `ja`/conditional-jump/internal-`call` target, or the pc immediately after any
    /// instruction, computed to `target` but not a valid instruction-start pc inside the text.
    /// `pc` is the instruction whose edge this was — never the (invalid) `target` itself.
    JumpOutOfText { pc: usize, target: i64 },
}

/// Cross-program-invocation syscall names, checked against a syscall hash to produce
/// [`Warning::Cpi`]'s name (plan Global Constraints, spec §5). Not exhaustive of every
/// `sol_invoke*` Solana defines — these are the two the design names — but a name is not
/// recoverable from a hash alone, so only a hash in this finite list can be named at all; anything
/// else unrecognised is [`Warning::UnknownSyscall`] instead.
const CPI_NAMES: &[&str] = &["sol_invoke_signed_c", "sol_invoke_signed_rust"];

/// Scans `program`'s text into functions and basic blocks. Infallible — see the module docs'
/// "Warnings, not refusals".
///
/// Two passes:
///
/// 1. **The whole text, unconditionally.** Every slot is decoded (`isa::decode`; an `lddw`
///    occupies two slots but yields one logical instruction, exactly as the interpreter's
///    instruction counter treats it — `interp.rs`'s "an `lddw` spans two slots but counts once").
///    Nothing is validated here — a bad register or an unassigned opcode is only checked once a pc
///    is actually visited in pass 2, matching "unreachable text is not translated" (spec §3) for
///    these too, not just for syscalls.
/// 2. **A reachability walk from the entrypoint and every internal call target found along the
///    way** (a worklist of function roots, so a call inside a called function discovers a third
///    function, and so on). Every check — register range, opcode validity, jump/call targets,
///    syscall hashes — happens exactly once per reachable pc, here.
pub fn scan(program: &Program<'_>) -> Scan {
    let text = program.text;
    let n_slots = text.len() / 8;

    // ---- pass 1: decode every slot ------------------------------------------------------------
    // `insn_len` can overshoot `n_slots` by one for a truncated `lddw` at the very last slot; that
    // slot itself is still a real, decodable (if malformed) instruction start, so it is still
    // inserted here — only slots strictly past it are never visited, which is exactly "not the
    // start of an instruction" for `in_text`'s purposes.
    let mut by_pc: BTreeMap<usize, Insn> = BTreeMap::new();
    let mut pc = 0usize;
    while pc < n_slots {
        let insn = isa::decode(read_slot(text, pc));
        by_pc.insert(pc, insn);
        pc += insn_len(&insn);
    }

    // ---- pass 2: reachability walk, function by function ---------------------------------------
    // `known_functions` doubles as "every function entry found so far" (the `callx_targets`
    // source) and as the worklist's dedup set.
    let mut known_functions: BTreeSet<usize> = BTreeSet::new();
    known_functions.insert(program.entry_pc);
    let mut worklist: VecDeque<usize> = VecDeque::new();
    worklist.push_back(program.entry_pc);

    let mut functions: Vec<Function> = Vec::new();
    let mut warnings: Vec<Warning> = Vec::new();
    while let Some(entry) = worklist.pop_front() {
        let f = scan_function(entry, &by_pc, n_slots, &mut known_functions, &mut worklist, &mut warnings);
        functions.push(f);
    }
    // `program.entry_pc`'s function first, whatever order the worklist discovered the rest in —
    // `Scan::entry` and `functions[0].entry` agree (see `Scan::functions`'s doc comment).
    functions.sort_by_key(|f| if f.entry == program.entry_pc { (0, f.entry) } else { (1, f.entry) });

    let callx_targets: Vec<usize> = known_functions.into_iter().collect();

    Scan { functions, entry: program.entry_pc, callx_targets, warnings }
}

/// One slot's instruction span: two for `lddw`, one for everything else.
fn insn_len(i: &Insn) -> usize {
    if i.opc == opc::LD_DW_IMM {
        2
    } else {
        1
    }
}

/// Slot `pc`'s eight bytes, little-endian — bounds already guaranteed by the `pc < n_slots` loop
/// that calls this.
fn read_slot(text: &[u8], pc: usize) -> u64 {
    let b = &text[pc * 8..pc * 8 + 8];
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// `pc + 1 + off` — the target of every taken conditional jump and of `ja` (`interp.rs`'s
/// `jump_to`), as a signed value so a target before slot 0 is reported rather than wrapping.
fn jump_to(pc: usize, off: i16) -> i64 {
    pc as i64 + 1 + off as i64
}

/// `pc + 1 + imm` — an internal `call imm`'s target (`interp.rs`: `next_pc + i.imm as i64` with
/// `next_pc == pc + 1` for `CALL_IMM`). The relative offset is carried in `imm`, not `off` — the
/// one place among the jump/call instructions where that is true.
fn call_target(pc: usize, imm: i32) -> i64 {
    pc as i64 + 1 + imm as i64
}

/// `target`, if it is both inside the text and the start of a real instruction (so a target
/// landing on the second slot of an `lddw` is `None` too — neither is a pc this scanner, the
/// emitter, or the interpreter can treat as code).
fn in_text(target: i64, n_slots: usize, by_pc: &BTreeMap<usize, Insn>) -> Option<usize> {
    if target >= 0 && (target as usize) < n_slots && by_pc.contains_key(&(target as usize)) {
        Some(target as usize)
    } else {
        None
    }
}

/// Validates `target` (an edge out of the instruction at `pc`: a jump/call target, or simply the
/// pc right after the current instruction), or — if it is not real code — records
/// [`Warning::JumpOutOfText`] at `pc` and returns the shared synthetic trap pc instead (`n_slots`,
/// one past the text's last real pc, never a real `by_pc` key). `term_at` gets that pc's
/// `Term::Trap(TrapKind::BadJump)` entry the first time it is used; inserting it again on a later
/// call is harmless (same value). The caller must not push the returned pc onto the discovery
/// `stack`, or treat it as real code to decode — compare it against `n_slots` first (every
/// call site here does).
fn resolve_edge(
    pc: usize,
    target: i64,
    n_slots: usize,
    by_pc: &BTreeMap<usize, Insn>,
    term_at: &mut BTreeMap<usize, Term>,
    warnings: &mut Vec<Warning>,
) -> usize {
    match in_text(target, n_slots, by_pc) {
        Some(t) => t,
        None => {
            warnings.push(Warning::JumpOutOfText { pc, target });
            term_at.insert(n_slots, Term::Trap(TrapKind::BadJump));
            n_slots
        }
    }
}

/// A syscall hash classified against `syscalls::SUPPORTED` and [`CPI_NAMES`]: internal names are
/// not recoverable from a hash alone, so CPI is recognised only by checking the hash against the
/// finite set of names the design refuses by name (see [`CPI_NAMES`]'s docs).
enum SyscallKind {
    Supported,
    Cpi(&'static str),
    Unknown,
}

fn classify_syscall(hash: u32) -> SyscallKind {
    if syscalls::SUPPORTED.iter().any(|(h, _)| *h == hash) {
        return SyscallKind::Supported;
    }
    for name in CPI_NAMES {
        if syscalls::murmur3_32(name.as_bytes(), 0) == hash {
            return SyscallKind::Cpi(name);
        }
    }
    SyscallKind::Unknown
}

/// Scans one function: a reachability walk from `entry` that (a) collects every `ja`/conditional
/// jump target inside the function, resolving every edge (never failing — see [`resolve_edge`])
/// and caching the terminator [`Term`] for every pc it visits, then (b) replays the reachable pcs
/// to lay out blocks, splitting at the collected jump targets and after every terminator. Two
/// passes over the same reachable set, not one, because a jump can target a pc *earlier* in
/// program order than the jump itself — the split point has to be known before blocks are built,
/// or an already-built block would need to be retroactively cut in two.
fn scan_function(
    entry: usize,
    by_pc: &BTreeMap<usize, Insn>,
    n_slots: usize,
    known_functions: &mut BTreeSet<usize>,
    call_worklist: &mut VecDeque<usize>,
    warnings: &mut Vec<Warning>,
) -> Function {
    if !by_pc.contains_key(&entry) {
        // Only reachable by directly constructing a `Program` whose `entry_pc` is not fetchable
        // (`Program::from_text` on an empty or truncated buffer — `elf::load` itself always
        // validates `e_entry` against the text). Not a real ELF the interpreter could load either,
        // but there is no source instruction to blame the way `resolve_edge` usually has one, so
        // this is handled directly rather than forced through it.
        warnings.push(Warning::JumpOutOfText { pc: entry, target: entry as i64 });
        let trap = Block { start: entry, end: entry, insns: Vec::new(), term: Term::Trap(TrapKind::BadJump) };
        return Function { entry, blocks: vec![trap] };
    }

    // ---- (a) reachability + jump targets + terminator classification --------------------------
    let mut reachable: HashSet<usize> = HashSet::new();
    let mut jump_targets: BTreeSet<usize> = BTreeSet::new();
    let mut term_at: BTreeMap<usize, Term> = BTreeMap::new();
    let mut stack: Vec<usize> = vec![entry];

    while let Some(start) = stack.pop() {
        let mut pc = start;
        loop {
            if reachable.contains(&pc) {
                break;
            }
            reachable.insert(pc);
            // Every pc pushed onto `stack` or reached via a straight-line `pc = next_pc` below was
            // already validated by whichever `resolve_edge`/bounds check produced it, so this
            // should always hit; the `else` is defense in depth against reaching the shared
            // synthetic trap pc (or any other non-instruction pc) through this walk rather than
            // only as `term_successors`' output in pass (b) — nothing further to discover through
            // it either way.
            let Some(&insn) = by_pc.get(&pc) else { break };

            // Register range and opcode validity: `interp.rs::step`'s own first check, made on
            // every instruction regardless of class — so made here the same way, before dispatch.
            if insn.dst > 10 || insn.src > 10 {
                warnings.push(Warning::RegisterOutOfRange { pc, opc: insn.opc });
                term_at.insert(pc, Term::Trap(TrapKind::BadInsn(insn.opc)));
                break;
            }
            let class = match isa::classify(insn.opc) {
                Some(c) => c,
                None => {
                    warnings.push(Warning::UnknownOpcode { pc, opc: insn.opc });
                    term_at.insert(pc, Term::Trap(TrapKind::BadInsn(insn.opc)));
                    break;
                }
            };
            let next_pc = pc + insn_len(&insn);

            match class {
                Class::Jmp if insn.opc == opc::JA => {
                    let target = resolve_edge(pc, jump_to(pc, insn.off), n_slots, by_pc, &mut term_at, warnings);
                    term_at.insert(pc, Term::Jump(target));
                    if target != n_slots {
                        jump_targets.insert(target);
                        stack.push(target);
                    }
                    break;
                }
                Class::Jmp => {
                    // Any of the 22 conditional jumps. `taken` and `not` are resolved
                    // independently: a bad `taken` target does not make the `not`-taken side bad
                    // too (and vice versa) — only whichever side actually runs would ever reach the
                    // interpreter's own check, so this scanner keeps the same independence.
                    let taken = resolve_edge(pc, jump_to(pc, insn.off), n_slots, by_pc, &mut term_at, warnings);
                    let not = resolve_edge(pc, next_pc as i64, n_slots, by_pc, &mut term_at, warnings);
                    term_at.insert(pc, Term::CondJump { taken, not });
                    if taken != n_slots {
                        jump_targets.insert(taken);
                        stack.push(taken);
                    }
                    if not != n_slots {
                        stack.push(not);
                    }
                    break;
                }
                Class::Call if insn.opc == opc::CALL_IMM => {
                    if insn.src == 1 {
                        // A syscall by hash: `Term::Syscall` either way. A hash this scanner
                        // cannot place as `SUPPORTED` gets a `Warning` (and, from the emitter, a
                        // runtime trap identical to the interpreter's `Halt::UnknownSyscall`) —
                        // see the module docs.
                        let hash = insn.imm as u32;
                        match classify_syscall(hash) {
                            SyscallKind::Supported => {}
                            SyscallKind::Cpi(name) => warnings.push(Warning::Cpi { pc, name }),
                            SyscallKind::Unknown => warnings.push(Warning::UnknownSyscall { pc, hash }),
                        }
                        let next = resolve_edge(pc, next_pc as i64, n_slots, by_pc, &mut term_at, warnings);
                        term_at.insert(pc, Term::Syscall { hash, next });
                        if next == n_slots {
                            break;
                        }
                        pc = next;
                        continue;
                    }
                    // src == 0: an internal call (the register check above already ruled out every
                    // dst/src above 10, and `elf.rs`/`interp.rs` never produce a `call imm` with
                    // any other src, so this is the only remaining case). Unlike `ja`/a conditional
                    // jump, the relative offset lives in `imm`, not `off` — `interp.rs`'s
                    // `target = next_pc + i.imm as i64` for `opc::CALL_IMM`, matching `elf.rs`'s
                    // `rel = target_pc - (site_pc + 1)` written into the immediate.
                    //
                    // A bad *target* is not redirected through `resolve_edge`'s shared trap pc like
                    // every other edge here: `Term::Call::target` names a function for the
                    // emitter's `r0 = f_<target>(...)`, and the shared trap pc is not a function.
                    // The interpreter would push a frame and only then trap trying to fetch the bad
                    // target (`interp.rs`'s `push_frame` before `slot_at`), but nothing observable
                    // happens from that frame push before the trap unwinds everything anyway, so
                    // trapping directly at the call site (no `Term::Call` at all) is the same
                    // observable outcome without needing a fictitious function to call first.
                    let raw_target = call_target(pc, insn.imm);
                    match in_text(raw_target, n_slots, by_pc) {
                        Some(target) => {
                            if known_functions.insert(target) {
                                call_worklist.push_back(target);
                            }
                            let next = resolve_edge(pc, next_pc as i64, n_slots, by_pc, &mut term_at, warnings);
                            term_at.insert(pc, Term::Call { target, next });
                            if next == n_slots {
                                break;
                            }
                            pc = next;
                            continue;
                        }
                        None => {
                            warnings.push(Warning::JumpOutOfText { pc, target: raw_target });
                            term_at.insert(pc, Term::Trap(TrapKind::BadJump));
                            break;
                        }
                    }
                }
                Class::Call => {
                    // CALL_REG (`callx`): v1 takes the target *address* from the register the
                    // immediate names (`interp.rs`), so `imm` is a register number here, not a pc
                    // — checked the same way the generic `dst`/`src` check above is (this is the
                    // one place `interp.rs` validates a register named outside `dst`/`src`).
                    let r = insn.imm as u32 as usize;
                    if r > 10 {
                        warnings.push(Warning::RegisterOutOfRange { pc, opc: insn.opc });
                        term_at.insert(pc, Term::Trap(TrapKind::BadInsn(insn.opc)));
                        break;
                    }
                    // The target is a runtime register *value*, unknown statically; the static
                    // approximation is every known function entry (`Scan::callx_targets`, filled
                    // in by `scan` once every function is found).
                    let next = resolve_edge(pc, next_pc as i64, n_slots, by_pc, &mut term_at, warnings);
                    term_at.insert(pc, Term::CallX { next });
                    if next == n_slots {
                        break;
                    }
                    pc = next;
                    continue;
                }
                Class::Exit => {
                    term_at.insert(pc, Term::Exit);
                    break;
                }
                Class::Ld | Class::St | Class::Alu32 | Class::Alu64 => {
                    // Not a terminator by itself — but if this is the very last instruction in the
                    // function's reachable stream (falls off the end of the text, or into the
                    // second slot of an `lddw` no earlier instruction claimed), the interpreter
                    // would fault fetching `next_pc` on its next step, exactly like a bad jump
                    // target; this instruction becomes its own trap right here rather than being
                    // silently dropped by the discovery loop's defensive `else { break }` above.
                    match in_text(next_pc as i64, n_slots, by_pc) {
                        Some(_) => {
                            pc = next_pc;
                            continue;
                        }
                        None => {
                            warnings.push(Warning::JumpOutOfText { pc, target: next_pc as i64 });
                            term_at.insert(pc, Term::Trap(TrapKind::BadJump));
                            break;
                        }
                    }
                }
            }
        }
    }

    // ---- (b) lay out blocks, splitting at jump_targets and after every terminator -------------
    let mut blocks: Vec<Block> = Vec::new();
    let mut block_starts: HashSet<usize> = HashSet::new();
    let mut worklist: VecDeque<usize> = VecDeque::new();
    worklist.push_back(entry);
    block_starts.insert(entry);

    while let Some(start) = worklist.pop_front() {
        if !by_pc.contains_key(&start) {
            // The shared synthetic trap pc (or, defensively, any other pc `resolve_edge` redirected
            // here instead of a real instruction start): no real code, `term_at[start]` is already
            // its `Term::Trap`.
            blocks.push(Block { start, end: start, insns: Vec::new(), term: term_at[&start] });
            continue;
        }
        let mut insns = Vec::new();
        let mut pc = start;
        loop {
            let insn = by_pc[&pc];
            insns.push(insn);
            if let Some(term) = term_at.get(&pc).copied() {
                // A terminator: the block ends here.
                for succ in term_successors(&term) {
                    if block_starts.insert(succ) {
                        worklist.push_back(succ);
                    }
                }
                blocks.push(Block { start, end: pc, insns, term });
                break;
            }
            let next_pc = pc + insn_len(&insn);
            if jump_targets.contains(&next_pc) {
                if block_starts.insert(next_pc) {
                    worklist.push_back(next_pc);
                }
                blocks.push(Block { start, end: pc, insns, term: Term::Fallthrough(next_pc) });
                break;
            }
            pc = next_pc;
        }
    }
    blocks.sort_by_key(|b| b.start);

    Function { entry, blocks }
}

/// The pcs a [`Term`] hands control to next — where the block-layout worklist enqueues from.
fn term_successors(term: &Term) -> Vec<usize> {
    match *term {
        Term::Fallthrough(next) => vec![next],
        Term::Jump(target) => vec![target],
        Term::CondJump { taken, not } => vec![taken, not],
        Term::Exit => vec![],
        Term::Call { next, .. } => vec![next],
        Term::Syscall { next, .. } => vec![next],
        Term::CallX { next } => vec![next],
        Term::Trap(_) => vec![],
    }
}
