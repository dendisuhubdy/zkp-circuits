//! The scanner: recovers functions, basic blocks and control-flow edges from a loaded sBPF
//! program, and refuses what it cannot statically account for.
//!
//! # Internal calls versus syscalls
//!
//! `sbpf_core::elf::load` normalises every `call imm` site so the encoding alone says what it is
//! (see `elf.rs`'s and `interp.rs`'s module docs): `src == 0` is a slot-relative internal call
//! (`target = pc + 1 + imm`) and `src == 1` is a syscall whose `imm` is the murmur3-32 hash of its
//! name. This scanner reads exactly that convention — it never re-derives it from relocations,
//! since a [`Program`] built by [`Program::from_text`] (as every test here does) never had any.
//!
//! # Refusals versus warnings
//!
//! Parity with the interpreter on every vector is the spec's binding requirement (spec §1), and
//! the interpreter only checks a syscall hash against `syscalls::SUPPORTED` when a `call imm` that
//! names it is actually *executed* — `interp.rs::dispatch`'s `other => Err(Halt::UnknownSyscall)`
//! fires per call, not per program. A real ELF can and does name an unsupported syscall on a path
//! no vector this translator is asked to prove ever takes (the committed SPL Token ELF calls
//! `sol_set_return_data` and `sol_get_sysvar`, neither implemented, from instruction handlers the
//! `Transfer` vector never reaches — `research/tests/sbpf_elf.rs`). Refusing the whole program for
//! that would break parity in the other direction: a program the interpreter runs successfully
//! would become untranslatable. So an unrecognised syscall hash — whether it matches no name this
//! scanner knows at all, or matches a cross-program-invocation name — is not a [`Refusal`]; it is
//! a [`Warning`] plus an ordinary [`Term::Syscall`], translated as code that traps at *runtime*
//! with exactly the `Halt::UnknownSyscall(hash)` the interpreter would raise if that call is ever
//! reached (Task 4's job; this scanner only records which pcs need it).
//!
//! What stays a hard [`Refusal`] is everything the *plan* (Global Constraints) and the *design
//! spec* (§3) call out by name as rejected at translation regardless of reachability — code no
//! toolchain emits and that the interpreter's own load-independent structural checks (`BadInsn`
//! for a bad register or an unassigned opcode, `BadJump` for a static jump/call target outside the
//! text) would trap on the moment it *is* reached, but that a well-formed program never contains
//! in the first place:
//!
//! - [`Refusal::RegisterOutOfRange`]: a `dst`/`src` nibble naming `r11..r15`, which do not exist
//!   (plan Global Constraints: "an instruction naming `dst > 10` or `src > 10` is refused at
//!   translation").
//! - [`Refusal::JumpOutOfText`]: a `ja`/conditional-jump/internal-`call` target outside the text,
//!   or landing on a slot that is not the start of an instruction (the second slot of an `lddw`) —
//!   design spec §3: "a `ja`/`j*` target outside the function's text is rejected at translation".
//! - [`Refusal::UnknownOpcode`]: a byte `isa::classify` does not assign to any v1 class — the same
//!   class of provably-malformed code as a bad register, by the same reasoning (not named
//!   explicitly by either document, but nothing a compiler emits triggers it; see the task-2
//!   report for the case this scanner cannot yet decide either way).

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
/// instruction when `term` is anything but [`Term::Fallthrough`].
#[derive(Clone, Debug)]
pub struct Block {
    pub start: usize,
    pub end: usize,
    pub insns: Vec<Insn>,
    pub term: Term,
}

/// How a block ends, and where control goes next. Every field is a pc in slots.
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
    /// Every `call imm` syscall site the scan could not place as a `syscalls::SUPPORTED` hash —
    /// still translated (as a [`Term::Syscall`] that traps at runtime if actually reached; see the
    /// module docs), but worth a diagnostic, since it means the source ELF's proof coverage does
    /// not extend to whatever instruction handler contains it.
    pub warnings: Vec<Warning>,
}

/// Why the scan refused to go on: code a well-formed program never contains, rejected regardless
/// of reachability (see the module docs for why this differs from [`Warning`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    RegisterOutOfRange { pc: usize, opc: u8 },
    JumpOutOfText { pc: usize, target: i64 },
    UnknownOpcode { pc: usize, opc: u8 },
}

/// A syscall hash the scan translated anyway (as a runtime trap if reached) rather than refusing
/// the whole program over — see the module docs' "Refusals versus warnings".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Warning {
    /// `hash` names neither a `syscalls::SUPPORTED` entry nor a [`CPI_NAMES`] entry — the runtime
    /// has no implementation for it at all (mirrors `Halt::UnknownSyscall` in `interp.rs`).
    UnknownSyscall { pc: usize, hash: u32 },
    /// `hash` matches `murmur3_32` of a cross-program-invocation name. CPI is a multi-program
    /// model this translator does not support (spec §5), but — unlike the plan's original
    /// "refused at translation" — an unreached CPI call must not block a program that never takes
    /// that path, so it is translated the same as any other unrecognised syscall: a runtime trap,
    /// with the name recorded here for diagnostics.
    Cpi { pc: usize, name: &'static str },
}

/// Cross-program-invocation syscall names, checked against a syscall hash to produce
/// [`Warning::Cpi`]'s name (plan Global Constraints, spec §5). Not exhaustive of every
/// `sol_invoke*` Solana defines — these are the two the design names — but a name is not
/// recoverable from a hash alone, so only a hash in this finite list can be named at all; anything
/// else unrecognised is [`Warning::UnknownSyscall`] instead.
const CPI_NAMES: &[&str] = &["sol_invoke_signed_c", "sol_invoke_signed_rust"];

/// Scans `program`'s text into functions and basic blocks, or refuses it.
///
/// Two passes:
///
/// 1. **The whole text, unconditionally.** Every slot is decoded (`isa::decode`; an `lddw`
///    occupies two slots but yields one logical instruction, exactly as the interpreter's
///    instruction counter treats it — `interp.rs`'s "an `lddw` spans two slots but counts once").
///    A `dst`/`src` nibble naming `r11..r15` ([`Refusal::RegisterOutOfRange`]) or a byte
///    `isa::classify` does not assign ([`Refusal::UnknownOpcode`]) refuses right here, regardless
///    of whether the instruction is reachable — the same defense in depth the interpreter's own
///    per-instruction check has, and cheap since the whole text is decoded anyway.
/// 2. **A reachability walk from the entrypoint and every internal call target found along the
///    way** (a worklist of function roots, so a call inside a called function discovers a third
///    function, and so on). Only *this* pass — not pass 1 — validates jump/call targets
///    ([`Refusal::JumpOutOfText`]) and classifies `call imm` sites (internal, a supported syscall,
///    or a syscall recorded as a [`Warning`] and translated as a runtime trap), matching the
///    design's "unreachable text is not translated" (spec §3): a `ja` past the text in dead code
///    is never visited and never refused.
pub fn scan(program: &Program<'_>) -> Result<Scan, Refusal> {
    let text = program.text;
    let n_slots = text.len() / 8;

    // ---- pass 1: decode every slot, refusing bad registers and unassigned opcodes -------------
    let mut by_pc: BTreeMap<usize, Insn> = BTreeMap::new();
    let mut pc = 0usize;
    while pc < n_slots {
        let slot = read_slot(text, pc);
        let insn = isa::decode(slot);
        if insn.dst > 10 || insn.src > 10 {
            return Err(Refusal::RegisterOutOfRange { pc, opc: insn.opc });
        }
        if isa::classify(insn.opc).is_none() {
            return Err(Refusal::UnknownOpcode { pc, opc: insn.opc });
        }
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
        let f =
            scan_function(entry, &by_pc, n_slots, &mut known_functions, &mut worklist, &mut warnings)?;
        functions.push(f);
    }
    // `program.entry_pc`'s function first, whatever order the worklist discovered the rest in —
    // `Scan::entry` and `functions[0].entry` agree (see `Scan::functions`'s doc comment).
    functions.sort_by_key(|f| if f.entry == program.entry_pc { (0, f.entry) } else { (1, f.entry) });

    let callx_targets: Vec<usize> = known_functions.into_iter().collect();

    Ok(Scan { functions, entry: program.entry_pc, callx_targets, warnings })
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

/// `target`, checked against the text and against `by_pc` (so a target landing on the second slot
/// of an `lddw` — not the start of any instruction — is refused exactly as an out-of-range one
/// is: neither is a pc this scanner, the emitter, or the interpreter can treat as code).
fn require_in_text(
    pc: usize,
    target: i64,
    n_slots: usize,
    by_pc: &BTreeMap<usize, Insn>,
) -> Result<usize, Refusal> {
    if target < 0 || target as usize >= n_slots || !by_pc.contains_key(&(target as usize)) {
        return Err(Refusal::JumpOutOfText { pc, target });
    }
    Ok(target as usize)
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
/// jump target inside the function, validating each as it is found, and caches the terminator
/// [`Term`] for every terminator pc it visits, then (b) replays the reachable pcs to lay out
/// blocks, splitting at the collected jump targets and after every terminator. Two passes over
/// the same reachable set, not one, because a jump can target a pc *earlier* in program order than
/// the jump itself — the split point has to be known before blocks are built, or an
/// already-built block would need to be retroactively cut in two.
fn scan_function(
    entry: usize,
    by_pc: &BTreeMap<usize, Insn>,
    n_slots: usize,
    known_functions: &mut BTreeSet<usize>,
    call_worklist: &mut VecDeque<usize>,
    warnings: &mut Vec<Warning>,
) -> Result<Function, Refusal> {
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
            // Pass 1 decoded the whole text, so any pc this walk reaches that is not a key was
            // reached as a target that `require_in_text` should already have refused; a missing
            // entry here means the pc is not the start of an instruction (e.g. one this function's
            // own fallthrough runs into) — the same refusal.
            let insn = *by_pc
                .get(&pc)
                .ok_or(Refusal::JumpOutOfText { pc, target: pc as i64 })?;
            let next_pc = pc + insn_len(&insn);

            match isa::classify(insn.opc).expect("pass 1 refused every unclassified opcode") {
                Class::Jmp if insn.opc == opc::JA => {
                    let target = require_in_text(pc, jump_to(pc, insn.off), n_slots, by_pc)?;
                    jump_targets.insert(target);
                    term_at.insert(pc, Term::Jump(target));
                    stack.push(target);
                    break;
                }
                Class::Jmp => {
                    // Any of the 22 conditional jumps. Both successors are pushed — `not` gets no
                    // `jump_targets` entry of its own (the conditional jump itself already forces
                    // a split right after it, in the block-layout pass below), but it still has to
                    // be *walked*, not just bounds-checked, or a further jump inside the not-taken
                    // arm would never be discovered.
                    let taken = require_in_text(pc, jump_to(pc, insn.off), n_slots, by_pc)?;
                    let not = require_in_text(pc, next_pc as i64, n_slots, by_pc)?;
                    jump_targets.insert(taken);
                    term_at.insert(pc, Term::CondJump { taken, not });
                    stack.push(taken);
                    stack.push(not);
                    break;
                }
                Class::Call if insn.opc == opc::CALL_IMM => {
                    if insn.src == 1 {
                        // A syscall by hash: `Term::Syscall` either way. A hash this scanner
                        // cannot place as `SUPPORTED` gets a `Warning` (and, from the emitter, a
                        // runtime trap identical to the interpreter's `Halt::UnknownSyscall`) —
                        // not a refusal; see the module docs' "Refusals versus warnings".
                        let hash = insn.imm as u32;
                        match classify_syscall(hash) {
                            SyscallKind::Supported => {}
                            SyscallKind::Cpi(name) => warnings.push(Warning::Cpi { pc, name }),
                            SyscallKind::Unknown => {
                                warnings.push(Warning::UnknownSyscall { pc, hash })
                            }
                        }
                        term_at.insert(pc, Term::Syscall { hash, next: next_pc });
                    } else {
                        // src == 0: an internal call (pass 1 already ruled out every dst/src above
                        // 10, and `elf.rs`/`interp.rs` never produce a `call imm` with any other
                        // src, so this is the only remaining case). Unlike `ja`/a conditional jump,
                        // the relative offset lives in `imm`, not `off` — `interp.rs`'s
                        // `target = next_pc + i.imm as i64` for `opc::CALL_IMM`, matching
                        // `elf.rs`'s `rel = target_pc - (site_pc + 1)` written into the immediate.
                        let target = require_in_text(pc, call_target(pc, insn.imm), n_slots, by_pc)?;
                        if known_functions.insert(target) {
                            call_worklist.push_back(target);
                        }
                        term_at.insert(pc, Term::Call { target, next: next_pc });
                    }
                    require_in_text(pc, next_pc as i64, n_slots, by_pc)?;
                    pc = next_pc;
                    continue;
                }
                Class::Call => {
                    // CALL_REG (`callx`): the target is a runtime register value, not a pc; the
                    // static approximation is every known function entry (`Scan::callx_targets`,
                    // filled in by `scan` from `known_functions` once every function is found).
                    term_at.insert(pc, Term::CallX { next: next_pc });
                    require_in_text(pc, next_pc as i64, n_slots, by_pc)?;
                    pc = next_pc;
                    continue;
                }
                Class::Exit => {
                    term_at.insert(pc, Term::Exit);
                    break;
                }
                Class::Ld | Class::St | Class::Alu32 | Class::Alu64 => {
                    pc = next_pc;
                    continue;
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

    Ok(Function { entry, blocks })
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
    }
}

