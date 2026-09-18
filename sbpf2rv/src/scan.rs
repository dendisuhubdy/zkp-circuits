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
//! `src` in `2..=10` (`interp.rs`'s catch-all `else { Halt::BadInsn }`) is neither — only a
//! hand-built program can produce it, since `elf::load` never writes anything but `0` or `1` there.
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
//! So none of it is a hard refusal (there is no `Refusal` type in this module — nothing about a
//! program's content makes the scan fail; the one failure, [`try_scan`]'s [`TooMuchWork`], is a
//! bound on the scan's own running time). Instead, every such site becomes an ordinary [`Term`] the
//! block it is in ends with, and a [`Warning`] recording why:
//!
//! - A bad register (`dst`/`src` naming `r11..r15`), an opcode `isa::classify` does not assign, or
//!   a `call imm` with `src` in `2..=10`: [`Warning::RegisterOutOfRange`] /
//!   [`Warning::UnknownOpcode`] / [`Warning::BadCallImmSrc`], and the instruction's block ends in
//!   [`Term::Trap`]`(`[`TrapKind::BadInsn`]`)` — exactly `interp.rs`'s `Halt::BadInsn(opc)`. None
//!   of these three ever ran (`interp.rs::step` returns before dispatch), so the instruction is
//!   *not* in `Block::insns` — see `Block`'s docs.
//! - A `ja`/conditional-jump/internal-`call` target outside the text, or simply falling off the
//!   end of the text after the last instruction: [`Warning::JumpOutOfText`], and
//!   [`Term::Trap`]`(`[`TrapKind::BadJump`]`)` — `interp.rs`'s `Halt::BadJump`. A conditional
//!   jump's two edges are resolved independently (see [`resolve_edge`]): a bad `taken` target does
//!   not stop the `not`-taken side from being real code, and vice versa, since only whichever side
//!   actually runs would ever reach the interpreter's own check. A target landing on the second
//!   slot of an `lddw` is different — see the next paragraph.
//! - An unrecognised syscall hash, or one naming a cross-program-invocation call: unchanged from
//!   the previous ruling — [`Warning::UnknownSyscall`] / [`Warning::Cpi`], and an ordinary
//!   [`Term::Syscall`] (Task 4 emits a runtime trap for it instead of a real call).
//!
//! # `lddw`'s second slot
//!
//! The interpreter has no concept of "instruction boundary" beyond wherever a given fetch happens
//! to land: `slot_at` + `isa::decode` (`interp.rs`) decode *whatever bytes are at a pc*, with no
//! memory of an earlier `lddw` having "claimed" the next slot as its high half. So a jump or call
//! that targets the second slot of some `lddw` elsewhere in the text does not automatically trap —
//! the interpreter decodes that slot fresh, as its own instruction, and either executes it (if
//! valid) or traps `BadInsn` on it (if not; real toolchain output always has opcode `0` there,
//! which is unassigned, so this is the common case in practice, but a hand-built slot need not be).
//! This scanner mirrors that exactly: [`scan`]'s pass 1 decodes every `lddw`'s second slot
//! independently too (alongside the canonical decode that skips over it), so every downstream
//! register-range/opcode-validity/edge check treats it like any other instruction start with no
//! special-casing — it is simply never reached by ordinary sequential fallthrough (only by an
//! explicit jump/call target), so it is never a block start unless something actually targets it.
//!
//! # A bad jump/call *target*
//!
//! Has nowhere well-formed to point a [`Term`]'s `usize` field at (there is no C label for a pc
//! outside the text), so every such edge across one [`Function`] is redirected to one synthetic pc
//! shared by the whole function — one past its text's last real pc — where [`scan`] plants a
//! single `Block` with no instructions and `term: Term::Trap(TrapKind::BadJump)`. See
//! [`resolve_edge`]. The one exception is an internal call whose *target* (not its return point)
//! is bad: see [`Term::Call`]'s docs and the "depth check, then trap" note on [`TrapKind::BadJump`].

use sbpf_core::elf::Program;
use sbpf_core::isa::{self, lddw_imm64, opc, Class, Insn};
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
/// otherwise).
///
/// # What `insns` contains
///
/// One entry per *logical* instruction (an `lddw` contributes its first slot only — the emitter
/// re-reads the upper half straight from `program.text` at `end + 1` when translating it, rather
/// than carrying a 64-bit immediate this type has nowhere to put), in program order — **except**
/// the instruction at `end` itself is left out when `term` is
/// `Term::Trap(TrapKind::BadInsn(_))`: `interp.rs::step` returns before dispatching to any
/// instruction's semantics when the register-range/opcode-validity check at its own top fails, so
/// that instruction never ran and the emitter must not translate it, only the trap. Every other
/// `term` — including `Term::Trap(TrapKind::BadJump)` — means the instruction at `end` *did* run
/// (or, for the shared synthetic trap block a bad jump/call target redirects to, that there is no
/// real instruction at all: `start == end`, `insns` is empty, and this block represents only the
/// failed fetch itself). See [`Term::Trap`] and [`TrapKind`] for the two `BadInsn`/`BadJump` cases
/// in detail, including the internal-call one where a *depth check* runs before the trap.
///
/// A `le`/`be` instruction is included like any other Ld/St/Alu instruction, since its opcode and
/// registers are always valid on their own; the emitter must still place a *runtime* check on the
/// width immediate (`interp.rs`: only 16/32/64 are valid, anything else is `Halt::BadInsn` in
/// `interp.rs::step`'s `LE`/`BE` arms specifically, checked separately from the opcode/register gate
/// every instruction goes through) — this scanner does not check it, since it is a per-*value* — not
/// per-instruction-shape — question no static scan resolves any more precisely than emitting the
/// same runtime check the interpreter has.
///
/// The shared synthetic trap block (see the module docs) has empty `insns` but is not "free": it
/// represents one more instruction dispatch attempt (the failed fetch) for the instruction-limit
/// counter the spec's per-block accounting decrements at the head of each basic block — the
/// emitter must count it, the same as any block with one real instruction in it would be.
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
    /// (a forward or backward jump target landing mid-stream, or two distinct straight-line paths
    /// converging on the same pc without either being a jump target itself).
    Fallthrough(usize),
    /// `ja`.
    Jump(usize),
    /// Any of the 22 conditional jumps.
    CondJump { taken: usize, not: usize },
    /// `exit`.
    Exit,
    /// `call imm`, `src == 0`: an internal call. Execution resumes at `next` on return. Always a
    /// *valid* target — a `call imm` whose target is not real code traps directly
    /// (`Term::Trap(TrapKind::BadJump)` at the call's own pc, not this variant with some
    /// placeholder target) rather than naming a non-function; see [`TrapKind::BadJump`]'s docs for
    /// why that is still faithful to the interpreter's own (frame-push-then-fetch) order.
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
    /// The interpreter would halt executing this pc — no successor. Paired with a [`Warning`] at
    /// the same pc explaining why, except at the one synthetic shared block a bad jump/call
    /// *target* redirects to (see the module docs), which carries no `Warning` of its own — the
    /// warning lives at whichever real instruction's edge was redirected here. See [`TrapKind`]
    /// for exactly which `Halt` this is and whether the instruction at `Block::end` ran first.
    Trap(TrapKind),
}

/// The exact `interp.rs::Halt` a [`Term::Trap`] stands in for, so Task 4 can emit the identical
/// runtime trap without cross-referencing [`Scan::warnings`]. See `Block`'s docs for whether the
/// instruction at the block's `end` is itself included in `insns` — it differs between the two.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrapKind {
    /// `Halt::BadInsn(opc)`: a `dst`/`src` nibble above `r10` (including `callx`'s register-number
    /// immediate), a byte `isa::classify` does not assign to any v1 class, or a `call imm` with
    /// `src` in `2..=10`. `interp.rs::step` returns this *before* dispatching to the instruction's
    /// semantics in every one of these cases, so the instruction never ran: it is not in
    /// `Block::insns`.
    BadInsn(u8),
    /// `Halt::BadJump`: a static jump/call target outside the text, or simply running off the end
    /// of the text. Unlike `BadInsn`, whatever instruction is at `Block::end` *did* run before
    /// this fires — for an ordinary instruction, its own semantics completed and only the next
    /// *fetch* failed; for an internal call whose target is bad specifically (`Term::Trap` sits
    /// directly on the `call imm` site, not a `Term::Call`), `interp.rs`'s own order is "the frame
    /// is pushed first and the target checked after" (`push_frame` before `slot_at`) — so the
    /// depth check (and, if it passes, the frame push) still has to run before this trap, exactly
    /// as it would for a call to a real target; only the fetch of the bad target itself fails.
    BadJump,
}

/// The whole scan: every function reachable from the entrypoint (transitively, through internal
/// calls) or from a `callx`-plausible constant (a post-relocation `lddw` immediate, or an
/// 8-byte-aligned word of the read-only data past the text, that points 8-aligned at a real
/// instruction start — see [`lddw_and_rodata_function_roots`]), and the static approximation of
/// every `callx`'s possible target.
#[derive(Clone, Debug)]
pub struct Scan {
    /// `functions[0]` is always the entrypoint's function (`functions[0].entry == entry`); every
    /// other function follows, sorted ascending by its entry pc. Discovery order (which call site,
    /// or which `lddw`/read-only-data word, found a function first) is not preserved.
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
    /// A `call imm` with `src` in `2..=10` — `interp.rs`'s catch-all `else { Halt::BadInsn }` for
    /// `CALL_IMM` (register range already rules out `11..=15` before this is even reached). Only a
    /// hand-built program can produce it; `elf::load` never writes anything but `0` or `1` there.
    BadCallImmSrc { pc: usize, src: u8 },
}

/// Cross-program-invocation syscall names, checked against a syscall hash to produce
/// [`Warning::Cpi`]'s name (plan Global Constraints, spec §5). Not exhaustive of every
/// `sol_invoke*` Solana defines — these are the two the design names — but a name is not
/// recoverable from a hash alone, so only a hash in this finite list can be named at all; anything
/// else unrecognised is [`Warning::UnknownSyscall`] instead.
const CPI_NAMES: &[&str] = &["sol_invoke_signed_c", "sol_invoke_signed_rust"];

/// Scans `program`'s text into functions and basic blocks. Nothing about the program's content is
/// refused — see the module docs' "Warnings, not refusals" — but the scan's work is bounded: this is
/// [`try_scan`], panicking past [`MAX_SCAN_STEPS`] (the CLI calls [`try_scan`] and reports it).
///
/// Three passes:
///
/// 1. **The whole text, unconditionally.** Every slot is decoded (`isa::decode`; an `lddw`
///    occupies two slots but yields one logical instruction, exactly as the interpreter's
///    instruction counter treats it — `interp.rs`'s "an `lddw` spans two slots but counts once").
///    Nothing is validated here — a bad register or an unassigned opcode is only checked once a pc
///    is actually visited in pass 3, matching "unreachable text is not translated" (spec §3) for
///    these too, not just for syscalls. Every `lddw`'s second slot is *also* decoded independently
///    and inserted — see the module docs' "`lddw`'s second slot".
/// 2. **Every `callx`-plausible constant** (see [`lddw_and_rodata_function_roots`]) becomes an
///    extra function root alongside the entrypoint, before any reachability walk runs — Critical
///    finding from the committed SPL Token ELF: a function reached *only* through `callx` (never
///    through a `call imm`) is invisible to a scan that only follows `call` targets.
/// 3. **A reachability walk from every root** (a worklist, so a call inside a called function
///    discovers a further function, and so on). Every check — register range, opcode validity,
///    jump/call targets, syscall hashes — happens exactly once per reachable pc, here.
pub fn scan(program: &Program<'_>) -> Scan {
    try_scan(program).unwrap_or_else(|e| panic!("{e}"))
}

/// How many instructions the scan may visit, summed over every function it walks, before it gives
/// up ([`try_scan`]). The committed SPL Token ELF needs about 13 000; this leaves room for any real
/// program while bounding a pathological one — one that names every instruction as a `callx` root,
/// so that each root's function walks the rest of the text — to seconds, not the quadratic hours a
/// verifier re-running the translation could otherwise be stalled for.
pub const MAX_SCAN_STEPS: usize = 4_000_000;

/// The scan gave up: it visited more than its limit of instructions (see [`MAX_SCAN_STEPS`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TooMuchWork {
    pub limit: usize,
    pub functions: usize,
    pub roots: usize,
}

impl std::fmt::Display for TooMuchWork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the scan visited more than {} instructions ({} functions walked, from {} roots): this ELF's code is reachable from too many function entries to translate (the interpreter still runs it)",
            self.limit, self.functions, self.roots
        )
    }
}

impl std::error::Error for TooMuchWork {}

/// [`scan`], refusing (with [`TooMuchWork`]) a program whose functions together take more than
/// [`MAX_SCAN_STEPS`] instruction visits. The only failure: nothing about a program's *content* is
/// refused (the module docs' "Warnings, not refusals").
pub fn try_scan(program: &Program<'_>) -> Result<Scan, TooMuchWork> {
    try_scan_with_limit(program, MAX_SCAN_STEPS)
}

/// [`try_scan`] with the limit as a parameter (for tests).
pub fn try_scan_with_limit(program: &Program<'_>, limit: usize) -> Result<Scan, TooMuchWork> {
    let text = program.text;
    let n_slots = text.len() / 8;

    // ---- pass 1: decode every slot, and every `lddw`'s second slot independently --------------
    let mut by_pc: BTreeMap<usize, Insn> = BTreeMap::new();
    let mut pc = 0usize;
    while pc < n_slots {
        let insn = isa::decode(read_slot(text, pc));
        by_pc.insert(pc, insn);
        if insn.opc == opc::LD_DW_IMM && pc + 1 < n_slots {
            // See the module docs: the interpreter has no notion of "this slot belongs to the
            // `lddw` at `pc`" — a jump or call landing here decodes it completely fresh, exactly
            // as this does. Registered unconditionally (even if invalid): the ordinary walk below
            // already produces `Term::Trap(TrapKind::BadInsn(hi.opc))` for an invalid one, with no
            // special-casing needed anywhere else, the moment something actually targets it.
            by_pc.insert(pc + 1, isa::decode(read_slot(text, pc + 1)));
        }
        pc += insn_len(&insn);
    }

    // ---- pass 2: every callx-plausible constant becomes an extra root -------------------------
    let mut known_functions: BTreeSet<usize> = BTreeSet::new();
    known_functions.insert(program.entry_pc);
    let mut worklist: VecDeque<usize> = VecDeque::new();
    worklist.push_back(program.entry_pc);
    for root in lddw_and_rodata_function_roots(program, &by_pc, n_slots) {
        if known_functions.insert(root) {
            worklist.push_back(root);
        }
    }

    // ---- pass 3: reachability walk, function by function ---------------------------------------
    // One function's walk is bounded by the text; the sum over functions is what a pathological
    // program can blow up, so it is checked after each.
    let mut functions: Vec<Function> = Vec::new();
    let mut warnings: Vec<Warning> = Vec::new();
    let mut steps = 0usize;
    while let Some(entry) = worklist.pop_front() {
        let f = scan_function(
            entry,
            &by_pc,
            n_slots,
            &mut known_functions,
            &mut worklist,
            &mut warnings,
        );
        steps += f.blocks.iter().map(|b| b.insns.len() + 1).sum::<usize>();
        functions.push(f);
        if steps > limit {
            return Err(TooMuchWork {
                limit,
                functions: functions.len(),
                roots: known_functions.len(),
            });
        }
    }
    // `program.entry_pc`'s function first, whatever order the worklist discovered the rest in —
    // `Scan::entry` and `functions[0].entry` agree (see `Scan::functions`'s doc comment).
    functions.sort_by_key(|f| {
        if f.entry == program.entry_pc {
            (0, f.entry)
        } else {
            (1, f.entry)
        }
    });

    let callx_targets: Vec<usize> = known_functions.into_iter().collect();

    Ok(Scan {
        functions,
        entry: program.entry_pc,
        callx_targets,
        warnings,
    })
}

/// Every pc `interp.rs`'s `callx` (`CALL_REG`) could statically land on beyond what a `call imm`
/// scan finds: `interp.rs`'s own arithmetic is `addr.wrapping_sub(text_va) / 8`, taking `addr`
/// from whichever register the program loaded it into — almost always via `lddw`, from a constant
/// baked into the ELF at compile time (a function pointer) or read out of a jump/dispatch table in
/// the read-only data. This scans both sources for candidate addresses and keeps only the ones
/// that plausibly *are* such a pointer:
///
/// - **Every `lddw`'s full 64-bit immediate**, anywhere in the text (`isa::lddw_imm64` over the
///   low slot pass 1 decoded and a fresh decode of its high slot) — regardless of whether that
///   `lddw` is itself reachable yet; a function pointer can be constructed by code no call target
///   has been discovered to reach, which is exactly the committed SPL Token ELF's pc 12244 case
///   (loaded by `lddw`s at pc 11595 and 12352, never named by any `call imm`).
/// - **Every 8-byte-aligned word of the read-only data outside the text** — the
///   `.rodata`/`.data.rel.ro`/`.eh_frame` bytes `.text` does not cover, wherever the text sits
///   inside the run: at `text_va - rodata_va` (zero for every v1 file `elf.rs` loads today, where
///   the run begins at `.text`, but not assumed), with words on either side of it scanned. Aligned by
///   virtual address. A `R_BPF_64_RELATIVE` relocation writes an address there as eight
///   little-endian bytes (`elf.rs`), which is how a `callx` jump table is laid out.
///
/// A candidate is kept only if, converted to a slot with `interp.rs`'s own division, it lands
/// exactly 8-aligned (no truncated remainder) on a pc [`Block`]-worth of real code starts at
/// (`by_pc.contains_key`) — otherwise it is just a value that happens to decode, not a pointer.
fn lddw_and_rodata_function_roots(
    program: &Program<'_>,
    by_pc: &BTreeMap<usize, Insn>,
    n_slots: usize,
) -> BTreeSet<usize> {
    let mut roots = BTreeSet::new();
    let text = program.text;

    for (&pc, insn) in by_pc.iter() {
        if insn.opc != opc::LD_DW_IMM || pc + 1 >= n_slots {
            continue;
        }
        let hi = isa::decode(read_slot(text, pc + 1));
        let value = lddw_imm64(*insn, hi);
        if let Some(target) = text_slot(value, program.text_va, n_slots, by_pc) {
            roots.insert(target);
        }
    }

    // The text's byte range inside the run, if it lies there at all: its words are code.
    let text_at = program
        .text_va
        .checked_sub(program.rodata_va)
        .and_then(|o| usize::try_from(o).ok());
    let in_text =
        |off: usize| text_at.is_some_and(|at| off < at.saturating_add(text.len()) && off + 8 > at);
    let rodata = program.rodata;
    let mut off = (program.rodata_va.wrapping_neg() % 8) as usize;
    while off + 8 <= rodata.len() {
        if !in_text(off) {
            let value = u64::from_le_bytes(rodata[off..off + 8].try_into().unwrap());
            if let Some(target) = text_slot(value, program.text_va, n_slots, by_pc) {
                roots.insert(target);
            }
        }
        off += 8;
    }

    roots
}

/// `value` (a virtual address), converted to a slot exactly as `interp.rs`'s `callx` does
/// (`addr.wrapping_sub(text_va) / 8`), kept only if it lands 8-aligned on a real instruction start.
fn text_slot(
    value: u64,
    text_va: u64,
    n_slots: usize,
    by_pc: &BTreeMap<usize, Insn>,
) -> Option<usize> {
    let diff = value.wrapping_sub(text_va);
    if !diff.is_multiple_of(8) {
        return None;
    }
    let target = diff / 8;
    if target >= n_slots as u64 {
        return None;
    }
    let target = target as usize;
    by_pc.contains_key(&target).then_some(target)
}

/// One slot's instruction span: two for `lddw`, one for everything else.
fn insn_len(i: &Insn) -> usize {
    if i.opc == opc::LD_DW_IMM {
        2
    } else {
        1
    }
}

/// Slot `pc`'s eight bytes, little-endian — bounds already guaranteed by every caller.
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

/// `target`, if it is both inside the text and the start of a real instruction (an `lddw`'s second
/// slot counts too — see the module docs — since pass 1 registers it in `by_pc` independently).
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

/// Scans one function: a reachability walk from `entry` that (a) collects every pc reachable by
/// straight-line fallthrough or a resolved edge, resolving every edge (never failing — see
/// [`resolve_edge`]) and caching the terminator [`Term`] for every pc it visits, then (b) replays
/// the reachable pcs to lay out blocks, splitting at the collected split points and after every
/// terminator. Two passes over the same reachable set, not one, because a jump can target a pc
/// *earlier* in program order than the jump itself — the split point has to be known before blocks
/// are built, or an already-built block would need to be retroactively cut in two.
///
/// A pc becomes a split point (`jump_targets`) two ways: it is an explicit `ja`/conditional-jump
/// target (found the instant that jump is decoded), or — checked at the top of (a)'s inner loop —
/// it is reached a *second* time by a distinct straight-line run that did not know about the first
/// (two calls' return points, an `lddw`'s reinterpreted second slot, or any other convergence
/// `jump_targets` did not already predict). Either way it must become its own block, or whichever
/// run reaches it first would silently swallow it into a block some other run also has a claim on.
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
        warnings.push(Warning::JumpOutOfText {
            pc: entry,
            target: entry as i64,
        });
        let trap = Block {
            start: entry,
            end: entry,
            insns: Vec::new(),
            term: Term::Trap(TrapKind::BadJump),
        };
        return Function {
            entry,
            blocks: vec![trap],
        };
    }

    // ---- (a) reachability + split points + terminator classification --------------------------
    let mut reachable: HashSet<usize> = HashSet::new();
    let mut jump_targets: BTreeSet<usize> = BTreeSet::new();
    let mut term_at: BTreeMap<usize, Term> = BTreeMap::new();
    let mut stack: Vec<usize> = vec![entry];

    while let Some(start) = stack.pop() {
        let mut pc = start;
        loop {
            if reachable.contains(&pc) {
                // A distinct straight-line run already reached this pc — via an explicit jump
                // target (already in `jump_targets`, so this is a no-op) or via its own ordinary
                // fallthrough (not yet — see this function's docs). Either way it now has more
                // than one distinct entry into it and must become its own block.
                jump_targets.insert(pc);
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
            // Neither ever runs the instruction (see `Block`'s docs on `insns`).
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
                    let target = resolve_edge(
                        pc,
                        jump_to(pc, insn.off),
                        n_slots,
                        by_pc,
                        &mut term_at,
                        warnings,
                    );
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
                    let taken = resolve_edge(
                        pc,
                        jump_to(pc, insn.off),
                        n_slots,
                        by_pc,
                        &mut term_at,
                        warnings,
                    );
                    let not =
                        resolve_edge(pc, next_pc as i64, n_slots, by_pc, &mut term_at, warnings);
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
                            SyscallKind::Unknown => {
                                warnings.push(Warning::UnknownSyscall { pc, hash })
                            }
                        }
                        let next = resolve_edge(
                            pc,
                            next_pc as i64,
                            n_slots,
                            by_pc,
                            &mut term_at,
                            warnings,
                        );
                        term_at.insert(pc, Term::Syscall { hash, next });
                        if next == n_slots {
                            break;
                        }
                        pc = next;
                        continue;
                    } else if insn.src != 0 {
                        // `src` in `2..=10` (register range above already ruled out `11..=15`):
                        // `interp.rs`'s catch-all `else { Halt::BadInsn(i.opc) } — nothing `elf.rs`
                        // or a hand-built program's `src == 0`/`1` convention produces, but a
                        // hand-built one *can* hit it directly (module docs).
                        warnings.push(Warning::BadCallImmSrc { pc, src: insn.src });
                        term_at.insert(pc, Term::Trap(TrapKind::BadInsn(insn.opc)));
                        break;
                    }
                    // src == 0: an internal call. Unlike `ja`/a conditional jump, the relative
                    // offset lives in `imm`, not `off` — `interp.rs`'s
                    // `target = next_pc + i.imm as i64` for `opc::CALL_IMM`, matching `elf.rs`'s
                    // `rel = target_pc - (site_pc + 1)` written into the immediate.
                    //
                    // A bad *target* is not redirected through `resolve_edge`'s shared trap pc like
                    // every other edge here: `Term::Call::target` names a function for the
                    // emitter's `r0 = f_<target>(...)`, and the shared trap pc is not a function.
                    // See `TrapKind::BadJump`'s docs for why trapping directly at the call site
                    // (still including it in `insns` — the depth check and frame push still run)
                    // is the same observable outcome as the interpreter's own push-then-fetch order.
                    let raw_target = call_target(pc, insn.imm);
                    match in_text(raw_target, n_slots, by_pc) {
                        Some(target) => {
                            if known_functions.insert(target) {
                                call_worklist.push_back(target);
                            }
                            let next = resolve_edge(
                                pc,
                                next_pc as i64,
                                n_slots,
                                by_pc,
                                &mut term_at,
                                warnings,
                            );
                            term_at.insert(pc, Term::Call { target, next });
                            if next == n_slots {
                                break;
                            }
                            pc = next;
                            continue;
                        }
                        None => {
                            warnings.push(Warning::JumpOutOfText {
                                pc,
                                target: raw_target,
                            });
                            term_at.insert(pc, Term::Trap(TrapKind::BadJump));
                            break;
                        }
                    }
                }
                Class::Call => {
                    // CALL_REG (`callx`): v1 takes the target *address* from the register the
                    // immediate names (`interp.rs`), so `imm` is a register number here, not a pc
                    // — checked the same way the generic `dst`/`src` check above is (this is the
                    // one place `interp.rs` validates a register named outside `dst`/`src`), and
                    // before any frame push, so (like the generic register check) this instruction
                    // never ran either.
                    let r = insn.imm as u32 as usize;
                    if r > 10 {
                        warnings.push(Warning::RegisterOutOfRange { pc, opc: insn.opc });
                        term_at.insert(pc, Term::Trap(TrapKind::BadInsn(insn.opc)));
                        break;
                    }
                    // The target is a runtime register *value*, unknown statically; the static
                    // approximation is every known function entry (`Scan::callx_targets`, filled
                    // in by `scan` once every function is found — including ones found only
                    // through `lddw`/read-only-data constants, not just `call imm` sites).
                    let next =
                        resolve_edge(pc, next_pc as i64, n_slots, by_pc, &mut term_at, warnings);
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
                            warnings.push(Warning::JumpOutOfText {
                                pc,
                                target: next_pc as i64,
                            });
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
            blocks.push(Block {
                start,
                end: start,
                insns: Vec::new(),
                term: term_at[&start],
            });
            continue;
        }
        let mut insns = Vec::new();
        let mut pc = start;
        loop {
            let insn = by_pc[&pc];
            if let Some(term) = term_at.get(&pc).copied() {
                // A terminator: the block ends here. Whether `insn` itself ran before `term` took
                // effect is `Block`'s docs' business; only `Trap(BadInsn(_))` means it did not.
                if !matches!(term, Term::Trap(TrapKind::BadInsn(_))) {
                    insns.push(insn);
                }
                for succ in term_successors(&term) {
                    if block_starts.insert(succ) {
                        worklist.push_back(succ);
                    }
                }
                blocks.push(Block {
                    start,
                    end: pc,
                    insns,
                    term,
                });
                break;
            }
            insns.push(insn);
            let next_pc = pc + insn_len(&insn);
            if jump_targets.contains(&next_pc) {
                if block_starts.insert(next_pc) {
                    worklist.push_back(next_pc);
                }
                blocks.push(Block {
                    start,
                    end: pc,
                    insns,
                    term: Term::Fallthrough(next_pc),
                });
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
