//! Scanner tests. Every program is hand-assembled with `sbpf_core::isa::encode` and loaded with
//! `Program::from_text` (no relocations — this scanner reads the `call imm` `src` convention
//! `sbpf_core::elf::load` would otherwise have written, so the tests just write it directly).
//!
//! `scan` refuses nothing about a program's content (ruling 2026-09-18; its only failure is the
//! work limit, `try_scan`): nothing this scanner cannot fully verify statically is refused — it becomes a `Warning` plus a `Term` that traps at runtime if actually reached,
//! exactly as `interp.rs` would. See `scan::scan`'s module docs.

use sbpf2rv::scan::{scan, try_scan_with_limit, Term, TrapKind, Warning, MAX_SCAN_STEPS};
use sbpf_core::elf::Program;
use sbpf_core::isa::{opc, Insn};
use sbpf_core::syscalls;

fn insn(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        opc,
        dst,
        src,
        off,
        imm,
    }
}

/// An internal `call imm`'s `imm`: unlike `ja`/a conditional jump, the relative offset from a
/// call site to its target lives in `imm`, not `off` (`target = pc + 1 + imm`).
fn call_offset(pc: usize, target: usize) -> i32 {
    (target as i64 - (pc as i64 + 1)) as i32
}

/// Encodes a straight-line instruction stream into the byte buffer `Program::from_text` wants.
fn text(insns: &[Insn]) -> Vec<u8> {
    let mut out = Vec::with_capacity(insns.len() * 8);
    for i in insns {
        out.extend_from_slice(&sbpf_core::isa::encode(*i).to_le_bytes());
    }
    out
}

fn exit() -> Insn {
    insn(opc::EXIT, 0, 0, 0, 0)
}

// ---- a single `exit` -----------------------------------------------------------------------

#[test]
fn a_single_exit_is_one_function_one_block() {
    let t = text(&[exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(scanned.entry, 0);
    assert_eq!(scanned.functions.len(), 1);
    let f = &scanned.functions[0];
    assert_eq!(f.entry, 0);
    assert_eq!(f.blocks.len(), 1);
    assert_eq!(f.blocks[0].start, 0);
    assert_eq!(f.blocks[0].end, 0);
    assert_eq!(f.blocks[0].insns.len(), 1);
    assert_eq!(f.blocks[0].term, Term::Exit);
    assert_eq!(scanned.callx_targets, vec![0]);
    assert!(scanned.warnings.is_empty());
}

// ---- a call to a second function ------------------------------------------------------------

#[test]
fn a_call_to_a_second_function_makes_two_functions_and_splits_the_caller() {
    // pc0: call target=2 (src=0: internal, imm = target - (pc+1) = 2 - 1 = 1)
    // pc1: exit                          (the call's return point — its own block)
    // pc2: exit                          (the called function)
    let t = text(&[
        insn(opc::CALL_IMM, 0, 0, 0, call_offset(0, 2)),
        exit(),
        exit(),
    ]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(scanned.functions.len(), 2);
    let mut by_entry: Vec<_> = scanned.functions.iter().map(|f| f.entry).collect();
    by_entry.sort();
    assert_eq!(by_entry, vec![0, 2]);

    let caller = scanned.functions.iter().find(|f| f.entry == 0).unwrap();
    // The call is a terminator: it ends block 0, and the return point (pc1) starts a new block.
    assert_eq!(caller.blocks.len(), 2);
    let b0 = caller.blocks.iter().find(|b| b.start == 0).unwrap();
    assert_eq!(b0.end, 0);
    assert_eq!(b0.term, Term::Call { target: 2, next: 1 });
    let b1 = caller.blocks.iter().find(|b| b.start == 1).unwrap();
    assert_eq!(b1.end, 1);
    assert_eq!(b1.term, Term::Exit);

    let callee = scanned.functions.iter().find(|f| f.entry == 2).unwrap();
    assert_eq!(callee.blocks.len(), 1);
    assert_eq!(callee.blocks[0].term, Term::Exit);

    // callx could statically land on either function entry.
    assert_eq!(scanned.callx_targets, vec![0, 2]);
    assert!(scanned.warnings.is_empty());
}

// ---- a jump target forces a block split, and a back edge does not loop the scanner ----------

#[test]
fn a_jump_target_splits_the_block_it_lands_in_the_middle_of() {
    // pc0: mov r0, 0                     (falls into pc1, which is a jump target below)
    // pc1: mov r1, 1                     (the jump target: loop head)
    // pc2: ja pc1                        (back edge; off = target - (pc+1) = 1 - 3 = -2)
    let t = text(&[
        insn(opc::MOV64_IMM, 0, 0, 0, 0),
        insn(opc::MOV64_IMM, 1, 0, 0, 1),
        insn(opc::JA, 0, 0, -2, 0),
    ]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(scanned.functions.len(), 1);
    let f = &scanned.functions[0];
    assert_eq!(f.blocks.len(), 2);

    let b0 = f.blocks.iter().find(|b| b.start == 0).unwrap();
    assert_eq!(b0.end, 0);
    assert_eq!(b0.insns.len(), 1);
    assert_eq!(b0.term, Term::Fallthrough(1));

    let b1 = f.blocks.iter().find(|b| b.start == 1).unwrap();
    assert_eq!(b1.end, 2);
    assert_eq!(b1.insns.len(), 2);
    assert_eq!(b1.term, Term::Jump(1));
    assert!(scanned.warnings.is_empty());
}

// ---- a conditional jump's two successors are both block starts ------------------------------

#[test]
fn a_conditional_jump_splits_into_taken_and_not_taken_blocks() {
    // pc0: jeq r0, 0, +1   (taken -> pc2, not -> pc1)
    // pc1: exit
    // pc2: exit
    let t = text(&[insn(opc::JEQ_IMM, 0, 0, 1, 0), exit(), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    let f = &scanned.functions[0];
    assert_eq!(f.blocks.len(), 3);
    let b0 = f.blocks.iter().find(|b| b.start == 0).unwrap();
    assert_eq!(b0.term, Term::CondJump { taken: 2, not: 1 });
    assert!(f
        .blocks
        .iter()
        .any(|b| b.start == 1 && b.term == Term::Exit));
    assert!(f
        .blocks
        .iter()
        .any(|b| b.start == 2 && b.term == Term::Exit));
    assert!(scanned.warnings.is_empty());
}

// ---- warnings + runtime traps (ruling 2026-09-18: none of this is a load-time check in
// interp.rs/elf.rs, so none of it blocks the whole scan any more than an unreached syscall does)
// ------------------------------------------------------------------------------------------------

#[test]
fn a_ja_past_the_text_is_a_warning_and_traps() {
    // pc0 (only slot): ja +10 -> target = 0 + 1 + 10 = 11, past a 1-slot text.
    let t = text(&[insn(opc::JA, 0, 0, 10, 0)]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(
        scanned.warnings,
        vec![Warning::JumpOutOfText { pc: 0, target: 11 }]
    );
    let f = &scanned.functions[0];
    let b0 = f.blocks.iter().find(|b| b.start == 0).unwrap();
    // `Term::Jump` still names the target — it is the shared synthetic trap pc (`n_slots == 1`
    // here), not folded into an inline `Term::Trap` on pc 0, so the "goto a real block" shape is
    // uniform for every edge kind.
    assert_eq!(b0.term, Term::Jump(1));
    let trap = f.blocks.iter().find(|b| b.start == 1).unwrap();
    assert_eq!(trap.end, 1);
    assert!(trap.insns.is_empty());
    assert_eq!(trap.term, Term::Trap(TrapKind::BadJump));
}

#[test]
fn a_call_past_the_text_is_a_warning_and_traps_at_the_call_site() {
    // pc0: call src=0 imm=10 -> target = 0 + 1 + 10 = 11, past a 1-slot text. A bad call *target*
    // (unlike every other edge) traps right at the call site instead of via the shared synthetic
    // block — there is no function to call, so `Term::Call` is never constructed at all.
    let t = text(&[insn(opc::CALL_IMM, 0, 0, 0, 10)]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(
        scanned.warnings,
        vec![Warning::JumpOutOfText { pc: 0, target: 11 }]
    );
    assert_eq!(
        scanned.functions.len(),
        1,
        "the bad target names no function"
    );
    let f = &scanned.functions[0];
    let b0 = f.blocks.iter().find(|b| b.start == 0).unwrap();
    // Important 3 (review round 1): unlike a `BadInsn` trap, the `call imm` itself is still in
    // `insns` — `interp.rs` pushes the frame (the depth check) *before* fetching the bad target
    // (`push_frame` then `slot_at`), so the emitter must still place the depth check ahead of the
    // trap, exactly as it would for a call to a real target.
    assert_eq!(
        b0.insns,
        vec![insn(opc::CALL_IMM, 0, 0, 0, 10)],
        "the depth check still runs"
    );
    assert_eq!(b0.term, Term::Trap(TrapKind::BadJump));
}

// ---- Important 2 (review round 1): a `Term::Trap(TrapKind::BadInsn(_))` means the trapping
// instruction itself never ran — `interp.rs::step` returns before dispatch — so it must be left
// out of `Block::insns`, unlike a `BadJump` trap (see `falling_off_the_end...` and
// `a_call_past_the_text...` above, and `Block`'s docs).

#[test]
fn mov_r11_is_a_warning_and_traps_without_the_instruction_in_insns() {
    // `dst` is a nibble, so r11 is representable in the encoding even though it does not exist.
    let t = text(&[insn(opc::MOV64_IMM, 11, 0, 0, 0), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(
        scanned.warnings,
        vec![Warning::RegisterOutOfRange {
            pc: 0,
            opc: opc::MOV64_IMM
        }]
    );
    let f = &scanned.functions[0];
    assert_eq!(
        f.blocks.len(),
        1,
        "the bad instruction is the whole function: nothing after it"
    );
    let b0 = &f.blocks[0];
    assert!(
        b0.insns.is_empty(),
        "the bad instruction never ran: {:?}",
        b0.insns
    );
    assert_eq!(
        b0.end, 0,
        "`end` still names the trapping pc even though it is not in `insns`"
    );
    assert_eq!(b0.term, Term::Trap(TrapKind::BadInsn(opc::MOV64_IMM)));
}

#[test]
fn src_r11_is_also_a_warning_and_traps_without_the_instruction_in_insns() {
    let t = text(&[insn(opc::ADD64_REG, 0, 11, 0, 0), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(
        scanned.warnings,
        vec![Warning::RegisterOutOfRange {
            pc: 0,
            opc: opc::ADD64_REG
        }]
    );
    let f = &scanned.functions[0];
    assert!(f.blocks[0].insns.is_empty());
    assert_eq!(
        f.blocks[0].term,
        Term::Trap(TrapKind::BadInsn(opc::ADD64_REG))
    );
}

#[test]
fn a_register_out_of_range_mid_block_excludes_only_the_bad_instruction() {
    // pc0: mov r0, 1        (ran: kept)
    // pc1: mov r11, 2       (never ran: excluded, but `end` still names it)
    let t = text(&[
        insn(opc::MOV64_IMM, 0, 0, 0, 1),
        insn(opc::MOV64_IMM, 11, 0, 0, 2),
        exit(),
    ]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    let f = &scanned.functions[0];
    assert_eq!(f.blocks.len(), 1);
    let b0 = &f.blocks[0];
    assert_eq!(b0.start, 0);
    assert_eq!(b0.end, 1);
    assert_eq!(b0.insns, vec![insn(opc::MOV64_IMM, 0, 0, 0, 1)]);
    assert_eq!(b0.term, Term::Trap(TrapKind::BadInsn(opc::MOV64_IMM)));
}

#[test]
fn an_unassigned_opcode_byte_is_a_warning_and_traps_without_the_instruction_in_insns() {
    // 0x00 is not assigned by SBPF v1 (`isa::classify` returns `None`).
    let t = text(&[insn(0x00, 0, 0, 0, 0)]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(
        scanned.warnings,
        vec![Warning::UnknownOpcode { pc: 0, opc: 0x00 }]
    );
    let f = &scanned.functions[0];
    assert!(f.blocks[0].insns.is_empty());
    assert_eq!(f.blocks[0].term, Term::Trap(TrapKind::BadInsn(0x00)));
}

#[test]
fn falling_off_the_end_of_the_text_is_a_warning_and_traps() {
    // A single `mov`, no `exit` after it: the interpreter would fault fetching pc 1 on its next
    // step, exactly like any other bad jump target.
    let t = text(&[insn(opc::MOV64_IMM, 0, 0, 0, 5)]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(
        scanned.warnings,
        vec![Warning::JumpOutOfText { pc: 0, target: 1 }]
    );
    let f = &scanned.functions[0];
    assert_eq!(f.blocks.len(), 1);
    // Unlike a `BadInsn` trap: the `mov` itself ran to completion (its own halt does not fire —
    // "its own halt wins" only in the sense that nothing overrides it) — only the *next* fetch
    // fails, so it stays in `insns`.
    assert_eq!(f.blocks[0].insns, vec![insn(opc::MOV64_IMM, 0, 0, 0, 5)]);
    assert_eq!(f.blocks[0].term, Term::Trap(TrapKind::BadJump));
}

#[test]
fn callx_with_a_register_number_above_r10_is_a_warning_and_traps_without_the_instruction_in_insns()
{
    // `callx`'s immediate is a register *number* (not a pc), checked the same way — the one place
    // besides `dst`/`src` that `interp.rs` validates a register reference, and (like the generic
    // register check) before any frame push, so this `callx` never ran either.
    let t = text(&[insn(opc::CALL_REG, 0, 0, 0, 11), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(
        scanned.warnings,
        vec![Warning::RegisterOutOfRange {
            pc: 0,
            opc: opc::CALL_REG
        }]
    );
    let f = &scanned.functions[0];
    assert!(f.blocks[0].insns.is_empty());
    assert_eq!(
        f.blocks[0].term,
        Term::Trap(TrapKind::BadInsn(opc::CALL_REG))
    );
}

#[test]
fn a_call_imm_with_src_2_to_10_is_bad_insn_0x85() {
    // Only a hand-built program can hit this — `elf::load` never writes anything but 0 or 1 to
    // `src` on a `call imm` (`interp.rs:412-415`'s catch-all `else { Halt::BadInsn(i.opc) }`).
    let t = text(&[insn(opc::CALL_IMM, 0, 5, 0, 0), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(
        scanned.warnings,
        vec![Warning::BadCallImmSrc { pc: 0, src: 5 }]
    );
    let f = &scanned.functions[0];
    assert!(
        f.blocks[0].insns.is_empty(),
        "never ran: no frame push, no dispatch"
    );
    assert_eq!(
        f.blocks[0].term,
        Term::Trap(TrapKind::BadInsn(opc::CALL_IMM))
    );
}

#[test]
fn a_conditional_jump_with_only_one_bad_target_keeps_the_other_side_real() {
    // pc0: jeq r0, 0, +10   (taken -> 0+1+10 = 11, past a 2-slot text; not -> pc1, real)
    // pc1: exit
    let t = text(&[insn(opc::JEQ_IMM, 0, 0, 10, 0), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(
        scanned.warnings,
        vec![Warning::JumpOutOfText { pc: 0, target: 11 }]
    );
    let f = &scanned.functions[0];
    let b0 = f.blocks.iter().find(|b| b.start == 0).unwrap();
    // `taken` is the shared synthetic trap pc (n_slots == 2 here); `not` is the real pc1.
    assert_eq!(b0.term, Term::CondJump { taken: 2, not: 1 });
    let not_taken = f.blocks.iter().find(|b| b.start == 1).unwrap();
    assert_eq!(
        not_taken.term,
        Term::Exit,
        "the real, in-text side must still be ordinary code"
    );
    let trap = f.blocks.iter().find(|b| b.start == 2).unwrap();
    assert_eq!(trap.term, Term::Trap(TrapKind::BadJump));
}

#[test]
fn an_entry_that_is_not_fetchable_traps_immediately() {
    // `Program::from_text` on an empty buffer: `entry_pc == 0`, but there are zero slots, so pc 0
    // is not fetchable — a degenerate case `elf::load` could never produce (it validates
    // `e_entry`), but the scanner must not panic on it.
    let program = Program::from_text(&[]).unwrap();
    let scanned = scan(&program);

    assert_eq!(
        scanned.warnings,
        vec![Warning::JumpOutOfText { pc: 0, target: 0 }]
    );
    assert_eq!(scanned.functions.len(), 1);
    let f = &scanned.functions[0];
    assert_eq!(f.blocks.len(), 1);
    assert!(f.blocks[0].insns.is_empty());
    assert_eq!(f.blocks[0].term, Term::Trap(TrapKind::BadJump));
}

// ---- CPI and unrecognised syscalls (unaffected by this ruling — already warnings) -----------

#[test]
fn a_call_to_sol_invoke_signed_c_is_a_warning_not_a_refusal() {
    let hash = syscalls::murmur3_32(b"sol_invoke_signed_c", 0);
    let t = text(&[insn(opc::CALL_IMM, 0, 1, 0, hash as i32), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);
    assert_eq!(
        scanned.warnings,
        vec![Warning::Cpi {
            pc: 0,
            name: "sol_invoke_signed_c"
        }]
    );
    let f = &scanned.functions[0];
    let b0 = f.blocks.iter().find(|b| b.start == 0).unwrap();
    assert_eq!(b0.term, Term::Syscall { hash, next: 1 });
}

#[test]
fn a_call_to_sol_invoke_signed_rust_is_a_warning_not_a_refusal() {
    let hash = syscalls::murmur3_32(b"sol_invoke_signed_rust", 0);
    let t = text(&[insn(opc::CALL_IMM, 0, 1, 0, hash as i32), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);
    assert_eq!(
        scanned.warnings,
        vec![Warning::Cpi {
            pc: 0,
            name: "sol_invoke_signed_rust"
        }]
    );
}

/// A CPI call reachable only from inside a called function's body (not the entry function
/// itself), to check the warning is recorded regardless of which function the site is in.
#[test]
fn a_cpi_call_inside_a_called_function_is_a_warning_not_a_refusal() {
    // pc0: call target=2 (the second function)
    // pc1: exit
    // pc2: call sol_invoke_signed_c (src=1)
    // pc3: exit
    let hash = syscalls::murmur3_32(b"sol_invoke_signed_c", 0);
    let t = text(&[
        insn(opc::CALL_IMM, 0, 0, 0, call_offset(0, 2)),
        exit(),
        insn(opc::CALL_IMM, 0, 1, 0, hash as i32),
        exit(),
    ]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);
    assert_eq!(
        scanned.warnings,
        vec![Warning::Cpi {
            pc: 2,
            name: "sol_invoke_signed_c"
        }]
    );
    let callee = scanned.functions.iter().find(|f| f.entry == 2).unwrap();
    let b2 = callee.blocks.iter().find(|b| b.start == 2).unwrap();
    assert_eq!(b2.term, Term::Syscall { hash, next: 3 });
}

#[test]
fn a_supported_syscall_is_not_refused_and_warns_nothing() {
    let hash = syscalls::SOL_LOG;
    let t = text(&[insn(opc::CALL_IMM, 0, 1, 0, hash as i32), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);
    assert!(scanned.warnings.is_empty());
    let f = &scanned.functions[0];
    let b0 = f.blocks.iter().find(|b| b.start == 0).unwrap();
    assert_eq!(b0.term, Term::Syscall { hash, next: 1 });
}

#[test]
fn an_unrecognised_syscall_hash_is_a_warning_not_a_refusal() {
    // Not in SUPPORTED, and its name does not start with "sol_invoke".
    let hash = syscalls::murmur3_32(b"sol_definitely_not_a_real_syscall", 0);
    let t = text(&[insn(opc::CALL_IMM, 0, 1, 0, hash as i32), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);
    assert_eq!(
        scanned.warnings,
        vec![Warning::UnknownSyscall { pc: 0, hash }]
    );
    let f = &scanned.functions[0];
    let b0 = f.blocks.iter().find(|b| b.start == 0).unwrap();
    assert_eq!(b0.term, Term::Syscall { hash, next: 1 });
}

// ---- callx -------------------------------------------------------------------------------

#[test]
fn callx_is_a_terminator_and_does_not_add_call_targets() {
    // pc0: callx r3  (`call reg`: v1 takes the target address from the register the immediate
    //                 names — CALL_REG's imm is the register number, not a pc)
    // pc1: exit
    let t = text(&[insn(opc::CALL_REG, 0, 0, 0, 3), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(scanned.functions.len(), 1);
    let f = &scanned.functions[0];
    assert_eq!(f.blocks.len(), 2);
    let b0 = f.blocks.iter().find(|b| b.start == 0).unwrap();
    assert_eq!(b0.term, Term::CallX { next: 1 });
    assert_eq!(scanned.callx_targets, vec![0]);
    assert!(scanned.warnings.is_empty());
}

// ---- the real SPL Token ELF ------------------------------------------------------------------

/// The committed SPL Token ELF (`research/tests/sbpf_elf.rs`'s own fixture) names two syscalls
/// `syscalls::SUPPORTED` does not implement — `sol_set_return_data` and `sol_get_sysvar` — from
/// instruction handlers the `Transfer` vector never reaches (`GetAccountDataSize`/
/// `AmountToUiAmount`/`UiAmountToAmount`, and the rent read `InitializeAccount` does). It is real,
/// valid, compiler-emitted code: the scan produces no `RegisterOutOfRange`/`UnknownOpcode`/
/// `JumpOutOfText` warning at all, only the two unsupported-syscall ones — and there is nothing
/// left in this crate that could refuse it outright: refusing the whole program over a syscall no
/// vector this translator is asked to prove ever reaches would break parity with the interpreter,
/// which loads and runs this exact file today.
#[test]
fn the_real_spl_token_elf_scans_clean_and_warns_only_the_two_unsupported_syscalls() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../guests-compiled/sbpf/programs/spl_token.so"
    );
    let mut bytes = std::fs::read(path).expect("the committed SPL Token ELF");
    let program = sbpf_core::elf::load(&mut bytes).expect("SPL Token must load");

    let scanned = scan(&program);

    let unsupported = ["sol_set_return_data", "sol_get_sysvar"];
    let unsupported_hashes: Vec<u32> = unsupported
        .iter()
        .map(|n| syscalls::murmur3_32(n.as_bytes(), 0))
        .collect();
    for (name, hash) in unsupported.iter().zip(&unsupported_hashes) {
        assert!(
            scanned
                .warnings
                .iter()
                .any(|w| matches!(w, Warning::UnknownSyscall { hash: h, .. } if *h == *hash)),
            "expected a Warning::UnknownSyscall naming {name} ({hash:#010x}); got {:?}",
            scanned.warnings
        );
    }
    // Nothing else in the committed file is unrecognised or structurally bad — every warning is
    // one of the two known-unsupported syscalls above, never a Cpi, a RegisterOutOfRange, an
    // UnknownOpcode, or a JumpOutOfText.
    for w in &scanned.warnings {
        match *w {
            Warning::UnknownSyscall { hash, .. } => {
                assert!(
                    unsupported_hashes.contains(&hash),
                    "unexpected unknown syscall hash {hash:#010x}"
                );
            }
            other => panic!("SPL Token should not produce this warning: {other:?}"),
        }
    }
}

// ==== Review round 1 (2026-09-18) ==============================================================

// ---- Critical 1: functions reachable only through callx --------------------------------------

#[test]
fn a_function_reachable_only_through_callx_is_discovered_via_its_lddw_constant() {
    // pc0-1: lddw r1, addr(pc3)
    // pc2: callx r1
    // pc3: exit                          -- reachable only via the lddw+callx above; no `call imm`
    //                                        anywhere in the program names it.
    let hidden = 3usize;
    let addr = sbpf_core::memory::REGION_PROGRAM + (hidden as u64) * 8;
    let t = text(&[
        insn(opc::LD_DW_IMM, 1, 0, 0, addr as u32 as i32),
        insn(0, 0, 0, 0, (addr >> 32) as i32),
        insn(opc::CALL_REG, 0, 0, 0, 1),
        exit(),
    ]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert!(
        scanned.callx_targets.contains(&hidden),
        "{:?}",
        scanned.callx_targets
    );
    let f = scanned.functions.iter().find(|f| f.entry == hidden);
    assert!(f.is_some(), "pc {hidden} must be its own function");
    assert_eq!(f.unwrap().blocks[0].term, Term::Exit);
}

#[test]
fn a_function_reachable_only_through_callx_is_discovered_via_a_rodata_word() {
    // The read-only data past the text (`R_BPF_64_RELATIVE`'s own encoding, `elf.rs`) rather than
    // an `lddw` immediate: pc2's address as an 8-byte little-endian word right after the text.
    let hidden = 2usize;
    let addr = sbpf_core::memory::REGION_PROGRAM + (hidden as u64) * 8;
    let t = text(&[
        insn(opc::CALL_REG, 0, 0, 0, 1),
        exit(),
        insn(opc::MOV64_IMM, 0, 0, 0, 9),
        exit(),
    ]);
    let mut rodata_buf = t.clone();
    rodata_buf.extend_from_slice(&addr.to_le_bytes());
    let program = Program {
        text: &t,
        text_va: sbpf_core::memory::REGION_PROGRAM,
        rodata: &rodata_buf,
        rodata_va: sbpf_core::memory::REGION_PROGRAM,
        entry_pc: 0,
        relocs_applied: false,
    };
    let scanned = scan(&program);

    assert!(
        scanned.callx_targets.contains(&hidden),
        "{:?}",
        scanned.callx_targets
    );
    let f = scanned
        .functions
        .iter()
        .find(|f| f.entry == hidden)
        .expect("must be its own function");
    assert_eq!(
        f.blocks.iter().find(|b| b.start == hidden).unwrap().insns,
        vec![insn(opc::MOV64_IMM, 0, 0, 0, 9), exit()]
    );
}

#[test]
fn a_rodata_word_below_the_text_is_a_root_too() {
    // The read-only run need not begin at `.text`: here an 8-byte table word sits *below* the text
    // (rodata_va < text_va), naming pc 2 — reachable only through it. The scan takes every
    // 8-aligned rodata word outside the text, wherever the text sits inside the run.
    let hidden = 2usize;
    let rodata_va = sbpf_core::memory::REGION_PROGRAM;
    let text_va = rodata_va + 8;
    let addr = |pc: u64| text_va + pc * 8;
    let mut t = text(&[
        insn(opc::CALL_REG, 0, 0, 0, 1),
        exit(),
        insn(opc::MOV64_IMM, 0, 0, 0, 9),
        exit(),
    ]);
    // An unreachable slot whose raw bytes are pc 3's address: the text's own words are code, never
    // table entries, so this is not a root.
    t.extend_from_slice(&addr(3).to_le_bytes());
    let mut rodata_buf = addr(hidden as u64).to_le_bytes().to_vec();
    rodata_buf.extend_from_slice(&t);
    let program = Program {
        text: &rodata_buf[8..],
        text_va,
        rodata: &rodata_buf,
        rodata_va,
        entry_pc: 0,
        relocs_applied: false,
    };
    let scanned = scan(&program);
    assert!(
        scanned.callx_targets.contains(&hidden),
        "{:?}",
        scanned.callx_targets
    );
    assert!(scanned.functions.iter().any(|f| f.entry == hidden));
    assert!(
        !scanned.callx_targets.contains(&3),
        "a word inside the text is not a table entry: {:?}",
        scanned.callx_targets
    );
}

/// A pathological ELF can name every instruction as a `callx` root, and each root's function walks
/// the rest of the text: quadratic work a verifier re-running the translation must not be stalled
/// by. The scan counts every instruction it visits and stops with an error past the limit.
#[test]
fn the_scan_stops_with_an_error_past_its_work_limit() {
    // 40 `lddw`s, each naming a different pc of one 200-instruction straight-line body: 40 roots,
    // each walking ~100 instructions on average.
    let body_at = 40 * 2 + 1;
    let mut insns = Vec::new();
    for k in 0..40u64 {
        let addr = sbpf_core::memory::REGION_PROGRAM + (body_at as u64 + 5 * k) * 8;
        insns.push(insn(opc::LD_DW_IMM, 1, 0, 0, addr as u32 as i32));
        insns.push(insn(0, 0, 0, 0, (addr >> 32) as i32));
    }
    insns.push(exit());
    for _ in 0..200 {
        insns.push(insn(opc::ADD64_IMM, 0, 0, 0, 1));
    }
    insns.push(exit());
    let t = text(&insns);
    let program = Program::from_text(&t).unwrap();
    let full = try_scan_with_limit(&program, MAX_SCAN_STEPS).expect("well under the default");
    assert_eq!(full.functions.len(), 41);
    let err = try_scan_with_limit(&program, 1_000)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("1000") && err.contains("instructions"),
        "{err}"
    );
    // `scan` is `try_scan` at the default limit.
    assert_eq!(scan(&program).functions.len(), 41);
}

/// The reviewer's own probe: pc 12244 (`mov r6, r2`, right after `exit` at pc 12243) is a real
/// function in the committed SPL Token ELF, loaded by `lddw r1` at pcs 11595 and 12352, named by
/// no `call imm` anywhere — invisible before this fix.
#[test]
fn the_real_spl_token_elf_finds_the_callx_only_function_at_12244() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../guests-compiled/sbpf/programs/spl_token.so"
    );
    let mut bytes = std::fs::read(path).expect("the committed SPL Token ELF");
    let program = sbpf_core::elf::load(&mut bytes).expect("SPL Token must load");
    let scanned = scan(&program);

    assert!(
        scanned.callx_targets.contains(&12244),
        "{:?}",
        scanned.callx_targets
    );
    let f12244 = scanned
        .functions
        .iter()
        .find(|f| f.entry == 12244)
        .expect("pc 12244 must be its own function");
    assert_eq!(f12244.blocks.iter().map(|b| b.end).max().unwrap(), 12258);
    // pc 12244's own body is short (12244..12258: a couple of internal calls, then exit) — the
    // reviewer's "slots 12244..12340 are in no function" is the *transitive* set: 12244 calls
    // 12259, which is itself only reachable through 12244 (no `call imm` elsewhere in the file
    // names it either) and reaches all the way to pc 12340.
    let f12259 = scanned
        .functions
        .iter()
        .find(|f| f.entry == 12259)
        .expect("pc 12259 must be its own function");
    let max_end = f12259.blocks.iter().map(|b| b.end).max().unwrap();
    assert!(
        max_end >= 12339,
        "function at 12259 only reaches pc {max_end}, expected >= 12339"
    );
}

// ---- Important 3: lddw's second slot ----------------------------------------------------------

#[test]
fn a_jump_onto_an_lddws_second_slot_is_never_a_block_start_by_itself() {
    // pc0-1: lddw r1, <irrelevant>
    // pc2: exit                          -- ordinary fallthrough from pc0 never visits pc1
    let t = text(&[
        insn(opc::LD_DW_IMM, 1, 0, 0, 0x1111_1111u32 as i32),
        insn(0, 0, 0, 0, 0),
        exit(),
    ]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    let f = &scanned.functions[0];
    assert!(
        !f.blocks.iter().any(|b| b.start == 1),
        "pc1 must not be a block start: {:?}",
        f.blocks
    );
}

#[test]
fn a_jump_onto_an_lddws_second_slot_with_a_valid_reinterpretation_is_ordinary_code() {
    // pc1's raw bytes, decoded fresh, are a valid `mov r0, 7` — the interpreter would execute it.
    // pc0-1: lddw r1, <irrelevant>
    // pc2: ja pc1                         -- off = 1 - (2+1) = -2
    let hi = insn(opc::MOV64_IMM, 0, 0, 0, 7);
    let t = text(&[
        insn(opc::LD_DW_IMM, 1, 0, 0, 0x1111_1111u32 as i32),
        hi,
        insn(opc::JA, 0, 0, -2, 0),
    ]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert!(scanned.warnings.is_empty(), "{:?}", scanned.warnings);
    let f = &scanned.functions[0];
    let b1 = f
        .blocks
        .iter()
        .find(|b| b.start == 1)
        .expect("pc1 must be a block, once targeted");
    assert_eq!(b1.insns, vec![hi]);
    // pc1 falls through into pc2 (the `ja`), which is *also* independently reached from pc0's own
    // fallthrough — a convergence forcing a split, not a "swallow pc2 into pc1's block" bug.
    assert_eq!(b1.term, Term::Fallthrough(2));
    let b2 = f.blocks.iter().find(|b| b.start == 2).unwrap();
    assert_eq!(b2.term, Term::Jump(1));
}

#[test]
fn a_jump_onto_an_lddws_second_slot_with_an_invalid_reinterpretation_traps() {
    // pc1's raw bytes: opcode 0, unassigned (the real toolchain's usual byte there) -> BadInsn(0).
    let hi = insn(0x00, 0, 0, 0, 0x2222_2222u32 as i32);
    let t = text(&[
        insn(opc::LD_DW_IMM, 1, 0, 0, 0x1111_1111u32 as i32),
        hi,
        insn(opc::JA, 0, 0, -2, 0),
    ]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(
        scanned.warnings,
        vec![Warning::UnknownOpcode { pc: 1, opc: 0x00 }]
    );
    let f = &scanned.functions[0];
    let b1 = f.blocks.iter().find(|b| b.start == 1).unwrap();
    assert!(b1.insns.is_empty());
    assert_eq!(b1.term, Term::Trap(TrapKind::BadInsn(0x00)));
}

// ---- Important 4: the requested regression tests ----------------------------------------------

#[test]
fn a_jump_inside_a_conditionals_not_taken_arm_is_still_discovered() {
    // pc0: jeq r0, 0, +1   (taken -> pc2; not -> pc1)
    // pc1: ja +0            (inside the not-taken arm; also targets pc2)
    // pc2: exit
    let t = text(&[
        insn(opc::JEQ_IMM, 0, 0, 1, 0),
        insn(opc::JA, 0, 0, 0, 0),
        exit(),
    ]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert!(scanned.warnings.is_empty());
    let f = &scanned.functions[0];
    assert_eq!(f.blocks.len(), 3);
    assert_eq!(
        f.blocks.iter().find(|b| b.start == 0).unwrap().term,
        Term::CondJump { taken: 2, not: 1 }
    );
    assert_eq!(
        f.blocks.iter().find(|b| b.start == 1).unwrap().term,
        Term::Jump(2)
    );
    assert_eq!(
        f.blocks.iter().find(|b| b.start == 2).unwrap().term,
        Term::Exit
    );
}

#[test]
fn an_internal_call_as_the_last_instruction_traps_on_next_but_still_calls() {
    // pc0: call target=0 (calls itself — the target's validity is not what this test is about);
    //      src=0, imm = target - (pc+1) = 0 - 1 = -1. No room for a return point after it.
    let t = text(&[insn(opc::CALL_IMM, 0, 0, 0, -1)]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(
        scanned.warnings,
        vec![Warning::JumpOutOfText { pc: 0, target: 1 }]
    );
    let f = &scanned.functions[0];
    let b0 = f.blocks.iter().find(|b| b.start == 0).unwrap();
    assert_eq!(
        b0.insns,
        vec![insn(opc::CALL_IMM, 0, 0, 0, -1)],
        "the call itself still runs"
    );
    assert_eq!(b0.term, Term::Call { target: 0, next: 1 });
    assert_eq!(
        f.blocks.iter().find(|b| b.start == 1).unwrap().term,
        Term::Trap(TrapKind::BadJump)
    );
}

#[test]
fn a_syscall_as_the_last_instruction_traps_on_next_but_still_calls() {
    let hash = syscalls::SOL_LOG;
    let t = text(&[insn(opc::CALL_IMM, 0, 1, 0, hash as i32)]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(
        scanned.warnings,
        vec![Warning::JumpOutOfText { pc: 0, target: 1 }]
    );
    let f = &scanned.functions[0];
    let b0 = f.blocks.iter().find(|b| b.start == 0).unwrap();
    assert_eq!(b0.insns, vec![insn(opc::CALL_IMM, 0, 1, 0, hash as i32)]);
    assert_eq!(b0.term, Term::Syscall { hash, next: 1 });
    assert_eq!(
        f.blocks.iter().find(|b| b.start == 1).unwrap().term,
        Term::Trap(TrapKind::BadJump)
    );
}

#[test]
fn a_callx_as_the_last_instruction_traps_on_next_but_still_dispatches() {
    let t = text(&[insn(opc::CALL_REG, 0, 0, 0, 3)]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(
        scanned.warnings,
        vec![Warning::JumpOutOfText { pc: 0, target: 1 }]
    );
    let f = &scanned.functions[0];
    let b0 = f.blocks.iter().find(|b| b.start == 0).unwrap();
    assert_eq!(b0.insns, vec![insn(opc::CALL_REG, 0, 0, 0, 3)]);
    assert_eq!(b0.term, Term::CallX { next: 1 });
    assert_eq!(
        f.blocks.iter().find(|b| b.start == 1).unwrap().term,
        Term::Trap(TrapKind::BadJump)
    );
}

#[test]
fn two_function_entries_falling_into_one_shared_body_scan_independently() {
    // pc0: exit                                     -- the program's actual entry (unrelated)
    // pc1: mov r0, 1                                 -- function A's entry
    // pc2: mov r0, 2                                 -- function B's entry — also A's own
    //                                                    fallthrough successor
    // pc3-4: lddw r1, addr(pc1)                       -- makes pc1 a callx-target candidate
    // pc5-6: lddw r1, addr(pc2)                       -- makes pc2 a callx-target candidate
    // pc7: exit                                       -- the shared tail both A and B reach
    let addr1 = sbpf_core::memory::REGION_PROGRAM + 8;
    let addr2 = sbpf_core::memory::REGION_PROGRAM + 16;
    let t = text(&[
        exit(),
        insn(opc::MOV64_IMM, 0, 0, 0, 1),
        insn(opc::MOV64_IMM, 0, 0, 0, 2),
        insn(opc::LD_DW_IMM, 1, 0, 0, addr1 as u32 as i32),
        insn(0, 0, 0, 0, (addr1 >> 32) as i32),
        insn(opc::LD_DW_IMM, 1, 0, 0, addr2 as u32 as i32),
        insn(0, 0, 0, 0, (addr2 >> 32) as i32),
        exit(),
    ]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert!(scanned.callx_targets.contains(&1));
    assert!(scanned.callx_targets.contains(&2));
    let fa = scanned
        .functions
        .iter()
        .find(|f| f.entry == 1)
        .expect("function A");
    let fb = scanned
        .functions
        .iter()
        .find(|f| f.entry == 2)
        .expect("function B");
    assert!(fa.blocks.iter().any(|b| b.start == 1));
    assert!(fb.blocks.iter().any(|b| b.start == 2));
    // Both independently reach the shared tail without panicking or corrupting either scan.
    assert_eq!(fa.blocks.iter().map(|b| b.end).max().unwrap(), 7);
    assert_eq!(fb.blocks.iter().map(|b| b.end).max().unwrap(), 7);
}
