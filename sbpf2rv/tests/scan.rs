//! Scanner tests. Every program is hand-assembled with `sbpf_core::isa::encode` and loaded with
//! `Program::from_text` (no relocations — this scanner reads the `call imm` `src` convention
//! `sbpf_core::elf::load` would otherwise have written, so the tests just write it directly).
//!
//! `scan` is infallible (ruling 2026-09-18): nothing this scanner cannot fully verify statically
//! is refused — it becomes a `Warning` plus a `Term` that traps at runtime if actually reached,
//! exactly as `interp.rs` would. See `scan::scan`'s module docs.

use sbpf_core::elf::Program;
use sbpf_core::isa::{opc, Insn};
use sbpf_core::syscalls;
use sbpf2rv::scan::{scan, Term, TrapKind, Warning};

fn insn(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn { opc, dst, src, off, imm }
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
    let t = text(&[insn(opc::CALL_IMM, 0, 0, 0, call_offset(0, 2)), exit(), exit()]);
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
    assert!(f.blocks.iter().any(|b| b.start == 1 && b.term == Term::Exit));
    assert!(f.blocks.iter().any(|b| b.start == 2 && b.term == Term::Exit));
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

    assert_eq!(scanned.warnings, vec![Warning::JumpOutOfText { pc: 0, target: 11 }]);
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

    assert_eq!(scanned.warnings, vec![Warning::JumpOutOfText { pc: 0, target: 11 }]);
    assert_eq!(scanned.functions.len(), 1, "the bad target names no function");
    let f = &scanned.functions[0];
    let b0 = f.blocks.iter().find(|b| b.start == 0).unwrap();
    assert_eq!(b0.term, Term::Trap(TrapKind::BadJump));
}

#[test]
fn mov_r11_is_a_warning_and_traps() {
    // `dst` is a nibble, so r11 is representable in the encoding even though it does not exist.
    let t = text(&[insn(opc::MOV64_IMM, 11, 0, 0, 0), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(scanned.warnings, vec![Warning::RegisterOutOfRange { pc: 0, opc: opc::MOV64_IMM }]);
    let f = &scanned.functions[0];
    assert_eq!(f.blocks.len(), 1, "the bad instruction is the whole function: nothing after it");
    let b0 = &f.blocks[0];
    assert_eq!(b0.insns, vec![insn(opc::MOV64_IMM, 11, 0, 0, 0)]);
    assert_eq!(b0.term, Term::Trap(TrapKind::BadInsn(opc::MOV64_IMM)));
}

#[test]
fn src_r11_is_also_a_warning_and_traps() {
    let t = text(&[insn(opc::ADD64_REG, 0, 11, 0, 0), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(scanned.warnings, vec![Warning::RegisterOutOfRange { pc: 0, opc: opc::ADD64_REG }]);
    let f = &scanned.functions[0];
    assert_eq!(f.blocks[0].term, Term::Trap(TrapKind::BadInsn(opc::ADD64_REG)));
}

#[test]
fn an_unassigned_opcode_byte_is_a_warning_and_traps() {
    // 0x00 is not assigned by SBPF v1 (`isa::classify` returns `None`).
    let t = text(&[insn(0x00, 0, 0, 0, 0)]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(scanned.warnings, vec![Warning::UnknownOpcode { pc: 0, opc: 0x00 }]);
    let f = &scanned.functions[0];
    assert_eq!(f.blocks[0].term, Term::Trap(TrapKind::BadInsn(0x00)));
}

#[test]
fn falling_off_the_end_of_the_text_is_a_warning_and_traps() {
    // A single `mov`, no `exit` after it: the interpreter would fault fetching pc 1 on its next
    // step, exactly like any other bad jump target.
    let t = text(&[insn(opc::MOV64_IMM, 0, 0, 0, 5)]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(scanned.warnings, vec![Warning::JumpOutOfText { pc: 0, target: 1 }]);
    let f = &scanned.functions[0];
    assert_eq!(f.blocks.len(), 1);
    assert_eq!(f.blocks[0].term, Term::Trap(TrapKind::BadJump));
}

#[test]
fn callx_with_a_register_number_above_r10_is_a_warning_and_traps() {
    // `callx`'s immediate is a register *number* (not a pc), checked the same way — the one place
    // besides `dst`/`src` that `interp.rs` validates a register reference.
    let t = text(&[insn(opc::CALL_REG, 0, 0, 0, 11), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(scanned.warnings, vec![Warning::RegisterOutOfRange { pc: 0, opc: opc::CALL_REG }]);
    let f = &scanned.functions[0];
    assert_eq!(f.blocks[0].term, Term::Trap(TrapKind::BadInsn(opc::CALL_REG)));
}

#[test]
fn a_conditional_jump_with_only_one_bad_target_keeps_the_other_side_real() {
    // pc0: jeq r0, 0, +10   (taken -> 0+1+10 = 11, past a 2-slot text; not -> pc1, real)
    // pc1: exit
    let t = text(&[insn(opc::JEQ_IMM, 0, 0, 10, 0), exit()]);
    let program = Program::from_text(&t).unwrap();
    let scanned = scan(&program);

    assert_eq!(scanned.warnings, vec![Warning::JumpOutOfText { pc: 0, target: 11 }]);
    let f = &scanned.functions[0];
    let b0 = f.blocks.iter().find(|b| b.start == 0).unwrap();
    // `taken` is the shared synthetic trap pc (n_slots == 2 here); `not` is the real pc1.
    assert_eq!(b0.term, Term::CondJump { taken: 2, not: 1 });
    let not_taken = f.blocks.iter().find(|b| b.start == 1).unwrap();
    assert_eq!(not_taken.term, Term::Exit, "the real, in-text side must still be ordinary code");
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

    assert_eq!(scanned.warnings, vec![Warning::JumpOutOfText { pc: 0, target: 0 }]);
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
    assert_eq!(scanned.warnings, vec![Warning::Cpi { pc: 0, name: "sol_invoke_signed_c" }]);
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
    assert_eq!(scanned.warnings, vec![Warning::Cpi { pc: 0, name: "sol_invoke_signed_rust" }]);
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
    assert_eq!(scanned.warnings, vec![Warning::Cpi { pc: 2, name: "sol_invoke_signed_c" }]);
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
    assert_eq!(scanned.warnings, vec![Warning::UnknownSyscall { pc: 0, hash }]);
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
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../guests-compiled/sbpf/programs/spl_token.so");
    let mut bytes = std::fs::read(path).expect("the committed SPL Token ELF");
    let program = sbpf_core::elf::load(&mut bytes).expect("SPL Token must load");

    let scanned = scan(&program);

    let unsupported = ["sol_set_return_data", "sol_get_sysvar"];
    let unsupported_hashes: Vec<u32> =
        unsupported.iter().map(|n| syscalls::murmur3_32(n.as_bytes(), 0)).collect();
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
