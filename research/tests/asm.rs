use rand_zkvm::asm::{ops::*, Assembler};
use rand_zkvm::guests;
use rand_zkvm::isa::*;

#[test]
fn labels_resolve_to_relative_offsets() {
    let mut a = Assembler::new(0);
    a.push(addi(1, 0, 3));          // 0x00
    a.label("loop");                // 0x04
    a.push(addi(1, 1, -1));         // 0x04
    a.branch(BranchCond::Ne, 1, 0, "loop"); // 0x08 -> -4
    a.jal(0, "end");                // 0x0c -> +8
    a.push(addi(2, 0, 99));         // 0x10 (skipped)
    a.label("end");                 // 0x14
    for i in halt() { a.push(i); }
    let p = a.assemble();
    assert_eq!(p.instr_at(8), Some(Instr::Branch { cond: BranchCond::Ne, rs1: 1, rs2: 0, imm: (-4i32) as u32 }));
    assert_eq!(p.instr_at(12), Some(Instr::Jal { rd: 0, imm: 8 }));
}

#[test]
fn li_handles_negative_and_large_values() {
    // li expands to lui+addi; check by decoding and simulating the two steps
    for v in [0i32, 1, -1, 2047, 2048, -2048, -2049, 0x7fff_ffff, i32::MIN, 0x1234_5678] {
        let seq = li(5, v);
        let mut acc: u32 = 0;
        for i in seq {
            match i {
                Instr::Lui { imm, .. } => acc = imm,
                Instr::AluImm { op: AluOp::Add, imm, rs1, .. } => { if rs1 == 0 { acc = imm } else { acc = acc.wrapping_add(imm) } }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(acc, v as u32, "li {v}");
    }
}

#[test]
fn every_guest_decodes() {
    for (name, p, _inputs) in guests::all() {
        for (i, w) in p.words.iter().enumerate() {
            Instr::decode(*w).unwrap_or_else(|e| panic!("{name} word {i}: {e:?}"));
        }
    }
}

#[test]
#[should_panic(expected = "at least one value")]
fn bubble_sort_rejects_empty_input() {
    let _ = guests::bubble_sort(&[]);
}

/// M4.2: `call_keccak` is the `KECCAK` syscall's three-instruction sequence — syscall number in
/// `a7`, the state's **word** address in `a0`, `ecall` — and every instruction of it round-trips
/// through the machine's own encoder.
#[test]
fn call_keccak_passes_the_syscall_number_and_a_word_address() {
    let seq = call_keccak(0x400 / 4);
    assert_eq!(seq, vec![addi(REG_A7, 0, SYS_KECCAK as i32), addi(REG_A0, 0, 0x400 / 4), Instr::Ecall]);
    for i in &seq { assert_eq!(Instr::decode(i.encode()).unwrap(), *i); }
}
