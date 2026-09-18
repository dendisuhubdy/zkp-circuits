//! Every rule the checker enforces, one rejection each, on hand-assembled words — no compiler
//! needed. Encodings: RV32I as in research/src/isa.rs's encoder.

use rand_guest::check::{check_text, Rule};
use rand_zkvm::isa::Instr;

fn enc(i: Instr) -> u32 { i.encode() }

fn ok_program() -> Vec<u32> {
    // li a7, 0 ; ecall  (HALT)
    vec![enc(Instr::AluImm { op: rand_zkvm::isa::AluOp::Add, rd: 17, rs1: 0, imm: 0 }), enc(Instr::Ecall)]
}

#[test]
fn a_clean_program_passes_with_no_findings() {
    let p = ok_program();
    let r = check_text(0x1000, &p, p.len(), 4096);
    assert!(r.is_ok(), "{r}");
    assert_eq!(r.words, 2);
}

#[test]
fn a_compressed_encoding_is_named() {
    let mut p = ok_program();
    p.push(0x0000_4501); // c.li a0, 0 — a 16-bit encoding: low bits are not 0b11
    let r = check_text(0x1000, &p, p.len(), 4096);
    assert!(r.findings.iter().any(|f| f.rule == Rule::Compressed), "{r}");
}

#[test]
fn fence_csr_and_ebreak_are_named_not_lumped_as_undecodable() {
    for (word, rule) in [(0x0ff0_000f, Rule::Fence), (0xc000_2573, Rule::Csr), (0x0010_0073, Rule::Ebreak)] {
        let mut p = ok_program();
        p.insert(0, word);
        let r = check_text(0x1000, &p, p.len(), 4096);
        assert!(r.findings.iter().any(|f| f.rule == rule && f.word == word), "{word:#x}: {r}");
    }
}

#[test]
fn an_unknown_syscall_number_is_named_and_a_known_one_is_not() {
    let bad = vec![enc(Instr::AluImm { op: rand_zkvm::isa::AluOp::Add, rd: 17, rs1: 0, imm: 99 }), enc(Instr::Ecall)];
    let r = check_text(0x1000, &bad, bad.len(), 4096);
    assert!(r.findings.iter().any(|f| f.rule == Rule::Syscall && f.what.contains("99")), "{r}");
    assert!(check_text(0x1000, &ok_program(), 2, 4096).is_ok());
}

#[test]
fn an_ecall_whose_a7_is_not_static_is_a_warning_not_a_finding() {
    // a7 = a0 ; ecall
    let p = vec![enc(Instr::AluReg { op: rand_zkvm::isa::AluOp::Add, rd: 17, rs1: 10, rs2: 0 }), enc(Instr::Ecall)];
    let r = check_text(0x1000, &p, p.len(), 4096);
    assert!(r.is_ok());
    assert_eq!(r.unresolved_ecalls, 1);
}

#[test]
fn the_cap_is_measured_against_the_loaders_own_word_count() {
    // The caller passes the loader's `Program::words.len()` for the image — text plus the real
    // data prologue — not a count the checker could estimate from the data words.
    let r = check_text(0x1000, &ok_program(), 10, 9);
    assert!(r.findings.iter().any(|f| f.rule == Rule::Cap), "{r}");
    assert!(r.findings.iter().any(|f| f.what.contains("10 words (text 2 + prologue 8)")), "{r}");
    assert!(check_text(0x1000, &ok_program(), 10, 10).is_ok());
}

#[test]
fn a_misaligned_base_is_a_layout_finding() {
    let r = check_text(0x1002, &ok_program(), 2, 4096);
    assert!(r.findings.iter().any(|f| f.rule == Rule::Layout), "{r}");
}
