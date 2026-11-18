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

#[test]
fn poseidon2_len_is_a_syscall_the_checker_accepts() {
    // li a7, 7 ; ecall  (POSEIDON2_LEN, the length-bound sponge guest_sdk::poseidon2_len calls)
    let p = vec![enc(Instr::AluImm { op: rand_zkvm::isa::AluOp::Add, rd: 17, rs1: 0, imm: 7 }), enc(Instr::Ecall)];
    let r = check_text(0x1000, &p, p.len(), 4096);
    assert!(r.is_ok(), "{r}");
    assert_eq!(r.unresolved_ecalls, 0);
}

// ---- TailScratch (ZKVM-101) -------------------------------------------------------------------

use rand_zkvm::isa::{AluOp, Width};

const T0: u32 = 5;
const T1: u32 = 6;
const RA: u32 = 1;
const A0: u32 = 10;

/// `auipc x, 0 ; jalr rd, 8(x)`: a far jump to the word after the pair, linking in `rd`.
fn far(x: u32, rd: u32) -> [u32; 2] {
    [enc(Instr::Auipc { rd: x, imm: 0 }), enc(Instr::Jalr { rd, rs1: x, imm: 8 })]
}

fn store(rs2: u32) -> u32 {
    enc(Instr::Store { rs1: A0, rs2, imm: 40, width: Width::Word })
}

fn tail_findings(p: &[u32]) -> Vec<rand_guest::check::Finding> {
    let r = check_text(0x1000, p, p.len(), 4096);
    r.findings.into_iter().filter(|f| f.rule == Rule::TailScratch).collect()
}

/// The shape clang 21.1.6 emits for a `minsize` function ending in an outlined store sequence:
/// `tail OUTLINED_FUNCTION_n` (`auipc t1 ; jalr zero, t1`) into a body that stores `t1` — which by
/// then holds the `auipc`'s address, not the value the function loaded into it.
#[test]
fn a_tail_call_whose_target_reads_the_jumps_own_scratch_register_is_named() {
    let mut p = far(T1, 0).to_vec();
    // The outlined body: unrelated stores first, then the one that reads t1.
    p.extend([store(A0 + 1), store(T1)]);
    p.extend(ok_program());
    let f = tail_findings(&p);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!((f[0].addr, f[0].word), (0x1004, p[1]), "the finding is at the jalr");
    for part in ["through t1", "to 0x1008", "reads t1 at 0x100c"] {
        assert!(f[0].what.contains(part), "{part}: {}", f[0].what);
    }
    assert!(!check_text(0x1000, &p, p.len(), 4096).is_ok(), "the image is rejected");
}

/// Correct code is not named: a target that writes the scratch register before reading it (what a
/// fixed outliner and every ordinary callee do), and the two linking forms — `call` (the target's
/// `ret` reads `ra`) and the outliner's own `call t0, …` (the body returns through `t0`) — where
/// the register holds the return address the target is meant to read.
#[test]
fn a_tail_call_into_code_that_does_not_read_the_scratch_register_first_is_not() {
    // t1 written, then read.
    let mut p = far(T1, 0).to_vec();
    p.extend([enc(Instr::AluImm { op: AluOp::Add, rd: T1, rs1: 0, imm: 5 }), store(T1)]);
    p.extend(ok_program());
    assert!(tail_findings(&p).is_empty());
    assert!(check_text(0x1000, &p, p.len(), 4096).is_ok());

    // t1 never touched.
    let mut p = far(T1, 0).to_vec();
    p.push(store(A0 + 1));
    p.extend(ok_program());
    assert!(tail_findings(&p).is_empty());

    // `call`: the target returns through ra.
    let mut p = far(RA, RA).to_vec();
    p.push(enc(Instr::Jalr { rd: 0, rs1: RA, imm: 0 }));
    assert!(tail_findings(&p).is_empty());

    // `call t0, OUTLINED_FUNCTION_n`: the body returns through t0.
    let mut p = far(T0, T0).to_vec();
    p.extend([store(T1), enc(Instr::Jalr { rd: 0, rs1: T0, imm: 0 })]);
    assert!(tail_findings(&p).is_empty());
}

/// The rule reads the target's straight-line code only: a read behind a control transfer is not
/// seen (README, "What `check` does not check"), and a target outside the text is left alone.
#[test]
fn the_tail_rule_stops_at_the_targets_first_control_transfer() {
    let mut p = far(T1, 0).to_vec();
    p.extend([enc(Instr::Jal { rd: 0, imm: 4 }), store(T1)]);
    p.extend(ok_program());
    assert!(tail_findings(&p).is_empty());

    let p = [enc(Instr::Auipc { rd: T1, imm: 0x10000 }), enc(Instr::Jalr { rd: 0, rs1: T1, imm: 0 }), store(T1)];
    assert!(tail_findings(&p).is_empty());
}
