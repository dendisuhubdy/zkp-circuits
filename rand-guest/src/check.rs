//! The ISA report: every text word decoded with the machine's own decoder, syscall numbers
//! resolved where they are static, the layout and the cap. A guest that passes cannot fail
//! in-circuit for an encoding, syscall-number or layout reason.

use rand_zkvm::isa::{AluOp, DecodeError, Instr};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule { Compressed, Undecodable, Fence, Csr, Ebreak, Syscall, Cap, Layout }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding { pub addr: u32, pub word: u32, pub rule: Rule, pub what: String }

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    /// The loader's own word count for this image: the text plus the data prologue
    /// `Program::from_flat_image` synthesises. Not an estimate — a prologue `li` is one word or
    /// two depending on the constant, and the base register is reset whenever the store's
    /// immediate would leave range, so only the loader can say.
    pub words: usize,
    pub cap: usize,
    pub unresolved_ecalls: usize,
}

impl Report {
    pub fn is_ok(&self) -> bool { self.findings.is_empty() }
}

/// The syscall numbers the machine implements (research/docs/01-isa.md "Syscall ABI").
pub const SYSCALLS: [(u32, &str); 7] = [(0, "HALT"), (1, "WRITE_OUTPUT"), (2, "READ_INPUT"), (3, "POSEIDON2"), (4, "KECCAK"), (5, "SHA256"), (6, "READ_PUBLIC")];

const OP_MISC_MEM: u32 = 0x0f;
const OP_SYSTEM: u32 = 0x73;

/// `program_words` is `Program::words.len()` for the image the text came from — the text plus the
/// loader's data prologue. It is what the chain counts against the cap, so it is what the caller
/// must pass; for a bare text with no data it is simply `text.len()`.
pub fn check_text(base_pc: u32, text: &[u32], program_words: usize, max_words: usize) -> Report {
    let mut r = Report { cap: max_words, ..Default::default() };
    if base_pc % 4 != 0 {
        r.findings.push(Finding { addr: base_pc, word: 0, rule: Rule::Layout, what: format!("text base {base_pc:#x} is not word-aligned") });
    }
    // The last `addi a7, x0, n` seen in straight-line code; cleared by any write to a7 that is
    // not that shape, and by any control transfer (a branch target could arrive with any a7).
    let mut a7: Option<u32> = None;
    for (i, &w) in text.iter().enumerate() {
        let addr = base_pc.wrapping_add(4 * i as u32);
        if w & 3 != 3 {
            r.findings.push(Finding { addr, word: w, rule: Rule::Compressed, what: "16-bit (RVC) encoding; the machine decodes only 32-bit RV32IM".into() });
            continue;
        }
        match Instr::decode(w) {
            Ok(Instr::Ecall) => match a7 {
                Some(n) if SYSCALLS.iter().any(|(k, _)| *k == n) => {}
                Some(n) => r.findings.push(Finding { addr, word: w, rule: Rule::Syscall, what: format!("ecall with a7 = {n}, which is no syscall the machine implements") }),
                None => r.unresolved_ecalls += 1,
            },
            Ok(Instr::AluImm { op: AluOp::Add, rd: 17, rs1: 0, imm }) => a7 = Some(imm),
            Ok(Instr::AluImm { rd: 17, .. }) | Ok(Instr::AluReg { rd: 17, .. }) | Ok(Instr::Lui { rd: 17, .. }) | Ok(Instr::Auipc { rd: 17, .. }) | Ok(Instr::Load { rd: 17, .. }) | Ok(Instr::Jal { rd: 17, .. }) | Ok(Instr::Jalr { rd: 17, .. }) => a7 = None,
            Ok(Instr::Jal { .. }) | Ok(Instr::Jalr { .. }) | Ok(Instr::Branch { .. }) => a7 = None,
            Ok(_) => {}
            Err(e) => {
                let opcode = w & 0x7f;
                let (rule, what) = match (opcode, e) {
                    (OP_MISC_MEM, _) => (Rule::Fence, "FENCE/FENCE.I: the machine has no memory ordering instructions".to_string()),
                    (OP_SYSTEM, _) if w == 0x0010_0073 => (Rule::Ebreak, "EBREAK: traps are not modelled".to_string()),
                    (OP_SYSTEM, _) => (Rule::Csr, "CSR instruction: the machine has no CSRs".to_string()),
                    (_, DecodeError::Opcode(o)) => (Rule::Undecodable, format!("opcode {o:#x} is outside RV32IM as the machine implements it")),
                    (_, DecodeError::Funct(f)) => (Rule::Undecodable, format!("funct {f:#x} is not an RV32IM encoding")),
                    (_, DecodeError::Shamt(s)) => (Rule::Undecodable, format!("shift amount {s} is out of range")),
                };
                r.findings.push(Finding { addr, word: w, rule, what });
            }
        }
    }
    r.words = program_words;
    if r.words > max_words {
        r.findings.push(Finding { addr: base_pc, word: 0, rule: Rule::Cap, what: format!("{} words (text {} + prologue {}) exceed the cap of {max_words}", r.words, text.len(), r.words.saturating_sub(text.len())) });
    }
    r
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for x in &self.findings {
            writeln!(f, "{:#010x}  {:#010x}  {:?}: {}", x.addr, x.word, x.rule, x.what)?;
        }
        writeln!(f, "{} words against a cap of {} ({}); {} ecall(s) with a non-static a7", self.words, self.cap, if self.words <= self.cap { "fits" } else { "does not fit" }, self.unresolved_ecalls)?;
        write!(f, "{}", if self.is_ok() { "OK" } else { "REJECTED" })
    }
}
