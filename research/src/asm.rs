//! A small assembler so guests can be written in Rust source without a RISC-V toolchain.
use crate::isa::*;
use std::collections::HashMap;

enum Item { Instr(Instr), Branch { cond: BranchCond, rs1: u32, rs2: u32, label: String }, Jal { rd: u32, label: String } }

pub struct Assembler { base_pc: u32, items: Vec<Item>, labels: HashMap<String, usize> }

impl Assembler {
    pub fn new(base_pc: u32) -> Self { Self { base_pc, items: Vec::new(), labels: HashMap::new() } }
    pub fn label(&mut self, name: &str) { assert!(self.labels.insert(name.to_string(), self.items.len()).is_none(), "duplicate label {name}"); }
    pub fn push(&mut self, i: Instr) { self.items.push(Item::Instr(i)); }
    pub fn extend(&mut self, is: impl IntoIterator<Item = Instr>) { for i in is { self.push(i); } }
    pub fn branch(&mut self, cond: BranchCond, rs1: u32, rs2: u32, label: &str) { self.items.push(Item::Branch { cond, rs1, rs2, label: label.into() }); }
    pub fn jal(&mut self, rd: u32, label: &str) { self.items.push(Item::Jal { rd, label: label.into() }); }
    pub fn assemble(self) -> Program {
        let target = |label: &str, from: usize| -> u32 {
            let to = *self.labels.get(label).unwrap_or_else(|| panic!("unknown label {label}"));
            ((to as i64 - from as i64) * 4) as i32 as u32
        };
        let words = self.items.iter().enumerate().map(|(i, it)| match it {
            Item::Instr(x) => x.encode(),
            Item::Branch { cond, rs1, rs2, label } => Instr::Branch { cond: *cond, rs1: *rs1, rs2: *rs2, imm: target(label, i) }.encode(),
            Item::Jal { rd, label } => Instr::Jal { rd: *rd, imm: target(label, i) }.encode(),
        }).collect();
        Program::new(self.base_pc, words)
    }
}

/// Mnemonic helpers. Immediates are `i32` for readability and stored sign-extended.
pub mod ops {
    use crate::isa::*;
    fn imm(i: i32) -> u32 { i as u32 }
    pub fn addi(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Add, rd, rs1, imm: imm(i) } }
    pub fn andi(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::And, rd, rs1, imm: imm(i) } }
    pub fn ori(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Or, rd, rs1, imm: imm(i) } }
    pub fn xori(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Xor, rd, rs1, imm: imm(i) } }
    pub fn slti(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Slt, rd, rs1, imm: imm(i) } }
    pub fn sltiu(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Sltu, rd, rs1, imm: imm(i) } }
    pub fn slli(rd: u32, rs1: u32, sh: u32) -> Instr { Instr::AluImm { op: AluOp::Sll, rd, rs1, imm: sh & 31 } }
    pub fn srli(rd: u32, rs1: u32, sh: u32) -> Instr { Instr::AluImm { op: AluOp::Srl, rd, rs1, imm: sh & 31 } }
    pub fn srai(rd: u32, rs1: u32, sh: u32) -> Instr { Instr::AluImm { op: AluOp::Sra, rd, rs1, imm: sh & 31 } }
    macro_rules! rrr { ($($name:ident => $op:ident),*) => { $( pub fn $name(rd: u32, rs1: u32, rs2: u32) -> Instr { Instr::AluReg { op: AluOp::$op, rd, rs1, rs2 } } )* } }
    rrr!(add => Add, sub => Sub, and => And, or => Or, xor => Xor, sll => Sll, srl => Srl, sra => Sra, slt => Slt, sltu => Sltu,
         mul => Mul, mulh => Mulh, mulhu => Mulhu, mulhsu => Mulhsu, div => Div, divu => Divu, rem => Rem, remu => Remu);
    pub fn lb(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Byte, signed: true } }
    pub fn lbu(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Byte, signed: false } }
    pub fn lh(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Half, signed: true } }
    pub fn lhu(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Half, signed: false } }
    pub fn lw(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Word, signed: false } }
    pub fn sb(rs1: u32, rs2: u32, off: i32) -> Instr { Instr::Store { rs1, rs2, imm: imm(off), width: Width::Byte } }
    pub fn sh(rs1: u32, rs2: u32, off: i32) -> Instr { Instr::Store { rs1, rs2, imm: imm(off), width: Width::Half } }
    pub fn sw(rs1: u32, rs2: u32, off: i32) -> Instr { Instr::Store { rs1, rs2, imm: imm(off), width: Width::Word } }
    pub fn lui(rd: u32, upper: u32) -> Instr { Instr::Lui { rd, imm: upper & 0xffff_f000 } }
    pub fn auipc(rd: u32, upper: u32) -> Instr { Instr::Auipc { rd, imm: upper & 0xffff_f000 } }
    pub fn jalr(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Jalr { rd, rs1, imm: imm(off) } }
    pub fn ecall() -> Instr { Instr::Ecall }
    pub fn mv(rd: u32, rs: u32) -> Instr { addi(rd, rs, 0) }
    /// Load a 32-bit constant: `lui` + `addi` when needed.
    pub fn li(rd: u32, v: i32) -> Vec<Instr> {
        if (-2048..=2047).contains(&v) { return vec![addi(rd, 0, v)]; }
        let v = v as u32;
        let lo = ((v & 0xfff) as i32) << 20 >> 20;           // sign-extended low 12
        let hi = v.wrapping_sub(lo as u32) & 0xffff_f000;     // upper 20 compensating for negative lo
        if lo == 0 { vec![lui(rd, hi)] } else { vec![lui(rd, hi), addi(rd, rd, lo)] }
    }
    pub fn halt() -> Vec<Instr> { let mut v = li(REG_A7, SYS_HALT as i32); v.push(ecall()); v }
    pub fn write_output(slot: u32, reg: u32) -> Vec<Instr> {
        let mut v = li(REG_A7, SYS_WRITE_OUTPUT as i32); v.extend(li(REG_A0, slot as i32)); v.push(mv(REG_A1, reg)); v.push(ecall()); v
    }
    /// Result lands in a0.
    pub fn read_input(idx: u32) -> Vec<Instr> { let mut v = li(REG_A7, SYS_READ_INPUT as i32); v.extend(li(REG_A0, idx as i32)); v.push(ecall()); v }
    /// M3.2: hashes `n` words at word address `ptr_words` (`a0`, the `MEM_ADDR` word-address
    /// convention) with the `POSEIDON2` sponge, overwriting `ptr_words..ptr_words+8` with the
    /// 8-word digest in place.
    pub fn call_poseidon2(ptr_words: i32, n: usize) -> Vec<Instr> {
        let mut v = li(REG_A7, SYS_POSEIDON2 as i32);
        v.extend(li(REG_A0, ptr_words));
        v.extend(li(REG_A1, n as i32));
        v.push(ecall());
        v
    }
}

// ───────────────────────── M3.3: note-layer guest routines ─────────────────────────
//
// `NOTE_COMMIT`, `NULLIFY` and `MERKLE_VERIFY` are library code, not new syscalls: they
// stage a domain tag plus the relevant `Word8`s into a scratch RAM buffer (word-for-word
// copies), call `ops::call_poseidon2` over that buffer, then copy out the 8-word result — the
// same shape `guests::transfer` used by hand for the M1.5/M3.2 development hash. All addressing is
// relative to a shared RAM-base register `base` (the caller loads its HEAP-relative value
// once, e.g. `guests::transfer`'s `BASE`); `ptr_words` is the scratch buffer's *word* address
// (`(HEAP + buf) / 4`, computed by the caller at assembly time since both are compile-time
// constants — `asm.rs` itself has no HEAP constant).
use crate::notes::{domain, Note};

/// Copies a `Word8` (8 words) from `base + src` to `base + dst`. The `Word8` analogue of a
/// hand-written 2-word `copy` helper.
pub fn copy_word8(a: &mut Assembler, base: u32, tmp: u32, src: i32, dst: i32) {
    for i in 0..8 {
        a.push(ops::lw(tmp, base, src + 4 * i));
        a.push(ops::sw(base, tmp, dst + 4 * i));
    }
}

/// `NOTE_COMMIT`: `note_words` (`Note::WORDS` words, already laid out at `base + note_at`)
/// hashed as `H(CM_DOMAIN, note_words)`. Stages `[CM_DOMAIN, note_words...]` at `base + buf`
/// (needs `1 + Note::WORDS` = 28 words of scratch), calls `POSEIDON2`, and copies the 8-word
/// digest to `base + cm_out`.
pub fn emit_note_commit(a: &mut Assembler, base: u32, tmp: u32, note_at: i32, buf: i32, ptr_words: i32, cm_out: i32) {
    a.extend(ops::li(tmp, domain::CM as i32));
    a.push(ops::sw(base, tmp, buf));
    for i in 0..Note::WORDS as i32 {
        a.push(ops::lw(tmp, base, note_at + 4 * i));
        a.push(ops::sw(base, tmp, buf + 4 + 4 * i));
    }
    a.extend(ops::call_poseidon2(ptr_words, 1 + Note::WORDS));
    copy_word8(a, base, tmp, buf, cm_out);
}

/// `NULLIFY`: the M1.5 form, `nf = H(NF_DOMAIN, nk, cm)` — bound to the commitment, not a
/// sender-chosen nonce, so two notes for the same owner can never collide to one nullifier.
/// `nk`/`cm` (8 words each) must already be at `base + nk_at` / `base + cm_at`. Stages
/// `[NF_DOMAIN, nk(8), cm(8)]` at `base + buf` (17 words of scratch), calls `POSEIDON2`, and
/// copies the digest to `base + nf_out`.
pub fn emit_nullify(a: &mut Assembler, base: u32, tmp: u32, nk_at: i32, cm_at: i32, buf: i32, ptr_words: i32, nf_out: i32) {
    a.extend(ops::li(tmp, domain::NF as i32));
    a.push(ops::sw(base, tmp, buf));
    copy_word8(a, base, tmp, nk_at, buf + 4);
    copy_word8(a, base, tmp, cm_at, buf + 36);
    a.extend(ops::call_poseidon2(ptr_words, 17));
    copy_word8(a, base, tmp, buf, nf_out);
}

/// `MERKLE_VERIFY`, depth `depth` (32 in this crate): proves the `Word8` at `base + leaf` is
/// a member of a tree whose root is written to `base + root_out`, given a private sibling
/// path already laid out at `base + path` (`depth` `Word8`s, leaf to root) and `index_word`
/// — a register holding the leaf's index, whose bit `level` selects which side the running
/// node is on at that level (`0`: running is left, sibling is right; `1`: the reverse).
///
/// Unrolled at assembly time (`depth` is fixed, so every level's path offset — `path + 32 *
/// level` — is a compile-time constant); the only runtime-conditioned step per level is the
/// branch that picks left/right order. Per level: `[NODE_DOMAIN, left(8), right(8)]` (17
/// words) staged at `base + buf`, one `POSEIDON2` call (`ceil(17/4) = 5` permutations),
/// result copied back into the running node. `label_prefix` must be unique per call site (two
/// `MERKLE_VERIFY`s in one program would otherwise collide on level labels).
#[allow(clippy::too_many_arguments)]
pub fn emit_merkle_verify(
    a: &mut Assembler,
    base: u32,
    tmp: u32,
    bit: u32,
    leaf: i32,
    path: i32,
    index_word: u32,
    buf: i32,
    ptr_words: i32,
    root_out: i32,
    depth: usize,
    label_prefix: &str,
) {
    use crate::isa::{BranchCond, REG_ZERO};
    copy_word8(a, base, tmp, leaf, root_out);
    for level in 0..depth {
        let sib = path + 32 * level as i32;
        let bit0 = format!("{label_prefix}_l{level}_bit0");
        let done = format!("{label_prefix}_l{level}_done");
        a.push(ops::srli(bit, index_word, level as u32));
        a.push(ops::andi(bit, bit, 1));
        a.branch(BranchCond::Eq, bit, REG_ZERO, &bit0);
        // bit == 1: the running node is on the right — [sibling, running].
        copy_word8(a, base, tmp, sib, buf + 4);
        copy_word8(a, base, tmp, root_out, buf + 36);
        a.jal(REG_ZERO, &done);
        a.label(&bit0);
        // bit == 0: the running node is on the left — [running, sibling].
        copy_word8(a, base, tmp, root_out, buf + 4);
        copy_word8(a, base, tmp, sib, buf + 36);
        a.label(&done);
        a.extend(ops::li(tmp, domain::NODE as i32));
        a.push(ops::sw(base, tmp, buf));
        a.extend(ops::call_poseidon2(ptr_words, 17));
        copy_word8(a, base, tmp, buf, root_out);
    }
}
