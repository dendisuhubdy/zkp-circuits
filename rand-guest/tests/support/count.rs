//! A cycle counter for images past the largest tier: `rand_zkvm::emulator::execute`'s instruction
//! semantics — the same decoder, ALU and syscalls — counting one cycle per instruction instead of
//! recording a `CycleEvent` for it (about 1.2 GB per 2^20 cycles, which is why `rand-guest run`
//! stops at the largest tier's budget). `POSEIDON2` is the emulator's row group: the ecall row,
//! one absorb row per four words, two write-back rows, the digest being `hash::sponge_hash` of
//! the words (the same overwrite-mode sponge). The tests that use it check its count and outputs
//! against `rand-guest run` wherever the run fits. Shared by rand-guest's `evm_precompiles` test
//! and evm2rv's `precompiles` test (`#[path]`), both of which depend on `rand_zkvm`.
//!
//! **Errors are the emulator's.** Wherever `execute` returns an `ExecError`, so does this, with
//! the same variant and argument: the cycle budget (`OutOfCycles`, checked before every row, the
//! `POSEIDON2` row group's included), a pc with no instruction (`BadPc`), a misaligned load or
//! store (`Misaligned`), `WRITE_OUTPUT` past the eight slots or to a slot already written
//! (`OutputSlot`, `DoubleWrite`), `READ_INPUT` past the input (`InputIndex`), `READ_PUBLIC` (the
//! counter has no public segment, so every index is past it: `PublicIndex`), `POSEIDON2` over more
//! than `POSEIDON2_MAX_WORDS` words or from a pointer at or above 2^30 (`Poseidon2WordCount`,
//! `Poseidon2Ptr`), `KECCAK`/`SHA256` past their pointer limits (`KeccakPtrOutOfRange`,
//! `Sha256PtrOutOfRange`) and an unknown syscall (`BadSyscall`). The one difference left is the
//! memory: 16 MiB of words here (a panic past it) against the emulator's unbounded map.

use rand_zkvm::emulator::{ExecError, KECCAK_PTR_LIMIT, SHA256_PTR_LIMIT};
use rand_zkvm::isa::{
    AluOp, BranchCond, Instr, Program, Width, NUM_OUTPUTS, POSEIDON2_MAX_WORDS, SYS_HALT,
    SYS_KECCAK, SYS_POSEIDON2, SYS_READ_INPUT, SYS_READ_PUBLIC, SYS_SHA256, SYS_WRITE_OUTPUT,
};

/// The emulator's alignment rule: a word access on a multiple of 4, a half on a multiple of 2.
fn misaligned(width: Width, addr: u32) -> Result<(), ExecError> {
    let off = addr & 3;
    let bad = match width {
        Width::Word => off != 0,
        Width::Half => off != 0 && off != 2,
        Width::Byte => false,
    };
    if bad {
        return Err(ExecError::Misaligned(addr));
    }
    Ok(())
}

fn sext(x: u32, bits: u32) -> u32 {
    ((x << (32 - bits)) as i32 >> (32 - bits)) as u32
}

/// `rand_zkvm::emulator::execute`'s instruction semantics — the same decoder, ALU and syscalls —
/// counting one cycle per row instead of recording it. Returns the outputs and the count, or the
/// error `execute` would return (with `limit` as its `max_cycles`).
pub fn count(
    program: &Program,
    inputs: &[u32],
    limit: u64,
) -> Result<([u32; NUM_OUTPUTS], u64), ExecError> {
    let mut regs = [0u32; 32];
    let mut ram = vec![0u32; 1 << 22]; // word addresses below 16 MiB
    let mut out = [0u32; NUM_OUTPUTS];
    let mut written = [false; NUM_OUTPUTS];
    let mut pc = program.base_pc;
    let mut n = 0u64;
    loop {
        if n >= limit {
            return Err(ExecError::OutOfCycles(limit as usize));
        }
        n += 1;
        let instr = program.instr_at(pc).ok_or(ExecError::BadPc(pc))?;
        let dec = instr.decoded();
        let a = regs[dec.rs1 as usize];
        let b = regs[dec.rs2 as usize];
        let b_eff = if dec.is_imm == 1 { dec.imm } else { b };
        let mut next = pc.wrapping_add(4);
        let mut c = 0u32;
        let mut write = dec.writes_rd == 1;
        match instr {
            Instr::AluImm { op, .. } | Instr::AluReg { op, .. } => c = op.eval(a, b_eff),
            Instr::Lui { imm, .. } => c = imm,
            Instr::Auipc { .. } => c = pc.wrapping_add(dec.imm),
            Instr::Jal { .. } => {
                c = pc.wrapping_add(4);
                next = pc.wrapping_add(dec.imm);
            }
            Instr::Jalr { .. } => {
                c = pc.wrapping_add(4);
                next = AluOp::Add.eval(a, b_eff);
            }
            Instr::Branch { cond, .. } => {
                let _: BranchCond = cond;
                let r = AluOp::from_code(dec.br_op).eval(a, b_eff);
                if (r == 1) != (dec.br_neg == 1) {
                    next = pc.wrapping_add(dec.imm);
                }
            }
            Instr::Load { width, signed, .. } => {
                let addr = a.wrapping_add(dec.imm);
                misaligned(width, addr)?;
                let (off, w) = (addr & 3, ram[(addr >> 2) as usize]);
                c = match width {
                    Width::Byte => {
                        let v = (w >> (8 * off)) & 0xff;
                        if signed {
                            sext(v, 8)
                        } else {
                            v
                        }
                    }
                    Width::Half => {
                        let v = (w >> (8 * off)) & 0xffff;
                        if signed {
                            sext(v, 16)
                        } else {
                            v
                        }
                    }
                    Width::Word => w,
                };
            }
            Instr::Store { width, .. } => {
                let addr = a.wrapping_add(dec.imm);
                misaligned(width, addr)?;
                let (off, i) = (addr & 3, (addr >> 2) as usize);
                ram[i] = match width {
                    Width::Byte => (ram[i] & !(0xff << (8 * off))) | ((b & 0xff) << (8 * off)),
                    Width::Half => (ram[i] & !(0xffff << (8 * off))) | ((b & 0xffff) << (8 * off)),
                    Width::Word => b,
                };
            }
            Instr::Ecall => {
                let (num, arg0, arg1) = (a, b, regs[rand_zkvm::emulator::ECALL_MEM_REG as usize]);
                match num {
                    SYS_HALT => return Ok((out, n)),
                    SYS_WRITE_OUTPUT => {
                        let slot = arg0 as usize;
                        if slot >= NUM_OUTPUTS {
                            return Err(ExecError::OutputSlot(arg0));
                        }
                        if written[slot] {
                            return Err(ExecError::DoubleWrite(arg0));
                        }
                        written[slot] = true;
                        out[slot] = arg1;
                    }
                    SYS_READ_INPUT => {
                        c = *inputs
                            .get(arg0 as usize)
                            .ok_or(ExecError::InputIndex(arg0))?;
                        write = true;
                    }
                    SYS_READ_PUBLIC => return Err(ExecError::PublicIndex(arg0)),
                    SYS_KECCAK => {
                        if arg0 > KECCAK_PTR_LIMIT {
                            return Err(ExecError::KeccakPtrOutOfRange(arg0));
                        }
                        let p = arg0 as usize;
                        let mut w = [0u32; 50];
                        w.copy_from_slice(&ram[p..p + 50]);
                        let mut st = rand_zkvm::keccak::words_to_state(&w);
                        rand_zkvm::keccak::keccak_f(&mut st);
                        ram[p..p + 50].copy_from_slice(&rand_zkvm::keccak::state_to_words(&st));
                    }
                    SYS_POSEIDON2 => {
                        if arg1 > POSEIDON2_MAX_WORDS {
                            return Err(ExecError::Poseidon2WordCount(arg1));
                        }
                        if arg0 >= 1 << 30 {
                            return Err(ExecError::Poseidon2Ptr(arg0));
                        }
                        let (p, len) = (arg0 as usize, arg1 as usize);
                        // The absorb rows and the two write-backs, each checked against the
                        // budget as the emulator pushes it.
                        let rows = len.div_ceil(4) as u64 + 2;
                        if n + rows > limit {
                            return Err(ExecError::OutOfCycles(limit as usize));
                        }
                        let digest = rand_zkvm::hash::sponge_hash(&ram[p..p + len]);
                        ram[p..p + 8].copy_from_slice(&digest);
                        n += rows;
                    }
                    SYS_SHA256 => {
                        if arg0 > SHA256_PTR_LIMIT {
                            return Err(ExecError::Sha256PtrOutOfRange(arg0));
                        }
                        let p = arg0 as usize;
                        let block: [u32; 16] = ram[p..p + 16].try_into().unwrap();
                        let mut h: [u32; 8] = ram[p + 16..p + 24].try_into().unwrap();
                        rand_zkvm::sha256::compress(&mut h, &block);
                        ram[p + 16..p + 24].copy_from_slice(&h);
                    }
                    other => return Err(ExecError::BadSyscall(other)),
                }
            }
        }
        if write {
            regs[dec.rd as usize] = c;
        }
        regs[0] = 0;
        pc = next;
    }
}
