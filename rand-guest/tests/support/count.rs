//! A cycle counter for images past the largest tier: `rand_zkvm::emulator::execute`'s instruction
//! semantics — the same decoder, ALU and syscalls — counting one cycle per instruction instead of
//! recording a `CycleEvent` for it (about 1.2 GB per 2^20 cycles, which is why `rand-guest run`
//! stops at the largest tier's budget). `POSEIDON2` is the emulator's row group: the ecall row,
//! one absorb row per four words, two write-back rows, the digest being `hash::sponge_hash` of
//! the words (the same overwrite-mode sponge). The tests that use it check its count and outputs
//! against `rand-guest run` wherever the run fits. Shared by rand-guest's `evm_precompiles` test and evm2rv's `precompiles` test
//! (`#[path]`), both of which depend on `rand_zkvm`.

use rand_zkvm::isa::{
    AluOp, BranchCond, Instr, Program, Width, SYS_HALT, SYS_KECCAK, SYS_POSEIDON2, SYS_READ_INPUT,
    SYS_SHA256, SYS_WRITE_OUTPUT,
};

fn sext(x: u32, bits: u32) -> u32 {
    ((x << (32 - bits)) as i32 >> (32 - bits)) as u32
}

/// `rand_zkvm::emulator::execute`'s instruction semantics — the same decoder, ALU and syscalls —
/// counting one cycle per instruction instead of recording it. Returns the outputs and the count.
pub fn count(program: &Program, inputs: &[u32], limit: u64) -> ([u32; 8], u64) {
    let mut regs = [0u32; 32];
    let mut ram = vec![0u32; 1 << 22]; // word addresses below 16 MiB
    let mut out = [0u32; 8];
    let mut pc = program.base_pc;
    let mut n = 0u64;
    loop {
        assert!(n < limit, "past {limit} cycles");
        n += 1;
        let instr = program
            .instr_at(pc)
            .unwrap_or_else(|| panic!("bad pc {pc:#x}"));
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
                        assert!(off & 1 == 0);
                        let v = (w >> (8 * off)) & 0xffff;
                        if signed {
                            sext(v, 16)
                        } else {
                            v
                        }
                    }
                    Width::Word => {
                        assert!(off == 0);
                        w
                    }
                };
            }
            Instr::Store { width, .. } => {
                let addr = a.wrapping_add(dec.imm);
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
                    SYS_HALT => return (out, n),
                    SYS_WRITE_OUTPUT => out[arg0 as usize] = arg1,
                    SYS_READ_INPUT => {
                        c = inputs[arg0 as usize];
                        write = true;
                    }
                    SYS_KECCAK => {
                        let p = arg0 as usize;
                        let mut w = [0u32; 50];
                        w.copy_from_slice(&ram[p..p + 50]);
                        let mut st = rand_zkvm::keccak::words_to_state(&w);
                        rand_zkvm::keccak::keccak_f(&mut st);
                        ram[p..p + 50].copy_from_slice(&rand_zkvm::keccak::state_to_words(&st));
                    }
                    SYS_POSEIDON2 => {
                        let (p, len) = (arg0 as usize, arg1 as usize);
                        let digest = rand_zkvm::hash::sponge_hash(&ram[p..p + len]);
                        ram[p..p + 8].copy_from_slice(&digest);
                        n += len.div_ceil(4) as u64 + 2; // the absorb rows and the two write-backs
                    }
                    SYS_SHA256 => {
                        let p = arg0 as usize;
                        let block: [u32; 16] = ram[p..p + 16].try_into().unwrap();
                        let mut h: [u32; 8] = ram[p + 16..p + 24].try_into().unwrap();
                        rand_zkvm::sha256::compress(&mut h, &block);
                        ram[p + 16..p + 24].copy_from_slice(&h);
                    }
                    other => panic!("syscall {other} (the counter does not model it)"),
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
