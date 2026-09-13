//! The sBPF ELF loader (M4.4 Task 5): `sbpf_core::elf::load` over hand-built ELF64 files that
//! exercise each of its paths, cross-checked against `solana-sbpf` 0.11.1 where the two loaders
//! describe the same thing, plus the committed SPL Token ELF (Task 6 commits the file and
//! un-`#[ignore]`s that test).

mod common;
use common::sbpf_elf_builder::{align8, build_elf, Rel, Sym, R_BPF_64_32, R_BPF_64_64, R_BPF_64_RELATIVE, TEXT_ADDR};
use common::sbpf_oracle as oracle;
use rand_zkvm::sbpf::{self, asm, insn, lddw};
use sbpf_core::elf::{self, Program};
use sbpf_core::interp::Halt;
use sbpf_core::isa::{self, opc};
use sbpf_core::memory::REGION_PROGRAM;
use sbpf_core::syscalls;

/// Decodes slot `i` of a loaded program's text.
fn slot(p: &Program, i: usize) -> isa::Insn {
    isa::decode(u64::from_le_bytes(p.text[8 * i..8 * i + 8].try_into().unwrap()))
}

#[test]
fn a_hand_built_elf_loads_its_text_rodata_and_entrypoint() {
    let text = asm(&[
        insn(opc::MOV64_IMM, 0, 0, 0, 1),
        insn(opc::MOV64_IMM, 0, 0, 0, 2),
        insn(opc::EXIT, 0, 0, 0, 0),
    ]);
    let rodata = b"read only".to_vec();
    let mut elf = build_elf(&text, &rodata, &[], &[], 1);
    let p = elf::load(&mut elf).unwrap();

    assert_eq!(p.text_va, REGION_PROGRAM + TEXT_ADDR);
    assert_eq!(p.text, &text[..]);
    assert_eq!(p.entry_pc, 1);
    // The read-only span starts at `.text` and runs to the end of `.rodata`, so it covers both.
    assert_eq!(p.rodata_va, REGION_PROGRAM + TEXT_ADDR);
    assert_eq!(p.rodata.len(), align8(text.len()) + rodata.len());
    assert_eq!(&p.rodata[..text.len()], &text[..]);
    assert_eq!(&p.rodata[align8(text.len())..], &rodata[..]);
    assert!(p.relocs_applied);

    // An entrypoint at slot 1 means the run starts there.
    let out = sbpf::run_elf(&mut build_elf(&text, &rodata, &[], &[], 1), &mut []);
    assert_eq!(out.result, Ok(2));
    let out = sbpf::run_elf(&mut build_elf(&text, &rodata, &[], &[], 0), &mut []);
    assert_eq!(out.result, Ok(2));
    let out = sbpf::run_elf(&mut build_elf(&text, &rodata, &[], &[], 2), &mut []);
    assert_eq!(out.result, Ok(0));
}

#[test]
fn r_bpf_64_relative_rebases_an_lddw_into_the_program_region() {
    // `lddw r1, <rodata address>` — the linker leaves the unrebased file address in the imm64 and
    // a `R_BPF_64_RELATIVE` at the slot; the loader adds the program region's base.
    let mut text: Vec<[u8; 8]> = Vec::new();
    let rodata_addr = align8(0x100 + 4 * 8) as u64; // four slots of text
    text.extend_from_slice(&lddw(1, rodata_addr));
    text.push(insn(opc::LD_B_REG, 0, 1, 3, 0));
    text.push(insn(opc::EXIT, 0, 0, 0, 0));
    let text = asm(&text);
    let rodata = b"abcdefgh".to_vec();
    let relocs = [Rel { offset: TEXT_ADDR, sym: 0, kind: R_BPF_64_RELATIVE }];

    let mut elf = build_elf(&text, &rodata, &[], &relocs, 0);
    let p = elf::load(&mut elf).unwrap();
    let (lo, hi) = (slot(&p, 0), slot(&p, 1));
    assert_eq!(isa::lddw_imm64(lo, hi), REGION_PROGRAM + rodata_addr);

    // And the program actually reads `rodata[3]` through the rebased pointer.
    let out = sbpf::run_elf(&mut build_elf(&text, &rodata, &[], &relocs, 0), &mut []);
    assert_eq!(out.result, Ok(u64::from(b'd')));

    // An `lddw` whose imm64 is already inside the program region is left alone.
    let mut text2: Vec<[u8; 8]> = Vec::new();
    text2.extend_from_slice(&lddw(1, REGION_PROGRAM + rodata_addr));
    text2.push(insn(opc::MOV64_REG, 0, 1, 0, 0));
    text2.push(insn(opc::EXIT, 0, 0, 0, 0));
    let text2 = asm(&text2);
    let out = sbpf::run_elf(&mut build_elf(&text2, &rodata, &[], &relocs, 0), &mut []);
    assert_eq!(out.result, Ok(REGION_PROGRAM + rodata_addr));
}

#[test]
fn r_bpf_64_relative_rebases_a_pointer_inside_a_data_section() {
    // A relocation whose site is *not* in `.text` patches an eight-byte pointer in place. SBPF v1
    // kept a toolchain bug's encoding: only the low 32 bits are stored, at the site's second word.
    let mut text: Vec<[u8; 8]> = Vec::new();
    let rodata_addr = align8(0x100 + 5 * 8) as u64;
    text.extend_from_slice(&lddw(1, rodata_addr)); // the pointer slot in .rodata
    text.push(insn(opc::LD_DW_REG, 1, 1, 0, 0)); // load the rebased pointer
    text.push(insn(opc::LD_B_REG, 0, 1, 0, 0)); // and dereference it
    text.push(insn(opc::EXIT, 0, 0, 0, 0));
    let text = asm(&text);

    // .rodata: eight bytes holding the (unrebased) address of the `Z` that follows it.
    let mut rodata = vec![0u8; 8];
    let target = rodata_addr + 8;
    rodata[4..8].copy_from_slice(&(target as u32).to_le_bytes());
    rodata.push(b'Z');

    let relocs = [
        Rel { offset: TEXT_ADDR, sym: 0, kind: R_BPF_64_RELATIVE },
        Rel { offset: rodata_addr, sym: 0, kind: R_BPF_64_RELATIVE },
    ];
    let mut elf = build_elf(&text, &rodata, &[], &relocs, 0);
    let p = elf::load(&mut elf).unwrap();
    let off = (rodata_addr - TEXT_ADDR) as usize;
    assert_eq!(
        u64::from_le_bytes(p.rodata[off..off + 8].try_into().unwrap()),
        REGION_PROGRAM + target
    );

    let out = sbpf::run_elf(&mut build_elf(&text, &rodata, &[], &relocs, 0), &mut []);
    assert_eq!(out.result, Ok(u64::from(b'Z')));
}

#[test]
fn r_bpf_64_64_adds_a_symbol_value_to_an_lddw() {
    // `lddw r1, &sym + 8`: the low imm holds the addend, the symbol carries the address.
    let mut text: Vec<[u8; 8]> = Vec::new();
    text.extend_from_slice(&lddw(1, 8));
    text.push(insn(opc::MOV64_REG, 0, 1, 0, 0));
    text.push(insn(opc::EXIT, 0, 0, 0, 0));
    let text = asm(&text);
    let syms = [Sym { name: "table", info: 0x11, value: 0x200 }]; // STT_OBJECT | STB_GLOBAL
    let relocs = [Rel { offset: TEXT_ADDR, sym: 1, kind: R_BPF_64_64 }];
    let mut elf = build_elf(&text, &[], &syms, &relocs, 0);
    let p = elf::load(&mut elf).unwrap();
    assert_eq!(isa::lddw_imm64(slot(&p, 0), slot(&p, 1)), REGION_PROGRAM + 0x208);
}

#[test]
fn r_bpf_64_32_turns_a_syscall_symbol_into_its_hash() {
    // An unresolved `call` — imm `-1`, src 0 — plus a `R_BPF_64_32` naming an undefined symbol is
    // a syscall: the loader writes murmur3 of the name into the imm and marks the slot `src = 1`.
    let text = asm(&[
        insn(opc::MOV64_IMM, 1, 0, 0, 0),
        insn(opc::MOV64_IMM, 2, 0, 0, 0),
        insn(opc::MOV64_IMM, 3, 0, 0, 0),
        insn(opc::CALL_IMM, 0, 0, 0, -1),
        insn(opc::EXIT, 0, 0, 0, 0),
    ]);
    let syms = [Sym { name: "sol_memset_", info: 0x10, value: 0 }]; // STT_NOTYPE, undefined
    let relocs = [Rel { offset: TEXT_ADDR + 3 * 8, sym: 1, kind: R_BPF_64_32 }];
    let mut elf = build_elf(&text, &[], &syms, &relocs, 0);
    let p = elf::load(&mut elf).unwrap();
    let call = slot(&p, 3);
    assert_eq!(call.opc, opc::CALL_IMM);
    assert_eq!(call.src, 1);
    assert_eq!(call.imm as u32, syscalls::SOL_MEMSET);
    assert_eq!(call.imm as u32, syscalls::murmur3_32(b"sol_memset_", 0));

    // A name the plan lists as unsupported still relocates — the loader does not decide policy —
    // and the *call* is what halts, with the hash in the error.
    let syms = [Sym { name: "sol_keccak256", info: 0x10, value: 0 }];
    let out = sbpf::run_elf(&mut build_elf(&text, &[], &syms, &relocs, 0), &mut []);
    assert_eq!(
        out.result,
        Err(Halt::UnknownSyscall(syscalls::murmur3_32(b"sol_keccak256", 0)))
    );
}

#[test]
fn r_bpf_64_32_turns_a_defined_function_symbol_into_a_relative_call() {
    // A defined `STT_FUNC` symbol inside `.text` is a bpf-to-bpf call: the loader rewrites the
    // imm to the *slot-relative* offset the interpreter uses, leaving `src = 0`.
    let text = asm(&[
        insn(opc::CALL_IMM, 0, 0, 0, -1), // slot 0 -> the callee at slot 2
        insn(opc::EXIT, 0, 0, 0, 0),
        insn(opc::MOV64_IMM, 0, 0, 0, 5), // slot 2
        insn(opc::EXIT, 0, 0, 0, 0),
    ]);
    let syms = [Sym { name: "callee", info: 0x12, value: TEXT_ADDR + 2 * 8 }];
    let relocs = [Rel { offset: TEXT_ADDR, sym: 1, kind: R_BPF_64_32 }];
    let mut elf = build_elf(&text, &[], &syms, &relocs, 0);
    let p = elf::load(&mut elf).unwrap();
    let call = slot(&p, 0);
    assert_eq!((call.opc, call.src, call.imm), (opc::CALL_IMM, 0, 1));

    let out = sbpf::run_elf(&mut build_elf(&text, &[], &syms, &relocs, 0), &mut []);
    assert_eq!(out.result, Ok(5));
}

#[test]
fn a_pc_relative_call_needs_no_relocation() {
    // The toolchain emits an intra-object call as a slot-relative `call`; nothing to patch.
    let text = asm(&[
        insn(opc::CALL_IMM, 0, 0, 0, 1),
        insn(opc::EXIT, 0, 0, 0, 0),
        insn(opc::MOV64_IMM, 0, 0, 0, 6),
        insn(opc::EXIT, 0, 0, 0, 0),
    ]);
    let out = sbpf::run_elf(&mut build_elf(&text, &[], &[], &[], 0), &mut []);
    assert_eq!(out.result, Ok(6));
}

#[test]
fn a_malformed_elf_is_refused_rather_than_trusted() {
    let text = asm(&[insn(opc::MOV64_IMM, 0, 0, 0, 1), insn(opc::EXIT, 0, 0, 0, 0)]);
    let good = build_elf(&text, b"ro", &[], &[], 0);
    assert!(elf::load(&mut good.clone()).is_ok());

    let bad = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut e = good.clone();
        f(&mut e);
        assert!(elf::load(&mut e).is_err(), "a malformed ELF was accepted");
    };
    bad(&|e| e[0] = 0); // magic
    bad(&|e| e[4] = 1); // ELFCLASS32
    bad(&|e| e[5] = 2); // big-endian
    bad(&|e| e[18] = 0xff); // e_machine
    bad(&|e| e[16] = 1); // e_type = ET_REL
    bad(&|e| e[24..32].copy_from_slice(&0u64.to_le_bytes())); // entry outside .text
    bad(&|e| e[24..32].copy_from_slice(&0x104u64.to_le_bytes())); // entry not slot-aligned
    bad(&|e| e[40..48].copy_from_slice(&u64::MAX.to_le_bytes())); // e_shoff out of bounds
    bad(&|e| e[60..62].copy_from_slice(&0u16.to_le_bytes())); // no sections, so no .text
    bad(&|e| e.truncate(60)); // a file shorter than its own header
    bad(&|e| e.truncate(0));
    // A `call` slot that already carries `src != 0` would be indistinguishable from the loader's
    // own syscall marking, so it is refused rather than reinterpreted.
    let mut e = build_elf(&asm(&[insn(opc::CALL_IMM, 0, 2, 0, 0)]), b"", &[], &[], 0);
    assert_eq!(elf::load(&mut e), Err(Halt::BadElf));
    // A `.text` whose length is not a whole number of slots.
    let mut e = build_elf(&[0u8; 12], b"", &[], &[], 0);
    assert_eq!(elf::load(&mut e), Err(Halt::BadElf));
    // A relocation type the loader does not implement.
    let mut e = build_elf(&text, b"ro", &[], &[Rel { offset: TEXT_ADDR, sym: 0, kind: 2 }], 0);
    assert_eq!(elf::load(&mut e), Err(Halt::BadElf));
    // A relocation whose site is outside the file.
    let mut e = build_elf(
        &text,
        b"ro",
        &[],
        &[Rel { offset: 1 << 40, sym: 0, kind: R_BPF_64_RELATIVE }],
        0,
    );
    assert_eq!(elf::load(&mut e), Err(Halt::BadElf));
    // A relocation naming a symbol index the table does not have.
    let mut e = build_elf(&text, b"ro", &[], &[Rel { offset: TEXT_ADDR, sym: 9, kind: R_BPF_64_32 }], 0);
    assert_eq!(elf::load(&mut e), Err(Halt::BadElf));
    // A defined function symbol pointing outside `.text`.
    let syms = [Sym { name: "callee", info: 0x12, value: 0x9000 }];
    let mut e = build_elf(&text, b"ro", &syms, &[Rel { offset: TEXT_ADDR, sym: 1, kind: R_BPF_64_32 }], 0);
    assert_eq!(elf::load(&mut e), Err(Halt::BadElf));
    // An ELF bigger than the ABI's cap cannot even be handed over, so the cap is a plain constant
    // check in `abi`, not a loader concern; assert it is the plan's number.
    assert_eq!(sbpf_core::abi::MAX_ELF_BYTES, 262_144);
}

#[test]
fn the_hand_built_elf_agrees_with_solana_sbpf() {
    // A relocation-only ELF (no calls, so the two loaders' different call conventions do not come
    // into it): the entrypoint, the read-only region's base and length, and the post-relocation
    // text bytes must all match `solana-sbpf`'s.
    // A `mov` at slot 0 so the entrypoint at slot 1 is a non-trivial one — and not the second half
    // of the `lddw`, which is not an instruction at all.
    let rodata_addr = align8(0x100 + 5 * 8) as u64;
    let mut text: Vec<[u8; 8]> = Vec::new();
    text.push(insn(opc::MOV64_IMM, 0, 0, 0, 0));
    text.extend_from_slice(&lddw(1, rodata_addr));
    text.push(insn(opc::LD_B_REG, 0, 1, 2, 0));
    text.push(insn(opc::EXIT, 0, 0, 0, 0));
    let text = asm(&text);
    let rodata = b"xyzw".to_vec();
    let relocs = [Rel { offset: TEXT_ADDR + 8, sym: 0, kind: R_BPF_64_RELATIVE }];
    let bytes = build_elf(&text, &rodata, &[], &relocs, 1);

    let mut ours_bytes = bytes.clone();
    let ours = elf::load(&mut ours_bytes).unwrap();
    let theirs = oracle::load(&bytes).expect("solana-sbpf rejected the hand-built ELF");
    assert_eq!(ours.entry_pc, theirs.entry_pc);
    assert_eq!(ours.text_va, theirs.text_va);
    assert_eq!(ours.text, &theirs.text[..]);
    assert_eq!(ours.rodata_va, theirs.rodata_va);
    assert_eq!(ours.rodata, &theirs.rodata[..]);

    // And the two machines run it to the same answer.
    assert_eq!(
        sbpf::run_elf(&mut bytes.clone(), &mut []).result.map_err(|_| ()),
        oracle::run_elf(&bytes, &[]).0.map_err(|_| ())
    );
    assert_eq!(sbpf::run_elf(&mut bytes.clone(), &mut []).result, Ok(u64::from(b'z')));
}

#[test]
#[ignore = "needs programs/spl_token.so, which Task 6 commits; un-ignore there"]
fn spl_token_elf_loads_with_relocations_applied() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../guests-compiled/sbpf/programs/spl_token.so");
    let bytes = std::fs::read(path).expect("the committed SPL Token ELF");
    let mut ours = bytes.clone();
    let p = elf::load(&mut ours).expect("SPL Token must load");

    // The entrypoint and the read-only region agree with `solana-sbpf`'s own loader.
    let theirs = oracle::load(&bytes).expect("solana-sbpf must load SPL Token");
    assert_eq!(p.entry_pc, theirs.entry_pc);
    assert_eq!(p.text_va, theirs.text_va);
    assert_eq!(p.rodata_va, theirs.rodata_va);
    assert_eq!(p.rodata.len(), theirs.rodata.len());

    // Every syscall call site names a syscall this interpreter either implements or deliberately
    // traps on — nothing outside the list the plan enumerates.
    let supported = syscalls::SUPPORTED;
    let trapping: Vec<u32> = [
        &b"sol_keccak256"[..],
        b"sol_secp256k1_recover",
        b"sol_ed25519_verify",
        b"sol_invoke_signed_c",
        b"sol_invoke_signed_rust",
        b"sol_create_program_address",
        b"sol_try_find_program_address",
        b"sol_get_clock_sysvar",
        b"sol_get_epoch_schedule_sysvar",
        b"sol_get_fees_sysvar",
        b"sol_get_rent_sysvar",
        b"sol_set_return_data",
        b"sol_get_return_data",
        b"sol_remaining_compute_units",
        b"sol_curve_validate_point",
    ]
    .iter()
    .map(|n| syscalls::murmur3_32(n, 0))
    .collect();
    let mut syscall_sites = 0usize;
    let mut unpatched = 0usize;
    let mut i = 0usize;
    while 8 * i + 8 <= p.text.len() {
        let ins = slot(&p, i);
        if ins.opc == opc::CALL_IMM {
            if ins.src == 1 {
                syscall_sites += 1;
                let h = ins.imm as u32;
                assert!(
                    supported.iter().any(|&(s, _)| s == h) || trapping.contains(&h),
                    "slot {i}: syscall hash {h:#010x} is neither supported nor a known trap"
                );
            } else if ins.imm == -1 {
                unpatched += 1;
            }
        }
        // `lddw` occupies two slots and its second half is not an instruction.
        i += if ins.opc == opc::LD_DW_IMM { 2 } else { 1 };
    }
    assert!(syscall_sites > 0, "SPL Token must call syscalls");
    assert_eq!(unpatched, 0, "{unpatched} call sites were left unrelocated");

    // No `R_BPF_64_RELATIVE` site is left unpatched: every `lddw` imm64 that is not a small
    // constant sits inside the program region rather than below it.
    let mut i = 0usize;
    while 8 * i + 16 <= p.text.len() {
        let lo = slot(&p, i);
        if lo.opc == opc::LD_DW_IMM {
            let v = isa::lddw_imm64(lo, slot(&p, i + 1));
            assert!(
                v < 0x1_0000 || (REGION_PROGRAM..REGION_PROGRAM + (1 << 32)).contains(&v),
                "slot {i}: lddw imm64 {v:#x} is neither a small constant nor a program address"
            );
            i += 2;
        } else {
            i += 1;
        }
    }
}
