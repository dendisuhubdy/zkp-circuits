//! What is refused, and where. Nothing about a program's *content* is refused by the scan (see
//! `scan::scan`'s module docs); what the pipeline refuses is a file `sbpf_core::elf::load` will not
//! load — and the CLI reports it with the loader's own `BadElf`. These tests build real ELF64
//! files with research's test builder (the one `tests/parity.rs` uses), break them one field at a
//! time, and check each refusal; the well-formed ones are loaded and scanned so the loader's
//! normalisation of calls, relocations and read-only data is seen by the scanner as expected.
//! The CLI itself is exercised through `CARGO_BIN_EXE_sbpf2rv`.

#[path = "../../research/tests/common/sbpf_elf_builder.rs"]
#[rustfmt::skip] // research's file, formatted (or not) by research
#[allow(dead_code)]
mod builder;

use builder::{build_elf, Rel, Sym, R_BPF_64_32, R_BPF_64_RELATIVE, TEXT_ADDR};
use sbpf2rv::emit::emit_program;
use sbpf2rv::scan::{scan, try_scan_with_limit, Term, TrapKind, Warning};
use sbpf_core::elf::Program;
use sbpf_core::interp::{Halt, Vm};
use sbpf_core::isa::{self, opc, Insn};
use sbpf_core::memory::{Memory, HEAP_BYTES, REGION_PROGRAM, STACK_BYTES};
use sbpf_core::syscalls;
use std::path::{Path, PathBuf};
use std::process::Command;

fn i(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        opc,
        dst,
        src,
        off,
        imm,
    }
}

fn exit() -> Insn {
    i(opc::EXIT, 0, 0, 0, 0)
}

fn text(insns: &[Insn]) -> Vec<u8> {
    insns
        .iter()
        .flat_map(|i| isa::encode(*i).to_le_bytes())
        .collect()
}

/// `mov r0, 7; exit` as a shared object.
fn small_elf() -> Vec<u8> {
    build_elf(
        &text(&[i(opc::MOV64_IMM, 0, 0, 0, 7), exit()]),
        &[],
        &[],
        &[],
        0,
    )
}

/// Whether `elf` loads, without keeping the program (it borrows the buffer).
fn loads(elf: &[u8]) -> Result<(), Halt> {
    let mut e = elf.to_vec();
    sbpf_core::elf::load(&mut e).map(|_| ())
}

/// The first occurrence of `needle` in `elf`, overwritten with `with` (the same length).
fn patch(elf: &mut [u8], needle: &[u8], with: &[u8]) {
    assert_eq!(needle.len(), with.len());
    let at = elf
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap_or_else(|| panic!("{needle:?} not in the file"));
    elf[at..at + with.len()].copy_from_slice(with);
}

/// The section header of `name`: its file offset.
fn shdr(elf: &[u8], name: &str) -> usize {
    let u16_at = |o: usize| u16::from_le_bytes(elf[o..o + 2].try_into().unwrap()) as usize;
    let u32_at = |o: usize| u32::from_le_bytes(elf[o..o + 4].try_into().unwrap()) as usize;
    let u64_at = |o: usize| u64::from_le_bytes(elf[o..o + 8].try_into().unwrap()) as usize;
    let (shoff, shnum, shstrndx) = (u64_at(0x28), u16_at(0x3c), u16_at(0x3e));
    let hdr = |k: usize| shoff + k * 64;
    let strtab = u64_at(hdr(shstrndx) + 0x18);
    (0..shnum)
        .find(|&k| {
            let at = strtab + u32_at(hdr(k));
            let end = at + elf[at..].iter().position(|&b| b == 0).unwrap();
            &elf[at..end] == name.as_bytes()
        })
        .map(hdr)
        .unwrap_or_else(|| panic!("no {name} section"))
}

fn set_u64(elf: &mut [u8], at: usize, v: u64) {
    elf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// The interpreter over a loaded program with an empty input region.
fn run(p: &Program<'_>) -> Result<u64, Halt> {
    let mut stack = vec![0u8; STACK_BYTES].into_boxed_slice();
    let mut heap = vec![0u8; HEAP_BYTES].into_boxed_slice();
    let mut input = Vec::new();
    let mem = Memory {
        text: p.text,
        text_va: p.text_va,
        rodata: p.rodata,
        rodata_base: p.rodata_va,
        stack: (&mut stack[..]).try_into().unwrap(),
        heap: (&mut heap[..]).try_into().unwrap(),
        input: &mut input,
    };
    let mut h = rand_zkvm::sbpf::HostRef;
    Vm::new(&mut h, p, mem).run()
}

fn work() -> PathBuf {
    let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/scan-rejects");
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Runs the CLI on `elf` (written to `name.so`) with `args`: `(status ok, stdout, stderr)`.
fn cli(name: &str, elf: &[u8], args: &[&str]) -> (bool, String, String) {
    let path = work().join(format!("{name}.so"));
    std::fs::write(&path, elf).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_sbpf2rv"))
        .arg(&path)
        .args(args)
        .output()
        .unwrap();
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

// ---- the well-formed file ------------------------------------------------------------------------

#[test]
fn a_hand_built_elf_loads_scans_clean_and_reports_no_refusal() {
    let elf = small_elf();
    let mut e = elf.clone();
    let p = sbpf_core::elf::load(&mut e).unwrap();
    assert_eq!(p.text_va, REGION_PROGRAM + TEXT_ADDR);
    assert_eq!(p.entry_pc, 0);
    assert!(p.relocs_applied);
    let s = scan(&p);
    assert!(s.warnings.is_empty());
    assert_eq!(run(&p), Ok(7));
    let (ok, out, err) = cli("small", &elf, &[]);
    assert!(ok, "{err}");
    assert_eq!(
        out,
        "entry pc 0: 1 function(s), 1 block(s), 2 instruction(s), 1 callx target(s), 0 refusal(s), 0 warning(s)\n  fn 0: 1 block(s)\n"
    );
}

#[test]
fn the_entry_may_be_any_slot_of_the_text() {
    let elf = build_elf(
        &text(&[exit(), i(opc::MOV64_IMM, 0, 0, 0, 5), exit()]),
        &[],
        &[],
        &[],
        1,
    );
    let mut e = elf.clone();
    let p = sbpf_core::elf::load(&mut e).unwrap();
    assert_eq!(p.entry_pc, 1);
    let s = scan(&p);
    assert_eq!(s.entry, 1);
    assert_eq!(s.functions[0].entry, 1);
    assert_eq!(run(&p), Ok(5));
    let (ok, out, _) = cli("entry1", &elf, &[]);
    assert!(ok);
    assert!(
        out.starts_with("entry pc 1: 1 function(s), 1 block(s), 2 instruction(s)"),
        "{out}"
    );
}

// ---- refused files ----------------------------------------------------------------------------------

#[test]
fn an_elf_without_a_text_section_is_refused() {
    let mut elf = small_elf();
    patch(&mut elf, b".text\0", b".tezt\0");
    assert_eq!(loads(&elf), Err(Halt::BadElf));
    let (ok, _, err) = cli("no-text", &elf, &[]);
    assert!(!ok);
    assert!(
        err.contains("is not a loadable sBPF v1 ELF: BadElf"),
        "{err}"
    );
}

#[test]
fn two_text_sections_are_refused() {
    let mut elf = small_elf();
    patch(&mut elf, b".rodata\0", b".text\0\0\0");
    assert_eq!(loads(&elf), Err(Halt::BadElf));
}

#[test]
fn a_text_whose_size_is_not_a_multiple_of_eight_is_refused() {
    let mut elf = small_elf();
    let h = shdr(&elf, ".text");
    let size = u64::from_le_bytes(elf[h + 32..h + 40].try_into().unwrap());
    assert_eq!(size, 16);
    set_u64(&mut elf, h + 32, 17);
    assert_eq!(loads(&elf), Err(Halt::BadElf));
    set_u64(&mut elf, h + 32, 15);
    assert_eq!(loads(&elf), Err(Halt::BadElf));
    set_u64(&mut elf, h + 32, 16);
    assert_eq!(loads(&elf), Ok(()));
}

#[test]
fn a_section_whose_address_is_not_its_file_offset_is_refused() {
    let mut elf = small_elf();
    let h = shdr(&elf, ".rodata");
    let addr = u64::from_le_bytes(elf[h + 16..h + 24].try_into().unwrap());
    set_u64(&mut elf, h + 16, addr + 8);
    assert_eq!(loads(&elf), Err(Halt::BadElf));
}

#[test]
fn an_entry_outside_or_unaligned_in_the_text_is_refused() {
    let base = small_elf();
    let with_entry = |e: u64| {
        let mut elf = base.clone();
        set_u64(&mut elf, 24, e);
        loads(&elf)
    };
    assert_eq!(with_entry(TEXT_ADDR), Ok(()));
    assert_eq!(with_entry(TEXT_ADDR + 8), Ok(()), "the last slot");
    assert_eq!(
        with_entry(TEXT_ADDR + 16),
        Err(Halt::BadElf),
        "one past the text"
    );
    assert_eq!(with_entry(TEXT_ADDR + 4), Err(Halt::BadElf), "unaligned");
    assert_eq!(with_entry(TEXT_ADDR - 8), Err(Halt::BadElf));
    assert_eq!(with_entry(0), Err(Halt::BadElf));
}

#[test]
fn the_v2_flag_is_refused_and_any_other_flag_word_is_v1() {
    let mut elf = small_elf();
    elf[48..52].copy_from_slice(&0x20u32.to_le_bytes());
    assert_eq!(loads(&elf), Err(Halt::BadElf));
    elf[48..52].copy_from_slice(&0x10u32.to_le_bytes());
    assert_eq!(loads(&elf), Ok(()));
}

#[test]
fn a_file_header_that_is_not_an_sbpf_v1_shared_object_is_refused() {
    let base = small_elf();
    let broken = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut elf = base.clone();
        f(&mut elf);
        loads(&elf)
    };
    assert_eq!(
        broken(&|e| e.truncate(63)),
        Err(Halt::BadElf),
        "shorter than a header"
    );
    assert_eq!(broken(&|e| e[1] = b'F'), Err(Halt::BadElf), "magic");
    assert_eq!(broken(&|e| e[4] = 1), Err(Halt::BadElf), "ELFCLASS32");
    assert_eq!(broken(&|e| e[5] = 2), Err(Halt::BadElf), "big-endian");
    assert_eq!(broken(&|e| e[16] = 2), Err(Halt::BadElf), "ET_EXEC");
    assert_eq!(
        broken(&|e| e[18..20].copy_from_slice(&62u16.to_le_bytes())),
        Err(Halt::BadElf),
        "EM_X86_64"
    );
    assert_eq!(
        broken(&|e| e[18..20].copy_from_slice(&263u16.to_le_bytes())),
        Ok(()),
        "EM_SBPF"
    );
    assert_eq!(
        broken(&|e| e[58..60].copy_from_slice(&40u16.to_le_bytes())),
        Err(Halt::BadElf),
        "e_shentsize"
    );
    assert_eq!(
        broken(&|e| e[60..62].copy_from_slice(&0u16.to_le_bytes())),
        Err(Halt::BadElf),
        "e_shnum 0"
    );
    assert_eq!(
        broken(&|e| e[62..64].copy_from_slice(&8u16.to_le_bytes())),
        Err(Halt::BadElf),
        "e_shstrndx out of range"
    );
    assert_eq!(broken(&|e| e[12] ^= 0x5a), Ok(()), "EI_PAD is not read");
}

#[test]
fn a_call_imm_with_a_src_nibble_above_one_is_refused_by_the_loader_but_scanned_from_text() {
    let t = text(&[i(opc::CALL_IMM, 0, 5, 0, 0), exit()]);
    assert_eq!(loads(&build_elf(&t, &[], &[], &[], 0)), Err(Halt::BadElf));
    // `Program::from_text` has no such pass: the scanner sees it and plants the runtime trap.
    let p = Program::from_text(&t).unwrap();
    let s = scan(&p);
    assert_eq!(s.warnings, vec![Warning::BadCallImmSrc { pc: 0, src: 5 }]);
    assert_eq!(
        s.functions[0].blocks[0].term,
        Term::Trap(TrapKind::BadInsn(opc::CALL_IMM))
    );
}

#[test]
fn the_loader_clears_the_toolchains_pseudo_call_marker_into_an_internal_call() {
    // The toolchain marks every `call imm` with `src = 1`; without a relocation naming the site it
    // is a slot-relative call, and the loader clears the marker so the scanner sees `src == 0`.
    let t = text(&[
        i(opc::CALL_IMM, 0, 1, 0, 1),  // 0: call 2
        exit(),                        // 1
        i(opc::MOV64_IMM, 0, 0, 0, 9), // 2
        exit(),                        // 3
    ]);
    let mut elf = build_elf(&t, &[], &[], &[], 0);
    let p = sbpf_core::elf::load(&mut elf).unwrap();
    let s = scan(&p);
    assert!(s.warnings.is_empty(), "{:?}", s.warnings);
    assert_eq!(s.functions.len(), 2);
    assert_eq!(
        s.functions[0].blocks[0].term,
        Term::Call { target: 2, next: 1 }
    );
    assert_eq!(run(&p), Ok(9));
}

#[test]
fn relocations_resolve_calls_to_functions_and_syscalls_by_name() {
    // 0: call f; 1: call sol_log_; 2: call sol_nope; 3: exit; 4: f: r0 = 1; 5: exit. Every call
    // site is the toolchain's `src = 1, imm = -1`, named by an `R_BPF_64_32` each.
    let t = text(&[
        i(opc::CALL_IMM, 0, 1, 0, -1),
        i(opc::CALL_IMM, 0, 1, 0, -1),
        i(opc::CALL_IMM, 0, 1, 0, -1),
        exit(),
        i(opc::MOV64_IMM, 0, 0, 0, 1),
        exit(),
    ]);
    let syms = [
        Sym {
            name: "f",
            info: 0x12,
            value: TEXT_ADDR + 8 * 4,
        },
        Sym {
            name: "sol_log_",
            info: 0x10,
            value: 0,
        },
        Sym {
            name: "sol_nope",
            info: 0x10,
            value: 0,
        },
    ];
    let rels: Vec<Rel> = (0..3)
        .map(|k| Rel {
            offset: TEXT_ADDR + 8 * k,
            sym: k as u32 + 1,
            kind: R_BPF_64_32,
        })
        .collect();
    let mut elf = build_elf(&t, &[], &syms, &rels, 0);
    let p = sbpf_core::elf::load(&mut elf).unwrap();
    let nope = syscalls::murmur3_32(b"sol_nope", 0);
    let s = scan(&p);
    assert_eq!(
        s.warnings,
        vec![Warning::UnknownSyscall { pc: 2, hash: nope }]
    );
    assert_eq!(s.callx_targets, vec![0, 4]);
    let f0 = &s.functions[0];
    let term = |pc: usize| f0.blocks.iter().find(|b| b.start == pc).unwrap().term;
    assert_eq!(term(0), Term::Call { target: 4, next: 1 });
    assert_eq!(
        term(1),
        Term::Syscall {
            hash: syscalls::SOL_LOG,
            next: 2
        }
    );
    assert_eq!(
        term(2),
        Term::Syscall {
            hash: nope,
            next: 3
        }
    );
    assert_eq!(run(&p), Err(Halt::UnknownSyscall(nope)));
    let c = emit_program(&p, &s).c;
    assert!(c.contains("r0 = sbpf_sys_log(r1, r2, r3, r4, r5);"), "{c}");
    assert!(
        c.contains(&format!(
            "sbpf_trap(SBPF_HALT_UNKNOWN_SYSCALL, {nope:#010x}u);"
        )),
        "{c}"
    );
}

#[test]
fn an_unsupported_or_misplaced_relocation_is_refused() {
    let t = text(&[
        i(opc::CALL_IMM, 0, 1, 0, -1),
        exit(),
        i(opc::MOV64_IMM, 0, 0, 0, 1),
        exit(),
    ]);
    let f = |value: u64| {
        [Sym {
            name: "f",
            info: 0x12,
            value,
        }]
    };
    let rel = |offset: u64, kind: u32| {
        [Rel {
            offset,
            sym: 1,
            kind,
        }]
    };
    // An unknown type.
    assert_eq!(
        loads(&build_elf(
            &t,
            &[],
            &f(TEXT_ADDR + 16),
            &rel(TEXT_ADDR, 2),
            0
        )),
        Err(Halt::BadElf)
    );
    // A call relocation outside the text.
    assert_eq!(
        loads(&build_elf(
            &t,
            &[0; 16],
            &f(TEXT_ADDR + 16),
            &rel(TEXT_ADDR + 32, R_BPF_64_32),
            0
        )),
        Err(Halt::BadElf)
    );
    // A function symbol that is unaligned, or outside the text.
    assert_eq!(
        loads(&build_elf(
            &t,
            &[],
            &f(TEXT_ADDR + 20),
            &rel(TEXT_ADDR, R_BPF_64_32),
            0
        )),
        Err(Halt::BadElf)
    );
    assert_eq!(
        loads(&build_elf(
            &t,
            &[],
            &f(TEXT_ADDR + 32),
            &rel(TEXT_ADDR, R_BPF_64_32),
            0
        )),
        Err(Halt::BadElf)
    );
    // A symbol index past the table.
    assert_eq!(
        loads(&build_elf(
            &t,
            &[],
            &f(TEXT_ADDR + 16),
            &[Rel {
                offset: TEXT_ADDR,
                sym: 7,
                kind: R_BPF_64_32
            }],
            0
        )),
        Err(Halt::BadElf)
    );
    // The same, well-formed.
    assert_eq!(
        loads(&build_elf(
            &t,
            &[],
            &f(TEXT_ADDR + 16),
            &rel(TEXT_ADDR, R_BPF_64_32),
            0
        )),
        Ok(())
    );
}

// ---- read-only data through the loader ---------------------------------------------------------------

#[test]
fn an_lddw_relocated_to_rodata_is_a_data_pointer_not_a_function_root() {
    // 0-1: lddw r1, &rodata (R_BPF_64_RELATIVE, site in the text); 2: r0 = [r1]; 3: exit.
    let rodata_addr = TEXT_ADDR + 32; // align8(TEXT_ADDR + 4 slots)
    let t = text(&[
        i(opc::LD_DW_IMM, 1, 0, 0, rodata_addr as i32),
        i(0, 0, 0, 0, 0),
        i(opc::LD_DW_REG, 0, 1, 0, 0),
        exit(),
    ]);
    let rodata = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut elf = build_elf(
        &t,
        &rodata,
        &[],
        &[Rel {
            offset: TEXT_ADDR,
            sym: 0,
            kind: R_BPF_64_RELATIVE,
        }],
        0,
    );
    let p = sbpf_core::elf::load(&mut elf).unwrap();
    assert_eq!(
        p.rodata_va,
        REGION_PROGRAM + TEXT_ADDR,
        "the run begins at .text"
    );
    assert_eq!(p.rodata.len(), 32 + 8);
    let s = scan(&p);
    assert!(s.warnings.is_empty(), "{:?}", s.warnings);
    assert_eq!(
        s.callx_targets,
        vec![0],
        "a pointer into the data names no function"
    );
    let c = emit_program(&p, &s).c;
    assert!(
        c.contains(&format!("r1 = {:#018x}ull;", REGION_PROGRAM + rodata_addr)),
        "{c}"
    );
    assert_eq!(run(&p), Ok(0x0807_0605_0403_0201));
}

#[test]
fn a_relocated_rodata_word_naming_a_function_is_a_callx_root() {
    // 0: callx r1; 1: exit; 2: r0 = 5; 3: exit — and an eight-byte table entry after the text
    // whose v1 encoding holds pc 2's file address in its second word.
    let t = text(&[
        i(opc::CALL_REG, 0, 0, 0, 1),
        exit(),
        i(opc::MOV64_IMM, 0, 0, 0, 5),
        exit(),
    ]);
    let mut rodata = [0u8; 8];
    rodata[4..8].copy_from_slice(&((TEXT_ADDR + 16) as u32).to_le_bytes());
    let mut elf = build_elf(
        &t,
        &rodata,
        &[],
        &[Rel {
            offset: TEXT_ADDR + 32,
            sym: 0,
            kind: R_BPF_64_RELATIVE,
        }],
        0,
    );
    let p = sbpf_core::elf::load(&mut elf).unwrap();
    assert_eq!(
        u64::from_le_bytes(p.rodata[32..40].try_into().unwrap()),
        REGION_PROGRAM + TEXT_ADDR + 16
    );
    let s = scan(&p);
    assert_eq!(s.callx_targets, vec![0, 2]);
    let f2 = s
        .functions
        .iter()
        .find(|f| f.entry == 2)
        .expect("pc 2 is a function");
    assert_eq!(
        f2.blocks[0].insns,
        vec![i(opc::MOV64_IMM, 0, 0, 0, 5), exit()]
    );
}

#[test]
fn a_call_imm_hidden_in_an_lddws_second_slot_passes_the_loader_and_traps_when_jumped_to() {
    // The loader's `call imm` pass steps over an `lddw`'s second slot, so a `call` with `src = 5`
    // there is not refused; the scanner decodes the slot independently and plants the trap the
    // interpreter would raise if a jump ever lands there.
    let t = text(&[
        i(opc::JA, 0, 0, 1, 0),             // 0: -> 2
        i(opc::LD_DW_IMM, 1, 0, 0, 0x1111), // 1
        i(opc::CALL_IMM, 0, 5, 0, 0),       // 2: the high half
        exit(),                             // 3
    ]);
    let mut elf = build_elf(&t, &[], &[], &[], 0);
    let p = sbpf_core::elf::load(&mut elf).expect("not refused");
    let s = scan(&p);
    assert_eq!(s.warnings, vec![Warning::BadCallImmSrc { pc: 2, src: 5 }]);
    let b2 = s.functions[0].blocks.iter().find(|b| b.start == 2).unwrap();
    assert!(b2.insns.is_empty());
    assert_eq!(b2.term, Term::Trap(TrapKind::BadInsn(opc::CALL_IMM)));
    assert_eq!(run(&p), Err(Halt::BadInsn(opc::CALL_IMM)));
}

// ---- registers ---------------------------------------------------------------------------------------------

#[test]
fn every_class_refuses_r11_to_r15_before_running_and_r10_is_allowed() {
    let shapes: [(&str, fn(u8) -> Insn); 9] = [
        ("alu64 dst", |r| i(opc::ADD64_IMM, r, 0, 0, 1)),
        ("alu32 src", |r| i(opc::ADD32_REG, 0, r, 0, 0)),
        ("load src", |r| i(opc::LD_W_REG, 0, r, 0, 0)),
        ("store dst", |r| i(opc::ST_DW_IMM, r, 0, 0, 0)),
        ("jump dst", |r| i(opc::JEQ_IMM, r, 0, 1, 0)),
        ("ja dst", |r| i(opc::JA, r, 0, 0, 0)),
        ("exit dst", |r| i(opc::EXIT, r, 0, 0, 0)),
        ("call src", |r| i(opc::CALL_IMM, 0, r, 0, 0)),
        ("lddw dst", |r| i(opc::LD_DW_IMM, r, 0, 0, 0)),
    ];
    for (what, shape) in shapes {
        for r in 11..=15u8 {
            let insn = shape(r);
            let t = text(&[insn, i(0, 0, 0, 0, 0), exit()]);
            let p = Program::from_text(&t).unwrap();
            let s = scan(&p);
            assert_eq!(
                s.warnings,
                vec![Warning::RegisterOutOfRange {
                    pc: 0,
                    opc: insn.opc
                }],
                "{what} r{r}"
            );
            let b0 = &s.functions[0].blocks[0];
            assert!(b0.insns.is_empty(), "{what} r{r}: never ran");
            assert_eq!(
                b0.term,
                Term::Trap(TrapKind::BadInsn(insn.opc)),
                "{what} r{r}"
            );
        }
        // r10 is a register like any other to the range check.
        let insn = shape(10);
        let t = text(&[insn, i(0, 0, 0, 0, 0), exit()]);
        let p = Program::from_text(&t).unwrap();
        let s = scan(&p);
        assert!(
            !s.warnings
                .iter()
                .any(|w| matches!(w, Warning::RegisterOutOfRange { .. })),
            "{what} r10: {:?}",
            s.warnings
        );
    }
}

#[test]
fn a_write_to_r10_is_neither_refused_nor_warned() {
    let t = text(&[
        i(opc::MOV64_REG, 10, 1, 0, 0),
        i(opc::ADD64_IMM, 10, 0, 0, -8),
        i(opc::ST_DW_IMM, 10, 0, 0, 1),
        exit(),
    ]);
    let p = Program::from_text(&t).unwrap();
    let s = scan(&p);
    assert!(s.warnings.is_empty());
    let c = emit_program(&p, &s).c;
    assert!(
        c.contains("    r10 = r1;\n    r10 = r10 + (uint64_t)-8;\n    sbpf_st8(r10, 0, 1);\n"),
        "{c}"
    );
}

// ---- the work limit ---------------------------------------------------------------------------------------

#[test]
fn the_scan_counts_each_blocks_instructions_plus_one_against_its_limit() {
    // One block of two instructions: three steps. The limit is exceeded strictly.
    let t = text(&[i(opc::MOV64_IMM, 0, 0, 0, 7), exit()]);
    let p = Program::from_text(&t).unwrap();
    assert!(try_scan_with_limit(&p, 2).is_err());
    assert!(try_scan_with_limit(&p, 3).is_ok());
    let e = try_scan_with_limit(&p, 2).unwrap_err();
    assert_eq!((e.limit, e.functions, e.roots), (2, 1, 1));
    // Two functions: each counted.
    let t = text(&[
        i(opc::CALL_IMM, 0, 0, 0, 1), // 0: call 2 — block [0], 2 steps
        exit(),                       // 1: block [1], 2 steps
        exit(),                       // 2: block [2], 2 steps
    ]);
    let p = Program::from_text(&t).unwrap();
    assert!(try_scan_with_limit(&p, 5).is_err());
    assert!(try_scan_with_limit(&p, 6).is_ok());
}

// ---- the CLI ------------------------------------------------------------------------------------------------

#[test]
fn the_cli_refuses_a_missing_file_and_a_bad_crate_name() {
    let o = Command::new(env!("CARGO_BIN_EXE_sbpf2rv"))
        .arg(work().join("does-not-exist.so"))
        .output()
        .unwrap();
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("reading") && err.contains("does-not-exist.so"),
        "{err}"
    );

    let out = work().join("named");
    let (ok, _, err) = cli(
        "name-check",
        &small_elf(),
        &["--out", out.to_str().unwrap(), "--name", "Spl Token"],
    );
    assert!(!ok);
    assert!(
        err.contains("--name \"Spl Token\" is not a crate name (try \"spl-token\")"),
        "{err}"
    );
    assert!(!out.join("program.c").exists(), "nothing written");
}

#[test]
fn the_cli_writes_the_six_shim_files_named_after_the_stem() {
    let out = work().join("written");
    let _ = std::fs::remove_dir_all(&out);
    let (ok, stdout, err) = cli("My_Prog", &small_elf(), &["--out", out.to_str().unwrap()]);
    assert!(ok, "{err}");
    for f in [
        "program.c",
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "src/main.rs",
        "shim.ld",
    ] {
        assert!(out.join(f).exists(), "{f}");
    }
    assert!(
        stdout.contains("and the my_prog shim crate: rand-guest build"),
        "{stdout}"
    );
    let toml = std::fs::read_to_string(out.join("Cargo.toml")).unwrap();
    assert!(toml.contains("name = \"my_prog\""), "{toml}");
    let c = std::fs::read_to_string(out.join("program.c")).unwrap();
    assert!(
        c.contains("const uint32_t sbpf_view_digest[8] = {"),
        "the guard"
    );
    assert!(
        c.contains(
            "L_0:\n    if ((budget -= 2) < 0) goto L_limit;\n    r0 = 7;\n    SBPF_RETURN();\n"
        ),
        "{c}"
    );
}

#[test]
fn the_cli_refuses_an_out_directory_outside_a_circuits_checkout() {
    let out = std::env::temp_dir().join(format!("sbpf2rv-outside-{}", std::process::id()));
    let (ok, _, err) = cli("outside", &small_elf(), &["--out", out.to_str().unwrap()]);
    let _ = std::fs::remove_dir_all(&out);
    assert!(!ok);
    assert!(err.contains("is not inside a circuits checkout"), "{err}");
}
