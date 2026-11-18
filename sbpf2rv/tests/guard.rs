//! What a translated image carries of its program (`shim::baked_c`: the addresses and the read-only
//! data, appended to the emitted code), and the translation's determinism. There is no ELF at run
//! time and no guard: `program.c` is the whole program, so `hc` binds it. Host-only: nothing here
//! needs a RISC-V toolchain (`tests/parity.rs` runs the images).

#[path = "../../research/tests/common/sbpf_elf_builder.rs"]
#[rustfmt::skip] // research's file, formatted (or not) by research
#[allow(dead_code)]
mod builder;

use builder::{build_elf, TEXT_ADDR};
use sbpf2rv::emit::emit_program;
use sbpf2rv::scan::scan;
use sbpf2rv::shim::{
    baked_c, crate_name, write_crate,
};
use sbpf_core::baked::baked_rodata;
use sbpf_core::elf::Program;
use sbpf_core::isa::{self, opc, Insn};
use sbpf_core::memory::REGION_PROGRAM;
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

fn text(insns: &[Insn]) -> Vec<u8> {
    insns
        .iter()
        .flat_map(|i| isa::encode(*i).to_le_bytes())
        .collect()
}

fn small(imm: i32, rodata: &[u8], entry: usize) -> Vec<u8> {
    build_elf(
        &text(&[i(opc::MOV64_IMM, 0, 0, 0, imm), i(opc::EXIT, 0, 0, 0, 0)]),
        rodata,
        &[],
        &[],
        entry,
    )
}

/// The read-only data a translated image of `elf` carries, and its address.
fn baked_of(elf: &[u8]) -> (u64, Vec<u8>) {
    let mut e = elf.to_vec();
    let p = sbpf_core::elf::load(&mut e).unwrap();
    let (va, bytes) = baked_rodata(&p);
    (va, bytes.to_vec())
}

fn section(elf: &[u8], name: &str) -> (usize, usize) {
    let u16_at = |o: usize| u16::from_le_bytes(elf[o..o + 2].try_into().unwrap()) as usize;
    let u32_at = |o: usize| u32::from_le_bytes(elf[o..o + 4].try_into().unwrap()) as usize;
    let u64_at = |o: usize| u64::from_le_bytes(elf[o..o + 8].try_into().unwrap()) as usize;
    let (shoff, shnum, shstrndx) = (u64_at(0x28), u16_at(0x3c), u16_at(0x3e));
    let hdr = |k: usize| shoff + k * 64;
    let strtab = u64_at(hdr(shstrndx) + 0x18);
    (0..shnum)
        .find_map(|k| {
            let at = strtab + u32_at(hdr(k));
            let end = at + elf[at..].iter().position(|&b| b == 0).unwrap();
            (&elf[at..end] == name.as_bytes())
                .then(|| (u64_at(hdr(k) + 0x18), u64_at(hdr(k) + 0x20)))
        })
        .unwrap_or_else(|| panic!("no {name} section"))
}

fn spl_token() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../guests-compiled/sbpf/programs/spl_token.so"
    ))
    .expect("the committed SPL Token ELF")
}

fn work(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/guard")
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ---- the view ---------------------------------------------------------------------------------------

/// The whole of `program.c` for an ELF: the emitted code, then `baked_c` — the addresses and the
/// read-only data. Everything a run can observe of the program, and so everything `hc` must bind.
fn c_of(elf: &[u8]) -> String {
    let mut e = elf.to_vec();
    let p = sbpf_core::elf::load(&mut e).unwrap();
    format!("{}{}", emit_program(&p, &scan(&p)).c, baked_c(&p, false))
}

#[test]
fn the_image_carries_the_read_only_data_without_the_text() {
    let rodata = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
    let elf = small(7, &rodata, 1);
    // The loaded run is the 16-byte text and then the 9 data bytes; the image takes the 9, at the
    // address the text ends.
    assert_eq!(baked_of(&elf), (REGION_PROGRAM + TEXT_ADDR + 16, rodata.to_vec()));
    let mut e = elf.clone();
    let p = sbpf_core::elf::load(&mut e).unwrap();
    assert_eq!(
        baked_c(&p, false),
        format!(
            "\n/* sbpf_core::baked::Baked: text_va, then the virtual address of the read-only data below. */\n\
             const uint64_t sbpf_baked[2] = {{{:#018x}ull, {:#018x}ull}};\n\
             /* The program's read-only data (sbpf_core::baked::baked_rodata): 9 byte(s). 4-aligned, so the\n   \
             loader writes it a word at a time. */\n\
             const uint32_t sbpf_rodata_len = 9;\n\
             __attribute__((aligned(4))) const uint8_t sbpf_rodata[9] = {{\n    1, 2, 3, 4, 5, 6, 7, 8, 9,\n}};\n",
            REGION_PROGRAM + TEXT_ADDR,
            REGION_PROGRAM + TEXT_ADDR + 16
        )
    );
    // With the text kept: the whole run, at the run's own address.
    let c = baked_c(&p, true);
    assert!(c.contains("const uint32_t sbpf_rodata_len = 25;\n"), "{c}");
    assert!(
        c.contains(&format!("{:#018x}ull, {:#018x}ull}};", REGION_PROGRAM + TEXT_ADDR, REGION_PROGRAM + TEXT_ADDR)),
        "{c}"
    );
    // No read-only data: an empty array is not C, so one zero byte and a length of 0.
    let mut e = small(7, &[], 0);
    let p = sbpf_core::elf::load(&mut e).unwrap();
    let c = baked_c(&p, false);
    assert!(c.contains("const uint32_t sbpf_rodata_len = 0;\n"), "{c}");
    assert!(c.ends_with("const uint8_t sbpf_rodata[1] = {0\n};\n"), "{c}");
}

#[test]
fn a_text_that_does_not_lead_the_run_leaves_the_whole_run_in_the_image() {
    let t = text(&[i(opc::EXIT, 0, 0, 0, 0)]);
    let data = [0xABu8; 12];
    let p = Program {
        text: &t,
        text_va: REGION_PROGRAM,
        rodata: &data,
        rodata_va: REGION_PROGRAM + 0x1000,
        entry_pc: 0,
        relocs_applied: false,
    };
    assert_eq!(baked_rodata(&p), (REGION_PROGRAM + 0x1000, &data[..]));
    // `Program::from_text`: the text is the whole run, so nothing is left to carry.
    let p = Program::from_text(&t).unwrap();
    assert_eq!(baked_rodata(&p), (REGION_PROGRAM + t.len() as u64, &[][..]));
}

// ---- what binds what -------------------------------------------------------------------------------
//
// There is no ELF at run time and no guard: `program.c` is the whole program, so any change a run
// could observe is a change to `program.c`, and so to `hc`.

#[test]
fn any_byte_a_run_can_observe_changes_program_c() {
    let base = small(7, &[9; 8], 0);
    let c0 = c_of(&base);
    // A text byte: the opcode, the register nibbles and the immediate of `mov r0, 7` each change
    // what the program does (its `off` field, bytes 2-3, means nothing to a `mov`, and the
    // interpreter ignores it too).
    let (off, len) = section(&base, ".text");
    assert_eq!(len, 16);
    for k in [0usize, 1, 4, 5, 6, 7] {
        let mut elf = base.clone();
        elf[off + k] ^= 0x01;
        assert_ne!(c_of(&elf), c0, "text byte {k}");
    }
    // A read-only byte, every one of them.
    let (off, len) = section(&base, ".rodata");
    for k in 0..len {
        let mut elf = base.clone();
        elf[off + k] ^= 0x80;
        assert_ne!(c_of(&elf), c0, "rodata byte {k}");
    }
    // The entry alone, and the amount of read-only data alone.
    assert_ne!(c_of(&small(7, &[9; 8], 1)), c0);
    assert_ne!(c_of(&small(7, &[9; 4], 0)), c0);
    assert_ne!(c_of(&small(7, &[0; 4], 0)), c_of(&small(7, &[0; 8], 0)));
}

#[test]
fn bytes_the_loader_never_reads_do_not_change_program_c() {
    let base = small(7, &[9; 8], 0);
    for (what, at) in [("EI_PAD", 12usize), ("EI_PAD last", 15), ("e_version", 20)] {
        let mut elf = base.clone();
        elf[at] ^= 0x5a;
        assert_eq!(c_of(&elf), c_of(&base), "{what}");
    }
    // The section header string table's own name is read by nobody either.
    let mut elf = base.clone();
    let at = elf.windows(10).position(|w| w == b".shstrtab\0").unwrap();
    elf[at + 1] = b'S';
    assert_eq!(c_of(&elf), c_of(&base));
}

#[test]
fn the_spl_token_image_carries_2848_bytes_of_a_108600_byte_elf() {
    let base = spl_token();
    assert_eq!(base.len(), 108_600);
    let (va, bytes) = baked_of(&base);
    // The ELF loads to a read-only run that begins with the text; what follows it is all the
    // translated code can load.
    let mut e = base.clone();
    let p = sbpf_core::elf::load(&mut e).unwrap();
    assert_eq!(bytes.len(), p.rodata.len() - p.text.len());
    assert_eq!(bytes.len(), 2_848);
    assert_eq!(va, p.text_va + p.text.len() as u64);
    // A read-only byte the transfer never reads is a different program.c; a byte the loader never
    // reads is not — and neither is a text byte in code nothing reaches (here the last slot's
    // immediate): it is not translated, and with no text bytes in the image no run can read it.
    let c0 = c_of(&base);
    let (off, len) = section(&base, ".text");
    let mut elf = base.clone();
    elf[off + len - 1] ^= 0x01;
    assert_eq!(c_of(&elf), c0, "unreachable code is not part of the program a run can observe");
    let (off, len) = section(&base, ".rodata");
    let mut elf = base.clone();
    elf[off + len - 2] ^= 0x01;
    assert_ne!(c_of(&elf), c0);
    let mut elf = base.clone();
    elf[12] ^= 0x5a;
    assert_eq!(c_of(&elf), c0);
}

#[test]
fn emitting_the_same_program_twice_is_byte_identical() {
    let mut e = spl_token();
    let p = sbpf_core::elf::load(&mut e).unwrap();
    let a = emit_program(&p, &scan(&p));
    let b = emit_program(&p, &scan(&p));
    assert_eq!(a.c, b.c);
    assert_eq!(
        (a.functions, a.blocks, a.instructions),
        (b.functions, b.blocks, b.instructions)
    );
    // The README's walkthrough counts.
    assert_eq!((a.functions, a.blocks, a.instructions), (30, 3546, 12061));
}

#[test]
fn write_crate_is_deterministic_and_ends_program_c_with_the_baked_program() {
    let mut e = small(7, &[], 0);
    let p = sbpf_core::elf::load(&mut e).unwrap();
    let c = emit_program(&p, &scan(&p)).c;
    let (a, b) = (work("crate-a"), work("crate-b"));
    write_crate(&a, "guard-test", &c, &p, false).unwrap();
    write_crate(&b, "guard-test", &c, &p, false).unwrap();
    for f in [
        "program.c",
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "src/main.rs",
        "shim.ld",
    ] {
        assert_eq!(
            std::fs::read(a.join(f)).unwrap(),
            std::fs::read(b.join(f)).unwrap(),
            "{f}"
        );
    }
    let pc = std::fs::read_to_string(a.join("program.c")).unwrap();
    assert!(pc.starts_with(&c));
    assert!(pc.ends_with(&baked_c(&p, false)));
    let toml = std::fs::read_to_string(a.join("Cargo.toml")).unwrap();
    assert!(toml.contains("name = \"guard-test\""));
    // Both crates sit four levels below the checkout root (sbpf2rv/target/guard/crate-a): the
    // relative paths say so.
    assert!(
        toml.contains("sbpf-core = { path = \"../../../../guests-compiled/sbpf-core\" }"),
        "{toml}"
    );
}

#[test]
fn the_cli_translates_the_same_elf_to_the_same_bytes_twice() {
    let elf = small(7, &[3; 8], 0);
    let src = work("cli-src").join("p.so");
    std::fs::write(&src, &elf).unwrap();
    let (a, b) = (work("cli-a"), work("cli-b"));
    for out in [&a, &b] {
        let o = Command::new(env!("CARGO_BIN_EXE_sbpf2rv"))
            .arg(&src)
            .arg("--out")
            .arg(out)
            .args(["--name", "twin"])
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    for f in [
        "program.c",
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "src/main.rs",
        "shim.ld",
    ] {
        assert_eq!(
            std::fs::read(a.join(f)).unwrap(),
            std::fs::read(b.join(f)).unwrap(),
            "{f}"
        );
    }
    let pc = std::fs::read_to_string(a.join("program.c")).unwrap();
    let mut e = elf.clone();
    let p = sbpf_core::elf::load(&mut e).unwrap();
    assert!(
        pc.ends_with(&baked_c(&p, false)),
        "program.c ends with the baked addresses and read-only data"
    );
}

#[test]
fn crate_name_normalises_a_file_stem() {
    assert_eq!(crate_name("spl_token"), "spl_token");
    assert_eq!(crate_name("Spl Token.v2"), "spl-token-v2");
    assert_eq!(crate_name("1abc"), "sbpf-1abc");
    assert_eq!(crate_name("-x"), "sbpf--x");
    assert_eq!(crate_name(""), "sbpf-");
    assert_eq!(crate_name("fine-name"), "fine-name");
}
