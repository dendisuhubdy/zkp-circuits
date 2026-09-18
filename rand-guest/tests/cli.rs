//! The checker's decode-class rules reach the named report through the CLI, not only through
//! `check_text`: the loader refuses any word `Instr::decode` rejects, so a `check` that asked the
//! loader first would print a bare `LoadError::Decode` instead of the rule. One rejection per rule,
//! each through a hand-built image container, a hand-built headerless flat binary and a hand-built
//! ELF — no compiler needed.

use rand_zkvm::isa::{AluOp, Instr, Program};
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rand-guest"))
}

/// `word` followed by `li a7, 0 ; ecall` (HALT), so everything but the offending word is clean.
fn text_with(word: u32) -> Vec<u32> {
    vec![word, Instr::AluImm { op: AluOp::Add, rd: 17, rs1: 0, imm: 0 }.encode(), Instr::Ecall.encode()]
}

fn bytes_of(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// A minimal ELF32-LE holding one `.text` (PROGBITS, ALLOC) at `0x1000`: the 52-byte header, two
/// section entries (the string table, `.text`) and the two sections — `tests/pack.rs`'s builder
/// shape, with a real text this time.
fn elf_with_text(text: &[u32]) -> Vec<u8> {
    let strtab = b"\0.text\0\0"; // padded to 8 so `.text` starts word-aligned in the file
    let shoff = 52u32;
    let strtab_off = shoff + 2 * 24;
    let text_off = strtab_off + strtab.len() as u32;
    let mut elf = vec![0u8; 52];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 1; // ELFCLASS32
    elf[5] = 1; // ELFDATA2LSB
    elf[0x20..0x24].copy_from_slice(&shoff.to_le_bytes());
    elf[0x2e..0x30].copy_from_slice(&24u16.to_le_bytes());
    elf[0x30..0x32].copy_from_slice(&2u16.to_le_bytes());
    elf[0x32..0x34].copy_from_slice(&0u16.to_le_bytes());
    let entry = |name: u32, typ: u32, flags: u32, addr: u32, off: u32, size: u32| -> Vec<u8> {
        [name, typ, flags, addr, off, size].iter().flat_map(|w| w.to_le_bytes()).collect()
    };
    elf.extend(entry(0, 3, 0, 0, strtab_off, strtab.len() as u32)); // the string table
    elf.extend(entry(1, 1, 0x2, 0x1000, text_off, 4 * text.len() as u32)); // .text
    elf.extend_from_slice(strtab);
    elf.extend(bytes_of(text));
    elf
}

fn check(path: &Path) -> (Option<i32>, String) {
    let o = Command::new(bin()).arg("check").arg(path).output().unwrap();
    (o.status.code(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

const CASES: [(u32, &str); 4] = [
    (0x0ff0_000f, "Fence"),      // fence iorw, iorw
    (0xc000_2573, "Csr"),        // csrrs a0, cycle, x0 (rdcycle a0)
    (0x0010_0073, "Ebreak"),     // ebreak
    (0x0000_4501, "Compressed"), // c.li a0, 0 in the low half: the low two bits are not 0b11
];

#[test]
fn every_decode_class_rule_is_named_through_an_image_a_flat_binary_and_an_elf() {
    let tmp = tempfile::tempdir().unwrap();
    for (word, rule) in CASES {
        let text = text_with(word);
        // The loader really does refuse each of these outright — the case this test exists for.
        assert!(Program::from_flat_binary(0x1000, &bytes_of(&text)).is_err(), "{rule}");
        let forms = [
            ("image", Program::to_flat_image(0x1000, &text, 0, &[])),
            ("flat", bytes_of(&text)),
            ("elf", elf_with_text(&text)),
        ];
        for (form, bytes) in forms {
            let path = tmp.path().join(format!("{rule}.{form}"));
            std::fs::write(&path, bytes).unwrap();
            let (code, out) = check(&path);
            assert_eq!(code, Some(1), "{rule} via {form}: {out}");
            assert!(out.contains(&format!("{word:#010x}  {rule}: ")), "{rule} via {form}: {out}");
            assert!(out.contains("REJECTED"), "{rule} via {form}: {out}");
            assert!(!out.contains("Error"), "{rule} via {form} fell through to a raw error: {out}");
            // The prologue is the loader's to count, and the loader refused: the report says so.
            assert!(out.contains("could not be counted"), "{rule} via {form}: {out}");
        }
    }
}

#[test]
fn a_clean_hand_built_image_and_elf_still_pass() {
    let tmp = tempfile::tempdir().unwrap();
    let text = text_with(Instr::AluImm { op: AluOp::Add, rd: 10, rs1: 0, imm: 1 }.encode());
    for (form, bytes) in [("image", Program::to_flat_image(0x1000, &text, 0, &[])), ("elf", elf_with_text(&text))] {
        let path = tmp.path().join(format!("clean.{form}"));
        std::fs::write(&path, bytes).unwrap();
        let (code, out) = check(&path);
        assert_eq!(code, Some(0), "{form}: {out}");
        assert!(out.ends_with("OK\n"), "{form}: {out}");
        assert!(!out.contains("could not be counted"), "{form}: {out}");
    }
}

/// Every io and load failure names the file and the step: no bare "No such file or directory",
/// no bare `Length(8)`.
#[test]
fn io_and_load_errors_name_the_file_and_the_step() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("missing.bin");
    for cmd in ["check", "info", "run", "pack"] {
        let o = Command::new(bin()).arg(cmd).arg(&missing).output().unwrap();
        let e = String::from_utf8_lossy(&o.stderr);
        assert!(!o.status.success() && e.contains(&format!("reading {}", missing.display())), "{cmd}: {e}");
    }
    // A truncated container — the magic and nothing else — is `LoadError::Length(4)`.
    let short = tmp.path().join("short.bin");
    std::fs::write(&short, rand_zkvm::isa::IMAGE_MAGIC.to_le_bytes()).unwrap();
    for cmd in ["info", "run"] {
        let o = Command::new(bin()).arg(cmd).arg(&short).output().unwrap();
        let e = String::from_utf8_lossy(&o.stderr);
        assert!(!o.status.success() && e.contains(&format!("loading {}", short.display())), "{cmd}: {e}");
    }
    let o = Command::new(bin()).arg("check").arg(&short).output().unwrap();
    let e = String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success() && e.contains(&format!("checking {}", short.display())), "check: {e}");
}

/// `$CLANG` set to something that is not a RISC-V clang is an error naming it, not a silent fall
/// back to whichever clang the search would have found next.
#[test]
fn a_clang_that_fails_the_probe_is_named_not_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("main.c"), "void main(void) {}\n").unwrap();
    let o = Command::new(bin())
        .env("CLANG", "/nonexistent/clang")
        .args(["build", "--lang", "c"])
        .arg(tmp.path())
        .arg("--out")
        .arg(tmp.path().join("out.bin"))
        .output()
        .unwrap();
    let e = String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success() && e.contains("$CLANG is /nonexistent/clang"), "{e}");
}

/// `pack --out ..` names no file; it must be refused, not panic on `file_name()`.
#[test]
fn pack_to_a_path_with_no_file_name_is_refused_not_panicked() {
    let tmp = tempfile::tempdir().unwrap();
    let elf = tmp.path().join("g.elf");
    std::fs::write(&elf, elf_with_text(&text_with(Instr::Ecall.encode()))).unwrap();
    let o = Command::new(bin()).arg("pack").arg(&elf).args(["--out", ".."]).current_dir(tmp.path()).output().unwrap();
    let e = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(1), "{e}");
    assert!(e.contains("names no file"), "{e}");
}
