//! ZKVM-106: a guest rejects with `refuse()`, never with a panic.
//!
//! A panic ends in the SDK's handler, which writes `out[7] = 0xdeadbeef` and **halts**, and a halted
//! run proves. These tests hold the toolchain to the three things that follow:
//!
//! - `guest_sdk::refuse` / `require!` (and `guest.h`'s `rand_refuse` / `RAND_REQUIRE`) end the run
//!   in a trap, `run` says so, and the prover returns an error instead of a proof;
//! - `build` and `check` reject a linked guest that still carries the panic machinery, naming the
//!   symbols, unless `--allow-panic` is passed;
//! - a guest that does panic is shown for what it is: `run` exits 0 with the sentinel and a warning.
//!
//! The Rust guests need the pinned toolchain with the guest target (as `tests/build.rs`); the C one
//! needs the pinned clang and is skipped without it.

use rand_guest::check::{is_panic_symbol, panic_findings, Rule};
use rand_zkvm::emulator::ExecError;
use rand_zkvm::isa::Program;
use rand_zkvm::machine::{FriProfile, Machine, ProveError};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rand-guest"))
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

/// `guests-compiled/fib`'s crate (manifest, lock file, release profile) with `main.rs` replaced,
/// beside it so its relative `guest-sdk` path holds.
fn rust_guest(main_rs: &str) -> tempfile::TempDir {
    let guest = tempfile::tempdir_in(root().join("guests-compiled")).unwrap();
    let src = root().join("guests-compiled/fib");
    std::fs::create_dir_all(guest.path().join("src")).unwrap();
    for f in ["Cargo.toml", "Cargo.lock"] {
        std::fs::copy(src.join(f), guest.path().join(f)).unwrap();
    }
    std::fs::write(guest.path().join("src/main.rs"), main_rs).unwrap();
    guest
}

fn build(guest: &Path, extra: &[&str]) -> Output {
    Command::new(bin()).arg("build").arg(guest).arg("--out").arg(guest.join("image.bin")).args(extra).output().unwrap()
}

fn run(image: &Path, input: u32) -> Output {
    Command::new(bin()).arg("run").arg(image).args(["--input", &input.to_string()]).output().unwrap()
}

/// The ELF `build` linked for a guest made by [`rust_guest`] (cargo names it after the package).
fn elf(guest: &Path) -> PathBuf {
    guest.join("target/riscv32im-unknown-none-elf/release/fib-guest")
}

/// Doubles its input, and rejects anything over 20 the right way.
const REQUIRE_GUEST: &str = r#"#![no_std]
#![no_main]
use guest_sdk::{halt, read_input, require, write_output};

#[no_mangle]
pub extern "C" fn main() -> ! {
    let n = read_input(0);
    require!(n <= 20);
    write_output(0, 2 * n);
    halt();
}
"#;

/// The same guest with the check written as an `assert!` — the mistake ZKVM-106 is about.
const ASSERT_GUEST: &str = r#"#![no_std]
#![no_main]
use guest_sdk::{halt, read_input, write_output};

#[no_mangle]
pub extern "C" fn main() -> ! {
    let n = read_input(0);
    assert!(n <= 20);
    write_output(0, 2 * n);
    halt();
}
"#;

#[test]
fn a_refusing_guest_builds_clean_traps_and_cannot_be_proved() {
    let guest = rust_guest(REQUIRE_GUEST);
    let o = build(guest.path(), &[]);
    assert!(o.status.success(), "a guest that rejects with require! links no panic machinery: {}", text(&o));
    assert!(!text(&o).contains("Panic: "), "{}", text(&o));
    let image = guest.path().join("image.bin");

    // The statement holds: an ordinary run.
    let ok = run(&image, 20);
    assert!(ok.status.success(), "{}", text(&ok));
    assert!(text(&ok).contains("out[0] = 40"), "{}", text(&ok));

    // The statement does not: a trap, reported as a refusal, exit code 2.
    let no = run(&image, 21);
    assert_eq!(no.status.code(), Some(2), "{}", text(&no));
    let s = text(&no);
    assert!(s.contains("refused: the guest called refuse()"), "{s}");
    assert!(s.contains("trap: InputIndex(4294967295)"), "{s}");
    assert!(!s.contains("out[0]"), "a refused run publishes nothing: {s}");

    // And the prover has nothing to prove: the error, not a proof.
    let program = Program::from_flat_image(&std::fs::read(&image).unwrap()).unwrap();
    let m = Machine::new(FriProfile::Test);
    match m.prove(&program, &[21], &[], None) {
        Err(ProveError::Exec(ExecError::InputIndex(u32::MAX))) => {}
        Err(e) => panic!("refused for another reason: {e:?}"),
        Ok(_) => panic!("a refused run was proved"),
    }
    // Private inputs past the one the guest reads do not rescue it either: `refuse` reads an index
    // no input vector reaches.
    assert!(matches!(m.prove(&program, &[21, 0, 0, 0], &[], None), Err(ProveError::Exec(ExecError::InputIndex(u32::MAX)))));
}

#[test]
fn a_panicking_guest_is_rejected_by_build_and_check_with_the_symbol_named() {
    let guest = rust_guest(ASSERT_GUEST);
    let o = build(guest.path(), &[]);
    let s = text(&o);
    assert!(!o.status.success(), "a guest with an assert! must not build by default: {s}");
    assert!(s.contains("Panic: "), "{s}");
    assert!(s.contains("rust_begin_unwind"), "the panic handler is named: {s}");
    assert!(s.contains("REJECTED"), "{s}");

    // `check` on the linked ELF says the same, and exits 1.
    let c = Command::new(bin()).arg("check").arg(elf(guest.path())).output().unwrap();
    assert_eq!(c.status.code(), Some(1), "{}", text(&c));
    assert!(text(&c).contains("Panic: ") && text(&c).contains("rust_begin_unwind"), "{}", text(&c));
    let findings = panic_findings(&std::fs::read(elf(guest.path())).unwrap()).unwrap();
    assert!(!findings.is_empty() && findings.iter().all(|f| f.rule == Rule::Panic), "{findings:?}");

    // The waiver builds it, and `check --allow-panic` passes the same ELF.
    let o = build(guest.path(), &["--allow-panic"]);
    assert!(o.status.success(), "{}", text(&o));
    let c = Command::new(bin()).arg("check").arg(elf(guest.path())).arg("--allow-panic").output().unwrap();
    assert!(c.status.success(), "{}", text(&c));

    // What the rule is for: the failed assert *halts*. `run` exits 0, the sentinel is in slot 7,
    // and the run would prove — `run` warns, since nothing else would.
    let image = guest.path().join("image.bin");
    let bad = run(&image, 21);
    assert!(bad.status.success(), "a panic halts: {}", text(&bad));
    let s = text(&bad);
    assert!(s.contains(&format!("out[7] = {}", 0xdead_beefu32)), "{s}");
    assert!(s.contains("warning: out[7] is the SDK panic handler's sentinel"), "{s}");
    let program = Program::from_flat_image(&std::fs::read(&image).unwrap()).unwrap();
    let exec = rand_zkvm::emulator::execute(&program, &[21], &[], 1 << 16).unwrap();
    assert!(exec.halted && exec.outputs[7] == 0xdead_beef && exec.outputs[0] == 0);
    // A run that does not panic carries no warning.
    let good = run(&image, 20);
    assert!(good.status.success() && !text(&good).contains("warning"), "{}", text(&good));

    // An image has no symbols, so `check` on one cannot apply the rule (and does not pretend to).
    let c = Command::new(bin()).arg("check").arg(&image).output().unwrap();
    assert!(c.status.success(), "{}", text(&c));
}

/// Which of the published guests link the panic machinery today. `fib` does not; the other five
/// do (bounds checks and the like in the interpreters, the sponge loops and the Dilithium code).
/// Their images are published and are not rebuilt here, so this is a record, not a fix: a consumer
/// of their proofs must treat `out[7] == 0xdeadbeef` as a rejection (the fullnode's PST-1 rule).
/// When one of them is ported to `refuse()`, move it to the clean list.
#[test]
fn the_published_guests_that_link_the_panic_machinery_are_these() {
    for (name, links_panic) in [("fib", false), ("keccak256", true), ("evm", true), ("sbpf", true), ("dilithium-verify", true), ("msauth", true)] {
        let tmp = tempfile::tempdir().unwrap();
        let o = Command::new(bin())
            .arg("build")
            .arg(root().join("guests-compiled").join(name))
            .arg("--out")
            .arg(tmp.path().join("image.bin"))
            .args(["--max-words", "65535"])
            .output()
            .unwrap();
        let s = text(&o);
        assert_eq!(!o.status.success(), links_panic, "{name}: {s}");
        assert_eq!(s.contains("Panic: "), links_panic, "{name}: {s}");
        if links_panic {
            assert!(s.contains("rust_begin_unwind"), "{name}: {s}");
        }
    }
}

#[test]
fn the_panic_rule_matches_the_machinery_and_not_a_name_that_merely_says_panic() {
    for s in ["_RNvCs1njKG4L9aB3_7___rustc17rust_begin_unwind", "rust_begin_unwind", "_RNvNtCs2XHhjFcCVfB_4core9panicking9panic_fmt", "_ZN4core9panicking18panic_bounds_check17h0123456789abcdefE", "_RNvNtNtCs2XHhjFcCVfB_4core9panicking11panic_const23panic_const_div_by_zero"] {
        assert!(is_panic_symbol(s), "{s}");
    }
    for s in ["sol_panic_", "main", "_start", "memcpy", "my_panic_free_helper", "_RNvCsabc_3fib4main"] {
        assert!(!is_panic_symbol(s), "{s}");
    }
}

#[test]
fn an_elf_without_a_symbol_table_is_a_finding_and_a_corrupt_one_an_error() {
    // The smallest ELF32-LE header with no sections: nothing to judge, which is not a pass.
    let mut elf = vec![0u8; 0x34];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 1;
    elf[5] = 1;
    let f = panic_findings(&elf).unwrap();
    assert_eq!(f.len(), 1);
    assert!(f[0].rule == Rule::Panic && f[0].what.contains("no symbol table"), "{f:?}");
    // One section header, a symbol table whose string table index is out of range.
    let mut bad = elf.clone();
    bad[0x20..0x24].copy_from_slice(&0x34u32.to_le_bytes()); // e_shoff
    bad[0x2e..0x30].copy_from_slice(&40u16.to_le_bytes()); // e_shentsize
    bad[0x30..0x32].copy_from_slice(&1u16.to_le_bytes()); // e_shnum
    let mut sh = [0u8; 40];
    sh[4..8].copy_from_slice(&2u32.to_le_bytes()); // SHT_SYMTAB
    sh[24..28].copy_from_slice(&9u32.to_le_bytes()); // sh_link
    sh[36..40].copy_from_slice(&16u32.to_le_bytes()); // sh_entsize
    bad.extend_from_slice(&sh);
    assert!(panic_findings(&bad).is_err());
    // A header that points past the end of the file.
    let mut cut = elf.clone();
    cut[0x20..0x24].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
    cut[0x2e..0x30].copy_from_slice(&40u16.to_le_bytes());
    cut[0x30..0x32].copy_from_slice(&3u16.to_le_bytes());
    assert!(panic_findings(&cut).is_err());
    assert!(panic_findings(b"not an elf").is_err());
}

/// The C twin: `RAND_REQUIRE` / `rand_refuse` from `guest.h`.
#[test]
fn a_c_guest_refuses_with_rand_refuse() {
    let Ok(_) = rand_guest::build::find_clang() else { eprintln!("no RISC-V clang; skipping"); return; };
    let guest = tempfile::tempdir_in(root().join("guests-compiled")).unwrap();
    std::fs::write(
        guest.path().join("main.c"),
        "#include \"guest.h\"\nvoid main(void) {\n    uint32_t n = rand_read_input(0);\n    RAND_REQUIRE(n <= 20);\n    if (n == 7) {\n        rand_refuse();\n    }\n    rand_write_output(0, 2 * n);\n    rand_halt();\n}\n",
    )
    .unwrap();
    let image = guest.path().join("image.bin");
    let o = Command::new(bin()).args(["build", "--lang", "c"]).arg(guest.path()).arg("--out").arg(&image).output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&run(&image, 20)).contains("out[0] = 40"));
    for bad in [21, 7] {
        let no = run(&image, bad);
        assert_eq!(no.status.code(), Some(2), "{}", text(&no));
        assert!(text(&no).contains("refused: the guest called refuse()"), "{}", text(&no));
    }
}
