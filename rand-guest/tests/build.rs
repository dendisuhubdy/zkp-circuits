//! `rand-guest build` over the four committed guests gives their committed images, and `check`
//! and `info` agree with `build` on what one of them is.
//!
//! The build needs the pinned toolchain with the guest target and llvm-tools installed
//! (`rustup +1.98.1 target add riscv32im-unknown-none-elf`), as `tests/pack.rs` does.

use rand_zkvm::isa::Program;
use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rand-guest"))
}

fn pinned(name: &str) -> String {
    let text = std::fs::read_to_string(root().join("guests-compiled/bin").join(format!("{name}.bin.sha256"))).unwrap();
    text.split_whitespace().next().unwrap().to_string()
}

fn pinned_bytes(name: &str) -> Vec<u8> {
    std::fs::read(root().join("guests-compiled/bin").join(format!("{name}.bin"))).unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

#[test]
fn build_reproduces_every_committed_image_and_reports_hc() {
    let tmp = tempfile::tempdir().unwrap();
    // Two gates, for the two shapes the four pins have, exactly as `tests/pack.rs` gates the
    // packer: `evm` and `sbpf` are image containers and are gated byte for byte; `fib` and
    // `keccak256` are pinned as headerless flat binaries (`objcopy -O binary`, loaded by
    // `Program::from_flat_binary(0x1000, …)`), so the image `build` writes for them is gated at
    // the program level instead — same `base_pc`, same `words`, same `digest()`.
    for name in ["fib", "keccak256", "evm", "sbpf"] {
        let out = tmp.path().join(format!("{name}.bin"));
        // 65535, not the default 4096: the two interpreters are far over the deploy cap and
        // `build` exits non-zero on a rejected image. The cap itself is what `info` below checks.
        let o = Command::new(bin())
            .arg("build")
            .arg(root().join("guests-compiled").join(name))
            .arg("--out")
            .arg(&out)
            .args(["--max-words", "65535"])
            .output()
            .unwrap();
        assert!(o.status.success(), "{name}: {}", String::from_utf8_lossy(&o.stderr));
        let image = std::fs::read(&out).unwrap();
        if name == "fib" || name == "keccak256" {
            let from_image = Program::from_flat_image(&image).unwrap();
            let from_flat = Program::from_flat_binary(0x1000, &pinned_bytes(name)).unwrap();
            assert_eq!(from_image.base_pc, from_flat.base_pc, "{name}: base_pc");
            assert_eq!(from_image.words, from_flat.words, "{name}: words");
            assert_eq!(from_image.digest(), from_flat.digest(), "{name}: digest");
        } else {
            assert_eq!(sha256_hex(&image), pinned(name), "{name}.bin");
        }
        let stdout = String::from_utf8_lossy(&o.stdout);
        assert!(stdout.contains("hc "), "{stdout}");
        assert!(stdout.contains("words"), "{stdout}");
    }
    pack_and_check_the_elf_build_left(tmp.path());
}

#[test]
fn info_and_check_agree_with_build_on_the_evm_image() {
    let image = root().join("guests-compiled/bin/evm.bin");
    let info = Command::new(bin()).arg("info").arg(&image).output().unwrap();
    assert!(info.status.success(), "{}", String::from_utf8_lossy(&info.stderr));
    let s = String::from_utf8_lossy(&info.stdout);
    // `docs/04-guests.md` measures the committed interpreter at 18 009 program words: the 16 370
    // text words plus the 1 639-word prologue the loader synthesises. The three numbers add up
    // because the prologue is the loader's own, counted rather than estimated from the 589
    // non-zero data words (a two-word estimate would say 1 178 and be 461 words short).
    assert!(s.contains("text 16370 words"), "{s}");
    assert!(s.contains("prologue 1639 words"), "{s}");
    assert!(s.contains("program 18009 words"), "{s}");
    assert!(s.contains("does not fit"), "the interpreter is over the 4096 cap: {s}");
    let check = Command::new(bin()).arg("check").arg(&image).args(["--max-words", "65535"]).output().unwrap();
    assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stdout));
}

#[test]
fn info_and_check_accept_the_headerless_flat_binary_pins() {
    // `fib.bin`/`keccak256.bin` predate this tool and carry no `IMAGE_MAGIC` header
    // (`build_reproduces_every_committed_image_and_reports_hc`'s comment above); `info` and
    // `check` must fall back to `Program::from_flat_binary` for them, same as `run` does, rather
    // than failing on the container reader's `Magic` error.
    let image = root().join("guests-compiled/bin/fib.bin");
    let info = Command::new(bin()).arg("info").arg(&image).output().unwrap();
    assert!(info.status.success(), "{}", String::from_utf8_lossy(&info.stderr));
    let s = String::from_utf8_lossy(&info.stdout);
    assert!(s.contains("flat binary"), "{s}");
    assert!(s.contains("26 words"), "{s}");
    let check = Command::new(bin()).arg("check").arg(&image).output().unwrap();
    assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stdout));
    assert!(String::from_utf8_lossy(&check.stdout).contains("OK"), "{}", String::from_utf8_lossy(&check.stdout));
}

/// `pack` and `check` on the ELF `build` left behind, in the same test so the ELF is known to be
/// there (cargo runs the test functions in parallel, so this cannot be a test of its own).
fn pack_and_check_the_elf_build_left(tmp: &std::path::Path) {
    let elf = root().join("guests-compiled/evm/target/riscv32im-unknown-none-elf/release/evm-guest");
    let out = tmp.join("packed.bin");
    let o = Command::new(bin()).arg("pack").arg(&elf).arg("--out").arg(&out).output().unwrap();
    assert!(o.status.success(), "pack: {}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(sha256_hex(&std::fs::read(&out).unwrap()), pinned("evm"), "pack");
    let sum = std::fs::read_to_string(tmp.join("packed.bin.sha256")).unwrap();
    assert_eq!(sum, format!("{}  packed.bin\n", pinned("evm")));

    // `check` takes an ELF as happily as an image, packing it on the way.
    let c = Command::new(bin()).arg("check").arg(&elf).args(["--max-words", "65535"]).output().unwrap();
    assert!(c.status.success(), "check on an ELF: {}", String::from_utf8_lossy(&c.stdout));
    assert!(String::from_utf8_lossy(&c.stdout).contains("OK"));

    // The default cap rejects it, with the exit code that says so.
    let c = Command::new(bin()).arg("check").arg(&out).output().unwrap();
    assert!(!c.status.success(), "the interpreter is over the default cap: {}", String::from_utf8_lossy(&c.stdout));
}

#[test]
fn a_guest_named_by_a_relative_path_builds_the_same_image() {
    // The linker script and the remap prefix are resolved against the *guest* directory, not the
    // caller's cwd: cargo runs there, so a path relative to ours would name nothing (or, worse,
    // something else) once cargo has changed directory.
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("evm.bin");
    let o = Command::new(bin())
        .current_dir(root())
        .args(["build", "guests-compiled/evm", "--max-words", "65535"])
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(sha256_hex(&std::fs::read(&out).unwrap()), pinned("evm"));
}

#[test]
fn the_cap_is_measured_against_the_loaders_word_count_not_an_estimate() {
    // 18 009 is what `Program::from_flat_image` makes of `evm.bin`, so the cap must bite at
    // exactly one word below it — not at the 17 548 an estimated two-word-per-data-word prologue
    // would give, which would let an over-cap image through.
    let image = root().join("guests-compiled/bin/evm.bin");
    let over = Command::new(bin()).arg("check").arg(&image).args(["--max-words", "18008"]).output().unwrap();
    assert!(!over.status.success(), "{}", String::from_utf8_lossy(&over.stdout));
    assert!(String::from_utf8_lossy(&over.stdout).contains("18009 words (text 16370 + prologue 1639)"), "{}", String::from_utf8_lossy(&over.stdout));
    let exact = Command::new(bin()).arg("check").arg(&image).args(["--max-words", "18009"]).output().unwrap();
    assert!(exact.status.success(), "{}", String::from_utf8_lossy(&exact.stdout));
}

/// The C path end to end: clang compiles `guests-compiled/c-fib` for the same machine the Rust
/// guests target, and the image runs to the same `fib(20)` the Rust `fib` guest gives. Gated on a
/// clang that has a `riscv32` target (`build::find_clang`), since Apple's system clang has none.
#[test]
fn a_c_guest_builds_checks_and_runs_like_the_rust_one() {
    let Some(_) = rand_guest::build::find_clang() else { eprintln!("no RISC-V clang; skipping"); return; };
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("c-fib.bin");
    let o = Command::new(bin()).args(["build", "--lang", "c"]).arg(root().join("guests-compiled/c-fib")).arg("--out").arg(&out).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let r = Command::new(bin()).args(["run"]).arg(&out).args(["--input", "20"]).output().unwrap();
    let s = String::from_utf8_lossy(&r.stdout);
    assert!(s.contains("out[0] = 6765"), "{s}");
}

/// A guest directory that carries its own `guest.h` would silently shadow the toolchain's copy
/// (`#include "guest.h"` resolves via `-I`, and a local file wins); `build --lang c` must refuse
/// it instead, naming the offending file. No clang needed: the guard runs before `find_clang`.
#[test]
fn a_guest_with_its_own_guest_h_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("fib.c"), "#include \"guest.h\"\nvoid main(void) { rand_halt(); }\n").unwrap();
    std::fs::write(tmp.path().join("guest.h"), "// a stray copy that would shadow the toolchain's\n").unwrap();
    let out = tmp.path().join("out.bin");
    let o = Command::new(bin()).args(["build", "--lang", "c"]).arg(tmp.path()).arg("--out").arg(&out).output().unwrap();
    assert!(!o.status.success());
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("guest.h"), "{stderr}");
}
