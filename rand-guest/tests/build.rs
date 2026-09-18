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
        // `build` writes the pin beside the image, in the committed pins' own form.
        let sum = std::fs::read_to_string(tmp.path().join(format!("{name}.bin.sha256"))).unwrap();
        assert_eq!(sum, format!("{}  {name}.bin\n", sha256_hex(&image)), "{name}.bin.sha256");
        let stdout = String::from_utf8_lossy(&o.stdout);
        assert!(stdout.contains("hc "), "{stdout}");
        assert!(stdout.contains("program id "), "{stdout}");
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

/// `build` reaches the checker's named report by the same path `check` takes: a guest whose text
/// the loader would refuse outright (a `fence`) is reported by rule, not as a bare load error, and
/// the build still fails.
#[test]
fn build_names_a_decode_class_rule_instead_of_a_load_error() {
    let Some(_) = rand_guest::build::find_clang() else { eprintln!("no RISC-V clang; skipping"); return; };
    let guest = tempfile::tempdir_in(root().join("guests-compiled")).unwrap();
    std::fs::write(
        guest.path().join("fence.c"),
        "#include \"guest.h\"\nvoid main(void) { __asm__ volatile(\"fence\"); rand_write_output(0, 1); rand_halt(); }\n",
    )
    .unwrap();
    let out = guest.path().join("fence.bin");
    let o = Command::new(bin()).args(["build", "--lang", "c"]).arg(guest.path()).arg("--out").arg(&out).output().unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(!o.status.success(), "{stdout}");
    assert!(stdout.contains("Fence: "), "{stdout}\n{}", String::from_utf8_lossy(&o.stderr));
    assert!(stdout.contains("REJECTED"), "{stdout}");
}

/// `build` never writes over a legacy flat pin: `guests-compiled/bin/fib.bin` and `keccak256.bin`
/// are headerless, `build` only writes the container form, and replacing either would break every
/// test (here and in fullnode) that loads it with `from_flat_binary`. The refusal names the file,
/// happens before any compiler runs, and leaves the file as it was.
#[test]
fn build_refuses_to_overwrite_a_legacy_flat_pin() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("fib.bin");
    std::fs::write(&out, pinned_bytes("fib")).unwrap();
    let o = Command::new(bin()).arg("build").arg(root().join("guests-compiled/fib")).arg("--out").arg(&out).output().unwrap();
    assert!(!o.status.success());
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains(&out.display().to_string()), "{stderr}");
    assert!(stderr.contains("legacy flat pin"), "{stderr}");
    assert_eq!(std::fs::read(&out).unwrap(), pinned_bytes("fib"), "the pin must be left as it was");
    assert!(!tmp.path().join("fib.bin.sha256").exists());
}

/// The C runtime (`rt.c`): clang lowers a struct copy to a `memcpy` call and a 64-bit division by
/// a runtime value to `__udivdi3`/`__umoddi3`/`__divdi3`/`__moddi3` even under
/// `-ffreestanding -fno-builtin`, and before `rt.c` existed such a guest could not link. This one
/// does both, builds, passes `check` at the default cap, and runs to the outputs computed here.
#[test]
fn a_c_guest_that_copies_a_struct_and_divides_a_u64_links_against_the_runtime() {
    let Some(clang) = rand_guest::build::find_clang() else { eprintln!("no RISC-V clang; skipping"); return; };
    let guest = tempfile::tempdir_in(root().join("guests-compiled")).unwrap();
    std::fs::write(
        guest.path().join("rt_user.c"),
        r#"#include "guest.h"
struct rec { uint32_t w[24]; };
/* Not inlined, so the 96-byte assignment stays a real `memcpy` call. */
__attribute__((noinline)) static void copy(struct rec *d, const struct rec *s) { *d = *s; }
/* One operation each and not inlined: beside a division, clang computes `n % d` as `n - q*d`,
 * which would leave the two remainder helpers untested. */
__attribute__((noinline)) static uint64_t udiv(uint64_t n, uint64_t d) { return n / d; }
__attribute__((noinline)) static uint64_t umod(uint64_t n, uint64_t d) { return n % d; }
__attribute__((noinline)) static int64_t sdiv(int64_t n, int64_t d) { return n / d; }
__attribute__((noinline)) static int64_t smod(int64_t n, int64_t d) { return n % d; }
void main(void) {
    struct rec a, b;
    uint32_t seed = rand_read_input(0);
    for (uint32_t i = 0; i < 24; i++) a.w[i] = seed * (i + 1);
    copy(&b, &a);
    uint32_t sum = 0;
    for (uint32_t i = 0; i < 24; i++) sum += b.w[i];
    uint64_t n = ((uint64_t)rand_read_input(1) << 32) | rand_read_input(2);
    uint64_t d = rand_read_input(3);
    uint64_t q = udiv(n, d), r = umod(n, d);
    int64_t sn = -(int64_t)n, sd = (int64_t)d;
    int64_t sq = sdiv(sn, sd), sr = smod(sn, sd);
    rand_write_output(0, sum);
    rand_write_output(1, b.w[23]);
    rand_write_output(2, (uint32_t)q);
    rand_write_output(3, (uint32_t)(q >> 32));
    rand_write_output(4, (uint32_t)r);
    rand_write_output(5, (uint32_t)(r >> 32));
    rand_write_output(6, (uint32_t)sq);
    rand_write_output(7, (uint32_t)sr);
    rand_halt();
}
"#,
    )
    .unwrap();
    let out = guest.path().join("rt_user.bin");
    let o = Command::new(bin()).args(["build", "--lang", "c"]).arg(guest.path()).arg("--out").arg(&out).output().unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{stdout}\n{}", String::from_utf8_lossy(&o.stderr));
    assert!(stdout.contains("OK"), "{stdout}");

    // The guest's own object really does call into the runtime (so this test exercises it), and
    // the runtime's object calls nothing — checked where an `llvm-nm` sits beside the clang.
    let nm = clang.with_file_name("llvm-nm");
    if let Ok(o) = Command::new(&nm).arg(guest.path().join("target/rand-guest/rt_user.o")).output() {
        let syms = String::from_utf8_lossy(&o.stdout);
        for f in ["memcpy", "__udivdi3", "__umoddi3", "__divdi3", "__moddi3"] {
            assert!(syms.contains(&format!("U {f}\n")), "rt_user.o does not call {f}: {syms}");
        }
        let rt = Command::new(&nm).arg("--undefined-only").arg(guest.path().join("target/rand-guest/_rand_guest_rt.o")).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&rt.stdout), "", "rt.c must call nothing");
    }

    let (seed, hi, lo, d) = (7u32, 0x1234_5678u32, 0x9abc_def0u32, 1_000_003u32);
    let n = ((hi as u64) << 32) | lo as u64;
    let (q, r) = (n / d as u64, n % d as u64);
    let (sq, sr) = (-(n as i64) / d as i64, -(n as i64) % d as i64);
    let want: [u32; 8] = [(1..=24).map(|i| seed * i).sum(), seed * 24, q as u32, (q >> 32) as u32, r as u32, (r >> 32) as u32, sq as u32, sr as u32];
    let run = Command::new(bin()).arg("run").arg(&out).arg("--input").args([seed, hi, lo, d].map(|w| w.to_string())).output().unwrap();
    let s = String::from_utf8_lossy(&run.stdout);
    assert!(run.status.success(), "{s}");
    for (i, w) in want.iter().enumerate() {
        assert!(s.contains(&format!("out[{i}] = {w}\n")), "out[{i}] should be {w}: {s}");
    }
}

/// `info` prints the chain's program id — fullnode's `randprotocol_core::program::program_id`, a
/// blake3 content address, not `hc` — for the loader's `(base_pc, words)`. The value is the one
/// fullnode's own function computes for the committed `evm.bin` (cross-checked once by calling
/// `randprotocol_core::program::program_id` on `Program::from_flat_image(evm.bin)` from a scratch
/// crate depending on both); fullnode has no fixed test vector for it to compare against.
#[test]
fn info_prints_the_program_id_fullnode_computes() {
    const EVM_PROGRAM_ID: &str = "9969434294cec7a4aa6c6cfc305dfbe2e9e96b5375c9436ccb3ac0c72c44762b";
    let o = Command::new(bin()).arg("info").arg(root().join("guests-compiled/bin/evm.bin")).output().unwrap();
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.contains(&format!("program id {EVM_PROGRAM_ID}\n")), "{s}");
    let p = Program::from_flat_image(&pinned_bytes("evm")).unwrap();
    assert_eq!(hex::encode(rand_guest::chain::program_id(p.base_pc, &p.words)), EVM_PROGRAM_ID);
    // A flat pin's id is over its `0x1000` base and its words, like any other program's.
    let fib = Program::from_flat_binary(0x1000, &pinned_bytes("fib")).unwrap();
    assert_eq!(hex::encode(rand_guest::chain::program_id(fib.base_pc, &fib.words)), "9d5a6507fb7f8dd6c77e4b542f3bcb3d9b68d2e79b87eb9ec5f1740fac776e26");
}
