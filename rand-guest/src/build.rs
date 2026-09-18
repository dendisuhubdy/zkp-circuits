//! Driving rustc (and, in Task 6, clang) for the guest target, then pack. The flags are the
//! former four Makefiles' (`guests-compiled/README.md`), generated here so no guest carries
//! them.

use crate::pack;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const TARGET: &str = "riscv32im-unknown-none-elf";
pub const TOOLCHAIN: &str = "1.98.1";

pub struct BuildOutput {
    pub elf: PathBuf,
    pub image: PathBuf,
    pub hc: [u32; 8],
    pub words: usize,
}

/// The rustflags list every guest gets. `root` is the checkout root (for the path remap), `ld`
/// the linker script.
///
///  * `-T<ld>`          the guest's linker script.
///  * `target-feature`  a misaligned load/store is a constraint violation in this machine
///                      (`research/docs/01-isa.md`), so the compiler must never assume otherwise.
///  * `remap-path-prefix` makes the panic `Location` strings LLVM puts in `.rodata` — which the
///                      image container carries into the guest's RAM, so `hc` binds them —
///                      independent of where this checkout lives, so an image reproduces byte for
///                      byte on any machine.
///
/// This is the only place the set is written down: cargo *merges* `--config` rustflags with a
/// `.cargo/config.toml`'s rather than overriding them, so a guest that also carried them would
/// link with a duplicate `-T`. The guests carry none.
///
/// Note what is *not* here (moved verbatim from the former `guests-compiled/evm/Makefile`):
/// nothing suppresses the opcode dispatch's jump tables. Before the image container existed they
/// had to be suppressed (`-C llvm-args=-max-jump-table-size=1`), because a jump table in an
/// unloadable `.rodata` means a jump to `pc 0`. With the container carrying them they are simply
/// faster, measured both ways on the ERC-20 transfer: 121 763 executed cycles and 17 983 program
/// words with the tables (126 491 all in, counting the digest prefixes) against 123 659 and
/// 17 065 with the compare-and-branch chain (128 158 all in) — the tables cost ~900 more program
/// words and save ~1 900 execution cycles. (Both figures are from the same build pair, which
/// predates two later `storage.rs` changes — a tidy-up and the duplicate-leaf-index check; the
/// committed image measures 121 638 executed cycles over 18 009 program words,
/// `docs/04-guests.md`.)
pub fn flags(root: &Path, ld: &Path) -> Vec<String> {
    vec![
        "-C".into(),
        format!("link-arg=-T{}", ld.display()),
        "-C".into(),
        "target-feature=-unaligned-scalar-mem".into(),
        format!("--remap-path-prefix={}=/rand-circuits", root.display()),
    ]
}

/// The `--config` argument carrying [`flags`]: a TOML array of strings, the shape the former
/// per-guest Makefiles' `RUSTFLAGS_LIST` had. Rust's `{:?}` is TOML's basic-string syntax for
/// these flags (they hold no backslashes or control characters).
pub fn cargo_config(root: &Path, ld: &Path) -> String {
    let quoted: Vec<String> = flags(root, ld).into_iter().map(|f| format!("{f:?}")).collect();
    format!("target.{TARGET}.rustflags=[{}]", quoted.join(","))
}

/// A guest's linker script: the one `.ld` in its directory, else `guest-sdk/guest.ld`.
pub fn find_ld(dir: &Path, root: &Path) -> Result<PathBuf> {
    let mut lds: Vec<_> = std::fs::read_dir(dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |e| e == "ld"))
        .collect();
    match lds.len() {
        0 => Ok(root.join("guest-sdk/guest.ld")),
        1 => Ok(lds.remove(0)),
        n => bail!("{n} linker scripts in {}; pass --ld", dir.display()),
    }
}

/// The directory holding `guest-sdk/`: walk up from the guest.
pub fn checkout_root(dir: &Path) -> Result<PathBuf> {
    let mut p = dir.canonicalize()?;
    loop {
        if p.join("guest-sdk/guest.ld").exists() {
            return Ok(p);
        }
        if !p.pop() {
            bail!("{} is not inside a circuits checkout (no guest-sdk/ above it)", dir.display());
        }
    }
}

pub fn build_rust(dir: &Path, ld: Option<&Path>, out: &Path) -> Result<BuildOutput> {
    // Absolute from here on: cargo runs in the guest directory, so a guest path relative to *our*
    // cwd would resolve against the wrong directory in `-T` and in the remap prefix.
    let dir = &dir.canonicalize().with_context(|| format!("no such guest directory: {}", dir.display()))?;
    let root = checkout_root(dir)?;
    let ld = match ld {
        Some(l) => l.to_path_buf(),
        None => find_ld(dir, &root)?,
    };
    // A relative `--ld` is the guest crate's own, as the former Makefiles wrote it; make it
    // absolute so the `--config` does not depend on where cargo is invoked from.
    let ld_abs = if ld.is_absolute() { ld } else { dir.join(ld) };
    let config = cargo_config(&root, &ld_abs);
    let status = Command::new("cargo")
        .arg(format!("+{TOOLCHAIN}"))
        .args(["build", "--release", "--target", TARGET, "--config"])
        .arg(&config)
        .current_dir(dir)
        .status()
        .with_context(|| format!("running cargo for {} (is the pinned toolchain installed?)", dir.display()))?;
    if !status.success() {
        bail!("cargo build failed for {}", dir.display());
    }
    let elf = find_elf(&dir.join("target").join(TARGET).join("release"))?;
    finish(elf, out)
}

/// A clang that can target this machine: `$CLANG`, else Homebrew's LLVM, else whatever `clang`
/// is on PATH — and only one whose `--print-targets` lists `riscv32`, since Apple's system clang
/// (the `clang` on PATH here) is built without the RISC-V backend and would fail at the first
/// source file with a target-not-found error instead.
pub fn find_clang() -> Option<PathBuf> {
    let candidates = [
        std::env::var("CLANG").ok().map(PathBuf::from),
        Some(PathBuf::from("/opt/homebrew/opt/llvm/bin/clang")),
        Some(PathBuf::from("clang")),
    ];
    candidates.into_iter().flatten().find(|c| {
        Command::new(c)
            .arg("--print-targets")
            .output()
            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("riscv32"))
            .unwrap_or(false)
    })
}

/// `rust-lld` from the pinned Rust sysroot's llvm-tools, so a C guest needs only clang installed:
/// the linker is the same one `build_rust` links with, and the same `guest.ld` drives it.
fn rust_lld() -> Result<PathBuf> {
    let sysroot = String::from_utf8(Command::new("rustc").arg(format!("+{TOOLCHAIN}")).args(["--print", "sysroot"]).output()?.stdout)?;
    let host = String::from_utf8(Command::new("rustc").arg(format!("+{TOOLCHAIN}")).arg("-vV").output()?.stdout)?
        .lines()
        .find_map(|l| l.strip_prefix("host: ").map(str::to_string))
        .context("rustc -vV printed no host line")?;
    let p = PathBuf::from(sysroot.trim()).join("lib/rustlib").join(host).join("bin/rust-lld");
    if !p.exists() {
        bail!("{} not found: rustup +{TOOLCHAIN} component add llvm-tools", p.display());
    }
    Ok(p)
}

/// The clang flags every C guest gets — the C counterpart of [`flags`], and, like it, the only
/// place the set is written down (the two translator tracks emit C into exactly this path).
///
///  * `--target=riscv32-unknown-none-elf`  bare metal, no host libc, no PIC.
///  * `-march=rv32im -mabi=ilp32`  the machine's exact ISA: the `M` extension is in the decoder,
///                      compressed (`C`) instructions are not, and `ilp32` keeps floats — which
///                      this machine has no registers for — out of the ABI.
///  * `-mno-relax`      linker relaxation rewrites `auipc`/`jalr` pairs into `jal` against a `gp`
///                      this machine never sets up; the Rust guests are equally unrelaxed.
///  * `-nostdlib -ffreestanding -fno-builtin`  there is no libc and no compiler runtime here, so
///                      the compiler must not synthesise calls into either.
///  * `-ffile-prefix-map` is [`flags`]'s `--remap-path-prefix`: an image reproduces byte for
///                      byte wherever the checkout lives. `-fdebug-prefix-map` alone would rewrite
///                      only DWARF, but the image container carries `.rodata` into the guest's RAM
///                      (`__FILE__`, assert text), and only the file map — the union of the debug
///                      and macro maps — reaches those strings too.
fn clang_flags(root: &Path) -> Vec<String> {
    vec![
        "--target=riscv32-unknown-none-elf".into(),
        "-march=rv32im".into(),
        "-mabi=ilp32".into(),
        "-mno-relax".into(),
        "-nostdlib".into(),
        "-ffreestanding".into(),
        "-fno-builtin".into(),
        "-Os".into(),
        format!("-ffile-prefix-map={}=/rand-circuits", root.display()),
    ]
}

/// The C path: clang over every `.c` in the guest directory plus this crate's own `start.S`,
/// linked by `rust_lld` against the same `guest.ld` the Rust guests use, then the same pack.
///
/// The guest carries neither the entry point nor the syscall wrappers: `guest.h` and `start.S`
/// are written into the guest's `target/rand-guest/` and that directory is the include path, so
/// a C guest is its own source and nothing else — the shape the sBPF and EVM translators will
/// emit into.
pub fn build_c(dir: &Path, ld: Option<&Path>, out: &Path) -> Result<BuildOutput> {
    // Absolute from here on, for `build_rust`'s reason: the paths below go into the object files
    // and the linker command line, and must not depend on the caller's cwd.
    let dir = &dir.canonicalize().with_context(|| format!("no such guest directory: {}", dir.display()))?;
    // A guest's own `guest.h` or `start.S` would shadow the toolchain's copy of the same name
    // written into `target/rand-guest/` below and put on the include path: `#include "guest.h"`
    // would resolve to the guest's stale copy silently, with no compiler diagnostic. Checked before
    // `find_clang`/`checkout_root` so the failure is cheap and does not depend on either being
    // available.
    for name in ["guest.h", "start.S"] {
        if dir.join(name).exists() {
            bail!("{} carries its own {name}, which would shadow the toolchain's copy written into target/rand-guest/; remove it", dir.display());
        }
    }
    let clang = find_clang().context("no clang with a riscv32 target: brew install llvm, or set CLANG")?;
    let root = checkout_root(dir)?;
    let ld = match ld {
        Some(l) => l.to_path_buf(),
        None => find_ld(dir, &root)?,
    };
    let ld_abs = if ld.is_absolute() { ld } else { dir.join(ld) };
    let target_dir = dir.join("target/rand-guest");
    std::fs::create_dir_all(&target_dir)?;
    let start = target_dir.join("start.S");
    std::fs::write(target_dir.join("guest.h"), include_str!("../guest.h"))?;
    std::fs::write(&start, include_str!("../start.S"))?;
    let mut sources: Vec<PathBuf> = std::fs::read_dir(dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |e| e == "c"))
        .collect();
    // Sorted, so the link order — and with it the image — does not depend on the directory's.
    sources.sort();
    if sources.is_empty() {
        bail!("no .c files in {}", dir.display());
    }
    let mut objects = Vec::new();
    // `start.S` last on the command line but first in the image: `guest.ld` puts `.text._start`
    // at `ORIGIN` whatever order the objects come in.
    for src in sources.iter().chain(std::iter::once(&start)) {
        // The generated start object is named `_rand_guest_start.o`, not `start.o`, so a guest
        // that happens to carry its own `start.c` cannot collide with it; every other object keeps
        // its source's name.
        let obj = if src == &start { target_dir.join("_rand_guest_start.o") } else { target_dir.join(src.file_name().unwrap()).with_extension("o") };
        let status = Command::new(&clang)
            .args(clang_flags(&root))
            .arg("-c")
            .arg("-I")
            .arg(&target_dir)
            .arg(src)
            .arg("-o")
            .arg(&obj)
            .status()
            .with_context(|| format!("running {} on {}", clang.display(), src.display()))?;
        if !status.success() {
            bail!("clang failed on {}", src.display());
        }
        objects.push(obj);
    }
    let elf = target_dir.join("guest.elf");
    let status = Command::new(rust_lld()?)
        .args(["-flavor", "gnu"])
        .arg("-T")
        .arg(&ld_abs)
        .args(&objects)
        .arg("-o")
        .arg(&elf)
        .status()?;
    if !status.success() {
        bail!("linking {} failed", elf.display());
    }
    finish(elf, out)
}

/// Pack an ELF into `out` and read back what the loader will make of it.
fn finish(elf: PathBuf, out: &Path) -> Result<BuildOutput> {
    let image = pack::pack(&std::fs::read(&elf)?)?;
    std::fs::write(out, &image)?;
    let program = rand_zkvm::isa::Program::from_flat_image(&image).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    Ok(BuildOutput { elf, image: out.to_path_buf(), hc: program.digest(), words: program.words.len() })
}

/// The one executable ELF in the release dir (cargo names it after the bin target).
fn find_elf(release: &Path) -> Result<PathBuf> {
    let mut elfs: Vec<_> = std::fs::read_dir(release)
        .with_context(|| format!("reading {}", release.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_none() && std::fs::read(p).map(|b| b.starts_with(b"\x7fELF")).unwrap_or(false))
        .collect();
    match elfs.len() {
        1 => Ok(elfs.remove(0)),
        0 => bail!("no ELF in {}", release.display()),
        _ => bail!("several ELFs in {}; the guest must have one bin target", release.display()),
    }
}
