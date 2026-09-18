//! Driving rustc (and, in Task 6, clang) for the guest target, then pack. The flags are the
//! four Makefiles', generated here so no guest carries them.

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
pub fn flags(root: &Path, ld: &Path) -> Vec<String> {
    vec![
        "-C".into(),
        format!("link-arg=-T{}", ld.display()),
        "-C".into(),
        "target-feature=-unaligned-scalar-mem".into(),
        format!("--remap-path-prefix={}=/rand-circuits", root.display()),
    ]
}

/// The `--config` argument carrying [`flags`]: a TOML array of strings, the shape the Makefiles'
/// `RUSTFLAGS_LIST` has. Rust's `{:?}` is TOML's basic-string syntax for these flags (they hold
/// no backslashes or control characters).
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
    // A relative `--ld` is the guest crate's own, as the Makefiles write it; make it absolute so
    // the `--config` does not depend on where cargo is invoked from.
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

/// Placeholder for the C path (Task 6): clang for the same target, then the same pack.
pub fn build_c(dir: &Path, _ld: Option<&Path>, _out: &Path) -> Result<BuildOutput> {
    bail!("C support lands in Task 6 ({})", dir.display())
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
