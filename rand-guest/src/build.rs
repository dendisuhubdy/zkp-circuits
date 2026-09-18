//! Driving rustc (and, in Task 6, clang) for the guest target, then pack. The flags are the
//! former four Makefiles' (`guests-compiled/README.md`), generated here so no guest carries
//! them.

use crate::pack;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const TARGET: &str = "riscv32im-unknown-none-elf";
pub const TOOLCHAIN: &str = "1.98.1";
/// The one clang whose output `hc` is published for (Homebrew LLVM's, `brew install llvm`): another
/// clang version schedules and allocates the same C differently, so a C guest — and every
/// `sbpf2rv` shim, whose `program.c` it compiles — would get a different image. [`find_clang`]
/// refuses any other version unless the builder sets [`CLANG_UNPINNED_VAR`]` = 1`.
pub const CLANG_VERSION: &str = "23.1.1";
/// The override for [`CLANG_VERSION`]: set to `1`, any clang with a riscv32 target is used, with a
/// warning that the image will not match the published one.
pub const CLANG_UNPINNED_VAR: &str = "RAND_GUEST_CLANG_UNPINNED";

/// What the builder's environment may not bring into a build. Each of these changes the image cargo
/// or clang produces — a profile, the rustflags, the compiler itself, where the output goes, what
/// clang includes — so none of them reaches a child process: `hc` is a function of the guest's
/// source and the pinned toolchain alone, which is what a verifier rebuilding the guest relies on.
/// Every `CARGO_PROFILE_*` and `CARGO_UNSTABLE_*` variable goes too ([`SCRUBBED_PREFIXES`]).
///
/// `.cargo/config.toml` files cannot be scrubbed this way; [`refuse_cargo_configs`] refuses them.
pub const SCRUBBED_VARS: &[&str] = &[
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_TARGET_RISCV32IM_UNKNOWN_NONE_ELF_RUSTFLAGS",
    "CARGO_TARGET_RISCV32IM_UNKNOWN_NONE_ELF_LINKER",
    "CARGO_INCREMENTAL",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "RUSTC_BOOTSTRAP",
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_TARGET_DIR",
    "CARGO_BUILD_TARGET",
    "CCC_OVERRIDE_OPTIONS",
    "CPATH",
    "C_INCLUDE_PATH",
    "COMPILER_PATH",
];

/// The prefixes [`SCRUBBED_VARS`] cannot list one by one.
pub const SCRUBBED_PREFIXES: &[&str] = &["CARGO_PROFILE_", "CARGO_UNSTABLE_"];

/// Removes [`SCRUBBED_VARS`] and every variable under [`SCRUBBED_PREFIXES`] from `cmd`'s environment.
pub fn scrub_env(cmd: &mut Command) -> &mut Command {
    for v in SCRUBBED_VARS {
        cmd.env_remove(v);
    }
    for (k, _) in std::env::vars_os() {
        if let Some(k) = k.to_str() {
            if SCRUBBED_PREFIXES.iter().any(|p| k.starts_with(p)) {
                cmd.env_remove(k);
            }
        }
    }
    cmd
}

/// `$CARGO_HOME`, else `~/.cargo`: where cargo reads its user-wide `config.toml`.
fn cargo_home() -> Option<PathBuf> {
    std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))
}

/// Refuses a build that cargo would read a `.cargo/config` or `.cargo/config.toml` into: one in
/// the guest directory or any of its ancestors, or in `$CARGO_HOME`. Cargo merges such a file into
/// the build (a `[profile]`, `[build] rustflags`, a `[target]` linker), and unlike an environment
/// variable it cannot be removed from the child, so the only reproducible answer is to refuse,
/// naming every file found.
pub fn refuse_cargo_configs(dir: &Path) -> Result<()> {
    let mut found = Vec::new();
    let mut p = Some(dir);
    while let Some(d) = p {
        for name in ["config", "config.toml"] {
            let f = d.join(".cargo").join(name);
            if f.exists() {
                found.push(f);
            }
        }
        p = d.parent();
    }
    if let Some(home) = cargo_home() {
        for name in ["config", "config.toml"] {
            let f = home.join(name);
            if f.exists() && !found.contains(&f) {
                found.push(f);
            }
        }
    }
    if !found.is_empty() {
        let list: Vec<String> = found.iter().map(|f| f.display().to_string()).collect();
        bail!(
            "refusing to build {}: cargo would merge these config files into the build, so hc would depend on this machine rather than the guest's source (the guest's ancestors and $CARGO_HOME must hold none): {}",
            dir.display(),
            list.join(", ")
        );
    }
    Ok(())
}

/// Where a build left its two files. What the image *is* — words, `hc`, the checker's verdict —
/// is the caller's to ask, through the same path `check` takes, so a build that produced an image
/// the loader refuses still reports the checker's named findings rather than a bare load error.
pub struct BuildOutput {
    pub elf: PathBuf,
    pub image: PathBuf,
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
    let mut lds: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("listing {} for its linker script", dir.display()))?
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
    let mut p = dir.canonicalize().with_context(|| format!("no such guest directory: {}", dir.display()))?;
    loop {
        if p.join("guest-sdk/guest.ld").exists() {
            return Ok(p);
        }
        if !p.pop() {
            bail!("{} is not inside a circuits checkout (no guest-sdk/ above it)", dir.display());
        }
    }
}

/// Refuse to build over an existing `out` that is not an image container (first word not
/// `IMAGE_MAGIC`). The two committed legacy flat pins, `guests-compiled/bin/fib.bin` and
/// `keccak256.bin`, are exactly such files: `build` only writes the container form, so a rebuild
/// "over" either would replace a pin that two repos load with `from_flat_binary(0x1000, …)` by a
/// file they cannot load, and every test that includes it would break. Checked first, before any
/// compiler runs.
pub fn refuse_legacy_out(out: &Path) -> Result<()> {
    let existing = match std::fs::read(out) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading the existing {}", out.display())),
    };
    let magic = existing.get(..4).map(|w| u32::from_le_bytes(w.try_into().unwrap()));
    if magic != Some(rand_zkvm::isa::IMAGE_MAGIC) {
        bail!(
            "{} exists and is not an image container — a legacy flat pin (like guests-compiled/bin/fib.bin and keccak256.bin, which are never rebuilt over); build writes only the container form, so pass a different --out",
            out.display()
        );
    }
    Ok(())
}

pub fn build_rust(dir: &Path, ld: Option<&Path>, out: &Path) -> Result<BuildOutput> {
    refuse_legacy_out(out)?;
    // Absolute from here on: cargo runs in the guest directory, so a guest path relative to *our*
    // cwd would resolve against the wrong directory in `-T` and in the remap prefix.
    let dir = &dir.canonicalize().with_context(|| format!("no such guest directory: {}", dir.display()))?;
    refuse_cargo_configs(dir)?;
    let root = checkout_root(dir)?;
    let ld = match ld {
        Some(l) => l.to_path_buf(),
        None => find_ld(dir, &root)?,
    };
    // A relative `--ld` is the guest crate's own, as the former Makefiles wrote it; make it
    // absolute so the `--config` does not depend on where cargo is invoked from.
    let ld_abs = if ld.is_absolute() { ld } else { dir.join(ld) };
    let config = cargo_config(&root, &ld_abs);
    // The output goes where this function looks for it, whatever the environment says, and no ELF
    // a previous build left there can be packed in place of this one's.
    let target_dir = dir.join("target");
    let release = target_dir.join(TARGET).join("release");
    remove_elfs(&release)?;
    let status = scrub_env(&mut Command::new("cargo"))
        .arg(format!("+{TOOLCHAIN}"))
        .args(["build", "--release", "--target", TARGET, "--target-dir"])
        .arg(&target_dir)
        .arg("--config")
        .arg(&config)
        .current_dir(dir)
        .status()
        .with_context(|| format!("running cargo for {} (is the pinned toolchain installed?)", dir.display()))?;
    if !status.success() {
        bail!("cargo build failed for {}", dir.display());
    }
    let elf = find_elf(&release)?;
    finish(elf, out)
}

/// A clang that can target this machine: `$CLANG`, else Homebrew's LLVM, else whatever `clang`
/// is on PATH — and only one whose `--print-targets` lists `riscv32`, since Apple's system clang
/// (the `clang` on PATH here) is built without the RISC-V backend and would fail at the first
/// source file with a target-not-found error instead.
///
/// `$CLANG` is an instruction, not a hint: if it is set and fails the probe this is an error
/// naming it, never a silent fall back to some other clang.
///
/// The clang found must then be [`CLANG_VERSION`] (`clang --version`'s `clang version X.Y.Z`), or
/// the build is refused: `hc` is published for that clang's output. [`CLANG_UNPINNED_VAR`]` = 1`
/// accepts any version, with a warning on stderr that `hc` will not match published images.
pub fn find_clang() -> Result<PathBuf> {
    let targets_riscv32 = |c: &Path| {
        scrub_env(&mut Command::new(c))
            .arg("--print-targets")
            .output()
            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("riscv32"))
            .unwrap_or(false)
    };
    let clang = if let Some(c) = std::env::var_os("CLANG") {
        let c = PathBuf::from(c);
        if !targets_riscv32(&c) {
            bail!("$CLANG is {}, which does not run or has no riscv32 target (`{} --print-targets`)", c.display(), c.display());
        }
        c
    } else {
        [PathBuf::from("/opt/homebrew/opt/llvm/bin/clang"), PathBuf::from("clang")]
            .into_iter()
            .find(|c| targets_riscv32(c))
            .context("no clang with a riscv32 target: brew install llvm, or set CLANG")?
    };
    let version = clang_version(&clang)?;
    if version != CLANG_VERSION {
        if std::env::var_os(CLANG_UNPINNED_VAR).is_some_and(|v| v == "1") {
            eprintln!(
                "WARNING: {} is clang {version}, not the pinned {CLANG_VERSION}; building anyway because {CLANG_UNPINNED_VAR}=1. hc will not match published images.",
                clang.display()
            );
        } else {
            bail!(
                "{} is clang {version}, but rand-guest is pinned to clang {CLANG_VERSION} (hc is published for its output): install it (brew install llvm) or point CLANG at it; {CLANG_UNPINNED_VAR}=1 builds with this one anyway, and hc will not match published images",
                clang.display()
            );
        }
    }
    Ok(clang)
}

/// `X.Y.Z` from `clang --version`'s first line (`[vendor] clang version X.Y.Z [(…)]`).
pub fn clang_version(clang: &Path) -> Result<String> {
    let o = scrub_env(&mut Command::new(clang))
        .arg("--version")
        .output()
        .with_context(|| format!("running {} --version", clang.display()))?;
    let text = String::from_utf8_lossy(&o.stdout);
    let first = text.lines().next().unwrap_or("");
    first
        .split_once("clang version ")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .map(str::to_string)
        .with_context(|| {
            format!(
                "{} --version printed no `clang version`: {first:?}",
                clang.display()
            )
        })
}

/// `rust-lld` from the pinned Rust sysroot's llvm-tools, so a C guest needs only clang installed:
/// the linker is the same one `build_rust` links with, and the same `guest.ld` drives it.
fn rust_lld() -> Result<PathBuf> {
    let rustc = |args: &[&str]| -> Result<String> {
        let o = Command::new("rustc")
            .arg(format!("+{TOOLCHAIN}"))
            .args(args)
            .output()
            .with_context(|| format!("running rustc +{TOOLCHAIN} {} to find rust-lld (is the pinned toolchain installed?)", args.join(" ")))?;
        if !o.status.success() {
            bail!("rustc +{TOOLCHAIN} {} failed: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
        }
        String::from_utf8(o.stdout).with_context(|| format!("rustc +{TOOLCHAIN} {} printed non-UTF-8", args.join(" ")))
    };
    let sysroot = rustc(&["--print", "sysroot"])?;
    let host = rustc(&["-vV"])?
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
///  * `-nostdlib -ffreestanding -fno-builtin`  there is no libc and no compiler runtime here.
///                      These stop the compiler *recognising* library functions, not *emitting*
///                      calls to them: a struct copy still lowers to `memcpy`, a large zero
///                      initialiser to `memset`, and a 64-bit `/` or `%` by a runtime value to
///                      `__udivdi3` and friends (RV32IM divides 32-bit values only). This crate's
///                      `rt.c` defines exactly those and is linked into every C guest.
///  * `-ffunction-sections -fdata-sections`, with `--gc-sections` at the link  one section per
///                      function and object, so the linker drops whatever the guest does not
///                      reach — `rt.c`'s functions included — as it does for the Rust guests.
///  * `-ffile-prefix-map` is [`flags`]'s `--remap-path-prefix`: an image reproduces byte for
///                      byte wherever the checkout lives. `-fdebug-prefix-map` alone would rewrite
///                      only DWARF, but the image container carries `.rodata` into the guest's RAM
///                      (`__FILE__`, assert text), and only the file map — the union of the debug
///                      and macro maps — reaches those strings too.
///  * `--no-default-config`  no clang configuration file (Homebrew's LLVM ships one per host).
pub fn clang_flags(root: &Path) -> Vec<String> {
    vec![
        "--no-default-config".into(),
        "--target=riscv32-unknown-none-elf".into(),
        "-march=rv32im".into(),
        "-mabi=ilp32".into(),
        "-mno-relax".into(),
        "-nostdlib".into(),
        "-ffreestanding".into(),
        "-fno-builtin".into(),
        "-ffunction-sections".into(),
        "-fdata-sections".into(),
        "-Os".into(),
        format!("-ffile-prefix-map={}=/rand-circuits", root.display()),
    ]
}

/// The C path: clang over every `.c` in the guest directory plus this crate's own `start.S` and
/// `rt.c`, linked by `rust_lld` against the same `guest.ld` the Rust guests use, then the same
/// pack.
///
/// The guest carries neither the entry point, the syscall wrappers nor the runtime: `guest.h`,
/// `start.S` and `rt.c` are written into the guest's `target/rand-guest/` and that directory is
/// the include path, so a C guest is its own source and nothing else — the shape the sBPF and EVM
/// translators will emit into.
pub fn build_c(dir: &Path, ld: Option<&Path>, out: &Path) -> Result<BuildOutput> {
    refuse_legacy_out(out)?;
    // Absolute from here on, for `build_rust`'s reason: the paths below go into the object files
    // and the linker command line, and must not depend on the caller's cwd.
    let dir = &dir.canonicalize().with_context(|| format!("no such guest directory: {}", dir.display()))?;
    // A guest's own `guest.h` or `start.S` fails silently in a different way each: a local
    // `guest.h` would shadow the toolchain's copy written into `target/rand-guest/` below, since
    // the quote-include form searches the including file's own directory before `-I`; a local
    // `start.S` would not be compiled at all — the loop below only globs `.c` files — so the
    // guest's intended entry point would be silently dropped in favour of the bundled one. Checked
    // before `find_clang`/`checkout_root` so the failure is cheap and does not depend on either
    // being available.
    for name in ["guest.h", "start.S"] {
        if dir.join(name).exists() {
            bail!("{} carries its own {name}, which would shadow the toolchain's copy written into target/rand-guest/; remove it", dir.display());
        }
    }
    let clang = find_clang()?;
    let root = checkout_root(dir)?;
    let ld = match ld {
        Some(l) => l.to_path_buf(),
        None => find_ld(dir, &root)?,
    };
    let ld_abs = if ld.is_absolute() { ld } else { dir.join(ld) };
    let target_dir = dir.join("target/rand-guest");
    std::fs::create_dir_all(&target_dir).with_context(|| format!("creating {}", target_dir.display()))?;
    let start = target_dir.join("start.S");
    let rt = target_dir.join("rt.c");
    for (name, text) in [("guest.h", include_str!("../guest.h")), ("start.S", include_str!("../start.S")), ("rt.c", include_str!("../rt.c"))] {
        let path = target_dir.join(name);
        std::fs::write(&path, text).with_context(|| format!("writing the toolchain's {}", path.display()))?;
    }
    let mut sources: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("listing {} for its .c files", dir.display()))?
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
    // `start.S` and `rt.c` last on the command line, `start.S` still first in the image:
    // `guest.ld` puts `.text._start` at `ORIGIN` whatever order the objects come in.
    for src in sources.iter().chain([&start, &rt]) {
        // The generated objects are named `_rand_guest_start.o` and `_rand_guest_rt.o`, not
        // `start.o`/`rt.o`, so a guest that happens to carry its own `start.c` or `rt.c` cannot
        // collide with them; every other object keeps its source's name.
        let obj = if src == &start {
            target_dir.join("_rand_guest_start.o")
        } else if src == &rt {
            target_dir.join("_rand_guest_rt.o")
        } else {
            target_dir.join(src.file_name().unwrap()).with_extension("o")
        };
        let status = scrub_env(&mut Command::new(&clang))
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
    let lld = rust_lld()?;
    // The ELF this build links, never one a previous build left.
    match std::fs::remove_file(&elf) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(e)
                .with_context(|| format!("removing the previous build's {}", elf.display()))
        }
        _ => {}
    }
    let status = scrub_env(&mut Command::new(&lld))
        .args(["-flavor", "gnu", "--gc-sections"])
        .arg("-T")
        .arg(&ld_abs)
        .args(&objects)
        .arg("-o")
        .arg(&elf)
        .status()
        .with_context(|| format!("running {}", lld.display()))?;
    if !status.success() {
        bail!("linking {} failed", elf.display());
    }
    finish(elf, out)
}

/// Pack an ELF into `out`. Not loaded here: the loader refuses an undecodable word outright, and
/// the checker, which the caller runs next, is what names it.
fn finish(elf: PathBuf, out: &Path) -> Result<BuildOutput> {
    let image = pack::pack(&std::fs::read(&elf).with_context(|| format!("reading the linked ELF {}", elf.display()))?)
        .with_context(|| format!("packing {}", elf.display()))?;
    pack::write_image(out, &image)?;
    Ok(BuildOutput { elf, image: out.to_path_buf() })
}

/// The executables in a cargo release dir: extension-less files starting with the ELF magic (cargo
/// names the guest's after its bin target).
fn elfs_in(dir: &Path) -> Result<Vec<PathBuf>> {
    Ok(std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension().is_none()
                && std::fs::read(p)
                    .map(|b| b.starts_with(b"\x7fELF"))
                    .unwrap_or(false)
        })
        .collect())
}

/// Deletes every executable in a cargo release dir (if it exists) before a build, so the ELF found
/// afterwards can only be the one this build wrote.
fn remove_elfs(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for p in elfs_in(dir)? {
        std::fs::remove_file(&p)
            .with_context(|| format!("removing the previous build's {}", p.display()))?;
    }
    Ok(())
}

/// The one executable ELF in the release dir (cargo names it after the bin target).
fn find_elf(release: &Path) -> Result<PathBuf> {
    let mut elfs = elfs_in(release)?;
    match elfs.len() {
        1 => Ok(elfs.remove(0)),
        0 => bail!("no ELF in {}", release.display()),
        _ => bail!("several ELFs in {}; the guest must have one bin target", release.display()),
    }
}
