//! The shim crate: the files `sbpf2rv` writes beside `program.c` so that `rand-guest build <dir>`
//! turns the translation into an image (spec §4). It is `guests-compiled/sbpf`'s `main.rs` with one
//! change — `abi::run_call_with_executor` is handed a closure that runs the translated program
//! instead of `Vm::run` — so input decoding, `check_region`, both digests, the stack and heap
//! zeroing and the status mapping are `sbpf-core`'s own, never reimplemented.
//!
//! Six files: `Cargo.toml`, `Cargo.lock` (complete, so nothing is resolved at build time),
//! `build.rs` (compiles `program.c` and `sbpf-rt/sbpf_rt.c` — only
//! that file: the software signature checks stay out, since the interpreter implements neither
//! syscall — with the `cc` crate, `rand-guest`'s pinned clang and exactly its C flags),
//! `src/main.rs`, `shim.ld` (`guests-compiled/sbpf/sbpf.ld`: the origin at `0x10000`, leaving the
//! loader room for the data prologue, and 1 MiB for the 368 KiB `Workspace` and the guard's 16 KiB
//! hash buffer in `.bss`), and `program.c` itself.
//!
//! The ELF guard: the ELF still arrives on the public tape, and the harness hands the translated
//! code the text, `rodata` and their addresses loaded from it, while the interpreter would also
//! start at its entry — so the image refuses any ELF that loads to a different program.
//! `program.c` ends with [`view_digest`] of the program `elf::load` makes of the source ELF
//! (`sbpf_view_digest`: the loaded text, rodata, addresses and entry, [`view_words`]); the
//! executor hashes the program it is handed the same way before running anything, returning
//! `Halt::BadElf` (status 2) on a mismatch. With it `hc` binds the loaded program: everything a
//! run can observe of the ELF.
//!
//! Reproducibility: a verifier rebuilds this crate from the published ELF to check `hc`, so nothing
//! machine-specific may reach the image. The paths to the checkout are relative (the crate must sit
//! inside a circuits checkout, as every `rand-guest` guest must), `-ffile-prefix-map` rewrites the
//! checkout's absolute path in anything clang records (`build.rs`), `rand-guest` remaps the Rust
//! side and scrubs the builder's environment, `build.rs` refuses a clang other than 23.1.1 and
//! passes `--no-default-config`, and every crates.io dependency is pinned to one exact version.

use anyhow::{bail, Context, Result};
use sbpf_core::elf::Program;
use std::path::{Path, PathBuf};

/// `cc`, and the two crates it pulls in, each pinned exactly (they drive clang; none reaches the
/// image, but the build must resolve the same way on every machine).
pub const CC_VERSION: &str = "1.4.6";
const SHLEX_VERSION: &str = "2.0.1";
const FIND_MSVC_TOOLS_VERSION: &str = "0.1.12";

/// The clang the generated `build.rs` accepts: `rand-guest`'s pin (`rand-guest/src/build.rs`,
/// `CLANG_VERSION`; a test keeps the two equal), with the same `RAND_GUEST_CLANG_UNPINNED=1`
/// override.
pub const CLANG_VERSION: &str = "23.1.1";

/// Words per `POSEIDON2` call (`isa::POSEIDON2_MAX_WORDS`): the ELF guard hashes its word stream in
/// chunks of this many words, each after the first beginning with the previous chunk's 8-word digest.
pub const DIGEST_CHUNK: usize = 4096;

/// `text_off`'s value in [`view_words`] when the text is not a span of the read-only run.
pub const TEXT_NOT_IN_RODATA: u32 = u32::MAX;

/// The loaded program view the ELF guard binds: every field of `sbpf_core::elf::Program` that the
/// shim, `sbpf-rt` or the interpreter reads at run time, as the word stream that is hashed.
///
/// * the header: `text_va` (low, high), `text.len()`, `rodata_va` (low, high), `rodata.len()`,
///   `entry_pc`, and `text_off` — where the text sits inside the read-only run when it is a span
///   of the same bytes (every v1 file: the run begins at `.text`), else [`TEXT_NOT_IN_RODATA`];
/// * the read-only run's bytes, packed four per word little-endian, the last word zero-padded;
/// * the text's bytes the same way, only when `text_off` is [`TEXT_NOT_IN_RODATA`] — otherwise
///   they are `rodata[text_off..][..text.len()]`, already hashed.
///
/// Read at run time: `execute` hands `sbpf-rt` the text, the read-only run and both addresses
/// (`sbpf_r`, the program region's loads and `callx`'s `(addr - text_va) / 8`); the interpreter also
/// starts at `entry_pc`, which the translation bakes, so a different entry would run different code
/// on the two sides. `relocs_applied` is read by nobody and is left out.
pub fn view_words(p: &Program<'_>) -> Vec<u32> {
    let text_off = p
        .text_va
        .checked_sub(p.rodata_va)
        .and_then(|o| usize::try_from(o).ok())
        .filter(|&o| {
            o.checked_add(p.text.len())
                .is_some_and(|end| end <= p.rodata.len())
                && p.rodata.as_ptr().wrapping_add(o) == p.text.as_ptr()
        });
    let mut w = vec![
        p.text_va as u32,
        (p.text_va >> 32) as u32,
        p.text.len() as u32,
        p.rodata_va as u32,
        (p.rodata_va >> 32) as u32,
        p.rodata.len() as u32,
        p.entry_pc as u32,
        text_off.map_or(TEXT_NOT_IN_RODATA, |o| o as u32),
    ];
    let pack = |w: &mut Vec<u32>, bytes: &[u8]| {
        w.extend(bytes.chunks(4).map(|c| {
            let mut b = [0u8; 4];
            b[..c.len()].copy_from_slice(c);
            u32::from_le_bytes(b)
        }))
    };
    pack(&mut w, p.rodata);
    if text_off.is_none() {
        pack(&mut w, p.text);
    }
    w
}

/// The `POSEIDON2` sponge over `words`, chained in [`DIGEST_CHUNK`]-word calls: the first over the
/// first 4 096 words, each later one over the previous digest followed by the next 4 088. Exactly
/// what the shim's guard computes, one syscall per chunk.
pub fn chained_digest(words: &[u32]) -> [u32; 8] {
    let first = words.len().min(DIGEST_CHUNK);
    let mut digest = rand_zkvm::hash::sponge_hash(&words[..first]);
    let mut pos = first;
    while pos < words.len() {
        let take = (words.len() - pos).min(DIGEST_CHUNK - 8);
        let mut msg = digest.to_vec();
        msg.extend_from_slice(&words[pos..pos + take]);
        digest = rand_zkvm::hash::sponge_hash(&msg);
        pos += take;
    }
    digest
}

/// The ELF guard's digest: [`chained_digest`] of [`view_words`] of the program `elf::load` made of
/// the source ELF. The shim computes the same over the program it loads from the public tape and
/// refuses any other (`Halt::BadElf`, status 2), so `hc` binds the loaded program.
pub fn view_digest(p: &Program<'_>) -> [u32; 8] {
    chained_digest(&view_words(p))
}

/// The C definition of the guard's constant, appended to `program.c`.
pub fn view_digest_c(digest: &[u32; 8]) -> String {
    let words: Vec<String> = digest.iter().map(|w| format!("0x{w:08x}u")).collect();
    format!(
        "\n/* The ELF guard (sbpf2rv::shim::view_digest): the digest of the loaded program (text, rodata,\n   addresses, entry) this file was translated from. The shim hashes the program it loads from the\n   public tape the same way and refuses any other (BadElf). */\nconst uint32_t sbpf_view_digest[8] = {{{}}};\n",
        words.join(", ")
    )
}

/// The circuits checkout containing `dir`: the nearest ancestor with `guest-sdk/guest.ld`, the
/// same walk `rand-guest`'s `checkout_root` makes.
pub fn checkout_root(dir: &Path) -> Result<PathBuf> {
    let mut p = dir
        .canonicalize()
        .with_context(|| format!("resolving {}", dir.display()))?;
    loop {
        if p.join("guest-sdk/guest.ld").exists() {
            return Ok(p);
        }
        if !p.pop() {
            bail!(
                "{} is not inside a circuits checkout (no guest-sdk/ above it): the shim crate depends on sbpf-core, guest-sdk and sbpf-rt by relative path, and `rand-guest build` needs the checkout too",
                dir.display()
            );
        }
    }
}

/// `root` as a relative path from `dir` (`dir` inside `root`): `..` once per level.
pub fn relative_root(dir: &Path, root: &Path) -> Result<String> {
    let dir = dir
        .canonicalize()
        .with_context(|| format!("resolving {}", dir.display()))?;
    let below = dir
        .strip_prefix(root)
        .with_context(|| format!("{} is not inside {}", dir.display(), root.display()))?;
    let n = below.components().count();
    Ok(if n == 0 {
        ".".into()
    } else {
        vec![".."; n].join("/")
    })
}

/// A crate name from a file stem: lowercase ASCII letters, digits, `-` and `_`, starting with a
/// letter.
pub fn crate_name(stem: &str) -> String {
    let mut s: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    if !s.starts_with(|c: char| c.is_ascii_lowercase()) {
        s.insert_str(0, "sbpf-");
    }
    s
}

pub fn cargo_toml(name: &str, rel: &str) -> String {
    format!(
        r#"# Generated by sbpf2rv: the shim crate that runs program.c (a translated sBPF program) in the Rand
# zkVM through sbpf-core's ABI harness. Build it with `rand-guest build <this directory>`.
[package]
name = "{name}"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
guest-sdk = {{ path = "{rel}/guest-sdk" }}
sbpf-core = {{ path = "{rel}/guests-compiled/sbpf-core" }}

# Pinned exactly: a verifier rebuilds this crate to check hc. `shlex` and `find-msvc-tools` are
# `cc`'s own dependencies, listed only to pin them too.
[build-dependencies]
cc = "={CC_VERSION}"
shlex = "={SHLEX_VERSION}"
find-msvc-tools = "={FIND_MSVC_TOOLS_VERSION}"

[features]
default = []
# Test-only (sbpf2rv/tests/parity.rs): the image writes [status, halt code, payload lo, payload hi,
# 0, 0, 0, 0] instead of the digest, so a test can compare the halt with the interpreter's. Never
# deploy an image built with it.
halt-words = []

# guests-compiled/sbpf's profile, except that this crate itself is size-optimised: the image shares
# the 65 535-word program cap with the translated program, which a whole SPL program nearly fills.
# The dependencies (sbpf-core's harness: decoding, the ELF loader, the digests) stay at opt-level 3,
# where they cost ~130 000 fewer cycles per call for ~150 more words.
[profile.release]
opt-level = "s"
lto = true
panic = "abort"
codegen-units = 1

[profile.release.package."*"]
opt-level = 3

# Its own workspace root, like every guest crate.
[workspace]
"#
    )
}

/// The registry packages the shim builds with, exactly as `cargo` locks them: name, version,
/// checksum, dependencies. With this lock written beside `Cargo.toml`, `cargo` neither resolves
/// nor updates anything (no `Locking`, no `Updating crates.io index`): a verifier's rebuild uses
/// these bytes and no others.
const REGISTRY: [(&str, &str, &str, &[&str]); 3] = [
    (
        "cc",
        CC_VERSION,
        "a3eb0f42d6c360dc3f8a821f6bf2fdea7f72bfd36b3076eb0e6d1e9e0752fff4",
        &["find-msvc-tools", "shlex"],
    ),
    (
        "find-msvc-tools",
        FIND_MSVC_TOOLS_VERSION,
        "3e0f1c7c3a72c66fd80abe965175f7523475c0489a87d3ff9d6e8c87d87a9d2d",
        &[],
    ),
    (
        "shlex",
        SHLEX_VERSION,
        "f8fadd59c855ef2080decdef8ff161eb6661b86933c9d82e5ba29dc602a55aba",
        &[],
    ),
];

/// `Cargo.lock` for the crate `name`: cargo's own format (version 4), packages sorted by name as
/// cargo writes them — the three registry packages, the two path dependencies, and the crate.
pub fn cargo_lock(name: &str) -> String {
    let mut packages: Vec<(String, String)> = Vec::new();
    for (n, v, sum, deps) in REGISTRY {
        let mut p = format!(
            "[[package]]\nname = \"{n}\"\nversion = \"{v}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{sum}\"\n"
        );
        if !deps.is_empty() {
            p.push_str("dependencies = [\n");
            for d in deps {
                p.push_str(&format!(" \"{d}\",\n"));
            }
            p.push_str("]\n");
        }
        packages.push((n.to_string(), p));
    }
    for n in ["guest-sdk", "sbpf-core"] {
        packages.push((
            n.to_string(),
            format!("[[package]]\nname = \"{n}\"\nversion = \"0.1.0\"\n"),
        ));
    }
    let mut deps = vec!["cc", "find-msvc-tools", "guest-sdk", "sbpf-core", "shlex"];
    deps.sort();
    let mut me = format!("[[package]]\nname = \"{name}\"\nversion = \"0.1.0\"\ndependencies = [\n");
    for d in deps {
        me.push_str(&format!(" \"{d}\",\n"));
    }
    me.push_str("]\n");
    packages.push((name.to_string(), me));
    packages.sort_by(|a, b| a.0.cmp(&b.0));
    let body: Vec<String> = packages.into_iter().map(|(_, p)| p).collect();
    format!(
        "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n{}",
        body.join("\n")
    )
}

pub fn build_rs(rel: &str) -> String {
    format!(
        r#"//! Generated by sbpf2rv: compiles program.c and sbpf-rt/sbpf_rt.c for the guest with `cc`, using
//! rand-guest's pinned clang and exactly rand-guest's C flags (rand-guest/src/build.rs, `clang_flags`) —
//! `no_default_flags`, so `cc` adds none of its own. sbpf_rt.c only: the software Ed25519 and
//! secp256k1 in sbpf-rt/ are not linked, since the interpreter implements neither syscall. Rust's
//! compiler_builtins supplies memcpy/memset and the 64-bit division helpers, so rand-guest's rt.c
//! is not linked either.

use std::path::{{Path, PathBuf}};
use std::process::Command;

/// The circuits checkout, relative to this crate.
const ROOT: &str = "{rel}";

/// rand-guest's `find_clang`: `$CLANG`, else Homebrew's LLVM, else `clang` on PATH — and only one
/// with a riscv32 target. `$CLANG` is an instruction: if it fails the probe, the build fails.
fn find_clang() -> PathBuf {{
    let targets_riscv32 = |c: &Path| {{
        Command::new(c)
            .arg("--print-targets")
            .output()
            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("riscv32"))
            .unwrap_or(false)
    }};
    if let Some(c) = std::env::var_os("CLANG") {{
        let c = PathBuf::from(c);
        assert!(targets_riscv32(&c), "$CLANG is {{}}, which does not run or has no riscv32 target", c.display());
        return c;
    }}
    [PathBuf::from("/opt/homebrew/opt/llvm/bin/clang"), PathBuf::from("clang")]
        .into_iter()
        .find(|c| targets_riscv32(c))
        .expect("no clang with a riscv32 target: brew install llvm, or set CLANG")
}}

/// An LLVM tool beside `clang` (`llvm-ar`, `llvm-ranlib`), else the one on PATH: the host's own
/// `ar` may not write an archive rust-lld reads.
fn llvm_tool(clang: &Path, name: &str) -> PathBuf {{
    match clang.parent().map(|d| d.join(name)) {{
        Some(p) if p.exists() => p,
        _ => PathBuf::from(name),
    }}
}}

/// rand-guest's clang pin (`CLANG_VERSION`): any other version is refused unless
/// RAND_GUEST_CLANG_UNPINNED=1, and then the build warns that hc will not match published images.
const CLANG_VERSION: &str = "{clang_version}";

fn assert_pinned(clang: &Path) {{
    let o = Command::new(clang).arg("--version").output().expect("clang --version");
    let text = String::from_utf8_lossy(&o.stdout);
    let first = text.lines().next().unwrap_or("").trim().to_string();
    println!("cargo:warning=sbpf2rv: clang {{first}}");
    let version = first.split_once("clang version ").and_then(|(_, r)| r.split_whitespace().next()).unwrap_or("?");
    if version != CLANG_VERSION {{
        if std::env::var("RAND_GUEST_CLANG_UNPINNED").as_deref() == Ok("1") {{
            println!("cargo:warning=WARNING: {{}} is clang {{version}}, not the pinned {{CLANG_VERSION}}; building anyway because RAND_GUEST_CLANG_UNPINNED=1. hc will not match published images.", clang.display());
        }} else {{
            panic!("{{}} is clang {{version}}, but rand-guest is pinned to clang {{CLANG_VERSION}} (hc is published for its output); RAND_GUEST_CLANG_UNPINNED=1 builds anyway, and hc will not match published images", clang.display());
        }}
    }}
}}

fn main() {{
    // The profile is part of the image: it must be the one Cargo.toml states (this crate at "s",
    // its dependencies at 3), not one a builder's CARGO_PROFILE_* environment substituted.
    assert_eq!(std::env::var("OPT_LEVEL").as_deref(), Ok("s"), "the shim must build at Cargo.toml's opt-level \"s\"");
    // `cc` appends CFLAGS (and ARFLAGS, RANLIBFLAGS) from the environment, under every spelling it
    // reads (cc 1.4.6 `target_envs`): none of them may reach the image.
    let target = std::env::var("TARGET").unwrap();
    let target_u = target.replace(['-', '.'], "_");
    for v in ["CFLAGS", "ARFLAGS", "RANLIBFLAGS"] {{
        for name in [format!("{{v}}_{{target}}"), format!("{{v}}_{{target_u}}"), format!("TARGET_{{v}}"), format!("HOST_{{v}}"), v.to_string()] {{
            std::env::remove_var(name);
        }}
    }}
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = dir.join(ROOT).canonicalize().expect("the circuits checkout this crate was generated in");
    let rt = root.join("sbpf-rt");
    let clang = find_clang();
    assert_pinned(&clang);
    cc::Build::new()
        .inherit_rustflags(false)
        .inherit_trim_paths(false)
        .compiler(&clang)
        .archiver(llvm_tool(&clang, "llvm-ar"))
        .ranlib(llvm_tool(&clang, "llvm-ranlib"))
        .no_default_flags(true)
        .warnings(false)
        .extra_warnings(false)
        .flag("--no-default-config")
        .flag("--target=riscv32-unknown-none-elf")
        .flag("-march=rv32im")
        .flag("-mabi=ilp32")
        .flag("-mno-relax")
        .flag("-nostdlib")
        .flag("-ffreestanding")
        .flag("-fno-builtin")
        .flag("-ffunction-sections")
        .flag("-fdata-sections")
        .flag("-Os")
        .flag(format!("-ffile-prefix-map={{}}=/rand-circuits", root.display()))
        .include(&rt)
        .include(root.join("rand-guest")) // guest.h: the SHA-256 coprocessor call
        .file(dir.join("program.c"))
        .file(rt.join("sbpf_rt.c"))
        .compile("sbpf_program");
    for f in [dir.join("program.c"), rt.join("sbpf_rt.c"), rt.join("sbpf_rt.h"), root.join("rand-guest/guest.h")] {{
        println!("cargo:rerun-if-changed={{}}", f.display());
    }}
    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-env-changed=RAND_GUEST_CLANG_UNPINNED");
}}
"#,
        clang_version = CLANG_VERSION
    )
}

/// `src/main.rs`.
pub const MAIN_RS: &str = r#"#![no_std]
#![no_main]

//! Generated by sbpf2rv: `guests-compiled/sbpf`'s main with two changes — the loaded program runs as
//! the translated C in `program.c` (through `sbpf-rt`) instead of on `sbpf-core`'s interpreter, and
//! the ELF guard refuses (`BadElf`, status 2) any ELF that does not load to the program `program.c`
//! was translated from.
//! Everything around the run is `sbpf_core::abi::run_call_with_executor`: the ELF from the public
//! segment and the instruction from the private one, `check_region`, both digests, the zeroed stack
//! and heap, and the status mapping — so the eight output words are the interpreter guest's.

use core::ptr::{addr_of, addr_of_mut};
use sbpf_core::abi::{run_call_with_executor, Workspace};
use sbpf_core::elf::Program;
use sbpf_core::interp::Halt;
use sbpf_core::memory::Memory;

/// The harness's `Host`: the machine's SHA-256 and Poseidon2 syscalls, as in the interpreter guest.
/// (The translated program's own `sol_sha256` reaches the coprocessor from C, through `sbpf-rt`.)
struct Syscalls;

impl sbpf_core::Host for Syscalls {
    fn sha256_compress(&mut self, words: &mut [u32; 24]) {
        guest_sdk::sha256_compress(words.as_mut_ptr());
    }

    fn poseidon2(&mut self, words: &mut [u32], n: usize) {
        guest_sdk::poseidon2(words.as_mut_ptr(), n);
    }
}

/// `sbpf_regions` (`sbpf-rt/sbpf_rt.h`), field for field.
#[repr(C)]
struct SbpfRegions {
    text: *const u8,
    text_va: u64,
    text_len: u32,
    rodata: *const u8,
    rodata_va: u64,
    rodata_len: u32,
    stack: *mut u8,
    heap: *mut u8,
    input: *mut u8,
    input_len: u32,
}

extern "C" {
    static mut sbpf_r: SbpfRegions;
    static mut sbpf_halt_arg: u64;
    fn sbpf_rt_reset();
    /// `program.c`'s entry: runs the program from `Vm::new`'s register state, returns an
    /// `SBPF_HALT_*` code, and on `SBPF_HALT_EXIT` (0) sets `*r0`.
    fn sbpf_entry(r0: *mut u64) -> u32;
}

/// `Halt::Trap`'s strings, by `SBPF_TRAP_*` index.
const TRAPS: [&str; 3] = ["abort", "sol_panic_", "sol_memcpy_ overlap"];

/// An `SBPF_HALT_*` code (the `Halt` variant's declaration index) and its payload, back to the
/// interpreter's `Halt`.
fn halt_from(code: u32, arg: u64) -> Halt {
    match code {
        1 => Halt::AccessViolation(arg),
        2 => Halt::BadInsn(arg as u8),
        3 => Halt::DivByZero,
        4 => Halt::UnknownSyscall(arg as u32),
        5 => Halt::CallDepth,
        6 => Halt::InstructionLimit,
        7 => Halt::BadElf,
        8 => Halt::BadJump,
        9 => Halt::StackOverflow,
        10 => Halt::Trap(TRAPS.get(arg as usize).copied().unwrap_or("sbpf-rt: unknown trap")),
        // 0 is not a halt, and the runtime has no other code; status 2 either way.
        _ => Halt::Trap("sbpf-rt: unknown halt code"),
    }
}

extern "C" {
    /// `program.c`'s ELF guard constant: `sbpf2rv::shim::view_digest` of the program it was
    /// translated from.
    static sbpf_view_digest: [u32; 8];
}

/// One `POSEIDON2` call's worth of words (`isa::POSEIDON2_MAX_WORDS`).
const CHUNK: usize = 4096;
/// The guard's hash buffer. The syscall writes its digest over the first 8 words it hashed, so it
/// cannot run over the program's own (borrowed, read-only) bytes: they are copied here a chunk at a
/// time, and each digest stays in place as the next chunk's first 8 words.
static mut HASH_BUF: [u32; CHUNK] = [0; CHUNK];

/// `sbpf2rv::shim::chained_digest`, streamed: words go into `HASH_BUF`, and a full buffer is hashed
/// only when another word arrives, so the last call is always `finish`'s.
struct Stream {
    buf: *mut u32,
    fill: usize,
    hashed: bool,
}

impl Stream {
    fn new() -> Self {
        Stream { buf: addr_of_mut!(HASH_BUF) as *mut u32, fill: 0, hashed: false }
    }

    /// Makes room: hashes a full buffer, leaving its digest as the first 8 words.
    #[inline(always)]
    fn room(&mut self) -> usize {
        if self.fill == CHUNK {
            guest_sdk::poseidon2(self.buf, CHUNK);
            self.fill = 8;
            self.hashed = true;
        }
        CHUNK - self.fill
    }

    fn word(&mut self, w: u32) {
        self.room();
        // SAFETY: `room` left `fill < CHUNK`; `HASH_BUF` is only reached through `self.buf`.
        unsafe { self.buf.add(self.fill).write(w) };
        self.fill += 1;
    }

    /// `bytes`, four per word little-endian, the last word zero-padded. Whole words are copied a
    /// run at a time (an unaligned run a word at a time, through byte loads); no slicing, so no
    /// panic path reaches an image with few words to spare. Inlined into its one call site.
    #[inline(always)]
    fn bytes(&mut self, bytes: &[u8]) {
        let (ptr, len) = (bytes.as_ptr(), bytes.len());
        let whole = len / 4;
        let aligned = ptr as usize % 4 == 0;
        let mut i = 0;
        while i < whole {
            let n = self.room().min(whole - i);
            // SAFETY: words `i..i + n` lie inside `bytes`, and `n` fits the buffer's room.
            unsafe {
                let src = ptr.add(4 * i) as *const u32;
                let dst = self.buf.add(self.fill);
                if aligned {
                    copy_words(src, dst, n);
                } else {
                    for k in 0..n {
                        dst.add(k).write(src.add(k).read_unaligned());
                    }
                }
            }
            self.fill += n;
            i += n;
        }
        let rest = len - 4 * whole;
        if rest != 0 {
            let mut w = 0u32;
            for k in 0..rest {
                // SAFETY: byte `4 * whole + k < len`.
                w |= (unsafe { *ptr.add(4 * whole + k) } as u32) << (8 * k);
            }
            self.word(w);
        }
    }

    /// The digest: the last call over what is left (unless the last full buffer was the end).
    fn finish(mut self) -> *const u32 {
        if !self.hashed || self.fill > 8 {
            guest_sdk::poseidon2(self.buf, self.fill);
        }
        self.fill = 0;
        self.buf
    }
}

/// `n` words from `src` to `dst`, eight at a time. The loads are volatile so the compiler cannot
/// turn the loop into a `memcpy` call (compiler_builtins' byte loop, ~9.5 cycles a byte here).
///
/// SAFETY: `src` and `dst` aligned, `n` words valid at each, not overlapping.
#[inline(always)]
unsafe fn copy_words(src: *const u32, dst: *mut u32, n: usize) {
    let mut i = 0;
    while i + 8 <= n {
        let w = [
            src.add(i).read_volatile(),
            src.add(i + 1).read_volatile(),
            src.add(i + 2).read_volatile(),
            src.add(i + 3).read_volatile(),
            src.add(i + 4).read_volatile(),
            src.add(i + 5).read_volatile(),
            src.add(i + 6).read_volatile(),
            src.add(i + 7).read_volatile(),
        ];
        for (k, x) in w.into_iter().enumerate() {
            dst.add(i + k).write(x);
        }
        i += 8;
    }
    while i < n {
        dst.add(i).write(src.add(i).read_volatile());
        i += 1;
    }
}

/// The ELF guard: whether the program loaded from the public tape is the one `program.c` was
/// translated from. The translated code is baked into this image, but the harness hands it the
/// loaded `.rodata`, the text, their addresses and the interpreter's entry from the tape's ELF, so
/// a different ELF would run this code over someone else's program. That view — exactly
/// `sbpf2rv::shim::view_words` — is hashed as `sbpf2rv::shim::chained_digest` hashes it, and
/// compared.
fn is_the_translated_program(p: &Program<'_>) -> bool {
    let text_off = p
        .text_va
        .checked_sub(p.rodata_va)
        .and_then(|o| usize::try_from(o).ok())
        .filter(|&o| {
            o.checked_add(p.text.len()).is_some_and(|end| end <= p.rodata.len())
                && p.rodata.as_ptr().wrapping_add(o) == p.text.as_ptr()
        });
    let mut h = Stream::new();
    for w in [
        p.text_va as u32,
        (p.text_va >> 32) as u32,
        p.text.len() as u32,
        p.rodata_va as u32,
        (p.rodata_va >> 32) as u32,
        p.rodata.len() as u32,
        p.entry_pc as u32,
        text_off.map_or(u32::MAX, |o| o as u32),
    ] {
        h.word(w);
    }
    // The text's bytes only when they are not a span of the run already hashed.
    let text: &[u8] = if text_off.is_none() { p.text } else { &[] };
    for part in [p.rodata, text] {
        h.bytes(part);
    }
    let digest = h.finish();
    // SAFETY: `digest` is `HASH_BUF`'s first 8 words; `sbpf_view_digest` is an immutable C constant.
    unsafe {
        let want = &*addr_of!(sbpf_view_digest);
        let mut same = true;
        for (i, w) in want.iter().enumerate() {
            same &= *digest.add(i) == *w;
        }
        same
    }
}

/// The executor: refuses a loaded program other than the translated one (`BadElf`, status 2 —
/// accepted divergence #3: the interpreter would run it), then points `sbpf-rt`'s regions at the
/// interpreter's own memory (text and read-only data from the loaded ELF, the stack and heap from
/// the `Workspace`, the instruction region), resets the per-run state, and runs the translated
/// entry.
fn execute(_h: &mut Syscalls, p: &Program<'_>, mem: Memory<'_>) -> Result<u64, Halt> {
    if !is_the_translated_program(p) {
        return Err(Halt::BadElf);
    }
    let Memory { stack, heap, input, .. } = mem;
    // SAFETY: `sbpf_r` is only read by `program.c`/`sbpf-rt` during `sbpf_entry` below, while every
    // slice it points into is borrowed by this function; the guest is single-threaded.
    unsafe {
        let r = &mut *addr_of_mut!(sbpf_r);
        r.text = p.text.as_ptr();
        r.text_va = p.text_va;
        r.text_len = p.text.len() as u32;
        r.rodata = p.rodata.as_ptr();
        r.rodata_va = p.rodata_va;
        r.rodata_len = p.rodata.len() as u32;
        r.stack = stack.as_mut_ptr();
        r.heap = heap.as_mut_ptr();
        r.input = input.as_mut_ptr();
        r.input_len = input.len() as u32;
        sbpf_rt_reset();
        let mut r0 = 0u64;
        match sbpf_entry(&mut r0) {
            0 => Ok(r0),
            code => Err(halt_from(code, *core::ptr::addr_of!(sbpf_halt_arg))),
        }
    }
}

/// The run's whole state, in `.bss` (see `guests-compiled/sbpf/src/main.rs`).
static mut W: Workspace = Workspace::ZERO;

#[no_mangle]
pub extern "C" fn main() -> ! {
    let w = unsafe { &mut *addr_of_mut!(W) };
    let mut exec = execute;
    let (out, result) = run_call_with_executor(
        &mut Syscalls,
        w,
        guest_sdk::read_public,
        u32::MAX,
        guest_sdk::read_input,
        u32::MAX,
        &mut exec,
    );
    #[cfg(feature = "halt-words")]
    let out = halt_words(out[0], &result);
    #[cfg(not(feature = "halt-words"))]
    let _ = result;
    for (slot, word) in out.iter().enumerate() {
        guest_sdk::write_output(slot as u32, *word);
    }
    guest_sdk::halt()
}

/// Test-only: `[status, code, payload lo, payload hi, 0, 0, 0, 0]`, the code the `Halt` variant's
/// declaration index (0 with `r0` as the payload if the program returned).
#[cfg(feature = "halt-words")]
fn halt_words(status: u32, r: &Result<u64, Halt>) -> [u32; 8] {
    let (code, payload): (u32, u64) = match *r {
        Ok(r0) => (0, r0),
        Err(h) => match h {
            Halt::Exit => (0, 0),
            Halt::AccessViolation(a) => (1, a),
            Halt::BadInsn(o) => (2, o as u64),
            Halt::DivByZero => (3, 0),
            Halt::UnknownSyscall(x) => (4, x as u64),
            Halt::CallDepth => (5, 0),
            Halt::InstructionLimit => (6, 0),
            Halt::BadElf => (7, 0),
            Halt::BadJump => (8, 0),
            Halt::StackOverflow => (9, 0),
            Halt::Trap(s) => (10, TRAPS.iter().position(|t| *t == s).map_or(u64::MAX, |i| i as u64)),
        },
    };
    [status, code, payload as u32, (payload >> 32) as u32, 0, 0, 0, 0]
}
"#;

/// `shim.ld`: `guests-compiled/sbpf/sbpf.ld`.
pub const LINKER_SCRIPT: &str = r#"/* Generated by sbpf2rv: guests-compiled/sbpf/sbpf.ld. ORIGIN is 0x10000 rather than guest.ld's
   0x1000, leaving the loader room below the text for the data prologue (the Rust harness's and
   program.c's read-only data); the 1 MiB of RAM holds sbpf-core's Workspace (368 KiB) and the ELF
   guard's 16 KiB hash buffer in .bss, the translated program's text, and the 64 KiB RV32 stack. */

ENTRY(_start)

MEMORY {
  RAM (rwx) : ORIGIN = 0x10000, LENGTH = 0x00100000
}

SECTIONS {
  . = 0x10000;
  .text : {
    *(.text._start)
    *(.text .text.*)
  } > RAM
  .rodata : { *(.rodata .rodata.*) } > RAM
  .data : { *(.data .data.*) } > RAM
  .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) } > RAM
  . = ALIGN(16); /* RISC-V psABI: sp must be 16-byte aligned */
  . = . + 0x10000; /* 64 KiB stack */
  __stack_top = .;
  /DISCARD/ : { *(.comment) *(.eh_frame*) *(.riscv.attributes) *(.note*) }
}
"#;

/// Writes the crate into `out` (created if needed): `program.c` — the emitted C followed by the ELF
/// guard's constant, `digest` ([`view_digest`] of the loaded source ELF) — and the shim's files.
pub fn write_crate(out: &Path, name: &str, program_c: &str, digest: &[u32; 8]) -> Result<()> {
    std::fs::create_dir_all(out.join("src"))
        .with_context(|| format!("creating {}", out.display()))?;
    let root = checkout_root(out)?;
    let rel = relative_root(out, &root)?;
    let files: [(&str, String); 6] = [
        ("program.c", format!("{program_c}{}", view_digest_c(digest))),
        ("Cargo.toml", cargo_toml(name, &rel)),
        ("Cargo.lock", cargo_lock(name)),
        ("build.rs", build_rs(&rel)),
        ("src/main.rs", MAIN_RS.to_string()),
        ("shim.ld", LINKER_SCRIPT.to_string()),
    ];
    for (f, text) in files {
        let p = out.join(f);
        std::fs::write(&p, text).with_context(|| format!("writing {}", p.display()))?;
    }
    Ok(())
}
