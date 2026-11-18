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
//! loader room for the data prologue, and 1 MiB for the 368 KiB `Workspace` in `.bss`), and
//! `program.c` itself.
//!
//! No ELF at run time (ZKVM-117): the image carries the whole program, so it takes no ELF on the
//! public tape, parses none and loads none. `program.c` ends with what the ELF used to supply
//! ([`baked_c`]): the read-only data the translated code may load (`sbpf_core::baked::baked_rodata`:
//! for SPL Token 2 848 bytes of a 108 600-byte ELF) as a constant array, and the two addresses the
//! runtime needs. So `hc` binds everything a run can observe of the program — its code, its entry,
//! its addresses and its read-only data — with no guard, and the public tape is the sysvar block
//! alone.
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

/// What a translated image carries instead of loading an ELF (`sbpf_core::baked`), as C appended to
/// `program.c`: the program's `text_va` and the virtual address of its read-only data, that data's
/// length, and the bytes themselves (`sbpf_core::baked::baked_rodata` of the loaded source ELF —
/// the read-only run without the instructions the code was translated from). An empty array is not
/// C, so no data is one zero byte and a length of 0.
///
/// The bytes become image data, which the loader's prologue writes into memory before `main`
/// (about 2.8 program words per word of data), so a program with a great deal of read-only data
/// pays for it in the 65 535-word program cap.
///
/// `text_in_image` keeps the whole read-only run, the program's own instruction bytes included,
/// for a program that loads from its text (accepted divergence #3 otherwise: such a load faults).
/// It costs those same 2.8 program words per word of text, which a large program cannot afford —
/// SPL Token's text alone would be 68 000.
pub fn baked_c(p: &Program<'_>, text_in_image: bool) -> String {
    let (rodata_va, bytes) = if text_in_image {
        (p.rodata_va, p.rodata)
    } else {
        sbpf_core::baked::baked_rodata(p)
    };
    let mut c = format!(
        "\n/* sbpf_core::baked::Baked: text_va, then the virtual address of the read-only data below. */\nconst uint64_t sbpf_baked[2] = {{{:#018x}ull, {:#018x}ull}};\n/* The program's read-only data (sbpf_core::baked::baked_rodata): {} byte(s). 4-aligned, so the\n   loader writes it a word at a time. */\nconst uint32_t sbpf_rodata_len = {};\n__attribute__((aligned(4))) const uint8_t sbpf_rodata[{}] = {{",
        p.text_va,
        rodata_va,
        bytes.len(),
        bytes.len(),
        bytes.len().max(1),
    );
    if bytes.is_empty() {
        c.push('0');
    }
    for (i, b) in bytes.iter().enumerate() {
        c.push_str(if i % 24 == 0 { "\n    " } else { " " });
        c.push_str(&format!("{b},"));
    }
    c.push_str("\n};\n");
    c
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

//! Generated by sbpf2rv: `guests-compiled/sbpf`'s main with two changes — the program runs as the
//! translated C in `program.c` (through `sbpf-rt`) instead of on `sbpf-core`'s interpreter, and no
//! ELF is read: `program.c` carries the program's read-only data and addresses too.
//! Everything around the run is `sbpf_core::baked::run_call_baked`: the sysvars from the public
//! segment and the instruction from the private one, `check_region`, the three digests, the zeroed
//! stack and heap, and the status mapping — so the eight output words are the interpreter guest's.

use core::ptr::{addr_of, addr_of_mut};
use sbpf_core::abi::{CallEnv, Workspace};
use sbpf_core::baked::{run_call_baked, Baked};
use sbpf_core::elf::Program;
use sbpf_core::interp::Halt;
use sbpf_core::memory::Memory;

/// The harness's `Host`: the machine's SHA-256 and Poseidon2 syscalls, as in the interpreter guest.
/// (The translated program's own `sol_sha256` reaches the coprocessor from C, through `sbpf-rt`.)
struct Syscalls;

impl sbpf_core::Host for Syscalls {
    fn sha256_compress(&mut self, words: &mut [u32; 24]) {
        guest_sdk::sha256_compress(words);
    }

    fn poseidon2(&mut self, words: &mut [u32], n: usize) {
        // SAFETY: `sbpf_core` calls this with `n <= words.len()` and `words.len() >= 8`, and `words`
        // is a live, exclusive `&mut` for the call — `guest_sdk::poseidon2`'s `# Safety` contract.
        unsafe { guest_sdk::poseidon2(words.as_mut_ptr(), n) };
    }

    /// Never called here: only the interpreter's `sol_keccak256` reaches it, and a translated
    /// program's goes to the coprocessor from C.
    fn keccak_f(&mut self, state: &mut [u32; 50]) {
        guest_sdk::keccak(state);
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
    sysvars: *const u8,
    sysvars_len: u32,
    program_id: *const u8,
    return_data: *mut u8,
}

extern "C" {
    static mut sbpf_r: SbpfRegions;
    static mut sbpf_halt_arg: u64;
    /// Bytes of `sbpf_r.return_data` the program set (`sol_set_return_data`).
    static mut sbpf_return_len: u32;
    fn sbpf_rt_reset();
    /// `program.c`'s entry: runs the program from `Vm::new`'s register state, returns an
    /// `SBPF_HALT_*` code, and on `SBPF_HALT_EXIT` (0) sets `*r0`.
    fn sbpf_entry(r0: *mut u64) -> u32;
}

/// `Halt::Trap`'s strings, by `SBPF_TRAP_*` index.
const TRAPS: [&str; 6] = [
    "abort",
    "sol_panic_",
    "sol_memcpy_ overlap",
    "return data too large",
    "return data overlap",
    "sysvar unavailable",
];

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
    /// `program.c`'s `sbpf_core::baked::Baked`: the program's `text_va`, and the virtual address
    /// of its read-only data.
    static sbpf_baked: [u64; 2];
    /// `program.c`'s copy of the program's read-only data: `sbpf_rodata_len` bytes at
    /// `sbpf_rodata`.
    static sbpf_rodata_len: u32;
    static sbpf_rodata: u8;
}

/// The executor: points `sbpf-rt`'s regions at the image's own read-only data (`p`, which
/// `run_call_baked` made of `sbpf_rodata`: no text bytes), at the stack and heap of the
/// `Workspace` and the instruction region, and at the call's sysvars, program id and return-data
/// buffer; resets the per-run state; and runs the translated entry.
fn execute(_h: &mut Syscalls, p: &Program<'_>, mem: Memory<'_>, env: &mut CallEnv<'_>) -> Result<u64, Halt> {
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
        r.sysvars = env.sysvars.as_ptr();
        r.sysvars_len = env.sysvars.len() as u32;
        r.program_id = env.program_id.as_ptr();
        r.return_data = env.return_data.as_mut_ptr();
        sbpf_rt_reset();
        let mut r0 = 0u64;
        let code = sbpf_entry(&mut r0);
        // `sbpf-rt` never sets more than the buffer holds (`SBPF_MAX_RETURN_DATA`).
        *env.return_len = *core::ptr::addr_of!(sbpf_return_len) as usize;
        match code {
            0 => Ok(r0),
            code => Err(halt_from(code, *core::ptr::addr_of!(sbpf_halt_arg))),
        }
    }
}

/// The run's whole state, in `.bss` (see `guests-compiled/sbpf/src/main.rs`).
static mut W: Workspace = Workspace::ZERO;

#[no_mangle]
pub extern "C" fn main() -> ! {
    let w = unsafe { &mut *addr_of_mut!(W) }; // SAFETY: the only reference to `W` ever made — `main` runs once, on the guest's one thread, and nothing else names `W`.
    let mut exec = execute;
    // SAFETY: immutable C constants; `sbpf_rodata` is at least `sbpf_rodata_len` bytes long
    // (`sbpf2rv::shim::baked_c` writes both from one slice).
    let ([text_va, rodata_va], rodata) = unsafe {
        (
            *addr_of!(sbpf_baked),
            core::slice::from_raw_parts(addr_of!(sbpf_rodata), *addr_of!(sbpf_rodata_len) as usize),
        )
    };
    let (out, result) = run_call_baked(
        &mut Syscalls,
        w,
        guest_sdk::read_public,
        u32::MAX,
        guest_sdk::read_input,
        u32::MAX,
        Baked { text_va, rodata_va },
        rodata,
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
   program.c's read-only data); the 1 MiB of RAM holds sbpf-core's Workspace (368 KiB) in .bss,
   the translated program's text and its read-only data, and the 64 KiB RV32 stack. */

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

/// Writes the crate into `out` (created if needed): `program.c` — the emitted C followed by
/// [`baked_c`] of `program`, the loaded source ELF — and the shim's files.
pub fn write_crate(
    out: &Path,
    name: &str,
    program_c: &str,
    program: &Program<'_>,
    text_in_image: bool,
) -> Result<()> {
    std::fs::create_dir_all(out.join("src"))
        .with_context(|| format!("creating {}", out.display()))?;
    let root = checkout_root(out)?;
    let rel = relative_root(out, &root)?;
    let files: [(&str, String); 6] = [
        ("program.c", format!("{program_c}{}", baked_c(program, text_in_image))),
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
