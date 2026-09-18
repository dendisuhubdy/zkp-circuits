//! The generated shim crate (the spec's §6): the interpreter guest's `main.rs` with the
//! interpreter replaced by the translated C, through `evm_core::abi::run_call_with_executor`.
//!
//! `evm2rv --out <dir>` writes, beside `contract.c`:
//!
//! * `Cargo.toml` — the guest crate: `guest-sdk`, and `evm-core` with its `ffi` feature (the
//!   `extern "C"` storage and Keccak entry points the runtime calls back into); `cc` to build the C.
//!   Its own workspace root and the interpreter guest's release profile. `cc` is pinned to
//!   `=1.4.6`, and a generated `Cargo.lock` ([`cargo_lock`]) fixes it and its dependencies. One cargo feature,
//!   `emit-outcome`, off by default, is for the parity test only (see `src/main.rs`).
//! * `build.rs` — compiles `contract.c` and `evm-rt/`'s `evm_rt.c`, `u256.c`, the call family's
//!   `evm_call.c` and the precompiles (`precompiles.c`, `evm_bn.c`, `evm_secp256k1.c`, `evm_bn254.c`; with `rand-guest/guest.h` on
//!   the include path for the SHA-256 coprocessor) with the `cc` crate, driving the clang `rand-guest` would pick (`$CLANG`, else Homebrew's LLVM, else `clang`
//!   on `PATH`, and only one with a `riscv32` target) with **exactly `rand-guest`'s C flags**
//!   ([`C_FLAGS`], rv32im — never rv32imc — `-Os`, the path remap), inheriting no rustflags and
//!   ignoring `CFLAGS`, and prints the clang's `--version` line as a cargo warning. Rust's `compiler_builtins`
//!   supplies `memcpy`/`memset` and the 64-bit division helpers, so `rand-guest`'s `rt.c` is not
//!   linked. No RISC-V clang is a build failure naming what was tried, never a skip.
//! * `src/main.rs` — decode the interpreter's exact input vector, run the translated code, publish
//!   the same eight words by the same `abi::public_output` rules. The executor fills the runtime's
//!   globals from the decoded call, enters `evm_entry` through `evm_rt_enter` (the runtime's
//!   setjmp), and maps the halt code, `gas_used`, the return data and the logs back into an
//!   `Outcome`.
//! * `shim.ld` — `guests-compiled/evm/evm.ld`'s layout (text at `0x10000`, leaving room below it
//!   for the data prologue the loader synthesises), since the shim has a data segment too.
//!
//! The crate refers to the checkout (`guest-sdk/`, `guests-compiled/evm-core/`, `evm-rt/`) by a
//! relative path when `<dir>` is inside one — which `rand-guest build` requires anyway — so the
//! generated text does not depend on where the checkout lives.

use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};

/// `rand-guest`'s C flags (`rand-guest/src/build.rs`'s `clang_flags`), in its order, without the
/// path remap, which `build.rs` appends with the checkout's absolute path. `tests/emit.rs` checks
/// this list against that function's text, so the two cannot drift apart silently.
pub const C_FLAGS: [&str; 10] = [
    "--target=riscv32-unknown-none-elf",
    "-march=rv32im",
    "-mabi=ilp32",
    "-mno-relax",
    "-nostdlib",
    "-ffreestanding",
    "-fno-builtin",
    "-ffunction-sections",
    "-fdata-sections",
    "-Os",
];

/// The directory holding `guest-sdk/guest.ld` at or above `dir` — `rand-guest`'s
/// `checkout_root` rule.
pub fn checkout_root(dir: &Path) -> Option<PathBuf> {
    let mut p = dir.canonicalize().ok()?;
    loop {
        if p.join("guest-sdk/guest.ld").exists() {
            return Some(p);
        }
        if !p.pop() {
            return None;
        }
    }
}

/// `dir`'s path to the checkout `root` above it, as `../..` (forward slashes: it goes into TOML
/// and Rust source).
fn up_to(root: &Path, dir: &Path) -> Result<String> {
    let below = dir
        .strip_prefix(root)
        .with_context(|| format!("{} is not under {}", dir.display(), root.display()))?;
    let n = below
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count();
    Ok(if n == 0 {
        ".".into()
    } else {
        vec![".."; n].join("/")
    })
}

/// A cargo package name from `s`: ASCII alphanumerics, `-` and `_` kept, anything else `-`.
pub fn crate_name(s: &str) -> String {
    let n: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let n = n.trim_matches('-').to_string();
    if n.is_empty() || n.starts_with(|c: char| c.is_ascii_digit()) {
        format!("evm2rv-{n}")
    } else {
        n
    }
}

/// The shim's files, as text, for a crate named `name` whose checkout is `up` above it.
pub struct Files {
    pub cargo_toml: String,
    pub cargo_lock: String,
    pub build_rs: String,
    pub main_rs: String,
    pub ld: String,
}

pub fn files(name: &str, up: &str) -> Files {
    Files {
        cargo_toml: cargo_toml(name, up),
        cargo_lock: cargo_lock(name),
        build_rs: build_rs(up),
        main_rs: MAIN_RS.to_string(),
        ld: LD.to_string(),
    }
}

/// Write `contract.c` and the shim crate into `out` (created if need be). `out` must be inside a
/// circuits checkout, as `rand-guest build` requires.
pub fn write_crate(out: &Path, name: &str, contract_c: &str) -> Result<()> {
    std::fs::create_dir_all(out.join("src"))
        .with_context(|| format!("creating {}", out.display()))?;
    let out = out
        .canonicalize()
        .with_context(|| format!("resolving {}", out.display()))?;
    let Some(root) = checkout_root(&out) else {
        bail!(
            "{} is not inside a circuits checkout (no guest-sdk/guest.ld above it); rand-guest build needs the shim inside one",
            out.display()
        );
    };
    let up = up_to(&root, &out)?;
    let f = files(name, &up);
    for (path, text) in [
        (out.join("contract.c"), contract_c),
        (out.join("Cargo.toml"), &f.cargo_toml),
        (out.join("Cargo.lock"), &f.cargo_lock),
        (out.join("build.rs"), &f.build_rs),
        (out.join("src/main.rs"), &f.main_rs),
        (out.join("shim.ld"), &f.ld),
    ] {
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

fn cargo_toml(name: &str, up: &str) -> String {
    format!(
        r#"# Generated by evm2rv: the shim crate for a translated EVM contract. Build it with
# `rand-guest build <this dir> --max-words 65535`. Do not edit — re-run evm2rv.
[package]
name = "{name}"
version = "0.1.0"
edition = "2021"
build = "build.rs"

[dependencies]
guest-sdk = {{ path = "{up}/guest-sdk" }}
# `ffi`: the `extern "C"` SLOAD/SSTORE/Keccak entry points evm-rt calls back into.
evm-core = {{ path = "{up}/guests-compiled/evm-core", features = ["ffi"] }}

[build-dependencies]
# Pinned exactly, with the generated Cargo.lock beside this file: the build script is part of
# what produces the image, so its compiler driver must not move with a crates.io release.
cc = "=1.4.6"

[features]
default = []
# Tests only (evm2rv's tests/parity.rs): out[6] = the halt code (a trap's opcode in bits 8..15)
# and out[7] = gas_used, in place of the digest's last two words. Never deploy such a build.
emit-outcome = []

[profile.release]
opt-level = 3
lto = true
panic = "abort"
codegen-units = 1

# Its own workspace root, like every guest crate.
[workspace]
"#
    )
}

/// The shim's registry dependencies, exactly: `cc` 1.4.6 and what it pulls in, as the first
/// parity build resolved them (name, version, checksum, dependencies).
const LOCKED: [(&str, &str, &str, &[&str]); 3] = [
    (
        "cc",
        "1.4.6",
        "a3eb0f42d6c360dc3f8a821f6bf2fdea7f72bfd36b3076eb0e6d1e9e0752fff4",
        &["find-msvc-tools", "shlex"],
    ),
    (
        "find-msvc-tools",
        "0.1.12",
        "3e0f1c7c3a72c66fd80abe965175f7523475c0489a87d3ff9d6e8c87d87a9d2d",
        &[],
    ),
    (
        "shlex",
        "2.0.1",
        "f8fadd59c855ef2080decdef8ff161eb6661b86933c9d82e5ba29dc602a55aba",
        &[],
    ),
];

/// The generated crate's `Cargo.lock`, in cargo's own format (version 4, packages sorted by
/// name), so cargo uses it as written: `rand-guest build` passes no `--locked`, but cargo never
/// re-resolves a lock that already satisfies the manifest, and the parity test checks the file is
/// unchanged and no `Locking`/`Updating` line appears.
pub fn cargo_lock(name: &str) -> String {
    let mut pkgs: Vec<(String, String)> = Vec::new();
    for (n, v, sum, deps) in LOCKED {
        let mut s = format!(
            "[[package]]\nname = \"{n}\"\nversion = \"{v}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{sum}\"\n"
        );
        if !deps.is_empty() {
            s.push_str("dependencies = [\n");
            for d in deps {
                s.push_str(&format!(" \"{d}\",\n"));
            }
            s.push_str("]\n");
        }
        pkgs.push((n.to_string(), s));
    }
    pkgs.push((
        name.to_string(),
        format!(
            "[[package]]\nname = \"{name}\"\nversion = \"0.1.0\"\ndependencies = [\n \"cc\",\n \"evm-core\",\n \"guest-sdk\",\n]\n"
        ),
    ));
    for local in ["evm-core", "guest-sdk"] {
        pkgs.push((
            local.to_string(),
            format!("[[package]]\nname = \"{local}\"\nversion = \"0.1.0\"\n"),
        ));
    }
    pkgs.sort_by(|a, b| a.0.cmp(&b.0));
    let body: Vec<String> = pkgs.into_iter().map(|(_, s)| s).collect();
    format!(
        "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n{}",
        body.join("\n")
    )
}

fn build_rs(up: &str) -> String {
    let flags: Vec<String> = C_FLAGS.iter().map(|f| format!("    {f:?},")).collect();
    BUILD_RS
        .replace("@UP@", up)
        .replace("@FLAGS@", &flags.join("\n"))
        .replace("@NFLAGS@", &C_FLAGS.len().to_string())
}

const BUILD_RS: &str = r#"//! Generated by evm2rv: compiles the translated contract (`contract.c`) and the EVM runtime
//! (`evm-rt/`: `evm_rt.c`, `u256.c` and the precompiles) into a static library for the zkVM, with the clang `rand-guest`
//! would pick and exactly `rand-guest`'s C flags. Do not edit — re-run evm2rv.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The circuits checkout, relative to this crate.
const ROOT: &str = "@UP@";

/// `rand-guest`'s C flags (`rand-guest/src/build.rs`'s `clang_flags`); the path remap is added
/// below with the checkout's absolute path. rv32im, never rv32imc.
const C_FLAGS: [&str; @NFLAGS@] = [
@FLAGS@
];

fn targets_riscv32(c: &Path) -> bool {
    Command::new(c)
        .arg("--print-targets")
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("riscv32"))
        .unwrap_or(false)
}

/// `rand-guest`'s `find_clang`: `$CLANG`, else Homebrew's LLVM, else `clang` on PATH — only one
/// with a `riscv32` target. None is a build failure, never a skip.
fn find_clang() -> PathBuf {
    println!("cargo:rerun-if-env-changed=CLANG");
    if let Some(c) = std::env::var_os("CLANG") {
        let c = PathBuf::from(c);
        if !targets_riscv32(&c) {
            panic!("$CLANG is {}, which does not run or has no riscv32 target", c.display());
        }
        return c;
    }
    for c in ["/opt/homebrew/opt/llvm/bin/clang", "clang"] {
        let c = PathBuf::from(c);
        if targets_riscv32(&c) {
            return c;
        }
    }
    panic!("no clang with a riscv32 target (tried $CLANG, /opt/homebrew/opt/llvm/bin/clang, clang): brew install llvm, or set CLANG");
}

/// The `llvm-ar` beside that clang, else the one on PATH.
fn find_ar(clang: &Path) -> PathBuf {
    let sibling = clang.with_file_name("llvm-ar");
    if sibling.exists() {
        sibling
    } else {
        PathBuf::from("llvm-ar")
    }
}

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if target != "riscv32im-unknown-none-elf" {
        panic!("this shim builds for riscv32im-unknown-none-elf only (`rand-guest build`), not {target}");
    }
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = dir.join(ROOT).canonicalize().expect("the circuits checkout above this crate");
    let rt = root.join("evm-rt");
    // The image must not depend on the builder's environment: `cc` appends these to every
    // compile it runs, so they are cleared for this process before it reads them.
    for v in [
        "CFLAGS",
        "TARGET_CFLAGS",
        "CFLAGS_riscv32im_unknown_none_elf",
        "CFLAGS_riscv32im-unknown-none-elf",
    ] {
        std::env::remove_var(v);
    }
    let clang = find_clang();
    // Which compiler produced the C half of the image (and so its hc), in the build's output.
    let version = Command::new(&clang)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().next().map(str::to_string))
        .unwrap_or_else(|| "(no --version output)".into());
    println!("cargo:warning=evm2rv: clang {version} ({})", clang.display());
    // The whole runtime, the precompiles included: `cc` archives it, and the linker takes only the
    // objects (and, with -ffunction-sections, only the functions) the contract reaches, so a
    // contract that never calls has none of the precompile code in its image.
    let sources = [
        dir.join("contract.c"),
        rt.join("evm_rt.c"),
        rt.join("u256.c"),
        rt.join("evm_call.c"),
        rt.join("precompiles.c"),
        rt.join("evm_bn.c"),
        rt.join("evm_secp256k1.c"),
        rt.join("evm_bn254.c"),
    ];
    let mut b = cc::Build::new();
    b.compiler(&clang)
        .archiver(find_ar(&clang))
        .no_default_flags(true)
        // cc 1.4.6 otherwise translates some of the Rust target's rustflags into C flags; the C
        // flags are exactly C_FLAGS and nothing else.
        .inherit_rustflags(false)
        .warnings(false)
        .extra_warnings(false)
        .include(&rt)
        // guest.h: precompiles.c's sha256 reaches the SHA-256 coprocessor through it.
        .include(root.join("rand-guest"));
    for f in C_FLAGS {
        b.flag(f);
    }
    b.flag(format!("-ffile-prefix-map={}=/rand-circuits", root.display()));
    for s in &sources {
        b.file(s);
        println!("cargo:rerun-if-changed={}", s.display());
    }
    for h in ["evm_rt.h", "u256.h", "precompiles.h", "evm_bn.h"] {
        println!("cargo:rerun-if-changed={}", rt.join(h).display());
    }
    println!("cargo:rerun-if-changed={}", root.join("rand-guest/guest.h").display());
    b.compile("evm2rv_contract");
}
"#;

const MAIN_RS: &str = r#"//! Generated by evm2rv: the interpreter guest's `main.rs` (`guests-compiled/evm/src/main.rs`) with
//! the interpreter replaced by the translated contract (`contract.c`, over `evm-rt`). The input
//! vector, its decoding, the storage witnesses, `logs_hash`, `public_output` and the `EVM_OUT`
//! digest are `evm_core::abi`'s, unchanged — the code hash the digest binds is the hash of the
//! input vector's code, as for the interpreter. Do not edit — re-run evm2rv.

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut};

use evm_core::abi::{run_call_with_executor, Workspace};
use evm_core::ffi::{halt_from_code, HostBox};
use evm_core::interp::{Buffers, Env, Halt, Log, Outcome, MAX_LOGS, MAX_RETURN_BYTES, MAX_TOPICS};
use evm_core::storage::StorageTree;
use evm_core::u256::U256;
use evm_core::Host;
use guest_sdk::{halt, keccak, poseidon2, read_input, write_output};

/// [`evm_core::Host`] as the machine's two syscalls (the interpreter guest's own).
struct Syscalls;

impl Host for Syscalls {
    fn keccak_f(&mut self, state: &mut [u32; 50]) {
        keccak(state.as_mut_ptr());
    }
    fn poseidon2(&mut self, words: &mut [u32], n: usize) {
        poseidon2(words.as_mut_ptr(), n);
    }
}

/// `evm_rt.h`'s `evm_log_t`.
#[repr(C)]
struct CLog {
    n_topics: u32,
    topics: [[u32; 8]; MAX_TOPICS],
}

// Every runtime global is `static mut`: C writes all of them (the result ones during the run),
// so Rust must not assume any is immutable. Each is read and written only through `addr_of!` /
// `addr_of_mut!`, never through a reference to the static itself.
extern "C" {
    static mut evm_address: [u32; 8];
    static mut evm_caller: [u32; 8];
    static mut evm_callvalue: [u32; 8];
    static mut evm_tree: *mut c_void;
    static mut evm_host: *mut c_void;
    static mut evm_ret: [u8; MAX_RETURN_BYTES];
    static mut evm_ret_len: u32;
    static mut evm_logs: [CLog; MAX_LOGS];
    static mut evm_n_logs: u32;
    static mut evm_halt_arg: u32;
    fn evm_rt_init(code: *const u8, code_len: u32, calldata: *const u8, calldata_len: u32, gas_limit: u64) -> u32;
    fn evm_rt_enter(entry: unsafe extern "C" fn()) -> u32;
    fn evm_gas_used() -> u64;
    /// The translated contract (`contract.c`).
    fn evm_entry();
}

/// The executor: the translated contract over the decoded call. The runtime keeps its own stack
/// and memory in `.bss`, so the interpreter's `Buffers` are not used.
fn translated(
    h: &mut Syscalls,
    code: &[u8],
    calldata: &[u8],
    env: Env,
    tree: &mut StorageTree,
    _bufs: &mut Buffers,
) -> Outcome {
    let mut hb = HostBox(h);
    let mut o = Outcome {
        halt: Halt::Stop,
        gas_used: 0,
        ret: [0; MAX_RETURN_BYTES],
        ret_len: 0,
        logs: [Log::EMPTY; MAX_LOGS],
        n_logs: 0,
    };
    // SAFETY: one thread; the runtime's globals are written here before `evm_entry` runs and read
    // after it has halted. `evm_tree`/`evm_host` point at `tree` and `hb`, both live for the whole
    // run; the runtime's longjmp only ever unwinds C frames (every Rust callback it makes —
    // `evm_sload`, `evm_sstore`, `evm_keccak256` — has returned before it halts).
    unsafe {
        let pre = evm_rt_init(code.as_ptr(), code.len() as u32, calldata.as_ptr(), calldata.len() as u32, env.gas_limit);
        if pre != 0 {
            // The interpreter's `pre_halt`: nothing runs, nothing is spent.
            o.halt = Halt::OutOfBounds;
            return o;
        }
        *addr_of_mut!(evm_address) = env.address.0;
        *addr_of_mut!(evm_caller) = env.caller.0;
        *addr_of_mut!(evm_callvalue) = env.callvalue.0;
        *addr_of_mut!(evm_tree) = tree as *mut StorageTree as *mut c_void;
        *addr_of_mut!(evm_host) = addr_of_mut!(hb) as *mut c_void;
        let code = evm_rt_enter(evm_entry);
        // `evm_rt_enter` returns a code from `ffi.rs`'s table, never 0; anything else would be a
        // runtime bug, reported as an exceptional halt rather than a panic (which is no proof).
        o.halt = halt_from_code(code, *addr_of!(evm_halt_arg)).unwrap_or(Halt::OutOfBounds);
        o.gas_used = evm_gas_used();
        let ret = &*addr_of!(evm_ret);
        let n = (*addr_of!(evm_ret_len) as usize).min(MAX_RETURN_BYTES);
        o.ret[..n].copy_from_slice(&ret[..n]);
        o.ret_len = n;
        let logs = &*addr_of!(evm_logs);
        let n = (*addr_of!(evm_n_logs) as usize).min(MAX_LOGS);
        for (dst, src) in o.logs.iter_mut().zip(logs.iter()).take(n) {
            dst.n_topics = src.n_topics as u8;
            for (t, s) in dst.topics.iter_mut().zip(src.topics.iter()) {
                *t = U256(*s);
            }
        }
        o.n_logs = n;
    }
    o
}

/// The whole run's state, in `.bss` (`evm_core::abi`'s module docs carry the pattern).
static mut W: Workspace = Workspace::ZERO;

#[no_mangle]
pub extern "C" fn main() -> ! {
    let w = unsafe { &mut *addr_of_mut!(W) };
    // `u32::MAX`: a READ_INPUT past the committed `n_in` is unsatisfiable in-circuit, so the
    // machine is the length check (`evm_core::abi::InputCursor`).
    let (out, _o) = run_call_with_executor(&mut Syscalls, w, read_input, u32::MAX, &mut translated);
    #[cfg(not(feature = "emit-outcome"))]
    {
        let mut k = 0;
        while k < 8 {
            write_output(k as u32, out[k]);
            k += 1;
        }
    }
    // Tests only: the status and digest words 0..4, then the halt and gas_used in place of the
    // digest's last two words.
    #[cfg(feature = "emit-outcome")]
    {
        let mut k = 0;
        while k < 6 {
            write_output(k as u32, out[k]);
            k += 1;
        }
        let arg = match _o.halt {
            Halt::Trap(op) => op as u32,
            _ => 0,
        };
        write_output(6, evm_core::ffi::halt_code(_o.halt) | (arg << 8));
        write_output(7, _o.gas_used as u32);
    }
    halt();
}
"#;

const LD: &str = r#"/* Generated by evm2rv: guests-compiled/evm/evm.ld's layout. guest-sdk/guest.ld with ORIGIN at
   0x10000 rather than 0x1000, leaving 0xf000 bytes below the text for the data prologue the
   loader synthesises (`Program::from_flat_image`): the shim has a data segment (.rodata: the
   jump switch's table, wide PUSH constants, panic locations). */

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
