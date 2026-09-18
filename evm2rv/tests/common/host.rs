//! The translated C built for the host (Task 6, ruling 1): many translated contracts, `evm-rt`
//! (`evm_rt.c`, `u256.c`, `evm_call.c` and the precompiles) and `test/host_jmp.c` compiled with the
//! host `cc` into one shared library, which this process loads and runs case after case — no
//! emulator per case. Storage and Keccak are **the Rust FFI itself**: the library's `evm_sload`,
//! `evm_sstore` and `evm_keccak256` forward to function pointers this side sets to
//! `evm_core::ffi`'s own `extern "C"` functions, so the storage tree, its witnesses and every hash
//! are the interpreter's, as in the shim.
//!
//! Each contract's `evm_entry` is renamed `evm_entry_<i>` and reached through a table; every
//! opcode's line is prefixed with `fuzz_cov[op]++` (the emitted C labels each op with a comment
//! naming it, which is what the counter keys on), and the dispatch's bad-jump exits count into
//! `fuzz_dyn_bad`. The instrumentation adds counters and nothing else. The library is compiled with
//! `-fsanitize=undefined -fno-sanitize-recover=undefined` (a UB report aborts the test process),
//! and cached under `target/` by a hash of everything that goes into it.

use std::ffi::{c_char, c_int, c_void, CString};
use std::path::{Path, PathBuf};
use std::process::Command;

use evm2rv::emit::mnemonic;
use evm_core::abi::{run_call_with_executor, Workspace};
use evm_core::ffi::{halt_from_code, HostBox};
use evm_core::interp::{Buffers, Env, Halt, Log, Outcome, MAX_LOGS, MAX_RETURN_BYTES, MAX_TOPICS};
use evm_core::storage::StorageTree;
use evm_core::u256::U256;

use super::root;

extern "C" {
    fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlerror() -> *const c_char;
}
const RTLD_NOW: c_int = 2;
#[cfg(target_os = "macos")]
const RTLD_LOCAL: c_int = 4;
#[cfg(not(target_os = "macos"))]
const RTLD_LOCAL: c_int = 0;

/// `fuzz_out` in the harness C.
#[repr(C)]
pub struct COut {
    pub halt: u32,
    pub arg: u32,
    pub gas_used: u64,
    pub ret_len: u32,
    pub ret: [u8; MAX_RETURN_BYTES],
    pub n_logs: u32,
    pub logs: [[u32; 1 + 8 * MAX_TOPICS]; MAX_LOGS],
    /// A call reached a precompile (`evm_rdata_live`).
    pub rdata_live: u32,
}

type RunFn = unsafe extern "C" fn(
    idx: u32,
    code: *const u8,
    code_len: u32,
    calldata: *const u8,
    calldata_len: u32,
    gas: u64,
    env: *const u32,
    tree: *mut c_void,
    host: *mut c_void,
    out: *mut COut,
) -> u32;
type HooksFn = unsafe extern "C" fn(*const c_void, *const c_void, *const c_void);

const HARNESS_C: &str = r#"/* evm2rv tests: the host harness around the translated contracts (tests/common/host.rs). */
#include <stdint.h>
#include <string.h>
#include "evm_rt.h"

typedef uint32_t (*sload_fn)(void *, void *, const uint32_t *, uint32_t *);
typedef uint32_t (*sstore_fn)(void *, void *, const uint32_t *, const uint32_t *);
typedef void (*keccak_fn)(void *, const uint8_t *, uint32_t, uint8_t *);
static sload_fn h_sload;
static sstore_fn h_sstore;
static keccak_fn h_keccak;

/* evm_core::ffi's functions, set by the Rust side before any run. */
void fuzz_set_hooks(const void *a, const void *b, const void *c) {
    h_sload = (sload_fn)a;
    h_sstore = (sstore_fn)b;
    h_keccak = (keccak_fn)c;
}
uint32_t evm_sload(void *t, void *h, const uint32_t *s, uint32_t *o) { return h_sload(t, h, s, o); }
uint32_t evm_sstore(void *t, void *h, const uint32_t *s, const uint32_t *v) { return h_sstore(t, h, s, v); }
void evm_keccak256(void *h, const uint8_t *p, uint32_t n, uint8_t *out) { h_keccak(h, p, n, out); }

uint64_t fuzz_cov[256];
uint64_t fuzz_dyn_bad;
extern void (*const fuzz_entries[])(void);

typedef struct {
    uint32_t halt, arg;
    uint64_t gas_used;
    uint32_t ret_len;
    uint8_t ret[MAX_RETURN_BYTES];
    uint32_t n_logs;
    evm_log_t logs[MAX_LOGS];
    uint32_t rdata_live;
} fuzz_out;

/* The shim's executor, over contract `idx`: a fresh process's state (the return-data buffer
 * empty, as .bss starts), the environment, the run, the results. */
uint32_t fuzz_run(uint32_t idx, const uint8_t *code, uint32_t code_len, const uint8_t *cd,
                  uint32_t cd_len, uint64_t gas, const uint32_t *env, void *tree, void *host,
                  fuzz_out *o) {
    memset(o, 0, sizeof *o);
    evm_rdata_len = 0;
    evm_rdata_live = 0;
    uint32_t pre = evm_rt_init(code, code_len, cd, cd_len, gas);
    if (pre != 0) {
        o->halt = pre;
        return pre;
    }
    memcpy(evm_address.l, env, 32);
    memcpy(evm_caller.l, env + 8, 32);
    memcpy(evm_callvalue.l, env + 16, 32);
    evm_tree = tree;
    evm_host = host;
    o->halt = evm_rt_enter(fuzz_entries[idx]);
    o->arg = evm_halt_arg;
    o->gas_used = evm_gas_used();
    o->ret_len = evm_ret_len;
    memcpy(o->ret, evm_ret, evm_ret_len);
    o->n_logs = evm_n_logs;
    memcpy(o->logs, evm_logs, sizeof evm_logs);
    o->rdata_live = evm_rdata_live;
    return o->halt;
}
"#;

/// The runtime's sources, as the shim's build.rs lists them, and the host's setjmp.
const RT_SOURCES: [&str; 8] = [
    "evm_rt.c",
    "u256.c",
    "evm_call.c",
    "precompiles.c",
    "evm_bn.c",
    "evm_secp256k1.c",
    "evm_bn254.c",
    "test/host_jmp.c",
];

/// The opcode an op comment's mnemonic names.
fn opcode_of(name: &str) -> Option<u8> {
    (0..=255u8).find(|&o| mnemonic(o) == name)
}

/// `c` with its `evm_entry` renamed `evm_entry_<i>` and the coverage counters added.
///
/// The op-comment check and the two bad-jump forms are independent `if`s, not `else if`s: a
/// dynamic `JUMP`/`JUMPI`'s whole body — comment, `u256_hi_zero` guard and `goto dispatch` — is
/// emitted on one line (`emit.rs`), so that line must both get its `fuzz_cov[op]++` *and* have its
/// inline `evm_halt(EVM_HALT_BAD_JUMP, …)` counted into `fuzz_dyn_bad`. An `else if` chain would
/// only ever apply the first match and silently undercount dynamic bad jumps on JUMP/JUMPI lines
/// (the dispatch table's own `default:` case is a separate line and is unaffected either way).
pub fn instrument(c: &str, i: usize) -> String {
    let names: Vec<(String, u8)> = (0..=255u8).map(|o| (mnemonic(o), o)).collect();
    let mut out = String::with_capacity(c.len() + c.len() / 4);
    for line in c.lines() {
        let mut line = line.replace("void evm_entry(void)", &format!("void evm_entry_{i}(void)"));
        let t = line.trim_start().to_string();
        if t.starts_with("/* 0x") {
            // `/* 0x0012 NAME [0x..] */ code`
            let end = t.find("*/").expect("a closed op comment") + 2;
            let name = t[3..end - 2].split_whitespace().nth(1).expect("a mnemonic");
            let op = names
                .iter()
                .find(|(n, _)| n == name)
                .map(|&(_, o)| o)
                .or_else(|| opcode_of(name))
                .expect("a known mnemonic");
            let indent = line[..line.len() - t.len()].to_string();
            let mut rewritten = String::new();
            rewritten.push_str(&indent);
            rewritten.push_str(&t[..end]);
            rewritten.push_str(&format!(" fuzz_cov[{op}]++;"));
            rewritten.push_str(&t[end..]);
            line = rewritten;
        }
        if t.starts_with("default: evm_halt(EVM_HALT_BAD_JUMP") {
            line = line.replace("default: ", "default: fuzz_dyn_bad++; ");
        } else if line.contains("if (!u256_hi_zero(d_)) evm_halt(EVM_HALT_BAD_JUMP, 0);") {
            line = line.replace(
                "if (!u256_hi_zero(d_)) evm_halt(EVM_HALT_BAD_JUMP, 0);",
                "if (!u256_hi_zero(d_)) { fuzz_dyn_bad++; evm_halt(EVM_HALT_BAD_JUMP, 0); }",
            );
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// FNV-1a, 64-bit: the cache key (stable across runs, unlike `DefaultHasher`).
fn fnv(h: &mut u64, bytes: &[u8]) {
    for &b in bytes {
        *h ^= b as u64;
        *h = h.wrapping_mul(0x100_0000_01b3);
    }
}

fn cc() -> String {
    std::env::var("CC").unwrap_or_else(|_| "cc".into())
}

/// The flags every object is compiled with (plus `-O1` for the runtime and `-O0` for the
/// contracts, which compile seven times faster so and run in microseconds either way). UBSan
/// traps and aborts; `-Werror` keeps the emitted C as clean on the host as it is on RV32.
fn cflags(rt: &Path) -> Vec<String> {
    vec![
        "-fPIC".into(),
        sanitize(),
        "-fno-sanitize-recover=undefined".into(),
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        "-Wno-unused-label".into(),
        format!("-I{}", rt.display()),
    ]
}

/// `-fsanitize=undefined`, plus `address` when `EVM2RV_HOST_ASAN` is set: the process must then
/// run with the ASan runtime preloaded (`DYLD_INSERT_LIBRARIES` on macOS, `LD_PRELOAD` elsewhere,
/// set to `cc -print-file-name=libclang_rt.asan_osx_dynamic.dylib` or its Linux twin).
fn sanitize() -> String {
    if std::env::var_os("EVM2RV_HOST_ASAN").is_some() {
        "-fsanitize=address,undefined".into()
    } else {
        "-fsanitize=undefined".into()
    }
}

/// A loaded library of translated contracts.
pub struct Lib {
    run: RunFn,
    pub cov: *const [u64; 256],
    pub dyn_bad: *const u64,
    pub path: PathBuf,
}

// SAFETY: one test thread drives a library at a time (the runtime's state is global).
unsafe impl Send for Lib {}
unsafe impl Sync for Lib {}

/// Build (or reuse) and load the library of `contracts` (translated C, in order) under
/// `target/host/<name>`. Compiles in parallel, `per_chunk` contracts to a file.
pub fn build(name: &str, contracts: &[String]) -> Lib {
    let rt = root().join("evm-rt");
    let asan = if std::env::var_os("EVM2RV_HOST_ASAN").is_some() {
        "-asan"
    } else {
        ""
    };
    let dir = root()
        .join("evm2rv/target/host")
        .join(format!("{name}{asan}"));
    std::fs::create_dir_all(&dir).unwrap();
    let flags = cflags(&rt);
    let mut key = 0xcbf2_9ce4_8422_2325u64;
    fnv(&mut key, HARNESS_C.as_bytes());
    fnv(&mut key, b"contracts -O0, runtime -O1");
    fnv(&mut key, flags.join(" ").as_bytes());
    fnv(&mut key, cc().as_bytes());
    for f in RT_SOURCES
        .iter()
        .chain(["evm_rt.h", "u256.h", "precompiles.h", "evm_bn.h"].iter())
    {
        fnv(&mut key, &std::fs::read(rt.join(f)).unwrap());
    }
    for c in contracts {
        fnv(&mut key, c.as_bytes());
    }
    let lib = dir.join("libfuzz.dylib");
    let stamp = dir.join("key");
    let key = format!("{key:016x} {}", contracts.len());
    if std::fs::read_to_string(&stamp).ok().as_deref() != Some(key.as_str()) || !lib.exists() {
        let _ = std::fs::remove_file(&stamp);
        compile(&dir, &rt, &flags, contracts, &lib);
        std::fs::write(&stamp, &key).unwrap();
    }
    load(&lib)
}

fn compile(dir: &Path, rt: &Path, flags: &[String], contracts: &[String], lib: &Path) {
    let t = std::time::Instant::now();
    let per_chunk = 64;
    let mut jobs: Vec<(PathBuf, PathBuf, &str)> = Vec::new(); // (source, object, -O)
    std::fs::write(dir.join("harness.c"), HARNESS_C).unwrap();
    jobs.push((dir.join("harness.c"), dir.join("harness.o"), "-O1"));
    let mut table = String::from("#include <stdint.h>\n");
    for i in 0..contracts.len() {
        table.push_str(&format!("void evm_entry_{i}(void);\n"));
    }
    table.push_str("void (*const fuzz_entries[])(void) = {\n");
    for i in 0..contracts.len() {
        table.push_str(&format!("    evm_entry_{i},\n"));
    }
    table.push_str("};\n");
    std::fs::write(dir.join("table.c"), table).unwrap();
    jobs.push((dir.join("table.c"), dir.join("table.o"), "-O0"));
    for (k, chunk) in contracts.chunks(per_chunk).enumerate() {
        let mut s = String::from("#include <stdint.h>\n#include \"evm_rt.h\"\nextern uint64_t fuzz_cov[256];\nextern uint64_t fuzz_dyn_bad;\n");
        for (j, c) in chunk.iter().enumerate() {
            let body = instrument(c, k * per_chunk + j);
            // Each contract's own includes are already above.
            s.push_str(&body.replace("#include <stdint.h>\n#include \"evm_rt.h\"\n", ""));
        }
        let src = dir.join(format!("chunk{k}.c"));
        std::fs::write(&src, s).unwrap();
        jobs.push((src, dir.join(format!("chunk{k}.o")), "-O0"));
    }
    for f in RT_SOURCES {
        let o = dir.join(format!("rt_{}.o", f.replace('/', "_")));
        jobs.push((rt.join(f), o, "-O1"));
    }
    let par = std::thread::available_parallelism().map_or(4, |n| n.get());
    let queue = std::sync::Mutex::new(jobs.clone());
    std::thread::scope(|s| {
        for _ in 0..par {
            s.spawn(|| loop {
                let Some((src, obj, opt)) = queue.lock().unwrap().pop() else {
                    return;
                };
                let o = Command::new(cc())
                    .arg(opt)
                    .args(flags)
                    .arg("-c")
                    .arg(&src)
                    .arg("-o")
                    .arg(&obj)
                    .output()
                    .unwrap();
                assert!(
                    o.status.success(),
                    "cc {}: {}",
                    src.display(),
                    String::from_utf8_lossy(&o.stderr)
                );
            });
        }
    });
    let o = Command::new(cc())
        .args(["-shared", &sanitize(), "-o"])
        .arg(lib)
        .args(jobs.iter().map(|(_, o, _)| o))
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "linking {}: {}",
        lib.display(),
        String::from_utf8_lossy(&o.stderr)
    );
    eprintln!(
        "host: compiled {} contracts into {} in {:.1}s",
        contracts.len(),
        lib.display(),
        t.elapsed().as_secs_f64()
    );
}

fn sym(h: *mut c_void, name: &str) -> *mut c_void {
    let n = CString::new(name).unwrap();
    let p = unsafe { dlsym(h, n.as_ptr()) };
    assert!(!p.is_null(), "no {name} in the library");
    p
}

fn load(lib: &Path) -> Lib {
    let p = CString::new(lib.to_str().unwrap()).unwrap();
    let h = unsafe { dlopen(p.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
    if h.is_null() {
        let e = unsafe { std::ffi::CStr::from_ptr(dlerror()) };
        panic!("dlopen {}: {}", lib.display(), e.to_string_lossy());
    }
    unsafe {
        let hooks: HooksFn = std::mem::transmute(sym(h, "fuzz_set_hooks"));
        hooks(
            evm_core::ffi::evm_sload as *const c_void,
            evm_core::ffi::evm_sstore as *const c_void,
            evm_core::ffi::evm_keccak256 as *const c_void,
        );
        Lib {
            run: std::mem::transmute::<*mut c_void, RunFn>(sym(h, "fuzz_run")),
            cov: sym(h, "fuzz_cov") as *const [u64; 256],
            dyn_bad: sym(h, "fuzz_dyn_bad") as *const u64,
            path: lib.to_path_buf(),
        }
    }
}

/// What the translated side reports beyond the Outcome.
#[derive(Clone, Copy, Debug, Default)]
pub struct Extra {
    /// A call reached a precompile: the interpreter (which traps on every call) is no oracle.
    pub reached_precompile: bool,
}

impl Lib {
    /// Contract `idx` over the input vector `words`, through `run_call_with_executor` exactly as
    /// the shim runs it: the eight public words, the Outcome, and what else the run reported.
    pub fn run_words<H: evm_core::Host>(
        &self,
        h: &mut H,
        idx: usize,
        words: &[u32],
    ) -> ([u32; 8], Outcome, Extra) {
        let mut ws = Box::new(Workspace::ZERO);
        let mut extra = Extra::default();
        let run = self.run;
        let mut exec = |h: &mut H,
                        code: &[u8],
                        calldata: &[u8],
                        env: Env,
                        tree: &mut StorageTree,
                        _b: &mut Buffers|
         -> Outcome {
            let mut hb = HostBox(h);
            let mut envw = [0u32; 24];
            envw[..8].copy_from_slice(&env.address.0);
            envw[8..16].copy_from_slice(&env.caller.0);
            envw[16..].copy_from_slice(&env.callvalue.0);
            let mut c = Box::new(std::mem::MaybeUninit::<COut>::zeroed());
            // SAFETY: the library's `fuzz_run` fills `c`; `tree` and `hb` outlive the call.
            let c = unsafe {
                run(
                    idx as u32,
                    code.as_ptr(),
                    code.len() as u32,
                    calldata.as_ptr(),
                    calldata.len() as u32,
                    env.gas_limit,
                    envw.as_ptr(),
                    tree as *mut StorageTree as *mut c_void,
                    &mut hb as *mut HostBox<'_> as *mut c_void,
                    c.as_mut_ptr(),
                );
                c.assume_init()
            };
            extra.reached_precompile = c.rdata_live != 0;
            let mut o = Outcome {
                halt: halt_from_code(c.halt, c.arg).unwrap_or(Halt::OutOfBounds),
                gas_used: c.gas_used,
                ret: [0; MAX_RETURN_BYTES],
                ret_len: 0,
                logs: [Log::EMPTY; MAX_LOGS],
                n_logs: 0,
            };
            let n = (c.ret_len as usize).min(MAX_RETURN_BYTES);
            o.ret[..n].copy_from_slice(&c.ret[..n]);
            o.ret_len = n;
            let n = (c.n_logs as usize).min(MAX_LOGS);
            for (dst, src) in o.logs.iter_mut().zip(c.logs.iter()).take(n) {
                dst.n_topics = src[0] as u8;
                for (t, k) in dst.topics.iter_mut().zip(0..MAX_TOPICS) {
                    *t = U256(src[1 + 8 * k..9 + 8 * k].try_into().unwrap());
                }
            }
            o.n_logs = n;
            o
        };
        let (out, o) = run_call_with_executor(
            h,
            &mut ws,
            |i| words[i as usize],
            words.len() as u32,
            &mut exec,
        );
        (out, o, extra)
    }

    /// The per-opcode execution counts so far.
    pub fn coverage(&self) -> [u64; 256] {
        unsafe { *self.cov }
    }
    pub fn dynamic_bad_jumps(&self) -> u64 {
        unsafe { *self.dyn_bad }
    }
}
