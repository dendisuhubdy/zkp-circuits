//! The host differential harness the `tests/parity_*.rs` files share: a hand-assembled program
//! runs through the interpreter (`sbpf_core::interp`) and through the emitted C compiled for the
//! host with `cc` against `sbpf-rt` (the same build `tests/fuzz.rs` makes, minus its coverage and
//! limit bookkeeping), and the two must agree on the halt kind with its payload, `r0` on a normal
//! exit, the allocator's cursor, and the stack, heap and input region afterwards (byte for byte, as
//! FNV-1a digests). Every program in a test is compiled into one driver, so a test costs one `cc`
//! invocation however many programs it runs.
//!
//! Needs only a host C compiler, never the guest toolchain. Not a test target itself: `cargo`
//! builds only the top-level files of `tests/` as tests.

#![allow(dead_code)]

use sbpf2rv::emit::emit_program;
use sbpf2rv::scan::scan;
use sbpf_core::elf::Program;
use sbpf_core::interp::{Halt, Vm};
use sbpf_core::isa::{self, opc, Insn};
use sbpf_core::memory::{Memory, HEAP_BYTES, STACK_BYTES};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

// ---- assembling -------------------------------------------------------------------------------------

pub fn i(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        opc,
        dst,
        src,
        off,
        imm,
    }
}

pub fn exit() -> Insn {
    i(opc::EXIT, 0, 0, 0, 0)
}

/// `mov64 dst, imm`.
pub fn mov(dst: u8, imm: i32) -> Insn {
    i(opc::MOV64_IMM, dst, 0, 0, imm)
}

/// `lddw dst, v`: the two slots.
pub fn lddw(dst: u8, v: u64) -> [Insn; 2] {
    [
        i(opc::LD_DW_IMM, dst, 0, 0, v as u32 as i32),
        i(0, 0, 0, 0, (v >> 32) as u32 as i32),
    ]
}

/// `dst = v`, as one `mov64` when `v` fits a sign-extended immediate, else an `lddw`.
pub fn set(dst: u8, v: u64) -> Vec<Insn> {
    if v as i64 >= i32::MIN as i64 && v as i64 <= i32::MAX as i64 {
        vec![mov(dst, v as i32)]
    } else {
        lddw(dst, v).to_vec()
    }
}

/// Encodes an instruction stream into the bytes `Program::from_text` wants.
pub fn text(insns: &[Insn]) -> Vec<u8> {
    insns
        .iter()
        .flat_map(|i| isa::encode(*i).to_le_bytes())
        .collect()
}

// ---- what a run leaves --------------------------------------------------------------------------------

/// What a run left, on either side: the halt as `sbpf-rt`'s `(code, payload)`, `r0` (0 unless the
/// run returned), the allocator's cursor and the three writable regions' digests.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Seen {
    pub code: u32,
    pub arg: u64,
    pub r0: u64,
    pub heap_used: u64,
    pub stack: u64,
    pub heap: u64,
    pub input: u64,
}

pub const HALT_EXIT: u32 = 0;
pub const HALT_ACCESS_VIOLATION: u32 = 1;
pub const HALT_BAD_INSN: u32 = 2;
pub const HALT_DIV_BY_ZERO: u32 = 3;
pub const HALT_UNKNOWN_SYSCALL: u32 = 4;
pub const HALT_CALL_DEPTH: u32 = 5;
pub const HALT_INSTRUCTION_LIMIT: u32 = 6;
pub const HALT_BAD_JUMP: u32 = 8;
pub const HALT_TRAP: u32 = 10;

const TRAPS: [&str; 3] = ["abort", "sol_panic_", "sol_memcpy_ overlap"];

/// `Result<u64, Halt>` as `sbpf-rt`'s `(code, payload)`: the `Halt` variant's declaration index.
pub fn halt_code(r: &Result<u64, Halt>) -> (u32, u64) {
    match *r {
        Ok(_) | Err(Halt::Exit) => (0, 0),
        Err(Halt::AccessViolation(a)) => (1, a),
        Err(Halt::BadInsn(o)) => (2, o as u64),
        Err(Halt::DivByZero) => (3, 0),
        Err(Halt::UnknownSyscall(h)) => (4, h as u64),
        Err(Halt::CallDepth) => (5, 0),
        Err(Halt::InstructionLimit) => (6, 0),
        Err(Halt::BadElf) => (7, 0),
        Err(Halt::BadJump) => (8, 0),
        Err(Halt::StackOverflow) => (9, 0),
        Err(Halt::Trap(s)) => (10, TRAPS.iter().position(|t| *t == s).unwrap() as u64),
    }
}

pub fn fnv(b: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &x in b {
        h = (h ^ u64::from(x)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The interpreter's run over `text` with `input` as the whole input region: the result, what it
/// left, and the meter.
pub fn interpret(text: &[u8], input: &[u8]) -> (Result<u64, Halt>, Seen, u64) {
    let p = Program::from_text(text).unwrap();
    let mut stack = vec![0u8; STACK_BYTES].into_boxed_slice();
    let mut heap = vec![0u8; HEAP_BYTES].into_boxed_slice();
    let mut input = input.to_vec();
    let (result, meter, heap_used) = {
        let mem = Memory {
            text: p.text,
            text_va: p.text_va,
            rodata: p.rodata,
            rodata_base: p.rodata_va,
            stack: (&mut stack[..]).try_into().unwrap(),
            heap: (&mut heap[..]).try_into().unwrap(),
            input: &mut input,
        };
        let mut h = rand_zkvm::sbpf::HostRef;
        let mut vm = Vm::new(&mut h, &p, mem);
        let r = vm.run();
        (r, vm.instructions_executed(), vm.heap_used)
    };
    let (code, arg) = halt_code(&result);
    let seen = Seen {
        code,
        arg,
        r0: *result.as_ref().unwrap_or(&0),
        heap_used: heap_used as u64,
        stack: fnv(&stack),
        heap: fnv(&heap),
        input: fnv(&input),
    };
    (result, seen, meter)
}

// ---- the host build -------------------------------------------------------------------------------

fn rt_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../sbpf-rt")
}

fn work_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("target/hostdiff")
}

fn cc(dir: &Path, args: &[String]) {
    let o = Command::new("cc")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("a host C compiler (`cc`)");
    assert!(
        o.status.success(),
        "cc {args:?} in {}:\n{}",
        dir.display(),
        String::from_utf8_lossy(&o.stderr)
    );
}

/// `sbpf_rt.o` and `host_glue.o`, compiled once per test process.
fn rt_objects() -> &'static [PathBuf; 2] {
    static RT: OnceLock<[PathBuf; 2]> = OnceLock::new();
    RT.get_or_init(|| {
        let dir = work_root().join(format!("rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let rt = rt_dir();
        cc(
            &dir,
            &[
                "-Os".into(),
                "-w".into(),
                format!("-I{}", rt.display()),
                "-c".into(),
                rt.join("sbpf_rt.c").display().to_string(),
                rt.join("test/host_glue.c").display().to_string(),
            ],
        );
        [dir.join("sbpf_rt.o"), dir.join("host_glue.o")]
    })
}

/// Reads `<idx> <text hex> <input hex>` per line, runs entry `idx` over those regions (the text
/// doubling as the read-only run, as `Program::from_text` has it), prints
/// `<idx> <code> <arg> <r0> <heap_used> <stack fnv> <heap fnv> <input fnv>`.
const DRIVER: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sbpf_rt.h"

typedef uint32_t (*entry_t)(uint64_t *);
extern const entry_t diff_entries[];

static uint8_t text[1 << 20], input[1 << 16], stack[SBPF_STACK_BYTES], heap[SBPF_HEAP_BYTES];

static size_t unhex(uint8_t *out, const char *h) {
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

static uint64_t fnv(const uint8_t *p, size_t n) {
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 0x100000001b3ull;
    return h;
}

int main(void) {
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, stdin) > 0) {
        char *save = NULL;
        char *k = strtok_r(line, " \n", &save);
        char *t = strtok_r(NULL, " \n", &save);
        char *in = strtok_r(NULL, " \n", &save);
        if (!k || !t || !in) continue;
        int idx = atoi(k);
        size_t tl = unhex(text, t), il = strcmp(in, "-") == 0 ? 0 : unhex(input, in);
        memset(stack, 0, sizeof stack);
        memset(heap, 0, sizeof heap);
        memset(&sbpf_r, 0, sizeof sbpf_r);
        sbpf_r.text = text;
        sbpf_r.text_va = SBPF_REGION_PROGRAM;
        sbpf_r.text_len = (uint32_t)tl;
        sbpf_r.rodata = text;
        sbpf_r.rodata_va = SBPF_REGION_PROGRAM;
        sbpf_r.rodata_len = (uint32_t)tl;
        sbpf_r.stack = stack;
        sbpf_r.heap = heap;
        sbpf_r.input = input;
        sbpf_r.input_len = (uint32_t)il;
        sbpf_rt_reset();
        uint64_t r0 = 0;
        uint32_t code = diff_entries[idx](&r0);
        printf("%d %u %llu %llu %u %llu %llu %llu\n", idx, code, (unsigned long long)sbpf_halt_arg,
               (unsigned long long)r0, sbpf_heap_used, (unsigned long long)fnv(stack, sizeof stack),
               (unsigned long long)fnv(heap, sizeof heap), (unsigned long long)fnv(input, il));
        fflush(stdout);
    }
    free(line);
    return 0;
}
"#;

/// The emitted C of `text`, scanned and translated as the pipeline would.
pub fn translate(text: &[u8]) -> String {
    let p = Program::from_text(text).unwrap();
    let s = scan(&p);
    emit_program(&p, &s).c
}

/// Builds one driver over every `(text, input)` and runs each through it.
pub fn run_c(name: &str, cases: &[(Vec<u8>, Vec<u8>)]) -> Vec<Seen> {
    let dir = work_root().join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut table = String::from("#include <stdint.h>\ntypedef uint32_t (*entry_t)(uint64_t *);\n");
    let mut files: Vec<String> = Vec::new();
    for (k, (t, _)) in cases.iter().enumerate() {
        let f = format!("c{k}.c");
        std::fs::write(
            dir.join(&f),
            format!("#define sbpf_entry sbpf_entry_{k}\n{}", translate(t)),
        )
        .unwrap();
        files.push(f);
        let _ = writeln!(table, "uint32_t sbpf_entry_{k}(uint64_t *);");
    }
    table.push_str("const entry_t diff_entries[] = {\n");
    for k in 0..cases.len() {
        let _ = writeln!(table, "    sbpf_entry_{k},");
    }
    table.push_str("};\n");
    std::fs::write(dir.join("table.c"), table).unwrap();
    std::fs::write(dir.join("driver.c"), DRIVER).unwrap();
    let rt = rt_dir();
    let mut args: Vec<String> = vec![
        "-Os".into(),
        "-w".into(),
        format!("-I{}", rt.display()),
        "-c".into(),
    ];
    args.extend(files.iter().cloned());
    args.extend(["table.c".into(), "driver.c".into()]);
    cc(&dir, &args);
    let mut link: Vec<String> = vec!["-o".into(), "driver".into()];
    link.extend(files.iter().map(|f| f.replace(".c", ".o")));
    link.extend(["table.o".into(), "driver.o".into()]);
    link.extend(rt_objects().iter().map(|p| p.display().to_string()));
    cc(&dir, &link);

    let mut stdin_text = String::new();
    for (k, (t, input)) in cases.iter().enumerate() {
        let inp = if input.is_empty() {
            "-".to_string()
        } else {
            hex(input)
        };
        let _ = writeln!(stdin_text, "{k} {} {inp}", hex(t));
    }
    let mut child = Command::new(dir.join("driver"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(stdin_text.as_bytes()));
    let o = child.wait_with_output().unwrap();
    let _ = writer.join().unwrap();
    let out = String::from_utf8(o.stdout).unwrap();
    let mut seen: Vec<Option<Seen>> = cases.iter().map(|_| None).collect();
    for l in out.lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let n = |i: usize| f[i].parse::<u64>().unwrap();
        seen[n(0) as usize] = Some(Seen {
            code: n(1) as u32,
            arg: n(2),
            r0: n(3),
            heap_used: n(4),
            stack: n(5),
            heap: n(6),
            input: n(7),
        });
    }
    assert!(
        o.status.success() && seen.iter().all(Option::is_some),
        "driver {name} failed ({}):\n{}",
        o.status,
        String::from_utf8_lossy(&o.stderr)
    );
    seen.into_iter().map(Option::unwrap).collect()
}

// ---- the comparison -------------------------------------------------------------------------------

/// Runs every `(program, input)` on both sides and asserts the translation equals the interpreter
/// exactly — the halt with its payload, `r0`, the allocator's cursor and every writable region —
/// returning the interpreter's results in order. `name` names the driver's directory under
/// `target/hostdiff/`, so it must be unique per test.
pub fn parity(name: &str, cases: &[(Vec<Insn>, Vec<u8>)]) -> Vec<Result<u64, Halt>> {
    let encoded: Vec<(Vec<u8>, Vec<u8>)> = cases
        .iter()
        .map(|(p, input)| (text(p), input.clone()))
        .collect();
    let c = run_c(name, &encoded);
    let mut results = Vec::with_capacity(cases.len());
    for (k, ((t, input), c)) in encoded.iter().zip(&c).enumerate() {
        let (result, seen, _) = interpret(t, input);
        assert_eq!(
            &seen,
            c,
            "{name} program {k}: interpreter {result:?} left {seen:?}, translated {c:?}\n{}",
            translate(t)
        );
        results.push(result);
    }
    results
}

/// [`parity`] over programs with an empty input region.
pub fn parity_bare(name: &str, programs: &[Vec<Insn>]) -> Vec<Result<u64, Halt>> {
    let cases: Vec<(Vec<Insn>, Vec<u8>)> =
        programs.iter().map(|p| (p.clone(), Vec::new())).collect();
    parity(name, &cases)
}
