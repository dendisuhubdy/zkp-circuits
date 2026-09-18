//! Differential fuzzing (Task 5): random well-formed programs (`src/gen.rs`) run through the
//! interpreter (`sbpf_core::interp`) and through the emitted C compiled for the host with `sbpf-rt`
//! (`cc`, no zkVM: the C is target-independent apart from the setjmp pair and the SHA-256
//! compression, which `sbpf-rt/test/host_glue.c` supplies), and the two must agree on
//!
//! * the halt kind **with its payload** (the faulting address, the opcode, the hash, the trap), and
//!   `r0` on a normal exit;
//! * the stack, the heap and the input region afterwards (byte for byte, as FNV-1a digests) and the
//!   allocator's cursor — except when either side reports `InstructionLimit`, where the run stopped
//!   at different points by design.
//!
//! Two differences are accepted, and each is asserted rather than skipped:
//!
//! * **The instruction limit** (Global Constraints, as amended in Task 3 and ruled final in Task 4):
//!   the translation charges a block at its head, or defers the check of a block to its successors.
//!   The host build records the count the translation had charged when it stopped (the emitted
//!   `SBPF_AT_LIMIT` hook at `L_limit`). When only the translation stopped, that count must be
//!   exactly the head-check arithmetic of a checked block holding the interpreter's stopping pc, and
//!   the meter within one block, plus one unchecked predecessor block, of the limit
//!   ([`limit_window`]); when both stopped at a checked block, it must be that block's count
//!   exactly; and when it is the interpreter that stopped, the pc it stopped at must lie in a block
//!   the translation leaves unchecked. Budget cases sized to end a few hundred instructions below
//!   the limit must be exactly equal.
//! * **A `callx` to real code that is not a known function entry** (Task 5 ruling 3): the
//!   translation halts `BadJump` at the `callx`. The generator reaches such code in exactly one way —
//!   the *pad* — which halts `AccessViolation(MAGIC)` in the interpreter, so that pair, and only it,
//!   is accepted.
//!
//! The corpus is `FUZZ_CASES` cases (default 10 000), seeds `FUZZ_SEED_BASE..` (default 0), so
//! every case is replayable from its seed alone (`FUZZ_ONLY=<seed>` runs one and prints its program and C). All
//! C is compiled in batches: one `cc` invocation per batch of files, one driver process per batch,
//! batches in parallel. A second test runs the first 1 000 seeds again under ASan and UBSan
//! (`FUZZ_SANITIZED_CASES` to change that).
//!
//! Every divergence found while writing this became a directed test at the end of this file.

#[path = "../src/gen.rs"]
#[allow(dead_code)]
mod gen;

use gen::{assemble, case, input_region, Case, Mix, MAGIC, MARK_BASE, MARK_BYTES, NAMED};
use sbpf2rv::emit::emit_program;
use sbpf2rv::scan::{scan, Scan};
use sbpf_core::elf::Program;
use sbpf_core::interp::{Halt, Vm, MAX_INSTRUCTIONS};
use sbpf_core::isa::{self, opc};
use sbpf_core::memory::{Memory, HEAP_BYTES, REGION_HEAP, REGION_PROGRAM, STACK_BYTES};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

const HALT_EXIT: u32 = 0;
const HALT_AV: u32 = 1;
const HALT_BAD_INSN: u32 = 2;
const HALT_DIV: u32 = 3;
const HALT_UNKNOWN_SYSCALL: u32 = 4;
const HALT_CALL_DEPTH: u32 = 5;
const HALT_LIMIT: u32 = 6;
const HALT_BAD_JUMP: u32 = 8;
const HALT_TRAP: u32 = 10;

/// `Result<u64, Halt>` as `(code, payload)` — `sbpf-rt`'s `SBPF_HALT_*` numbering (the enum's
/// declaration order, which research's `sbpf_rt` test checks) and its `SBPF_TRAP_*` indices.
fn halt_code(r: &Result<u64, Halt>) -> (u32, u64) {
    const TRAPS: [&str; 3] = ["abort", "sol_panic_", "sol_memcpy_ overlap"];
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

fn fnv(b: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &x in b {
        h = (h ^ u64::from(x)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// What a run left, on either side.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Seen {
    code: u32,
    arg: u64,
    r0: u64,
    heap_used: u64,
    stack: u64,
    heap: u64,
    input: u64,
}

/// The interpreter's run, plus what only it can tell: the meter and the pc it stopped at, and the
/// coverage marks.
struct Interp {
    seen: Seen,
    meter: u64,
    pc: u64,
    marks: Vec<u8>,
}

fn interpret(text: &[u8], data: &[u8]) -> Interp {
    let p = Program::from_text(text).unwrap();
    let mut stack = vec![0u8; STACK_BYTES].into_boxed_slice();
    let mut heap = vec![0u8; HEAP_BYTES].into_boxed_slice();
    let mut input = input_region(data);
    let (result, meter, pc, heap_used) = {
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
        (r, vm.instructions_executed(), vm.pc, vm.heap_used)
    };
    let (code, arg) = halt_code(&result);
    let m = (MARK_BASE - REGION_HEAP) as usize;
    let marks = heap[m..m + MARK_BYTES as usize].to_vec();
    Interp {
        seen: Seen {
            code,
            arg,
            r0: *result.as_ref().unwrap_or(&0),
            heap_used: heap_used as u64,
            stack: fnv(&stack),
            heap: fnv(&heap),
            input: fnv(&input),
        },
        meter,
        pc,
        marks,
    }
}

/// One case, ready to run on both sides.
struct Prepared {
    seed: u64,
    budget: bool,
    /// A budget case sized to end a few hundred instructions below the limit: only
    /// [`Verdict::Equal`], with neither side at the limit, is acceptable.
    below: bool,
    text: Vec<u8>,
    data: Vec<u8>,
    c: String,
    scan: Scan,
}

/// Assembles `c` at the host's text address. A budget case's parameters are chosen so the run's
/// last instruction (its planned fault, or `exit`) lands a few instructions either side of the
/// limit, or (one in eight) 200 to 499 below it: the count is `m0 + per·(T − 1) + 2·(P − 1) + C`
/// (`gen::budget_body`), measured here — the affinity itself asserted — and solved for.
fn prepare(c: &Case) -> Prepared {
    let (text, _) = assemble(&c.items, REGION_PROGRAM);
    let mut data = c.data.clone();
    let mut below = false;
    if c.budget {
        let count = |t: u64, p: u64, k: u64| {
            let mut d = data.clone();
            for (i, v) in [t, p, k].into_iter().enumerate() {
                d[8 + 8 * i..16 + 8 * i].copy_from_slice(&v.to_le_bytes());
            }
            interpret(&text, &d).meter
        };
        let m0 = count(1, 1, 0);
        let per = count(2, 1, 0) - m0;
        assert_eq!(count(1, 2, 0), m0 + 2, "seed {}: not affine in P", c.seed);
        assert_eq!(count(1, 1, 1), m0 + 1, "seed {}: not affine in C", c.seed);
        assert_eq!(
            count(3, 1, 0),
            m0 + 2 * per,
            "seed {}: not affine in T",
            c.seed
        );
        let mut r = Mix(c.seed ^ 0xb0d6e7);
        // Exactly at the limit, or one past it, a quarter of the time; a few hundred below it an
        // eighth of the time; else anywhere within 12.
        let target = match r.below(8) {
            0 => MAX_INSTRUCTIONS,
            1 => MAX_INSTRUCTIONS + 1,
            2 => {
                below = true;
                MAX_INSTRUCTIONS - 200 - r.below(300)
            }
            _ => MAX_INSTRUCTIONS + r.below(25) - 12,
        };
        let t = ((target - m0) / per).saturating_sub(1);
        let rem = target - m0 - per * t;
        let (p, k) = (rem / 2, rem % 2);
        for (i, v) in [t + 1, p + 1, k].into_iter().enumerate() {
            data[8 + 8 * i..16 + 8 * i].copy_from_slice(&v.to_le_bytes());
        }
    }
    let p = Program::from_text(&text).unwrap();
    let s = scan(&p);
    let c_src = emit_program(&p, &s).c;
    Prepared {
        seed: c.seed,
        budget: c.budget,
        below,
        text,
        data,
        c: c_src,
        scan: s,
    }
}

// ---- the host build -------------------------------------------------------------------------------

fn rt_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../sbpf-rt")
}

fn work(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/fuzz")
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Reads `<idx> <text hex> <input hex>` per line, runs entry `idx` over those regions, prints
/// `<idx> <code> <arg> <r0> <heap_used> <stack fnv> <heap fnv> <input fnv> <budget at L_limit>` —
/// the last is what the emitted `SBPF_AT_LIMIT` hook recorded ([`AT_LIMIT_HOOK`]), or `LLONG_MIN`
/// if no `L_limit` ran.
const DRIVER: &str = r#"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sbpf_rt.h"

typedef uint32_t (*entry_t)(uint64_t *);
extern const entry_t fuzz_entries[];

static uint8_t text[1 << 20], input[1 << 16], stack[SBPF_STACK_BYTES], heap[SBPF_HEAP_BYTES];
long long sbpf_fuzz_at_limit;

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
        size_t tl = unhex(text, t), il = unhex(input, in);
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
        sbpf_fuzz_at_limit = LLONG_MIN;
        uint64_t r0 = 0;
        uint32_t code = fuzz_entries[idx](&r0);
        printf("%d %u %llu %llu %u %llu %llu %llu %lld\n", idx, code, (unsigned long long)sbpf_halt_arg,
               (unsigned long long)r0, sbpf_heap_used, (unsigned long long)fnv(stack, sizeof stack),
               (unsigned long long)fnv(heap, sizeof heap), (unsigned long long)fnv(input, il),
               sbpf_fuzz_at_limit);
        fflush(stdout);
    }
    free(line);
    return 0;
}
"#;

fn cc(dir: &Path, args: &[&str], sanitize: bool) {
    let mut c = Command::new("cc");
    c.current_dir(dir).args(args);
    if sanitize {
        c.args([
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
        ]);
    }
    let o = c.output().expect("a host C compiler (`cc`)");
    assert!(
        o.status.success(),
        "cc {args:?} in {}:\n{}",
        dir.display(),
        String::from_utf8_lossy(&o.stderr)
    );
}

/// Defines the emitted C's `SBPF_AT_LIMIT` hook (empty in every real build) to record the
/// function-local budget at `L_limit`, for the driver to print.
const AT_LIMIT_HOOK: &str = "extern long long sbpf_fuzz_at_limit;\n\
     #define SBPF_AT_LIMIT(budget) (sbpf_fuzz_at_limit = (long long)(budget))\n";

/// What the translation did on one case: what it left, and the instruction count it had charged
/// when it stopped at an `L_limit` (`MAX_INSTRUCTIONS` minus the recorded budget), if it did.
struct CRun {
    seen: Seen,
    at_limit: Option<u64>,
}

/// Builds one driver over `batch`'s programs and runs every case through it.
fn run_c(name: &str, batch: &[&Prepared], sanitize: bool) -> Vec<CRun> {
    let dir = work(name);
    let mut table = String::from("#include <stdint.h>\ntypedef uint32_t (*entry_t)(uint64_t *);\n");
    let mut files: Vec<String> = Vec::new();
    for (k, p) in batch.iter().enumerate() {
        let f = format!("c{k}.c");
        std::fs::write(
            dir.join(&f),
            format!("#define sbpf_entry sbpf_entry_{k}\n{AT_LIMIT_HOOK}{}", p.c),
        )
        .unwrap();
        files.push(f);
        let _ = writeln!(table, "uint32_t sbpf_entry_{k}(uint64_t *);");
    }
    table.push_str("const entry_t fuzz_entries[] = {\n");
    for k in 0..batch.len() {
        let _ = writeln!(table, "    sbpf_entry_{k},");
    }
    table.push_str("};\n");
    std::fs::write(dir.join("table.c"), table).unwrap();
    std::fs::write(dir.join("driver.c"), DRIVER).unwrap();
    let rt = rt_dir();
    let inc = format!("-I{}", rt.display());
    let mut args: Vec<String> = vec!["-Os".into(), "-w".into(), inc, "-c".into()];
    args.extend(files.iter().cloned());
    args.extend(["table.c".into(), "driver.c".into()]);
    args.push(rt.join("sbpf_rt.c").display().to_string());
    args.push(rt.join("test/host_glue.c").display().to_string());
    cc(
        &dir,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        sanitize,
    );
    let mut objs: Vec<String> = files.iter().map(|f| f.replace(".c", ".o")).collect();
    objs.extend(
        ["table.o", "driver.o", "sbpf_rt.o", "host_glue.o"]
            .iter()
            .map(|s| s.to_string()),
    );
    let mut link = vec!["-o".to_string(), "driver".into()];
    link.extend(objs);
    cc(
        &dir,
        &link.iter().map(String::as_str).collect::<Vec<_>>(),
        sanitize,
    );

    let mut input = String::new();
    for (k, p) in batch.iter().enumerate() {
        let _ = writeln!(
            input,
            "{k} {} {}",
            hex(&p.text),
            hex(&input_region(&p.data))
        );
    }
    let mut child = Command::new(dir.join("driver"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let o = child.wait_with_output().unwrap();
    let _ = writer.join().unwrap();
    let out = String::from_utf8(o.stdout).unwrap();
    let mut seen: Vec<Option<CRun>> = batch.iter().map(|_| None).collect();
    for l in out.lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let n = |i: usize| f[i].parse::<u64>().unwrap();
        let budget: i64 = f[8].parse().unwrap();
        seen[n(0) as usize] = Some(CRun {
            seen: Seen {
                code: n(1) as u32,
                arg: n(2),
                r0: n(3),
                heap_used: n(4),
                stack: n(5),
                heap: n(6),
                input: n(7),
            },
            at_limit: (budget != i64::MIN).then(|| (MAX_INSTRUCTIONS as i64 - budget) as u64),
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

/// One emitted block: the C function it is in, its label, its charge, whether it checks.
struct CBlock {
    func: usize,
    start: usize,
    charge: u64,
    checked: bool,
}

/// Every labelled block of the emitted C, with its charge line (`if ((budget -= n) < 0) goto
/// L_limit;` checks, `budget -= n;` only charges, no line charges nothing).
fn c_blocks(c: &str) -> Vec<CBlock> {
    let mut v = Vec::new();
    let mut func = usize::MAX;
    let mut lines = c.lines().peekable();
    while let Some(l) = lines.next() {
        if let Some(rest) = l.strip_prefix("SBPF_FN f_") {
            if l.ends_with('{') {
                func = rest.split('(').next().unwrap().parse().unwrap();
            }
            continue;
        }
        let Some(pc) = l.strip_prefix("L_").and_then(|r| r.strip_suffix(':')) else {
            continue;
        };
        let Ok(start) = pc.parse::<usize>() else {
            continue; // L_limit
        };
        let next = lines.peek().map_or("", |n| n.trim_start());
        let num = |r: &str| {
            r.split(|ch: char| !ch.is_ascii_digit())
                .next()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        };
        let (charge, checked) = if let Some(r) = next.strip_prefix("if ((budget -= ") {
            (num(r), true)
        } else if let Some(r) = next.strip_prefix("budget -= ") {
            (num(r), false)
        } else {
            (0, true)
        };
        v.push(CBlock {
            func,
            start,
            charge,
            checked,
        });
    }
    v
}

/// The instruction starts of a scanned block, as the emitter walks them (`lddw` is one).
fn starts(b: &sbpf2rv::scan::Block) -> Vec<usize> {
    let mut pc = b.start;
    b.insns
        .iter()
        .map(|i| {
            let here = pc;
            pc += if i.opc == opc::LD_DW_IMM { 2 } else { 1 };
            here
        })
        .collect()
}

/// Every emitted block the interpreter's stopping pc `pc` may lie in (one per C function whose code
/// contains it), with how many of its instructions run before `pc`.
fn blocks_containing(p: &Prepared, pc: u64) -> Vec<(CBlock, u64)> {
    let n_slots = (p.text.len() / 8) as u64;
    let cb = c_blocks(&p.c);
    let mut out = Vec::new();
    for f in &p.scan.functions {
        for b in &f.blocks {
            let st = starts(b);
            let here = if pc >= n_slots {
                // The shared trap block of a jump out of the text.
                b.insns.is_empty() && b.start as u64 >= n_slots
            } else {
                (b.start as u64..=b.end as u64).contains(&pc)
                    && (st.contains(&(pc as usize)) || b.end as u64 == pc)
            };
            if !here {
                continue;
            }
            // The emitted block: this C function's last label at or before `pc` inside `b` (a
            // merged member's entry splits a scanned block).
            let label = cb
                .iter()
                .filter(|c| {
                    c.func == f.entry
                        && c.start >= b.start
                        && (c.start as u64 <= pc || pc >= n_slots)
                })
                .max_by_key(|c| c.start);
            if let Some(c) = label {
                let before = st
                    .iter()
                    .filter(|&&s| s >= c.start && (s as u64) < pc)
                    .count() as u64;
                out.push((
                    CBlock {
                        func: c.func,
                        start: c.start,
                        charge: c.charge,
                        checked: c.checked,
                    },
                    before,
                ));
            }
        }
    }
    out
}

/// Ruling 1's loose bound, which the exact check in [`compare`] implies: the largest block
/// containing `pc` plus its largest in-function predecessor, each with one extra instruction for a
/// failed fetch.
fn limit_window(s: &Scan, pc: u64) -> u64 {
    let mut w = 1;
    for f in &s.functions {
        for b in &f.blocks {
            if (b.start as u64..=b.end as u64).contains(&pc) {
                let pred = f
                    .blocks
                    .iter()
                    .filter(|p| {
                        use sbpf2rv::scan::Term::*;
                        match p.term {
                            Fallthrough(n) | Jump(n) | Syscall { next: n, .. } => n == b.start,
                            CondJump { taken, not } => taken == b.start || not == b.start,
                            Call { next, .. } | CallX { next } => next == b.start,
                            _ => false,
                        }
                    })
                    .map(|p| p.insns.len() as u64 + 1)
                    .max()
                    .unwrap_or(0);
                w = w.max(b.insns.len() as u64 + 1 + pred);
            }
        }
    }
    w
}

/// How the two runs relate: equal, or one of the two accepted differences (checked here), or a
/// divergence (`Err`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    Equal,
    /// The translation stopped at the limit; the interpreter faulted or exited just before it.
    LimitTranslationOnly,
    /// The interpreter stopped at the limit; the translation, in an unchecked block, faulted.
    LimitInterpreterOnly,
    CallxNonEntry,
}

fn compare(p: &Prepared, i: &Interp, run: &CRun) -> Result<Verdict, String> {
    let a = &i.seen;
    let c = &run.seen;
    // The count the translation stopped at, recorded at `L_limit`: present exactly when it halted
    // there, and past the limit, or the head check itself is wrong.
    let count = match (c.code == HALT_LIMIT, run.at_limit) {
        (true, Some(n)) if n > MAX_INSTRUCTIONS => Some(n),
        (false, None) => None,
        (_, n) => {
            return Err(format!(
                "translated {c:?} with count at L_limit {n:?}: an InstructionLimit halt comes from \
                 an L_limit, after charging past {MAX_INSTRUCTIONS}, and nothing else does"
            ))
        }
    };
    if a.code == c.code && a.arg == c.arg && (a.code != HALT_EXIT || a.r0 == c.r0) {
        if a.code == HALT_LIMIT {
            // Both stopped: the interpreter before `pc` (its meter at the limit). If every emitted
            // block holding `pc` checks at its head, the translation stopped at that head, having
            // charged exactly what ran before `pc` in the block plus the block's whole count. (If
            // one only charges, the translation ran on to a later head; the count is only bounded.)
            let n = count.unwrap();
            let bs = blocks_containing(p, i.pc);
            if !bs.is_empty()
                && bs.iter().all(|(b, _)| b.checked)
                && !bs
                    .iter()
                    .any(|(b, before)| MAX_INSTRUCTIONS - before + b.charge == n)
            {
                return Err(format!(
                    "both at the limit (interpreter before pc {}), but the translation stopped at \
                     count {n}, which no checked block holding pc charges to",
                    i.pc
                ));
            }
            return Ok(Verdict::Equal);
        }
        if a == c {
            return Ok(Verdict::Equal);
        }
        return Err(format!(
            "same halt, different memory: interpreter {a:?}, translated {c:?}"
        ));
    }
    if a.code == HALT_AV && a.arg == MAGIC && c.code == HALT_BAD_JUMP {
        return Ok(Verdict::CallxNonEntry);
    }
    if let Some(n) = count {
        // The translation stops at the head of a checked block B exactly when the count at B's
        // start plus B's charge passes the limit, and the count it recorded there is that sum. The
        // interpreter stopped inside B, at `pc`, having run `before + 1` of B's instructions (its
        // meter counts the one at `pc`).
        let exact = blocks_containing(p, i.pc).iter().any(|(b, before)| {
            b.checked && i.meter > *before && i.meter - before - 1 + b.charge == n
        });
        let w = limit_window(&p.scan, i.pc);
        if exact && MAX_INSTRUCTIONS - i.meter < w {
            return Ok(Verdict::LimitTranslationOnly);
        }
        return Err(format!(
            "translated InstructionLimit at count {n}, interpreter {a:?} at meter {} (pc {}), {} \
             before the limit (window {w}, head check at exactly that count: {exact})",
            i.meter,
            i.pc,
            MAX_INSTRUCTIONS - i.meter
        ));
    }
    if a.code == HALT_LIMIT {
        // The interpreter stopped before running `pc`; the translation ran on only if `pc` lies in
        // a block that only charges, and then it must have faulted before the next check.
        let unchecked = blocks_containing(p, i.pc).iter().any(|(b, _)| !b.checked);
        if c.code != HALT_EXIT && unchecked {
            return Ok(Verdict::LimitInterpreterOnly);
        }
        return Err(format!(
            "interpreter InstructionLimit before pc {} (in no unchecked block, or the translation \
             exited), translated {c:?}",
            i.pc
        ));
    }
    Err(format!("interpreter {a:?}, translated {c:?}"))
}

/// The other accepted limit difference, rechecked on a budget case: the interpreter stopped at the
/// limit and the translation, in an unchecked block, faulted. With fewer loop trips the interpreter
/// reaches that fault inside the limit; it must be the translation's, payload included (every
/// budget-case fault's payload is a constant).
fn recheck_fault(p: &Prepared, c: &Seen) -> Result<(), String> {
    let t = u64::from_le_bytes(p.data[8..16].try_into().unwrap());
    // A trip is at least 3 instructions and the run overshoots by at most 12 plus a block: 42
    // fewer trips always bring the fault inside the limit.
    let fewer = t.saturating_sub(42).max(1);
    let mut d = p.data.clone();
    d[8..16].copy_from_slice(&fewer.to_le_bytes());
    let i = interpret(&p.text, &d);
    if (i.seen.code, i.seen.arg) == (c.code, c.arg) && c.code != HALT_LIMIT {
        Ok(())
    } else {
        Err(format!(
            "interpreter at the limit, translated {c:?}; with {fewer} trips instead of {t} the \
             interpreter gives {:?}",
            i.seen
        ))
    }
}

/// A failure as a replayable program: the seed, the text as slot words, the data, a listing.
fn replay(p: &Prepared) -> String {
    let words: Vec<String> = p
        .text
        .chunks(8)
        .map(|c| format!("{:#018x}", u64::from_le_bytes(c.try_into().unwrap())))
        .collect();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/fuzz/failures");
    let _ = std::fs::create_dir_all(&dir);
    let cpath = dir.join(format!("seed-{}.c", p.seed));
    let _ = std::fs::write(&cpath, &p.c);
    format!(
        "seed {} (FUZZ_ONLY={} replays it; C in {})\ntext: &[{}]\ndata: \"{}\"\n{}",
        p.seed,
        p.seed,
        cpath.display(),
        words.join(", "),
        hex(&p.data),
        gen::disassemble(&p.text)
    )
}

// ---- coverage ---------------------------------------------------------------------------------------

/// The terminal classes of a halt: the halt, refined by the instruction the interpreter stopped at.
fn halt_classes(p: &Prepared, i: &Interp) -> Vec<String> {
    let a = &i.seen;
    let n_slots = (p.text.len() / 8) as u64;
    let at = (i.pc < n_slots).then(|| {
        let k = i.pc as usize * 8;
        isa::decode(u64::from_le_bytes(p.text[k..k + 8].try_into().unwrap()))
    });
    let op = at.map(|x| x.opc);
    let width = |o: u8| match o {
        opc::LD_B_REG | opc::ST_B_IMM | opc::ST_B_REG => Some(1u64),
        opc::LD_H_REG | opc::ST_H_IMM | opc::ST_H_REG => Some(2),
        opc::LD_W_REG | opc::ST_W_IMM | opc::ST_W_REG => Some(4),
        opc::LD_DW_REG | opc::ST_DW_IMM | opc::ST_DW_REG => Some(8),
        _ => None,
    };
    let one = |s: &str| vec![s.to_string()];
    match a.code {
        HALT_EXIT => vec![],
        HALT_AV if a.arg == MAGIC => one("halt:callx to non-entry code (accepted BadJump)"),
        HALT_AV => match op.and_then(width) {
            Some(w) => {
                let (region, off) = (a.arg >> 32, a.arg & 0xffff_ffff);
                let len = match region {
                    1 => p.text.len() as u64,
                    2 => STACK_BYTES as u64,
                    3 => HEAP_BYTES as u64,
                    4 => gen::INPUT_LEN,
                    _ => 0,
                };
                let load = matches!(
                    op,
                    Some(opc::LD_B_REG | opc::LD_H_REG | opc::LD_W_REG | opc::LD_DW_REG)
                );
                let name = ["", "program", "stack", "heap", "input"];
                vec![
                    format!(
                        "halt:AccessViolation, {}",
                        if load { "load" } else { "store" }
                    ),
                    format!("halt:AccessViolation, width {w}"),
                    if off < len && off + w > len {
                        format!(
                            "halt:AccessViolation, straddling the {} region's end",
                            name[region as usize]
                        )
                    } else {
                        "halt:AccessViolation, outside every region".into()
                    },
                ]
            }
            None => one("halt:AccessViolation, in a syscall"),
        },
        HALT_BAD_INSN => one(match a.arg as u8 {
            opc::LE | opc::BE => "halt:BadInsn, le/be width",
            o if isa::classify(o).is_none() => "halt:BadInsn, v2 or unassigned opcode",
            opc::CALL_REG => "halt:BadInsn, callx register above r10",
            opc::CALL_IMM if at.is_some_and(|x| x.src <= 10 && x.dst <= 10) => {
                "halt:BadInsn, call imm with src 2..10"
            }
            _ => "halt:BadInsn, register nibble above r10",
        }),
        HALT_DIV => one(match op {
            Some(o) if o & 0x08 != 0 => "halt:DivByZero, by register",
            _ => "halt:DivByZero, by immediate",
        }),
        HALT_UNKNOWN_SYSCALL => one("halt:UnknownSyscall"),
        HALT_CALL_DEPTH => one("halt:CallDepth"),
        HALT_LIMIT => one("halt:InstructionLimit"),
        HALT_BAD_JUMP => one(match op {
            Some(opc::CALL_REG) => "halt:BadJump, callx to non-code",
            Some(opc::CALL_IMM) => "halt:BadJump, call out of the text",
            Some(opc::EXIT) => "halt:BadJump, return to past the text",
            Some(opc::LD_DW_IMM) => "halt:BadJump, lddw in the last slot",
            _ => "halt:BadJump, jump or fall out of the text",
        }),
        HALT_TRAP => one([
            "halt:Trap abort",
            "halt:Trap sol_panic_",
            "halt:Trap sol_memcpy_ overlap",
        ][a.arg as usize]),
        other => vec![format!("halt:code {other}")],
    }
}

/// Every class the generator must reach at least 100 times in a 10 000-case run (ruling 2): every
/// opcode `isa::classify` assigns (`exit` is `exit:callee`), every named pattern, every halt.
fn required_classes() -> Vec<String> {
    let mut v: Vec<String> = (0..=255u8)
        .filter(|&o| isa::classify(o).is_some() && o != opc::EXIT)
        .map(|o| format!("op {o:#04x}"))
        .collect();
    // The budget cases are about 1% of the corpus, so their own sub-classes are reported, not
    // required.
    v.extend(
        NAMED
            .iter()
            .filter(|n| !n.starts_with("budget:"))
            .map(|n| n.to_string()),
    );
    let halts = [
        "halt:AccessViolation, load",
        "halt:AccessViolation, store",
        "halt:AccessViolation, width 1",
        "halt:AccessViolation, width 2",
        "halt:AccessViolation, width 4",
        "halt:AccessViolation, width 8",
        "halt:AccessViolation, outside every region",
        "halt:AccessViolation, straddling the program region's end",
        "halt:AccessViolation, straddling the stack region's end",
        "halt:AccessViolation, straddling the heap region's end",
        "halt:AccessViolation, straddling the input region's end",
        "halt:AccessViolation, in a syscall",
        "halt:BadInsn, le/be width",
        "halt:BadInsn, v2 or unassigned opcode",
        "halt:BadInsn, callx register above r10",
        "halt:BadInsn, call imm with src 2..10",
        "halt:BadInsn, register nibble above r10",
        "halt:DivByZero, by register",
        "halt:DivByZero, by immediate",
        "halt:UnknownSyscall",
        "halt:CallDepth",
        "budget case",
        "halt:BadJump, callx to non-code",
        "halt:BadJump, call out of the text",
        "halt:BadJump, jump or fall out of the text",
        "halt:BadJump, return to past the text",
        "halt:BadJump, lddw in the last slot",
        "halt:Trap abort",
        "halt:Trap sol_panic_",
        "halt:Trap sol_memcpy_ overlap",
        "halt:callx to non-entry code (accepted BadJump)",
    ];
    v.extend(halts.iter().map(|s| s.to_string()));
    v
}

/// The classes a case executed, read off its marks — or an error if the marks cannot be trusted.
/// The page is out of every program write's reach by construction (`gen`'s module docs): `main`
/// allocates it first, so no allocator block can overlap it, which holds exactly when the cursor
/// is at least the page's size (the first block on an empty heap is the heap's first bytes); and
/// nothing but a mark writes there, so every byte is 0 or 1. Either failing means a mark could
/// have been set by something other than the code it names, and the case fails rather than
/// counting.
fn classes_of(p: &Prepared, i: &Interp) -> Result<Vec<String>, String> {
    if MARK_BASE != REGION_HEAP || i.seen.heap_used < MARK_BYTES {
        return Err(format!(
            "the coverage page was not the allocator's first block (cursor {:#x}): its marks \
             cannot be trusted",
            i.seen.heap_used
        ));
    }
    if let Some((id, m)) = i.marks.iter().enumerate().find(|(_, &m)| m > 1) {
        return Err(format!(
            "coverage byte {id} is {m}: something other than a mark wrote the page"
        ));
    }
    let mut v: Vec<String> = Vec::new();
    for (id, &m) in i.marks.iter().enumerate() {
        if m != 0 {
            if id < 256 {
                v.push(format!("op {id:#04x}"));
            } else {
                match NAMED.get(id - 256) {
                    Some(n) => v.push(n.to_string()),
                    None => return Err(format!("coverage byte {id} is set: no class has it")),
                }
            }
        }
    }
    v.extend(halt_classes(p, i));
    if p.budget {
        v.push("budget case".into());
    }
    if p.below {
        v.push("budget:a few hundred below the limit".into());
    }
    Ok(v)
}

// ---- the run ----------------------------------------------------------------------------------------

struct Totals {
    cases: usize,
    verdicts: BTreeMap<String, usize>,
    classes: BTreeMap<String, usize>,
    failures: Vec<String>,
}

fn fuzz(seeds: &[u64], batch: usize, tag: &str, sanitize: bool) -> Totals {
    let t0 = Instant::now();
    let chunks: Vec<&[u64]> = seeds.chunks(batch).collect();
    let next = AtomicUsize::new(0);
    let totals = Mutex::new(Totals {
        cases: 0,
        verdicts: BTreeMap::new(),
        classes: BTreeMap::new(),
        failures: Vec::new(),
    });
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let k = next.fetch_add(1, Ordering::SeqCst);
                if k >= chunks.len() {
                    break;
                }
                let prepared: Vec<Prepared> =
                    chunks[k].iter().map(|&s| prepare(&case(s))).collect();
                let interp: Vec<Interp> = prepared
                    .iter()
                    .map(|p| interpret(&p.text, &p.data))
                    .collect();
                let refs: Vec<&Prepared> = prepared.iter().collect();
                let c = run_c(&format!("{tag}-{k}"), &refs, sanitize);
                let mut verdicts = Vec::new();
                let mut failures = Vec::new();
                let mut pads = Vec::new();
                for ((p, i), c) in prepared.iter().zip(&interp).zip(&c) {
                    match compare(p, i, c) {
                        Ok(v) if p.below && (v != Verdict::Equal || i.seen.code == HALT_LIMIT) => {
                            failures.push(format!(
                                "a run a few hundred instructions below the limit (meter {}): \
                                 {v:?}, interpreter {:?}, translated {:?}\n{}",
                                i.meter,
                                i.seen,
                                c.seen,
                                replay(p)
                            ))
                        }
                        Ok(v) => {
                            verdicts.push(format!("{v:?}"));
                            match v {
                                Verdict::CallxNonEntry => {
                                    pads.push(prepare(&gen::with_pad_named(&case(p.seed))))
                                }
                                Verdict::LimitInterpreterOnly if p.budget => {
                                    match recheck_fault(p, &c.seen) {
                                        Ok(()) => verdicts.push(
                                            "LimitInterpreterOnly, rechecked with fewer trips"
                                                .into(),
                                        ),
                                        Err(e) => failures.push(format!("{e}\n{}", replay(p))),
                                    }
                                }
                                _ => {}
                            }
                        }
                        Err(e) => failures.push(format!("{e}\n{}", replay(p))),
                    }
                }
                // The accepted `callx` divergence, rechecked: with the pad named, both sides must
                // agree exactly — so the translation's BadJump was that `callx` and nothing else.
                if !pads.is_empty() {
                    let refs: Vec<&Prepared> = pads.iter().collect();
                    let c = run_c(&format!("{tag}-{k}-pad"), &refs, sanitize);
                    for (p, c) in pads.iter().zip(&c) {
                        let i = interpret(&p.text, &p.data);
                        let v = compare(p, &i, c);
                        if v != Ok(Verdict::Equal) || i.seen.code != HALT_AV || i.seen.arg != MAGIC
                        {
                            failures.push(format!(
                                "with the pad named: {v:?}, interpreter {:?}\n{}",
                                i.seen,
                                replay(p)
                            ));
                        } else {
                            verdicts.push("CallxNonEntry, rechecked with the pad named".into());
                        }
                    }
                }
                let mut t = totals.lock().unwrap();
                t.cases += prepared.len();
                for v in verdicts {
                    *t.verdicts.entry(v).or_default() += 1;
                }
                t.failures.extend(failures);
                for (p, i) in prepared.iter().zip(&interp) {
                    match classes_of(p, i) {
                        Ok(classes) => {
                            for class in classes {
                                *t.classes.entry(class).or_default() += 1;
                            }
                        }
                        Err(e) => t.failures.push(format!("{e}\n{}", replay(p))),
                    }
                }
            });
        }
    });
    let t = totals.into_inner().unwrap();
    eprintln!(
        "fuzz {tag}: {} cases in {:.1} s ({} threads, batches of {batch}{})",
        t.cases,
        t0.elapsed().as_secs_f64(),
        threads,
        if sanitize { ", ASan+UBSan" } else { "" }
    );
    t
}

fn cases_wanted() -> u64 {
    std::env::var("FUZZ_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000)
}

/// `FUZZ_SEED_BASE`: where the seed range starts (default 0), so a run can cover fresh seeds
/// without replaying the default corpus.
fn seed_base() -> u64 {
    std::env::var("FUZZ_SEED_BASE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// The corpus: seeds `FUZZ_SEED_BASE..+FUZZ_CASES` (default `0..10 000`), every one equal (or one
/// of the two accepted differences), and every class of ruling 2 reached at least 100 times in any
/// run of 10 000 or more.
#[test]
fn the_translation_matches_the_interpreter_on_random_programs() {
    if let Ok(only) = std::env::var("FUZZ_ONLY") {
        let seed: u64 = only.parse().unwrap();
        let p = prepare(&case(seed));
        let i = interpret(&p.text, &p.data);
        let c = &run_c("only", &[&p], false)[0];
        eprintln!("{}\n{}", replay(&p), p.c);
        eprintln!(
            "interpreter {:?} meter {} pc {}\ntranslated  {:?} (count at L_limit {:?})",
            i.seen, i.meter, i.pc, c.seen, c.at_limit
        );
        compare(&p, &i, c).unwrap();
        return;
    }
    let n = cases_wanted();
    let seeds: Vec<u64> = (seed_base()..seed_base() + n).collect();
    let t = fuzz(&seeds, 200, "corpus", false);
    eprintln!("verdicts: {:?}", t.verdicts);
    eprintln!("classes reached (cases that executed each):");
    let required = required_classes();
    let mut short = Vec::new();
    for class in &required {
        let k = t.classes.get(class).copied().unwrap_or(0);
        eprintln!("  {k:6}  {class}");
        if k < 100 {
            short.push(format!("{class}: {k}"));
        }
    }
    for (class, k) in &t.classes {
        if !required.contains(class) {
            eprintln!("  {k:6}  {class} (not required)");
        }
    }
    assert!(
        t.failures.is_empty(),
        "{} of {} cases diverge; the first:\n{}",
        t.failures.len(),
        t.cases,
        t.failures[0]
    );
    if n >= 10_000 {
        assert!(
            short.is_empty(),
            "classes reached fewer than 100 times: {short:?}"
        );
    }
}

/// ASan and UBSan over the runtime and the emitted C, on the first 1 000 seeds from
/// `FUZZ_SEED_BASE` (`FUZZ_SANITIZED_CASES` changes the count).
#[test]
fn the_host_build_is_clean_under_asan_and_ubsan() {
    if std::env::var("FUZZ_ONLY").is_ok() {
        return;
    }
    let n = std::env::var("FUZZ_SANITIZED_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| cases_wanted().min(1_000));
    let seeds: Vec<u64> = (seed_base()..seed_base() + n).collect();
    let t = fuzz(&seeds, 100, "sanitized", true);
    assert!(t.failures.is_empty(), "{}", t.failures[0]);
}

// ---- directed tests: every divergence the fuzzer found, as the program that shows it ------------

/// Runs one program (slot words, host text address) over `data` on both sides and returns the
/// interpreter's result after asserting the translation equals it exactly (no accepted difference).
fn check_program(words: &[u64], data: &[u8]) -> Result<u64, Halt> {
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let p = Program::from_text(&text).unwrap();
    let s = scan(&p);
    let prepared = Prepared {
        seed: u64::MAX,
        budget: false,
        below: false,
        c: emit_program(&p, &s).c,
        text: text.clone(),
        data: data.to_vec(),
        scan: s,
    };
    let i = interpret(&text, data);
    let c = &run_c(
        &format!("directed-{:016x}", fnv(&text)),
        &[&prepared],
        false,
    )[0];
    assert_eq!(
        compare(&prepared, &i, c),
        Ok(Verdict::Equal),
        "interpreter {:?}, translated {:?}\n{}",
        i.seen,
        c.seen,
        prepared.c
    );
    match i.seen.code {
        HALT_EXIT => Ok(i.seen.r0),
        _ => Err(Halt::Exit), // the halt itself was compared above, payload included
    }
}

/// Fuzz seed 133. A `callx` copies back the union of what every `callx` target may write
/// (`callx_mod`), so it must also pass every one of those registers in: a target that does not write
/// one hands back what it was given. Here the `callx` lands on `B`, which touches nothing; `A`, the
/// other target, writes `r2`. The caller's `r2` (7) must survive the call. Before the fix `r2` went
/// in as 0 (no target *reads* it) and came back as 0.
#[test]
fn a_callx_passes_every_register_any_target_may_hand_back() {
    let va = REGION_PROGRAM;
    let words = [
        0x0000_0007_0000_02b7,                      // 0: mov r2, 7
        0x0000_0000_0000_0318 | (va + 8 * 6) << 32, // 1: lddw r3, B
        (va + 8 * 6) >> 32 << 32,                   // 2:   (high half)
        0x0000_0003_0000_008d,                      // 3: callx r3
        0x0000_0000_0000_20bf,                      // 4: mov r0, r2
        0x0000_0000_0000_0095,                      // 5: exit
        0x0000_0001_0000_00b7,                      // 6: B: mov r0, 1
        0x0000_0000_0000_0095,                      // 7: exit
        0x0000_0005_0000_02b7,                      // 8: A: mov r2, 5
        0x0000_0000_0000_0095,                      // 9: exit
        0x0000_0000_0000_0018 | (va + 8 * 8) << 32, // 10: lddw r0, A (dead: makes A a target)
        (va + 8 * 8) >> 32 << 32,                   // 11:   (high half)
    ];
    assert_eq!(check_program(&words, &[0u8; gen::DATA_LEN]), Ok(7));
}
