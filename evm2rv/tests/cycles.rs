//! The measured cycles-per-opcode table for the interpreter image (ZKVM-121's acceptance: "a
//! measured cycles-per-opcode table"), published as `evm2rv/CYCLES.md`.
//!
//! **The method** cancels the harness. For an opcode, a stack-neutral snippet is built (its
//! operands pushed, the opcode, its results popped) and laid out as
//!
//! ```text
//! PUSH2 dest  JUMP  |  A: JUMPDEST  snippet × n  |  B: JUMPDEST  snippet × n  |  STOP
//! ```
//!
//! and the committed `guests-compiled/bin/evm.bin` runs it twice, with the same bytes except
//! `dest`: once entering at `A`, once at `B`. The first run executes `n` snippets and one
//! `JUMPDEST` more than the second, and nothing else differs: the code's length and bytes (so
//! its decoding, its jumpdest scan and its hash), the calldata and the witnesses are identical.
//! `JUMPDEST`, `PUSH1` and `POP` are measured the same way first and subtracted, as are `PUSH2`
//! and `PUSH32` where a snippet uses them.
//!
//! Cycles are counted by `rand-guest/tests/support/count.rs` — the emulator's instruction
//! semantics without its per-cycle event log — and one run is checked against
//! `rand_zkvm::emulator::execute` itself.
//!
//! **What the test asserts.** Every figure moves whenever `evm.bin` is rebuilt, so the published
//! file records the image it was measured on (the image's sha256, `evm.bin.sha256`). While the
//! committed image is that one, the file must be exactly what this test measures. When the image
//! has moved, the test asserts the table's structure (every opcode the interpreter runs is
//! measured or listed as not measurable, and every figure is within bounds), says the published
//! figures are for an older image, and passes: a change to the interpreter does not fail here for
//! having changed its speed. Regenerate with
//! `EVM2RV_CYCLES_REGEN=1 cargo +1.98.1 test --test cycles`.

mod common;
#[path = "../../rand-guest/tests/support/count.rs"]
mod count;

use std::collections::BTreeMap;
use std::fmt::Write as _;

use common::root;
use evm2rv::compat::{self, thousands, Behaviour};
use evm_core::u256::U256;
use rand_zkvm::evm::{erc20_transfer, EvmCall, ALICE, BOB};
use rand_zkvm::isa::Program;

/// More than any run here spends (an `SSTORE` is 2 900).
const GAS: u64 = 1_000_000_000;
/// The cycle budget of one run.
const LIMIT: u64 = 1 << 26;
/// Snippets per half, by default.
const N: usize = 32;

const JUMPDEST: u8 = 0x5b;
const POP: u8 = 0x50;

/// The wide operands: `a` is on top of the stack, `b` under it, `m` third (a modulus).
const WIDE_A: [u8; 32] = [
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];
const WIDE_B: [u8; 32] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];
const WIDE_M: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x61,
];

/// A snippet: its bytes, and how many of each baseline opcode it contains besides the one being
/// measured.
#[derive(Clone, Default)]
struct Snippet {
    code: Vec<u8>,
    push1: u32,
    push2: u32,
    push32: u32,
    pops: u32,
    jumpdests: u32,
}

impl Snippet {
    fn p1(mut self, v: u8) -> Self {
        self.code.extend([0x60, v]);
        self.push1 += 1;
        self
    }
    fn p2(mut self, v: usize) -> Self {
        self.code.push(0x61);
        self.code.extend((v as u16).to_be_bytes());
        self.push2 += 1;
        self
    }
    fn p32(mut self, v: [u8; 32]) -> Self {
        self.code.push(0x7f);
        self.code.extend(v);
        self.push32 += 1;
        self
    }
    /// The opcode being measured (or raw bytes that are neither a baseline nor subtracted).
    fn op(mut self, bytes: &[u8]) -> Self {
        self.code.extend(bytes);
        self
    }
    fn pop(mut self, n: u32) -> Self {
        self.code.extend(std::iter::repeat_n(POP, n as usize));
        self.pops += n;
        self
    }
    fn jumpdest(mut self) -> Self {
        self.code.push(JUMPDEST);
        self.jumpdests += 1;
        self
    }
}

/// The measured baselines, in cycles.
#[derive(Clone, Copy, Debug, Default)]
struct Base {
    jumpdest: f64,
    push1: f64,
    push2: f64,
    push32: f64,
    pop: f64,
}

struct Bench {
    program: Program,
    runs: usize,
}

impl Bench {
    /// A call of `code`: 64 bytes of calldata, slot 0 holding 5 with its witness supplied. From
    /// the ERC-20 fixture rather than a struct literal, so a new `EvmCall` field does not break
    /// this file.
    fn call(code: Vec<u8>) -> EvmCall {
        let mut c = erc20_transfer(ALICE, BOB, U256::ZERO, &[]);
        c.code = code;
        c.calldata = vec![0x11; 64];
        c.tree.insert(U256::ZERO, U256::from_u32(5));
        c.touched = vec![U256::ZERO];
        c.gas_limit = GAS;
        c
    }

    /// The cycles of `code` on the image, which must end in success (a snippet that halted
    /// exceptionally would have measured nothing).
    fn cycles(&mut self, code: Vec<u8>) -> u64 {
        let words = Self::call(code).input_words();
        let (out, n) = count::count(&self.program, &words, LIMIT).expect("the run fits the budget");
        assert_eq!(out[0], 1, "the measured code did not run to STOP (status {})", out[0]);
        self.runs += 1;
        n
    }

    /// The layout: `PUSH2 dest JUMP`, `A: JUMPDEST`, `n` snippets, `B: JUMPDEST`, `n` snippets,
    /// `STOP`. `snippet(at)` is the snippet placed at code offset `at` (a jump inside one needs
    /// its own position). Returns the code, `A` and `B`.
    fn layout(snippet: &dyn Fn(usize) -> Snippet, n: usize) -> (Vec<u8>, usize, usize) {
        let mut code = vec![0x61, 0, 0, 0x56];
        let a = code.len();
        code.push(JUMPDEST);
        for _ in 0..n {
            let s = snippet(code.len());
            code.extend(s.code);
        }
        let b = code.len();
        code.push(JUMPDEST);
        for _ in 0..n {
            let s = snippet(code.len());
            code.extend(s.code);
        }
        code.push(0x00);
        (code, a, b)
    }

    /// The cycles of one snippet: (the run entering at `A` − the run entering at `B` − one
    /// `JUMPDEST`) / `n`.
    fn snippet(&mut self, snippet: &dyn Fn(usize) -> Snippet, n: usize, jumpdest: f64) -> f64 {
        let (mut code, a, b) = Self::layout(snippet, n);
        code[1..3].copy_from_slice(&(a as u16).to_be_bytes());
        let long = self.cycles(code.clone());
        code[1..3].copy_from_slice(&(b as u16).to_be_bytes());
        let short = self.cycles(code);
        ((long - short) as f64 - jumpdest) / n as f64
    }

    /// The cycles of the one opcode a snippet measures: the snippet less its baselines.
    fn opcode(&mut self, snippet: &dyn Fn(usize) -> Snippet, n: usize, base: &Base) -> f64 {
        let s = snippet(0);
        self.snippet(snippet, n, base.jumpdest)
            - s.push1 as f64 * base.push1
            - s.push2 as f64 * base.push2
            - s.push32 as f64 * base.push32
            - s.pops as f64 * base.pop
            - s.jumpdests as f64 * base.jumpdest
    }

    /// A one-off difference: the code `PUSH2 dest JUMP, A: JUMPDEST, snippet, B: JUMPDEST, STOP`
    /// entered at `A` and at `B`, less the snippet's baselines and the one `JUMPDEST`. The run
    /// entering at `B` executes no snippet at all.
    fn first(&mut self, s: &Snippet, base: &Base) -> f64 {
        let mut code = vec![0x61, 0, 0, 0x56];
        let a = code.len();
        code.push(JUMPDEST);
        code.extend(&s.code);
        let b = code.len();
        code.extend([JUMPDEST, 0x00]);
        code[1..3].copy_from_slice(&(a as u16).to_be_bytes());
        let long = self.cycles(code.clone());
        code[1..3].copy_from_slice(&(b as u16).to_be_bytes());
        let short = self.cycles(code);
        (long - short) as f64
            - base.jumpdest
            - s.push1 as f64 * base.push1
            - s.push2 as f64 * base.push2
            - s.push32 as f64 * base.push32
            - s.pops as f64 * base.pop
    }
}

/// One measured row.
struct Row {
    op: u8,
    /// The opcode's name, or a variant of it (`JUMPI, taken`).
    name: String,
    /// Cycles with the small operands.
    small: f64,
    /// Cycles with the wide operands, where the opcode's cost depends on them.
    wide: Option<f64>,
    /// The operands, top of the stack first.
    operands: &'static str,
}

/// The snippets: (opcode, name, small-operand snippet, wide-operand snippet, operands, copies).
type Build = Box<dyn Fn(usize) -> Snippet>;
struct Spec {
    op: u8,
    name: String,
    small: Build,
    wide: Option<Build>,
    operands: &'static str,
    n: usize,
}

fn fixed(s: Snippet) -> Build {
    Box::new(move |_| s.clone())
}

fn specs() -> Vec<Spec> {
    let s = Snippet::default;
    let mut v: Vec<Spec> = Vec::new();
    let mut add = |op: u8, small: Snippet, wide: Option<Snippet>, operands: &'static str| {
        v.push(Spec {
            op,
            name: compat::name(op),
            small: fixed(small),
            wide: wide.map(fixed),
            operands,
            n: N,
        })
    };

    // Two operands, one result: 7 on top of 3; wide: A on top of B.
    for op in (0x01..=0x07).chain(0x10..=0x14).chain(0x16..=0x18) {
        add(
            op,
            s().p1(3).p1(7).op(&[op]).pop(1),
            Some(s().p32(WIDE_B).p32(WIDE_A).op(&[op]).pop(1)),
            "7, 3 / wide: A, B",
        );
    }
    for op in [0x08, 0x09] {
        add(
            op,
            s().p1(5).p1(3).p1(7).op(&[op]).pop(1),
            Some(s().p32(WIDE_M).p32(WIDE_B).p32(WIDE_A).op(&[op]).pop(1)),
            "7, 3, modulus 5 / wide: A, B, modulus M",
        );
    }
    add(
        0x0a,
        s().p1(5).p1(3).op(&[0x0a]).pop(1),
        Some(s().p32(WIDE_B).p32(WIDE_A).op(&[0x0a]).pop(1)),
        "base 3, exponent 5 / wide: base A, exponent B (249 bits)",
    );
    add(
        0x0b,
        s().p1(0x80).p1(0).op(&[0x0b]).pop(1),
        Some(s().p32(WIDE_A).p1(15).op(&[0x0b]).pop(1)),
        "byte 0 of 0x80 / wide: byte 15 of A",
    );
    for op in [0x15, 0x19, 0x1e] {
        add(
            op,
            s().p1(7).op(&[op]).pop(1),
            Some(s().p32(WIDE_A).op(&[op]).pop(1)),
            "7 / wide: A",
        );
    }
    add(
        0x1a,
        s().p1(7).p1(31).op(&[0x1a]).pop(1),
        Some(s().p32(WIDE_A).p1(15).op(&[0x1a]).pop(1)),
        "byte 31 of 7 / wide: byte 15 of A",
    );
    for op in 0x1b..=0x1d {
        add(
            op,
            s().p1(7).p1(4).op(&[op]).pop(1),
            Some(s().p32(WIDE_A).p1(100).op(&[op]).pop(1)),
            "7 by 4 bits / wide: A by 100 bits",
        );
    }
    add(
        0x20,
        s().p1(32).p1(0).op(&[0x20]).pop(1),
        Some(s().p1(200).p1(0).op(&[0x20]).pop(1)),
        "32 bytes at 0 (one permutation) / wide: 200 bytes at 0 (two)",
    );
    // No operand, one result.
    for op in [0x30, 0x33, 0x34, 0x36, 0x38, 0x3d, 0x58, 0x59, 0x5a, 0x5f] {
        add(op, s().op(&[op]).pop(1), None, "");
    }
    add(0x35, s().p1(0).op(&[0x35]).pop(1), None, "offset 0 of 64 bytes of calldata");
    for op in [0x37, 0x39] {
        add(
            op,
            s().p1(32).p1(0).p1(0).op(&[op]),
            Some(s().p2(1024).p1(0).p1(0).op(&[op])),
            "32 bytes to memory 0 from offset 0 / wide: 1 024 bytes",
        );
    }
    add(0x3e, s().p1(0).p1(0).p1(0).op(&[0x3e]), None, "length 0 (any other traps)");
    add(0x51, s().p1(0).op(&[0x51]).pop(1), None, "offset 0");
    add(0x52, s().p1(7).p1(0).op(&[0x52]), None, "7 at offset 0");
    add(0x53, s().p1(7).p1(0).op(&[0x53]), None, "7 at offset 0");
    add(
        0x54,
        s().p1(0).op(&[0x54]).pop(1),
        None,
        "slot 0, already read in this call (its witness verified)",
    );
    add(
        0x55,
        s().p1(7).p1(0).op(&[0x55]),
        None,
        "7 to slot 0, already written in this call",
    );
    add(0x5c, s().p1(1).op(&[0x5c]).pop(1), None, "key 1, an empty table");
    add(0x5d, s().p1(7).p1(1).op(&[0x5d]), None, "7 to key 1, the table's only key");
    add(
        0x5e,
        s().p1(32).p1(0).p1(32).op(&[0x5e]),
        Some(s().p2(1024).p1(0).p2(1024).op(&[0x5e])),
        "32 bytes from 0 to 32 / wide: 1 024 bytes from 0 to 1 024",
    );
    // PUSHn, DUPn, SWAPn.
    for n in 1..=32u8 {
        let mut code = vec![0x5f + n];
        code.extend(std::iter::repeat_n(0x11, n as usize));
        add(0x5f + n, s().op(&code).pop(1), None, "n bytes of 0x11");
    }
    for n in 1..=16u8 {
        let mut d = s();
        for _ in 0..n {
            d = d.p1(7);
        }
        add(0x7f + n, d.op(&[0x7f + n]).pop(n as u32 + 1), None, "");
        let mut w = s();
        for _ in 0..=n {
            w = w.p1(7);
        }
        add(0x8f + n, w.op(&[0x8f + n]).pop(n as u32 + 1), None, "");
    }
    drop(add);

    // JUMP and JUMPI: the destination is the snippet's own JUMPDEST.
    v.push(Spec {
        op: 0x56,
        name: "JUMP".into(),
        small: Box::new(|at| Snippet::default().p2(at + 4).op(&[0x56]).jumpdest()),
        wide: None,
        operands: "to the next opcode",
        n: N,
    });
    v.push(Spec {
        op: 0x57,
        name: "JUMPI, taken".into(),
        small: Box::new(|at| Snippet::default().p1(1).p2(at + 6).op(&[0x57]).jumpdest()),
        wide: None,
        operands: "condition 1, to the next opcode",
        n: N,
    });
    v.push(Spec {
        op: 0x57,
        name: "JUMPI, not taken".into(),
        small: fixed(Snippet::default().p1(0).p2(4).op(&[0x57])),
        wide: None,
        operands: "condition 0",
        n: N,
    });
    // LOGn: eight logs is the cap, so four copies a half. No data.
    for n in 0..=4u8 {
        let mut l = Snippet::default();
        for _ in 0..n {
            l = l.p1(7);
        }
        v.push(Spec {
            op: 0xa0 + n,
            name: compat::name(0xa0 + n),
            small: fixed(l.p1(0).p1(0).op(&[0xa0 + n])),
            wide: None,
            operands: "no data, topics 7; 4 copies a half (8 logs is the cap), so an average: \
                       it includes hashing the topics into the public output, which goes by \
                       blocks",
            n: 4,
        });
    }
    v
}

/// Opcodes the interpreter runs that the method cannot repeat: each ends the run.
const NOT_REPEATABLE: [u8; 3] = [0x00, 0xf3, 0xfd];

struct Measured {
    base: Base,
    rows: Vec<Row>,
    /// (what, cycles): the one-off differences.
    first: Vec<(&'static str, f64)>,
    runs: usize,
}

fn measure() -> Measured {
    let mut b = Bench {
        program: rand_zkvm::guests::compiled::evm(),
        runs: 0,
    };
    // The baselines. JUMPDEST: n of them and the one at B, so the difference is n + 1.
    let (mut code, a, bb) = Bench::layout(&|_| Snippet::default().jumpdest(), N);
    code[1..3].copy_from_slice(&(a as u16).to_be_bytes());
    let long = b.cycles(code.clone());
    code[1..3].copy_from_slice(&(bb as u16).to_be_bytes());
    let short = b.cycles(code.clone());
    let mut base = Base {
        jumpdest: (long - short) as f64 / (N + 1) as f64,
        ..Base::default()
    };
    // The counter is the emulator: the same run through `execute` takes the same cycles.
    let words = Bench::call(code).input_words();
    let exec = rand_zkvm::emulator::execute(&b.program, &words, &[], 1 << 20).unwrap();
    assert_eq!(exec.cycles() as u64, short, "count.rs and the emulator disagree");
    assert_eq!(exec.outputs[0], 1);

    // PUSH1 alone (the stack grows by n, far under its 1 024), then PUSH1 POP.
    base.push1 = b.snippet(&|_| Snippet::default().p1(7), N, base.jumpdest);
    let other = b.snippet(&|_| Snippet::default().p1(0xff), N, base.jumpdest);
    assert_eq!(base.push1, other, "PUSH1's cycles depend on the byte pushed");
    base.pop = b.snippet(&|_| Snippet::default().p1(7).pop(1), N, base.jumpdest) - base.push1;
    base.push2 = b.snippet(&|_| Snippet::default().p2(0x1111), N, base.jumpdest);
    base.push32 = b.snippet(&|_| Snippet::default().p32(WIDE_A), N, base.jumpdest);

    let mut rows = vec![
        Row {
            op: POP,
            name: "POP".into(),
            small: base.pop,
            wide: None,
            operands: "baseline: (PUSH1 POP) less PUSH1",
        },
        Row {
            op: JUMPDEST,
            name: "JUMPDEST".into(),
            small: base.jumpdest,
            wide: None,
            operands: "baseline",
        },
    ];
    for spec in specs() {
        let small = b.opcode(&spec.small, spec.n, &base);
        let wide = spec.wide.as_ref().map(|w| b.opcode(w, spec.n, &base));
        rows.push(Row {
            op: spec.op,
            name: spec.name,
            small,
            wide,
            operands: spec.operands,
        });
    }
    rows.sort_by(|x, y| x.op.cmp(&y.op));

    // Storage's first touch: the Merkle walk that verifies the witness (and, for a write, the
    // new root), which the repeated figure does not contain.
    let first = vec![
        (
            "`SLOAD`, the first touch of a slot",
            b.first(&Snippet::default().p1(0).op(&[0x54]).pop(1), &base),
        ),
        (
            "`SSTORE`, the first touch of a slot",
            b.first(&Snippet::default().p1(7).p1(0).op(&[0x55]), &base),
        ),
    ];
    Measured {
        base,
        rows,
        first,
        runs: b.runs,
    }
}

/// A figure: whole when it is whole (every one should be: each copy of a snippet takes the same
/// path), else to one decimal.
fn fig(x: f64) -> String {
    if (x - x.round()).abs() < 1e-9 {
        thousands(x.round() as u64)
    } else {
        let tenths = (x * 10.0).round() as u64;
        format!("≈ {}.{}", thousands(tenths / 10), tenths % 10)
    }
}

/// The family whose rows fold into one in the table.
fn family(op: u8) -> Option<u8> {
    match op {
        0x60..=0x7f => Some(0x60),
        0x80..=0x8f => Some(0x80),
        0x90..=0x9f => Some(0x90),
        _ => None,
    }
}

/// The committed image's sha256, from `evm.bin.sha256` (which `rand-guest/tests/build.rs` holds
/// to the image).
fn image_sha256() -> String {
    let text = std::fs::read_to_string(root().join("guests-compiled/bin/evm.bin.sha256")).unwrap();
    text.split_whitespace().next().unwrap().to_string()
}

const IMAGE_LINE: &str = "Measured on `guests-compiled/bin/evm.bin` with sha256 `";

fn render(m: &Measured, image: &str) -> String {
    let mut s = String::new();
    s.push_str(
        "<!-- GENERATED by evm2rv/tests/cycles.rs — do not edit.\n     \
         Regenerate: (cd evm2rv && EVM2RV_CYCLES_REGEN=1 cargo +1.98.1 test --test cycles).\n     \
         The test checks this file against what it measures while evm.bin is the image named\n     \
         below, and the table's structure and bounds once the image has moved. -->\n\n",
    );
    s.push_str("# Cycles per opcode: the EVM interpreter\n\n");
    s.push_str(
        "What one EVM opcode costs the interpreter guest (`evm-core`, `evm.bin`) in zkVM cycles. \
         What each opcode does, and its gas, is in [COMPATIBILITY.md](COMPATIBILITY.md).\n\n",
    );
    writeln!(s, "{IMAGE_LINE}{image}`. **Every figure moves when the image is rebuilt**; a figure here describes that image and no other.\n").unwrap();
    s.push_str("## Method\n\n");
    s.push_str(
        "For each opcode a stack-neutral snippet is built: `PUSH1` its operands, the opcode, \
         `POP` its results. The code is\n\n\
         ```text\n\
         PUSH2 dest  JUMP  |  A: JUMPDEST  snippet × 32  |  B: JUMPDEST  snippet × 32  |  STOP\n\
         ```\n\n\
         and the image runs it twice in the emulator with the same bytes except `dest`: entering \
         at `A`, then at `B`. The difference is 32 snippets and one `JUMPDEST`. Everything that \
         depends on the code, the calldata or the witnesses (reading the input, the jumpdest \
         scan, the hashes, the output) is the same in both runs and cancels. `JUMPDEST`, `PUSH1` \
         and `POP` are measured the same way first and subtracted, so a row is the opcode alone: \
         its dispatch, its gas charge, its stack accesses and its work.\n\n",
    );
    writeln!(
        s,
        "The baselines: `JUMPDEST` {}, `PUSH1` {}, `POP` {}, `PUSH2` {}, `PUSH32` {} cycles.\n",
        fig(m.base.jumpdest),
        fig(m.base.push1),
        fig(m.base.pop),
        fig(m.base.push2),
        fig(m.base.push32)
    )
    .unwrap();
    s.push_str(
        "Arithmetic depends on its operands, so those rows have two figures: **small** (one-byte \
         operands) and **wide** (32-byte operands). The wide operands are \
         A = `0xfedcba9876543210` repeated four times, B = `0x0123456789abcdef` repeated four \
         times, and M = 2^255 − 159. The first operand named is the top of the stack. Wide is \
         not always dearer: a comparison is decided by the first limb that differs, and a shift \
         by a whole number of limbs moves fewer bits.\n\n",
    );
    s.push_str("## The table\n\n");
    s.push_str("| byte | opcode | cycles (small) | cycles (wide) | operands |\n|---|---|---:|---:|---|\n");
    let mut i = 0;
    while i < m.rows.len() {
        let r = &m.rows[i];
        // PUSH1–32, DUP1–16 and SWAP1–16 fold into one row each when their figures are one
        // figure or an even staircase; otherwise every opcode keeps its own row.
        let mut j = i;
        while family(r.op).is_some()
            && j + 1 < m.rows.len()
            && family(m.rows[j + 1].op) == family(r.op)
        {
            j += 1;
        }
        let run = &m.rows[i..=j];
        let step = if run.len() > 1 { run[1].small - run[0].small } else { 0.0 };
        let even = run.windows(2).all(|w| w[1].small - w[0].small == step);
        if run.len() > 1 && even {
            let last = &run[run.len() - 1];
            let (cycles, note) = if step == 0.0 {
                (fig(r.small), r.operands.to_string())
            } else {
                (
                    format!("{} to {}", fig(r.small), fig(last.small)),
                    format!("{}; {} more for each byte", r.operands, fig(step)),
                )
            };
            writeln!(
                s,
                "| `{:#04x}`–`{:#04x}` | `{}`–`{}` | {cycles} |  | {note} |",
                r.op, last.op, r.name, last.name
            )
            .unwrap();
            i = j + 1;
            continue;
        }
        writeln!(
            s,
            "| `{:#04x}` | `{}` | {} | {} | {} |",
            r.op,
            r.name,
            fig(r.small),
            r.wide.map_or(String::new(), fig),
            r.operands
        )
        .unwrap();
        i += 1;
    }
    s.push_str("\n## Storage: the first touch\n\n");
    s.push_str(
        "The `SLOAD` and `SSTORE` rows above are for a slot the call has already touched. The \
         first touch of a slot also verifies its Merkle witness against the storage root: the \
         leaf and 32 levels of Poseidon2. (Every `SSTORE`, first or not, rehashes the path to \
         the new root, which is why the repeated `SSTORE` is already dear.) Measured as a \
         one-off difference: `A: JUMPDEST, snippet, B: JUMPDEST, STOP`, entered at `A` and at \
         `B`, with the slot's witness in the input of both runs.\n\n",
    );
    s.push_str("| | cycles |\n|---|---:|\n");
    for (what, c) in &m.first {
        writeln!(s, "| {what} | {} |", fig(*c)).unwrap();
    }
    s.push_str("\n## Not measured\n\n");
    s.push_str(
        "- `STOP`, `RETURN`, `REVERT` and `INVALID` end the run, so they cannot be repeated and \
         have no row.\n\
         - The opcodes the interpreter traps on have no cost to measure.\n\
         - **Translated code.** A translation has no per-opcode cost to tabulate this way: \
         `evm2rv` compiles a whole basic block, stage two keeps a block's words in registers and \
         folds constants, so an opcode's cycles depend on its neighbours, and each measurement \
         would be its own image build with the pinned clang. The whole-contract figures for the \
         ERC-20 are in [README.md](README.md), \"Cycles against the interpreter\".\n\
         - A swap-shaped contract. The only whole contracts measured are the ERC-20's vectors.\n",
    );
    s
}

#[test]
fn the_committed_cycles_table_is_what_the_image_measures() {
    let t = std::time::Instant::now();
    let m = measure();
    let image = image_sha256();
    let want = render(&m, &image);
    eprintln!("{want}");
    eprintln!("{} runs of evm.bin in {:.1}s", m.runs, t.elapsed().as_secs_f64());

    // Structure: every opcode the interpreter runs has a row, or is one that ends the run.
    let measured: BTreeMap<u8, usize> = m.rows.iter().fold(BTreeMap::new(), |mut acc, r| {
        *acc.entry(r.op).or_default() += 1;
        acc
    });
    for o in compat::opcodes() {
        let runs = matches!(o.interp, Behaviour::Runs | Behaviour::RunsIf);
        let has = measured.contains_key(&o.byte);
        assert_eq!(
            has,
            runs && !NOT_REPEATABLE.contains(&o.byte),
            "{:#04x}: a row iff the interpreter runs it and it can be repeated",
            o.byte
        );
    }
    // Bounds: an opcode is at least a dispatch and at most a few hundred thousand cycles (the
    // wide EXP is the largest); the baselines are small.
    let base = [m.base.jumpdest, m.base.push1, m.base.push2, m.base.push32, m.base.pop];
    for b in base {
        assert!((1.0..2_000.0).contains(&b), "a baseline of {b} cycles");
    }
    for r in &m.rows {
        for c in std::iter::once(r.small).chain(r.wide) {
            assert!(
                (1.0..1_000_000.0).contains(&c),
                "{}: {c} cycles is out of bounds",
                r.name
            );
        }
    }
    for (what, c) in &m.first {
        assert!((1.0..1_000_000.0).contains(c), "{what}: {c} cycles");
    }
    // The first touch contains the repeated cost and the Merkle walk on top.
    let repeated = |op: u8| m.rows.iter().find(|r| r.op == op).unwrap().small;
    assert!(m.first[0].1 > repeated(0x54) && m.first[1].1 > repeated(0x55));

    let path = root().join("evm2rv/CYCLES.md");
    if std::env::var_os("EVM2RV_CYCLES_REGEN").is_some() {
        std::fs::write(&path, &want).unwrap();
    }
    let have = std::fs::read_to_string(&path).unwrap_or_default();
    let recorded = have
        .lines()
        .find_map(|l| l.strip_prefix(IMAGE_LINE))
        .and_then(|l| l.split('`').next())
        .expect("CYCLES.md names the image it was measured on");
    if recorded == image {
        assert!(
            have == want,
            "{} is stale for the committed evm.bin; regenerate with \
             EVM2RV_CYCLES_REGEN=1 cargo +1.98.1 test --test cycles",
            path.display()
        );
    } else {
        // The image has been rebuilt since the table was measured. Its figures are for the image
        // it names; the structure must still be the current one.
        eprintln!(
            "CYCLES.md was measured on evm.bin {recorded}; the committed image is {image}. \
             Its figures are stale: regenerate with EVM2RV_CYCLES_REGEN=1 cargo +1.98.1 test \
             --test cycles"
        );
        for r in &m.rows {
            let cell = format!("`{}`", r.name);
            if family(r.op).is_none() {
                assert!(have.contains(&cell), "CYCLES.md has no row for {cell}");
            }
        }
    }
}
